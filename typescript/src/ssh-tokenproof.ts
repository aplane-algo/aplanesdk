// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { createHash, createHmac, randomBytes, timingSafeEqual } from "crypto";

export const SSH_TOKEN_PROOF_DOMAIN = "aplane-ssh-token-proof-v1";
export const SSH_TOKEN_PROOF_IDENTITY = "default";
const NONCE_SIZE = 32;
const MAX_MESSAGE_SIZE = 1024;

function field(value: Buffer): Buffer {
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(value.length);
  return Buffer.concat([length, value]);
}

export function encodeTokenProofTranscript(
  identity: string,
  hostKeyHash: Buffer,
  clientNonce: Buffer,
  serverNonce: Buffer
): Buffer {
  if (
    !identity ||
    Buffer.byteLength(identity) > 128 ||
    hostKeyHash.length !== 32 ||
    clientNonce.length !== NONCE_SIZE ||
    serverNonce.length !== NONCE_SIZE
  ) {
    throw new Error("invalid SSH token proof transcript");
  }
  return Buffer.concat([
    field(Buffer.from(SSH_TOKEN_PROOF_DOMAIN)),
    field(Buffer.from(identity)),
    field(hostKeyHash),
    field(clientNonce),
    field(serverNonce),
  ]);
}

export function computeTokenProof(token: string, role: "server" | "client", transcript: Buffer): Buffer {
  if (!token || transcript.length === 0) {
    throw new Error("invalid SSH token proof input");
  }
  return createHmac("sha256", token)
    .update(Buffer.concat([field(Buffer.from(role)), field(transcript)]))
    .digest();
}

export function encodeTokenProofBytes(value: Buffer): string {
  return value.toString("base64url");
}

export function decodeTokenProofBytes(value: unknown, size: number): Buffer {
  if (typeof value !== "string" || value.includes("=")) {
    throw new Error("token proof value is not canonical base64url");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== size || decoded.toString("base64url") !== value) {
    throw new Error(`token proof value must encode ${size} bytes`);
  }
  return decoded;
}

function scanJSONString(source: string, start: number): [string, number] {
  let end = start + 1;
  while (end < source.length) {
    if (source[end] === "\\") {
      end += 2;
      continue;
    }
    if (source[end] === '"') {
      const raw = source.slice(start, end + 1);
      return [JSON.parse(raw) as string, end + 1];
    }
    end += 1;
  }
  throw new Error("unterminated token proof JSON string");
}

export function parseTokenProofMessage(source: string, required: string[]): Record<string, unknown> {
  if (!source || Buffer.byteLength(source) > MAX_MESSAGE_SIZE) {
    throw new Error("invalid token proof message size");
  }
  let offset = 0;
  const whitespace = () => {
    while (/\s/.test(source[offset] ?? "")) offset += 1;
  };
  whitespace();
  if (source[offset++] !== "{") throw new Error("token proof message must be an object");
  const keys: string[] = [];
  whitespace();
  while (source[offset] !== "}") {
    if (source[offset] !== '"') throw new Error("invalid token proof field");
    const [key, next] = scanJSONString(source, offset);
    offset = next;
    if (keys.includes(key)) throw new Error(`duplicate token proof field ${key}`);
    keys.push(key);
    whitespace();
    if (source[offset++] !== ":") throw new Error("invalid token proof field");
    whitespace();
    if (source[offset] === '"') {
      [, offset] = scanJSONString(source, offset);
    } else {
      const match = source.slice(offset).match(/^-?(?:0|[1-9]\d*)/);
      if (!match) throw new Error("unsupported token proof field value");
      offset += match[0].length;
    }
    whitespace();
    if (source[offset] === ",") {
      offset += 1;
      whitespace();
      continue;
    }
    if (source[offset] !== "}") throw new Error("invalid token proof message");
  }
  offset += 1;
  whitespace();
  if (offset !== source.length || keys.length !== required.length || required.some((key) => !keys.includes(key))) {
    throw new Error("unexpected token proof fields");
  }
  const parsed = JSON.parse(source) as Record<string, unknown>;
  return parsed;
}

export class SSHTokenProofClient {
  private hostHash = Buffer.alloc(0);
  private clientNonce = Buffer.alloc(0);
  private round = 0;
  private verified = false;
  private token: string;

  constructor(token: string) {
    this.token = token;
  }

  captureHostKey(keyBlob: Buffer): void {
    const hash = createHash("sha256").update(keyBlob).digest();
    if (this.hostHash.length && !timingSafeEqual(this.hostHash, hash)) {
      throw new Error("SSH host key changed during authentication");
    }
    this.hostHash = hash;
  }

  challenge(name: string, instructions: string, prompts: Array<{ prompt: string; echo?: boolean }>): string[] {
    if (
      name !== SSH_TOKEN_PROOF_DOMAIN ||
      instructions !== "" ||
      prompts.length !== 1 ||
      prompts[0].echo ||
      this.hostHash.length !== 32
    ) {
      throw new Error("unexpected SSH token proof challenge shape");
    }

    if (this.round === 0) {
      const message = parseTokenProofMessage(prompts[0].prompt, ["version", "step"]);
      if (message.version !== 1 || message.step !== "client_nonce") {
        throw new Error("unexpected token proof client-nonce question");
      }
      this.clientNonce = randomBytes(NONCE_SIZE);
      this.round = 1;
      return [JSON.stringify({ client_nonce: encodeTokenProofBytes(this.clientNonce) })];
    }

    if (this.round === 1) {
      const message = parseTokenProofMessage(prompts[0].prompt, [
        "version",
        "step",
        "server_nonce",
        "proof",
      ]);
      if (message.version !== 1 || message.step !== "server_proof") {
        throw new Error("unexpected token proof server-proof question");
      }
      const serverNonce = decodeTokenProofBytes(message.server_nonce, NONCE_SIZE);
      const serverProof = decodeTokenProofBytes(message.proof, 32);
      const transcript = encodeTokenProofTranscript(
        SSH_TOKEN_PROOF_IDENTITY,
        this.hostHash,
        this.clientNonce,
        serverNonce
      );
      const expected = computeTokenProof(this.token, "server", transcript);
      if (!timingSafeEqual(expected, serverProof)) {
        throw new Error("SSH server token proof is invalid");
      }
      const clientProof = computeTokenProof(this.token, "client", transcript);
      this.round = 2;
      this.verified = true;
      return [JSON.stringify({ client_proof: encodeTokenProofBytes(clientProof) })];
    }

    throw new Error("unexpected additional SSH token proof challenge");
  }

  get serverVerified(): boolean {
    return this.verified && this.round === 2;
  }

  dispose(): void {
    this.hostHash.fill(0);
    this.clientNonce.fill(0);
    this.hostHash = Buffer.alloc(0);
    this.clientNonce = Buffer.alloc(0);
    this.token = "";
    this.round = -1;
    this.verified = false;
  }
}
