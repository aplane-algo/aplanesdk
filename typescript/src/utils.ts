// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import * as fs from "fs";
import * as path from "path";
import { createHash } from "crypto";
import {
  SignerError,
  EnrollmentError,
} from "./errors.js";
import {
  loadConfig,
  isNetworkAllowed,
  loadClientEndpointRegistry,
  resolveClientEndpoint,
  clientEndpointSshHostPort,
  resolveDataDir,
  expandPath,
  DEFAULT_SSH_PORT,
} from "./config.js";
import {
  SSH_ENROLLMENT_COMMAND,
  SSH_ENROLLMENT_USERNAME,
  normalizeSSHSetupTimeout,
  sshConnectionFailedMessage,
  validateEnrollmentLabel,
} from "./ssh.js";

// Re-export config utilities
export {
  loadConfig,
  isNetworkAllowed,
  loadClientEndpointRegistry,
  resolveClientEndpoint,
  resolveDataDir,
  expandPath,
};

function parseHostKeyType(key: Buffer): string {
  if (key.length < 4) return "unknown";
  const typeLen = key.readUInt32BE(0);
  if (key.length < 4 + typeLen) return "unknown";
  return key.subarray(4, 4 + typeLen).toString("ascii");
}

function formatHostEntry(host: string, port: number): string {
  return port === 22 ? host : `[${host}]:${port}`;
}

function loadKnownHostKey(knownHostsPath: string, host: string, port: number): Buffer | null {
  if (!fs.existsSync(knownHostsPath)) return null;
  const hostEntry = formatHostEntry(host, port);
  const content = fs.readFileSync(knownHostsPath, "utf-8");
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const parts = trimmed.split(" ");
    if (parts.length >= 3 && parts[0] === hostEntry) {
      return Buffer.from(parts[2], "base64");
    }
  }
  return null;
}

function saveHostKey(knownHostsPath: string, host: string, port: number, key: Buffer): void {
  const dir = path.dirname(knownHostsPath);
  if (dir && dir !== ".") {
    fs.mkdirSync(dir, { recursive: true });
  }
  const hostEntry = formatHostEntry(host, port);
  const keyType = parseHostKeyType(key);
  const keyBase64 = key.toString("base64");
  fs.appendFileSync(knownHostsPath, `${hostEntry} ${keyType} ${keyBase64}\n`, { mode: 0o600 });
}

/** Options for requestEnrollment. */
export interface RequestEnrollmentOptions {
  /** SSH port on the signer (default: 1127) */
  sshPort?: number;
  /** Path to the known_hosts file that pins the signer's host key (required) */
  knownHostsPath?: string;
  /** If true, trust and save an unknown host key (TOFU). Default: false */
  autoAddHost?: boolean;
  /** Optional display label shown to the operator (printable, single line, <= 64 bytes) */
  label?: string;
  /** TCP connection and SSH authentication timeout in milliseconds (default: 60000) */
  setupTimeout?: number;
  /** Optional cancellation signal; also abandons the wait for the operator */
  signal?: AbortSignal;
}

/** The signer's answer to an enrollment request. */
export interface EnrollmentResult {
  /**
   * SHA256 fingerprint of the client key the request was made with; it
   * equals the key the client authenticated with.
   */
  fingerprint: string;
  /**
   * True when the request was queued for the operator to approve later in
   * apadmin (the normal outcome); false when the key was already enrolled.
   */
  pending: boolean;
}

/**
 * Parses the signer's answer: "pending <fingerprint>" when the request was
 * queued for the operator, "enrolled <fingerprint>" when the key was already
 * enrolled. The fingerprint must be the key this client authenticated with.
 */
export function parseEnrollmentReply(reply: string | Buffer, clientFingerprint: string): EnrollmentResult {
  // The reply is read as bytes, so text that is not UTF-8 is reported as
  // \xNN escapes, as Go and Python report it, rather than decoded to U+FFFD.
  const bytes = trimBytes(typeof reply === "string" ? Buffer.from(reply, "utf8") : reply);
  const unexpected = () => new EnrollmentError(`Unexpected enrollment response: "${safeEnrollmentText(bytes)}"`);
  let fingerprint: Buffer;
  let pending: boolean;
  if (startsWithText(bytes, "pending ")) {
    [fingerprint, pending] = [bytes.subarray("pending ".length), true];
  } else if (startsWithText(bytes, "enrolled ")) {
    [fingerprint, pending] = [bytes.subarray("enrolled ".length), false];
  } else {
    throw unexpected();
  }
  if (fingerprint.length === 0) {
    throw unexpected();
  }
  if (!fingerprint.equals(Buffer.from(clientFingerprint, "utf8"))) {
    throw new EnrollmentError(
      `Signer answered for ${safeEnrollmentText(fingerprint)}, ` +
      `but this client authenticated with ${clientFingerprint}`
    );
  }
  return { fingerprint: clientFingerprint, pending };
}

function startsWithText(bytes: Buffer, prefix: string): boolean {
  const wanted = Buffer.from(prefix, "utf8");
  return bytes.length >= wanted.length && bytes.subarray(0, wanted.length).equals(wanted);
}

/** What is read of the signer's enrollment answer; a real one is one short line. */
export const MAX_ENROLLMENT_REPLY_BYTES = 4096;
/** How much of the signer's text an enrollment error carries. */
export const MAX_ENROLLMENT_ERROR_BYTES = 256;

const GO_SHORT_ESCAPES: Record<number, string> = {
  0x07: "\\a", 0x08: "\\b", 0x0c: "\\f", 0x0a: "\\n", 0x0d: "\\r", 0x09: "\\t", 0x0b: "\\v",
};
// Go's unicode.IsPrint: letters, marks, numbers, punctuation, symbols and
// the ASCII space.
const PRINTABLE = /^[\p{L}\p{M}\p{N}\p{P}\p{S} ]$/u;

/**
 * The signer's text as an error may carry it: every character that does not
 * print as itself (controls, formatting characters such as bidirectional
 * overrides) escaped as Go escapes it, a byte that is not UTF-8 as \\xNN, and
 * the result cut to MAX_ENROLLMENT_ERROR_BYTES between characters, so an
 * escape is never cut in half. An error message is often printed to a
 * terminal, and this text comes from the server.
 */
export function safeEnrollmentText(text: string | Buffer): string {
  const bytes = typeof text === "string" ? Buffer.from(text, "utf8") : text;
  let out = "";
  let size = 0;
  for (let i = 0; i < bytes.length;) {
    const [code, width] = decodeUtf8(bytes, i);
    let piece: string;
    if (code < 0) {
      piece = `\\x${bytes[i].toString(16).padStart(2, "0")}`;
    } else {
      const ch = String.fromCodePoint(code);
      if (PRINTABLE.test(ch)) {
        piece = ch;
      } else if (code in GO_SHORT_ESCAPES) {
        piece = GO_SHORT_ESCAPES[code];
      } else if (code < 0x20 || code === 0x7f) {
        piece = `\\x${code.toString(16).padStart(2, "0")}`;
      } else if (code < 0x10000) {
        piece = `\\u${code.toString(16).padStart(4, "0")}`;
      } else {
        piece = `\\U${code.toString(16).padStart(8, "0")}`;
      }
    }
    const pieceSize = Buffer.byteLength(piece, "utf8");
    if (size + pieceSize > MAX_ENROLLMENT_ERROR_BYTES) {
      return out + "...";
    }
    out += piece;
    size += pieceSize;
    i += code < 0 ? 1 : width;
  }
  return out;
}

/**
 * The code point that starts at bytes[i] and its length, or -1 when the bytes
 * there are not UTF-8 (a stray byte, an overlong form, a surrogate, a value
 * past U+10FFFF), as Go's utf8.DecodeRune reports one invalid byte.
 */
function decodeUtf8(bytes: Buffer, i: number): [number, number] {
  const lead = bytes[i];
  if (lead < 0x80) return [lead, 1];
  let width: number;
  let code: number;
  let min: number;
  if (lead >= 0xc2 && lead <= 0xdf) {
    [width, code, min] = [2, lead & 0x1f, 0x80];
  } else if (lead >= 0xe0 && lead <= 0xef) {
    [width, code, min] = [3, lead & 0x0f, 0x800];
  } else if (lead >= 0xf0 && lead <= 0xf4) {
    [width, code, min] = [4, lead & 0x07, 0x10000];
  } else {
    return [-1, 1];
  }
  if (i + width > bytes.length) return [-1, 1];
  for (let k = 1; k < width; k++) {
    const next = bytes[i + k];
    if ((next & 0xc0) !== 0x80) return [-1, 1];
    code = (code << 6) | (next & 0x3f);
  }
  if (code < min || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return [-1, 1];
  return [code, width];
}

/**
 * Ask the signer to enroll this client's SSH key, so the key can open API
 * connections. The signer answers at once: the request is queued for the
 * operator to approve later in apadmin (`pending: true`, the normal
 * outcome), or the key is already enrolled. Nothing waits for the operator
 * and nothing is stored on the client: the key is its credential, and the
 * client learns the outcome by connecting after approval (an unenrolled key
 * still fails the handshake).
 *
 * @param host - Signer host
 * @param sshKeyPath - Path to the client's SSH private key
 * @param options - sshPort, knownHostsPath, autoAddHost, label, setupTimeout, signal
 * @returns The key's fingerprint (SHA256:...) and whether approval is pending
 */
export async function requestEnrollment(
  host: string,
  sshKeyPath: string,
  options: RequestEnrollmentOptions = {}
): Promise<EnrollmentResult> {
  const sshPort = options.sshPort ?? DEFAULT_SSH_PORT;
  const setupTimeout = normalizeSSHSetupTimeout(options.setupTimeout);
  const label = options.label ?? "";
  try {
    validateEnrollmentLabel(label);
  } catch (error) {
    throw new SignerError(error instanceof Error ? error.message : String(error));
  }
  if (!options.knownHostsPath) {
    throw new SignerError("known_hosts path is required for SSH host key verification");
  }
  // ssh2 is CommonJS; under ESM interop only some of its exports are
  // detected as named, so take utils from the default export when needed.
  const ssh2 = await import("ssh2");
  const Client = ssh2.Client;
  const utils = ssh2.utils ?? (ssh2 as unknown as { default: typeof ssh2 }).default.utils;
  const expandedKeyPath = expandPath(sshKeyPath);
  const knownHostsPath = expandPath(options.knownHostsPath);

  if (!fs.existsSync(expandedKeyPath)) {
    throw new SignerError(`SSH key not found: ${expandedKeyPath}`);
  }

  const privateKey = fs.readFileSync(expandedKeyPath, "utf-8");
  const parsedKey = utils.parseKey(privateKey);
  if (parsedKey instanceof Error) {
    throw new SignerError(`failed to parse SSH key ${expandedKeyPath}: ${parsedKey.message}`);
  }
  // ssh2 can parse an OpenSSH file that holds no key to undefined.
  if (!parsedKey) {
    throw new SignerError(`failed to parse SSH key ${expandedKeyPath}: it holds no key`);
  }
  if (!parsedKey.isPrivateKey()) {
    throw new SignerError(`SSH key ${expandedKeyPath} is not a private key`);
  }
  const clientFingerprint = sshFingerprintSHA256(parsedKey.getPublicSSH());
  // A server can let a client in without asking for a key. Its answer would
  // then speak for a key this client never proved it holds, so note each
  // signature the key makes while authenticating.
  let keySigned = false;
  const signWithKey = parsedKey.sign.bind(parsedKey);
  parsedKey.sign = (data: Buffer | string, algo?: string): Buffer => {
    const signature: Buffer | Error = signWithKey(data, algo);
    if (!(signature instanceof Error)) keySigned = true;
    return signature as Buffer;
  };
  const publicKeyAuth: import("ssh2").PublicKeyAuthMethod = {
    type: "publickey",
    username: SSH_ENROLLMENT_USERNAME,
    key: parsedKey,
  };
  const command = label ? `${SSH_ENROLLMENT_COMMAND} ${label}` : SSH_ENROLLMENT_COMMAND;

  return new Promise((resolve, reject) => {
    const client = new Client();
    let hostKeyError = "";
    let settled = false;
    const cleanupSetup = () => options.signal?.removeEventListener("abort", abortSetup);
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      cleanupSetup();
      fn();
    };
    const abortSetup = () => {
      finish(() => {
        client.destroy();
        reject(new EnrollmentError("SSH setup canceled"));
      });
    };
    if (options.signal?.aborted) {
      abortSetup();
      return;
    }
    options.signal?.addEventListener("abort", abortSetup, { once: true });

    client.on("ready", () => {
      if (!keySigned) {
        client.end();
        finish(() => reject(new EnrollmentError("The signer did not authenticate this client's SSH key")));
        return;
      }
      client.exec(command, (err: Error | undefined, channel: import("ssh2").ClientChannel) => {
        if (err) {
          client.end();
          finish(() => reject(new EnrollmentError(`Failed to start enrollment: ${safeEnrollmentText(err.message)}`)));
          return;
        }

        // The node writes every reply, an ERROR: line included, to stdout.
        const chunks: Buffer[] = [];
        let received = 0;

        channel.on("data", (data: Buffer) => {
          if (settled) return;
          received += data.length;
          if (received > MAX_ENROLLMENT_REPLY_BYTES) {
            // Not waiting for the exit status: a server that streams without
            // end may never exit.
            finish(() => reject(new EnrollmentError(
              `Enrollment response exceeded ${MAX_ENROLLMENT_REPLY_BYTES} bytes`
            )));
            client.destroy();
            return;
          }
          chunks.push(data);
        });

        channel.on("close", (code: number) => {
          client.end();
          finish(() => {
            const output = Buffer.concat(chunks);
            if (code !== 0) {
              let message = trimBytes(output);
              if (message.subarray(0, 7).toString("latin1") === "ERROR: ") message = message.subarray(7);
              reject(new EnrollmentError(message.length ? safeEnrollmentText(message) : "Enrollment rejected"));
              return;
            }
            try {
              resolve(parseEnrollmentReply(output, clientFingerprint));
            } catch (error) {
              reject(error);
            }
          });
        });
      });
    });

    client.on("error", (err: Error) => {
      finish(() => reject(new EnrollmentError(
        hostKeyError || sshConnectionFailedMessage(err, SSH_ENROLLMENT_USERNAME)
      )));
    });

    // ssh2 reports a peer that disconnects mid-handshake with close alone and
    // clears readyTimeout, so an unfinished setup must fail here.
    client.on("close", () => {
      finish(() => reject(new EnrollmentError(
        hostKeyError || "SSH connection closed before setup completed"
      )));
    });

    client.connect({
      host,
      port: sshPort,
      username: SSH_ENROLLMENT_USERNAME,
      // The parsed key, so the signatures it makes can be seen.
      authHandler: [publicKeyAuth],
      readyTimeout: setupTimeout,
      hostVerifier: (key: Buffer): boolean => {
        const storedKey = loadKnownHostKey(knownHostsPath, host, sshPort);

        if (storedKey === null) {
          if (!options.autoAddHost) {
            hostKeyError =
              `Unknown SSH host key for ${formatHostEntry(host, sshPort)}; ` +
              `pass autoAddHost: true to trust on first use, or save the host key in ${knownHostsPath}`;
            return false;
          }
          saveHostKey(knownHostsPath, host, sshPort, key);
          return true;
        }

        if (storedKey.equals(key)) {
          return true;
        }

        hostKeyError =
          `SSH host key mismatch for ${formatHostEntry(host, sshPort)} ` +
          `(possible MITM attack); remove the old key from ${knownHostsPath} to connect`;
        return false;
      },
    });
  });
}

/** bytes without leading and trailing ASCII whitespace. */
function trimBytes(bytes: Buffer): Buffer {
  let start = 0;
  let end = bytes.length;
  const space = (b: number) => b === 0x20 || (b >= 0x09 && b <= 0x0d);
  while (start < end && space(bytes[start])) start++;
  while (end > start && space(bytes[end - 1])) end--;
  return bytes.subarray(start, end);
}

/** SHA256 fingerprint of an SSH public key in wire format, as OpenSSH prints it. */
function sshFingerprintSHA256(publicKeyWire: Buffer): string {
  const digest = createHash("sha256").update(publicKeyWire).digest("base64");
  return `SHA256:${digest.replace(/=+$/, "")}`;
}

/** Options for requestEnrollmentFromEnv. */
export interface RequestEnrollmentFromEnvOptions {
  /** Client data directory (default: APCLIENT_DATA) */
  dataDir?: string;
  /** Endpoint alias (default: the registry's signer endpoint) */
  endpoint?: string;
  /** If true, trust and save an unknown host key (TOFU). Default: false */
  autoAddHost?: boolean;
  /** Optional display label shown to the operator */
  label?: string;
  /** TCP connection and SSH authentication timeout in milliseconds (default: 60000) */
  setupTimeout?: number;
  /** Optional cancellation signal */
  signal?: AbortSignal;
}

/**
 * Ask the endpoint selected from the data directory's endpoints.yaml (the
 * default signer, or `endpoint`) to enroll the client key configured for it.
 * See requestEnrollment for the result; nothing is stored.
 */
export async function requestEnrollmentFromEnv(
  options: RequestEnrollmentFromEnvOptions = {}
): Promise<EnrollmentResult> {
  const rawOptions = options as Record<string, unknown>;
  for (const removed of ["host", "sshPort", "identity"]) {
    if (removed in rawOptions) {
      throw new SignerError(
        `requestEnrollmentFromEnv option "${removed}" was removed; configure and select an endpoints.yaml alias`,
      );
    }
  }
  const dataDir = resolveDataDir(options.dataDir);
  loadConfig(dataDir);
  const registry = loadClientEndpointRegistry(dataDir);
  const { endpoint } = resolveClientEndpoint(registry, options.endpoint);
  const { host, port: sshPort } = clientEndpointSshHostPort(endpoint);
  const sshKeyPath = endpoint.identityFile;
  const knownHostsPath = endpoint.knownHostsPath;

  if (!fs.existsSync(sshKeyPath)) {
    throw new SignerError(
      `SSH key not found at ${sshKeyPath}\n` +
      `Create one with: ssh-keygen -t ed25519 -f ${sshKeyPath}`
    );
  }

  return requestEnrollment(host, sshKeyPath, {
    sshPort,
    knownHostsPath,
    autoAddHost: options.autoAddHost,
    label: options.label,
    setupTimeout: options.setupTimeout,
    signal: options.signal,
  });
}
