// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  SSH_TOKEN_PROOF_DOMAIN,
  SSH_TOKEN_PROOF_USERNAME,
  SSH_TOKEN_PROOF_VERSION,
  SSH_TOKEN_PROVISIONING_USERNAME,
  SSHTokenProofClient,
  computeTokenProof,
  decodeTokenProofBytes,
  encodeTokenProofBytes,
  encodeTokenProofTranscript,
  parseTokenProofMessage,
} from "../src/ssh-tokenproof.js";

const dirname = path.dirname(fileURLToPath(import.meta.url));
type TokenProofVector = {
  schema_version: number;
  protocol: string;
  username: string;
  token: string;
  host_key_hash: string;
  client_nonce: string;
  server_nonce: string;
  transcript_hex: string;
  server_proof: string;
  server_proof_question: string;
  client_proof_answer: string;
};
const vector = JSON.parse(
  fs.readFileSync(path.resolve(dirname, "../../contracts/sshtunnel/token_proof_v1.json"), "utf8")
) as TokenProofVector;

test("SSH token proof matches the contract vector", () => {
  assert.equal(vector.schema_version, SSH_TOKEN_PROOF_VERSION);
  assert.equal(vector.protocol, SSH_TOKEN_PROOF_DOMAIN);
  assert.equal(vector.username, SSH_TOKEN_PROOF_USERNAME);
  const decode = (value: string) => decodeTokenProofBytes(value, 32);
  const transcript = encodeTokenProofTranscript(
    decode(vector.host_key_hash),
    decode(vector.client_nonce),
    decode(vector.server_nonce)
  );
  assert.equal(transcript.toString("hex"), vector.transcript_hex);
  assert.equal(
    encodeTokenProofBytes(computeTokenProof(vector.token, "server", transcript)),
    vector.server_proof
  );

  const proof = new SSHTokenProofClient(vector.token);
  Object.assign(proof, {
    hostHash: decode(vector.host_key_hash),
    clientNonce: decode(vector.client_nonce),
    round: 1,
  });
  assert.deepEqual(
    proof.challenge(SSH_TOKEN_PROOF_DOMAIN, "", [
      { prompt: vector.server_proof_question, echo: false },
    ]),
    [vector.client_proof_answer]
  );
  assert.equal(proof.serverVerified, true);
});

test("SSH token provisioning uses the fixed username", () => {
  assert.equal(SSH_TOKEN_PROVISIONING_USERNAME, "request-token");
});

test("SSH token proof rejects duplicate fields and padded base64url", () => {
  assert.throws(
    () => parseTokenProofMessage('{"version":1,"version":1,"step":"client_nonce"}', ["version", "step"]),
    /duplicate/
  );
  assert.throws(
    () => decodeTokenProofBytes("ERERERERERERERERERERERERERERERERERERERERERE=", 32),
    /canonical/
  );
});

test("SSH token proof requires an accepted host key", () => {
  const proof = new SSHTokenProofClient("token");
  assert.throws(
    () => proof.challenge(SSH_TOKEN_PROOF_DOMAIN, "", [
      { prompt: '{"version":1,"step":"client_nonce"}', echo: false },
    ]),
    /challenge shape/
  );
});

test("SSH token proof disposal zeros and releases authentication state", () => {
  const proof = new SSHTokenProofClient("token");
  const hostHash = Buffer.alloc(32, 0x68);
  const clientNonce = Buffer.alloc(32, 0x6e);
  Object.assign(proof, { hostHash, clientNonce, round: 2, verified: true });

  proof.dispose();

  assert.ok(hostHash.every((value) => value === 0));
  assert.ok(clientNonce.every((value) => value === 0));
  assert.equal(proof.serverVerified, false);
  assert.deepEqual(
    Object.assign({}, proof),
    {
      hostHash: Buffer.alloc(0),
      clientNonce: Buffer.alloc(0),
      round: -1,
      verified: false,
      token: "",
    }
  );
});
