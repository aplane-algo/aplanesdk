// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  SSH_TOKEN_PROOF_DOMAIN,
  SSHTokenProofClient,
  computeTokenProof,
  decodeTokenProofBytes,
  encodeTokenProofBytes,
  encodeTokenProofTranscript,
  parseTokenProofMessage,
} from "../src/ssh-tokenproof.js";

const dirname = path.dirname(fileURLToPath(import.meta.url));
const vector = JSON.parse(
  fs.readFileSync(path.resolve(dirname, "../../contracts/sshtunnel/token_proof_v1.json"), "utf8")
) as Record<string, string>;

test("SSH token proof matches the contract vector", () => {
  const decode = (value: string) => decodeTokenProofBytes(value, 32);
  const transcript = encodeTokenProofTranscript(
    vector.identity_id,
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
