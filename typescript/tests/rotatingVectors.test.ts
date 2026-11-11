// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

// The rotating vectors are what a live signer returned for a rotating spend,
// and copies of those answers altered in each way a signer may not alter
// them. Every SDK must accept the captured answers and refuse every altered
// one. See contracts/signerapi_vectors/README.md.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import type { RotatingPrepareResponse, RotatingSignResponse } from "../src/types.js";
import { newPreparedRotating } from "../src/rotating.js";
import { errorText } from "../src/errors.js";

interface RotatingVectorCase {
  key_type: string;
  original_txn_hex: string;
  prepare: RotatingPrepareResponse;
  sign: RotatingSignResponse;
}

interface RotatingVectors {
  cases: Record<string, RotatingVectorCase>;
  prepare_tampered: Array<{ name: string; case: string; prepare: RotatingPrepareResponse }>;
  sign_tampered: Array<{ name: string; case: string; sign: RotatingSignResponse }>;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vectorsPath = path.resolve(__dirname, "../../contracts/signerapi_vectors/rotating_vectors.json");
const vectors = JSON.parse(fs.readFileSync(vectorsPath, "utf-8")) as RotatingVectors;

// The vectors are checked with no max fee increase: the fee ceiling depends on
// the client's own setting and is tested directly.
function preparedFrom(c: RotatingVectorCase, prepare: RotatingPrepareResponse) {
  return newPreparedRotating(c.original_txn_hex, prepare, undefined, undefined);
}

describe("rotating vectors", () => {
  it("accepts every captured answer and refuses every altered one", (t) => {
    const names = Object.keys(vectors.cases).sort();
    assert.ok(names.length > 0, "no captured rotating cases");
    assert.ok(vectors.prepare_tampered.length > 0, "no altered prepare answers");
    assert.ok(vectors.sign_tampered.length > 0, "no altered sign answers");

    let accepted = 0;
    for (const name of names) {
      const c = vectors.cases[name];
      const prepared = preparedFrom(c, c.prepare);
      prepared.verifySigned(c.sign);
      accepted++;
    }

    const acceptedPrepares: string[] = [];
    let preparesRefused = 0;
    for (const altered of vectors.prepare_tampered) {
      const c = vectors.cases[altered.case];
      assert.ok(c, `altered prepare names unknown case ${altered.case}`);
      try {
        preparedFrom(c, altered.prepare);
        acceptedPrepares.push(`${altered.case}: ${altered.name}`);
      } catch {
        preparesRefused++;
      }
    }

    const acceptedSigns: string[] = [];
    let signsRefused = 0;
    for (const altered of vectors.sign_tampered) {
      const c = vectors.cases[altered.case];
      assert.ok(c, `altered sign names unknown case ${altered.case}`);
      // Checked against the case's own, unaltered prepare answer.
      const prepared = preparedFrom(c, c.prepare);
      try {
        prepared.verifySigned(altered.sign);
        acceptedSigns.push(`${altered.case}: ${altered.name}`);
      } catch {
        signsRefused++;
      }
    }

    t.diagnostic(
      `cases accepted ${accepted}/${names.length}; prepare alterations refused ` +
        `${preparesRefused}/${vectors.prepare_tampered.length}; sign alterations refused ` +
        `${signsRefused}/${vectors.sign_tampered.length}`,
    );
    assert.deepEqual(acceptedPrepares, [], "altered prepare answers were accepted");
    assert.deepEqual(acceptedSigns, [], "altered sign answers were accepted");
    assert.equal(accepted, names.length);
  });

  it("refuses every altered answer at the check meant for it, not in decoding the vector", () => {
    // An alteration must reach the verifier: a refusal for a malformed vector
    // file would hide a missing check.
    for (const altered of vectors.prepare_tampered) {
      const c = vectors.cases[altered.case];
      assert.throws(
        () => preparedFrom(c, altered.prepare),
        (error: unknown) => {
          assert.doesNotMatch(errorText(error), /original transaction:/, `${altered.case}: ${altered.name}`);
          return true;
        },
      );
    }
  });

  it("covers every captured case with alterations", () => {
    for (const name of Object.keys(vectors.cases)) {
      assert.ok(vectors.prepare_tampered.some((entry) => entry.case === name), name);
      assert.ok(vectors.sign_tampered.some((entry) => entry.case === name), name);
    }
  });
});
