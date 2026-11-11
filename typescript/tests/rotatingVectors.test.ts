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
import { SignOutcomeUnknownError, SignerError, errorText } from "../src/errors.js";
import { SignerClient } from "../src/client.js";
import algosdk from "algosdk";
import { alternateSpellings, installSigners, statusBody } from "./fakeNetwork.js";

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
  sign_answer_bodies: Array<{ name: string; case: string; body: string; expect: "accepted" | "refused" | "unknown" }>;
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

    // A refusal must come from the verifier, as a SignerError: a TypeError or
    // other programming error refuses nothing on purpose.
    const notVerifier: string[] = [];
    const refusedBy = (label: string, error: unknown) => {
      if (!(error instanceof SignerError)) {
        notVerifier.push(`${label}: ${error instanceof Error ? error.name : typeof error}: ${errorText(error)}`);
      }
    };

    const acceptedPrepares: string[] = [];
    let preparesRefused = 0;
    for (const altered of vectors.prepare_tampered) {
      const c = vectors.cases[altered.case];
      assert.ok(c, `altered prepare names unknown case ${altered.case}`);
      try {
        preparedFrom(c, altered.prepare);
        acceptedPrepares.push(`${altered.case}: ${altered.name}`);
      } catch (error) {
        refusedBy(`prepare ${altered.case}: ${altered.name}`, error);
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
      } catch (error) {
        refusedBy(`sign ${altered.case}: ${altered.name}`, error);
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
    assert.deepEqual(notVerifier, [], "altered answers were refused by something other than the verifier");
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

  it("refuses a rekey_to in another spelling of the same address", () => {
    // The bytes are unchanged and algosdk reads the spelling as the same
    // address, so only the canonical-spelling check can refuse it.
    for (const [name, c] of Object.entries(vectors.cases)) {
      const spellings = alternateSpellings(c.prepare.rekey_to);
      assert.equal(spellings.length, 3);
      for (const spelling of spellings) {
        assert.equal(algosdk.Address.fromString(spelling).toString(), c.prepare.rekey_to, "algosdk reads the spelling as the address");
        assert.throws(
          () => preparedFrom(c, { ...c.prepare, rekey_to: spelling }),
          (error: unknown) => {
            assert.ok(error instanceof SignerError, String(error));
            assert.match(errorText(error), /invalid rekey_to: .* is not the canonical spelling/, `${name}: ${spelling}`);
            return true;
          },
        );
      }
    }
  });

  it("refuses an account in another spelling of the sender", () => {
    for (const [name, c] of Object.entries(vectors.cases)) {
      for (const spelling of alternateSpellings(c.prepare.account)) {
        assert.throws(() => preparedFrom(c, { ...c.prepare, account: spelling }), /is not the sender/, name);
      }
    }
  });

  it("reads every raw sign answer body as the shared rule says, through the real transport", async (t) => {
    // Each body answers a sign request for its case's own prepared group. The
    // class is the client's: the signed group back (accepted), a plain error
    // (refused), or a sign outcome unknown error carrying the prepared group.
    const bodies = vectors.sign_answer_bodies;
    assert.ok(bodies.length > 0, "no raw sign answer bodies");
    const counts: Record<string, number> = { accepted: 0, refused: 0, unknown: 0 };
    const mismatches: string[] = [];
    for (const entry of bodies) {
      const c = vectors.cases[entry.case];
      assert.ok(c, `raw body names unknown case ${entry.case}`);
      const prepared = preparedFrom(c, c.prepare);
      const restore = installSigners({
        "http://signer.test": (path) => {
          if (path === "/status") return { body: statusBody() };
          if (path === "/sign/rotating/sign") return { raw: entry.body };
          if (path === "/sign/cancel") return { body: { state: "canceled" } };
          throw new Error(`unexpected signer path ${path}`);
        },
      });
      let got: string;
      try {
        const signed = await new SignerClient("http://signer.test").signPreparedRotating(prepared);
        got = "accepted";
        assert.deepEqual(signed.signedGroup, c.sign.signed, `${entry.case}: ${entry.name}: accepted another group`);
      } catch (error) {
        if (error instanceof SignOutcomeUnknownError) {
          got = error.rotating === prepared ? "unknown" : "unknown without the prepared group";
        } else if (error instanceof SignerError) {
          got = "refused";
        } else {
          got = `${error instanceof Error ? error.name : typeof error}: ${errorText(error)}`;
        }
      } finally {
        restore();
      }
      if (got !== entry.expect) {
        mismatches.push(`${entry.case}: ${entry.name}: got ${got}, want ${entry.expect}`);
      } else {
        counts[got]++;
      }
    }
    t.diagnostic(
      `raw sign answers: ${bodies.length} bodies; accepted ${counts.accepted}, refused ${counts.refused}, unknown ${counts.unknown}`,
    );
    assert.deepEqual(mismatches, []);
  });

  it("covers every captured case with alterations", () => {
    for (const name of Object.keys(vectors.cases)) {
      assert.ok(vectors.prepare_tampered.some((entry) => entry.case === name), name);
      assert.ok(vectors.sign_tampered.some((entry) => entry.case === name), name);
    }
  });
});
