// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

// The client checks every /sign and /plan result against what it asked for.

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import algosdk, { type Transaction } from "algosdk";
import { SignerClient } from "../src/client.js";
import { MaxFeeIncreaseError, SignerError } from "../src/index.js";
import type { SignRequest } from "../src/types.js";
import { bytesToHex, encodeTransaction, hexToBytes } from "../src/encoding.js";
import {
  decodeCanonicalSignedTransaction,
  decodeRequestSlots,
  signedTransactionMatchesCanonical,
  validatePlanResponse,
  validateSignResponse,
} from "../src/verify.js";
import {
  type FakeSignerOptions,
  authorize,
  decodeSigned,
  encodeSigned,
  fakeAccount,
  fakeAddress,
  fakeLogicSigAccount,
  fakePQAccount,
  holdProgram,
  fakePayment,
  planResponse,
  regroup,
  signEntries,
  signResponse,
  signedHex,
  signerFetch,
} from "./fakeSigner.js";
import { alternateSpellings } from "./fakeNetwork.js";

// The validators read the typed camelCase report the client hands them.
function typedMutations(raw: any) {
  if (!raw) return undefined;
  return {
    dummiesAdded: raw.dummies_added,
    groupIdChanged: raw.group_id_changed,
    feesModified: raw.fees_modified,
    totalFeesDelta: raw.total_fees_delta,
    originalCount: raw.original_count,
    finalCount: raw.final_count,
    passthroughCount: raw.passthrough_count,
    foreignCount: raw.foreign_count,
  };
}

function checkSign(requests: SignRequest[], body: any): void {
  validateSignResponse(
    decodeRequestSlots(requests),
    body.signed,
    typedMutations(body.mutations),
    undefined,
  );
}

function checkPlan(requests: SignRequest[], body: any): void {
  validatePlanResponse(
    decodeRequestSlots(requests),
    body.transactions,
    typedMutations(body.mutations),
    undefined,
  );
}

function pregroupedPair(): Transaction[] {
  return algosdk.assignGroupID([fakePayment(41, 42, 1_000_000), fakePayment(43, 44, 5)]);
}

const single = () => signEntries(fakePayment(41, 42, 1_000_000));
const pair = () => signEntries(fakePayment(41, 42, 1_000_000), fakePayment(43, 44, 5));
const pregrouped = () => signEntries(...pregroupedPair());
const passthrough = () => {
  const txns = pregroupedPair();
  const entries = signEntries(...txns);
  entries[1] = { signed_txn_hex: signedHex(txns[1]) };
  return entries;
};
const foreign = () => {
  const entries = signEntries(...pregroupedPair());
  entries[1] = { txn_bytes_hex: entries[1].txn_bytes_hex };
  return entries;
};

const raised: FakeSignerOptions = { feeRaise: { 0: 2000 } };
const withDummies: FakeSignerOptions = { feeRaise: { 0: 2000 }, dummies: 2 };

/** Replace the transaction inside a signed slot. */
function resign(body: any, index: number, edit: (txn: Transaction) => void): void {
  const txn = decodeSigned(body.signed[index]).txn;
  edit(txn);
  body.signed[index] = signedHex(txn);
}

describe("validateSignResponse", () => {
  const accepted: Array<[string, () => SignRequest[], FakeSignerOptions, number]> = [
    ["single transaction, nothing changed", single, {}, 1],
    // A native Falcon or LogicSig account: the signer raises the fee of an
    // ungrouped transaction and leaves it ungrouped.
    ["single transaction, fee raised", single, raised, 1],
    ["ungrouped pair is grouped", pair, {}, 2],
    ["fee raised and dummies appended", single, withDummies, 3],
    ["pre-grouped pair is returned as sent", pregrouped, {}, 2],
    ["passthrough position", passthrough, {}, 2],
    ["foreign position", foreign, {}, 2],
  ];
  for (const [name, entries, options, want] of accepted) {
    it(`accepts: ${name}`, () => {
      const requests = entries();
      const body = signResponse(requests, options);
      assert.equal(body.signed.length, want);
      checkSign(requests, body);
    });
  }

  const rejected: Array<[string, () => SignRequest[], FakeSignerOptions, (body: any) => void, RegExp]> = [
    [
      "substituted receiver and amount", single, {},
      (body) => {
        body.signed[0] = signedHex(fakePayment(41, 45, 100_000_000));
      },
      /unreported fields at original position 1/,
    ],
    [
      "unreported fee raise", single, {},
      (body) => resign(body, 0, (txn) => { txn.fee += 5000n; }),
      /unreported fields at original position 1/,
    ],
    [
      "fee raise larger than reported total", single, raised,
      (body) => resign(body, 0, (txn) => { txn.fee += 1n; }),
      /total_fees_delta 2000 does not match observed delta 2001/,
    ],
    [
      "reported fee index did not increase", single, raised,
      (body) => resign(body, 0, (txn) => { txn.fee = 1000n; }),
      /did not increase the fee/,
    ],
    [
      "reported fee index decreased the fee", single, raised,
      (body) => resign(body, 0, (txn) => { txn.fee = 999n; }),
      /did not increase the fee/,
    ],
    [
      "negative total fee delta", single, raised,
      (body) => { body.mutations.total_fees_delta = -2000; },
      /total_fees_delta must not be negative/,
    ],
    [
      "duplicated fee index", single, raised,
      (body) => { body.mutations.fees_modified = [0, 0]; },
      /fee index 0 is duplicated/,
    ],
    [
      "fee index outside the request", single, withDummies,
      (body) => { body.mutations.fees_modified = [0, 1]; },
      /fee index 1 is outside original positions/,
    ],
    [
      "fee index on a passthrough position", passthrough, {},
      (body) => { body.mutations.fees_modified = [1]; },
      /fee index 1 is a passthrough position/,
    ],
    [
      "group ID that does not bind the group", pair, {},
      (body) => {
        for (let index = 0; index < body.signed.length; index++) {
          resign(body, index, (txn) => { txn.group = new Uint8Array(32).fill(0x99); });
        }
      },
      /does not carry the canonical group ID/,
    ],
    [
      "group ID changed without a report", pregrouped, {},
      (body) => resign(body, 0, (txn) => { txn.group = new Uint8Array(32).fill(0x99); }),
      /unreported fields at original position 1/,
    ],
    [
      "group ID change reported for one transaction", single, raised,
      (body) => { body.mutations.group_id_changed = true; },
      /group ID change for a single transaction/,
    ],
    [
      "appended payment that is not a dummy", single, withDummies,
      (body) => {
        // A 50 ALGO payment in the dummy's place, regrouped so the group ID
        // is still canonical.
        const txns = body.signed.map((item: string) => decodeSigned(item).txn);
        txns[1] = fakePayment(41, 45, 50_000_000);
        body.signed = regroup(txns).map((txn) => signedHex(txn));
      },
      /appended transaction 1 is not the canonical resource dummy/,
    ],
    [
      "dummy with a different authorization", single, withDummies,
      (body) => { body.signed[2] = signedHex(decodeSigned(body.signed[2]).txn); },
      /appended transaction 2 does not carry the canonical resource dummy authorization/,
    ],
    [
      "dummies_added does not match appended count", single, withDummies,
      (body) => { body.mutations.dummies_added = 1; },
      /dummies_added 1 does not match appended count 2/,
    ],
    [
      "final_count does not match returned count", single, withDummies,
      (body) => { body.mutations.final_count = 2; },
      /final_count 2 does not match returned count 3/,
    ],
    [
      "original_count does not match request", single, raised,
      (body) => { body.mutations.original_count = 2; },
      /original_count 2 does not match request count 1/,
    ],
    [
      "appended without a mutation report", single, withDummies,
      (body) => { delete body.mutations; },
      /appended 2 transaction\(s\) without a mutation report/,
    ],
    [
      "appended without a group ID change", single, withDummies,
      (body) => { body.mutations.group_id_changed = false; },
      /appended dummies without reporting a group ID change/,
    ],
    [
      "trailing bytes after a signed transaction", single, {},
      (body) => { body.signed[0] += body.signed[0]; },
      /signed transaction 1: /,
    ],
    [
      "truncated response", pair, {},
      (body) => { body.signed = body.signed.slice(0, 1); },
      /returned 1 signed transaction\(s\), want at least 2/,
    ],
    [
      "empty signed position", pair, {},
      (body) => { body.signed[1] = ""; },
      /no signature for position 2/,
    ],
    [
      "empty dummy position", single, withDummies,
      (body) => { body.signed[2] = ""; },
      /empty dummy transaction at position 3/,
    ],
    [
      "empty passthrough position", passthrough, {},
      (body) => { body.signed[1] = ""; },
      /no signature for position 2/,
    ],
    [
      "altered passthrough", passthrough, {},
      (body) => { body.signed[1] = signedHex(decodeSigned(body.signed[1]).txn, 9); },
      /signer changed passthrough transaction 2/,
    ],
    [
      "passthrough not reported", passthrough, {},
      (body) => { delete body.mutations; },
      /passthrough_count 0 does not match the 1 passthrough transaction\(s\) requested/,
    ],
    [
      "signed foreign position", foreign, {},
      (body) => { body.signed[1] = signedHex(pregroupedPair()[1]); },
      /signed transaction for foreign position 2/,
    ],
    [
      "foreign count does not match", foreign, {},
      (body) => { body.mutations.foreign_count = 0; },
      /foreign_count 0 does not match the 1 foreign transaction\(s\) requested/,
    ],
  ];
  for (const [name, entries, options, tamper, error] of rejected) {
    it(`rejects: ${name}`, () => {
      const requests = entries();
      const body = signResponse(requests, options);
      checkSign(requests, body);
      tamper(body);
      assert.throws(() => checkSign(requests, body), error);
    });
  }
});

describe("validatePlanResponse", () => {
  const requests = () => {
    const entries = pair();
    entries[1] = { txn_bytes_hex: entries[1].txn_bytes_hex };
    return entries;
  };
  const options: FakeSignerOptions = { feeRaise: { 0: 1000 }, dummies: 1 };

  function replan(body: any, edit: (txns: Transaction[]) => void): void {
    const txns = body.transactions.map((item: string) =>
      algosdk.decodeUnsignedTransaction(hexToBytes(item).slice(2)),
    );
    edit(txns);
    body.transactions = regroup(txns).map((txn) => encodeTransaction(txn)[0]);
  }

  it("accepts a reported fee raise, grouping and dummy with a foreign position", () => {
    const body = planResponse(requests(), options);
    assert.equal(body.transactions.length, 3);
    checkPlan(requests(), body);
  });

  const rejected: Array<[string, (body: any) => void, RegExp]> = [
    [
      "unreported original mutation",
      (body) => replan(body, (txns) => {
        txns[0] = fakePayment(41, 42, 999_999);
        txns[0].fee = 2000n;
      }),
      /unreported fields at original position 1/,
    ],
    [
      "foreign position changed",
      (body) => replan(body, (txns) => { txns[1].fee += 1000n; }),
      /unreported fields at original position 2/,
    ],
    [
      "fee index on a foreign position",
      (body) => { body.mutations.fees_modified = [0, 1]; },
      /fee index 1 is a foreign position/,
    ],
    [
      "non-dummy appended transaction",
      (body) => replan(body, (txns) => {
        const dummy = txns[2].sender.toString();
        txns[2] = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
          sender: dummy,
          receiver: dummy,
          amount: 1,
          note: new Uint8Array([0]),
          suggestedParams: {
            fee: 0, flatFee: true, minFee: 0, firstValid: 10, lastValid: 1010,
            genesisID: "testnet-v1.0", genesisHash: txns[0].genesisHash,
          },
        });
        txns[2].fee = 0n;
      }),
      /appended transaction 1 is not the canonical resource dummy/,
    ],
    [
      "dummy on a different validity window",
      (body) => replan(body, (txns) => { txns[2].lastValid += 1n; }),
      /appended transaction 1 is not the canonical resource dummy/,
    ],
    [
      "missing TX prefix",
      (body) => { body.transactions[0] = body.transactions[0].slice(4); },
      /planned transaction 1: missing TX prefix/,
    ],
    [
      "trailing bytes",
      (body) => { body.transactions[0] += "00"; },
      /planned transaction 1: /,
    ],
    [
      "truncated plan",
      (body) => { body.transactions = body.transactions.slice(0, 1); },
      /returned 1 planned transaction\(s\), want at least 2/,
    ],
  ];
  for (const [name, tamper, error] of rejected) {
    it(`rejects: ${name}`, () => {
      const body = planResponse(requests(), options);
      tamper(body);
      assert.throws(() => checkPlan(requests(), body), error);
    });
  }
});

describe("public sign, plan and simulate calls", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function stubSigner(options: FakeSignerOptions): void {
    globalThis.fetch = (async (url: string, init: any) => {
      if (String(url).endsWith("/status")) {
        return {
          status: 200,
          ok: true,
          json: async () => ({ state: "unlocked", approval_wait_seconds: 60 }),
        };
      }
      return signerFetch(options)(url, init);
    }) as any;
  }

  it("reject a substituted transaction", async () => {
    const txn = fakePayment(41, 42, 1_000_000);
    const other = fakePayment(41, 45, 100_000_000);
    stubSigner({
      tamper: (body) => {
        if (body.signed) body.signed = [signedHex(other)];
        else body.transactions = [encodeTransaction(other)[0]];
      },
    });
    const client = new SignerClient("http://localhost:11270");
    const error = /unreported fields at original position 1/;
    let simulated = false;
    const algod = {
      simulateTransactions: () => {
        simulated = true;
        return { do: async () => ({}) };
      },
    } as any;

    await assert.rejects(client.signTransaction(txn), error);
    await assert.rejects(client.signTransactions([txn]), error);
    await assert.rejects(client.signTransactionsList([txn]), error);
    await assert.rejects(client.signRequests(signEntries(txn)), error);
    await assert.rejects(client.planGroup([txn]), error);
    await assert.rejects(
      client.simulatePreparedGroup(algod, {
        transactions: [{ transaction: txn, authAddress: txn.sender.toString() }],
      }),
      error,
    );
    assert.equal(simulated, false);
  });

  it("accept a raised fee and an appended dummy", async () => {
    const txn = fakePayment(41, 42, 1_000_000);
    stubSigner({ feeRaise: { 0: 2000 }, dummies: 1 });
    const client = new SignerClient("http://localhost:11270");

    const signed = await client.signTransactionsList([txn]);
    assert.equal(signed.length, 2);
    const first = algosdk.decodeSignedTransaction(Buffer.from(signed[0], "base64"));
    assert.equal(first.txn.fee, txn.fee + 2000n);

    const plan = await client.planGroup([txn]);
    assert.equal(plan.transactions.length, 2);
    assert.equal(plan.mutations?.dummiesAdded, 1);
  });
});

describe("signed transaction identity checks", () => {
  it("reject trailing bytes and non-canonical wrappers", () => {
    const txn = fakePayment(41, 42, 1);
    const other = fakePayment(41, 45, 2);
    const canonicalHex = encodeTransaction(txn)[0];
    const signed = signedHex(txn);

    signedTransactionMatchesCanonical("slot", 0, signed, canonicalHex);

    // A second signed transaction after the first.
    const concatenated = signed + signedHex(other);
    // The same signed transaction with its keys out of canonical order. The
    // canonical bytes are a two-entry map: the 70-byte sig entry, then txn.
    const raw = hexToBytes(signed);
    const reordered = bytesToHex(
      new Uint8Array([raw[0], ...raw.slice(71), ...raw.slice(1, 71)]),
    );
    assert.deepEqual(
      algosdk.decodeSignedTransaction(hexToBytes(reordered)).txn.toByte(),
      txn.toByte(),
      "the reordered bytes still decode as the same signed transaction",
    );

    for (const bad of [concatenated, reordered]) {
      assert.throws(
        () => signedTransactionMatchesCanonical("slot", 0, bad, canonicalHex),
        /slot 0: /,
      );
      assert.throws(() => decodeCanonicalSignedTransaction(hexToBytes(bad)));
    }
    assert.throws(
      () => signedTransactionMatchesCanonical("slot", 0, signedHex(other), canonicalHex),
      /does not match the submitted canonical bytes/,
    );
  });

  it("require canonical request bytes", () => {
    const txn = fakePayment(41, 42, 1);
    const canonical = encodeTransaction(txn)[0];
    const signed = signedHex(txn);
    const bad: SignRequest[] = [
      { auth_address: fakeAddress(41), txn_bytes_hex: canonical.slice(4) },
      { auth_address: fakeAddress(41), txn_bytes_hex: `${canonical}00` },
      { signed_txn_hex: signed + signed },
    ];
    for (const entry of bad) {
      assert.throws(() => decodeRequestSlots([entry]), /transaction 1: /);
    }
    assert.deepEqual(decodeRequestSlots(signEntries(txn))[0].txn.toByte(), txn.toByte());
  });
});

describe("maxFeeIncrease", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function stubSigner(options: FakeSignerOptions): void {
    globalThis.fetch = (async (url: string, init: any) => {
      if (String(url).endsWith("/status")) {
        return {
          status: 200,
          ok: true,
          json: async () => ({ state: "unlocked", approval_wait_seconds: 60 }),
        };
      }
      return signerFetch(options)(url, init);
    }) as any;
  }

  const txnsFor = (count: number) =>
    [fakePayment(41, 42, 1_000_000), fakePayment(43, 44, 5)].slice(0, count);

  type Case = [
    name: string,
    limit: number | bigint | undefined,
    feeRaise: Record<number, number>,
    count: number,
    refused?: [raised: number, ceiling: number],
  ];
  const cases: Case[] = [
    // Unset is unbounded: a reported raise of any size is accepted.
    ["unset, large raise", undefined, { 0: 5_000_000 }, 1],
    ["above the raise", 200_000, { 0: 3000 }, 1],
    ["equal to the raise", 3000, { 0: 3000 }, 1],
    ["equal to the raise, as a bigint", 3000n, { 0: 3000 }, 1],
    ["one below the raise", 2999, { 0: 3000 }, 1, [3000, 2999]],
    ["zero with a raise", 0, { 0: 1 }, 1, [1, 0]],
    ["zero with no raise", 0, {}, 2],
    ["a raise spread over two positions is summed", 4999n, { 0: 2000, 1: 3000 }, 2, [5000, 4999]],
    ["two positions at the sum", 5000, { 0: 2000, 1: 3000 }, 2],
  ];
  for (const [name, limit, feeRaise, count, refused] of cases) {
    it(name, async () => {
      stubSigner({ feeRaise });
      const client = new SignerClient("http://localhost:11270", undefined, null, {
        maxFeeIncrease: limit,
      });
      const txns = txnsFor(count);
      let simulated = 0;
      const algod = {
        simulateTransactions: () => {
          simulated++;
          return { do: async () => ({ txnGroups: [{}] }) };
        },
      } as any;
      const prepared = {
        transactions: txns.map((txn) => ({ transaction: txn, authAddress: txn.sender.toString() })),
      };
      const calls: Array<[string, () => Promise<unknown>]> = [
        ["response", () => client.signTransactions(txns)],
        ["response", () => client.signTransactionsList(txns)],
        ["response", () => client.signRequests(signEntries(...txns))],
        ["plan", () => client.planGroup(txns)],
        ["response", () => client.simulatePreparedGroup(algod, prepared)],
      ];
      for (const [kind, call] of calls) {
        if (!refused) {
          await call();
          continue;
        }
        await assert.rejects(call(), {
          name: "MaxFeeIncreaseError",
          message:
            `verify signer ${kind}: signer raised fees by ${refused[0]} microAlgos, ` +
            `more than the max fee increase ${refused[1]} set on this client`,
        });
      }
      assert.equal(simulated, refused ? 0 : 1);
    });
  }

  it("ignores zero-fee dummies", async () => {
    stubSigner({ feeRaise: { 0: 2000 }, dummies: 2 });
    const client = new SignerClient("http://localhost:11270", undefined, null, {
      maxFeeIncrease: 2000,
    });
    assert.equal((await client.signTransactionsList([fakePayment()])).length, 3);
  });

  it("has no default, and can be set, changed and removed", async () => {
    const client = new SignerClient("http://localhost:11270");
    assert.equal(client.maxFeeIncrease, undefined);
    client.maxFeeIncrease = 0;
    assert.equal(client.maxFeeIncrease, 0);
    client.maxFeeIncrease = 250_000n;
    assert.equal(client.maxFeeIncrease, 250_000n);
    client.maxFeeIncrease = undefined;
    assert.equal(client.maxFeeIncrease, undefined);

    const invalid = /maxFeeIncrease must be a non-negative whole number/;
    for (const bad of [-1, 1.5, Number.NaN, -1n, "1000" as any]) {
      assert.throws(() => { client.maxFeeIncrease = bad; }, invalid);
      assert.throws(
        () => new SignerClient("http://localhost:11270", undefined, null, { maxFeeIncrease: bad }),
        invalid,
      );
      // Refused before any connection is attempted.
      await assert.rejects(
        SignerClient.connectSsh("signer.invalid", "/nonexistent/key", { maxFeeIncrease: bad }),
        invalid,
      );
    }
    assert.equal(client.maxFeeIncrease, undefined, "a refused value must not become the setting");
  });

  // A getter alone would let `client.maxFeeIncrease = 0` vanish in plain
  // JavaScript and leave the client unbounded.
  it("is enforced when assigned as a property", async () => {
    stubSigner({ feeRaise: { 0: 3000 } });
    const client = new SignerClient("http://localhost:11270");
    const txn = fakePayment();

    (client as any).maxFeeIncrease = 0;
    assert.equal(client.maxFeeIncrease, 0);
    await assert.rejects(client.signTransaction(txn), /more than the max fee increase 0 set on this client/);

    client.maxFeeIncrease = 3000n;
    await client.signTransaction(txn);

    client.maxFeeIncrease = undefined;
    assert.equal(client.maxFeeIncrease, undefined);
    await client.signTransaction(txn);
  });

  it("reads back as it was set", () => {
    const fromNumber = new SignerClient("http://localhost:11270", undefined, null, {
      maxFeeIncrease: 250_000,
    });
    assert.strictEqual(fromNumber.maxFeeIncrease, 250_000);
    assert.equal(JSON.stringify({ maxFeeIncrease: fromNumber.maxFeeIncrease }), '{"maxFeeIncrease":250000}');
    // A copy of the setting configures another client the same way.
    const copy = new SignerClient("http://localhost:11270", undefined, null, {
      maxFeeIncrease: fromNumber.maxFeeIncrease,
    });
    assert.strictEqual(copy.maxFeeIncrease, 250_000);

    const fromBigint = new SignerClient("http://localhost:11270", undefined, null, {
      maxFeeIncrease: 250_000n,
    });
    assert.strictEqual(fromBigint.maxFeeIncrease, 250_000n);
  });

  it("refuses with a typed error carrying the raise and the limit", async () => {
    stubSigner({ feeRaise: { 0: 2000, 1: 3000 } });
    const client = new SignerClient("http://localhost:11270", undefined, null, {
      maxFeeIncrease: 4999,
    });
    const txns = txnsFor(2);
    const calls: Array<[string, () => Promise<unknown>]> = [
      ["verify signer response: ", () => client.signTransactions(txns)],
      ["verify signer plan: ", () => client.planGroup(txns)],
    ];
    for (const [prefix, call] of calls) {
      await assert.rejects(call(), (error: unknown) => {
        assert.ok(error instanceof MaxFeeIncreaseError);
        assert.ok(error instanceof SignerError);
        assert.equal(error.name, "MaxFeeIncreaseError");
        assert.equal(error.raised, 5000n);
        assert.equal(error.limit, 4999n);
        assert.equal(
          error.message,
          `${prefix}signer raised fees by 5000 microAlgos, more than the max fee increase 4999 set on this client`,
        );
        return true;
      });
    }

    // Any other verification failure is a plain SignerError.
    stubSigner({ tamper: (body) => { if (body.signed) body.signed[0] = ""; } });
    await assert.rejects(client.signTransactions(txns), (error: unknown) => {
      assert.ok(error instanceof SignerError);
      assert.ok(!(error instanceof MaxFeeIncreaseError));
      return true;
    });
  });

  it("serializes its refusal to JSON with the amounts as decimal strings", () => {
    const error = new MaxFeeIncreaseError(5000n, 4999n, "verify signer response: ");
    assert.equal(typeof error.raised, "bigint");
    assert.deepEqual(JSON.parse(JSON.stringify(error)), {
      name: "MaxFeeIncreaseError",
      message:
        "verify signer response: signer raised fees by 5000 microAlgos, more than the max fee increase 4999 set on this client",
      raised: "5000",
      limit: "4999",
    });
    assert.equal(JSON.parse(JSON.stringify({ error })).error.limit, "4999");
  });

  it("refuses options that are not an object", () => {
    const invalid = /SignerClient options must be an object/;
    for (const bad of [200_000, 200_000n, "200000", true] as any[]) {
      assert.throws(() => new SignerClient("http://localhost:11270", undefined, null, bad), invalid);
    }
    for (const fine of [undefined, null, {}] as any[]) {
      const client = new SignerClient("http://localhost:11270", undefined, null, fine);
      assert.equal(client.maxFeeIncrease, undefined);
    }
  });

  it("requires the validators to be told the ceiling", () => {
    // Not optional parameters: leaving the ceiling out does not type-check,
    // so a new caller cannot skip the check by omission.
    assert.equal(validateSignResponse.length, 4);
    assert.equal(validatePlanResponse.length, 4);
  });

  it("gets a valid ceiling past validation and on to the connection", async () => {
    // A valid value is not what stops this call: with nothing listening, it
    // fails at the SSH connection, not at the ceiling check.
    await assert.rejects(
      SignerClient.connectSsh("127.0.0.1", "/nonexistent/key", {
        maxFeeIncrease: 250_000,
        sshPort: 1,
        knownHostsPath: "/nonexistent/known_hosts",
        sshSetupTimeout: 2000,
      }),
      (error: Error) => {
        assert.doesNotMatch(error.message, /maxFeeIncrease/);
        return true;
      },
    );
  });

  it("is no longer settable through a method", () => {
    const client = new SignerClient("http://localhost:11270");
    assert.equal((client as any).setMaxFeeIncrease, undefined);
  });

  it("treats null options as no options", () => {
    const client = new SignerClient("http://localhost:11270", undefined, null, null);
    assert.equal(client.maxFeeIncrease, undefined);
    const nullField = new SignerClient("http://localhost:11270", undefined, null, {
      maxFeeIncrease: null as any,
    });
    assert.equal(nullField.maxFeeIncrease, undefined);
  });

  // A call is held to the ceiling in force when it started. Removing it
  // while the signer is still waiting for approval lets nothing through.
  it("is snapshotted when the call starts", async () => {
    const txn = fakePayment();
    const client = new SignerClient("http://localhost:11270", undefined, null, {
      maxFeeIncrease: 1000,
    });
    let release: () => void = () => {};
    let arrived: () => void = () => {};
    let hold = true;
    globalThis.fetch = (async (url: string, init: any) => {
      if (String(url).endsWith("/status")) {
        return { status: 200, ok: true, json: async () => ({ state: "unlocked", approval_wait_seconds: 60 }) };
      }
      if (hold) {
        const released = new Promise<void>((resolve) => { release = resolve; });
        arrived();
        await released;
      }
      return signerFetch({ feeRaise: { 0: 3000 } })(url, init);
    }) as any;
    const refused = /more than the max fee increase 1000 set on this client/;

    for (const start of [
      () => client.signTransaction(txn),
      () => client.planGroup([txn]),
    ]) {
      client.maxFeeIncrease = 1000;
      const requestSent = new Promise<void>((resolve) => { arrived = resolve; });
      const call = start();
      const outcome = assert.rejects(call, refused);
      await requestSent;
      client.maxFeeIncrease = undefined;
      release();
      await outcome;
    }

    // A call started with no ceiling is not held to one.
    hold = false;
    await client.signTransaction(txn);
  });
});

// A signed position must carry exactly one authorization, and it must be the
// requested auth address's. The Go and Python suites run the same list.
describe("authorization of a signed position", () => {
  const ed = fakeAccount(41);
  const other = fakeAccount(45);
  const lsig = fakeLogicSigAccount(1);
  fakeLogicSigAccount(2);
  const pq = fakePQAccount(3);
  const otherPQ = fakePQAccount(4);
  const dummyProgram = new Uint8Array([0x03, 0x31, 0x20, 0x32, 0x03, 0x12]);
  const dummy = holdProgram(dummyProgram);

  function check(txn: Transaction, auth: string, signedHexValue: string): void {
    const sender = txn.sender.toString();
    const request = { auth_address: auth, txn_sender: sender, txn_bytes_hex: encodeTransaction(txn)[0] };
    validateSignResponse(decodeRequestSlots([request]), [signedHexValue], undefined, undefined);
  }

  const accepted: Array<[string, string, string]> = [
    ["ed25519, sender signs", ed, ed],
    ["ed25519, rekeyed sender", other, ed],
    ["LogicSig account", lsig, lsig],
    ["LogicSig account, rekeyed sender", ed, lsig],
    ["native Falcon account", pq, pq],
    ["native Falcon account, rekeyed sender", ed, pq],
    ["the dummy program, when it is the auth address", dummy, dummy],
  ];
  for (const [name, sender, auth] of accepted) {
    it(`accepts ${name}`, () => {
      const txn = fakePayment(41, 42, 1_000_000, sender);
      check(txn, auth, encodeSigned(authorize(txn, auth)));
    });
  }

  type Fields = Record<string, any>;
  const raw = (signed: algosdk.SignedTransaction): Fields =>
    algosdk.msgpackRawDecode(algosdk.encodeMsgpack(signed)) as Fields;
  // msgpackRawEncode writes canonical msgpack: sorted keys, as the Algorand
  // libraries do.
  const pack = (fields: Fields): string => bytesToHex(algosdk.msgpackRawEncode(fields));
  /** Edit the signed transaction's top-level wire fields; undefined removes one. */
  const edit = (changes: Record<string, unknown | ((fields: Fields) => unknown)>) =>
    (signed: algosdk.SignedTransaction): string => {
      const fields = raw(signed);
      for (const [name, value] of Object.entries(changes)) {
        const next = typeof value === "function" ? (value as (f: Fields) => unknown)(fields) : value;
        if (next === undefined) delete fields[name];
        else fields[name] = next;
      }
      return pack(fields);
    };
  const resign = (auth: string, stripSigner = false) =>
    (signed: algosdk.SignedTransaction): string => {
      const fields = raw(authorize(signed.txn, auth));
      if (stripSigner) delete fields.sgnr;
      return pack(fields);
    };
  const otherBytes = algosdk.decodeAddress(other).publicKey;

  const refused: Array<[string, string, string, (signed: algosdk.SignedTransaction) => string, RegExp]> = [
    ["an unsigned wrapper", ed, ed, edit({ sig: undefined }), /carries no authorization/],
    [
      "a signature by another key", ed, ed, resign(other, true),
      /signature does not verify under the requested auth address/,
    ],
    [
      "a signature over another transaction", ed, ed,
      edit({ sig: () => raw(authorize(fakePayment(41, 45, 5), ed)).sig }),
      /signature does not verify under the requested auth address/,
    ],
    [
      "the dummy LogicSig on an original position", ed, ed,
      edit({ sig: undefined, lsig: { l: dummyProgram } }),
      new RegExp(`LogicSig program address ${dummy} is not the requested auth address`),
    ],
    [
      "the dummy LogicSig naming itself as signer", ed, ed, resign(dummy),
      new RegExp(`names signer ${dummy}, but the sender signs for itself`),
    ],
    [
      "another LogicSig program", lsig, lsig,
      edit({ lsig: (fields: Fields) => ({ ...fields.lsig, l: new Uint8Array([0x06, 0x81, 2]) }) }),
      /is not the requested auth address/,
    ],
    [
      "a LogicSig delegated by a signature", lsig, lsig,
      edit({ lsig: (fields: Fields) => ({ ...fields.lsig, sig: new Uint8Array(64).fill(1) }) }),
      /LogicSig is delegated by a signature/,
    ],
    ["a wrong signer field", other, ed, edit({ sgnr: otherBytes }), /not the requested auth address/],
    [
      "a missing signer field for a rekeyed sender", other, ed, edit({ sgnr: undefined }),
      /does not name its signer/,
    ],
    [
      "a signer field when the sender signs", ed, ed, edit({ sgnr: otherBytes }),
      /but the sender signs for itself/,
    ],
    [
      "a multisig", ed, ed,
      (signed) => encodeSigned(new algosdk.SignedTransaction({
        txn: signed.txn,
        msig: { v: 1, thr: 1, subsig: [{ pk: otherBytes }] },
      })),
      /carries a multisig/,
    ],
    [
      "two authorizations", ed, ed, edit({ lsig: { l: new Uint8Array([0x06, 0x81, 1]) } }),
      /signed transaction 1/,
    ],
    [
      "a post-quantum proof with no signature", pq, pq,
      edit({ pqsig: (fields: Fields) => ({ ...fields.pqsig, sig: new Uint8Array() }) }),
      /signed transaction 1/,
    ],
    [
      "a post-quantum proof with another scheme", pq, pq,
      edit({ pqsig: (fields: Fields) => ({ ...fields.pqsig, sch: new Uint8Array([0x78, 0x39]) }) }),
      /post-quantum scheme/,
    ],
    [
      "another post-quantum key", pq, pq,
      edit({ pqsig: () => raw(authorize(fakePayment(41, 42, 1, otherPQ), otherPQ)).pqsig }),
      /post-quantum key's address/,
    ],
  ];
  for (const [name, sender, auth, tamper, error] of refused) {
    it(`refuses ${name}`, () => {
      const txn = fakePayment(41, 42, 1_000_000, sender);
      const signed = authorize(txn, auth);
      check(txn, auth, encodeSigned(signed));
      assert.throws(() => check(txn, auth, tamper(signed)), (thrown: Error) => {
        assert.match(thrown.message, /^signed transaction 1/);
        assert.match(thrown.message, error);
        return true;
      });
    });
  }

  it("refuses a request whose auth address is not an address", async () => {
    const txn = fakePayment();
    assert.throws(
      () => decodeRequestSlots([{ auth_address: "AUTH", txn_bytes_hex: encodeTransaction(txn)[0] }]),
      /auth_address "AUTH" is not a valid address/,
    );
    const client = new SignerClient("http://localhost:11270");
    await assert.rejects(client.signTransaction(txn, "AUTH"), /is not a valid address/);
  });

  // algosdk reads an alternate spelling (the unused low bits of the last
  // character set otherwise) as the address; the Go and Python SDKs refuse
  // it, and so does the request, before anything is posted.
  it("refuses an auth address that is not spelled canonically, before posting", async () => {
    const txn = fakePayment();
    const sender = txn.sender.toString();
    const previous = globalThis.fetch;
    const posted: string[] = [];
    globalThis.fetch = (async (url: unknown) => {
      posted.push(String(url));
      throw new TypeError("fetch failed: nothing should be posted");
    }) as typeof fetch;
    try {
      for (const spelling of alternateSpellings(sender)) {
        assert.ok(algosdk.isValidAddress(spelling), `algosdk reads ${spelling} as an address`);
        const want = `auth_address ${spelling} is not the canonical spelling of ${sender}`;
        assert.throws(
          () => decodeRequestSlots([{ auth_address: spelling, txn_bytes_hex: encodeTransaction(txn)[0] }]),
          (error: unknown) => error instanceof SignerError && error.message === `transaction 1: ${want}`,
        );
        const client = new SignerClient("http://localhost:11270");
        await assert.rejects(client.signTransaction(txn, spelling), (error: unknown) => {
          assert.ok(error instanceof SignerError, String(error));
          assert.ok((error as Error).message.includes(want), (error as Error).message);
          return true;
        });
        await assert.rejects(
          client.signRequests([{ auth_address: spelling, txn_bytes_hex: encodeTransaction(txn)[0] }]),
          (error: unknown) => error instanceof SignerError && (error as Error).message.includes(want),
        );
      }
    } finally {
      globalThis.fetch = previous;
    }
    assert.deepEqual(posted, []);
  });
});

// A request that already carries a group ID is immutable to the signer, so a
// response that regroups it, raises a fee on it or appends to it is refused:
// the positions the signer did not return stay bound to the original group.
describe("a request that is already grouped", () => {
  const groupedSingle = () => signEntries(pregroupedPair()[0]);
  const ungroupedWithForeign = () => {
    const entries = pair();
    entries[1] = { txn_bytes_hex: entries[1].txn_bytes_hex };
    return entries;
  };
  const regrouped = /group ID change for a request that was already grouped/;

  const refused: Array<[string, () => SignRequest[], FakeSignerOptions, RegExp]> = [
    ["fee raised and regrouped, with a foreign position", foreign, { feeRaise: { 0: 2000 } }, regrouped],
    ["a dummy appended, with a foreign position", foreign, { dummies: 1 }, regrouped],
    ["fee raised and regrouped, every position signed", pregrouped, { feeRaise: { 0: 2000 } }, regrouped],
    [
      "fee raised on a single grouped transaction", groupedSingle, { feeRaise: { 0: 2000 } },
      /fee change for a request that was already grouped/,
    ],
  ];
  for (const [name, entries, options, error] of refused) {
    it(`refuses ${name}`, () => {
      const requests = entries();
      assert.throws(() => checkSign(requests, signResponse(requests, options)), error);
      assert.throws(() => checkPlan(requests, planResponse(requests, options)), error);
    });
  }

  const accepted: Array<[string, () => SignRequest[], FakeSignerOptions]> = [
    ["a grouped request returned as sent, with a foreign position", foreign, {}],
    ["a grouped request returned as sent, every position signed", pregrouped, {}],
    // The signer does group an ungrouped request that has a foreign position,
    // and may raise the fee of a position it signs in it.
    ["an ungrouped request with a foreign position, grouped", ungroupedWithForeign, {}],
    [
      "an ungrouped request with a foreign position, fee raised and a dummy",
      ungroupedWithForeign, { feeRaise: { 0: 2000 }, dummies: 1 },
    ],
  ];
  for (const [name, entries, options] of accepted) {
    it(`accepts ${name}`, () => {
      const requests = entries();
      checkSign(requests, signResponse(requests, options));
    });
  }
});

// Requests and the responses a live signer returned for them. The fake signer
// builds its dummies with the helpers under test, so these are what show the
// SDK's idea of a canonical dummy is the signer's.
describe("captured signer responses", () => {
  const vectors = JSON.parse(
    fs.readFileSync(
      path.resolve(
        path.dirname(fileURLToPath(import.meta.url)),
        "../../contracts/signerapi_vectors/real_sign_responses.json",
      ),
      "utf8",
    ),
  ) as Record<string, { request: { requests: SignRequest[] }; response: any }>;
  // The slot whose last byte is flipped: the appended dummy where there is
  // one, otherwise the first signed transaction.
  const tamperSlot: Record<string, number> = {
    logicsig_falcon_single: 1,
    logicsig_falcon_pair: 2,
    native_falcon_single: 0,
    ed25519_pair: 0,
  };

  it("are the expected cases", () => {
    assert.deepEqual(Object.keys(vectors).sort(), Object.keys(tamperSlot).sort());
  });

  for (const name of Object.keys(tamperSlot)) {
    it(`accepts ${name}, and refuses it with one byte flipped`, () => {
      const { request, response } = vectors[name];
      checkSign(request.requests, response);

      const raw = hexToBytes(response.signed[tamperSlot[name]]);
      raw[raw.length - 1] ^= 0x01;
      const signed = [...response.signed];
      signed[tamperSlot[name]] = bytesToHex(raw);
      assert.throws(() => checkSign(request.requests, { ...response, signed }));
    });
  }

  const rewrite = (signedHexValue: string, edit: (fields: Record<string, any>) => void): string => {
    const fields = algosdk.msgpackRawDecode(hexToBytes(signedHexValue)) as Record<string, any>;
    edit(fields);
    return bytesToHex(algosdk.msgpackRawEncode(fields));
  };

  it("refuses an Ed25519 signature with one byte flipped", () => {
    const { request, response } = vectors.ed25519_pair;
    const signed = [...response.signed];
    signed[0] = rewrite(signed[0], (fields) => {
      fields.sig = Uint8Array.from(fields.sig);
      fields.sig[0] ^= 0x01;
    });
    assert.throws(
      () => checkSign(request.requests, { ...response, signed }),
      /signature does not verify under the requested auth address/,
    );
  });

  it("refuses a dummy whose authorization is changed", () => {
    const { request, response } = vectors.logicsig_falcon_single;
    const signed = [...response.signed];
    signed[1] = rewrite(signed[1], (fields) => {
      fields.lsig = { ...fields.lsig, arg: [new Uint8Array([1])] };
    });
    assert.throws(
      () => checkSign(request.requests, { ...response, signed }),
      /appended transaction 1 does not carry the canonical resource dummy authorization/,
    );
  });
});
