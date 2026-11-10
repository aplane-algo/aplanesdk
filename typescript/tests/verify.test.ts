// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

// The client checks every /sign and /plan result against what it asked for.

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import algosdk, { type Transaction } from "algosdk";
import { SignerClient } from "../src/client.js";
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
  validateSignResponse(decodeRequestSlots(requests), body.signed, typedMutations(body.mutations));
}

function checkPlan(requests: SignRequest[], body: any): void {
  validatePlanResponse(
    decodeRequestSlots(requests),
    body.transactions,
    typedMutations(body.mutations),
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
    validateSignResponse(decodeRequestSlots([request]), [signedHexValue], undefined);
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
});
