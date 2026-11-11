// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

// The rotating account flow, ported from the Go SDK's rotating_test.go.

import { describe, it, afterEach, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import algosdk, { type Transaction } from "algosdk";
import { SignerClient } from "../src/client.js";
import {
  AuthenticationError,
  KeyNotFoundError,
  MaxFeeIncreaseError,
  RotatingPreflightError,
  SignerError,
  SignerUnavailableError,
  SigningRejectedError,
  SignOutcomeUnknownError,
  UnsupportedGroupError,
  errorText,
} from "../src/errors.js";
import {
  ERROR_CODE_ROTATING_WINDOW_NOT_CURRENT,
  ErrorCodes,
  SIGNING_FLOW_ROTATING1,
  type PreparedGroup,
} from "../src/types.js";
import {
  PreparedRotating,
  ROTATING_MAX_LEAD,
  ROTATING_MAX_VALIDITY_WINDOW,
  ROTATING_MIN_REMAINING,
  checkRotatingWindow,
  rotatingTiming,
  rotatingWindowCurrent,
} from "../src/rotating.js";
import { bytesToBase64, bytesToHex, encodeTransaction, hexToBytes } from "../src/encoding.js";
import { canonicalDummyTransaction, cloneTransaction, groupIDBytes, signCanonicalDummy } from "../src/verify.js";
import { fakeAccount, fakeAddress, regroup } from "./fakeSigner.js";
import {
  FakeAlgod,
  alternateSpellings,
  blobHex,
  installSigners,
  passingGroupResult,
  statusBody,
  testGenesisHash,
  type FakeReply,
  type WireKey,
} from "./fakeNetwork.js";

const SIGNER = "http://signer.test";

let restore: (() => void) | undefined;
afterEach(() => {
  restore?.();
  restore = undefined;
});

// A stage program for tests. Its address stands for a stage's.
const rotatingTestProgram = new Uint8Array([0x0a, 0x81, 0x01]);
// A program other than the stage that signs.
const rotatingNextProgram = new Uint8Array([0x0a, 0x81, 0x02]);
// An address no fixture uses.
const elsewhere = (() => {
  const bytes = new Uint8Array(32);
  bytes[0] = 0x55;
  return new algosdk.Address(bytes);
})();

function stageAddress(program: Uint8Array): algosdk.Address {
  return new algosdk.LogicSig(program).address();
}

type Mutable<T> = { -readonly [K in keyof T]: T[K] };
/**
 * A transaction with its fields writable, for a test that alters one, as a
 * signer that changed a field would.
 */
function writable(txn: Transaction): any {
  return txn;
}

interface ErrorBody {
  error: string;
  code: string;
}

/**
 * A fake signer holding one rotating account. It prepares and signs as the
 * real one does, and lets a test alter either answer.
 */
class RotatingSigner {
  account: string;
  stage: number;
  program: Uint8Array;
  dummies: number;
  charge: bigint;
  /** Change an answer before it is sent. */
  alterPrepare?: (response: any, txns: Transaction[]) => void;
  alterSign?: (response: any, signed: algosdk.SignedTransaction[]) => void;
  /** Answered, in order, before any success. A null entry closes the connection with no answer. */
  prepareErrors: (ErrorBody | null)[] = [];
  signErrors: (ErrorBody | null)[] = [];
  errorStatus = 0;

  paths: string[] = [];
  prepareSeen: Transaction[] = [];
  signRequests: any[] = [];
  cancelRequests: any[] = [];

  constructor(options: { account: string; stage: number; program: Uint8Array; dummies?: number; charge?: bigint }) {
    this.account = options.account;
    this.stage = options.stage;
    this.program = options.program;
    this.dummies = options.dummies ?? 0;
    this.charge = options.charge ?? 0n;
  }

  count(path: string): number {
    return this.paths.filter((entry) => entry === path).length;
  }

  nextTarget(): algosdk.Address {
    const bytes = new Uint8Array(32);
    bytes[0] = 0xaa;
    bytes[31] = this.stage + 1;
    return new algosdk.Address(bytes);
  }

  private fail(queue: (ErrorBody | null)[]): FakeReply | undefined {
    if (queue.length === 0) return undefined;
    const failure = queue.shift() as ErrorBody | null;
    if (failure === null) return "drop";
    let status = this.errorStatus || 409;
    if (failure.code === ErrorCodes.BadRequest) status = 400;
    return { status, body: failure };
  }

  handle = (path: string, body: any): FakeReply => {
    this.paths.push(path);
    switch (path) {
      case "/status":
        return { body: statusBody() };
      case "/keys":
        return {
          body: {
            count: 1,
            keys: [{ address: this.account, key_type: "aplane.rotating-triple-wotsc.v1", signing_flow: SIGNING_FLOW_ROTATING1 }],
          },
        };
      case "/sign/rotating/prepare": {
        const txn = algosdk.decodeUnsignedTransaction(hexToBytes(body.txn_bytes_hex).slice(2));
        this.prepareSeen.push(txn);
        const failure = this.fail(this.prepareErrors);
        if (failure) return failure;
        const { response, txns } = this.prepare(txn);
        this.alterPrepare?.(response, txns);
        return { body: response };
      }
      case "/sign/rotating/sign": {
        this.signRequests.push(body);
        const failure = this.fail(this.signErrors);
        if (failure) return failure;
        const { response, signed } = this.sign(body);
        this.alterSign?.(response, signed);
        return { body: response };
      }
      case "/sign/cancel":
        this.cancelRequests.push(body);
        return { body: { state: "canceled" } };
      default:
        throw new Error(`unexpected signer path ${path}`);
    }
  };

  // The group the real signer would build: the spend with the rotation rekey
  // and the authorization charge, then canonical dummies, grouped.
  prepare(original: Transaction): { response: any; txns: Transaction[] } {
    const spend = cloneTransaction(original);
    writable(spend).rekeyTo = this.nextTarget();
    spend.fee += this.charge;
    const txns: Transaction[] = [spend];
    for (let index = 0; index < this.dummies; index++) {
      txns.push(canonicalDummyTransaction(original, undefined, index));
    }
    let report: any;
    if (this.dummies > 0 || this.charge > 0n) {
      report = { original_count: 1, final_count: txns.length, dummies_added: this.dummies };
      if (this.charge > 0n) {
        report.fees_modified = [0];
        report.total_fees_delta = Number(this.charge);
      }
    }
    if (txns.length > 1) {
      regroup(txns);
      report.group_id_changed = true;
    }
    const response: any = {
      account: this.account,
      stage: this.stage,
      target: this.stage + 1,
      rekey_to: this.nextTarget().toString(),
      mutations: report,
    };
    setPrepared(response, txns);
    return { response, txns };
  }

  sign(request: any): { response: any; signed: algosdk.SignedTransaction[] } {
    const signed = (request.transactions as string[]).map((txnHex, index) => {
      const txn = algosdk.decodeUnsignedTransaction(hexToBytes(txnHex).slice(2));
      if (index === 0) {
        const lsig = new algosdk.LogicSig(this.program, [new Uint8Array([1, 2, 3])]);
        const stage = stageAddress(this.program);
        const sgnr = stage.toString() !== txn.sender.toString() ? stage : undefined;
        return new algosdk.SignedTransaction({ txn, lsig, sgnr });
      }
      return algosdk.decodeSignedTransaction(signCanonicalDummy(txn));
    });
    const spend = signed[0].txn;
    const response: any = {
      stage: this.stage,
      target: this.stage + 1,
      txid: spend.txID(),
      // A Go signer encodes a lone spend's zero group digest.
      group_id: bytesToBase64(groupIDBytes(spend) ?? new Uint8Array(32)),
    };
    setSigned(response, signed);
    return { response, signed };
  }
}

function setPrepared(response: any, txns: Transaction[]): void {
  response.transactions = txns.map((txn) => encodeTransaction(txn)[0]);
}

function setSigned(response: any, signed: algosdk.SignedTransaction[]): void {
  response.signed = signed.map((entry) => bytesToHex(algosdk.encodeMsgpack(entry)));
}

/** A payment from sender with the given validity rounds. */
function rotatingPayment(sender: string, first: number, last: number): Transaction {
  return algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender,
    receiver: fakeAddress(42),
    amount: 5000,
    suggestedParams: {
      fee: 1000, flatFee: true, minFee: 1000, firstValid: first, lastValid: last,
      genesisID: "testnet-v1.0", genesisHash: testGenesisHash,
    },
  });
}

/**
 * A rotating account at stage 3 whose spends need one dummy and a 1,000
 * microAlgo charge, and a node at round 10.
 */
function rotatingFixture(options: { account?: string; stage?: number; dummies?: number; charge?: bigint } = {}) {
  const signer = new RotatingSigner({
    account: options.account ?? fakeAccount(41),
    stage: options.stage ?? 3,
    program: rotatingTestProgram,
    dummies: options.dummies ?? 1,
    charge: options.charge ?? 1000n,
  });
  const node = new FakeAlgod();
  restore = installSigners({ [SIGNER]: signer.handle });
  const client = new SignerClient(SIGNER);
  return { signer, node, algod: node as any, client, txn: rotatingPayment(signer.account, 10, 110) };
}

function rotatingGroup(txn: Transaction, extra: Partial<PreparedGroup["transactions"][number]> = {}): PreparedGroup {
  return { transactions: [{ transaction: txn, authAddress: txn.sender.toString(), ...extra }] };
}

function refusal(code: string, message: string): ErrorBody {
  return { error: message, code };
}

function codeOf(error: unknown): string {
  return error instanceof SignerError ? error.code : "";
}

/** Assert a rejection whose message contains every one of texts. */
function mentions(...texts: Array<string | RegExp>) {
  return (error: unknown) => {
    const message = errorText(error);
    for (const text of texts) {
      if (typeof text === "string") {
        assert.ok(message.includes(text), `error ${JSON.stringify(message)} does not mention ${JSON.stringify(text)}`);
      } else {
        assert.match(message, text);
      }
    }
    return true;
  };
}

const oldBackoff = rotatingTiming.unprovenBackoffMs;
beforeEach(() => {
  rotatingTiming.unprovenBackoffMs = 1;
});
afterEach(() => {
  rotatingTiming.unprovenBackoffMs = oldBackoff;
});

describe("sendPrepared with a rotating account", () => {
  it("prepares, simulates, signs and submits", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    const result = await client.sendPrepared(algod, rotatingGroup(txn));
    assert.equal(signer.count("/sign/rotating/prepare"), 1);
    assert.equal(signer.count("/sign/rotating/sign"), 1);
    assert.equal(signer.count("/sign"), 0);

    // The group was simulated once, unsigned, exactly as prepared. Fixing
    // signers has the node take the sender's authorizer from the chain;
    // without it an account that has rotated fails its own simulation.
    assert.equal(node.simulated.length, 1);
    assert.equal(node.simulated[0].allowEmptySignatures, true);
    assert.equal(node.simulated[0].fixSigners, true);
    const prepared: string[] = signer.signRequests[0].transactions;
    const simulated = node.simulated[0].txnGroups[0].txns;
    assert.equal(simulated.length, 2);
    assert.equal(prepared.length, 2);
    simulated.forEach((entry, index) => {
      assert.equal(entry.sig, undefined, `simulated transaction ${index} carries a signature`);
      assert.equal(entry.lsig, undefined, `simulated transaction ${index} carries a LogicSig`);
      assert.equal(entry.msig, undefined);
      assert.equal(encodeTransaction(entry.txn)[0], prepared[index], `simulated transaction ${index} is not the prepared one`);
    });

    assert.equal(result.flow, SIGNING_FLOW_ROTATING1);
    assert.equal(result.originalCount, 1);
    assert.equal(result.signedGroup.length, 2);
    assert.notEqual(result.groupId, "");
    assert.equal(node.submitted.length, 1);
    assert.equal(blobHex(node.submitted[0]), result.signedGroup.join(""));
    const spend = algosdk.decodeSignedTransaction(hexToBytes(result.signedGroup[0]));
    assert.equal(spend.txn.rekeyTo?.toString(), signer.nextTarget().toString());
    assert.equal(spend.txn.fee, 2000n);
    assert.equal(spend.sgnr?.toString(), stageAddress(rotatingTestProgram).toString());
    // The ID is the signed spend's, not the draft's.
    assert.equal(result.txIds[0], spend.txn.txID());
    assert.notEqual(result.txIds[0], txn.txID());
    assert.deepEqual(result.fees, [2000n, 0n]);
    const details = result.rotating;
    assert.ok(details, "want details");
    assert.equal(details.stage, 3);
    assert.equal(details.target, 4);
    assert.equal(details.rekeyTo, signer.nextTarget().toString());
    assert.equal(details.attempts, 1);
    assert.notEqual(details.requestId, "");
    assert.equal(result.outcome, "confirmed");
  });

  it("sends a stage 0 spend with no dummies", async () => {
    const account = stageAddress(rotatingTestProgram).toString();
    const { node, algod, client } = rotatingFixture({ account, stage: 0, dummies: 0, charge: 0n });
    const result = await client.sendPrepared(algod, rotatingGroup(rotatingPayment(account, 10, 110)));
    const spend = algosdk.decodeSignedTransaction(node.submitted[0]);
    assert.equal(spend.sgnr, undefined);
    assert.equal(result.signedGroup.length, 1);
    assert.equal(result.groupId, "");
    assert.equal(result.mutations, undefined);
  });
});

/** Change the prepared spend, regroup, and write the group back, as a signer that altered the spend would have to. */
function respend(response: any, txns: Transaction[], change: (spend: Mutable<Transaction>) => void): void {
  change(writable(txns[0]));
  if (txns.length > 1) regroup(txns);
  setPrepared(response, txns);
}

// The things a signer may not do to a prepared group. Each alters a correct
// prepare response; text is what the check says.
const prepareTampers: Array<{
  name: string;
  alter: (response: any, txns: Transaction[]) => void;
  text: string | RegExp;
  /** Where the refusal comes from, when not the prepared-group check. */
  prefix?: string;
}> = [
  { name: "receiver changed", alter: (r, t) => respend(r, t, (s) => { writable(s as Transaction).payment!.receiver = elsewhere; }), text: "changed unreported fields" },
  { name: "amount changed", alter: (r, t) => respend(r, t, (s) => { writable(s as Transaction).payment!.amount += 1n; }), text: "changed unreported fields" },
  { name: "note added", alter: (r, t) => respend(r, t, (s) => { s.note = new Uint8Array([0x78]); }), text: "changed unreported fields" },
  { name: "close-out added", alter: (r, t) => respend(r, t, (s) => { writable(s as Transaction).payment!.closeRemainderTo = elsewhere; }), text: "changed unreported fields" },
  { name: "validity rounds changed", alter: (r, t) => respend(r, t, (s) => { s.lastValid -= 1n; }), text: "changed unreported fields" },
  { name: "network changed", alter: (r, t) => respend(r, t, (s) => { const hash = new Uint8Array(s.genesisHash!); hash[1] ^= 1; s.genesisHash = hash; }), text: "changed unreported fields" },
  { name: "rekey to an address other than the one reported", alter: (r, t) => respend(r, t, (s) => { s.rekeyTo = elsewhere; }), text: "changed unreported fields" },
  { name: "rekey left out", alter: (r, t) => respend(r, t, (s) => { s.rekeyTo = undefined; }), text: "changed unreported fields" },
  { name: "reported rekey target is the zero address", alter: (r) => { r.rekey_to = algosdk.ALGORAND_ZERO_ADDRESS_STRING; }, text: "rekey_to must be another, non-zero address" },
  { name: "reported rekey target is the account", alter: (r) => { r.rekey_to = r.account; }, text: "rekey_to must be another, non-zero address" },
  { name: "reported rekey target is not an address", alter: (r) => { r.rekey_to = "nonsense"; }, text: "invalid rekey_to" },
  { name: "fee raised more than reported", alter: (r, t) => respend(r, t, (s) => { s.fee += 500n; }), text: "total_fees_delta" },
  { name: "fee raised with no fee report", alter: (r) => { delete r.mutations.fees_modified; delete r.mutations.total_fees_delta; }, text: "changed unreported fields" },
  { name: "fee lowered", alter: (r, t) => respend(r, t, (s) => { s.fee = 500n; }), text: "did not increase the fee" },
  {
    name: "group ID not the group's",
    alter: (r, t) => {
      for (const txn of t) {
        const group = new Uint8Array(txn.group!);
        group[0] ^= 1;
        txn.group = group;
      }
      setPrepared(r, t);
    },
    text: "canonical group ID",
  },
  { name: "dummy pays the account's money", alter: (r, t) => { writable(t[1]).payment!.amount = 1n; regroup(t); setPrepared(r, t); }, text: "not the canonical resource dummy" },
  { name: "dummy on other rounds", alter: (r, t) => { writable(t[1]).lastValid += 1n; regroup(t); setPrepared(r, t); }, text: "not the canonical resource dummy" },
  {
    name: "extra transaction beyond the report",
    alter: (r, t) => {
      t.push(canonicalDummyTransaction(t[0], undefined, t.length - 1));
      regroup(t);
      setPrepared(r, t);
    },
    text: "final_count",
  },
  { name: "dummies with no report", alter: (r) => { delete r.mutations; }, text: "without a mutation report" },
  { name: "no transactions", alter: (r) => { delete r.transactions; }, text: "prepared group is empty" },
  { name: "another account", alter: (r) => { r.account = fakeAddress(9); }, text: "is not the sender" },
  { name: "target is not the next stage", alter: (r) => { r.target = r.stage + 2; }, text: "not the stage after" },
  { name: "target equals the stage", alter: (r) => { r.target = r.stage; }, text: "not the stage after" },
  // The largest stage a uint64 holds, as JSON carries it: JSON.parse cannot
  // read it exactly, so the answer is refused as unreadable rather than
  // rounded. Prepare releases nothing, so that is a plain error.
  {
    name: "stage number overflows",
    alter: (r) => { r.stage = 18446744073709551615; r.target = 0; },
    prefix: "failed to decode response",
    text: "stage is not an unsigned integer the SDK can read exactly",
  },
  {
    name: "stage number beyond the safe integers",
    alter: (r) => { r.stage = 2 ** 53; r.target = 2 ** 53 + 1; },
    prefix: "failed to decode response",
    text: "stage is not an unsigned integer the SDK can read exactly",
  },
  // algosdk's decoder refuses the extra byte before the canonical check does.
  { name: "trailing bytes after the spend", alter: (r) => { r.transactions[0] += "00"; }, text: /not canonical|invalid msgpack/ },
  { name: "spend without the TX prefix", alter: (r) => { r.transactions[0] = r.transactions[0].slice(4); }, text: "missing TX prefix" },
  { name: "spend is not hex", alter: (r) => { r.transactions[0] = "zz"; }, text: "invalid hex" },
];

describe("prepareRotating refuses an altered group", () => {
  // The client's authority boundary for a prepared group: each case is one
  // thing the signer may not do. None reaches simulation or signing.
  for (const tamper of prepareTampers) {
    it(tamper.name, async () => {
      const { signer, node, algod, client, txn } = rotatingFixture();
      signer.alterPrepare = tamper.alter;
      await assert.rejects(
        client.sendPrepared(algod, rotatingGroup(txn)),
        mentions(tamper.prefix ?? "verify prepared rotating group", tamper.text),
      );
      assert.equal(node.simulated.length, 0);
      assert.equal(signer.count("/sign/rotating/sign"), 0);
      assert.equal(node.submitted.length, 0);
    });
  }
});

describe("prepareRotating holds the fee ceiling", () => {
  it("refuses a charge over the client's max fee increase", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    client.maxFeeIncrease = 999;
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), (error: unknown) => {
      assert.ok(error instanceof MaxFeeIncreaseError, String(error));
      assert.equal(error.raised, 1000n);
      assert.equal(error.limit, 999n);
      return true;
    });
    assert.equal(node.simulated.length, 0);
    assert.equal(signer.count("/sign/rotating/sign"), 0);

    client.maxFeeIncrease = 1000;
    await client.sendPrepared(algod, rotatingGroup(txn));
  });
});

/** encodeMsgpack refuses a signed transaction with two authorizations, so build one by hand. */
function withSecondAuthorization(signed: algosdk.SignedTransaction): string {
  const object = algosdk.decodeObj(algosdk.encodeMsgpack(signed)) as Record<string, unknown>;
  const sig = new Uint8Array(64);
  sig[0] = 1;
  object.sig = sig;
  return bytesToHex(algosdk.encodeObj(object));
}

// Signed responses that are not exactly the prepared group, properly
// authorized. Each alters a correct sign response.
const signTampers: Array<{ name: string; alter: (response: any, signed: algosdk.SignedTransaction[]) => void; text: string | RegExp }> = [
  {
    name: "spend changed after preparation",
    alter: (r, s) => {
      const txn = cloneTransaction(s[0].txn);
      writable(txn).payment!.amount += 1n;
      s[0] = new algosdk.SignedTransaction({ txn, lsig: s[0].lsig, sgnr: s[0].sgnr });
      setSigned(r, s);
    },
    text: "differs from the prepared transaction",
  },
  {
    name: "dummy changed after preparation",
    alter: (r, s) => {
      const txn = cloneTransaction(s[1].txn);
      writable(txn).note = new Uint8Array([9]);
      s[1] = new algosdk.SignedTransaction({ txn, lsig: s[1].lsig });
      setSigned(r, s);
    },
    text: "differs from the prepared transaction",
  },
  { name: "transactions reordered", alter: (r) => { [r.signed[0], r.signed[1]] = [r.signed[1], r.signed[0]]; }, text: "differs from the prepared transaction" },
  { name: "transaction missing", alter: (r) => { r.signed = r.signed.slice(0, 1); }, text: "signed group has 1 transaction(s), prepared 2" },
  { name: "extra transaction", alter: (r) => { r.signed.push(r.signed[1]); }, text: "signed group has 3 transaction(s), prepared 2" },
  // algosdk's decoder refuses the extra byte before the canonical check does.
  { name: "trailing bytes", alter: (r) => { r.signed[0] += "00"; }, text: /not a canonical signed transaction|invalid msgpack/ },
  {
    name: "spend not signed",
    alter: (r, s) => { s[0] = new algosdk.SignedTransaction({ txn: s[0].txn, sgnr: s[0].sgnr }); setSigned(r, s); },
    text: "not authorized by a stage program",
  },
  {
    name: "spend signed by a plain key instead",
    alter: (r, s) => {
      const sig = new Uint8Array(64);
      sig[0] = 1;
      s[0] = new algosdk.SignedTransaction({ txn: s[0].txn, sig, sgnr: s[0].sgnr });
      setSigned(r, s);
    },
    text: "not authorized by a stage program",
  },
  // algosdk's decoder refuses two authorizations before the authorization check does.
  { name: "spend carries two authorizations", alter: (r, s) => { r.signed[0] = withSecondAuthorization(s[0]); }, text: /more than one authorization|more than 1 signature/ },
  {
    name: "stage program delegated by a signature",
    alter: (r, s) => {
      const lsig = new algosdk.LogicSig(s[0].lsig!.logic, s[0].lsig!.args);
      const sig = new Uint8Array(64);
      sig[0] = 1;
      lsig.sig = sig;
      s[0] = new algosdk.SignedTransaction({ txn: s[0].txn, lsig, sgnr: s[0].sgnr });
      setSigned(r, s);
    },
    text: "delegated by a signature",
  },
  {
    name: "signer of the spend not named",
    alter: (r, s) => { s[0] = new algosdk.SignedTransaction({ txn: s[0].txn, lsig: s[0].lsig }); setSigned(r, s); },
    text: "does not name its signer",
  },
  {
    name: "named signer is not the program's address",
    alter: (r, s) => {
      s[0] = new algosdk.SignedTransaction({ txn: s[0].txn, lsig: s[0].lsig, sgnr: stageAddress(rotatingNextProgram) });
      setSigned(r, s);
    },
    text: "not the requested auth address",
  },
  {
    name: "dummy not signed",
    alter: (r, s) => { s[1] = new algosdk.SignedTransaction({ txn: s[1].txn }); setSigned(r, s); },
    text: "not the canonical signed resource dummy",
  },
  {
    name: "dummy signed by another program",
    alter: (r, s) => {
      s[1] = new algosdk.SignedTransaction({ txn: s[1].txn, lsig: new algosdk.LogicSig(rotatingNextProgram) });
      setSigned(r, s);
    },
    text: "not the canonical signed resource dummy",
  },
  { name: "another stage reported", alter: (r) => { r.stage += 1; r.target += 1; }, text: "signer reports stage 4 to 5, prepared 3 to 4" },
  { name: "another transaction ID reported", alter: (r, s) => { r.txid = s[1].txn.txID(); }, text: "signer reports transaction ID" },
  { name: "another group ID reported", alter: (r) => { r.group_id = bytesToBase64(new Uint8Array(32)); }, text: "signer reports group ID" },
];

describe("signPreparedRotating refuses an altered response", () => {
  // Each case is a signed group that is not exactly the prepared one,
  // properly authorized. None is submitted.
  for (const tamper of signTampers) {
    it(tamper.name, async () => {
      const { signer, node, algod, client, txn } = rotatingFixture();
      signer.alterSign = tamper.alter;
      await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), mentions("verify signer response", tamper.text));
      assert.equal(node.submitted.length, 0);
      assert.equal(signer.count("/sign/rotating/sign"), 1);
    });
  }
});

describe("the stage program must fit the stage", () => {
  it("stage 0 signs as the account itself", async () => {
    // The signer claims stage 0, but the program is not the account's.
    const { node, algod, client, txn } = rotatingFixture({ stage: 0 });
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), mentions("does not fit stage 0"));
    assert.equal(node.submitted.length, 0);
  });

  it("a later stage does not sign as the account", async () => {
    const account = stageAddress(rotatingTestProgram).toString();
    const { algod, client } = rotatingFixture({ account, stage: 2, dummies: 0, charge: 0n });
    await assert.rejects(
      client.sendPrepared(algod, rotatingGroup(rotatingPayment(account, 10, 110))),
      mentions("does not fit stage 2"),
    );
  });

  it("the next stage's program does not sign", async () => {
    // A spend signed by the program whose address is its own rekey target:
    // a rule the shared vectors cannot carry, since it needs the pair of
    // answers to agree.
    const { signer, node, algod, client, txn } = rotatingFixture();
    signer.alterPrepare = (response, txns) => {
      // The reported target is the address of the program that signs.
      const target = stageAddress(rotatingTestProgram);
      response.rekey_to = target.toString();
      writable(txns[0]).rekeyTo = target;
      regroup(txns);
      setPrepared(response, txns);
    };
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), mentions("authorized by the next stage's program"));
    assert.equal(node.submitted.length, 0);
  });
});

describe("a failed preflight signs nothing", () => {
  it("simulation fails", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    node.simulate = () => ({ lastRound: 10n, txnGroups: [{ failureMessage: "logic eval error: rekey not allowed", txnResults: [] }] });
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), (error: unknown) => {
      assert.ok(error instanceof RotatingPreflightError, String(error));
      assert.match(error.failureMessage, /rekey not allowed/);
      assert.ok(error.prepared instanceof PreparedRotating, "want error.prepared instanceof PreparedRotating");
      return true;
    });
    assert.equal(signer.count("/sign/rotating/sign"), 0);
    assert.equal(node.submitted.length, 0);
  });

  it("simulation cannot be run", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    node.simulate = () => {
      throw new Error("Network request error. Received status 500");
    };
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), mentions("nothing was signed"));
    assert.equal(signer.count("/sign/rotating/sign"), 0);
  });

  it("simulate only never signs", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    const prepared = await client.prepareRotating(txn);
    const simulation = await client.simulatePreparedRotating(algod, prepared);
    assert.equal(simulation.failed, false);
    assert.equal(simulation.txIds.length, 2);
    assert.equal(signer.count("/sign/rotating/sign"), 0);
    assert.equal(node.submitted.length, 0);
  });
});

describe("rotating retries", () => {
  const stageChanged = refusal(ErrorCodes.RotatingStageChanged, "the account's authorizer changed");
  const notCurrent = refusal(ERROR_CODE_ROTATING_WINDOW_NOT_CURRENT, "fewer than 10 rounds remain before last valid round");
  const unproven = refusal(ErrorCodes.RotatingStageUnproven, "the account's live stage has not been found yet");

  it("stage not found yet, then found", async () => {
    const { signer, algod, client, txn } = rotatingFixture();
    signer.prepareErrors = [unproven];
    const result = await client.sendPrepared(algod, rotatingGroup(txn));
    assert.equal(result.rotating?.attempts, 2);
    assert.equal(signer.count("/sign/rotating/prepare"), 2);
    assert.equal(signer.count("/sign/rotating/sign"), 1);
  });

  it("authorizer moved before signing, then signed", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    signer.signErrors = [stageChanged];
    const result = await client.sendPrepared(algod, rotatingGroup(txn));
    assert.equal(result.rotating?.attempts, 2);
    // Every attempt is prepared, simulated and presented for approval again.
    assert.equal(signer.count("/sign/rotating/prepare"), 2);
    assert.equal(signer.count("/sign/rotating/sign"), 2);
    assert.equal(node.simulated.length, 2);
    assert.equal(node.submitted.length, 1);
    // The supplied transaction was not rebuilt.
    assert.equal(result.rotating?.transaction.firstValid, txn.firstValid);
    assert.equal(result.rotating?.transaction.lastValid, txn.lastValid);
  });

  it("gives up after three attempts", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    signer.signErrors = [stageChanged, stageChanged, stageChanged, stageChanged];
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), (error: unknown) => {
      assert.equal(codeOf(error), ErrorCodes.RotatingStageChanged, String(error));
      return true;
    });
    assert.equal(signer.count("/sign/rotating/sign"), 3);
    assert.equal(node.submitted.length, 0);
  });

  it("window not current: supplied input is returned, not rebuilt", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    signer.signErrors = [notCurrent];
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), (error: unknown) => {
      assert.equal(codeOf(error), ERROR_CODE_ROTATING_WINDOW_NOT_CURRENT, String(error));
      return true;
    });
    assert.equal(signer.count("/sign/rotating/prepare"), 1);
    assert.equal(signer.count("/sign/rotating/sign"), 1);
    assert.equal(node.submitted.length, 0);
  });

  it("window not current: rebuilt when refresh is allowed", async () => {
    const { signer, node, algod, client } = rotatingFixture();
    signer.signErrors = [notCurrent];
    node.round = 50n;
    const result = await client.sendPrepared(algod, rotatingGroup(rotatingPayment(signer.account, 50, 150)), { refreshValidity: true });
    assert.equal(result.rotating?.attempts, 2);
    assert.equal(signer.count("/sign/rotating/sign"), 2);
    assert.equal(signer.prepareSeen.length, 2);
  });

  it("an uncoded bad request is not retried", async () => {
    const { signer, algod, client, txn } = rotatingFixture();
    // The old wording of a timing refusal, without the code.
    signer.signErrors = [refusal(ErrorCodes.BadRequest, "fewer than 10 rounds remain before last valid round 110")];
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn), { refreshValidity: true }), (error: unknown) => {
      assert.equal(codeOf(error), ErrorCodes.BadRequest, String(error));
      return true;
    });
    assert.equal(signer.count("/sign/rotating/sign"), 1);
    assert.equal(signer.count("/sign/rotating/prepare"), 1);
  });

  it("a policy refusal is not retried", async () => {
    const { signer, algod, client, txn } = rotatingFixture();
    signer.errorStatus = 403;
    signer.signErrors = [refusal(ErrorCodes.Forbidden, "rejected")];
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), SigningRejectedError);
    assert.equal(signer.count("/sign/rotating/sign"), 1);
    assert.equal(signer.count("/sign/rotating/prepare"), 1);
  });
});

describe("rotating validity rounds", () => {
  it("a supplied window over the limit is refused before the signer", async () => {
    const { signer, algod, client } = rotatingFixture();
    await assert.rejects(
      client.sendPrepared(algod, rotatingGroup(rotatingPayment(signer.account, 10, 1010))),
      mentions("validity window is 1000 rounds"),
    );
    assert.equal(signer.count("/sign/rotating/prepare"), 0);
  });

  it("refresh rebuilds an overlong or stale window", async () => {
    for (const [first, last] of [[10, 1010], [1, 12]]) {
      const { signer, node, algod, client } = rotatingFixture();
      node.round = 40n;
      const result = await client.sendPrepared(algod, rotatingGroup(rotatingPayment(signer.account, first, last)), { refreshValidity: true });
      const sent = signer.prepareSeen[0];
      assert.equal(sent.firstValid, 40n, `rounds ${first}-${last}`);
      assert.ok(sent.lastValid >= 50n, "want sent.lastValid >= 50n");
      assert.ok(sent.lastValid - sent.firstValid <= BigInt(ROTATING_MAX_VALIDITY_WINDOW), "want sent.lastValid - sent.firstValid <= BigInt(ROTATING_MAX_VALIDITY_WINDOW)");
      assert.equal(result.rotating?.transaction.firstValid, sent.firstValid, "the result reports the transaction that was prepared");
      restore?.();
    }
  });

  it("a current window is left alone even when refresh is allowed", async () => {
    const { signer, algod, client, txn } = rotatingFixture();
    await client.sendPrepared(algod, rotatingGroup(txn), { refreshValidity: true });
    const sent = signer.prepareSeen[0];
    assert.equal(sent.firstValid, txn.firstValid);
    assert.equal(sent.lastValid, txn.lastValid);
  });
});

describe("rotating refuses unsupported shapes", () => {
  const cases: Array<{ name: string; build: (account: string) => PreparedGroup; text: string }> = [
    {
      name: "already grouped",
      build: (account) => {
        const txn = rotatingPayment(account, 10, 110);
        const group = new Uint8Array(32);
        group[0] = 1;
        txn.group = group;
        return rotatingGroup(txn);
      },
      text: "must be ungrouped",
    },
    {
      name: "sets its own rekey",
      build: (account) => {
        const txn = rotatingPayment(account, 10, 110);
        writable(txn).rekeyTo = elsewhere;
        return rotatingGroup(txn);
      },
      text: "must not set rekey_to",
    },
    {
      name: "closes the account",
      build: (account) => {
        const txn = rotatingPayment(account, 10, 110);
        writable(txn).payment!.closeRemainderTo = elsewhere;
        return rotatingGroup(txn);
      },
      text: "cannot close out",
    },
    {
      name: "carries LogicSig arguments",
      build: (account) => rotatingGroup(rotatingPayment(account, 10, 110), { lsigArgs: { x: new Uint8Array([1]) } }),
      text: "takes no LogicSig arguments",
    },
  ];
  for (const test of cases) {
    it(test.name, async () => {
      const { signer, algod, client } = rotatingFixture();
      await assert.rejects(client.sendPrepared(algod, test.build(signer.account), { refreshValidity: true }), (error: unknown) => {
        assert.ok(error instanceof UnsupportedGroupError, String(error));
        assert.ok(errorText(error).includes(test.text), errorText(error));
        return true;
      });
      assert.equal(signer.count("/sign/rotating/prepare"), 0);
    });
  }
});

describe("lost and refused sign answers", () => {
  it("a lost answer, then an identical retry", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    signer.signErrors = [null]; // the first sign gets no answer

    let unknown: SignOutcomeUnknownError | undefined;
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn), { refreshValidity: true }), (error: unknown) => {
      assert.ok(error instanceof SignOutcomeUnknownError, String(error));
      assert.ok(error.rotating instanceof PreparedRotating, "want error.rotating instanceof PreparedRotating");
      assert.notEqual(error.requestId, "");
      unknown = error;
      return true;
    });
    // The send stops: no second prepare, no second sign, nothing submitted.
    assert.equal(signer.count("/sign/rotating/prepare"), 1);
    assert.equal(signer.count("/sign/rotating/sign"), 1);
    assert.equal(node.submitted.length, 0);
    // The pending approval is cancelled, best effort, under the same ID.
    assert.equal(signer.count("/sign/cancel"), 1);
    assert.equal(signer.cancelRequests[0].request_id, signer.signRequests[0].request_id);
    assert.equal(signer.cancelRequests[0].request_id, unknown!.requestId);

    // The caller's recovery: the same prepared group, signed again.
    const signed = await client.signPreparedRotating(unknown!.rotating!);
    const [first, second] = signer.signRequests;
    assert.deepEqual(second.transactions, first.transactions, "the retry sent the identical prepared group");
    assert.equal(second.account, first.account);
    assert.notEqual(second.request_id, first.request_id, "the retry reused the request ID");
    assert.equal(signer.count("/sign/rotating/prepare"), 1, "the retry prepared again");
    const result = await client.submitSignedGroup(algod, signed.signedGroup);
    assert.equal(result.outcome, "confirmed");
    assert.equal(result.txIds[0], signed.txId);
    assert.equal(result.txIds[0], unknown!.rotating!.txIds()[0]);
  });

  it("a refused retry makes no further call", async () => {
    const { signer, node, client, txn } = rotatingFixture();
    const prepared = await client.prepareRotating(txn);
    signer.signErrors = [refusal(ErrorCodes.RotatingStageChanged, "the account's authorizer changed")];
    await assert.rejects(client.signPreparedRotating(prepared), (error: unknown) => {
      assert.equal(codeOf(error), ErrorCodes.RotatingStageChanged, String(error));
      return true;
    });
    assert.equal(signer.count("/sign/rotating/prepare"), 1);
    assert.equal(signer.count("/sign/rotating/sign"), 1);
    assert.equal(node.submitted.length, 0);
  });
});

describe("a prepared rotating group", () => {
  it("cannot be changed by its holder", async () => {
    const { signer, client, txn } = rotatingFixture();
    const prepared = await client.prepareRotating(txn);
    const want = prepared.transactions();
    // Everything handed out is a copy.
    prepared.transactions()[0] = "00";
    prepared.mutations()!.feesModified![0] = 7;
    writable(prepared.original()).payment!.amount = 999999n;
    writable(txn).payment!.amount = 999999n;
    // And the object itself is frozen.
    assert.throws(() => {
      (prepared as any).accountValue = fakeAddress(9);
    }, TypeError);
    assert.throws(() => {
      new (PreparedRotating as any)(Symbol("PreparedRotating"), {});
    }, /made by prepareRotating/);

    await client.signPreparedRotating(prepared, { requestId: "client-chosen-id" });
    const request = signer.signRequests[0];
    assert.deepEqual(request.transactions, want);
    assert.equal(request.request_id, "client-chosen-id");
    assert.equal(prepared.original().payment?.amount, 5000n);
    assert.deepEqual(prepared.mutations()?.feesModified, [0]);
  });

  it("is refused when forged, before any request is made", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    const prepared = await client.prepareRotating(txn);
    const pathsBefore = signer.paths.length;
    // An object built on the class's prototype, carrying a copy of a real
    // group's values and its own checks, passes instanceof; it is still not
    // a PreparedRotating that prepareRotating made.
    const own = (value: unknown) => ({ value, enumerable: true });
    const forged = Object.create(PreparedRotating.prototype, {
      verify: own(() => undefined),
      verifySigned: own(() => ({ signedGroup: [], stage: 3, target: 4, txId: "", groupId: "", requestId: "" })),
      transactions: own(() => prepared.transactions()),
      decoded: own(() => prepared.decoded()),
      txIds: own(() => prepared.txIds()),
      mutations: own(() => undefined),
      signRequestBody: own((requestId: string) => prepared.signRequestBody(requestId)),
    }) as PreparedRotating;
    assert.ok(forged instanceof PreparedRotating, "want forged instanceof PreparedRotating");
    assert.equal(PreparedRotating.isGenuine(forged), false);
    assert.equal(PreparedRotating.isGenuine(prepared), true);

    const notGenuine = mentions("prepared rotating group is required");
    await assert.rejects(client.signPreparedRotating(forged), notGenuine);
    await assert.rejects(client.simulatePreparedRotating(algod, forged), notGenuine);
    await assert.rejects(client.signPreparedRotating({} as any), notGenuine);
    assert.equal(signer.paths.length, pathsBefore, "a forged group reached the signer");
    assert.equal(node.simulated.length, 0, "a forged group reached the node");
  });

  it("has state no holder can reach", async () => {
    const { client, txn } = rotatingFixture();
    const prepared = await client.prepareRotating(txn);
    // The state is in private fields: nothing is enumerable or settable, and
    // the class's methods cannot be replaced.
    assert.deepEqual(Object.keys(prepared), []);
    assert.equal(Object.isFrozen(prepared), true);
    assert.equal(Object.isFrozen(PreparedRotating.prototype), true);
    assert.equal(Object.isFrozen(PreparedRotating), true);
    assert.throws(() => {
      (PreparedRotating as any).verifyBinding = () => undefined;
    }, TypeError);
  });
});

describe("the prepare answer is read with its types", () => {
  // Prepare releases nothing, so an answer that cannot be read is a plain
  // error, as in the Go SDK.
  const cases: Array<{ name: string; alter: (response: any) => void; text: RegExp }> = [
    { name: "an account that is a list", alter: (r) => { r.account = [r.account]; }, text: /failed to decode response: account is not a string/ },
    { name: "a rekey_to that is a list", alter: (r) => { r.rekey_to = [r.rekey_to]; }, text: /failed to decode response: rekey_to is not a string/ },
    { name: "a stage that is a string", alter: (r) => { r.stage = String(r.stage); }, text: /failed to decode response: stage is not an unsigned integer/ },
    { name: "mutations that are false", alter: (r) => { r.mutations = false; }, text: /failed to decode response: mutations is not an object/ },
    { name: "a transaction that is a number", alter: (r) => { r.transactions[0] = 5; }, text: /failed to decode response: transactions\[0\] is not a string/ },
    {
      name: "a report with camelCase keys only",
      alter: (r) => {
        r.mutations = { dummiesAdded: 1, groupIdChanged: true, feesModified: [0], totalFeesDelta: 1000, originalCount: 1, finalCount: 2 };
      },
      text: /verify prepared rotating group: mutation original_count 0/,
    },
  ];
  for (const test of cases) {
    it(`refuses ${test.name}`, async () => {
      const { signer, client, txn } = rotatingFixture();
      signer.alterPrepare = test.alter;
      await assert.rejects(client.prepareRotating(txn), (error: unknown) => {
        assert.ok(error instanceof SignerError && !(error instanceof SignOutcomeUnknownError), String(error));
        assert.match(errorText(error), test.text);
        return true;
      });
    });
  }

  it("reads null mutations as none", async () => {
    const account = stageAddress(rotatingTestProgram).toString();
    const { signer, client } = rotatingFixture({ account, stage: 0, dummies: 0, charge: 0n });
    signer.alterPrepare = (response) => {
      response.mutations = null;
    };
    const prepared = await client.prepareRotating(rotatingPayment(account, 10, 110));
    assert.equal(prepared.mutations(), undefined);
  });

  it("refuses a body that is null", async () => {
    const { signer, client, txn } = rotatingFixture();
    restore?.();
    restore = installSigners({
      [SIGNER]: (path, body) => (path === "/sign/rotating/prepare" ? { raw: "null" } : signer.handle(path, body)),
    });
    await assert.rejects(client.prepareRotating(txn), /failed to decode response: the answer is not an object/);
  });
});

describe("prepared group checks the vectors cannot reach", () => {
  it("refuses a last valid round before the first", async () => {
    const { signer, algod, client } = rotatingFixture();
    const backwards = rotatingPayment(signer.account, 110, 10);
    await assert.rejects(client.prepareRotating(backwards), mentions("last valid round 10 is before first valid round 110"));
    await assert.rejects(
      client.sendPrepared(algod, rotatingGroup(backwards)),
      mentions("last valid round 10 is before first valid round 110"),
    );
    assert.equal(signer.count("/sign/rotating/prepare"), 0);
  });

  it("refuses a prepared group over the maximum group size", async () => {
    const { signer, client, txn } = rotatingFixture({ dummies: 15 });
    const prepared = await client.prepareRotating(txn);
    assert.equal(prepared.transactions().length, 16, "a full group of 16 is accepted");
    // A seventeenth transaction, reported. algosdk cannot group 17, so the
    // group ID is written by hand; the size is refused before it is read.
    signer.alterPrepare = (response, txns) => {
      txns.push(canonicalDummyTransaction(txns[0], undefined, 15));
      const group = new Uint8Array(32).fill(9);
      for (const entry of txns) entry.group = group;
      response.mutations.final_count = 17;
      response.mutations.dummies_added = 16;
      setPrepared(response, txns);
    };
    await assert.rejects(client.prepareRotating(txn), mentions("verify prepared rotating group", "maximum group size 16"));
  });

  it("refuses prepared bytes algosdk decodes but that are not canonical", async () => {
    // A fee written as a 32-bit integer where the canonical encoding uses 16
    // bits: algosdk decodes it, and only the re-encode comparison refuses it.
    const { signer, client, txn } = rotatingFixture();
    signer.alterPrepare = (response) => {
      const canonical = "a3666565cd07d0"; // "fee": 2000
      assert.ok(response.transactions[0].includes(canonical), "want response.transactions[0].includes(canonical)");
      response.transactions[0] = response.transactions[0].replace(canonical, "a3666565ce000007d0");
    };
    await assert.rejects(client.prepareRotating(txn), (error: unknown) => {
      assert.ok(error instanceof SignerError, String(error));
      assert.match(errorText(error), /verify prepared rotating group: prepared transaction 1: bytes are not canonical/);
      return true;
    });
  });
});

describe("prepare helpers and rotating accounts", () => {
  it("build a rotating window", async () => {
    const stage = stageAddress(rotatingTestProgram).toString();
    const rotating = fakeAccount(41);
    const ordinary = fakeAccount(43);
    const keys: WireKey[] = [
      { address: rotating, key_type: "aplane.rotating-triple-wotsc.v1", signing_flow: SIGNING_FLOW_ROTATING1 },
      { address: ordinary, key_type: "ed25519" },
    ];
    restore = installSigners({
      [SIGNER]: (path) => {
        if (path === "/status") return { body: statusBody() };
        if (path === "/keys") return { body: { count: keys.length, keys } };
        throw new Error(`unexpected signer path ${path}`);
      },
    });
    const node = new FakeAlgod();
    node.round = 500n;
    // The account has rotated: the chain names a stage address the signer
    // does not list.
    node.authAddrs[rotating] = stage;
    const client = new SignerClient(SIGNER);

    const prepared = await client.preparePayment(node, { sender: rotating, receiver: fakeAddress(42), amount: 1 });
    assert.equal(prepared.authAddress, rotating, "the auth address is the rotating account itself");
    const txn = prepared.transaction as Transaction;
    assert.equal(txn.firstValid, 500n);
    assert.equal(txn.lastValid, 500n + BigInt(ROTATING_MAX_VALIDITY_WINDOW));
    checkRotatingWindow(txn);

    const plain = await client.preparePayment(node, { sender: ordinary, receiver: fakeAddress(42), amount: 1 });
    const plainTxn = plain.transaction as Transaction;
    assert.equal(plainTxn.lastValid - plainTxn.firstValid, 1000n, "an ordinary account keeps the node's window");

    const resolved = await client.resolveAuthAddress(rotating, () => stage);
    assert.equal(resolved.authAddress, rotating);
    assert.equal(resolved.chainAuthAddress, stage);
    assert.equal(resolved.isRekeyed, false);
  });

  it("all fetch the sender-aware parameters", () => {
    // Every prepare helper must fetch its parameters through
    // prepSuggestedParams, which fits a rotating sender's window. A direct
    // fetch would build a transaction a rotating account can't send.
    const here = path.dirname(fileURLToPath(import.meta.url));
    const source = fs.readFileSync(path.resolve(here, "../src/client.ts"), "utf-8");
    assert.equal(
      source.split("getTransactionParams().do(").length - 1,
      1,
      "client.ts fetches suggested parameters outside prepSuggestedParams",
    );
    assert.equal(
      source.split("this.prepSuggestedParams(algodClient, params.sender)").length - 1,
      9,
      "client.ts does not have 9 sender-aware parameter fetches",
    );
  });

  it("do not report a signer failure from the parameter fetch", async () => {
    // A locked or unreachable signer is reported by the helper's key
    // resolution, in its usual form, not by the parameter fetch.
    restore = installSigners({ [SIGNER]: () => ({ status: 503, body: { error: "unavailable" } }) });
    const node = new FakeAlgod();
    const client = new SignerClient(SIGNER);
    const params = await (client as any).prepSuggestedParams(node, fakeAccount(41));
    assert.equal(params.suggestedParams.lastValid - params.suggestedParams.firstValid, 1000n);
    await assert.rejects(
      client.preparePayment(node, { sender: fakeAccount(41), receiver: fakeAddress(42), amount: 1 }),
      SignerUnavailableError,
    );
  });

  it("resolution reports the chain's authorizer", async () => {
    const sender = fakeAccount(41);
    const holder = fakeAccount(45);
    restore = installSigners({
      [SIGNER]: (path) => {
        if (path === "/status") return { body: statusBody() };
        return { body: { count: 2, keys: [{ address: sender }, { address: holder }] } };
      },
    });
    const client = new SignerClient(SIGNER);
    const rekeyed = await client.resolveAuthAddress(sender, () => holder);
    assert.equal(rekeyed.chainAuthAddress, holder);
    assert.equal(rekeyed.authAddress, holder);
    assert.equal(rekeyed.isRekeyed, true);
    const own = await client.resolveAuthAddress(sender, () => "");
    assert.equal(own.chainAuthAddress, "");
    assert.equal(own.authAddress, sender);
    assert.equal(own.isRekeyed, false);
  });
});

describe("rotating timing", () => {
  it("the constants match the contract", () => {
    // docs/ARCH_SIGNING.md, "Rotating accounts": a window of at most 100
    // rounds, first valid at most 2 rounds ahead, at least 10 rounds left.
    assert.equal(ROTATING_MAX_VALIDITY_WINDOW, 100);
    assert.equal(ROTATING_MAX_LEAD, 2);
    assert.equal(ROTATING_MIN_REMAINING, 10);
    const txn = rotatingPayment(fakeAccount(41), 12, 112);
    for (const [round, want] of [[9n, false], [10n, true], [102n, true], [103n, false]] as const) {
      assert.equal(rotatingWindowCurrent(txn, round), want, `round ${round}`);
    }
    assert.equal(rotatingWindowCurrent(rotatingPayment(fakeAccount(41), 12, 113), 10n), false, "a 101-round window was accepted");
  });

  it("refuses stale rounds that may not be rebuilt before the operator is asked", async () => {
    const { signer, node, algod, client } = rotatingFixture();
    node.round = 105n; // fewer than 10 rounds left of 10-110
    await assert.rejects(
      client.sendPrepared(algod, rotatingGroup(rotatingPayment(signer.account, 10, 110))),
      mentions("are not current at round 105"),
    );
    assert.equal(signer.count("/sign/rotating/prepare"), 0);
  });

  it("does not keep a window too short to sign when rebuilding", async () => {
    const { signer, node, algod, client } = rotatingFixture();
    node.round = 40n;
    await client.sendPrepared(algod, rotatingGroup(rotatingPayment(signer.account, 40, 45)), { refreshValidity: true });
    const sent = signer.prepareSeen[0];
    assert.equal(sent.firstValid, 40n);
    assert.equal(sent.lastValid, 40n + BigInt(ROTATING_MAX_VALIDITY_WINDOW));
  });

  it("widens the window after a timing refusal", async () => {
    const { signer, node, algod, client } = rotatingFixture();
    signer.signErrors = [refusal(ERROR_CODE_ROTATING_WINDOW_NOT_CURRENT, "too few rounds remain")];
    node.round = 40n;
    // A 12-round window is current, and leaves the operator two rounds.
    const result = await client.sendPrepared(algod, rotatingGroup(rotatingPayment(signer.account, 40, 52)), { refreshValidity: true });
    assert.equal(result.rotating?.attempts, 2);
    const [first, second] = signer.prepareSeen;
    assert.equal(first.lastValid - first.firstValid, 12n, "a current window was changed before the first attempt");
    assert.equal(second.lastValid - second.firstValid, BigInt(ROTATING_MAX_VALIDITY_WINDOW), "after a timing refusal the window is the longest");
  });
});

describe("rotating retry bounds", () => {
  const repeat = (body: ErrorBody) => [body, body, body, body, body, body];

  it("a stage that is never found ends after three prepares", async () => {
    const { signer, algod, client, txn } = rotatingFixture();
    signer.prepareErrors = repeat(refusal(ErrorCodes.RotatingStageUnproven, "not found yet"));
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), (error: unknown) => {
      assert.equal(codeOf(error), ErrorCodes.RotatingStageUnproven, String(error));
      return true;
    });
    assert.equal(signer.count("/sign/rotating/prepare"), 3);
    assert.equal(signer.count("/sign/rotating/sign"), 0);
  });

  it("a window that is never current ends after three signs", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    signer.signErrors = repeat(refusal(ERROR_CODE_ROTATING_WINDOW_NOT_CURRENT, "too few rounds remain"));
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn), { refreshValidity: true }), (error: unknown) => {
      assert.equal(codeOf(error), ERROR_CODE_ROTATING_WINDOW_NOT_CURRENT, String(error));
      return true;
    });
    assert.equal(signer.count("/sign/rotating/sign"), 3);
    assert.equal(node.submitted.length, 0);
  });

  it("the wait to retry honors the signal", async () => {
    rotatingTiming.unprovenBackoffMs = 3_600_000;
    const { signer, algod, client, txn } = rotatingFixture();
    signer.prepareErrors = repeat(refusal(ErrorCodes.RotatingStageUnproven, "not found yet"));
    await assert.rejects(
      client.sendPrepared(algod, rotatingGroup(txn), { signal: AbortSignal.timeout(200) }),
      (error: unknown) => {
        assert.equal(codeOf(error), ErrorCodes.RotatingStageUnproven, String(error));
        return true;
      },
    );
    assert.equal(signer.count("/sign/rotating/prepare"), 1, "the refusal comes after one prepare");
  });
});

describe("sendPayment and a rotating account", () => {
  it("may rebuild the window of the transaction it built", async () => {
    const { signer, node, algod, client } = rotatingFixture();
    signer.signErrors = [refusal(ERROR_CODE_ROTATING_WINDOW_NOT_CURRENT, "too few rounds remain")];
    node.authAddrs[signer.account] = stageAddress(rotatingTestProgram).toString();
    // sendPayment built the transaction, so it may rebuild its rounds with no
    // option set; and the helper gave a rotated account a window it can use.
    const result = await client.sendPayment(algod, { sender: signer.account, receiver: fakeAddress(42), amount: 5000 });
    assert.equal(result.rotating?.attempts, 2);
    const sent = signer.prepareSeen[0];
    assert.equal(sent.lastValid - sent.firstValid, BigInt(ROTATING_MAX_VALIDITY_WINDOW));
  });
});

describe("rotating stops before signing", () => {
  it("when simulation reports no group", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    node.simulate = () => ({ lastRound: 10n, version: 2 });
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), (error: unknown) => {
      assert.ok(error instanceof RotatingPreflightError, String(error));
      assert.match(errorText(error), /no result for the group/);
      return true;
    });
    assert.equal(signer.count("/sign/rotating/sign"), 0);
  });

  it("when simulation reports two groups", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    node.simulate = () => ({ lastRound: 10n, version: 2, txnGroups: [{ txnResults: [] }, { txnResults: [] }] });
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), (error: unknown) => {
      assert.ok(error instanceof RotatingPreflightError, String(error));
      assert.equal(error.failureMessage, "the node returned 2 results for one group");
      return true;
    });
    assert.equal(signer.count("/sign/rotating/sign"), 0);
  });

  // The unsigned rotating group holds the spend and its resource dummy.
  for (const [name, group, failure] of [
    ["one group result without transaction results", { txnResults: [] }, "the node returned 0 transaction results for 2 transactions"],
    ["a group result with one transaction result", { txnResults: [{}] }, "the node returned 1 transaction results for 2 transactions"],
    ["failed-at without a message", { ...passingGroupResult(2), failedAt: [0] }, "the node reported a failure without a message"],
    ["a group result that is not an object", "x", "the node's result for the group is not an object"],
  ] as Array<[string, unknown, string]>) {
    it(`when simulation reports ${name}`, async () => {
      const { signer, node, algod, client, txn } = rotatingFixture();
      node.simulate = () => ({ lastRound: 10n, version: 2, txnGroups: [group] });
      await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), (error: unknown) => {
        assert.ok(error instanceof RotatingPreflightError, String(error));
        assert.equal(error.failureMessage, failure);
        return true;
      });
      assert.equal(signer.count("/sign/rotating/sign"), 0);
    });
  }

  it("when the signal aborts after simulation", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    // A signal that aborts once the simulation has been answered, without
    // interrupting the requests already made.
    const controller = new AbortController();
    node.simulate = () => {
      controller.abort();
      return { lastRound: 10n, version: 2, txnGroups: [passingGroupResult(2)] };
    };
    // The send's own check stops it before signing is attempted at all, not
    // the signing call's check on an aborted signal.
    let signCalls = 0;
    const sign = client.signPreparedRotating.bind(client);
    (client as any).signPreparedRotating = (...args: Parameters<typeof sign>) => {
      signCalls++;
      return sign(...args);
    };
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn), { signal: controller.signal }), (error: unknown) => {
      assert.ok(error instanceof SignerUnavailableError, String(error));
      assert.ok(!(error instanceof SignOutcomeUnknownError), "a plain stop, not an unknown sign outcome");
      return true;
    });
    assert.equal(node.simulated.length, 1);
    assert.equal(signCalls, 0, "signing was attempted after the signal aborted");
    assert.equal(signer.count("/sign/rotating/sign"), 0);
  });

  it("the steps report an empty simulation answer as failed", async () => {
    const { node, algod, client, txn } = rotatingFixture();
    node.simulate = () => ({ lastRound: 10n, version: 2 });
    const prepared = await client.prepareRotating(txn);
    const simulation = await client.simulatePreparedRotating(algod, prepared);
    assert.equal(simulation.failed, true);
  });
});

describe("signPreparedRotating answer classification", () => {
  it("an unreadable answer is an unknown outcome", async () => {
    const { signer, client, txn } = rotatingFixture();
    const prepared = await client.prepareRotating(txn);
    restore?.();
    restore = installSigners({
      [SIGNER]: (path, body) => (path === "/sign/rotating/sign" ? { raw: '{"signed": ["ab' } : signer.handle(path, body)),
    });
    await assert.rejects(client.signPreparedRotating(prepared), (error: unknown) => {
      assert.ok(error instanceof SignOutcomeUnknownError, String(error));
      assert.equal(error.rotating, prepared);
      return true;
    });
  });

  // A 200 body that cannot be read as a sign answer may stand for a
  // released signature, as an unparseable one does.
  for (const body of [
    "123", '"ok"', "[]", "null", "", '{"signed":"x"}', '{"signed":[1]}', '{"stage":"3"}', '{"stage":-1}',
    '{"stage":1.5}', '{"stage":9007199254740992}', '{"stage":18446744073709551616}', '{"txid":7}', '{"group_id":false}',
  ]) {
    it(`a 200 body ${body} is an unknown outcome`, async () => {
      const { signer, client, txn } = rotatingFixture();
      const prepared = await client.prepareRotating(txn);
      restore?.();
      restore = installSigners({
        [SIGNER]: (path, request) => (path === "/sign/rotating/sign" ? { raw: body } : signer.handle(path, request)),
      });
      await assert.rejects(client.signPreparedRotating(prepared), (error: unknown) => {
        assert.ok(error instanceof SignOutcomeUnknownError, String(error));
        assert.equal(error.rotating, prepared);
        return true;
      });
    });
  }

  it("a readable answer that fails its check is a plain refusal", async () => {
    const { signer, client, txn } = rotatingFixture();
    const prepared = await client.prepareRotating(txn);
    signer.alterSign = (response) => {
      response.signed = response.signed.slice(0, 1);
    };
    await assert.rejects(client.signPreparedRotating(prepared), (error: unknown) => {
      assert.ok(!(error instanceof SignOutcomeUnknownError), String(error));
      assert.match(errorText(error), /verify signer response/);
      return true;
    });
  });

  it("an unreadable answer through sendPrepared is an unknown outcome", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    restore?.();
    restore = installSigners({
      [SIGNER]: (path, request) => (path === "/sign/rotating/sign" ? { raw: '{"signed":[1]}' } : signer.handle(path, request)),
    });
    await assert.rejects(client.sendPrepared(algod, rotatingGroup(txn)), SignOutcomeUnknownError);
    assert.equal(node.submitted.length, 0);
  });

  it("a lone spend's answer may leave out group_id, and a stage 0 answer its stage", async () => {
    // Left out, each takes its zero value, as the Go SDK reads the answer.
    const account = stageAddress(rotatingTestProgram).toString();
    const { signer, node, algod, client } = rotatingFixture({ account, stage: 0, dummies: 0, charge: 0n });
    signer.alterSign = (response) => {
      delete response.group_id;
      delete response.stage;
    };
    const result = await client.sendPrepared(algod, rotatingGroup(rotatingPayment(account, 10, 110)));
    assert.equal(result.rotating?.stage, 0);
    assert.equal(result.groupId, "");
    assert.equal(node.submitted.length, 1);

    signer.alterSign = (response) => {
      response.group_id = null;
      response.stage = null;
    };
    await client.sendPrepared(algod, rotatingGroup(rotatingPayment(account, 10, 110)));
  });

  it("an unauthenticated connection is an AuthenticationError", async () => {
    const { signer, client, txn } = rotatingFixture();
    signer.errorStatus = 401;
    signer.prepareErrors = [refusal(ErrorCodes.Unauthorized, "no")];
    await assert.rejects(client.prepareRotating(txn), AuthenticationError);
  });

  it("an already aborted signal sends nothing", async () => {
    const { signer, client, txn } = rotatingFixture();
    const prepared = await client.prepareRotating(txn);
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(client.signPreparedRotating(prepared, { signal: controller.signal }), (error: unknown) => {
      assert.ok(error instanceof SignerUnavailableError, String(error));
      assert.ok(!(error instanceof SignOutcomeUnknownError), "want !(error instanceof SignOutcomeUnknownError)");
      return true;
    });
    assert.equal(signer.count("/sign/rotating/sign"), 0, "a sign request went out on an aborted signal");
  });
});

describe("alternate spellings of an address", () => {
  it("a rekey_to the signer spells otherwise is refused before simulation or signing", async () => {
    const { signer, node, algod, client, txn } = rotatingFixture();
    // The prepared bytes are unchanged: only the reported spelling differs.
    signer.alterPrepare = (response) => {
      response.rekey_to = alternateSpellings(response.rekey_to)[0];
    };
    await assert.rejects(
      client.sendPrepared(algod, rotatingGroup(txn)),
      mentions("verify prepared rotating group", "invalid rekey_to", "not the canonical spelling"),
    );
    assert.equal(node.simulated.length, 0);
    assert.equal(signer.count("/sign/rotating/sign"), 0);
  });

  describe("in the prepare helpers", () => {
    const rotating = fakeAccount(41);
    const ordinary = fakeAccount(43);
    const keys: WireKey[] = [
      { address: rotating, key_type: "aplane.rotating-triple-wotsc.v1", signing_flow: SIGNING_FLOW_ROTATING1 },
      { address: ordinary, key_type: "ed25519" },
    ];
    const setup = () => {
      const paths: string[] = [];
      restore = installSigners({
        [SIGNER]: (path) => {
          paths.push(path);
          if (path === "/status") return { body: statusBody() };
          if (path === "/keys") return { body: { count: keys.length, keys } };
          throw new Error(`unexpected signer path ${path}`);
        },
      });
      const node = new FakeAlgod();
      return { client: new SignerClient(SIGNER), node, paths };
    };

    it("refuse a sender spelled otherwise, which the rotating check would not find", async () => {
      const { client, node, paths } = setup();
      for (const spelling of alternateSpellings(rotating)) {
        await assert.rejects(
          client.preparePayment(node, { sender: spelling, receiver: fakeAddress(42), amount: 1 }),
          mentions("sender", "not the canonical spelling"),
        );
      }
      assert.deepEqual(paths, [], "the signer was asked about a misspelled sender");
    });

    it("refuse a rekey target spelled otherwise, which the rotating-target check would not find", async () => {
      const { client, node } = setup();
      // Spelled canonically, a rekey to a rotating account is refused.
      await assert.rejects(client.prepareRekey(node, { sender: ordinary, rekeyTo: rotating }), /rotating account/);
      for (const spelling of alternateSpellings(rotating)) {
        await assert.rejects(
          client.prepareRekey(node, { sender: ordinary, rekeyTo: spelling }),
          mentions("rekeyTo", "not the canonical spelling"),
        );
      }
    });

    it("refuse a close-to spelled otherwise, which the comparison with the sender would miss", async () => {
      const { client, node } = setup();
      for (const spelling of alternateSpellings(ordinary)) {
        await assert.rejects(
          client.prepareAccountClose(node, { sender: ordinary, closeTo: spelling }),
          mentions("closeTo", "not the canonical spelling"),
        );
        await assert.rejects(
          client.prepareAsaOptOut(node, { sender: ordinary, closeTo: spelling, assetId: 5 }),
          mentions("closeTo", "not the canonical spelling"),
        );
      }
      for (const spelling of alternateSpellings(fakeAddress(42))) {
        await assert.rejects(
          client.preparePayment(node, { sender: ordinary, receiver: spelling, amount: 1 }),
          mentions("receiver", "not the canonical spelling"),
        );
      }
    });

    // An algosdk Address, passed from untyped code, equals no address string:
    // every comparison and key lookup that follows would miss.
    const asObject = (address: string) => algosdk.Address.fromString(address) as unknown as string;
    const notAString = (name: string) => mentions(`${name} must be an address string, not an algosdk Address`);

    it("refuse an algosdk Address as sender, receiver, rekeyTo or closeTo", async () => {
      const { client, node, paths } = setup();
      const receiver = fakeAddress(42);
      await assert.rejects(
        client.preparePayment(node, { sender: asObject(ordinary), receiver, amount: 1 }),
        notAString("sender"),
      );
      await assert.rejects(
        client.prepareAbiAppCall(node, { sender: asObject(ordinary), appId: 7, methodSignature: "f(account)void", args: [ordinary] }),
        notAString("sender"),
      );
      await assert.rejects(
        client.prepareRekey(node, { sender: asObject(ordinary), rekeyTo: receiver }),
        notAString("sender"),
      );
      assert.deepEqual(paths, [], "the signer was asked about a sender that is not a string");
      await assert.rejects(
        client.preparePayment(node, { sender: ordinary, receiver: asObject(receiver), amount: 1 }),
        notAString("receiver"),
      );
      await assert.rejects(
        client.prepareAsaTransfer(node, { sender: ordinary, receiver: asObject(receiver), assetId: 5, amount: 1 }),
        notAString("receiver"),
      );
      await assert.rejects(
        client.prepareRekey(node, { sender: ordinary, rekeyTo: asObject(receiver) }),
        notAString("rekeyTo"),
      );
      // Closing to the sender itself is refused by a comparison an object misses.
      await assert.rejects(
        client.prepareAccountClose(node, { sender: ordinary, closeTo: asObject(ordinary) }),
        notAString("closeTo"),
      );
      await assert.rejects(
        client.prepareAsaOptOut(node, { sender: ordinary, closeTo: asObject(ordinary), assetId: 5 }),
        notAString("closeTo"),
      );
      await assert.rejects(
        client.prepareAccountClose(node, { sender: asObject(ordinary), closeTo: receiver }),
        notAString("sender"),
      );
    });

    it("refuse a rekey to a rotating account named by an algosdk Address", async () => {
      const { client, node } = setup();
      // The key lookup that finds the rotating account would miss an object.
      await assert.rejects(
        client.prepareRekey(node, { sender: ordinary, rekeyTo: asObject(rotating) }),
        notAString("rekeyTo"),
      );
    });

    it("resolveAuthAddress never resolves a misspelled rotating account to an ordinary key", async () => {
      const { client } = setup();
      const stage = stageAddress(rotatingTestProgram).toString();
      for (const spelling of alternateSpellings(rotating)) {
        // Looked up as given, as the Go SDK does: the spelling names no key.
        for (const chainAuth of ["", stage]) {
          await assert.rejects(client.resolveAuthAddress(spelling, () => chainAuth), KeyNotFoundError);
        }
      }
    });
  });
});
