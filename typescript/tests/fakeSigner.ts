// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * A stand-in for apsigner's planner, for tests.
 *
 * It does to a request group what the real signer does, so mocked responses
 * are ones a real signer could return: it raises the fees it is told to,
 * appends resource dummies, groups an ungrouped group, reports all of it, and
 * signs.
 */

import algosdk, { type Transaction } from "algosdk";
import type { SignRequest } from "../src/types.js";
import { bytesToHex, encodeTransaction, hexToBytes } from "../src/encoding.js";
import {
  canonicalDummyTransaction,
  cloneTransaction,
  decodeRequestSlots,
  groupIDBytes,
  signCanonicalDummy,
} from "../src/verify.js";

export interface FakeSignerOptions {
  /** Fee increase per request index. */
  feeRaise?: Record<number, number>;
  /** Resource dummies to append. */
  dummies?: number;
  /** Edits the wire response body before it is returned. */
  tamper?: (body: any) => void;
}

export function fakeAddress(seed: number): string {
  const bytes = new Uint8Array(32);
  bytes[31] = seed;
  return algosdk.encodeAddress(bytes);
}

// The fake signer's accounts, by address: Ed25519 keys, LogicSig programs and
// native Falcon public keys, as the real signer holds them.
const keys = new Map<string, Uint8Array>();
const programs = new Map<string, Uint8Array>();
const pqKeys = new Map<string, { sch: Uint8Array; slt: number; pk: Uint8Array; sig: Uint8Array }>();
const accountsBySeed = new Map<number, string>();

/** The address of the fake signer's Ed25519 account for a seed. */
export function fakeAccount(seed: number): string {
  let address = accountsBySeed.get(seed);
  if (!address) {
    const generated = algosdk.generateAccount();
    address = generated.addr.toString();
    keys.set(address, generated.sk);
    accountsBySeed.set(seed, address);
  }
  return address;
}

/** Have the fake signer hold a LogicSig account for the given program. */
export function holdProgram(program: Uint8Array): string {
  const address = new algosdk.LogicSigAccount(program).address().toString();
  programs.set(address, program);
  return address;
}

/** A LogicSig account the fake signer holds: the hash of its program. */
export function fakeLogicSigAccount(seed: number): string {
  return holdProgram(new Uint8Array([0x06, 0x81, seed])); // #pragma version 6; pushint seed
}

/**
 * A native Falcon account the fake signer holds. The public key and signature
 * are filler: nothing verifies them.
 */
export function fakePQAccount(seed: number): string {
  const sch = new Uint8Array([0x66, 0x31]); // "f1"
  const pk = new Uint8Array(1793).fill(seed);
  const { address, salt } = algosdk.addressFromPQKey(sch, pk);
  pqKeys.set(address.toString(), { sch, slt: salt, pk, sig: new Uint8Array(1232).fill(9) });
  return address.toString();
}

/**
 * Sign as the fake signer's account at authAddress would: the account's kind
 * of authorization, and the signer field when the account is not the sender.
 * An address the fake signer does not hold gets a signature that verifies
 * under nothing.
 */
export function authorize(txn: Transaction, authAddress: string): algosdk.SignedTransaction {
  const sgnr =
    authAddress !== txn.sender.toString() ? algosdk.Address.fromString(authAddress) : undefined;
  const key = keys.get(authAddress);
  if (key) {
    return algosdk.decodeSignedTransaction(txn.signTxn(key));
  }
  const program = programs.get(authAddress);
  if (program) {
    const lsig = new algosdk.LogicSig(program, [new Uint8Array([1, 2, 3])]);
    return new algosdk.SignedTransaction({ txn, lsig, sgnr });
  }
  const pqsig = pqKeys.get(authAddress);
  if (pqsig) {
    return new algosdk.SignedTransaction({ txn, pqsig, sgnr });
  }
  return new algosdk.SignedTransaction({ txn, sig: new Uint8Array(64).fill(1), sgnr });
}

export function encodeSigned(signed: algosdk.SignedTransaction): string {
  return bytesToHex(algosdk.encodeMsgpack(signed));
}

export function fakePayment(
  senderSeed = 41,
  receiverSeed = 42,
  amount = 1_000_000,
  sender?: string,
): Transaction {
  const genesisHash = new Uint8Array(32);
  genesisHash[0] = 7;
  return algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: sender ?? fakeAccount(senderSeed),
    receiver: fakeAddress(receiverSeed),
    amount,
    suggestedParams: {
      fee: 1000,
      flatFee: true,
      minFee: 1000,
      firstValid: 10,
      lastValid: 1010,
      genesisID: "testnet-v1.0",
      genesisHash,
    },
  });
}

export function signEntries(...txns: Transaction[]): SignRequest[] {
  return txns.map((txn) => {
    const [txnBytesHex, sender] = encodeTransaction(txn);
    return { auth_address: sender, txn_sender: sender, txn_bytes_hex: txnBytesHex };
  });
}

/**
 * A transaction signed by its sender. With `fill`, the signature is that byte
 * repeated instead: the same transaction, signed by nobody.
 */
export function signedHex(txn: Transaction, fill?: number): string {
  if (fill !== undefined) {
    return encodeSigned(
      new algosdk.SignedTransaction({ txn, sig: new Uint8Array(64).fill(fill) }),
    );
  }
  return encodeSigned(authorize(txn, txn.sender.toString()));
}

export function decodeSigned(hex: string): algosdk.SignedTransaction {
  return algosdk.decodeSignedTransaction(hexToBytes(hex));
}

/** Assign the canonical group ID to a group, replacing any it carries. */
export function regroup(txns: Transaction[]): Transaction[] {
  txns.forEach((txn) => {
    txn.group = undefined;
  });
  const groupID = algosdk.computeGroupID(txns);
  txns.forEach((txn) => {
    txn.group = groupID;
  });
  return txns;
}

function finalize(requests: SignRequest[], options: FakeSignerOptions) {
  const slots = decodeRequestSlots(requests);
  const dummies = options.dummies ?? 0;
  const report: Record<string, unknown> = { original_count: slots.length };
  const preGrouped = groupIDBytes(slots[0].txn) !== undefined;
  const feesModified: number[] = [];
  let total = 0;
  let passthroughCount = 0;
  let foreignCount = 0;
  const final = slots.map((slot, index) => {
    const txn = cloneTransaction(slot.txn);
    const raise = options.feeRaise?.[index] ?? 0;
    if (raise > 0) {
      txn.fee += BigInt(raise);
      feesModified.push(index);
      total += raise;
    }
    if (slot.mode === "passthrough") passthroughCount++;
    if (slot.mode === "foreign") foreignCount++;
    return txn;
  });
  for (let index = 0; index < dummies; index++) {
    final.push(canonicalDummyTransaction(slots[0].txn, undefined, index));
  }
  report.final_count = final.length;
  if (dummies > 0) report.dummies_added = dummies;
  if (total > 0) {
    report.total_fees_delta = total;
    report.fees_modified = feesModified;
  }
  if (passthroughCount > 0) report.passthrough_count = passthroughCount;
  if (foreignCount > 0) report.foreign_count = foreignCount;
  if (final.length > 1 && (!preGrouped || dummies > 0 || total > 0)) {
    regroup(final);
    report.group_id_changed = true;
  }
  const reported = Object.keys(report).length > 2;
  return { slots, final, report: reported ? report : undefined };
}

/** The /sign response body a real signer would return for these requests. */
export function signResponse(requests: SignRequest[], options: FakeSignerOptions = {}): any {
  const { slots, final, report } = finalize(requests, options);
  const signed = final.map((txn, index) => {
    if (index >= slots.length) return bytesToHex(signCanonicalDummy(txn));
    if (slots[index].mode === "passthrough") return requests[index].signed_txn_hex as string;
    if (slots[index].mode === "foreign") return "";
    return encodeSigned(authorize(txn, requests[index].auth_address as string));
  });
  const body: any = { signed };
  if (report) body.mutations = report;
  options.tamper?.(body);
  return body;
}

/** The /plan response body a real signer would return for these requests. */
export function planResponse(requests: SignRequest[], options: FakeSignerOptions = {}): any {
  const { final, report } = finalize(requests, options);
  const body: any = { transactions: final.map((txn) => encodeTransaction(txn)[0]) };
  if (report) body.mutations = report;
  options.tamper?.(body);
  return body;
}

/**
 * A fetch stand-in for one /sign or /plan call, answering as a real signer
 * would for the request it receives.
 */
export function signerFetch(options: FakeSignerOptions = {}) {
  return (url: unknown, init?: { body?: string }) => {
    const requests = JSON.parse(init?.body ?? "{}").requests as SignRequest[];
    const body = String(url).endsWith("/plan")
      ? planResponse(requests, options)
      : signResponse(requests, options);
    return { status: 200, ok: true, json: async () => body };
  };
}
