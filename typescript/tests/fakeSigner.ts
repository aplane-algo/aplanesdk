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

export function fakePayment(
  senderSeed = 41,
  receiverSeed = 42,
  amount = 1_000_000,
  sender?: string,
): Transaction {
  const genesisHash = new Uint8Array(32);
  genesisHash[0] = 7;
  return algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: sender ?? fakeAddress(senderSeed),
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

/** A signed transaction as an Ed25519 signer would return it. */
export function signedHex(txn: Transaction, fill = 1): string {
  const signed = new algosdk.SignedTransaction({ txn, sig: new Uint8Array(64).fill(fill) });
  return bytesToHex(algosdk.encodeMsgpack(signed));
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
    return signedHex(txn);
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
