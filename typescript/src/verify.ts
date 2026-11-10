// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * Checks of signer results against the request that produced them.
 *
 * The signer may raise the fees it reports on positions it signs, assign a
 * canonical group ID, and append reported canonical resource dummies. It may
 * not alter any other transaction field. Every /sign and /plan result passes
 * through here before a caller can submit or simulate it.
 */

import algosdk, { type Transaction } from "algosdk";
import type { MutationReport, SignRequest } from "./types.js";
import { signRequestMode, type SignRequestMode } from "./types.js";
import { SignerError } from "./errors.js";
import { encodeTransaction, hexToBytes } from "./encoding.js";

/** Algorand's maximum transaction group size. */
export const MAX_GROUP_SIZE = 16;
export const DUMMY_PROGRAM = new Uint8Array([0x03, 0x31, 0x20, 0x32, 0x03, 0x12]);

const UINT64_MAX = (1n << 64n) - 1n;

/**
 * Validate a max fee increase setting: unset, or a non-negative whole number
 * of microAlgos. The value is returned as given, so a caller reads back what
 * it set; null is treated as unset.
 */
export function checkMaxFeeIncrease(
  value: number | bigint | undefined | null,
): number | bigint | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value === "bigint" ? value >= 0n : Number.isSafeInteger(value) && value >= 0) {
    return value;
  }
  throw new SignerError(
    "maxFeeIncrease must be a non-negative whole number of microAlgos, or undefined",
  );
}

/** One decoded /sign or /plan request entry. */
export interface RequestSlot {
  mode: SignRequestMode;
  txn: Transaction;
  /** The signed bytes as sent, for a passthrough entry. */
  signedBytes?: Uint8Array;
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function byteArraysEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  return left.every((value, index) => value === right[index]);
}

export function cloneTransaction(txn: Transaction): Transaction {
  return algosdk.decodeUnsignedTransaction(txn.toByte());
}

export function groupIDBytes(txn: Transaction): Uint8Array | undefined {
  const group = txn.group;
  if (
    group === undefined ||
    group.length === 0 ||
    group.every((value) => value === 0)
  ) {
    return undefined;
  }
  if (group.length !== 32) {
    throw new SignerError("transaction has invalid group ID");
  }
  return group;
}

/** hexToBytes, with the position named in the error. */
function decodeHex(value: string, label: string): Uint8Array {
  try {
    return hexToBytes(value);
  } catch {
    throw new SignerError(`${label} is invalid hex`);
  }
}

/**
 * Decode TX-prefixed unsigned transaction bytes, requiring the canonical
 * encoding of the decoded transaction.
 */
export function decodeCanonicalTransaction(raw: Uint8Array): Transaction {
  if (raw.length < 3 || raw[0] !== 0x54 || raw[1] !== 0x58) {
    throw new SignerError("missing TX prefix");
  }
  let txn: Transaction;
  try {
    txn = algosdk.decodeUnsignedTransaction(raw.slice(2));
  } catch (error) {
    throw new SignerError(`invalid msgpack: ${errorText(error)}`);
  }
  if (!byteArraysEqual(raw.slice(2), txn.toByte())) {
    throw new SignerError("bytes are not canonical");
  }
  return txn;
}

/**
 * Decode signed transaction bytes, requiring the canonical encoding of the
 * decoded value. Comparing only the inner transaction would let a
 * non-canonical wrapper, or fields the decoder drops, through to submission.
 */
export function decodeCanonicalSignedTransaction(raw: Uint8Array): algosdk.SignedTransaction {
  if (raw.length === 0) {
    throw new SignerError("empty signed transaction");
  }
  let signed: algosdk.SignedTransaction;
  try {
    signed = algosdk.decodeSignedTransaction(raw);
  } catch (error) {
    throw new SignerError(`invalid msgpack: ${errorText(error)}`);
  }
  if (!byteArraysEqual(raw, algosdk.encodeMsgpack(signed))) {
    throw new SignerError("bytes are not a canonical signed transaction");
  }
  return signed;
}

/** Decode every request entry before it is sent to the signer. */
export function decodeRequestSlots(requests: SignRequest[]): RequestSlot[] {
  return requests.map((request, index) => {
    const position = index + 1;
    const mode = signRequestMode(request);
    if (mode === "passthrough") {
      const raw = decodeHex(request.signed_txn_hex || "", `transaction ${position}: signed_txn_hex`);
      try {
        const signed = decodeCanonicalSignedTransaction(raw);
        return { mode, txn: signed.txn, signedBytes: raw };
      } catch (error) {
        throw new SignerError(
          `transaction ${position}: passthrough transaction: ${errorText(error)}`,
        );
      }
    }
    const raw = decodeHex(request.txn_bytes_hex || "", `transaction ${position}: txn_bytes_hex`);
    try {
      return { mode, txn: decodeCanonicalTransaction(raw) };
    } catch (error) {
      throw new SignerError(`transaction ${position}: txn_bytes_hex: ${errorText(error)}`);
    }
  });
}

function mutationInteger(mutations: MutationReport, name: keyof MutationReport, wire: string): number {
  const value = mutations[name] ?? 0;
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new SignerError(`mutation ${wire} must be an integer`);
  }
  return value;
}

/**
 * Require a multi-transaction group to carry the group ID computed over
 * itself, and return it. A single transaction needs no group ID.
 */
export function validateCanonicalGroupID(txns: Transaction[]): Uint8Array | undefined {
  if (txns.length < 2) {
    return undefined;
  }
  const cleared = txns.map(cloneTransaction);
  cleared.forEach((txn) => {
    txn.group = undefined;
  });
  let want: Uint8Array;
  try {
    want = algosdk.computeGroupID(cleared);
  } catch (error) {
    throw new SignerError(`compute canonical returned group ID: ${errorText(error)}`);
  }
  txns.forEach((txn, index) => {
    const group = groupIDBytes(txn);
    if (group === undefined || !byteArraysEqual(group, want)) {
      throw new SignerError(
        `returned transaction ${index + 1} does not carry the canonical group ID`,
      );
    }
  });
  return want;
}

/**
 * Rebuild the index'th resource dummy the signer's planner appends to a
 * group: a zero-fee, zero-amount self-payment from the dummy address with the
 * index as its one-byte note, on the first original transaction's validity
 * window and genesis, in the group.
 */
export function canonicalDummyTransaction(
  firstOriginal: Transaction,
  groupID: Uint8Array | undefined,
  index: number,
): Transaction {
  const dummyAddress = new algosdk.LogicSigAccount(DUMMY_PROGRAM).address();
  const dummy = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: dummyAddress,
    receiver: dummyAddress,
    amount: 0,
    note: new Uint8Array([index]),
    suggestedParams: {
      fee: 0,
      flatFee: true,
      minFee: 0,
      firstValid: firstOriginal.firstValid,
      lastValid: firstOriginal.lastValid,
      genesisID: firstOriginal.genesisID,
      genesisHash: firstOriginal.genesisHash,
    },
  });
  dummy.fee = 0n;
  dummy.group = groupID;
  return dummy;
}

/** Require every appended transaction to be the canonical resource dummy. */
export function validateCanonicalDummies(
  firstOriginal: Transaction,
  groupID: Uint8Array | undefined,
  appended: Transaction[],
): void {
  appended.forEach((txn, index) => {
    const want = canonicalDummyTransaction(firstOriginal, groupID, index);
    if (!byteArraysEqual(want.toByte(), txn.toByte())) {
      throw new SignerError(
        `appended transaction ${index + 1} is not the canonical resource dummy`,
      );
    }
  });
}

/** Sign a resource dummy with the dummy LogicSig, its only valid authorization. */
export function signCanonicalDummy(txn: Transaction): Uint8Array {
  const dummyAccount = new algosdk.LogicSigAccount(DUMMY_PROGRAM);
  return algosdk.signLogicSigTransactionObject(txn, dummyAccount).blob;
}

/**
 * Check a /sign or /plan result against the request.
 *
 * `returned` holds the transaction observed at each final position. An
 * undefined entry is a foreign position /sign returned empty: nothing was
 * observed, and the position is taken as the request's transaction in the
 * final group.
 *
 * `maxFeeIncrease`, when set, is the caller's ceiling on the total fee the
 * signer may add across the request's positions. The report's own total
 * cannot serve: it is written by the party being checked. Appended dummies
 * pay no fee, so the total over original positions is the whole increase.
 */
export function validateGroupMutations(
  slots: RequestSlot[],
  returned: (Transaction | undefined)[],
  mutations?: MutationReport,
  maxFeeIncrease?: bigint,
): void {
  if (returned.length < slots.length) {
    throw new SignerError(
      `signer returned ${returned.length} transaction(s), want at least ${slots.length}`,
    );
  }
  if (returned.length > MAX_GROUP_SIZE) {
    throw new SignerError(
      `signer returned ${returned.length} transaction(s), more than the maximum group size ${MAX_GROUP_SIZE}`,
    );
  }
  const appended = returned.length - slots.length;
  const passthroughCount = slots.filter((slot) => slot.mode === "passthrough").length;
  const foreignCount = slots.filter((slot) => slot.mode === "foreign").length;

  if (mutations !== undefined && mutations !== null && typeof mutations !== "object") {
    throw new SignerError("mutation report must be an object");
  }
  const report: MutationReport = mutations ?? {};
  const groupIdChanged = report.groupIdChanged ?? false;
  if (typeof groupIdChanged !== "boolean") {
    throw new SignerError("mutation group_id_changed must be a boolean");
  }
  const reportedDelta = mutationInteger(report, "totalFeesDelta", "total_fees_delta");
  if (!mutations) {
    if (appended !== 0) {
      throw new SignerError(
        `signer appended ${appended} transaction(s) without a mutation report`,
      );
    }
  } else {
    const originalCount = mutationInteger(report, "originalCount", "original_count");
    const finalCount = mutationInteger(report, "finalCount", "final_count");
    const dummiesAdded = mutationInteger(report, "dummiesAdded", "dummies_added");
    if (originalCount !== slots.length) {
      throw new SignerError(
        `mutation original_count ${originalCount} does not match request count ${slots.length}`,
      );
    }
    if (finalCount !== returned.length) {
      throw new SignerError(
        `mutation final_count ${finalCount} does not match returned count ${returned.length}`,
      );
    }
    if (dummiesAdded !== appended) {
      throw new SignerError(
        `mutation dummies_added ${dummiesAdded} does not match appended count ${appended}`,
      );
    }
    if (reportedDelta < 0) {
      throw new SignerError("mutation total_fees_delta must not be negative");
    }
    if (appended > 0 && !groupIdChanged) {
      throw new SignerError("mutation appended dummies without reporting a group ID change");
    }
    if (returned.length === 1 && groupIdChanged) {
      throw new SignerError("mutation reported a group ID change for a single transaction");
    }
  }
  const reportedPassthrough = mutationInteger(report, "passthroughCount", "passthrough_count");
  if (reportedPassthrough !== passthroughCount) {
    throw new SignerError(
      `mutation passthrough_count ${reportedPassthrough} does not match the ` +
      `${passthroughCount} passthrough transaction(s) requested`,
    );
  }
  const reportedForeign = mutationInteger(report, "foreignCount", "foreign_count");
  if (reportedForeign !== foreignCount) {
    throw new SignerError(
      `mutation foreign_count ${reportedForeign} does not match the ` +
      `${foreignCount} foreign transaction(s) requested`,
    );
  }

  const feeModified = new Set<number>();
  if (report.feesModified !== undefined && report.feesModified !== null && !Array.isArray(report.feesModified)) {
    throw new SignerError("mutation fees_modified must be an array");
  }
  for (const index of report.feesModified ?? []) {
    if (!Number.isInteger(index) || index < 0 || index >= slots.length) {
      throw new SignerError(`mutation fee index ${index} is outside original positions`);
    }
    if (feeModified.has(index)) {
      throw new SignerError(`mutation fee index ${index} is duplicated`);
    }
    if (slots[index].mode !== "sign") {
      throw new SignerError(
        `mutation fee index ${index} is a ${slots[index].mode} position, whose fee the signer cannot change`,
      );
    }
    feeModified.add(index);
  }

  let assigned: Uint8Array | undefined;
  if (groupIdChanged) {
    const observed = returned.find((txn) => txn !== undefined);
    if (!observed) {
      throw new SignerError(
        "signer reported a group ID change but returned no transaction that carries it",
      );
    }
    assigned = groupIDBytes(observed);
  }

  const final: Transaction[] = [];
  let totalFeeDelta = 0n;
  slots.forEach((slot, index) => {
    const want = cloneTransaction(slot.txn);
    if (groupIdChanged) {
      want.group = assigned;
    }
    const got = returned[index];
    if (got === undefined) {
      final.push(want);
      return;
    }
    if (feeModified.has(index)) {
      if (got.fee <= want.fee) {
        throw new SignerError(
          `reported fee mutation at original position ${index + 1} did not increase the fee`,
        );
      }
      totalFeeDelta += got.fee - want.fee;
      if (totalFeeDelta > UINT64_MAX) {
        throw new SignerError("observed fee delta overflows uint64");
      }
      want.fee = got.fee;
    }
    if (!byteArraysEqual(want.toByte(), got.toByte())) {
      throw new SignerError(
        `signer changed unreported fields at original position ${index + 1}`,
      );
    }
    final.push(got);
  });
  if (BigInt(reportedDelta) !== totalFeeDelta) {
    throw new SignerError(
      `mutation total_fees_delta ${reportedDelta} does not match observed delta ${totalFeeDelta}`,
    );
  }
  if (maxFeeIncrease !== undefined && totalFeeDelta > maxFeeIncrease) {
    throw new SignerError(
      `signer raised fees by ${totalFeeDelta} microAlgos, more than the max fee increase ${maxFeeIncrease} set on this client`,
    );
  }
  for (let index = slots.length; index < returned.length; index++) {
    const extra = returned[index];
    if (extra === undefined) {
      throw new SignerError(`signer returned no transaction at appended position ${index + 1}`);
    }
    final.push(extra);
  }

  const groupID = validateCanonicalGroupID(final);
  if (appended > 0) {
    validateCanonicalDummies(slots[0].txn, groupID, final.slice(slots.length));
  }
}

/**
 * Check a /sign response against the request before anyone can submit it.
 *
 * Sign positions must carry the requested transaction, changed only as the
 * mutation report states. Passthrough positions must come back byte for byte,
 * foreign positions stay empty, and every appended position must be the
 * canonical signed resource dummy.
 */
export function validateSignResponse(
  slots: RequestSlot[],
  signed: unknown,
  mutations?: MutationReport,
  maxFeeIncrease?: bigint,
): void {
  if (!Array.isArray(signed) || signed.some((item) => typeof item !== "string")) {
    throw new SignerError("signer returned a malformed signed list");
  }
  const signedHexes = signed as string[];
  if (signedHexes.length < slots.length) {
    throw new SignerError(
      `signer returned ${signedHexes.length} signed transaction(s), want at least ${slots.length}`,
    );
  }
  const signedBytes: Uint8Array[] = [];
  const returned = signedHexes.map((signedHex, index): Transaction | undefined => {
    const position = index + 1;
    const slot: RequestSlot | undefined = slots[index];
    if (slot?.mode === "foreign") {
      if (signedHex) {
        throw new SignerError(
          `signer returned a signed transaction for foreign position ${position}`,
        );
      }
      signedBytes.push(new Uint8Array());
      return undefined;
    }
    if (!signedHex) {
      if (!slot) {
        throw new SignerError(`signer returned empty dummy transaction at position ${position}`);
      }
      throw new SignerError(`signer returned no signature for position ${position}`);
    }
    const raw = decodeHex(signedHex, `signed transaction ${position}`);
    signedBytes.push(raw);
    if (slot?.mode === "passthrough") {
      if (!slot.signedBytes || !byteArraysEqual(raw, slot.signedBytes)) {
        throw new SignerError(`signer changed passthrough transaction ${position}`);
      }
      return slot.txn;
    }
    try {
      return decodeCanonicalSignedTransaction(raw).txn;
    } catch (error) {
      throw new SignerError(`signed transaction ${position}: ${errorText(error)}`);
    }
  });
  validateGroupMutations(slots, returned, mutations, maxFeeIncrease);
  for (let index = slots.length; index < signedHexes.length; index++) {
    const want = signCanonicalDummy(returned[index] as Transaction);
    if (!byteArraysEqual(want, signedBytes[index])) {
      throw new SignerError(
        `appended transaction ${index - slots.length + 1} does not carry the canonical resource dummy authorization`,
      );
    }
  }
}

/**
 * Check a /plan response against the request. A plan result is the final
 * group as unsigned transactions, so every position is observed, foreign
 * ones included.
 */
export function validatePlanResponse(
  slots: RequestSlot[],
  transactions: unknown,
  mutations?: MutationReport,
  maxFeeIncrease?: bigint,
): void {
  const planned = transactions ?? [];
  if (!Array.isArray(planned) || planned.some((item) => typeof item !== "string")) {
    throw new SignerError("signer returned a malformed planned transaction list");
  }
  if (planned.length < slots.length) {
    throw new SignerError(
      `signer returned ${planned.length} planned transaction(s), want at least ${slots.length}`,
    );
  }
  const returned = (planned as string[]).map((txnHex, index) => {
    const raw = decodeHex(txnHex, `planned transaction ${index + 1}`);
    try {
      return decodeCanonicalTransaction(raw);
    } catch (error) {
      throw new SignerError(`planned transaction ${index + 1}: ${errorText(error)}`);
    }
  });
  validateGroupMutations(slots, returned, mutations, maxFeeIncrease);
}

/**
 * Require a signed slot to sign exactly the canonical TX-prefixed bytes at
 * its position. The signed bytes must themselves be canonical, with nothing
 * after the signed transaction.
 */
export function signedTransactionMatchesCanonical(
  label: string,
  index: number,
  signedHex: string,
  canonicalHex: string,
): void {
  let signed: algosdk.SignedTransaction;
  try {
    signed = decodeCanonicalSignedTransaction(decodeHex(signedHex, "signed transaction"));
  } catch (error) {
    throw new SignerError(`${label} ${index}: ${errorText(error)}`);
  }
  if (encodeTransaction(signed.txn)[0] !== canonicalHex.toLowerCase()) {
    throw new SignerError(
      `${label} ${index} does not match the submitted canonical bytes`,
    );
  }
}
