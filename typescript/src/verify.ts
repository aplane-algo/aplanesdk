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

import { createPublicKey, verify as verifySignature } from "crypto";
import algosdk, { type Transaction } from "algosdk";
import type { MutationReport, SignRequest } from "./types.js";
import { signRequestMode, type SignRequestMode } from "./types.js";
import { MaxFeeIncreaseError, SignerError, errorText } from "./errors.js";
import { encodeTransaction, hexToBytes } from "./encoding.js";

/** Algorand's maximum transaction group size. */
export const MAX_GROUP_SIZE = 16;
export const DUMMY_PROGRAM = new Uint8Array([0x03, 0x31, 0x20, 0x32, 0x03, 0x12]);
/**
 * Opcode cost of one run of DUMMY_PROGRAM: txn RekeyTo, global ZeroAddress and
 * ==, three opcodes costing 1 each, with no branch. It matches apsigner's
 * signing.DummyOpcodeCost. A test derives it from the program bytes.
 */
export const DUMMY_OPCODE_COST = 3;

const UINT64_MAX = (1n << 64n) - 1n;

/**
 * The SDK's one whole-number check: a bigint, or a number that is a safe
 * integer, as a bigint. Anything else (a fraction, NaN, a string, a boolean)
 * is undefined. Callers add their own bounds and error text.
 */
export function wholeNumber(value: unknown): bigint | undefined {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  return undefined;
}

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
  const whole = wholeNumber(value);
  if (whole !== undefined && whole >= 0n) {
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
  /** The address a sign position asked the signer to sign with. */
  auth?: string;
  /** The auth address a passthrough's signed bytes carry, if any. */
  signer?: string;
}

/**
 * The slot of a sign-mode position. The auth address must be a real address:
 * the returned authorization is checked against it.
 */
export function signSlot(txn: Transaction, authAddress: string | undefined): RequestSlot {
  if (typeof authAddress !== "string" || !algosdk.isValidAddress(authAddress)) {
    throw new SignerError(`auth_address ${JSON.stringify(authAddress)} is not a valid address`);
  }
  return { mode: "sign", txn, auth: authAddress };
}

/** Decode a passthrough's signed bytes, strictly. */
export function decodePassthroughSlot(raw: Uint8Array): RequestSlot {
  const signed = decodeCanonicalSignedTransaction(raw);
  return {
    mode: "passthrough",
    txn: signed.txn,
    signedBytes: raw,
    signer: signed.sgnr?.toString(),
  };
}

// The fixed DER prefix of an Ed25519 public key in SubjectPublicKeyInfo form.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function ed25519Verifies(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
      format: "der",
      type: "spki",
    });
    return verifySignature(null, message, key, signature);
  } catch {
    return false;
  }
}

const FALCON1024_SCHEME = "f1";

/**
 * Require a signed position to carry exactly one authorization, and that
 * authorization to be the requested auth address's. A response that signs the
 * right transaction with the wrong key, or with no key at all, is as unusable
 * as one that signs the wrong transaction.
 *
 * - sig: an Ed25519 signature over the transaction that verifies under the
 *   auth address.
 * - lsig: a plain LogicSig (a program and its args, not one delegated by a
 *   signature) whose program address is the auth address.
 * - pqsig: a native Falcon-1024 proof with its public key and signature
 *   present, whose derived account address is the auth address. The Falcon
 *   signature itself is not verified.
 * - msig: refused. The signer never returns a multisig for a position it
 *   signs.
 *
 * The signer field (sgnr) must name the auth address when that differs from
 * the sender, and must be absent when they are the same.
 */
export function validateAuthorization(signed: algosdk.SignedTransaction, auth: string): void {
  const kinds = [signed.sig, signed.msig, signed.lsig, signed.pqsig].filter(
    (kind) => kind !== undefined,
  ).length;
  if (kinds === 0) {
    throw new SignerError("carries no authorization");
  }
  if (kinds > 1) {
    throw new SignerError("carries more than one authorization");
  }

  const sender = signed.txn.sender.toString();
  const named = signed.sgnr?.toString();
  const want = auth !== sender ? auth : undefined;
  if (named !== want) {
    if (want === undefined) {
      throw new SignerError(`names signer ${named}, but the sender signs for itself`);
    }
    if (named === undefined) {
      throw new SignerError(`does not name its signer ${auth}, which is not the sender`);
    }
    throw new SignerError(`names signer ${named}, not the requested auth address ${auth}`);
  }

  if (signed.msig !== undefined) {
    throw new SignerError(
      "carries a multisig, which the signer does not return for a position it signs",
    );
  }
  if (signed.sig !== undefined) {
    const message = hexToBytes(encodeTransaction(signed.txn)[0]);
    if (!ed25519Verifies(algosdk.decodeAddress(auth).publicKey, message, signed.sig)) {
      throw new SignerError(
        `signature does not verify under the requested auth address ${auth}`,
      );
    }
    return;
  }
  if (signed.lsig !== undefined) {
    const lsig = signed.lsig;
    if (!lsig.logic || lsig.logic.length === 0) {
      throw new SignerError("LogicSig has no program");
    }
    if (lsig.sig || lsig.msig || lsig.lmsig || lsig.pqsig) {
      throw new SignerError(
        "LogicSig is delegated by a signature, which the signer does not return for a position it signs",
      );
    }
    const program = lsig.address().toString();
    if (program !== auth) {
      throw new SignerError(
        `LogicSig program address ${program} is not the requested auth address ${auth}`,
      );
    }
    return;
  }
  const proof = signed.pqsig as NonNullable<typeof signed.pqsig>;
  const scheme = Buffer.from(proof.sch ?? []).toString("latin1");
  if (scheme !== FALCON1024_SCHEME) {
    throw new SignerError(
      `post-quantum scheme ${JSON.stringify(scheme)} is not ${JSON.stringify(FALCON1024_SCHEME)}`,
    );
  }
  if (!proof.pk || proof.pk.length === 0 || !proof.sig || proof.sig.length === 0) {
    throw new SignerError("post-quantum authorization is missing its public key or signature");
  }
  let derived: string;
  try {
    derived = algosdk.addressFromPQSig(proof).toString();
  } catch (error) {
    throw new SignerError(`post-quantum key's address cannot be derived: ${errorText(error)}`);
  }
  if (derived !== auth) {
    throw new SignerError(
      `post-quantum key's address ${derived} is not the requested auth address ${auth}`,
    );
  }
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
        return decodePassthroughSlot(raw);
      } catch (error) {
        throw new SignerError(
          `transaction ${position}: passthrough transaction: ${errorText(error)}`,
        );
      }
    }
    const raw = decodeHex(request.txn_bytes_hex || "", `transaction ${position}: txn_bytes_hex`);
    let txn: Transaction;
    try {
      txn = decodeCanonicalTransaction(raw);
    } catch (error) {
      throw new SignerError(`transaction ${position}: txn_bytes_hex: ${errorText(error)}`);
    }
    if (mode === "foreign") {
      return { mode, txn };
    }
    try {
      return signSlot(txn, request.auth_address);
    } catch (error) {
      throw new SignerError(`transaction ${position}: ${errorText(error)}`);
    }
  });
}

/**
 * The typed camelCase form of a wire mutation report that was read with its
 * answer's shape: only the snake_case keys, as the Go SDK reads them.
 */
export function mutationReportFromWire(raw: Record<string, any>): MutationReport {
  return {
    dummiesAdded: raw.dummies_added,
    groupIdChanged: raw.group_id_changed,
    feesModified: raw.fees_modified,
    totalFeesDelta: raw.total_fees_delta,
    originalCount: raw.original_count,
    finalCount: raw.final_count,
    passthroughCount: raw.passthrough_count,
    foreignCount: raw.foreign_count,
    reason: raw.reason,
  };
}

/**
 * The typed camelCase form of a /plan mutation report, which also takes the
 * camelCase keys.
 */
export function normalizeMutationReport(raw: any): MutationReport {
  return {
    dummiesAdded: raw.dummies_added ?? raw.dummiesAdded,
    groupIdChanged: raw.group_id_changed ?? raw.groupIdChanged,
    feesModified: raw.fees_modified ?? raw.feesModified,
    totalFeesDelta: raw.total_fees_delta ?? raw.totalFeesDelta,
    originalCount: raw.original_count ?? raw.originalCount,
    finalCount: raw.final_count ?? raw.finalCount,
    passthroughCount: raw.passthrough_count ?? raw.passthroughCount,
    foreignCount: raw.foreign_count ?? raw.foreignCount,
    reason: raw.reason,
  };
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
 * `maxFeeIncrease` is the caller's ceiling on the total fee the signer may
 * add across the request's positions, or undefined for no ceiling; it is not
 * optional, so a caller cannot leave the check out by omission. The report's
 * own total cannot serve: it is written by the party being checked. An
 * appended dummy carries a zero fee of its own, and the signer charges its
 * base fee to an original position, so the total over original positions is
 * the whole increase, dummies included.
 */
export function validateGroupMutations(
  slots: RequestSlot[],
  returned: (Transaction | undefined)[],
  mutations: MutationReport | undefined,
  maxFeeIncrease: bigint | undefined,
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

  // A request that already carries a group ID is immutable to the signer: its
  // planner raises no fee on it, appends no dummy to it and never regroups
  // it, whatever the modes of its positions. A response that reports any of
  // these could not be submitted, because positions the signer did not return
  // stay bound to the original group.
  if (slots.some((slot) => groupIDBytes(slot.txn) !== undefined)) {
    if (groupIdChanged) {
      throw new SignerError(
        "signer reported a group ID change for a request that was already grouped",
      );
    }
    if (feeModified.size > 0) {
      throw new SignerError(
        "signer reported a fee change for a request that was already grouped",
      );
    }
    if (appended > 0) {
      throw new SignerError(
        `signer appended ${appended} transaction(s) to a request that was already grouped`,
      );
    }
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
    throw new MaxFeeIncreaseError(totalFeeDelta, maxFeeIncrease);
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
  mutations: MutationReport | undefined,
  maxFeeIncrease: bigint | undefined,
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
    let decoded: algosdk.SignedTransaction;
    try {
      decoded = decodeCanonicalSignedTransaction(raw);
    } catch (error) {
      throw new SignerError(`signed transaction ${position}: ${errorText(error)}`);
    }
    if (slot) {
      try {
        validateAuthorization(decoded, slot.auth as string);
      } catch (error) {
        throw new SignerError(`signed transaction ${position} ${errorText(error)}`);
      }
    }
    return decoded.txn;
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
  mutations: MutationReport | undefined,
  maxFeeIncrease: bigint | undefined,
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
