// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * The rotating account flow (rotating1): every spend rekeys the account to a
 * fresh one-time stage, so the signer adds a rekey to the caller's
 * transaction. The checks here make sure it changed nothing else.
 */

import algosdk, { type Transaction } from "algosdk";
import type {
  AppCallInfo,
  MutationReport,
  RotatingPrepareResponse,
  RotatingSignResponse,
} from "./types.js";
import { SignerError, UnsupportedGroupError, errorText } from "./errors.js";
import { bytesToBase64, hexToBytes } from "./encoding.js";
import { ROTATING_PREPARE_ANSWER, readAnswer } from "./answers.js";
import {
  byteArraysEqual,
  cloneTransaction,
  decodeCanonicalSignedTransaction,
  decodeCanonicalTransaction,
  groupIDBytes,
  mutationReportFromWire,
  signCanonicalDummy,
  signSlot,
  validateAuthorization,
  validateGroupMutations,
  wholeNumber,
} from "./verify.js";

// The rotating1 timing contract (docs/ARCH_SIGNING.md in the aplane repo,
// "Rotating accounts"). The signer enforces these; the SDK mirrors them to
// build a suitable window and to refuse an unsuitable one early.

/** The longest lastValid - firstValid span a rotating account's transaction may have. */
export const ROTATING_MAX_VALIDITY_WINDOW = 100;
/** How far firstValid may be ahead of the current round when the signer signs. */
export const ROTATING_MAX_LEAD = 2;
/** The fewest rounds that must remain before lastValid when the signer signs. */
export const ROTATING_MIN_REMAINING = 10;

/** How many times one send prepares a rotating spend. */
export const ROTATING_SEND_ATTEMPTS = 3;

/**
 * The wait before preparing again after the signer reports it has not found
 * the account's live stage yet, in milliseconds. It grows with each attempt.
 * Tests shorten it; it is not part of the package's exports.
 */
export const rotatingTiming = { unprovenBackoffMs: 2000 };

const UINT64_MAX = (1n << 64n) - 1n;

/** Options for prepareRotating. */
export interface RotatingPrepareOptions {
  /**
   * Optional app-call metadata shown to the operator when the prepared spend
   * is signed. The signer checks it against the spend's bytes and does not
   * sign it.
   */
  appCallInfo?: AppCallInfo;
  /** Optional caller cancellation signal for the prepare request. */
  signal?: AbortSignal;
}

/** Options for signPreparedRotating. */
export interface RotatingSignOptions {
  /**
   * The sign request's ID, for cancelSignRequest() and the signer's audit
   * log. Empty means the SDK creates one. It is not an idempotency key.
   */
  requestId?: string;
  /**
   * Optional caller cancellation signal. Aborting it while the signer waits
   * for approval aborts the request and sends a best-effort /sign/cancel; an
   * already aborted signal sends nothing.
   */
  signal?: AbortSignal;
}

/**
 * A signed rotating group, checked against the prepared one. Submit it
 * promptly: the stage's one-time keys are revealed until this transaction or
 * a later rotation confirms.
 */
export interface RotatingSignResult {
  /** The signed group, hex msgpack, in prepared order. */
  signedGroup: string[];
  stage: number;
  target: number;
  /**
   * Computed from the prepared bytes; the signer's own report of them was
   * checked against these. groupId is base64, or empty for a lone spend.
   */
  txId: string;
  groupId: string;
  requestId: string;
}

// Only this module makes a PreparedRotating, and only after checking it.
const constructToken = Symbol("PreparedRotating");

interface PreparedRotatingFields {
  account: string;
  originalHex: string;
  stage: number;
  target: number;
  rekeyTo: string;
  transactions: string[];
  mutations?: MutationReport;
  appCallInfo?: AppCallInfo;
  ceiling: bigint | undefined;
}

function frozenReport(report: MutationReport | undefined): MutationReport | undefined {
  if (report === undefined) return undefined;
  const copy: MutationReport = { ...report };
  if (Array.isArray(report.feesModified)) {
    copy.feesModified = Object.freeze([...report.feesModified]) as number[];
  }
  return Object.freeze(copy);
}

function copyReport(report: MutationReport | undefined): MutationReport | undefined {
  if (report === undefined) return undefined;
  const copy: MutationReport = { ...report };
  if (Array.isArray(report.feesModified)) {
    copy.feesModified = [...report.feesModified];
  }
  return copy;
}

/** hexToBytes, with the position named in the error. */
function decodeHex(value: unknown, label: string): Uint8Array {
  try {
    return hexToBytes(value as string);
  } catch (error) {
    throw new SignerError(`${label}: invalid hex: ${errorText(error)}`);
  }
}

/** A stage number from the wire: a non-negative safe integer, or undefined. */
function wireStage(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function isZeroAddress(address: algosdk.Address): boolean {
  return address.publicKey.every((byte) => byte === 0);
}

/**
 * A rotating account's spend as the signer prepared it: the exact unsigned
 * group it will sign, checked against the transaction the caller sent. It
 * cannot be changed after it is made: its state is held in private fields,
 * every value it hands out is a copy, and only prepareRotating makes one.
 * Nothing has been signed and no one-time key has been used.
 */
export class PreparedRotating {
  readonly #account: string;
  readonly #originalHex: string;
  readonly #stage: number;
  readonly #target: number;
  readonly #rekeyTo: string;
  readonly #transactions: readonly string[];
  readonly #mutations?: MutationReport;
  readonly #appCallInfo?: AppCallInfo;
  readonly #ceiling: bigint | undefined;

  /** Not for callers: prepareRotating makes a PreparedRotating. */
  constructor(token: symbol, fields: PreparedRotatingFields) {
    if (token !== constructToken) {
      throw new SignerError("a PreparedRotating is made by prepareRotating");
    }
    this.#account = fields.account;
    this.#originalHex = fields.originalHex;
    this.#stage = fields.stage;
    this.#target = fields.target;
    this.#rekeyTo = fields.rekeyTo;
    this.#transactions = Object.freeze([...fields.transactions]);
    this.#mutations = frozenReport(fields.mutations);
    this.#appCallInfo = fields.appCallInfo ? Object.freeze({ ...fields.appCallInfo }) : undefined;
    this.#ceiling = fields.ceiling;
    Object.freeze(this);
  }

  /**
   * Whether value is a PreparedRotating that prepareRotating made. An object
   * built on the class's prototype is not one.
   */
  static isGenuine(value: unknown): value is PreparedRotating {
    return typeof value === "object" && value !== null && #account in value;
  }

  /**
   * Check a genuine prepared group's binding again, with the class's own
   * check. The SDK runs it when the group is simulated or signed.
   */
  static verifyBinding(prepared: PreparedRotating): void {
    if (!PreparedRotating.isGenuine(prepared)) {
      throw new SignerError("not a PreparedRotating made by prepareRotating");
    }
    prepared.#verify();
  }

  /** The rotating account. */
  get account(): string {
    return this.#account;
  }

  /** The stage whose keys will sign. */
  get stage(): number {
    return this.#stage;
  }

  /** The stage the spend hands the account to: always stage + 1. */
  get target(): number {
    return this.#target;
  }

  /**
   * The next stage's address, as the signer reported it. The SDK cannot
   * derive stage addresses; it binds this address to the prepared spend,
   * and the signer derives it again from the seed before it signs.
   */
  get rekeyTo(): string {
    return this.#rekeyTo;
  }

  /**
   * The prepared group, hex msgpack with the TX prefix: the spend first,
   * then any resource dummies.
   */
  transactions(): string[] {
    return [...this.#transactions];
  }

  /**
   * The signer's report of what it added to the spend, checked against the
   * prepared bytes. Undefined when it added nothing but the rekey.
   */
  mutations(): MutationReport | undefined {
    return copyReport(this.#mutations);
  }

  /** The transaction the caller sent to be prepared. */
  original(): Transaction {
    return decodeCanonicalTransaction(hexToBytes(this.#originalHex));
  }

  /** The IDs of the prepared transactions. Signing does not change them. */
  txIds(): string[] {
    return this.decoded().map((txn) => txn.txID());
  }

  /** The prepared transactions, decoded strictly. */
  decoded(): Transaction[] {
    return this.#transactions.map((txnHex, index) => {
      const raw = decodeHex(txnHex, `prepared transaction ${index + 1}`);
      try {
        return decodeCanonicalTransaction(raw);
      } catch (error) {
        throw new SignerError(`prepared transaction ${index + 1}: ${errorText(error)}`);
      }
    });
  }

  /** The /sign/rotating/sign request body for this prepared group. */
  signRequestBody(requestId: string): Record<string, unknown> {
    const body: Record<string, unknown> = {
      request_id: requestId,
      account: this.#account,
      transactions: this.transactions(),
    };
    if (this.#appCallInfo) {
      body.app_call_info = { ...this.#appCallInfo };
    }
    return body;
  }

  /**
   * Check the prepared group against the transaction the caller sent. It is
   * the client's authority boundary for a rotating spend: the signer may set
   * rekey_to to the address it reports, raise the spend's fee, assign the
   * canonical group ID and append canonical resource dummies, and nothing
   * else. It runs when the group is prepared, simulated and signed.
   */
  #verify(): void {
    let original: Transaction;
    try {
      original = decodeCanonicalTransaction(hexToBytes(this.#originalHex));
    } catch (error) {
      throw new SignerError(`original transaction: ${errorText(error)}`);
    }
    const sender = original.sender.toString();
    if (this.#account !== sender) {
      throw new SignerError(`prepared account ${this.#account} is not the sender`);
    }
    // A stage that is not a safe integer cannot be represented exactly, and
    // its successor neither.
    const stage = wireStage(this.#stage);
    const target = wireStage(this.#target);
    if (stage === undefined || target === undefined || target !== stage + 1) {
      throw new SignerError(
        `prepared target stage ${this.#target} is not the stage after ${this.#stage}`,
      );
    }
    let rekeyTo: algosdk.Address;
    try {
      rekeyTo = algosdk.Address.fromString(this.#rekeyTo);
    } catch (error) {
      throw new SignerError(`invalid rekey_to: ${errorText(error)}`);
    }
    // algosdk also reads the spellings that differ only in the unused low
    // bits of the last character; the Go SDK's decoder refuses them. Kept,
    // one would report a rekey_to that is not the chain's auth address.
    if (rekeyTo.toString() !== this.#rekeyTo) {
      throw new SignerError(
        `invalid rekey_to: ${this.#rekeyTo} is not the canonical spelling of ${rekeyTo.toString()}`,
      );
    }
    if (isZeroAddress(rekeyTo) || rekeyTo.toString() === sender) {
      throw new SignerError("rekey_to must be another, non-zero address");
    }
    if (this.#transactions.length === 0) {
      throw new SignerError("prepared group is empty");
    }
    const txns = this.decoded();

    // The one change no ordinary sign response may make is applied to the
    // expectation, so the common check still refuses every unrequested rekey.
    const expected = cloneTransaction(original);
    (expected as unknown as { rekeyTo?: algosdk.Address }).rekeyTo = rekeyTo;
    const slot = signSlot(expected, this.#account);
    validateGroupMutations([slot], txns, this.#mutations, this.#ceiling);
  }

  /**
   * Check that the signer signed exactly the prepared bytes: one canonically
   * encoded signed transaction per prepared transaction, in order, the spend
   * authorized by a stage program consistent with the reported stage, and
   * every dummy by the dummy program.
   */
  verifySigned(response: RotatingSignResponse): RotatingSignResult {
    const txns = this.decoded();
    // A field left out or null, and a null entry in signed, take their zero
    // values, as the Go SDK reads the answer.
    const answer = (response ?? {}) as Partial<Record<keyof RotatingSignResponse, unknown>>;
    const listed = answer.signed ?? [];
    if (!Array.isArray(listed) || listed.some((item) => item !== null && typeof item !== "string")) {
      throw new SignerError("signer returned a malformed signed list");
    }
    const signed = listed.map((item) => (item === null ? "" : item)) as string[];
    const reportedStage = answer.stage ?? 0;
    const reportedTarget = answer.target ?? 0;
    const reportedTxId = answer.txid ?? "";
    const reportedGroupId = answer.group_id ?? "";
    if (signed.length !== txns.length) {
      throw new SignerError(
        `signed group has ${signed.length} transaction(s), prepared ${txns.length}`,
      );
    }
    if (reportedStage !== this.#stage || reportedTarget !== this.#target) {
      throw new SignerError(
        `signer reports stage ${String(reportedStage)} to ${String(reportedTarget)}, prepared ${this.#stage} to ${this.#target}`,
      );
    }
    const spend = txns[0];
    signed.forEach((signedHex, index) => {
      const position = index + 1;
      const raw = decodeHex(signedHex, `signed transaction ${position}`);
      let stxn: algosdk.SignedTransaction;
      try {
        stxn = decodeCanonicalSignedTransaction(raw);
      } catch (error) {
        throw new SignerError(`signed transaction ${position}: ${errorText(error)}`);
      }
      if (!byteArraysEqual(stxn.txn.toByte(), txns[index].toByte())) {
        throw new SignerError(`signed transaction ${position} differs from the prepared transaction`);
      }
      if (index > 0) {
        if (!byteArraysEqual(raw, signCanonicalDummy(txns[index]))) {
          throw new SignerError(
            `signed transaction ${position} is not the canonical signed resource dummy`,
          );
        }
        return;
      }
      // The spend is signed by the current stage's program. Its address is
      // the account itself at stage 0 and the account's authorizer after. It
      // is never the next stage's address, which is the rekey target.
      if (!stxn.lsig || !stxn.lsig.logic || stxn.lsig.logic.length === 0) {
        throw new SignerError("spend is not authorized by a stage program");
      }
      const stageAddress = stxn.lsig.address().toString();
      try {
        validateAuthorization(stxn, stageAddress);
      } catch (error) {
        throw new SignerError(`spend ${errorText(error)}`);
      }
      if ((stageAddress === spend.sender.toString()) !== (this.#stage === 0)) {
        throw new SignerError(
          `spend's stage program does not fit stage ${this.#stage} of the account`,
        );
      }
      if (spend.rekeyTo !== undefined && stageAddress === spend.rekeyTo.toString()) {
        throw new SignerError("spend is authorized by the next stage's program");
      }
    });

    const txId = spend.txID();
    if (reportedTxId !== txId) {
      throw new SignerError(`signer reports transaction ID ${String(reportedTxId)}, the spend's is ${txId}`);
    }
    const group = groupIDBytes(spend);
    const groupId = group === undefined ? "" : bytesToBase64(group);
    // A lone spend's group is the zero digest, which a signer may report
    // encoded rather than empty.
    const zeroGroup = bytesToBase64(new Uint8Array(32));
    if (reportedGroupId !== groupId && !(groupId === "" && reportedGroupId === zeroGroup)) {
      throw new SignerError(
        `signer reports group ID ${JSON.stringify(reportedGroupId)}, the spend's is ${JSON.stringify(groupId)}`,
      );
    }
    return {
      signedGroup: [...signed],
      stage: this.#stage,
      target: this.#target,
      txId,
      groupId,
      requestId: "",
    };
  }
}

// The class and its methods cannot be replaced, so the checks the SDK calls
// on a genuine PreparedRotating are the class's own.
Object.freeze(PreparedRotating.prototype);
Object.freeze(PreparedRotating);

/**
 * Bind a prepare response to the transaction that was sent and check it.
 * Everything it keeps is a copy.
 */
export function newPreparedRotating(
  originalHex: string,
  response: unknown,
  ceiling: bigint | undefined,
  appCallInfo: AppCallInfo | undefined,
): PreparedRotating {
  // Read as the Go SDK decodes it: typed fields, the snake_case report keys
  // only, and a field left out or null at its zero value.
  const read = readAnswer<Partial<RotatingPrepareResponse>>(ROTATING_PREPARE_ANSWER, response);
  if ("problem" in read) {
    throw new SignerError(`failed to decode response: ${read.problem}`);
  }
  const body = read.answer;
  const prepared = new PreparedRotating(constructToken, {
    account: body.account ?? "",
    originalHex,
    stage: body.stage ?? 0,
    target: body.target ?? 0,
    rekeyTo: body.rekey_to ?? "",
    transactions: body.transactions ?? [],
    mutations: body.mutations ? mutationReportFromWire(body.mutations) : undefined,
    appCallInfo,
    ceiling,
  });
  PreparedRotating.verifyBinding(prepared);
  return prepared;
}

/**
 * The rotating rules about a spend's shape that need neither the signer nor
 * the chain. The signer applies them too.
 */
export function checkRotatingShape(txn: Transaction): void {
  if (groupIDBytes(txn) !== undefined) {
    throw new UnsupportedGroupError(
      "group not supported by unified sending: a rotating account's transaction must be ungrouped; the signer forms the group",
    );
  }
  if (txn.rekeyTo !== undefined && !isZeroAddress(txn.rekeyTo)) {
    throw new UnsupportedGroupError(
      "group not supported by unified sending: a rotating account's transaction must not set rekey_to; the signer rotates the account itself",
    );
  }
  const closeTo = txn.payment?.closeRemainderTo;
  if (closeTo !== undefined && !isZeroAddress(closeTo)) {
    throw new UnsupportedGroupError(
      "group not supported by unified sending: a rotating account cannot close out",
    );
  }
}

/** Refuse a validity window the stage program never accepts, whatever the round. */
export function checkRotatingWindow(txn: Transaction): void {
  if (txn.lastValid < txn.firstValid) {
    throw new SignerError(
      `last valid round ${txn.lastValid} is before first valid round ${txn.firstValid}`,
    );
  }
  const window = txn.lastValid - txn.firstValid;
  if (window > BigInt(ROTATING_MAX_VALIDITY_WINDOW)) {
    throw new SignerError(
      `validity window is ${window} rounds; a rotating account accepts at most ${ROTATING_MAX_VALIDITY_WINDOW} ` +
        "(build the transaction with a prepare helper, or set refreshValidity)",
    );
  }
}

/** Whether txn's window meets the signer's timing rule at round. */
export function rotatingWindowCurrent(txn: Transaction, round: bigint): boolean {
  const first = txn.firstValid;
  const last = txn.lastValid;
  return (
    last >= first &&
    last - first <= BigInt(ROTATING_MAX_VALIDITY_WINDOW) &&
    first <= round + BigInt(ROTATING_MAX_LEAD) &&
    last >= round + BigInt(ROTATING_MIN_REMAINING)
  );
}

/**
 * Rebuild txn's validity rounds from current suggested parameters, keeping
 * everything else. The window keeps its length unless that is over the
 * rotating limit or too short to ever be signed. widen takes the longest
 * window instead: after the signer found the window not current, the same
 * length would leave the operator no more time.
 */
export async function refreshRotatingValidity(
  algodClient: any,
  txn: Transaction,
  widen: boolean,
  customOptions?: Record<string, unknown>,
): Promise<Transaction> {
  let suggested: any;
  try {
    suggested = await algodClient.getTransactionParams().do(undefined, customOptions);
  } catch (error) {
    throw new SignerError(`failed to get suggested params: ${errorText(error)}`);
  }
  // A window shorter than the rounds that must remain can never be signed,
  // so it is not kept either.
  let window = BigInt(ROTATING_MAX_VALIDITY_WINDOW);
  if (!widen && txn.lastValid > txn.firstValid) {
    const length = txn.lastValid - txn.firstValid;
    if (length >= BigInt(ROTATING_MIN_REMAINING) && length < window) {
      window = length;
    }
  }
  const first = wholeNumber(suggested?.firstValid);
  if (first === undefined || first < 0n || first > UINT64_MAX) {
    throw new SignerError(`suggested first valid round ${String(suggested?.firstValid)} is not a round`);
  }
  if (first > UINT64_MAX - window) {
    throw new SignerError(`first valid round ${first} leaves no room for a validity window`);
  }
  const rebuilt = cloneTransaction(txn) as unknown as { firstValid: bigint; lastValid: bigint };
  rebuilt.firstValid = first;
  rebuilt.lastValid = first + window;
  return rebuilt as unknown as Transaction;
}
