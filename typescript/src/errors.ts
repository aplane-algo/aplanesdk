// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import type { SignRequest } from "./types.js";
import type { PreparedRotating } from "./rotating.js";

/**
 * Base exception for signer errors.
 *
 * `code` carries the stable machine-readable wire error code from the signer
 * when one was provided (see ErrorCodes in types.ts); branch on it instead of
 * matching message text. Empty when the error was raised client-side or the
 * response body was not a JSON error envelope.
 */
export class SignerError extends Error {
  code: string;

  constructor(message: string, code: string = "") {
    super(message);
    this.name = "SignerError";
    this.code = code;
  }
}

/**
 * The signer raised fees by more than the client's `maxFeeIncrease`. `raised`
 * is the total the signer added across the request's positions and `limit`
 * the ceiling the call was held to, both in microAlgos.
 */
export class MaxFeeIncreaseError extends SignerError {
  readonly raised: bigint;
  readonly limit: bigint;

  constructor(raised: bigint, limit: bigint, prefix: string = "") {
    super(
      `${prefix}signer raised fees by ${raised} microAlgos, more than the max fee increase ${limit} set on this client`,
    );
    this.name = "MaxFeeIncreaseError";
    this.raised = raised;
    this.limit = limit;
  }

  /**
   * JSON.stringify cannot write a bigint, so the amounts are written as
   * decimal strings.
   */
  toJSON(): { name: string; message: string; raised: string; limit: string } {
    return {
      name: this.name,
      message: this.message,
      raised: this.raised.toString(),
      limit: this.limit.toString(),
    };
  }
}

/** Word a failed check of a signer result, keeping a ceiling refusal's type. */
export function verificationError(prefix: string, error: unknown): SignerError {
  if (error instanceof MaxFeeIncreaseError) {
    return new MaxFeeIncreaseError(error.raised, error.limit, prefix);
  }
  return new SignerError(`${prefix}${errorText(error)}`);
}

/**
 * The signer refused the request as unauthenticated (HTTP 401): the
 * connection did not arrive through an enrolled SSH key.
 */
export class AuthenticationError extends SignerError {
  constructor(message: string = "Not authenticated: connect through an enrolled SSH key", code: string = "") {
    super(message, code);
    this.name = "AuthenticationError";
  }
}

/**
 * Operator rejected the signing request (HTTP 403).
 */
export class SigningRejectedError extends SignerError {
  constructor(message: string = "Signing request rejected by operator", code: string = "") {
    super(message, code);
    this.name = "SigningRejectedError";
  }
}

/**
 * Signer not reachable or locked (HTTP 503, timeout, network error).
 */
export class SignerUnavailableError extends SignerError {
  constructor(message: string = "Signer not reachable or locked", code: string = "") {
    super(message, code);
    this.name = "SignerUnavailableError";
  }
}

/**
 * Requested auth_address not found in signer.
 */
export class KeyNotFoundError extends SignerError {
  constructor(message: string = "Key not found in signer", code: string = "") {
    super(message, code);
    this.name = "KeyNotFoundError";
  }
}

/**
 * Key deletion failed (not found or other error).
 */
export class KeyDeletionError extends SignerError {
  constructor(message: string = "Key deletion failed", code: string = "") {
    super(message, code);
    this.name = "KeyDeletionError";
  }
}

/**
 * Enrollment of the client key failed (rejected by the operator, no operator
 * connected, or the signer could not record the key).
 */
export class EnrollmentError extends SignerError {
  constructor(message: string = "Enrollment failed", code: string = "") {
    super(message, code);
    this.name = "EnrollmentError";
  }
}

/**
 * Transaction was rejected by the network.
 */
export class TransactionRejectedError extends SignerError {
  /** Transaction ID (if known) */
  txid: string;
  /** Rejection reason */
  reason: string;

  constructor(txid: string, reason: string) {
    super(`Transaction ${txid} rejected: ${reason}`);
    this.name = "TransactionRejectedError";
    this.txid = txid;
    this.reason = reason;
  }
}

/**
 * LogicSig program returned false.
 */
export class LogicSigRejectedError extends TransactionRejectedError {
  constructor(txid: string, reason: string = "LogicSig program returned false") {
    super(txid, reason);
    this.name = "LogicSigRejectedError";
  }
}

/**
 * Account has insufficient funds for the transaction.
 */
export class InsufficientFundsError extends TransactionRejectedError {
  constructor(txid: string, reason: string = "Insufficient funds") {
    super(txid, reason);
    this.name = "InsufficientFundsError";
  }
}

/**
 * Transaction is malformed or invalid.
 */
export class InvalidTransactionError extends TransactionRejectedError {
  constructor(txid: string, reason: string = "Invalid transaction") {
    super(txid, reason);
    this.name = "InvalidTransactionError";
  }
}

/** The message of a caught value, which need not be an Error. */
export function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * A key in the group needs a signing flow this SDK version cannot run. Thrown
 * by sendPrepared before any signature is requested.
 */
export class UnsupportedSigningFlowError extends SignerError {
  constructor(message: string = "unsupported signing flow") {
    super(message);
    this.name = "UnsupportedSigningFlowError";
  }
}

/**
 * The group is one unified sending does not cover, such as a pre-signed or
 * foreign position, or a rotating account's transaction in a group. The
 * lower-level signing calls still handle it. Nothing was signed.
 */
export class UnsupportedGroupError extends SignerError {
  constructor(message: string = "group not supported by unified sending") {
    super(message);
    this.name = "UnsupportedGroupError";
  }
}

/**
 * A signing exchange ended with no usable answer: a /sign request, or an
 * approval-bearing step of the cosigned or rotating sequence. The signer may
 * or may not have released a signature. Nothing was submitted by this call.
 *
 * `requestId` and `requests` are set for the ordinary /sign flow; `rotating`
 * is the prepared group of a rotating account, and calling
 * signPreparedRotating with it again asks for the same transaction and is the
 * safe recovery. Do not build and sign a replacement transaction on the
 * strength of this error alone: check the request with the operator or the
 * signer's audit log first. `cause` is the failure that ended the exchange.
 */
export class SignOutcomeUnknownError extends SignerError {
  readonly requestId: string;
  readonly requests?: SignRequest[];
  readonly rotating?: PreparedRotating;
  readonly cause: unknown;

  constructor(options: {
    requestId?: string;
    requests?: SignRequest[];
    rotating?: PreparedRotating;
    cause: unknown;
  }) {
    const requestId = options.requestId ?? "";
    super(
      requestId === ""
        ? `signing ended with no answer, so a signature may have been released: ${errorText(options.cause)}`
        : `sign request ${requestId}: no answer from the signer, so a signature may have been released: ${errorText(options.cause)}`,
    );
    this.name = "SignOutcomeUnknownError";
    this.requestId = requestId;
    this.requests = options.requests;
    this.rotating = options.rotating;
    this.cause = options.cause;
  }
}

function firstOrEmpty(values: string[]): string {
  return values.length === 0 ? "" : values[0];
}

/**
 * The network refused the signed group: the node rejected it on submission,
 * or dropped it from its pool. The signed bytes (hex msgpack) and their IDs
 * are kept.
 */
export class SubmissionRejectedError extends SignerError {
  readonly signedGroup: string[];
  readonly txIds: string[];
  readonly cause: unknown;

  constructor(signedGroup: string[], txIds: string[], cause: unknown) {
    super(`network rejected transaction ${firstOrEmpty(txIds)}: ${errorText(cause)}`);
    this.name = "SubmissionRejectedError";
    this.signedGroup = [...signedGroup];
    this.txIds = [...txIds];
    this.cause = cause;
  }
}

/** Where a send's outcome became uncertain. See SubmissionUncertainError. */
export type SendStage = "unsent" | "submit" | "confirm";

/** The submission's answer never arrived, so the node may or may not have the group. */
export const SEND_STAGE_SUBMIT = "submit";
/** The node accepted the group, and it was not seen in a block within the wait. */
export const SEND_STAGE_CONFIRM = "confirm";
/**
 * The group was signed and the call ended before it was sent to the node,
 * because the caller's signal was aborted. The node does not have it; submit
 * `signedGroup` to send it.
 */
export const SEND_STAGE_UNSENT = "unsent";

/**
 * A signed group this call did not see confirmed or refused. Unless `stage`
 * is "unsent" the group may still confirm. Look its IDs up, or submit the
 * same `signedGroup` again while it is valid; never sign a replacement until
 * the outcome is known, because both could execute.
 */
export class SubmissionUncertainError extends SignerError {
  readonly stage: SendStage;
  readonly signedGroup: string[];
  readonly txIds: string[];
  readonly cause: unknown;

  constructor(stage: SendStage, signedGroup: string[], txIds: string[], cause: unknown) {
    super(`outcome of transaction ${firstOrEmpty(txIds)} is unknown (${stage}): ${errorText(cause)}`);
    this.name = "SubmissionUncertainError";
    this.stage = stage;
    this.signedGroup = [...signedGroup];
    this.txIds = [...txIds];
    this.cause = cause;
  }
}

/**
 * A prepared rotating group failed its unsigned simulation, or the node
 * returned no result for it. Nothing was signed. `failureMessage` is the
 * node's failure message.
 */
export class RotatingPreflightError extends SignerError {
  readonly prepared: PreparedRotating;
  readonly failureMessage: string;

  constructor(prepared: PreparedRotating, failureMessage: string) {
    super(`prepared rotating group failed simulation; nothing was signed: ${failureMessage}`);
    this.name = "RotatingPreflightError";
    this.prepared = prepared;
    this.failureMessage = failureMessage;
  }
}

// Errors from an approval-bearing exchange that ended with no usable answer:
// the exchange failed, or a 200 arrived whose body could not be read as the
// answer. The signer may have acted on the request. The error itself keeps its
// class and message, so the lower-level calls report it as before; a send
// reads the mark. The mark is a property of the error under a registered
// symbol, so it survives wrapping as another error's cause and is the same
// mark whichever build of the package (ESM or CommonJS) made the error.
const LOST_ANSWER = Symbol.for("aplanesdk.lostAnswer");

/** Mark error as a lost answer of an approval-bearing request, and return it. */
export function markLostAnswer<T>(error: T): T {
  if ((typeof error === "object" && error !== null) || typeof error === "function") {
    try {
      Object.defineProperty(error, LOST_ANSWER, {
        value: true,
        enumerable: false,
        configurable: true,
      });
    } catch {
      // A frozen value cannot carry the mark; it is not an error the SDK made.
    }
  }
  return error;
}

/**
 * Whether error, or an error in its cause chain, is a lost answer of an
 * approval-bearing request.
 */
export function isLostAnswer(error: unknown): boolean {
  const seen = new Set<unknown>();
  let current: unknown = error;
  while ((typeof current === "object" && current !== null) || typeof current === "function") {
    if (seen.has(current)) return false;
    seen.add(current);
    if ((current as Record<symbol, unknown>)[LOST_ANSWER] === true) return true;
    current = (current as { cause?: unknown }).cause;
  }
  return false;
}

/**
 * The plain stop for a caller's aborted signal, before anything was asked:
 * the error an aborted request already raises.
 */
export function callerAborted(): SignerUnavailableError {
  return new SignerUnavailableError("Request aborted by caller");
}
