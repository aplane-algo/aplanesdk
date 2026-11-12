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
 * Cosigner discovery could not route a cosigned account's witness key to
 * exactly one cosigner endpoint of endpoints.yaml: no endpoint lists it, more
 * than one does, none is configured, or an endpoint's SSH host key differs
 * from the pinned one. It is a plain error, never an unknown outcome: the
 * cosigned sequence resolves a target that cannot take the listed-rekey path
 * before any approval-bearing request, and one that may take it only after
 * the base component answer says it needs the cosigner, before the cosigner
 * is asked. `cause` is the underlying failure, when there is one.
 */
export class CosignerDiscoveryError extends SignerError {
  readonly cause?: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "CosignerDiscoveryError";
    this.cause = cause;
  }
}

/**
 * A signing exchange ended with no usable answer: a /sign request, or an
 * approval-bearing step of the cosigned or rotating sequence, got no answer,
 * an answer that could not be read, or one the SDK failed while checking
 * (a fault in the SDK, not a refusal by its checks). The signer may or may
 * not have released a signature. Nothing was submitted by this call.
 *
 * `requestId` is the request whose answer was lost: the /sign request of the
 * ordinary flow, the rotating sign request, or the cosigned sequence's
 * /sign/component, /sign/assemble or primary /sign request. `requests` is
 * set for the ordinary /sign flow; `rotating` is the prepared group of a
 * rotating account, and calling signPreparedRotating with it again asks for
 * the same transaction, with the same IDs, and is the safe recovery. For any
 * other account, do not build a replacement with different transaction IDs
 * until the round `lastValid` has passed; the operator or the signer's audit
 * log can say what happened to the request. `cause` is the failure that
 * ended the exchange.
 *
 * `lastValid` is the earliest last valid round among the transactions sent to
 * be signed (of the prepared group, for a rotating account). The signer never
 * changes a validity round, so after that round no signature the request
 * released can execute, and for an account that is not rotating a
 * replacement is then safe without any lookup.
 */
export class SignOutcomeUnknownError extends SignerError {
  readonly requestId: string;
  readonly requests?: SignRequest[];
  readonly rotating?: PreparedRotating;
  readonly lastValid: bigint;
  readonly cause: unknown;

  constructor(options: {
    requestId?: string;
    requests?: SignRequest[];
    rotating?: PreparedRotating;
    lastValid: bigint;
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
    this.lastValid = options.lastValid;
    this.cause = options.cause;
  }
}

function firstOrEmpty(values: string[]): string {
  return values.length === 0 ? "" : values[0];
}

/**
 * A send signed a group, and algosdk's submit call or its confirmation wait
 * then failed. It says which step failed and nothing about what the node did.
 *
 * `signedGroup` is the signed group, hex msgpack, and `txIds` its transaction
 * IDs. `lastValid` is the earliest last valid round of the group. `submitted`
 * is true when algosdk's sendRawTransaction returned success and the failure
 * came later, and false when it did not return success. False does not mean
 * the node lacks the group: the answer may have been lost. `cause` is
 * algosdk's error, unchanged (the signal's reason when the call's signal was
 * aborted); read it as in any algosdk program.
 *
 * When `submitted` is true, follow the group with algosdk's
 * waitForConfirmation on the first of `txIds` for `lastValid` minus the
 * current round, at least 1.
 *
 * When it is false, there are two cases. If `cause` is algod's own HTTP 400
 * (algosdk's error then carries the answer, and `cause.response.status` is
 * 400), the node answered: read its reason, as in any algosdk program. The
 * reason decides what to do. A node that says the transaction is already in
 * the ledger or the pool has the group: follow the first of `txIds`. A
 * refusal the same bytes always get, such as an overspend or a failed
 * signature or program, stands; after `lastValid`, "dead" is such an answer
 * and proves nothing about whether the group confirmed earlier. A refusal
 * that depends on the moment, such as a fee below what the pool asks now or
 * a node that is behind, may not recur: submitting the same group later may
 * work. Anything else (no answer, a lost connection, a 5xx, the signal)
 * leaves open whether the node has the group: follow the first of `txIds`
 * with algosdk's wait for a few rounds, and if it does not confirm, submit
 * the same `signedGroup` again with SignerClient.submitSignedGroup. The same
 * signed group cannot pay twice. After `lastValid` neither a refusal nor a
 * node's "not found" proves anything; check an indexer. The SDK itself reads
 * neither the status nor the text.
 */
export class SubmissionError extends SignerError {
  readonly signedGroup: string[];
  readonly txIds: string[];
  readonly lastValid: bigint;
  readonly submitted: boolean;
  readonly cause: unknown;

  constructor(options: {
    signedGroup: string[];
    txIds: string[];
    lastValid: bigint;
    submitted: boolean;
    cause: unknown;
  }) {
    const step = options.submitted ? "wait for confirmation of" : "submit";
    super(`${step} transaction ${firstOrEmpty(options.txIds)}: ${errorText(options.cause)}`);
    this.name = "SubmissionError";
    this.signedGroup = [...options.signedGroup];
    this.txIds = [...options.txIds];
    this.lastValid = options.lastValid;
    this.submitted = options.submitted;
    this.cause = options.cause;
  }
}

/**
 * A prepared rotating group failed its unsigned simulation: the node reported
 * a failure, or returned no result for it, more than one, or a result without
 * one transaction result per transaction. Nothing was signed.
 * `failureMessage` is the node's failure message, or which of those it was.
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
// reads the mark, and the ID of the request whose answer was lost from it.
// The mark is a property of the error under a registered symbol, so it
// survives wrapping as another error's cause and is the same mark whichever
// build of the package (ESM or CommonJS) made the error.
const LOST_ANSWER = Symbol.for("aplanesdk.lostAnswer");

/** What the lost-answer mark holds. */
interface LostAnswerMark {
  /** The ID of the request whose answer was lost. */
  requestId: string;
}

/**
 * Mark error as the lost answer of the approval-bearing request requestId,
 * and return it.
 */
export function markLostAnswer<T>(error: T, requestId: string = ""): T {
  if ((typeof error === "object" && error !== null) || typeof error === "function") {
    try {
      Object.defineProperty(error, LOST_ANSWER, {
        value: Object.freeze({ requestId }),
        enumerable: false,
        configurable: true,
      });
    } catch {
      // A frozen value cannot carry the mark; it is not an error the SDK made.
    }
  }
  return error;
}

/** The first lost-answer mark on error or its cause chain. */
function lostAnswerMark(error: unknown): LostAnswerMark | undefined {
  const seen = new Set<unknown>();
  let current: unknown = error;
  while ((typeof current === "object" && current !== null) || typeof current === "function") {
    if (seen.has(current)) return undefined;
    seen.add(current);
    const mark = (current as Record<symbol, unknown>)[LOST_ANSWER];
    if (typeof mark === "object" && mark !== null) {
      const requestId = (mark as { requestId?: unknown }).requestId;
      return { requestId: typeof requestId === "string" ? requestId : "" };
    }
    current = (current as { cause?: unknown }).cause;
  }
  return undefined;
}

/**
 * Whether error, or an error in its cause chain, is a lost answer of an
 * approval-bearing request.
 */
export function isLostAnswer(error: unknown): boolean {
  return lostAnswerMark(error) !== undefined;
}

/**
 * The ID of the approval-bearing request whose answer error lost, or "" when
 * error is not a lost answer or the mark names no request.
 */
export function lostAnswerRequestId(error: unknown): string {
  return lostAnswerMark(error)?.requestId ?? "";
}

// An error a cosigner resolver threw. A resolver runs before the request that
// needs its answer, so its error is never an unknown outcome, even when it
// carries a lost-answer mark from a call the resolver made: the mark there
// says nothing of this send. The error is marked in place and passed on as it
// is; a value that cannot take a property is remembered instead.
const RESOLVER_ERROR = Symbol.for("aplanesdk.resolverError");
const unmarkableResolverErrors = new WeakSet<object>();

/** Mark error as one a cosigner resolver threw, and return it. */
export function markResolverError<T>(error: T): T {
  if ((typeof error === "object" && error !== null) || typeof error === "function") {
    try {
      Object.defineProperty(error, RESOLVER_ERROR, { value: true, enumerable: false, configurable: true });
    } catch {
      unmarkableResolverErrors.add(error as object);
    }
  }
  return error;
}

/** Whether error itself is one a cosigner resolver threw. */
export function isResolverError(error: unknown): boolean {
  if ((typeof error !== "object" || error === null) && typeof error !== "function") return false;
  return (error as Record<symbol, unknown>)[RESOLVER_ERROR] === true ||
    unmarkableResolverErrors.has(error as object);
}

/**
 * The plain stop for a caller's aborted signal, before anything was asked:
 * the error an aborted request already raises.
 */
export function callerAborted(): SignerUnavailableError {
  return new SignerUnavailableError("Request aborted by caller");
}
