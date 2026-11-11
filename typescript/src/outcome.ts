// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * Where things stand after an uncertain outcome: a SignOutcomeUnknownError
 * or a SubmissionUncertainError. It reads the node only. It never signs,
 * never submits and never calls the signer.
 *
 * It rests on two facts: the signer never submits, so a signature it released
 * reaches the chain only if someone holding the signed bytes submits them;
 * and a transaction cannot execute after its last valid round, which the
 * signer never changes.
 */

import type { PreparedRotating } from "./rotating.js";
import {
  SignOutcomeUnknownError,
  SignerError,
  SubmissionUncertainError,
  WaitForOutcomeError,
  callerAborted,
  errorText,
} from "./errors.js";
import { algodOptions, algodRound, algodStatus } from "./send.js";
import { wholeNumber } from "./verify.js";

/** Where an uncertain outcome stands. See OutcomeReport. */
export type OutcomeState = "confirmed" | "pending" | "not_seen" | "signable" | "expired" | "too_old";

/** The group was confirmed. Do not send it again. */
export const OUTCOME_CONFIRMED = "confirmed";
/** The group is in the node's pool. Wait. */
export const OUTCOME_PENDING = "pending";
/** The node does not have the signed group, and it can still execute. */
export const OUTCOME_NOT_SEEN = "not_seen";
/** A signature may have been released, and it can still execute. */
export const OUTCOME_SIGNABLE = "signable";
/** Nothing from the request can execute any more: a replacement is safe. */
export const OUTCOME_EXPIRED = "expired";
/**
 * The group's validity ended so long ago that the node may no longer
 * remember it. Look it up on an indexer.
 */
export const OUTCOME_TOO_OLD = "too_old";

/**
 * How many rounds past a transaction's last valid round a node is trusted to
 * answer for it. A node answers only for recent rounds: past this margin a
 * confirmed transaction can look "not found".
 */
const NODE_MEMORY_ROUNDS = 500n;

/** What resolveOutcome found. */
export interface OutcomeReport {
  state: OutcomeState;
  /** The round the group confirmed in; 0n unless state is "confirmed". */
  confirmedRound: bigint;
  /**
   * The transaction IDs: the signed group's, or a rotating account's
   * prepared group's. Empty when they are not known: the signer may have
   * changed an ordinary or cosigned group's transactions.
   */
  txIds: string[];
  /** The earliest last valid round, from the error. */
  lastValid: bigint;
  /** The node's last round when it was checked. */
  currentRound: bigint;
  /** Whether building and signing a replacement is safe now. */
  safeToReplace: boolean;
  /** The signed group the error carried, hex msgpack. */
  signedGroup?: string[];
  /** The prepared rotating group the error carried. */
  rotating?: PreparedRotating;
  /** What to do, in one sentence. */
  advice: string;
}

/** Options for resolveOutcome. */
export interface ResolveOutcomeOptions {
  /** Optional caller cancellation signal, passed to the node's requests. */
  signal?: AbortSignal;
}

/** Options for waitForOutcome. */
export interface WaitForOutcomeOptions {
  /** Optional caller cancellation signal. */
  signal?: AbortSignal;
  /** How long to wait, in milliseconds. Unset or 0 waits until the outcome settles. */
  timeoutMs?: number;
}

/** What the node said of the group's first transaction. */
type Lookup =
  | { found: "confirmed"; round: bigint }
  | { found: "pool" }
  | { found: "pool_error" }
  | { found: "not_found" };

type UncertainError = SubmissionUncertainError | SignOutcomeUnknownError;

/**
 * The error, if it is one resolveOutcome reads, with the values it needs.
 * Anything else is refused before the node is asked anything.
 */
function checkUncertain(error: unknown): UncertainError {
  if (!(error instanceof SubmissionUncertainError) && !(error instanceof SignOutcomeUnknownError)) {
    throw new SignerError("not an uncertain outcome");
  }
  // Zero would read as long expired; only an error built by hand has it.
  if (typeof error.lastValid !== "bigint" || error.lastValid <= 0n) {
    throw new SignerError("the error carries no last valid round");
  }
  if (error instanceof SubmissionUncertainError && (!Array.isArray(error.txIds) || error.txIds.length === 0)) {
    throw new SignerError("the error carries no transaction IDs");
  }
  return error;
}

/** The node's last round. */
async function nodeRound(algodClient: any, signal?: AbortSignal): Promise<bigint> {
  let status: any;
  try {
    status = await algodClient.status().do(undefined, algodOptions(signal));
  } catch (error) {
    if (signal?.aborted) throw callerAborted();
    throw new SignerError(`read the node's last round: ${errorText(error)}`);
  }
  return algodRound(status?.lastRound, "last round");
}

/**
 * Look the first transaction ID up in the node's pool and recent blocks. A
 * group is atomic, so one ID is enough. A 404 is "not found"; any other
 * failure is an error, never a state.
 */
async function lookUp(algodClient: any, txId: string, signal?: AbortSignal): Promise<Lookup> {
  let info: any;
  try {
    info = await algodClient.pendingTransactionInformation(txId).do(undefined, algodOptions(signal));
  } catch (error) {
    if (algodStatus(error) === 404) return { found: "not_found" };
    if (signal?.aborted) throw callerAborted();
    throw new SignerError(`look up transaction ${txId}: ${errorText(error)}`);
  }
  if (typeof info !== "object" || info === null) {
    throw new SignerError(`look up transaction ${txId}: the node's answer is not an object`);
  }
  const confirmed = info.confirmedRound === undefined || info.confirmedRound === null
    ? 0n
    : wholeNumber(info.confirmedRound);
  if (confirmed === undefined || confirmed < 0n) {
    throw new SignerError(`look up transaction ${txId}: confirmed round ${String(info.confirmedRound)} is not a round`);
  }
  if (confirmed > 0n) return { found: "confirmed", round: confirmed };
  const poolError = info.poolError;
  if (poolError !== undefined && poolError !== null && typeof poolError !== "string") {
    throw new SignerError(`look up transaction ${txId}: the pool error is not text`);
  }
  if (typeof poolError === "string" && poolError !== "") return { found: "pool_error" };
  return { found: "pool" };
}

function confirmedAdvice(round: bigint): string {
  return `The group was confirmed in round ${round}. Do not send it again.`;
}

const PENDING_ADVICE = "The group is in the node's pool. Wait; do not send again.";

/**
 * Say where an uncertain outcome stands, from the node's last round and, when
 * the transaction IDs are known, a lookup of the first one.
 */
export async function resolveOutcome(
  algodClient: any,
  error: unknown,
  options?: ResolveOutcomeOptions,
): Promise<OutcomeReport> {
  const uncertain = checkUncertain(error);
  if (!algodClient) {
    throw new SignerError("algodClient is required");
  }
  const signal = options?.signal;
  if (signal?.aborted) {
    throw callerAborted();
  }
  const lastValid = uncertain.lastValid;
  // The round is read before the lookup: a group not found once the round
  // is past its last valid round can no longer confirm later.
  const current = await nodeRound(algodClient, signal);
  const report = (
    state: OutcomeState,
    advice: string,
    fields: Partial<OutcomeReport> = {},
  ): OutcomeReport => ({
    state,
    confirmedRound: 0n,
    txIds: [],
    lastValid,
    currentRound: current,
    safeToReplace: state === OUTCOME_EXPIRED,
    advice,
    ...fields,
  });

  if (uncertain instanceof SubmissionUncertainError) {
    const kept = { txIds: [...uncertain.txIds], signedGroup: [...uncertain.signedGroup] };
    const found = await lookUp(algodClient, uncertain.txIds[0], signal);
    if (found.found === "confirmed") {
      return report(OUTCOME_CONFIRMED, confirmedAdvice(found.round), { ...kept, confirmedRound: found.round });
    }
    if (found.found === "pool") {
      return report(OUTCOME_PENDING, PENDING_ADVICE, kept);
    }
    // Not found, or dropped from the pool.
    if (current <= lastValid) {
      return report(
        OUTCOME_NOT_SEEN,
        `The node does not have the group and it can still execute until round ${lastValid}. ` +
          `Submit the same signed group again, or wait until round ${lastValid} has passed.`,
        kept,
      );
    }
    if (current <= lastValid + NODE_MEMORY_ROUNDS) {
      return report(
        OUTCOME_EXPIRED,
        "The group was not confirmed and can no longer execute. It is safe to build a new one.",
        kept,
      );
    }
    return report(
      OUTCOME_TOO_OLD,
      "The group's validity ended more than 500 rounds ago and this node may no longer remember it. " +
        "Look the transaction ID up on an indexer before sending again.",
      kept,
    );
  }

  // Nothing was submitted by the call that failed. A rotating account's
  // prepared group has known IDs, since signing does not change them, and
  // someone holding a released signature may have submitted it. Any other
  // group's IDs are unknown: the signer may have changed its transactions.
  const rotating = uncertain.rotating;
  let txIds: string[] = [];
  if (rotating) {
    txIds = rotating.txIds();
    const found = await lookUp(algodClient, txIds[0], signal);
    if (found.found === "confirmed") {
      return report(OUTCOME_CONFIRMED, confirmedAdvice(found.round), { txIds, rotating, confirmedRound: found.round });
    }
    if (found.found === "pool") {
      return report(OUTCOME_PENDING, PENDING_ADVICE, { txIds, rotating });
    }
    // Not found, or dropped from the pool: the rounds decide.
  }
  const fields: Partial<OutcomeReport> = rotating ? { txIds, rotating } : {};
  if (current <= lastValid) {
    const next = rotating
      ? `Sign the same prepared group again, or wait until round ${lastValid} has passed.`
      : `Wait until round ${lastValid} has passed before building a replacement.`;
    return report(
      OUTCOME_SIGNABLE,
      `A signature may have been released and can execute until round ${lastValid}. ${next}`,
      fields,
    );
  }
  // This call never submitted, so expiry alone settles it.
  return report(
    OUTCOME_EXPIRED,
    "No signature released by that request can execute any more. It is safe to build a new one.",
    fields,
  );
}

/** The longest delay a timer takes. */
const MAX_TIMER_MS = 2_147_483_647;

/**
 * promise, or a rejection as soon as signal aborts: a node call that does not
 * honour the signal does not hold the wait past its end.
 */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    promise.catch(() => undefined);
    return Promise.reject(callerAborted());
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(callerAborted());
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (reason) => {
        signal.removeEventListener("abort", onAbort);
        reject(reason);
      },
    );
  });
}

/** Whether a state is final: nothing more can happen to the group. */
function settled(state: OutcomeState): boolean {
  return state === OUTCOME_CONFIRMED || state === OUTCOME_EXPIRED || state === OUTCOME_TOO_OLD;
}

/**
 * Call resolveOutcome once per round until the outcome is confirmed, expired
 * or too old. When the caller's signal is aborted or the time limit passes
 * first, it throws a WaitForOutcomeError that carries the last report. It
 * never signs or submits anything.
 */
export async function waitForOutcome(
  algodClient: any,
  error: unknown,
  options?: WaitForOutcomeOptions,
): Promise<OutcomeReport> {
  checkUncertain(error);
  const timeoutMs = options?.timeoutMs;
  if (
    timeoutMs !== undefined &&
    timeoutMs !== null &&
    (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs < 0)
  ) {
    throw new SignerError("timeoutMs must be a non-negative number of milliseconds");
  }
  if (typeof timeoutMs === "number" && timeoutMs > MAX_TIMER_MS) {
    throw new SignerError(`timeoutMs must not exceed ${MAX_TIMER_MS} milliseconds`);
  }
  const callerSignal = options?.signal;
  const controller = new AbortController();
  let ending: unknown;
  const end = (cause: unknown) => {
    if (ending === undefined) ending = cause;
    controller.abort();
  };
  const onAbort = () => end(callerAborted());
  let timer: ReturnType<typeof setTimeout> | undefined;
  if (callerSignal?.aborted) {
    onAbort();
  } else {
    callerSignal?.addEventListener("abort", onAbort, { once: true });
  }
  if (timeoutMs) {
    timer = setTimeout(
      () => end(new SignerError(`the outcome did not settle within ${timeoutMs} ms`)),
      timeoutMs,
    );
  }
  const signal = controller.signal;
  let last: OutcomeReport | undefined;
  try {
    for (;;) {
      if (signal.aborted) throw new WaitForOutcomeError(last, ending);
      try {
        last = await untilAborted(resolveOutcome(algodClient, error, { signal }), signal);
      } catch (failure) {
        if (signal.aborted) throw new WaitForOutcomeError(last, ending);
        throw failure;
      }
      if (settled(last.state)) return last;
      if (signal.aborted) throw new WaitForOutcomeError(last, ending);
      // statusAfterBlock(n) returns once round n+1 exists.
      try {
        await untilAborted(
          Promise.resolve(algodClient.statusAfterBlock(last.currentRound).do(undefined, algodOptions(signal))),
          signal,
        );
      } catch (failure) {
        if (signal.aborted) throw new WaitForOutcomeError(last, ending);
        throw new SignerError(`wait for round ${last.currentRound + 1n}: ${errorText(failure)}`);
      }
    }
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    callerSignal?.removeEventListener("abort", onAbort);
  }
}
