// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * The one submission layer of every send: it submits signed bytes exactly as
 * given with algosdk and waits with algosdk's own confirmation wait. It never
 * signs or rebuilds anything.
 */

import algosdk, { type Transaction } from "algosdk";
import type { MutationReport } from "./types.js";
import type { CosignedCosignerResolver, CosignedSignResult, SignerClient } from "./client.js";
import { SignerError, SubmissionError, errorText } from "./errors.js";
import { bytesToBase64, encodeTransaction, hexToBytes } from "./encoding.js";
import {
  decodeCanonicalSignedTransaction,
  groupIDBytes,
  validateCanonicalGroupID,
  wholeNumber,
} from "./verify.js";

/** How many rounds a send waits for confirmation when waitRounds is unset or zero. */
export const DEFAULT_SEND_WAIT_ROUNDS = 10;

const UINT64_MAX = (1n << 64n) - 1n;

/** How far a send got on the network. */
export type SendOutcome = "submitted" | "confirmed";
/**
 * algosdk's submit call returned success, and the send did not wait for
 * confirmation. Returned only when SendOptions.noWait is set.
 */
export const SEND_OUTCOME_SUBMITTED = "submitted";
/** algosdk's waitForConfirmation returned the group's confirmed round. */
export const SEND_OUTCOME_CONFIRMED = "confirmed";

/**
 * Options for sendPrepared, sendPayment and submitSignedGroup. With none
 * set, a send signs, submits and waits for confirmation.
 */
export interface SendOptions {
  /**
   * Return as soon as algosdk's submit call returns success, with outcome
   * "submitted", instead of waiting for confirmation.
   */
  noWait?: boolean;
  /**
   * How many rounds algosdk's waitForConfirmation waits for the group. Unset
   * or zero means 10. The wait takes no signal, so this is what bounds it.
   */
  waitRounds?: number | bigint;
  /**
   * Let a send rebuild the validity rounds of a rotating account's
   * transaction when they are stale or the window is too long. That changes
   * the transaction's ID, so it is off by default for a transaction the
   * caller supplies. Do not set it when something outside the transaction,
   * such as an app argument or a proof, binds its rounds. sendPayment builds
   * its own transaction and always may. Other accounts ignore it.
   */
  refreshValidity?: boolean;
  /**
   * A cosigned account's cosigner, used only when the group has a position
   * that needs one. Give a client, with the Witness Key ID it signs under,
   * or a resolver. The caller owns these clients; a send never closes them.
   * With neither, a client made with SignerClient.fromEnv finds the cosigner
   * in its endpoints.yaml (see EndpointCosignerResolver) and closes the
   * connections it opens for that when it is closed.
   */
  cosignerClient?: SignerClient;
  cosignerComponentKey?: string;
  cosignerResolver?: CosignedCosignerResolver;
  /**
   * Optional caller cancellation signal. It covers signing and submission.
   * An abort before anything is asked of the signer is a plain stop. Once a
   * group is signed, an abort found before the submit call ends the send
   * with a SubmissionError whose submitted is false, and nothing is posted;
   * one found after a successful submit and before the confirmation wait
   * starts ends it with a SubmissionError whose submitted is true. Either
   * way the signal's reason is the cause. With noWait there is no wait to
   * start, so a send whose submit call returned success returns its result
   * whatever the signal. The signal is also passed to the algod requests
   * the send makes, the submit call among them. algosdk's
   * waitForConfirmation takes no signal, so the wait cannot be interrupted:
   * waitRounds bounds it.
   */
  signal?: AbortSignal;
}

/** The rotation a rotating account's send performed. */
export interface RotatingSendDetails {
  /** The stage that signed the spend; target, stage + 1, now controls the account. */
  stage: number;
  target: number;
  /** The target's address, as the signer reported it. */
  rekeyTo: string;
  /** How many times the spend was prepared. */
  attempts: number;
  /**
   * The transaction that was prepared: the one supplied, with its validity
   * rounds rebuilt if the send was allowed to.
   */
  transaction: Transaction;
  /** The sign request that released the signature. */
  requestId: string;
}

/**
 * A group that was signed and submitted. Every value is computed from the
 * signed bytes, after they were checked against the request.
 */
export interface SendResult {
  /**
   * The signing flow the group took: "" for the ordinary /sign flow,
   * "cosigned1" or "rotating1".
   */
  flow: string;
  /**
   * The exact group submitted, hex msgpack, in order. The first
   * originalCount entries are the caller's transactions, in the order given;
   * the rest are resource dummies the signer appended.
   */
  signedGroup: string[];
  originalCount: number;
  /**
   * The IDs of the signed transactions, in signedGroup order. A signer may
   * raise a fee or assign a group, so these can differ from the IDs of the
   * transactions the caller prepared.
   */
  txIds: string[];
  /** The group's ID in base64, or "" for a lone transaction. */
  groupId: string;
  /** The fees the signed transactions pay, in microAlgos. */
  fees: bigint[];
  /**
   * The signer's report of what it changed, checked against the signed
   * bytes. Undefined when it changed nothing.
   */
  mutations?: MutationReport;
  /** How far the group got. */
  outcome: SendOutcome;
  /** The round the group confirmed in; 0n unless outcome is "confirmed". */
  confirmedRound: bigint;
  /**
   * What algosdk's waitForConfirmation returned, unchanged; undefined unless
   * outcome is "confirmed". It describes the first transaction of the signed
   * group, the one the wait followed. Read its inner transactions, logs and
   * created IDs as in any algosdk program.
   */
  confirmation?: algosdk.modelsv2.PendingTransactionResponse;
  /** The component responses of a cosigned send. */
  cosigned?: CosignedSignResult;
  /** The rotation a rotating account's send performed. */
  rotating?: RotatingSendDetails;
}

/** SendOptions as the submission layer reads them, checked before anything is signed. */
export interface CheckedSendOptions {
  noWait: boolean;
  waitRounds: bigint;
  signal?: AbortSignal;
}

/**
 * Check a send's options before anything is signed: a bad value found after
 * signing would cost the signed group.
 */
export function checkSendOptions(options: SendOptions | undefined): CheckedSendOptions {
  if (options !== undefined && options !== null && typeof options !== "object") {
    throw new SignerError("send options must be an object");
  }
  let waitRounds = BigInt(DEFAULT_SEND_WAIT_ROUNDS);
  const requested = options?.waitRounds;
  if (requested !== undefined && requested !== null) {
    const rounds = wholeNumber(requested);
    if (rounds === undefined || rounds < 0n || rounds > UINT64_MAX) {
      throw new SignerError(
        "waitRounds must be a whole number of rounds (a safe integer or a bigint) below 2**64",
      );
    }
    if (rounds > 0n) waitRounds = rounds;
  }
  return { noWait: Boolean(options?.noWait), waitRounds, signal: options?.signal };
}

/** The algod request options that carry the caller's signal, if any. */
export function algodOptions(signal?: AbortSignal): Record<string, unknown> | undefined {
  return signal ? { signal } : undefined;
}

/** A round or count from algod as a bigint, or an error naming it. */
export function algodRound(value: unknown, label: string): bigint {
  const round = wholeNumber(value);
  if (round === undefined || round < 0n || round > UINT64_MAX) {
    throw new SignerError(`${label} ${String(value)} is not a round`);
  }
  return round;
}

/**
 * Decode a signed group for submission or simulation: each entry one
 * canonically encoded signed transaction, hex msgpack. The raw hex is what
 * gets submitted and the decoded value what gets simulated, so the two must
 * be the same transaction exactly.
 */
export function decodeExecutableSignedGroup(signedGroup: string[]): {
  decoded: algosdk.SignedTransaction[];
  raw: Uint8Array[];
} {
  if (!Array.isArray(signedGroup) || signedGroup.length === 0) {
    throw new SignerError("signed group is empty");
  }
  const raw: Uint8Array[] = [];
  const decoded = signedGroup.map((signedHex, index) => {
    if (!signedHex) {
      throw new SignerError(`signed group position ${index + 1} is empty`);
    }
    try {
      const bytes = hexToBytes(signedHex);
      raw.push(bytes);
      return decodeCanonicalSignedTransaction(bytes);
    } catch (error) {
      // Anything but a refusal is a fault in the SDK, left as it is.
      if (!(error instanceof SignerError)) throw error;
      throw new SignerError(`signed group position ${index + 1}: ${errorText(error)}`);
    }
  });
  return { decoded, raw };
}

/**
 * Send one group to the node's simulate endpoint, with execution traces when
 * the node allows them. allowEmptySignatures simulates an unsigned group, and
 * has the node fix signers: an unsigned transaction names no signer, and a
 * rekeyed sender, such as a rotating account after its first spend, needs
 * its authorizer taken from the chain. A signed simulation leaves both off so
 * the node checks every signature.
 */
export async function runSimulation(
  algodClient: any,
  group: algosdk.SignedTransaction[],
  allowEmptySignatures: boolean,
  signal?: AbortSignal,
): Promise<algosdk.modelsv2.SimulateResponse> {
  const makeRequest = (trace: boolean) => new algosdk.modelsv2.SimulateRequest({
    txnGroups: [new algosdk.modelsv2.SimulateRequestTransactionGroup({ txns: group })],
    allowEmptySignatures,
    fixSigners: allowEmptySignatures,
    allowMoreLogging: trace,
    execTraceConfig: trace
      ? new algosdk.modelsv2.SimulateTraceConfig({ enable: true, stateChange: true })
      : undefined,
  });
  try {
    return await algodClient.simulateTransactions(makeRequest(true)).do(undefined, algodOptions(signal));
  } catch {
    try {
      return await algodClient.simulateTransactions(makeRequest(false)).do(undefined, algodOptions(signal));
    } catch (error) {
      throw new SignerError(`simulation API call failed: ${errorText(error)}`);
    }
  }
}

/**
 * Why a simulation of one group of transactionCount transactions did anything
 * but pass, or "" when it passed. It passes only when the node returned
 * exactly one group result, an object with no failure message and no
 * failed-at, holding one transaction result per transaction submitted:
 * anything else checked less than the group, so it is a failure. The reason
 * is the node's own failure message, or which of those it was.
 */
export function simulationFailure(response: any, transactionCount: number): string {
  const groups = response?.txnGroups;
  if (!Array.isArray(groups) || groups.length === 0) {
    return "the node returned no result for the group";
  }
  if (groups.length !== 1) {
    return `the node returned ${groups.length} results for one group`;
  }
  const group = groups[0];
  if (typeof group !== "object" || group === null || Array.isArray(group)) {
    return "the node's result for the group is not an object";
  }
  // A message is a failure whatever its type; only one left out, or empty,
  // is none.
  const message = group.failureMessage;
  if (message !== undefined && message !== null && message !== "") {
    return String(message);
  }
  const failedAt = group.failedAt;
  if (failedAt !== undefined && failedAt !== null && !(Array.isArray(failedAt) && failedAt.length === 0)) {
    return "the node reported a failure without a message";
  }
  const results = Array.isArray(group.txnResults) ? group.txnResults.length : 0;
  if (results !== transactionCount) {
    return `the node returned ${results} transaction results for ${transactionCount} transactions`;
  }
  return "";
}

/**
 * Fill the result's IDs, fees and group ID from its signed bytes and return
 * those bytes decoded from hex. Each entry must be one canonically encoded
 * signed transaction, and a group of several must carry the group ID
 * computed over itself.
 */
export function describeSignedGroup(result: SendResult): Uint8Array[] {
  const { decoded, raw } = decodeExecutableSignedGroup(result.signedGroup);
  if (decoded.length < result.originalCount) {
    throw new SignerError(
      `signed group has ${decoded.length} transaction(s), fewer than the ${result.originalCount} prepared`,
    );
  }
  const txns = decoded.map((signed) => signed.txn);
  let groupID = validateCanonicalGroupID(txns);
  if (txns.length === 1) {
    groupID = groupIDBytes(txns[0]);
  }
  result.fees = txns.map((txn) => txn.fee);
  result.groupId = groupID === undefined ? "" : bytesToBase64(groupID);
  result.txIds = txns.map((txn) => txn.txID());
  return raw;
}

/**
 * The earliest last valid round among txns, or 0n for none. A group cannot
 * execute after it: one of its transactions no longer can.
 */
export function earliestLastValid(txns: Transaction[]): bigint {
  let earliest: bigint | undefined;
  for (const txn of txns) {
    if (earliest === undefined || txn.lastValid < earliest) earliest = txn.lastValid;
  }
  return earliest ?? 0n;
}

/**
 * The one submission path of every send. It posts the signed bytes exactly as
 * given with algosdk's sendRawTransaction and, unless noWait is set, waits
 * with algosdk's waitForConfirmation on the first transaction ID for
 * waitRounds rounds. It reads nothing into either call's answer or error: a
 * failure of either is a SubmissionError whose cause is algosdk's error. It
 * never signs or rebuilds anything.
 *
 * The signal is checked before the submit call and again before the wait,
 * and is passed to the submit call. algosdk's wait takes no signal.
 */
export async function submitAndTrack(
  algodClient: any,
  raw: Uint8Array[],
  result: SendResult,
  options: CheckedSendOptions,
): Promise<void> {
  const signal = options.signal;
  // The bytes were checked when the result was described; their rounds say
  // until when the group can execute.
  const lastValid = earliestLastValid(raw.map((entry) => algosdk.decodeSignedTransaction(entry).txn));
  const failed = (submitted: boolean, cause: unknown) =>
    new SubmissionError({ signedGroup: result.signedGroup, txIds: result.txIds, lastValid, submitted, cause });

  if (signal?.aborted) {
    throw failed(false, signal.reason);
  }
  try {
    await algodClient.sendRawTransaction(raw).do(undefined, algodOptions(signal));
  } catch (error) {
    throw failed(false, error);
  }
  result.outcome = SEND_OUTCOME_SUBMITTED;
  if (options.noWait) {
    return;
  }

  if (signal?.aborted) {
    throw failed(true, signal.reason);
  }
  let confirmation: algosdk.modelsv2.PendingTransactionResponse;
  try {
    // checkSendOptions never leaves waitRounds at 0, which algosdk's wait
    // fails at once.
    confirmation = await algosdk.waitForConfirmation(algodClient, result.txIds[0], Number(options.waitRounds));
  } catch (error) {
    throw failed(true, error);
  }
  result.outcome = SEND_OUTCOME_CONFIRMED;
  result.confirmedRound = confirmation.confirmedRound ?? 0n;
  result.confirmation = confirmation;
}

/** The TX-prefixed hex of the transactions in a signed group, for simulation results. */
export function signedGroupTransactions(decoded: algosdk.SignedTransaction[]): string[] {
  return decoded.map((signed) => encodeTransaction(signed.txn)[0]);
}
