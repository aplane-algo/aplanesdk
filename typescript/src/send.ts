// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * The one submission layer of every send: it submits signed bytes exactly as
 * given and tracks their outcome. It never signs or rebuilds anything.
 */

import algosdk, { type Transaction } from "algosdk";
import type { MutationReport } from "./types.js";
import type { CosignedCosignerResolver, CosignedSignResult, SignerClient } from "./client.js";
import {
  SEND_STAGE_CONFIRM,
  SEND_STAGE_SUBMIT,
  SEND_STAGE_UNSENT,
  SignerError,
  SubmissionRejectedError,
  SubmissionUncertainError,
  callerAborted,
  errorText,
  type SendStage,
} from "./errors.js";
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
 * The node accepted the group; it was not seen in a block by this call.
 * Returned only when SendOptions.noWait is set.
 */
export const SEND_OUTCOME_SUBMITTED = "submitted";
/** The group was seen in a block. */
export const SEND_OUTCOME_CONFIRMED = "confirmed";

/**
 * Options for sendPrepared, sendPayment and submitSignedGroup. With none
 * set, a send signs, submits and waits for confirmation.
 */
export interface SendOptions {
  /**
   * Return as soon as the node accepts the group, with outcome "submitted",
   * instead of waiting for confirmation.
   */
  noWait?: boolean;
  /** How many rounds to wait for confirmation. Unset or zero means 10. */
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
   */
  cosignerClient?: SignerClient;
  cosignerComponentKey?: string;
  cosignerResolver?: CosignedCosignerResolver;
  /**
   * Optional caller cancellation signal. An abort before anything is asked
   * of the signer is a plain stop; once a group is signed, an abort before
   * it is sent ends the send with a SubmissionUncertainError at stage
   * "unsent". The signal is also passed to the algod requests the send
   * makes.
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

/** The HTTP status of an algod error, when the node answered. */
function algodStatus(error: unknown): number | undefined {
  const status = (error as { response?: { status?: unknown } } | null)?.response?.status;
  return typeof status === "number" ? status : undefined;
}

/** The text of an algod error and of the body it carries. */
function algodErrorText(error: unknown): string {
  let text = errorText(error);
  const body = (error as { response?: { body?: unknown } } | null)?.response?.body;
  if (body instanceof Uint8Array && body.length > 0) {
    try {
      text += ` ${new TextDecoder().decode(body)}`;
    } catch {
      // The message alone is all there is.
    }
  }
  return text;
}

/**
 * Whether a submission was refused only because the node already has a
 * transaction with the same ID, in its pool or in a block. algod answers that
 * with a 400 like any refusal and no code, so the text is all there is to go
 * on. One case is not recognised: a committed transaction that carries a
 * lease is refused for its lease first, and that answer is the same as a real
 * lease conflict's.
 */
export function alreadyKnownToNode(error: unknown): boolean {
  return algodStatus(error) === 400 && algodErrorText(error).toLowerCase().includes("already in ledger");
}

/**
 * The one submission path of every send. It submits the signed bytes exactly
 * as given and, unless told not to, waits for the first transaction to
 * confirm. It never signs or rebuilds anything.
 */
export async function submitAndTrack(
  algodClient: any,
  raw: Uint8Array[],
  result: SendResult,
  options: CheckedSendOptions,
): Promise<void> {
  const waitRounds = options.waitRounds;
  const blob = new Uint8Array(raw.reduce((total, entry) => total + entry.length, 0));
  let offset = 0;
  for (const entry of raw) {
    blob.set(entry, offset);
    offset += entry.length;
  }
  const txId = result.txIds[0];
  const signal = options.signal;
  const uncertain = (stage: SendStage, cause: unknown) =>
    new SubmissionUncertainError(stage, result.signedGroup, result.txIds, cause);

  if (signal?.aborted) {
    throw uncertain(SEND_STAGE_UNSENT, callerAborted());
  }
  let answered = false;
  let sentId: unknown;
  try {
    const response = await algodClient.sendRawTransaction(blob).do(undefined, algodOptions(signal));
    answered = true;
    sentId = response?.txid;
  } catch (error) {
    if (alreadyKnownToNode(error)) {
      // The node already has a transaction with this ID, pending or
      // committed: an earlier submission of this group reached it. That is
      // not a refusal, and the lookup below finds the outcome.
    } else if (algodStatus(error) === 400) {
      throw new SubmissionRejectedError(result.signedGroup, result.txIds, error);
    } else {
      throw uncertain(SEND_STAGE_SUBMIT, error);
    }
  }
  if (answered && sentId !== txId) {
    throw uncertain(
      SEND_STAGE_SUBMIT,
      new SignerError(`node reported transaction ID ${String(sentId)} for a group whose first transaction is ${txId}`),
    );
  }
  result.outcome = SEND_OUTCOME_SUBMITTED;
  if (options.noWait) {
    return;
  }

  let last: bigint;
  try {
    const status = await algodClient.status().do(undefined, algodOptions(signal));
    last = algodRound(status?.lastRound, "last round");
  } catch (error) {
    throw uncertain(SEND_STAGE_CONFIRM, new SignerError(`read current round: ${errorText(error)}`));
  }
  // The group is looked up now and after each of the next waitRounds rounds.
  const deadline = waitRounds < UINT64_MAX - last ? last + waitRounds : UINT64_MAX;
  for (;;) {
    // A lookup error is not an answer: behind a load balancer another node
    // may not have the transaction yet.
    let info: any;
    try {
      info = await algodClient.pendingTransactionInformation(txId).do(undefined, algodOptions(signal));
    } catch {
      info = undefined;
    }
    if (info) {
      if (typeof info.poolError === "string" && info.poolError !== "") {
        throw new SubmissionRejectedError(
          result.signedGroup,
          result.txIds,
          new SignerError(`dropped from the transaction pool: ${info.poolError}`),
        );
      }
      const confirmed = wholeNumber(info.confirmedRound);
      if (confirmed !== undefined && confirmed > 0n) {
        result.outcome = SEND_OUTCOME_CONFIRMED;
        result.confirmedRound = confirmed;
        return;
      }
    }
    if (last >= deadline) {
      throw uncertain(SEND_STAGE_CONFIRM, new SignerError(`not confirmed after ${waitRounds} rounds`));
    }
    // statusAfterBlock(n) returns once round n+1 exists.
    let next: bigint;
    try {
      const status = await algodClient.statusAfterBlock(last).do(undefined, algodOptions(signal));
      next = algodRound(status?.lastRound, "last round");
    } catch (error) {
      throw uncertain(
        SEND_STAGE_CONFIRM,
        new SignerError(`wait for round ${last + 1n}: ${errorText(error)}`),
      );
    }
    last = next > last ? next : last + 1n;
  }
}

/** The TX-prefixed hex of the transactions in a signed group, for simulation results. */
export function signedGroupTransactions(decoded: algosdk.SignedTransaction[]): string[] {
  return decoded.map((signed) => encodeTransaction(signed.txn)[0]);
}
