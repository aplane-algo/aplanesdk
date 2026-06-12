// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import * as fs from "fs";
import * as path from "path";
import * as net from "net";
import { randomBytes } from "crypto";
import algosdk, { type Transaction } from "algosdk";
import type { Client as SSHClient, ClientChannel } from "ssh2";
import type {
  KeyInfo,
  AccountInfoLookup,
  AccountInfoResult,
  ConnectSshOptions,
  FromEnvOptions,
  PaymentPrepParams,
  AsaTransferPrepParams,
  AsaOptInPrepParams,
  AsaOptOutPrepParams,
  AccountClosePrepParams,
  RekeyPrepParams,
  KeyregPrepParams,
  AppCallPrepParams,
  AbiAppCallPrepParams,
  AppDeployPrepParams,
  SweepPrepParams,
  SignOptions,
  LsigArgs,
  LsigArgsMap,
  SignRequest,
  GroupSignRequest,
  GroupSignResponse,
  GroupSimulateResponse,
  StatusResponse,
  ResolvedAuthAddress,
  PreparedTransaction,
  PreparedGroup,
  PreparedCheck,
  KeysResponse,
  KeyTypesResponse,
  KeyTypeInfo,
  CreationParam,
  GenerateResult,
  PlanGroupResponse,
  RuntimeArg,
  SigningArg,
  MutationReport,
  CancelSignResponse,
  ComponentSignRequest,
  ComponentSignResponse,
  GuardedAssemblyRequest,
  GuardedAssemblyResponse,
  GuardedPassthroughItem,
  SentryReferenceCandidate,
  AdminSyncSentryReferencesRequest,
  AdminSyncSentryReferencesResponse,
  ErrorResponse,
} from "./types.js";
import { ErrorCodes, SIGNING_FLOW_SENTRY1 } from "./types.js";
import {
  SignerError,
  AuthenticationError,
  SigningRejectedError,
  SignerUnavailableError,
  KeyNotFoundError,
  KeyDeletionError,
} from "./errors.js";
import {
  encodeTransaction,
  encodeLsigArgs,
  concatenateSignedTxns,
  bytesToHex,
  hexToBytes,
} from "./encoding.js";
import { preparedGroupToSignRequests } from "./prepared.js";
import {
  loadConfig,
  loadTokenFromDir,
  resolveDataDir,
  expandPath,
  DEFAULT_SIGNER_PORT,
  DEFAULT_SSH_PORT,
} from "./config.js";

const HEALTH_TIMEOUT = 3000;
const STATUS_TIMEOUT = 5000;
const INVENTORY_TIMEOUT = 30000;
const MUTATION_TIMEOUT = 60000;
const GROUP_PLAN_TIMEOUT = 60000;
const GROUP_SIMULATE_TIMEOUT = 60000;
const COMPONENT_SIGN_TIMEOUT = 120000;
const GUARDED_ASSEMBLY_TIMEOUT = 120000;
const SIGN_CANCEL_TIMEOUT = 5000;
const SIGN_APPROVAL_SLACK = 30000;
const DEFAULT_SIGN_REQUEST_TIMEOUT = 360000;
const MAX_DISCOVERED_APPROVAL_WAIT = 1800000;
const APPROVAL_WAIT_REFRESH = 300000;
const MAX_SIGN_REQUEST_ID_LENGTH = 128;
const MAX_COMPONENT_GROUP_SIZE = 16;
const COMPONENT_SIGN_ROLE_USER = "user";
const COMPONENT_SIGN_ROLE_SENTRY = "sentry";
const APP_CALL_MAX_APP_ARGS = 16;
const APP_CALL_METHOD_ARGS_TUPLE_THRESHOLD = APP_CALL_MAX_APP_ARGS - 2;
const GUARDED_LSIG_BUDGET_BYTES = 1000;
const GUARDED_MAX_GROUP_SIZE = 16;
const GUARDED_DEFAULT_MIN_FEE = 1000;
const GUARDED_DUMMY_PROGRAM = new Uint8Array([0x03, 0x31, 0x20, 0x32, 0x03, 0x12]);
function newSignRequestId(): string {
  return `sdk-${randomBytes(16).toString("hex")}`;
}

function validateSignRequestId(requestId: string, required = false): void {
  if (!requestId) {
    if (required) {
      throw new SignerError("request_id is required");
    }
    return;
  }
  if (requestId.length > MAX_SIGN_REQUEST_ID_LENGTH) {
    throw new SignerError("request_id is too long");
  }
  for (const ch of requestId) {
    if (/^[A-Za-z0-9_.:-]$/.test(ch)) {
      continue;
    }
    throw new SignerError(`request_id contains invalid character ${JSON.stringify(ch)}`);
  }
}

type ComponentSignatureByIndex = Map<number, { signature: string; requestId: string }>;

function componentSignaturesByIndex(response: ComponentSignResponse): ComponentSignatureByIndex {
  const signatures: ComponentSignatureByIndex = new Map();
  for (const signature of response.signatures) {
    signatures.set(signature.target_index, {
      signature: signature.signature,
      requestId: response.request_id,
    });
  }
  return signatures;
}

async function resolveSentryForTarget(
  target: GuardedSignTarget,
  options: GuardedSignOptions,
): Promise<GuardedSentryResolution> {
  if (options.sentryResolver) {
    const resolved = await options.sentryResolver(target);
    if (!resolved.client) {
      throw new SignerError("sentry resolver returned no client");
    }
    return resolved;
  }
  if (!options.sentryClient) {
    throw new SignerError("sentryClient or sentryResolver is required");
  }
  return {
    client: options.sentryClient,
    componentKey: target.sentryComponentKey || options.sentryComponentKey || "",
  };
}

async function requestPrimaryGuardedPassthrough(
  userClient: SignerClient,
  groupBytesHex: string[],
  guardedIndices: Set<number>,
  primaryTargets: GuardedPrimarySignTarget[],
  signal?: AbortSignal,
): Promise<{ response: GroupSignResponse; passthrough: GuardedPassthroughItem[] }> {
  const primaryByIndex = new Map<number, GuardedPrimarySignTarget>();
  for (const target of primaryTargets) {
    if (!Number.isInteger(target.targetIndex) || target.targetIndex < 0 || target.targetIndex >= groupBytesHex.length) {
      throw new SignerError(`primary target ${target.targetIndex} out of range`);
    }
    if (guardedIndices.has(target.targetIndex)) {
      throw new SignerError(`primary target ${target.targetIndex} overlaps guarded target`);
    }
    if (primaryByIndex.has(target.targetIndex)) {
      throw new SignerError(`duplicate primary target index ${target.targetIndex}`);
    }
    if (!target.authAddress) {
      throw new SignerError(`primary target ${target.targetIndex} missing authAddress`);
    }
    primaryByIndex.set(target.targetIndex, target);
  }

  const requests: SignRequest[] = groupBytesHex.map((txnHex, index) => {
    const target = primaryByIndex.get(index);
    if (!target) {
      return { txn_bytes_hex: txnHex };
    }
    const request: SignRequest = {
      txn_bytes_hex: txnHex,
      auth_address: target.authAddress,
    };
    if (target.txnSender) {
      request.txn_sender = target.txnSender;
    }
    if (target.lsigArgs) {
      request.lsig_args = target.lsigArgs;
    }
    if (target.lsigSize) {
      request.lsig_size = target.lsigSize;
    }
    if (target.appCallInfo) {
      request.app_call_info = target.appCallInfo;
    }
    return request;
  });

  const response = await userClient.signRequests(requests, { signal });
  const passthrough: GuardedPassthroughItem[] = [];
  for (const index of Array.from(primaryByIndex.keys()).sort((a, b) => a - b)) {
    if (!response.signed || !response.signed[index]) {
      throw new SignerError(`primary signer returned no signed transaction for target ${index}`);
    }
    passthrough.push({
      target_index: index,
      signed_txn_hex: response.signed[index],
    });
  }
  return { response, passthrough };
}

function guardedDummiesNeeded(totalLsigBytes: number, txnCount: number): number {
  const currentBudget = txnCount * GUARDED_LSIG_BUDGET_BYTES;
  if (totalLsigBytes <= currentBudget) {
    return 0;
  }
  const extraBudget = totalLsigBytes - currentBudget;
  return Math.ceil(extraBudget / GUARDED_LSIG_BUDGET_BYTES);
}

function applyGuardedDummyFees(
  txns: Transaction[],
  lsigIndices: number[],
  dummyCount: number,
  minFee: number,
): void {
  const totalFees = BigInt(dummyCount) * BigInt(minFee);
  if (lsigIndices.length === 0) {
    if (txns.length === 0) {
      throw new SignerError("no transactions to apply dummy fees to");
    }
    (txns[0] as any).fee = BigInt((txns[0] as any).fee || 0) + totalFees;
    return;
  }

  const feePerLsig = totalFees / BigInt(lsigIndices.length);
  const remainder = totalFees % BigInt(lsigIndices.length);
  for (let offset = 0; offset < lsigIndices.length; offset++) {
    const index = lsigIndices[offset];
    const extra = feePerLsig + (offset === 0 ? remainder : 0n);
    (txns[index] as any).fee = BigInt((txns[index] as any).fee || 0) + extra;
  }
}

function cloneTransaction(txn: Transaction): Transaction {
  return algosdk.decodeUnsignedTransaction(txn.toByte());
}

function createGuardedDummies(firstTxn: Transaction, count: number): Transaction[] {
  if (count === 0) {
    return [];
  }
  const dummyAccount = new algosdk.LogicSigAccount(GUARDED_DUMMY_PROGRAM);
  const dummyAddress = dummyAccount.address().toString();
  const first = firstTxn as any;
  const suggestedParams: any = {
    fee: Number(first.fee || GUARDED_DEFAULT_MIN_FEE),
    firstValid: first.firstValid ?? first.firstValidRound ?? 0,
    lastValid: first.lastValid ?? first.lastValidRound ?? 0,
    genesisHash: first.genesisHash,
    genesisID: first.genesisID,
    flatFee: true,
  };

  const dummies: Transaction[] = [];
  for (let index = 0; index < count; index++) {
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: dummyAddress,
      receiver: dummyAddress,
      amount: 0,
      note: new Uint8Array([index]),
      suggestedParams,
    });
    (txn as any).fee = 0n;
    dummies.push(txn);
  }
  return dummies;
}

function signGuardedDummies(dummies: Transaction[], startIndex: number): GuardedPassthroughItem[] {
  if (dummies.length === 0) {
    return [];
  }
  const dummyAccount = new algosdk.LogicSigAccount(GUARDED_DUMMY_PROGRAM);
  return dummies.map((txn, offset) => {
    const signed = algosdk.signLogicSigTransactionObject(txn, dummyAccount);
    return {
      target_index: startIndex + offset,
      signed_txn_hex: bytesToHex(signed.blob),
    };
  });
}

async function buildPreparedGuardedSignOptions(
  options: PreparedGuardedGroupOptions,
): Promise<GuardedSignOptions> {
  if (!options.userClient) {
    throw new SignerError("userClient is required");
  }
  const prepared = options.preparedGroup.transactions || [];
  if (prepared.length === 0) {
    throw new SignerError("prepared group is empty");
  }

  const txns: Transaction[] = [];
  const guardedTargets: GuardedSignTarget[] = [];
  const primaryTargets: GuardedPrimarySignTarget[] = [];
  const lsigIndices: number[] = [];
  let totalLsigBytes = 0;

  for (let index = 0; index < prepared.length; index++) {
    const item = prepared[index];
    if (item.signedTransactionBase64) {
      throw new SignerError(
        `prepared transaction ${index}: passthrough entries are not supported in prepared guarded groups`
      );
    }
    if (!item.transaction) {
      throw new SignerError(`prepared transaction ${index}: transaction is required`);
    }
    txns.push(cloneTransaction(item.transaction));

    let key = item.signerKey;
    if (!key && item.authAddress) {
      key = await options.userClient.getKeyInfo(item.authAddress);
    }
    if (!key) {
      throw new SignerError(`prepared transaction ${index}: signer key metadata is required`);
    }

    let lsigSize = item.lsigSize || 0;
    if (key.lsigSize && key.lsigSize > 0) {
      lsigSize = key.lsigSize;
    }
    if (lsigSize > 0) {
      totalLsigBytes += lsigSize;
      lsigIndices.push(index);
    }

    if (key.signingFlow) {
      if (key.signingFlow !== SIGNING_FLOW_SENTRY1) {
        throw new SignerError(
          `prepared transaction ${index}: signer key requires signing flow "${key.signingFlow}", which this SDK does not support; upgrade the SDK`,
        );
      }
      if (!item.authAddress) {
        throw new SignerError(`prepared transaction ${index}: guarded auth address is required`);
      }
      guardedTargets.push({
        targetIndex: index,
        guardedAccount: item.authAddress,
        sentryPublicKeyHex: key.parameters?.sentry_public_key || "",
        sentryComponentKeyType: key.sentryComponentKeyType || "",
      });
      continue;
    }

    if (!item.authAddress) {
      throw new SignerError(`prepared transaction ${index}: primary auth address is required`);
    }
    primaryTargets.push({
      targetIndex: index,
      authAddress: item.authAddress,
      txnSender: item.txnSender,
      lsigArgs: item.lsigArgs ? encodeLsigArgs(item.lsigArgs) : undefined,
      lsigSize,
      appCallInfo: item.appCallInfo,
    });
  }

  if (guardedTargets.length === 0) {
    throw new SignerError("prepared group has no guarded targets");
  }

  const minFee = options.minFee || GUARDED_DEFAULT_MIN_FEE;
  const dummyCount = guardedDummiesNeeded(totalLsigBytes, txns.length);
  if (txns.length + dummyCount > GUARDED_MAX_GROUP_SIZE) {
    throw new SignerError(
      `group would be ${txns.length + dummyCount} transactions (max ${GUARDED_MAX_GROUP_SIZE}) ` +
      `- cannot add ${dummyCount} dummies for LSig budget`
    );
  }
  if (dummyCount > 0) {
    applyGuardedDummyFees(txns, lsigIndices, dummyCount, minFee);
  }

  const dummies = createGuardedDummies(txns[0], dummyCount);
  const allTxns = [...txns, ...dummies];
  if (allTxns.length > 1) {
    for (const txn of allTxns) {
      (txn as any).group = undefined;
    }
    algosdk.assignGroupID(allTxns);
  }

  return {
    userClient: options.userClient,
    sentryClient: options.sentryClient,
    sentryResolver: options.sentryResolver,
    sentryComponentKey: options.sentryComponentKey,
    groupBytesHex: allTxns.map((txn) => encodeTransaction(txn)[0]),
    guardedTargets,
    primaryTargets,
    passthrough: signGuardedDummies(allTxns.slice(txns.length), txns.length),
    assemblyRequestId: options.assemblyRequestId,
    signal: options.signal,
  };
}

/**
 * Sign and assemble a guarded group using explicit signer clients.
 *
 * The helper expects canonical TX-prefixed group bytes. Planning and endpoint
 * discovery stay caller-owned.
 */
export async function signPreparedGuardedGroup(
  options: PreparedGuardedGroupOptions,
): Promise<GuardedSignResult> {
  return signGuardedGroup(await buildPreparedGuardedSignOptions(options));
}

export async function signGuardedGroup(options: GuardedSignOptions): Promise<GuardedSignResult> {
  if (!options.userClient) {
    throw new SignerError("userClient is required");
  }
  if (!options.guardedTargets || options.guardedTargets.length === 0) {
    throw new SignerError("at least one guarded target is required");
  }
  validateComponentGroupBytes(options.groupBytesHex);

  const targets = [...options.guardedTargets].sort((a, b) => a.targetIndex - b.targetIndex);
  const guardedIndices = new Set<number>();
  const userGroups = new Map<string, number[]>();
  for (const target of targets) {
    if (!Number.isInteger(target.targetIndex) || target.targetIndex < 0 || target.targetIndex >= options.groupBytesHex.length) {
      throw new SignerError(`guarded target ${target.targetIndex} out of range`);
    }
    if (guardedIndices.has(target.targetIndex)) {
      throw new SignerError(`duplicate guarded target index ${target.targetIndex}`);
    }
    if (!target.guardedAccount) {
      throw new SignerError(`guarded target ${target.targetIndex} missing guardedAccount`);
    }
    guardedIndices.add(target.targetIndex);
    const indices = userGroups.get(target.guardedAccount) || [];
    indices.push(target.targetIndex);
    userGroups.set(target.guardedAccount, indices);
  }

  const userComponentResponses: ComponentSignResponse[] = [];
  const userSignatures: ComponentSignatureByIndex = new Map();
  for (const guardedAccount of Array.from(userGroups.keys()).sort()) {
    const response = await options.userClient.requestComponentSign({
      role: COMPONENT_SIGN_ROLE_USER,
      component_key: guardedAccount,
      group_bytes_hex: options.groupBytesHex,
      target_indices: (userGroups.get(guardedAccount) || []).sort((a, b) => a - b),
    }, { signal: options.signal });
    userComponentResponses.push(response);
    for (const [index, signature] of componentSignaturesByIndex(response)) {
      userSignatures.set(index, signature);
    }
  }

  const sentryGroups: Array<{
    client: SignerClient;
    componentKey: string;
    indices: number[];
  }> = [];
  for (const target of targets) {
    const resolved = await resolveSentryForTarget(target, options);
    let group = sentryGroups.find(
      (item) => item.client === resolved.client && item.componentKey === (resolved.componentKey || "")
    );
    if (!group) {
      group = { client: resolved.client, componentKey: resolved.componentKey || "", indices: [] };
      sentryGroups.push(group);
    }
    group.indices.push(target.targetIndex);
  }

  const sentryComponentResponses: ComponentSignResponse[] = [];
  const sentrySignatures: ComponentSignatureByIndex = new Map();
  for (const group of sentryGroups) {
    const response = await group.client.requestComponentSign({
      role: COMPONENT_SIGN_ROLE_SENTRY,
      component_key: group.componentKey,
      group_bytes_hex: options.groupBytesHex,
      target_indices: group.indices.sort((a, b) => a - b),
    }, { signal: options.signal });
    sentryComponentResponses.push(response);
    for (const [index, signature] of componentSignaturesByIndex(response)) {
      sentrySignatures.set(index, signature);
    }
  }

  let primarySignResponse: GroupSignResponse | undefined;
  const passthrough = [...(options.passthrough || [])];
  if (options.primaryTargets && options.primaryTargets.length > 0) {
    const primary = await requestPrimaryGuardedPassthrough(
      options.userClient,
      options.groupBytesHex,
      guardedIndices,
      options.primaryTargets,
      options.signal,
    );
    primarySignResponse = primary.response;
    passthrough.push(...primary.passthrough);
  }

  const assemblyTargets = targets.map((target) => {
    const userSignature = userSignatures.get(target.targetIndex);
    const sentrySignature = sentrySignatures.get(target.targetIndex);
    if (!userSignature) {
      throw new SignerError(`missing user component signature for target ${target.targetIndex}`);
    }
    if (!sentrySignature) {
      throw new SignerError(`missing sentry component signature for target ${target.targetIndex}`);
    }
    return {
      target_index: target.targetIndex,
      guarded_account: target.guardedAccount,
      user_signature: userSignature.signature,
      user_source_request_id: userSignature.requestId,
      sentry_signature: sentrySignature.signature,
      sentry_source_request_id: sentrySignature.requestId,
      runtime_args: target.runtimeArgs,
    };
  });

  const assemblyResponse = await options.userClient.requestGuardedAssemble({
    request_id: options.assemblyRequestId,
    group_bytes_hex: options.groupBytesHex,
    targets: assemblyTargets,
    passthrough,
  }, { signal: options.signal });

  return {
    signedGroup: assemblyResponse.signed_group,
    userComponentResponses,
    sentryComponentResponses,
    primarySignResponse,
    assemblyResponse,
  };
}

function validateComponentGroupBytes(items: string[]): void {
  if (!items || items.length === 0) {
    throw new SignerError("group_bytes_hex is empty");
  }
  if (items.length > MAX_COMPONENT_GROUP_SIZE) {
    throw new SignerError(
      `group_bytes_hex length ${items.length} exceeds max ${MAX_COMPONENT_GROUP_SIZE}`
    );
  }
  items.forEach((item, index) => {
    if (!item) {
      throw new SignerError(`group_bytes_hex ${index} is empty`);
    }
  });
}

function validateComponentTargetIndices(indices: number[], groupLen: number): void {
  if (!indices || indices.length === 0) {
    throw new SignerError("target_indices is empty");
  }
  const seen = new Set<number>();
  for (const index of indices) {
    if (!Number.isInteger(index) || index < 0 || index >= groupLen) {
      throw new SignerError(`target_indices ${index} out of range`);
    }
    if (seen.has(index)) {
      throw new SignerError(`target_indices contains duplicate ${index}`);
    }
    seen.add(index);
  }
}

function validateComponentSignRequest(request: ComponentSignRequest): void {
  validateSignRequestId(request.request_id || "");
  if (request.role === COMPONENT_SIGN_ROLE_USER) {
    if (!request.component_key) {
      throw new SignerError("component_key is required for user role");
    }
  } else if (request.role !== COMPONENT_SIGN_ROLE_SENTRY) {
    throw new SignerError(
      `role must be ${JSON.stringify(COMPONENT_SIGN_ROLE_USER)} or ${JSON.stringify(COMPONENT_SIGN_ROLE_SENTRY)}`
    );
  }
  validateComponentGroupBytes(request.group_bytes_hex);
  validateComponentTargetIndices(request.target_indices, request.group_bytes_hex.length);
}

function validateComponentSignResponse(response: ComponentSignResponse): void {
  if (!response.request_id) {
    throw new SignerError("request_id is required");
  }
  validateSignRequestId(response.request_id);
  if (!response.signatures || response.signatures.length === 0) {
    throw new SignerError("signatures array is empty");
  }
  const seen = new Set<number>();
  response.signatures.forEach((signature, index) => {
    const item = index + 1;
    if (!Number.isInteger(signature.target_index) || signature.target_index < 0) {
      throw new SignerError(`signature ${item}: target_index must be non-negative`);
    }
    if (seen.has(signature.target_index)) {
      throw new SignerError(`signature ${item}: duplicate target_index ${signature.target_index}`);
    }
    seen.add(signature.target_index);
    if (!signature.signature) {
      throw new SignerError(`signature ${item}: signature is required`);
    }
    if (!signature.signature_scheme) {
      throw new SignerError(`signature ${item}: signature_scheme is required`);
    }
  });
}

function validateAssemblyIndex(index: number, groupLen: number, covered: Set<number>): void {
  if (!Number.isInteger(index) || index < 0 || index >= groupLen) {
    throw new SignerError(`target_index ${index} out of range`);
  }
  if (covered.has(index)) {
    throw new SignerError(`duplicate target_index ${index}`);
  }
  covered.add(index);
}

function validateGuardedAssemblyRequest(request: GuardedAssemblyRequest): void {
  validateSignRequestId(request.request_id || "");
  validateComponentGroupBytes(request.group_bytes_hex);
  const targets = request.targets || [];
  const passthrough = request.passthrough || [];
  if (targets.length === 0 && passthrough.length === 0) {
    throw new SignerError("targets or passthrough is required");
  }

  const covered = new Set<number>();
  targets.forEach((target, index) => {
    const item = index + 1;
    validateAssemblyIndex(target.target_index, request.group_bytes_hex.length, covered);
    if (!target.guarded_account) {
      throw new SignerError(`target ${item}: guarded_account is required`);
    }
    if (!target.user_signature) {
      throw new SignerError(`target ${item}: user_signature is required`);
    }
    if (!target.sentry_signature) {
      throw new SignerError(`target ${item}: sentry_signature is required`);
    }
    validateSignRequestId(target.user_source_request_id || "");
    validateSignRequestId(target.sentry_source_request_id || "");
  });

  passthrough.forEach((item, index) => {
    validateAssemblyIndex(item.target_index, request.group_bytes_hex.length, covered);
    if (!item.signed_txn_hex) {
      throw new SignerError(`passthrough ${index + 1}: signed_txn_hex is required`);
    }
  });

  for (let index = 0; index < request.group_bytes_hex.length; index++) {
    if (!covered.has(index)) {
      throw new SignerError(`group position ${index} is not covered by targets or passthrough`);
    }
  }
}

function validateGuardedAssemblyResponse(response: GuardedAssemblyResponse): void {
  if (!response.request_id) {
    throw new SignerError("request_id is required");
  }
  validateSignRequestId(response.request_id);
  if (!response.signed_group || response.signed_group.length === 0) {
    throw new SignerError("signed_group is empty");
  }
  response.signed_group.forEach((signed, index) => {
    if (!signed) {
      throw new SignerError(`signed_group ${index} is empty`);
    }
  });
}

/**
 * Find an available local port.
 */
async function findFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr && typeof addr === "object") {
        const port = addr.port;
        server.close(() => resolve(port));
      } else {
        reject(new Error("Could not get server address"));
      }
    });
  });
}

/**
 * Parse the key type string from an SSH public key in wire format.
 * Wire format: [4-byte big-endian length][key-type-string][...rest]
 */
function parseHostKeyType(key: Buffer): string {
  if (key.length < 4) return "unknown";
  const typeLen = key.readUInt32BE(0);
  if (key.length < 4 + typeLen) return "unknown";
  return key.subarray(4, 4 + typeLen).toString("ascii");
}

/**
 * Format a host entry for known_hosts (OpenSSH format: [host]:port for non-22).
 */
function formatHostEntry(host: string, port: number): string {
  return port === 22 ? host : `[${host}]:${port}`;
}

/**
 * Load a stored host key from a known_hosts file.
 * Returns the raw key as a Buffer, or null if not found.
 */
function loadKnownHostKey(knownHostsPath: string, host: string, port: number): Buffer | null {
  if (!fs.existsSync(knownHostsPath)) return null;
  const hostEntry = formatHostEntry(host, port);
  const content = fs.readFileSync(knownHostsPath, "utf-8");
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const parts = trimmed.split(" ");
    if (parts.length >= 3 && parts[0] === hostEntry) {
      return Buffer.from(parts[2], "base64");
    }
  }
  return null;
}

/**
 * Save a host key to a known_hosts file in OpenSSH format (TOFU).
 */
function saveHostKey(knownHostsPath: string, host: string, port: number, key: Buffer): void {
  const dir = path.dirname(knownHostsPath);
  if (dir && dir !== ".") {
    fs.mkdirSync(dir, { recursive: true });
  }
  const hostEntry = formatHostEntry(host, port);
  const keyType = parseHostKeyType(key);
  const keyBase64 = key.toString("base64");
  fs.appendFileSync(knownHostsPath, `${hostEntry} ${keyType} ${keyBase64}\n`, { mode: 0o600 });
}

/**
 * SSH tunnel wrapper that forwards a local port to a remote port.
 */
class SSHTunnel {
  private sshClient: SSHClient | null = null;
  private server: net.Server | null = null;
  localPort: number = 0;

  async connect(options: {
    host: string;
    sshPort: number;
    username: string;
    privateKeyPath: string;
    remoteHost: string;
    remotePort: number;
    knownHostsPath: string;
    trustOnFirstUse: boolean;
  }): Promise<void> {
    if (!options.knownHostsPath) {
      throw new SignerError(
        "known_hosts path is required for SSH host key verification"
      );
    }

    // Dynamically import ssh2
    const { Client } = await import("ssh2");

    const privateKey = fs.readFileSync(options.privateKeyPath, "utf-8");
    this.localPort = await findFreePort();

    // Track host key error for meaningful rejection messages
    let hostKeyError = "";

    return new Promise((resolve, reject) => {
      this.sshClient = new Client();

      this.sshClient.on("ready", () => {
        // Create local server that forwards to remote via SSH
        this.server = net.createServer((localSocket) => {
          this.sshClient!.forwardOut(
            "127.0.0.1",
            this.localPort,
            options.remoteHost,
            options.remotePort,
            (err: Error | undefined, channel: ClientChannel) => {
              if (err) {
                localSocket.destroy();
                return;
              }
              localSocket.pipe(channel).pipe(localSocket);
            }
          );
        });

        this.server.listen(this.localPort, "127.0.0.1", () => {
          resolve();
        });

        this.server.on("error", (err) => {
          reject(new SignerUnavailableError(`SSH tunnel server error: ${err.message}`));
        });
      });

      this.sshClient.on("error", (err: Error) => {
        const msg = hostKeyError || `SSH connection failed: ${err.message}`;
        reject(new SignerUnavailableError(msg));
      });

      this.sshClient.connect({
        host: options.host,
        port: options.sshPort,
        username: options.username,
        privateKey: privateKey,
        hostVerifier: (key: Buffer): boolean => {
          const storedKey = loadKnownHostKey(
            options.knownHostsPath, options.host, options.sshPort
          );

          if (storedKey === null) {
            if (!options.trustOnFirstUse) {
              hostKeyError =
                `Unknown SSH host key for ${formatHostEntry(options.host, options.sshPort)}; ` +
        `to trust this host, set endpoint.ssh.trust_on_first_use: true in config.yaml, ` +
                `or connect via apshell first to save the host key to ${options.knownHostsPath}`;
              return false;
            }
            // TOFU enabled — trust and save key
            saveHostKey(options.knownHostsPath, options.host, options.sshPort, key);
            return true;
          }

          if (storedKey.equals(key)) {
            return true; // Known host, key matches
          }

          // Key mismatch — possible MITM attack
          hostKeyError =
            `SSH host key mismatch for ${formatHostEntry(options.host, options.sshPort)} ` +
            `(possible MITM attack); remove the old key from ${options.knownHostsPath} to connect`;
          return false;
        },
      });
    });
  }

  async close(): Promise<void> {
    const server = this.server;
    const sshClient = this.sshClient;
    this.server = null;
    this.sshClient = null;

    const closeServer = server
      ? new Promise<void>((resolve) => {
          server.close(() => resolve());
        })
      : Promise.resolve();
    const closeSSH = sshClient
      ? new Promise<void>((resolve) => {
          sshClient.once("close", () => resolve());
          sshClient.end();
        })
      : Promise.resolve();

    await Promise.all([closeServer, closeSSH]);
  }
}

export interface GuardedSignTarget {
  targetIndex: number;
  guardedAccount: string;
  sentryPublicKeyHex?: string;
  sentryComponentKeyType?: string;
  sentryComponentKey?: string;
  runtimeArgs?: string[];
}

export interface GuardedPrimarySignTarget {
  targetIndex: number;
  authAddress: string;
  txnSender?: string;
  lsigArgs?: Record<string, string>;
  lsigSize?: number;
  appCallInfo?: { mode?: string; method?: string };
}

export interface GuardedSentryResolution {
  client: SignerClient;
  componentKey?: string;
}

export type GuardedSentryResolver = (
  target: GuardedSignTarget
) => GuardedSentryResolution | Promise<GuardedSentryResolution>;

export interface GuardedSignOptions {
  userClient: SignerClient;
  sentryClient?: SignerClient;
  sentryResolver?: GuardedSentryResolver;
  sentryComponentKey?: string;
  groupBytesHex: string[];
  guardedTargets: GuardedSignTarget[];
  primaryTargets?: GuardedPrimarySignTarget[];
  passthrough?: GuardedPassthroughItem[];
  assemblyRequestId?: string;
  signal?: AbortSignal;
}

export interface PreparedGuardedGroupOptions {
  userClient: SignerClient;
  preparedGroup: PreparedGroup;
  sentryClient?: SignerClient;
  sentryResolver?: GuardedSentryResolver;
  sentryComponentKey?: string;
  assemblyRequestId?: string;
  minFee?: number;
  signal?: AbortSignal;
}

export interface GuardedSignResult {
  signedGroup: string[];
  userComponentResponses: ComponentSignResponse[];
  sentryComponentResponses: ComponentSignResponse[];
  primarySignResponse?: GroupSignResponse;
  assemblyResponse: GuardedAssemblyResponse;
}

function extractAuthAddress(accountInfo: AccountInfoResult): string {
  if (!accountInfo) {
    return "";
  }
  if (typeof accountInfo === "string") {
    return accountInfo;
  }
  return (
    accountInfo["auth-addr"] ||
    accountInfo.auth_addr ||
    accountInfo.authAddr ||
    accountInfo.authAddress ||
    ""
  );
}

function findSpendableKey(keys: KeyInfo[], address: string): KeyInfo | undefined {
  return keys.find((key) => (
    key.address === address && key.isSpendingAccount !== false
  ));
}

function accountAmount(accountInfo: AccountInfoResult | Record<string, any>): number {
  if (!accountInfo || typeof accountInfo === "string") {
    return 0;
  }
  const raw = accountInfo as Record<string, any>;
  return Number(raw.amount || 0);
}

function accountMinBalance(accountInfo: AccountInfoResult | Record<string, any>): number {
  if (!accountInfo || typeof accountInfo === "string") {
    return 0;
  }
  const raw = accountInfo as Record<string, any>;
  return Number(raw["min-balance"] || raw.min_balance || raw.minBalance || 0);
}

function accountAssetHolding(
  accountInfo: AccountInfoResult | Record<string, any>,
  assetId: number | bigint,
): Record<string, any> | undefined {
  if (!accountInfo || typeof accountInfo === "string") {
    return undefined;
  }
  const raw = accountInfo as Record<string, any>;
  const wanted = BigInt(assetId);
  const assets = Array.isArray(raw.assets) ? raw.assets : [];
  return assets.find((holding: Record<string, any>) => {
    const id = holding["asset-id"] ?? holding.asset_id ?? holding.assetId;
    return id !== undefined && BigInt(id) === wanted && holding.deleted !== true;
  });
}

function assetHoldingAmount(holding: Record<string, any>): bigint {
  return BigInt(holding.amount || 0);
}

function accountList(accountInfo: AccountInfoResult | Record<string, any>, names: string[]): unknown[] {
  if (!accountInfo || typeof accountInfo === "string") {
    return [];
  }
  const raw = accountInfo as Record<string, any>;
  for (const name of names) {
    const value = raw[name];
    if (Array.isArray(value) && value.length > 0) {
      return value;
    }
  }
  return [];
}

function accountInt(accountInfo: AccountInfoResult | Record<string, any>, names: string[]): number {
  if (!accountInfo || typeof accountInfo === "string") {
    return 0;
  }
  const raw = accountInfo as Record<string, any>;
  for (const name of names) {
    const value = raw[name];
    if (value !== undefined && value !== null) {
      return Number(value);
    }
  }
  return 0;
}

function accountStatus(accountInfo: AccountInfoResult | Record<string, any>): string {
  if (!accountInfo || typeof accountInfo === "string") {
    return "";
  }
  return String((accountInfo as Record<string, any>).status || "");
}

function applyPrepFee(params: Record<string, any>, fee?: number, useFlatFee?: boolean): void {
  if (!fee) {
    return;
  }
  params.fee = fee;
  params.flatFee = Boolean(useFlatFee);
  params.flat_fee = Boolean(useFlatFee);
}

function asaOptInChecks(
  accountInfo: AccountInfoResult | Record<string, any>,
  assetId: number | bigint,
  fee: number,
): PreparedCheck[] {
  if (accountAssetHolding(accountInfo, assetId)) {
    throw new SignerError(`sender is already opted into asset ${assetId}`);
  }
  if (accountAmount(accountInfo) < fee) {
    throw new SignerError(`insufficient funds for opt-in fee: balance ${accountAmount(accountInfo)}, fee ${fee}`);
  }
  return [{
    name: "asa_opt_in",
    status: "ok",
    data: { assetId, fee },
  }];
}

function asaOptOutChecks(
  senderInfo: AccountInfoResult | Record<string, any>,
  closeInfo: AccountInfoResult | Record<string, any>,
  assetId: number | bigint,
  closeTo: string,
): PreparedCheck[] {
  const holding = accountAssetHolding(senderInfo, assetId);
  if (!holding) {
    throw new SignerError(`sender is not opted into asset ${assetId}`);
  }
  if (!accountAssetHolding(closeInfo, assetId)) {
    throw new SignerError(`close_to is not opted into asset ${assetId}`);
  }
  return [{
    name: "asa_opt_out",
    status: "ok",
    data: {
      assetId,
      balance: assetHoldingAmount(holding),
      closeTo,
    },
  }];
}

function accountCloseChecks(
  accountInfo: AccountInfoResult | Record<string, any>,
  fee: number,
): PreparedCheck[] {
  if (accountStatus(accountInfo).toLowerCase() === "online") {
    throw new SignerError("cannot close an online account");
  }
  if (
    accountList(accountInfo, ["assets"]).length > 0 ||
    accountInt(accountInfo, ["total-assets-opted-in", "total_assets_opted_in", "totalAssetsOptedIn"]) > 0
  ) {
    throw new SignerError("cannot close account with ASA holdings");
  }
  if (
    accountList(accountInfo, ["created-assets", "created_assets", "createdAssets"]).length > 0 ||
    accountInt(accountInfo, ["total-created-assets", "total_created_assets", "totalCreatedAssets"]) > 0
  ) {
    throw new SignerError("cannot close account with created assets");
  }
  if (
    accountList(accountInfo, ["apps-local-state", "apps_local_state", "appsLocalState"]).length > 0 ||
    accountInt(accountInfo, ["total-apps-opted-in", "total_apps_opted_in", "totalAppsOptedIn"]) > 0
  ) {
    throw new SignerError("cannot close account with app opt-ins");
  }
  if (
    accountList(accountInfo, ["created-apps", "created_apps", "createdApps"]).length > 0 ||
    accountInt(accountInfo, ["total-created-apps", "total_created_apps", "totalCreatedApps"]) > 0
  ) {
    throw new SignerError("cannot close account with created apps");
  }
  if (accountAmount(accountInfo) < fee) {
    throw new SignerError(`insufficient funds for close fee: balance ${accountAmount(accountInfo)}, fee ${fee}`);
  }
  return [{
    name: "account_close",
    status: "ok",
    data: {
      balance: accountAmount(accountInfo),
      minBalance: accountMinBalance(accountInfo),
      fee,
    },
  }];
}

function rekeyChecks(accountInfo: AccountInfoResult | Record<string, any>, rekeyTo: string): PreparedCheck[] {
  const authAddress = extractAuthAddress(accountInfo);
  if (authAddress && authAddress !== rekeyTo) {
    throw new SignerError(`rekey target is itself rekeyed to ${authAddress}`);
  }
  return [{
    name: "rekey",
    status: "ok",
    data: { rekeyTo },
  }];
}

function validateKeyregParams(params: KeyregPrepParams): void {
  if (params.nonParticipation) {
    return;
  }
  if (!params.voteKey) {
    throw new SignerError("voteKey is required");
  }
  if (!params.selectionKey) {
    throw new SignerError("selectionKey is required");
  }
  if (!params.voteFirst) {
    throw new SignerError("voteFirst is required");
  }
  if (!params.voteLast) {
    throw new SignerError("voteLast is required");
  }
  if (BigInt(params.voteLast) < BigInt(params.voteFirst)) {
    throw new SignerError("voteLast must be greater than or equal to voteFirst");
  }
  if (!params.voteKeyDilution) {
    throw new SignerError("voteKeyDilution is required");
  }
}

function validatePaymentGroup(transactions: PreparedTransaction[]): PreparedCheck {
  const totals = new Map<string, { available: bigint; required: bigint }>();
  for (const item of transactions) {
    if (!item.transaction) {
      throw new SignerError("payment group transaction is required");
    }
    const txn = item.transaction as any;
    const sender = txn.sender.toString();
    const total = totals.get(sender) || { available: 0n, required: 0n };
    total.required += BigInt(txn.payment?.amount || 0) + BigInt(txn.fee || 0);
    for (const check of item.checks || []) {
      if (check.name !== "payment_balance" || !check.data) {
        continue;
      }
      total.available = BigInt((check.data.available as number | bigint | undefined) || 0);
    }
    totals.set(sender, total);
  }
  for (const [sender, total] of totals) {
    if (total.available < total.required) {
      throw new SignerError(
        `payment group insufficient funds for ${sender}: available ${total.available}, required ${total.required}`,
      );
    }
  }
  return {
    name: "payment_group_balance",
    status: "ok",
    data: { senderCount: totals.size },
  };
}

function validateAsaTransferGroup(transactions: PreparedTransaction[]): PreparedCheck {
  const totals = new Map<string, { balance: bigint; amount: bigint }>();
  for (const item of transactions) {
    if (!item.transaction) {
      throw new SignerError("ASA transfer group transaction is required");
    }
    const txn = item.transaction as any;
    const assetIndex = BigInt(txn.assetTransfer?.assetIndex || 0);
    const key = `${txn.sender.toString()}:${assetIndex}`;
    const total = totals.get(key) || { balance: 0n, amount: 0n };
    total.amount += BigInt(txn.assetTransfer?.amount || 0);
    for (const check of item.checks || []) {
      if (check.name !== "asa_transfer" || !check.data) {
        continue;
      }
      total.balance = BigInt((check.data.balance as number | bigint | undefined) || 0);
    }
    totals.set(key, total);
  }
  for (const [key, total] of totals) {
    if (total.balance < total.amount) {
      throw new SignerError(
        `ASA transfer group insufficient asset balance for ${key}: available ${total.balance}, required ${total.amount}`,
      );
    }
  }
  return {
    name: "asa_transfer_group_balance",
    status: "ok",
    data: { holdingCount: totals.size },
  };
}

function appCallChecks(params: AppCallPrepParams, info: { mode?: string; method?: string }): PreparedCheck[] {
  return [{
    name: "app_call",
    status: "ok",
    data: {
      appId: params.appId,
      onCompletion: params.onComplete ?? algosdk.OnApplicationComplete.NoOpOC,
      args: params.appArgs?.length || 0,
      accounts: params.accounts?.length || 0,
      foreignApps: params.foreignApps?.length || 0,
      foreignAssets: params.foreignAssets?.length || 0,
      boxes: params.boxes?.length || 0,
      mode: info.mode,
      ...(info.method ? { method: info.method } : {}),
    },
  }];
}

function encodeAbiMethodArgs(
  method: any,
  args: unknown[],
  sender: string,
  appId: number | bigint,
  accounts?: string[],
  foreignApps?: Array<number | bigint>,
  foreignAssets?: Array<number | bigint>,
): {
  appArgs: Uint8Array[];
  accounts: string[];
  foreignApps: Array<number | bigint>;
  foreignAssets: Array<number | bigint>;
} {
  if (args.length !== method.args.length) {
    throw new SignerError(`incorrect number of ABI arguments: got ${args.length}, want ${method.args.length}`);
  }

  const transactionTypes = new Set(["txn", "pay", "keyreg", "acfg", "axfer", "afrz", "appl"]);
  const referenceTypes = new Set(["account", "application", "asset"]);
  const basicArgTypes: any[] = [];
  const basicArgValues: unknown[] = [];
  const refArgTypes: string[] = [];
  const refArgValues: unknown[] = [];
  const refArgIndexToBasicArgIndex = new Map<number, number>();

  for (let index = 0; index < method.args.length; index++) {
    let argType = method.args[index].type as any;
    const argValue = args[index];
    const argTypeName = String(argType);
    if (transactionTypes.has(argTypeName)) {
      throw new SignerError("ABI transaction arguments are not supported by prepareAbiAppCall");
    }
    if (referenceTypes.has(argTypeName)) {
      refArgIndexToBasicArgIndex.set(refArgTypes.length, basicArgTypes.length);
      refArgTypes.push(argTypeName);
      refArgValues.push(argValue);
      argType = new (algosdk as any).ABIUintType(8);
    } else if (typeof argType === "string") {
      argType = (algosdk as any).ABIType.from(argType);
    }
    basicArgTypes.push(argType);
    basicArgValues.push(argValue);
  }

  const resolvedAccounts = [...(accounts || [])];
  const resolvedApps = [...(foreignApps || [])];
  const resolvedAssets = [...(foreignAssets || [])];
  const refIndexes = resolveAbiReferenceArgs(
    sender,
    appId,
    refArgTypes,
    refArgValues,
    resolvedAccounts,
    resolvedApps,
    resolvedAssets,
  );
  refIndexes.forEach((resolved, index) => {
    if (resolved > 255) {
      throw new SignerError(`ABI reference index ${resolved} exceeds uint8`);
    }
    const basicIndex = refArgIndexToBasicArgIndex.get(index);
    if (basicIndex === undefined) {
      throw new SignerError(`missing ABI reference index ${index}`);
    }
    basicArgValues[basicIndex] = resolved;
  });

  if (basicArgValues.length > APP_CALL_MAX_APP_ARGS - 1) {
    const tupleTypes = basicArgTypes.slice(APP_CALL_METHOD_ARGS_TUPLE_THRESHOLD);
    const tupleValues = basicArgValues.slice(APP_CALL_METHOD_ARGS_TUPLE_THRESHOLD);
    basicArgTypes.length = APP_CALL_METHOD_ARGS_TUPLE_THRESHOLD;
    basicArgValues.length = APP_CALL_METHOD_ARGS_TUPLE_THRESHOLD;
    basicArgTypes.push(new (algosdk as any).ABITupleType(tupleTypes));
    basicArgValues.push(tupleValues);
  }

  const appArgs: Uint8Array[] = [method.getSelector()];
  for (let index = 0; index < basicArgTypes.length; index++) {
    appArgs.push(basicArgTypes[index].encode(basicArgValues[index] as any));
  }
  return {
    appArgs,
    accounts: resolvedAccounts,
    foreignApps: resolvedApps,
    foreignAssets: resolvedAssets,
  };
}

function resolveAbiReferenceArgs(
  sender: string,
  appId: number | bigint,
  argTypes: string[],
  values: unknown[],
  accounts: string[],
  apps: Array<number | bigint>,
  assets: Array<number | bigint>,
): number[] {
  const resolved: number[] = [];
  for (let index = 0; index < argTypes.length; index++) {
    switch (argTypes[index]) {
      case "account": {
        const address = marshalAbiAddress(values[index]);
        if (address === sender) {
          resolved.push(0);
        } else {
          const existing = accounts.indexOf(address);
          if (existing >= 0) {
            resolved.push(existing + 1);
          } else {
            accounts.push(address);
            resolved.push(accounts.length);
          }
        }
        break;
      }
      case "application": {
        const refAppId = BigInt(values[index] as any);
        if (refAppId === BigInt(appId)) {
          resolved.push(0);
        } else {
          const existing = indexOfUint64(apps, refAppId);
          if (existing >= 0) {
            resolved.push(existing + 1);
          } else {
            apps.push(uint64Value(refAppId));
            resolved.push(apps.length);
          }
        }
        break;
      }
      case "asset": {
        const assetId = BigInt(values[index] as any);
        const existing = indexOfUint64(assets, assetId);
        if (existing >= 0) {
          resolved.push(existing);
        } else {
          assets.push(uint64Value(assetId));
          resolved.push(assets.length - 1);
        }
        break;
      }
      default:
        throw new SignerError(`unknown reference type: ${argTypes[index]}`);
    }
  }
  return resolved;
}

function marshalAbiAddress(value: unknown): string {
  if (typeof value === "string") {
    algosdk.decodeAddress(value);
    return value;
  }
  if (value instanceof Uint8Array) {
    if (value.length !== 32) {
      throw new SignerError("decoded value is not a 32-byte address");
    }
    return algosdk.encodeAddress(value);
  }
  if (value && typeof (value as { toString?: unknown }).toString === "function") {
    const address = (value as { toString: () => string }).toString();
    algosdk.decodeAddress(address);
    return address;
  }
  throw new SignerError("account reference arguments must be Algorand addresses");
}

function indexOfUint64(values: Array<number | bigint>, target: bigint): number {
  return values.findIndex((value) => BigInt(value) === target);
}

function uint64Value(value: bigint): number | bigint {
  if (value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  return value;
}

/**
 * Client for apsigner signing service.
 *
 * Use static methods to create instances:
 * ```typescript
 * // SSH tunnel connection
 * const client = await SignerClient.connectSsh(
 *   "signer.example.com",
 *   "your-token",
 *   "~/.ssh/id_ed25519"
 * );
 *
 * // From environment/config (recommended)
 * const client = await SignerClient.fromEnv();
 *
 * // Sign transactions
 * const signed = await client.signTransaction(txn);
 *
 * // Close when done (important for SSH)
 * await client.close();
 * ```
 */
/**
 * Reject truncated or partially empty /sign responses so a malformed signer
 * reply can never submit an incomplete group. The server may append signed
 * dummy transactions after the request slots, and foreign-mode slots are
 * returned empty by design.
 */
function validateGroupSignResponse(requests: SignRequest[], signed: string[]): void {
  if (signed.length < requests.length) {
    throw new SignerError(
      `Server returned ${signed.length} signed transaction(s), want at least ${requests.length}`
    );
  }
  requests.forEach((request, index) => {
    const foreign =
      !!request.txn_bytes_hex && !request.auth_address && !request.signed_txn_hex;
    if (foreign) {
      return;
    }
    if (!signed[index]) {
      throw new SignerError(`Server returned no signature for position ${index + 1}`);
    }
  });
  for (let i = requests.length; i < signed.length; i++) {
    if (!signed[i]) {
      throw new SignerError(`Server returned empty dummy transaction at position ${i + 1}`);
    }
  }
}

export class SignerClient {
  private baseUrl: string;
  private token: string;
  private explicitTimeout?: number;
  private keyCache: Map<string, KeyInfo> = new Map();
  private keyCacheRevision?: number;
  private tunnel: SSHTunnel | null = null;
  private approvalWaitSeconds?: number;
  private approvalWaitFetchedAt?: number;
  private approvalWaitKnown = false;

  /**
   * Create a SignerClient instance.
   *
   * baseUrl is an internal HTTP endpoint. Prefer static methods
   * (connectSsh, fromEnv) so connection details come from explicit SSH
   * parameters or APCLIENT_DATA-derived config.
   */
  constructor(
    baseUrl: string,
    token: string,
    timeout?: number,
    tunnel: SSHTunnel | null = null
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.token = token;
    this.explicitTimeout = timeout && timeout > 0 ? timeout : undefined;
    this.tunnel = tunnel;
  }

  /**
   * Connect to remote apsigner via SSH tunnel.
   *
   * Establishes an SSH tunnel to the remote host and forwards
   * the signer port to a local port. Uses 2FA: token (as SSH username)
   * + public key authentication.
   *
   * @param host - Remote host running apsigner
   * @param token - Authentication token (used for both SSH and HTTP API)
   * @param sshKeyPath - Path to SSH private key (e.g., ~/.ssh/id_ed25519)
   * @param options - Connection options
   * @returns Promise<SignerClient> instance with active SSH tunnel
   *
   * @example
   * ```typescript
   * const client = await SignerClient.connectSsh(
   *   "signer.example.com",
   *   "your-token",
   *   "~/.ssh/id_ed25519"
   * );
   *
   * // Use the client...
   * const signed = await client.signTransaction(txn);
   *
   * // Close when done
   * await client.close();
   * ```
   */
  static async connectSsh(
    host: string,
    token: string,
    sshKeyPath: string,
    options: ConnectSshOptions = {}
  ): Promise<SignerClient> {
    const sshPort = options.sshPort ?? DEFAULT_SSH_PORT;
    const signerPort = options.signerPort ?? DEFAULT_SIGNER_PORT;
    const timeout = options.timeout;
    const knownHostsPath = options.knownHostsPath ?? "";
    if (!knownHostsPath) {
      throw new SignerError("known_hosts path is required");
    }

    const expandedKeyPath = expandPath(sshKeyPath);

    if (!fs.existsSync(expandedKeyPath)) {
      throw new SignerError(`SSH key not found: ${expandedKeyPath}`);
    }

    const trustOnFirstUse = options.trustOnFirstUse ?? false;
    const tunnel = new SSHTunnel();

    try {
      // Token is used as SSH username for 2FA (token + public key)
      await tunnel.connect({
        host,
        sshPort,
        username: token,
        privateKeyPath: expandedKeyPath,
        remoteHost: "127.0.0.1",
        remotePort: signerPort,
        knownHostsPath,
        trustOnFirstUse,
      });
    } catch (error) {
      await tunnel.close();
      if (error instanceof SignerError) {
        throw error;
      }
      throw new SignerUnavailableError(
        `SSH tunnel failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    // Connect through tunnel
    const baseUrl = `http://127.0.0.1:${tunnel.localPort}`;
    const client = new SignerClient(baseUrl, token, timeout, tunnel);

    // Verify connection
    const healthy = await client.health();
    if (!healthy) {
      await client.close();
      throw new SignerUnavailableError(
        `Connected via SSH but signer not responding on port ${signerPort}`
      );
    }

    return client;
  }

  /**
   * Connect using config file from data directory.
   *
   * Data directory contents:
   *   - config.yaml: Connection settings (endpoint.signer_port, endpoint.ssh)
   *   - aplane.token: Authentication token
   *   - .ssh/id_ed25519: SSH key (if using SSH tunnel)
   *
   * The data directory is required: pass `options.dataDir` or set the
   * `APCLIENT_DATA` environment variable. Throws `SignerError` if neither is set.
   *
   * @param options - Connection options
   * @returns Promise<SignerClient> instance
   *
   * @example
   * ```typescript
   * // Reads APCLIENT_DATA from the environment
   * const client = await SignerClient.fromEnv();
   *
   * // Or pass explicitly
   * const client = await SignerClient.fromEnv({ dataDir: "/custom/path" });
   * ```
   */
  static async fromEnv(options: FromEnvOptions = {}): Promise<SignerClient> {
    const dataDir = resolveDataDir(options.dataDir);
    const timeout = options.timeout;

    // Load config from data_dir/config.yaml
    const config = loadConfig(dataDir);

    // Load token from data directory
    const token = loadTokenFromDir(dataDir);

    // Check if SSH is configured
    if (config.ssh) {
      // Resolve SSH key path (relative to data_dir)
      const sshKeyPath = path.join(dataDir, config.ssh.identityFile);

      if (!fs.existsSync(sshKeyPath)) {
        throw new SignerError(`SSH configured but key not found at ${sshKeyPath}`);
      }

      // Resolve known_hosts path (relative to data dir, or use config override)
      const knownHostsPath = path.join(dataDir, config.ssh.knownHostsPath);

      return SignerClient.connectSsh(config.ssh.host, token, sshKeyPath, {
        sshPort: config.ssh.port,
        signerPort: config.signerPort,
        timeout,
        knownHostsPath,
        trustOnFirstUse: config.ssh.trustOnFirstUse,
      });
    }

    // SSH is required
    throw new SignerError(
      "No endpoint.ssh block in config.yaml. " +
      "Add endpoint.ssh with host, port, and identity_file."
    );
  }

  /**
   * Close the client and any SSH tunnel.
   */
  async close(): Promise<void> {
    if (this.tunnel) {
      await this.tunnel.close();
      this.tunnel = null;
    }
  }

  /**
   * Check if signer is healthy and reachable.
   *
   * @returns true if healthy, false otherwise
   */
  async health(): Promise<boolean> {
    try {
      const response = await this.fetch("/health", {
        method: "GET",
        timeout: this.timeoutFor(HEALTH_TIMEOUT),
      });
      return response.status === 200;
    } catch {
      return false;
    }
  }

  /**
   * Fetch authenticated signer status and keyset revision.
   *
   * /status is authenticated but does not require the signer to be unlocked.
   * A locked state in a 200 response is returned as normal data.
   */
  async getStatus(): Promise<StatusResponse> {
    const response = await this.fetch("/status", {
      method: "GET",
      timeout: this.timeoutFor(STATUS_TIMEOUT),
    });

    if (response.status === 401) {
      throw new AuthenticationError();
    }
    if (response.status === 503) {
      throw new SignerUnavailableError(await this.errorMessage(response, "Signer unavailable"));
    }
    if (response.status !== 200) {
      throw await this.signerHTTPError(response, `Failed to get signer status: HTTP ${response.status}`);
    }

    const data = (await response.json()) as Record<string, unknown>;
    const identity: StatusResponse = {
      identityId: String(data.identity_id || ""),
      nodeRole: typeof data.node_role === "string" ? data.node_role : undefined,
      state: String(data.state || ""),
      signerLocked: Boolean(data.signer_locked),
      readyForSigning: Boolean(data.ready_for_signing),
      keyCount: Number(data.key_count || 0),
      keysetRevision: Number(data.keyset_revision || 0),
      approvalWaitSeconds:
        typeof data.approval_wait_seconds === "number" ? data.approval_wait_seconds : undefined,
    };
    this.cacheApprovalWait(identity.approvalWaitSeconds);
    return identity;
  }

  private cacheApprovalWait(seconds?: number): void {
    this.approvalWaitSeconds =
      seconds && seconds > 0 && seconds <= MAX_DISCOVERED_APPROVAL_WAIT / 1000
        ? seconds
        : undefined;
    this.approvalWaitFetchedAt = Date.now();
    this.approvalWaitKnown = true;
  }

  private cachedApprovalWait(now: number = Date.now()): number | undefined {
    if (!this.approvalWaitKnown || !this.approvalWaitSeconds || !this.approvalWaitFetchedAt) {
      return undefined;
    }
    if (now - this.approvalWaitFetchedAt > APPROVAL_WAIT_REFRESH) {
      return undefined;
    }
    return this.approvalWaitSeconds * 1000;
  }

  private needsApprovalWaitDiscovery(now: number = Date.now()): boolean {
    if (!this.approvalWaitKnown || !this.approvalWaitFetchedAt) {
      return true;
    }
    return now - this.approvalWaitFetchedAt > APPROVAL_WAIT_REFRESH;
  }

  private async discoverApprovalWait(): Promise<void> {
    if (!this.needsApprovalWaitDiscovery()) {
      return;
    }
    try {
      await this.getStatus();
    } catch {
      // /status discovery failure must not fail /sign; use fallback timeout.
    }
  }

  private signRequestTimeout(): number {
    const wait = this.cachedApprovalWait();
    return this.timeoutFor(wait ? wait + SIGN_APPROVAL_SLACK : DEFAULT_SIGN_REQUEST_TIMEOUT);
  }

  private timeoutFor(defaultTimeout: number): number {
    if (this.explicitTimeout && this.explicitTimeout < defaultTimeout) {
      return this.explicitTimeout;
    }
    return defaultTimeout;
  }

  /**
   * List available signing keys.
   *
   * @param refresh - If true, bypass cache and fetch fresh data
   * @returns List of KeyInfo with address, keyType, etc.
   */
  async listKeys(refresh: boolean = false): Promise<KeyInfo[]> {
    if (!refresh && this.keyCache.size > 0) {
      return Array.from(this.keyCache.values());
    }

    const response = await this.fetch("/keys", {
      method: "GET",
      timeout: this.timeoutFor(INVENTORY_TIMEOUT),
    });

    if (response.status === 401) {
      throw new AuthenticationError();
    }

    if (response.status !== 200) {
      throw await this.signerHTTPError(response, `Failed to list keys: HTTP ${response.status}`);
    }

    const data = (await response.json()) as KeysResponse;
    const keys: KeyInfo[] = [];
    this.keyCache.clear();
    this.keyCacheRevision = undefined;

    for (const k of data.keys || []) {
      // Parse signing_args, mapping snake_case API fields to camelCase TypeScript
      let signingArgs: SigningArg[] | undefined;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const rawArgs = (k as any).signing_args;
      if (rawArgs) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        signingArgs = rawArgs.map((arg: any) => ({
          name: arg.name,
          type: arg.type || "bytes",
          description: arg.description || "",
          label: arg.label,
          required: arg.required,
          byteLength: arg.byte_length,
        }));
      }

      // Map snake_case API fields to camelCase TypeScript interface
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const raw = k as any;
      const templateProvenanceStatus = raw.template_provenance_status || raw.template_status;
      const templateProvenanceNote = raw.template_provenance_note || raw.template_warning;
      const keyInfo: KeyInfo = {
        address: k.address,
        publicKeyHex: raw.public_key_hex || "",
        keyType: raw.key_type || "",
        signingFlow: raw.signing_flow || undefined,
        sentryComponentKeyType: raw.sentry_component_key_type || undefined,
        lsigSize: raw.lsig_size || 0,
        isGenericLsig: raw.is_generic_lsig || false,
        isComponentKey: raw.is_component_key || false,
        isSpendingAccount: typeof raw.is_spending_account === "boolean" ? raw.is_spending_account : undefined,
        signingArgs,
        parameters: raw.parameters,
        templateProvenanceStatus,
        templateProvenanceNote,
        templateStatus: templateProvenanceStatus,
        templateWarning: templateProvenanceNote,
      };
      keys.push(keyInfo);
      this.keyCache.set(keyInfo.address, keyInfo);
    }

    return keys;
  }

  /**
   * Return cached keys when /status.keyset_revision is unchanged.
   */
  async listKeysIfKeysetChanged(): Promise<KeyInfo[]> {
    const status = await this.getStatus();
    if (status.signerLocked) {
      throw new SignerUnavailableError("signer is locked");
    }
    if (
      this.keyCache.size > 0 &&
      this.keyCacheRevision !== undefined &&
      this.keyCacheRevision === status.keysetRevision
    ) {
      return Array.from(this.keyCache.values());
    }
    const keys = await this.listKeys(true);
    this.keyCacheRevision = status.keysetRevision;
    return keys;
  }

  /**
   * Get key info for a specific address.
   *
   * @param address - The Algorand address to look up
   * @returns KeyInfo if found, undefined otherwise
   */
  async getKeyInfo(address: string): Promise<KeyInfo | undefined> {
    if (!this.keyCache.has(address)) {
      await this.listKeys(true);
    }
    return this.keyCache.get(address);
  }

  /**
   * Resolve sender -> effective signer and verify signer key ownership.
   */
  async resolveAuthAddress(
    address: string,
    accountInfoLookup: AccountInfoLookup,
  ): Promise<ResolvedAuthAddress> {
    if (!accountInfoLookup) {
      throw new SignerError("accountInfoLookup is required");
    }

    let accountInfo: AccountInfoResult;
    try {
      accountInfo = await accountInfoLookup(address);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new SignerError(`failed to query account info: ${message}`);
    }

    const authAddress = extractAuthAddress(accountInfo);
    const signingAddress =
      authAddress && authAddress !== address ? authAddress : address;
    const keyInfo = findSpendableKey(
      await this.listKeysIfKeysetChanged(),
      signingAddress,
    );
    if (!keyInfo) {
      if (signingAddress === address) {
        throw new KeyNotFoundError(`${address} is not available for signing`);
      }
      throw new KeyNotFoundError(
        `account is rekeyed to ${authAddress} but that address is not signable`,
      );
    }

    return {
      address,
      authAddress: signingAddress,
      isRekeyed: signingAddress !== address,
      keyInfo,
    };
  }

  /**
   * Build a prepared ALGO payment transaction.
   */
  async preparePayment(
    algodClient: any,
    params: PaymentPrepParams,
  ): Promise<PreparedTransaction> {
    if (!algodClient) {
      throw new SignerError("algodClient is required");
    }
    if (!params.sender) {
      throw new SignerError("sender is required");
    }
    if (!params.receiver) {
      throw new SignerError("receiver is required");
    }

    const suggestedParams = await algodClient.getTransactionParams().do();
    applyPrepFee(suggestedParams, params.fee, params.useFlatFee);

    const senderInfo = await algodClient.accountInformation(params.sender).do();
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: params.sender,
      receiver: params.receiver,
      amount: params.amount,
      note: params.note,
      suggestedParams,
    });

    const fee = Number((txn as any).fee || 0);
    const available = accountAmount(senderInfo) - accountMinBalance(senderInfo);
    const required = Number(params.amount) + fee;
    if (available < required) {
      throw new SignerError(`insufficient funds: available ${available}, required ${required}`);
    }

    const resolved = await this.resolveAuthAddress(params.sender, () => senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
      signerKey: resolved.keyInfo,
      checks: [{
        name: "payment_balance",
        status: "ok",
        data: {
          amount: params.amount,
          fee,
          available,
        },
      }],
    };
  }

  /**
   * Build a prepared ASA transfer transaction.
   */
  async prepareAsaTransfer(
    algodClient: any,
    params: AsaTransferPrepParams,
  ): Promise<PreparedTransaction> {
    if (!algodClient) {
      throw new SignerError("algodClient is required");
    }
    if (!params.sender) {
      throw new SignerError("sender is required");
    }
    if (!params.receiver) {
      throw new SignerError("receiver is required");
    }
    if (!params.assetId) {
      throw new SignerError("assetId is required");
    }

    const suggestedParams = await algodClient.getTransactionParams().do();
    applyPrepFee(suggestedParams, params.fee, params.useFlatFee);

    const senderInfo = await algodClient.accountInformation(params.sender).do();
    const receiverInfo = await algodClient.accountInformation(params.receiver).do();
    const senderHolding = accountAssetHolding(senderInfo, params.assetId);
    if (!senderHolding) {
      throw new SignerError(`sender is not opted into asset ${params.assetId}`);
    }
    const senderAmount = assetHoldingAmount(senderHolding);
    if (senderAmount < BigInt(params.amount)) {
      throw new SignerError(
        `insufficient asset balance: available ${senderAmount}, required ${params.amount}`,
      );
    }
    if (!accountAssetHolding(receiverInfo, params.assetId)) {
      throw new SignerError(`receiver is not opted into asset ${params.assetId}`);
    }

    const txn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
      sender: params.sender,
      receiver: params.receiver,
      amount: params.amount,
      assetIndex: params.assetId,
      note: params.note,
      suggestedParams,
    });

    const resolved = await this.resolveAuthAddress(params.sender, () => senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
      signerKey: resolved.keyInfo,
      checks: [{
        name: "asa_transfer",
        status: "ok",
        data: {
          assetId: params.assetId,
          amount: params.amount,
          balance: senderAmount,
        },
      }],
    };
  }

  /**
   * Build a prepared ASA opt-in transaction.
   */
  async prepareAsaOptIn(
    algodClient: any,
    params: AsaOptInPrepParams,
  ): Promise<PreparedTransaction> {
    if (!algodClient) {
      throw new SignerError("algodClient is required");
    }
    if (!params.sender) {
      throw new SignerError("sender is required");
    }
    if (!params.assetId) {
      throw new SignerError("assetId is required");
    }

    const suggestedParams = await algodClient.getTransactionParams().do();
    applyPrepFee(suggestedParams, params.fee, params.useFlatFee);

    const senderInfo = await algodClient.accountInformation(params.sender).do();
    const checks = asaOptInChecks(senderInfo, params.assetId, Number(suggestedParams.fee || 0));
    const txn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
      sender: params.sender,
      receiver: params.sender,
      amount: 0,
      assetIndex: params.assetId,
      note: params.note,
      suggestedParams,
    });

    const resolved = await this.resolveAuthAddress(params.sender, () => senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
      signerKey: resolved.keyInfo,
      checks,
    };
  }

  /**
   * Build a prepared ASA opt-out transaction.
   */
  async prepareAsaOptOut(
    algodClient: any,
    params: AsaOptOutPrepParams,
  ): Promise<PreparedTransaction> {
    if (!algodClient) {
      throw new SignerError("algodClient is required");
    }
    if (!params.sender) {
      throw new SignerError("sender is required");
    }
    if (!params.closeTo) {
      throw new SignerError("closeTo is required");
    }
    if (params.closeTo === params.sender) {
      throw new SignerError("closeTo must differ from sender");
    }
    if (!params.assetId) {
      throw new SignerError("assetId is required");
    }

    const suggestedParams = await algodClient.getTransactionParams().do();
    applyPrepFee(suggestedParams, params.fee, params.useFlatFee);

    const senderInfo = await algodClient.accountInformation(params.sender).do();
    const closeInfo = await algodClient.accountInformation(params.closeTo).do();
    const checks = asaOptOutChecks(senderInfo, closeInfo, params.assetId, params.closeTo);
    const txn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
      sender: params.sender,
      receiver: params.sender,
      amount: 0,
      assetIndex: params.assetId,
      closeRemainderTo: params.closeTo,
      note: params.note,
      suggestedParams,
    });

    const resolved = await this.resolveAuthAddress(params.sender, () => senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
      signerKey: resolved.keyInfo,
      checks,
    };
  }

  /**
   * Build a prepared account close transaction.
   */
  async prepareAccountClose(
    algodClient: any,
    params: AccountClosePrepParams,
  ): Promise<PreparedTransaction> {
    if (!algodClient) {
      throw new SignerError("algodClient is required");
    }
    if (!params.sender) {
      throw new SignerError("sender is required");
    }
    if (!params.closeTo) {
      throw new SignerError("closeTo is required");
    }
    if (params.closeTo === params.sender) {
      throw new SignerError("closeTo must differ from sender");
    }

    const suggestedParams = await algodClient.getTransactionParams().do();
    applyPrepFee(suggestedParams, params.fee, params.useFlatFee);

    const senderInfo = await algodClient.accountInformation(params.sender).do();
    const checks = accountCloseChecks(senderInfo, Number(suggestedParams.fee || 0));
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: params.sender,
      receiver: params.closeTo,
      amount: 0,
      closeRemainderTo: params.closeTo,
      note: params.note,
      suggestedParams,
    });

    const resolved = await this.resolveAuthAddress(params.sender, () => senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
      signerKey: resolved.keyInfo,
      checks,
    };
  }

  /**
   * Build a prepared self-payment rekey transaction.
   */
  async prepareRekey(
    algodClient: any,
    params: RekeyPrepParams,
  ): Promise<PreparedTransaction> {
    if (!algodClient) {
      throw new SignerError("algodClient is required");
    }
    if (!params.sender) {
      throw new SignerError("sender is required");
    }
    if (!params.rekeyTo) {
      throw new SignerError("rekeyTo is required");
    }

    const suggestedParams = await algodClient.getTransactionParams().do();
    applyPrepFee(suggestedParams, params.fee, params.useFlatFee);

    const senderInfo = await algodClient.accountInformation(params.sender).do();
    const targetInfo = params.rekeyTo === params.sender
      ? { address: params.rekeyTo }
      : await algodClient.accountInformation(params.rekeyTo).do();
    const checks = rekeyChecks(targetInfo, params.rekeyTo);
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: params.sender,
      receiver: params.sender,
      amount: 0,
      rekeyTo: params.rekeyTo,
      note: params.note,
      suggestedParams,
    });

    const resolved = await this.resolveAuthAddress(params.sender, () => senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
      signerKey: resolved.keyInfo,
      checks,
    };
  }

  /**
   * Build a prepared key registration transaction.
   */
  async prepareKeyreg(
    algodClient: any,
    params: KeyregPrepParams,
  ): Promise<PreparedTransaction> {
    if (!algodClient) {
      throw new SignerError("algodClient is required");
    }
    if (!params.sender) {
      throw new SignerError("sender is required");
    }
    validateKeyregParams(params);

    const suggestedParams = await algodClient.getTransactionParams().do();
    applyPrepFee(suggestedParams, params.fee, params.useFlatFee);

    const senderInfo = await algodClient.accountInformation(params.sender).do();
    const txn = algosdk.makeKeyRegistrationTxnWithSuggestedParamsFromObject({
      sender: params.sender,
      voteKey: params.voteKey,
      selectionKey: params.selectionKey,
      stateProofKey: params.stateProofKey,
      voteFirst: params.voteFirst,
      voteLast: params.voteLast,
      voteKeyDilution: params.voteKeyDilution,
      nonParticipation: params.nonParticipation,
      note: params.note,
      suggestedParams,
    });

    const resolved = await this.resolveAuthAddress(params.sender, () => senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
      signerKey: resolved.keyInfo,
      checks: [{
        name: "keyreg",
        status: "ok",
        data: {
          nonParticipation: Boolean(params.nonParticipation),
          voteFirst: params.voteFirst || 0,
          voteLast: params.voteLast || 0,
          voteKeyDilution: params.voteKeyDilution || 0,
        },
      }],
    };
  }

  /**
   * Build a prepared raw app-call transaction.
   */
  async prepareAppCall(
    algodClient: any,
    params: AppCallPrepParams,
  ): Promise<PreparedTransaction> {
    return this.prepareAppCallWithInfo(algodClient, params, { mode: "raw" });
  }

  /**
   * Build a prepared ABI method-call transaction.
   */
  async prepareAbiAppCall(
    algodClient: any,
    params: AbiAppCallPrepParams,
  ): Promise<PreparedTransaction> {
    if (!params.methodSignature) {
      throw new SignerError("methodSignature is required");
    }
    const method = (algosdk as any).ABIMethod.fromSignature(params.methodSignature);
    const encoded = encodeAbiMethodArgs(
      method,
      params.args || [],
      params.sender,
      params.appId,
      params.accounts,
      params.foreignApps,
      params.foreignAssets,
    );
    return this.prepareAppCallWithInfo(
      algodClient,
      {
        ...params,
        appArgs: encoded.appArgs,
        accounts: encoded.accounts,
        foreignApps: encoded.foreignApps,
        foreignAssets: encoded.foreignAssets,
      },
      { mode: "abi", method: method.getSignature() },
    );
  }

  private async prepareAppCallWithInfo(
    algodClient: any,
    params: AppCallPrepParams,
    appCallInfo: { mode?: string; method?: string },
  ): Promise<PreparedTransaction> {
    if (!algodClient) {
      throw new SignerError("algodClient is required");
    }
    if (!params.sender) {
      throw new SignerError("sender is required");
    }
    if (!params.appId || BigInt(params.appId) === 0n) {
      throw new SignerError("appId is required");
    }
    const onComplete = params.onComplete ?? algosdk.OnApplicationComplete.NoOpOC;
    if (!Number.isInteger(onComplete) || onComplete < 0 || onComplete > algosdk.OnApplicationComplete.DeleteApplicationOC) {
      throw new SignerError(`invalid onComplete: ${onComplete}`);
    }

    const suggestedParams = await algodClient.getTransactionParams().do();
    applyPrepFee(suggestedParams, params.fee, params.useFlatFee);

    const senderInfo = await algodClient.accountInformation(params.sender).do();
    const txn = algosdk.makeApplicationCallTxnFromObject({
      sender: params.sender,
      appIndex: params.appId,
      onComplete,
      appArgs: params.appArgs,
      accounts: params.accounts,
      foreignApps: params.foreignApps,
      foreignAssets: params.foreignAssets,
      boxes: params.boxes,
      approvalProgram: params.approvalProgram,
      clearProgram: params.clearProgram,
      numLocalInts: params.numLocalInts,
      numLocalByteSlices: params.numLocalByteSlices,
      numGlobalInts: params.numGlobalInts,
      numGlobalByteSlices: params.numGlobalByteSlices,
      extraPages: params.extraPages,
      note: params.note,
      suggestedParams,
    });

    const resolved = await this.resolveAuthAddress(params.sender, () => senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
      signerKey: resolved.keyInfo,
      appCallInfo,
      checks: appCallChecks(params, appCallInfo),
    };
  }

  /**
   * Build a prepared application create transaction.
   */
  async prepareAppDeploy(
    algodClient: any,
    params: AppDeployPrepParams,
  ): Promise<PreparedTransaction> {
    if (!algodClient) {
      throw new SignerError("algodClient is required");
    }
    if (!params.sender) {
      throw new SignerError("sender is required");
    }
    if (!params.approvalProgram || params.approvalProgram.length === 0) {
      throw new SignerError("approvalProgram is required");
    }
    if (!params.clearProgram || params.clearProgram.length === 0) {
      throw new SignerError("clearProgram is required");
    }

    const suggestedParams = await algodClient.getTransactionParams().do();
    applyPrepFee(suggestedParams, params.fee, params.useFlatFee);

    const senderInfo = await algodClient.accountInformation(params.sender).do();
    const txn = algosdk.makeApplicationCreateTxnFromObject({
      sender: params.sender,
      onComplete: params.optIn ? algosdk.OnApplicationComplete.OptInOC : algosdk.OnApplicationComplete.NoOpOC,
      approvalProgram: params.approvalProgram,
      clearProgram: params.clearProgram,
      numLocalInts: params.numLocalInts,
      numLocalByteSlices: params.numLocalByteSlices,
      numGlobalInts: params.numGlobalInts,
      numGlobalByteSlices: params.numGlobalByteSlices,
      extraPages: params.extraPages,
      appArgs: params.appArgs,
      accounts: params.accounts,
      foreignApps: params.foreignApps,
      foreignAssets: params.foreignAssets,
      boxes: params.boxes,
      note: params.note,
      suggestedParams,
    });

    const resolved = await this.resolveAuthAddress(params.sender, () => senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
      signerKey: resolved.keyInfo,
      appCallInfo: { mode: "raw" },
      checks: [{
        name: "app_deploy",
        status: "ok",
        data: {
          extraPages: params.extraPages || 0,
          approvalProgramLen: params.approvalProgram.length,
          clearProgramLen: params.clearProgram.length,
          optIn: Boolean(params.optIn),
        },
      }],
    };
  }

  /**
   * Build a sweep group from normalized ASA transfers and payments.
   */
  async prepareSweepGroup(
    algodClient: any,
    params: SweepPrepParams,
  ): Promise<PreparedGroup> {
    const asaTransfers = params.asaTransfers || [];
    const payments = params.payments || [];
    if (asaTransfers.length === 0 && payments.length === 0) {
      throw new SignerError("sweep group must not be empty");
    }

    const transactions: PreparedTransaction[] = [];
    for (let index = 0; index < asaTransfers.length; index++) {
      try {
        transactions.push(await this.prepareAsaTransfer(algodClient, asaTransfers[index]));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new SignerError(`ASA transfer ${index}: ${message}`);
      }
    }
    for (let index = 0; index < payments.length; index++) {
      try {
        transactions.push(await this.preparePayment(algodClient, payments[index]));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new SignerError(`payment ${index}: ${message}`);
      }
    }

    const checks: PreparedCheck[] = [{
      name: "sweep_group",
      status: "ok",
      data: {
        asaTransferCount: asaTransfers.length,
        paymentCount: payments.length,
      },
    }];
    if (asaTransfers.length > 0) {
      checks.push(validateAsaTransferGroup(transactions.slice(0, asaTransfers.length)));
    }
    if (payments.length > 0) {
      checks.push(validatePaymentGroup(transactions.slice(asaTransfers.length)));
    }
    return { transactions, checks };
  }

  /**
   * Build an ordered group of prepared ALGO payment transactions.
   */
  async preparePaymentGroup(
    algodClient: any,
    payments: PaymentPrepParams[],
  ): Promise<PreparedGroup> {
    if (!payments || payments.length === 0) {
      throw new SignerError("payments must not be empty");
    }
    const transactions: PreparedTransaction[] = [];
    for (let index = 0; index < payments.length; index++) {
      try {
        transactions.push(await this.preparePayment(algodClient, payments[index]));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new SignerError(`payment ${index}: ${message}`);
      }
    }
    return {
      transactions,
      checks: [{
        name: "payment_group",
        status: "ok",
        data: { count: payments.length },
      }, validatePaymentGroup(transactions)],
    };
  }

  /**
   * Build an ordered group of prepared ASA transfer transactions.
   */
  async prepareAsaTransferGroup(
    algodClient: any,
    transfers: AsaTransferPrepParams[],
  ): Promise<PreparedGroup> {
    if (!transfers || transfers.length === 0) {
      throw new SignerError("transfers must not be empty");
    }
    const transactions: PreparedTransaction[] = [];
    for (let index = 0; index < transfers.length; index++) {
      try {
        transactions.push(await this.prepareAsaTransfer(algodClient, transfers[index]));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new SignerError(`ASA transfer ${index}: ${message}`);
      }
    }
    return {
      transactions,
      checks: [{
        name: "asa_transfer_group",
        status: "ok",
        data: { count: transfers.length },
      }, validateAsaTransferGroup(transactions)],
    };
  }

  /**
   * Return the payment-first group shape for payment plus app-call workflows.
   */
  preparePaymentAppCallGroup(
    payment: PreparedTransaction,
    appCall: PreparedTransaction,
  ): PreparedGroup {
    if (!payment.transaction) {
      throw new SignerError("payment transaction is required");
    }
    if (!appCall.transaction) {
      throw new SignerError("app call transaction is required");
    }
    return {
      transactions: [payment, appCall],
      checks: [{
        name: "payment_app_call_order",
        status: "ok",
        data: { paymentIndex: 0, appCallIndex: 1 },
      }],
    };
  }

  /**
   * List available key types supported by the signer.
   *
   * @returns List of KeyTypeInfo describing each available key type
   */
  async listKeyTypes(): Promise<KeyTypeInfo[]> {
    const response = await this.fetch("/keytypes", {
      method: "GET",
      timeout: this.timeoutFor(INVENTORY_TIMEOUT),
    });

    if (response.status === 401) {
      throw new AuthenticationError();
    }
    if (response.status !== 200) {
      throw await this.signerHTTPError(response, `Failed to list key types: HTTP ${response.status}`);
    }

    const data = (await response.json()) as KeyTypesResponse;
    const result: KeyTypeInfo[] = [];

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    for (const kt of (data as any).key_types || []) {
      let creationParams: CreationParam[] | undefined;
      if (kt.creation_params) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        creationParams = kt.creation_params.map((p: any) => ({
          name: p.name,
          label: p.label || "",
          description: p.description,
          paramType: p.type,
          required: p.required,
          maxLength: p.max_length,
          inputModes: Array.isArray(p.input_modes)
            ? p.input_modes.map((mode: any) => ({
                name: mode.name,
                label: mode.label,
                transform: mode.transform,
                byteLength: mode.byte_length,
                inputType: mode.input_type,
              }))
            : undefined,
          minItems: p.min_items,
          maxItems: p.max_items,
          options: p.options,
          min: p.min,
          max: p.max,
          example: p.example,
          placeholder: p.placeholder,
          default: p.default,
        }));
      }

      let runtimeArgs: RuntimeArg[] | undefined;
      if (kt.runtime_args) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        runtimeArgs = kt.runtime_args.map((arg: any) => ({
          name: arg.name,
          type: arg.type || "bytes",
          description: arg.description || "",
          label: arg.label,
          required: arg.required,
          byteLength: arg.byte_length,
        }));
      }

      result.push({
        keyType: kt.key_type,
        family: kt.family || "",
        displayName: kt.display_name,
        description: kt.description,
        requiresLogicsig: kt.requires_logicsig,
        mnemonicWordCount: kt.mnemonic_word_count,
        mnemonicImport: kt.mnemonic_import,
        mnemonicScheme: kt.mnemonic_scheme,
        signingFlow: kt.signing_flow || undefined,
        sentryComponentKeyType: kt.sentry_component_key_type || undefined,
        creationParams,
        runtimeArgs,
      });
    }

    return result;
  }

  /**
   * Generate a new key on the signer.
   *
   * @param keyType - Type of key to generate (e.g., "ed25519", "aplane.falcon1024.v1")
   * @param parameters - Optional creation parameters (type-specific)
   * @returns GenerateResult with address, keyType, and parameters
   */
  async generateKey(
    keyType: string,
    parameters?: Record<string, string>
  ): Promise<GenerateResult> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body: any = { key_type: keyType };
    if (parameters) {
      body.parameters = parameters;
    }

    const response = await this.fetch("/admin/generate", {
      method: "POST",
      body: JSON.stringify(body),
      timeout: this.timeoutFor(MUTATION_TIMEOUT),
    });

    if (response.status === 401) {
      throw new AuthenticationError();
    }
    if (response.status === 403) {
      throw await this.forbiddenLockedError(response);
    }
    if (response.status === 400) {
      throw await this.signerHTTPError(response, "Bad request");
    }
    if (response.status !== 200) {
      throw await this.signerHTTPError(response, `Key generation failed: HTTP ${response.status}`);
    }

    const data = (await response.json()) as Record<string, unknown>;
    if (data.error) {
      throw new SignerError(String(data.error));
    }

    // Invalidate key cache
    this.keyCache.clear();
    this.keyCacheRevision = undefined;

    return {
      address: String(data.address || ""),
      publicKeyHex: typeof data.public_key_hex === "string" ? data.public_key_hex : undefined,
      keyType: String(data.key_type || ""),
      isComponentKey: Boolean(data.is_component_key),
      isSpendingAccount: typeof data.is_spending_account === "boolean" ? data.is_spending_account : undefined,
      parameters: data.parameters as Record<string, string> | undefined,
    };
  }

  /**
   * Delete a key from the signer.
   *
   * @param address - Algorand address of the key to delete
   */
  async deleteKey(address: string): Promise<void> {
    const response = await this.fetch(`/admin/keys?address=${encodeURIComponent(address)}`, {
      method: "DELETE",
      timeout: this.timeoutFor(MUTATION_TIMEOUT),
    });

    if (response.status === 401) {
      throw new AuthenticationError();
    }
    if (response.status === 403) {
      throw await this.forbiddenLockedError(response);
    }
    if (response.status === 404) {
      throw new KeyDeletionError(await this.errorMessage(response, `Key not found: ${address}`));
    }
    if (response.status !== 200) {
      throw await this.signerHTTPError(response, `Key deletion failed: HTTP ${response.status}`);
    }

    const data = await this.safeJson(response);
    if (data.error) {
      throw new SignerError(String(data.error));
    }

    // Invalidate key cache
    this.keyCache.clear();
    this.keyCacheRevision = undefined;
  }

  /**
   * Ask apsigner to cancel a live synchronous /sign request.
   *
   * Cancellation is idempotent for client behavior. A successful response
   * returns state "canceled" or "not_found".
   */
  async cancelSignRequest(requestId: string): Promise<CancelSignResponse> {
    validateSignRequestId(requestId, true);
    const response = await this.fetch("/sign/cancel", {
      method: "POST",
      body: JSON.stringify({ request_id: requestId }),
      timeout: this.timeoutFor(SIGN_CANCEL_TIMEOUT),
    });

    if (response.status === 401) {
      throw new AuthenticationError();
    }
    if (response.status !== 200) {
      throw await this.signerHTTPError(response, `Sign cancel failed: HTTP ${response.status}`);
    }

    const data = (await response.json()) as CancelSignResponse;
    if (data.error) {
      throw new SignerError(data.error);
    }
    return data;
  }

  /**
   * Send a raw role-specific component signing request to /sign/component.
   *
   * This is a low-level building block for guarded-account flows. The SDK
   * validates request and response shape but does not assemble transactions.
   */
  async requestComponentSign(
    request: ComponentSignRequest,
    options?: { signal?: AbortSignal },
  ): Promise<ComponentSignResponse> {
    const requestBody: ComponentSignRequest = {
      ...request,
      request_id: request.request_id || newSignRequestId(),
    };
    try {
      validateComponentSignRequest(requestBody);
    } catch (error) {
      throw new SignerError(
        `invalid component sign request: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    const response = await this.fetch("/sign/component", {
      method: "POST",
      body: JSON.stringify(requestBody),
      timeout: this.timeoutFor(COMPONENT_SIGN_TIMEOUT),
      signal: options?.signal,
    });

    if (response.status === 401) {
      throw new AuthenticationError();
    }

    if (response.status === 403) {
      throw await this.forbiddenRejectedError(response, "Component signing request rejected");
    }

    if (response.status === 503) {
      throw new SignerUnavailableError(await this.errorMessage(response, "Signer unavailable"));
    }

    if (response.status !== 200) {
      throw await this.signerHTTPError(response, `Component signing failed: HTTP ${response.status}`);
    }

    let data: ComponentSignResponse & { error?: string };
    try {
      data = (await response.json()) as ComponentSignResponse & { error?: string };
    } catch {
      throw new SignerError("Server returned invalid JSON");
    }

    if (data.error) {
      throw new SignerError(data.error);
    }

    try {
      validateComponentSignResponse(data);
    } catch (error) {
      throw new SignerError(
        `invalid component sign response: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    return data;
  }

  /**
   * Send a raw guarded transaction assembly request to /sign/assemble.
   */
  async requestGuardedAssemble(
    request: GuardedAssemblyRequest,
    options?: { signal?: AbortSignal },
  ): Promise<GuardedAssemblyResponse> {
    const requestBody: GuardedAssemblyRequest = {
      ...request,
      request_id: request.request_id || newSignRequestId(),
    };
    try {
      validateGuardedAssemblyRequest(requestBody);
    } catch (error) {
      throw new SignerError(
        `invalid guarded assembly request: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    const response = await this.fetch("/sign/assemble", {
      method: "POST",
      body: JSON.stringify(requestBody),
      timeout: this.timeoutFor(GUARDED_ASSEMBLY_TIMEOUT),
      signal: options?.signal,
    });

    if (response.status === 401) {
      throw new AuthenticationError();
    }

    if (response.status === 403) {
      throw await this.forbiddenRejectedError(response, "Guarded assembly request rejected");
    }

    if (response.status === 503) {
      throw new SignerUnavailableError(await this.errorMessage(response, "Signer unavailable"));
    }

    if (response.status !== 200) {
      throw await this.signerHTTPError(response, `Guarded assembly failed: HTTP ${response.status}`);
    }

    let data: GuardedAssemblyResponse & { error?: string };
    try {
      data = (await response.json()) as GuardedAssemblyResponse & { error?: string };
    } catch {
      throw new SignerError("Server returned invalid JSON");
    }

    if (data.error) {
      throw new SignerError(data.error);
    }

    try {
      validateGuardedAssemblyResponse(data);
    } catch (error) {
      throw new SignerError(
        `invalid guarded assembly response: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    return data;
  }

  /**
   * Sync public sentry reference candidates into the connected signer.
   */
  async adminSyncSentryReferences(
    candidates: SentryReferenceCandidate[],
  ): Promise<AdminSyncSentryReferencesResponse> {
    const requestBody: AdminSyncSentryReferencesRequest = { candidates };
    const response = await this.fetch("/admin/sentries/sync", {
      method: "POST",
      body: JSON.stringify(requestBody),
      timeout: this.timeoutFor(MUTATION_TIMEOUT),
    });

    if (response.status === 401) {
      throw new AuthenticationError();
    }
    if (response.status === 403) {
      throw await this.forbiddenLockedError(response);
    }
    if (response.status !== 200) {
      throw await this.signerHTTPError(response, `Sentry reference sync failed: HTTP ${response.status}`);
    }

    let data: AdminSyncSentryReferencesResponse;
    try {
      data = (await response.json()) as AdminSyncSentryReferencesResponse;
    } catch {
      throw new SignerError("Server returned invalid JSON");
    }

    if (data.error) {
      throw new SignerError(data.error);
    }

    return data;
  }

  private async bestEffortCancelSignRequest(requestId: string): Promise<void> {
    try {
      await this.cancelSignRequest(requestId);
    } catch {
      // Best-effort cleanup only; preserve the original signing error.
    }
  }

  /**
   * Preview group building without signing or approval.
   *
   * Sends the same request as signTransactions() to the /plan endpoint.
   * The server performs group building (dummy insertion, fee pooling,
   * group ID computation) and returns the planned group as unsigned
   * transactions plus a mutation report.
   *
   * @param txns - List of algosdk Transaction objects
   * @param authAddresses - List of auth addresses (one per txn)
   * @param lsigArgsMap - Optional mapping of address -> lsigArgs
   * @param passthrough - Optional mapping of group index -> base64-encoded pre-signed transaction
   * @param lsigSizes - Optional mapping of group index -> LSig size hint for foreign transactions
   * @returns PlanGroupResponse with transactions and mutations
   */
  async planGroup(
    txns: (Transaction | null)[],
    authAddresses?: (string | null)[],
    lsigArgsMap?: LsigArgsMap,
    passthrough?: Record<number, string>,
    lsigSizes?: Record<number, number>,
  ): Promise<PlanGroupResponse> {
    const authAddrs = authAddresses ?? txns.map((txn) => txn?.sender?.toString() ?? null);

    if (authAddrs.length !== txns.length) {
      throw new SignerError("authAddresses length must match txns length");
    }

    const requestBody = this.buildSignRequestBody(
      txns, authAddrs, lsigArgsMap, passthrough, lsigSizes,
    );

    const response = await this.fetch("/plan", {
      method: "POST",
      body: JSON.stringify(requestBody),
      timeout: this.timeoutFor(GROUP_PLAN_TIMEOUT),
    });

    if (response.status === 401) {
      throw new AuthenticationError();
    }
    if (response.status === 400) {
      throw await this.badRequestError(response);
    }
    if (response.status === 403) {
      throw await this.signerHTTPError(response, "Forbidden");
    }
    if (response.status !== 200) {
      throw await this.signerHTTPError(response, `Plan failed: HTTP ${response.status}`);
    }

    let data: PlanGroupResponse;
    try {
      data = (await response.json()) as PlanGroupResponse;
    } catch {
      throw new SignerError("Server returned invalid JSON");
    }

    if (data.error) {
      throw new SignerError(data.error);
    }

    if (data.mutations) {
      data = {
        ...data,
        mutations: this.normalizeMutationReport(data.mutations),
      };
    }

    return data;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private normalizeMutationReport(raw: any): MutationReport {
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

  /**
   * Sign a transaction via apsigner.
   *
   * The server automatically handles:
   * - Dummy transaction creation for large LogicSigs (e.g., Falcon-1024)
   * - Fee pooling (distributes fees across the group)
   * - Group ID computation
   *
   * @param txn - algosdk Transaction object
   * @param authAddress - Key to sign with (defaults to txn.sender)
   * @param lsigArgs - Optional runtime args for generic LogicSigs
   * @returns Base64-encoded signed transaction(s), ready for algodClient.sendRawTransaction()
   *
   * @example
   * ```typescript
   * // Basic signing (uses txn.sender as authAddress)
   * const signed = await client.signTransaction(txn);
   *
   * // Rekeyed account
   * const signed = await client.signTransaction(txn, "SIGNER_KEY_ADDRESS");
   *
   * // Generic LogicSig with runtime args
   * const signed = await client.signTransaction(txn, hashlockAddr, {
   *   preimage: new Uint8Array([...])
   * });
   * ```
   */
  async signTransaction(
    txn: Transaction,
    authAddress?: string,
    lsigArgs?: LsigArgs,
    options?: SignOptions,
  ): Promise<string> {
    const auth = authAddress ?? txn.sender.toString();
    const lsigArgsMap = lsigArgs ? { [auth]: lsigArgs } : undefined;

    const signedList = await this.signRequest([txn], [auth], lsigArgsMap, undefined, undefined, options);

    // Concatenate all signed txns and return as single base64 string
    return concatenateSignedTxns(signedList);
  }

  /**
   * Sign multiple transactions as a group.
   *
   * The server automatically handles:
   * - Group ID computation (for 2+ transactions)
   * - Dummy transaction creation for large LogicSigs
   * - Fee pooling across the group
   *
   * Note: Without passthrough, transactions should NOT have group IDs
   * pre-assigned. The server computes the group ID after adding any
   * required dummies.
   *
   * @param txns - List of algosdk Transaction objects (null for passthrough slots)
   * @param authAddresses - List of auth addresses (one per txn, null for foreign)
   * @param lsigArgsMap - Optional mapping of address -> lsigArgs
   * @param passthrough - Optional mapping of group index -> base64-encoded pre-signed transaction
   * @param lsigSizes - Optional mapping of group index -> LSig size hint for foreign transactions
   * @returns Base64-encoded concatenated signed transactions for the entire group
   */
  async signTransactions(
    txns: (Transaction | null)[],
    authAddresses?: (string | null)[],
    lsigArgsMap?: LsigArgsMap,
    passthrough?: Record<number, string>,
    lsigSizes?: Record<number, number>,
    options?: SignOptions,
  ): Promise<string> {
    const authAddrs =
      authAddresses ?? txns.map((txn) => txn?.sender?.toString() ?? null);

    if (authAddrs.length !== txns.length) {
      throw new SignerError("authAddresses length must match txns length");
    }

    const signedList = await this.signRequest(
      txns, authAddrs, lsigArgsMap, passthrough, lsigSizes, options,
    );

    // Reject if any foreign (empty) slots exist
    if (signedList.some((s) => s === "")) {
      throw new SignerError(
        "signTransactions() cannot produce a complete group when foreign " +
        "entries are present (some slots are unsigned). Use " +
        "signTransactionsList() + assembleGroup() instead."
      );
    }

    // Concatenate all signed txns and return as single base64 string
    return concatenateSignedTxns(signedList);
  }

  /**
   * Sign multiple transactions and return as a list.
   *
   * Like signTransactions() but returns individual base64-encoded signed
   * transactions instead of concatenated. Useful when you need to inspect
   * or handle transactions individually, especially in multi-party workflows.
   *
   * @param txns - List of algosdk Transaction objects (null for passthrough slots)
   * @param authAddresses - List of auth addresses (one per txn, passthrough slots may be null)
   * @param lsigArgsMap - Optional mapping of address -> lsigArgs
   * @param passthrough - Optional mapping of group index -> base64-encoded pre-signed transaction
   * @param lsigSizes - Optional mapping of group index -> LSig size hint for planning foreign transactions
   * @returns List of base64-encoded signed transactions
   */
  async signTransactionsList(
    txns: (Transaction | null)[],
    authAddresses?: (string | null)[],
    lsigArgsMap?: LsigArgsMap,
    passthrough?: Record<number, string>,
    lsigSizes?: Record<number, number>,
    options?: SignOptions,
  ): Promise<string[]> {
    const authAddrs =
      authAddresses ?? txns.map((txn) => txn?.sender?.toString() ?? null);

    if (authAddrs.length !== txns.length) {
      throw new SignerError("authAddresses length must match txns length");
    }

    const signedHexes = await this.signRequest(
      txns, authAddrs, lsigArgsMap, passthrough, lsigSizes, options,
    );

    // Convert each hex to base64 (empty strings stay empty for foreign entries)
    return signedHexes.map((hex) => {
      if (hex === "") return "";
      const bytes = hexToBytes(hex);
      if (typeof Buffer !== "undefined") {
        return Buffer.from(bytes).toString("base64");
      }
      const binary = String.fromCharCode(...bytes);
      return btoa(binary);
    });
  }

  /**
   * Send raw signing request entries to /sign.
   *
   * Higher-level helpers build these entries from algosdk transactions;
   * adapters can use this method directly when they already own transaction
   * encoding.
   */
  async signRequests(
    requests: SignRequest[],
    options?: SignOptions,
  ): Promise<GroupSignResponse> {
    if (requests.length === 0) {
      throw new SignerError("requests must not be empty");
    }

    const requestId = options?.requestId ?? newSignRequestId();
    validateSignRequestId(requestId, true);
    const signBody: GroupSignRequest = { request_id: requestId, requests };

    await this.discoverApprovalWait();

    let response: Response;
    try {
      response = await this.fetch("/sign", {
        method: "POST",
        body: JSON.stringify(signBody),
        timeout: this.signRequestTimeout(),
        signal: options?.signal,
      });
    } catch (error) {
      await this.bestEffortCancelSignRequest(requestId);
      throw error;
    }

    if (response.status === 401) {
      throw new AuthenticationError();
    }

    if (response.status === 400) {
      throw await this.badRequestError(response);
    }

    if (response.status === 403) {
      throw await this.forbiddenRejectedError(response, "Signing request rejected by operator");
    }

    if (response.status === 503) {
      const error = await this.errorMessage(response, "Signer unavailable");
      throw new SignerUnavailableError(error);
    }

    if (response.status !== 200) {
      throw await this.signerHTTPError(response, `Signing failed: HTTP ${response.status}`);
    }

    let data: GroupSignResponse;
    try {
      data = (await response.json()) as GroupSignResponse;
    } catch {
      throw new SignerError("Server returned invalid JSON");
    }

    if (data.error) {
      throw new SignerError(data.error);
    }

    validateGroupSignResponse(requests, data.signed ?? []);

    return data;
  }

  /**
   * Send raw signing request entries to /simulate.
   *
   * The signer signs internally, runs algod simulation, and returns
   * diagnostics plus final unsigned transaction bytes. Signed bytes are never
   * returned by this endpoint.
   */
  async simulateRequests(
    requests: SignRequest[],
    options?: { requestId?: string; signal?: AbortSignal },
  ): Promise<GroupSimulateResponse> {
    if (requests.length === 0) {
      throw new SignerError("requests must not be empty");
    }

    const requestId = options?.requestId ?? "";
    if (requestId) {
      validateSignRequestId(requestId);
    }
    const requestBody: GroupSignRequest = requestId
      ? { request_id: requestId, requests }
      : { requests };

    const response = await this.fetch("/simulate", {
      method: "POST",
      body: JSON.stringify(requestBody),
      timeout: this.timeoutFor(GROUP_SIMULATE_TIMEOUT),
      signal: options?.signal,
    });

    if (response.status === 401) {
      throw new AuthenticationError();
    }

    if (response.status === 400) {
      throw await this.badRequestError(response);
    }

    if (response.status === 403) {
      throw await this.signerHTTPError(response, "Forbidden");
    }

    if (response.status === 503) {
      const error = await this.errorMessage(response, "Signer unavailable");
      throw new SignerUnavailableError(error);
    }

    if (response.status !== 200) {
      throw await this.signerHTTPError(response, `Simulation failed: HTTP ${response.status}`);
    }

    let data: GroupSimulateResponse;
    try {
      data = (await response.json()) as GroupSimulateResponse;
    } catch {
      throw new SignerError("Server returned invalid JSON");
    }

    if (data.error) {
      throw new SignerError(data.error);
    }

    if (data.mutations) {
      data = {
        ...data,
        mutations: this.normalizeMutationReport(data.mutations),
      };
    }

    return data;
  }

  /**
   * Simulate a prepared group through apsigner /simulate.
   */
  async simulatePreparedGroup(
    group: PreparedGroup,
    options?: { requestId?: string; signal?: AbortSignal },
  ): Promise<GroupSimulateResponse> {
    return this.simulateRequests(preparedGroupToSignRequests(group), options);
  }

  /**
   * Simulate one prepared transaction through apsigner /simulate.
   */
  async simulatePreparedTransaction(
    prepared: PreparedTransaction,
    options?: { requestId?: string; signal?: AbortSignal },
  ): Promise<GroupSimulateResponse> {
    return this.simulatePreparedGroup({ transactions: [prepared] }, options);
  }

  /**
   * Build the JSON request body for /sign and /plan endpoints.
   */
  private buildSignRequestBody(
    txns: (Transaction | null)[],
    authAddresses: (string | null)[],
    lsigArgsMap?: LsigArgsMap,
    passthrough?: Record<number, string>,
    lsigSizes?: Record<number, number>,
    allowForeign = true,
  ): { requests: SignRequest[] } {
    if (txns.length === 0) {
      throw new SignerError("transactions must not be empty");
    }

    // Validate passthrough indices
    if (passthrough) {
      for (const idx of Object.keys(passthrough).map(Number)) {
        if (idx < 0 || idx >= txns.length) {
          throw new SignerError(`passthrough index ${idx} out of range for ${txns.length} transactions`);
        }
      }
    }

    // Validate lsigSizes indices
    if (lsigSizes) {
      for (const [idx, size] of Object.entries(lsigSizes).map(([k, v]) => [Number(k), v] as const)) {
        if (idx < 0 || idx >= txns.length) {
          throw new SignerError(`lsigSizes index ${idx} out of range for ${txns.length} transactions`);
        }
        if (typeof size !== "number" || size < 0) {
          throw new SignerError(`lsigSizes[${idx}] must be a non-negative integer`);
        }
      }
    }

    const signRequests: SignRequest[] = [];
    for (let i = 0; i < txns.length; i++) {
      const txn = txns[i];
      const authAddr = authAddresses[i];

      // Passthrough: include pre-signed transaction as-is
      if (passthrough && i in passthrough) {
        const signedHex = Buffer.from(passthrough[i], "base64").toString("hex");
        signRequests.push({ signed_txn_hex: signedHex });
        continue;
      }

      // Foreign mode: txn_bytes_hex without auth_address
      if (!authAddr) {
        if (!allowForeign) {
          throw new SignerError(
            `foreign entries are only supported on /plan; use planGroup() first, then resubmit slot ${i} as passthrough`
          );
        }
        if (!txn) {
          throw new SignerError(`transaction is required for foreign-mode entry at index ${i}`);
        }
        const [txnBytesHex] = encodeTransaction(txn);
        const req: SignRequest = { txn_bytes_hex: txnBytesHex };
        if (lsigSizes && i in lsigSizes) {
          req.lsig_size = lsigSizes[i];
        }
        signRequests.push(req);
        continue;
      }

      if (!txn) {
        throw new SignerError(`transaction is required for sign-mode entry at index ${i}`);
      }

      const [txnBytesHex, txnSender] = encodeTransaction(txn);

      const req: SignRequest = {
        txn_bytes_hex: txnBytesHex,
        auth_address: authAddr,
        txn_sender: txnSender,
      };

      // Add LogicSig args if provided
      if (lsigArgsMap && lsigArgsMap[authAddr]) {
        req.lsig_args = encodeLsigArgs(lsigArgsMap[authAddr]);
      }

      signRequests.push(req);
    }

    return { requests: signRequests };
  }

  /**
   * Send signing request to the /sign endpoint.
   * Returns hex-encoded signed transactions.
   */
  private async signRequest(
    txns: (Transaction | null)[],
    authAddresses: (string | null)[],
    lsigArgsMap?: LsigArgsMap,
    passthrough?: Record<number, string>,
    lsigSizes?: Record<number, number>,
    options?: SignOptions,
  ): Promise<string[]> {
    const requestBody = this.buildSignRequestBody(
      txns, authAddresses, lsigArgsMap, passthrough, lsigSizes, false,
    );
    const data = await this.signRequests(requestBody.requests, options);

    // Return hex-encoded signed transactions
    const signedHexes = data.signed || [];
    if (signedHexes.length === 0) {
      throw new SignerError("Server returned no signed transactions");
    }

    return signedHexes;
  }

  /**
   * Parse JSON response safely, returning empty object on failure.
   */
  private async safeJson(response: Response): Promise<Record<string, unknown>> {
    try {
      return (await response.json()) as Record<string, unknown>;
    } catch {
      return {};
    }
  }

  /**
   * Parse a non-2xx signer error response.
   */
  private async errorMessage(response: Response, fallback: string): Promise<string> {
    const { message } = await this.errorParts(response, fallback);
    return message;
  }

  /**
   * Parse a non-2xx signer error response into its stable machine-readable
   * code (empty on pre-code signers) and human-readable message.
   */
  private async errorParts(
    response: Response,
    fallback: string
  ): Promise<{ code: string; message: string }> {
    try {
      const jsonResponse =
        typeof response.clone === "function" ? response.clone() : response;
      const data = (await jsonResponse.json()) as Partial<ErrorResponse>;
      if (typeof data.error === "string" && data.error.trim() !== "") {
        return {
          code: typeof data.code === "string" ? data.code : "",
          message: data.error,
        };
      }
    } catch {
      // Fall through to text/fallback handling.
    }

    try {
      const textResponse =
        typeof response.clone === "function" ? response.clone() : response;
      const text = (await textResponse.text()).trim();
      if (text !== "") {
        return { code: "", message: text };
      }
    } catch {
      // Fall through to fallback.
    }

    return { code: "", message: fallback };
  }

  /**
   * Build a SignerError for a non-2xx response, carrying the stable wire
   * error code when the signer provided one.
   */
  private async signerHTTPError(response: Response, fallback: string): Promise<SignerError> {
    const { code, message } = await this.errorParts(response, fallback);
    return new SignerError(message, code);
  }

  /**
   * Classify a 400 at signing/planning endpoints. The wire code is
   * authoritative: not_found maps to KeyNotFoundError. Pre-code signers send
   * no code and keep the legacy message-text mapping.
   */
  private async badRequestError(response: Response): Promise<SignerError> {
    const { code, message } = await this.errorParts(response, "Bad request");
    if (
      code === ErrorCodes.NotFound ||
      (code === "" && message.toLowerCase().includes("not found"))
    ) {
      return new KeyNotFoundError(message, code);
    }
    return new SignerError(`Bad request: ${message}`, code);
  }

  /**
   * Classify a 403 at endpoints that historically reported the signer as
   * locked. The wire code distinguishes a genuinely locked signer from other
   * forbidden conditions; pre-code signers send no code and keep the legacy
   * locked mapping.
   */
  private async forbiddenLockedError(response: Response): Promise<SignerError> {
    const { code, message } = await this.errorParts(response, "Signer is locked");
    if (code === "" || code === ErrorCodes.Locked) {
      return new SignerUnavailableError("Signer is locked", code);
    }
    return new SignerError(message, code);
  }

  /**
   * Classify a 403 at endpoints that historically reported the request as
   * rejected. A locked code maps to the locked error; forbidden (or no code,
   * for pre-code signers) keeps the rejection error.
   */
  private async forbiddenRejectedError(response: Response, fallback: string): Promise<SignerError> {
    const { code, message } = await this.errorParts(response, fallback);
    if (code === ErrorCodes.Locked) {
      return new SignerUnavailableError("Signer is locked", code);
    }
    if (code === "" || code === ErrorCodes.Forbidden) {
      return new SigningRejectedError(message, code);
    }
    return new SignerError(message, code);
  }

  /**
   * Make an HTTP request with authentication and timeout.
   */
  private async fetch(
    path: string,
    options: {
      method: string;
      body?: string;
      timeout?: number;
      signal?: AbortSignal;
    }
  ): Promise<Response> {
    const url = this.baseUrl + path;
    const timeout = options.timeout ?? this.timeoutFor(INVENTORY_TIMEOUT);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    const abortFromCaller = () => controller.abort();
    if (options.signal?.aborted) {
      controller.abort();
    } else {
      options.signal?.addEventListener("abort", abortFromCaller, { once: true });
    }

    try {
      const headers: Record<string, string> = {
        Authorization: `aplane ${this.token}`,
      };

      if (options.body) {
        headers["Content-Type"] = "application/json";
      }

      const response = await fetch(url, {
        method: options.method,
        headers,
        body: options.body,
        signal: controller.signal,
      });

      return response;
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        const msg = options.signal?.aborted
          ? "Request aborted by caller"
          : `Request timed out after ${timeout}ms`;
        throw new SignerUnavailableError(msg);
      }
      throw new SignerUnavailableError(
        `Failed to connect: ${error instanceof Error ? error.message : String(error)}`
      );
    } finally {
      clearTimeout(timeoutId);
      options.signal?.removeEventListener("abort", abortFromCaller);
    }
  }
}
