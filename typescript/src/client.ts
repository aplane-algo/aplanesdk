// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import * as fs from "fs";
import * as path from "path";
import * as net from "net";
import { randomBytes } from "crypto";
import algosdk, { type Algodv2, type Transaction } from "algosdk";
import type { Client as SSHClient, ClientChannel } from "ssh2";
import type {
  KeyInfo,
  AccountInfoLookup,
  AccountInfoResult,
  AuthAddressValue,
  ConnectSshOptions,
  SignerClientOptions,
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
  SimulationResult,
  StatusResponse,
  RotatingAccountStatus,
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
  ComponentRequest,
  ComponentResponse,
  AssemblyRequest,
  AssemblyTarget,
  AssemblyResponse,
  CosignedPassthroughItem,
  ErrorResponse,
  BoundedAuthorizationInfo,
  LogicSigResourceUsage,
  LogicSigResourceProfile,
  AppCallInfo,
  RotatingPrepareRequest,
  RotatingPrepareResponse,
  RotatingSignResponse,
} from "./types.js";
import {
  ErrorCodes,
  SIGNING_FLOW_BOUNDED1,
  SIGNING_FLOW_COSIGNED1,
  BOUNDED_CONTRACT_BOUNDED2,
  BOUNDED_CONTRACT_PLAIN1,
  SIGNING_FLOW_ROTATING1,
  COMPONENT_PATH_SPEND,
  COMPONENT_PATH_SPENDING_REKEY,
  COMPONENT_PATH_LISTED_REKEY,
  componentNeedsCosigner,
  PQ_SCHEME_FALCON1024,
  validateLogicSigResources,
  validateSignRequests,
  wireLogicSigResources,
  ERROR_CODE_ROTATING_WINDOW_NOT_CURRENT,
} from "./types.js";
import {
  SignerError,
  errorText,
  verificationError,
  AuthenticationError,
  SigningRejectedError,
  SignerUnavailableError,
  KeyNotFoundError,
  KeyDeletionError,
  RotatingPreflightError,
  SignOutcomeUnknownError,
  UnsupportedGroupError,
  UnsupportedSigningFlowError,
  callerAborted,
  isLostAnswer,
  markLostAnswer,
} from "./errors.js";
import {
  encodeTransaction,
  encodeLsigArgs,
  concatenateSignedTxns,
  bytesToBase64,
  bytesToHex,
  hexToBytes,
  base64ToBytes,
} from "./encoding.js";
import { preparedGroupToSignRequests, preparedTransactionToSignRequest } from "./prepared.js";
import {
  DUMMY_OPCODE_COST,
  DUMMY_PROGRAM as COSIGNED_DUMMY_PROGRAM,
  MAX_GROUP_SIZE,
  checkMaxFeeIncrease,
  cloneTransaction,
  decodeCanonicalTransaction,
  decodePassthroughSlot,
  decodeRequestSlots,
  signSlot,
  type RequestSlot,
  groupIDBytes,
  signCanonicalDummy,
  signedTransactionMatchesCanonical,
  validateCanonicalDummies,
  validateCanonicalGroupID,
  validatePlanResponse,
  validateSignResponse,
  wholeNumber,
  normalizeMutationReport,
} from "./verify.js";
import {
  SEND_OUTCOME_SUBMITTED,
  algodOptions,
  algodRound,
  checkSendOptions,
  decodeExecutableSignedGroup,
  describeSignedGroup,
  runSimulation,
  signedGroupTransactions,
  submitAndTrack,
  type CheckedSendOptions,
  type SendOptions,
  type SendResult,
} from "./send.js";
import {
  PreparedRotating,
  ROTATING_MAX_LEAD,
  ROTATING_MAX_VALIDITY_WINDOW,
  ROTATING_MIN_REMAINING,
  ROTATING_SEND_ATTEMPTS,
  checkRotatingShape,
  checkRotatingWindow,
  newPreparedRotating,
  refreshRotatingValidity,
  rotatingTiming,
  rotatingWindowCurrent,
  simulationFailed,
  simulationFailure,
  type RotatingPrepareOptions,
  type RotatingSignOptions,
  type RotatingSignResult,
} from "./rotating.js";
import {
  ASSEMBLY_ANSWER,
  COMPONENT_ANSWER,
  GROUP_SIGN_ANSWER,
  ROTATING_SIGN_ANSWER,
  answerProblem,
  type AnswerShape,
} from "./answers.js";
import {
  SSH_USERNAME,
  normalizeSSHSetupTimeout,
  sshConnectionFailedMessage,
} from "./ssh.js";
import {
  loadConfig,
  loadClientEndpointRegistry,
  resolveClientEndpoint,
  clientEndpointSshHostPort,
  resolveDataDir,
  expandPath,
  DEFAULT_SSH_PORT,
} from "./config.js";

const HEALTH_TIMEOUT = 3000;
const STATUS_TIMEOUT = 5000;
const INVENTORY_TIMEOUT = 30000;
const MUTATION_TIMEOUT = 60000;
const GROUP_PLAN_TIMEOUT = 60000;
const COMPONENT_SIGN_TIMEOUT = 120000;
const COSIGNED_ASSEMBLY_TIMEOUT = 120000;
const SIGN_CANCEL_TIMEOUT = 5000;
const SIGN_APPROVAL_SLACK = 30000;
const DEFAULT_SIGN_REQUEST_TIMEOUT = 360000;
const MAX_DISCOVERED_APPROVAL_WAIT = 1800000;
const APPROVAL_WAIT_REFRESH = 300000;
const MAX_SIGN_REQUEST_ID_LENGTH = 128;
const APP_CALL_MAX_APP_ARGS = 16;
const APP_CALL_METHOD_ARGS_TUPLE_THRESHOLD = APP_CALL_MAX_APP_ARGS - 2;

// This must exactly mirror apsigner's canonical dummy lsigresource.Usage.
// /plan and /sign must see the same declaration to keep fee planning idempotent.
export function cosignedDummyLogicSigResources(): LogicSigResourceUsage {
  return {
    programBytes: COSIGNED_DUMMY_PROGRAM.length,
    argumentBytes: 0,
    maxOpcodeCost: DUMMY_OPCODE_COST,
  };
}
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

/**
 * The cosigner signatures by target index. requestComponents has checked the
 * response covers exactly the requested targets as cosigner components; each
 * signature must also be in the scheme the account names for its cosigner.
 */
function componentSignaturesByIndex(
  response: ComponentResponse,
  schemes: Map<number, string>,
): ComponentSignatureByIndex {
  const signatures: ComponentSignatureByIndex = new Map();
  for (const component of response.components) {
    const want = schemes.get(component.target_index);
    if (want && component.signature_scheme !== want) {
      throw new SignerError(
        `cosigner signature for target ${component.target_index} used scheme ` +
          `${JSON.stringify(component.signature_scheme)}, want ${JSON.stringify(want)}`,
      );
    }
    signatures.set(component.target_index, {
      signature: component.signature || "",
      requestId: response.request_id,
    });
  }
  return signatures;
}

function componentRequestForIndices(
  groupBytesHex: string[],
  indices: number[],
  componentKey: string,
  dummyPositions: number[] = [],
  appCallInfo: Map<number, AppCallInfo | undefined> = new Map(),
): ComponentRequest {
  const targetSet = new Set(indices);
  return {
    group_bytes_hex: [...groupBytesHex],
    targets: indices.map((targetIndex) => ({
      target_index: targetIndex,
      kind: "cosigner" as const,
      component_key: componentKey,
      app_call_info: appCallInfo.get(targetIndex),
    })),
    contextual_positions: groupBytesHex.slice(0, groupBytesHex.length - dummyPositions.length).flatMap((_, index) =>
      targetSet.has(index) ? [] : [{ target_index: index, app_call_info: appCallInfo.get(index) }]),
    dummy_positions: dummyPositions.length > 0
      ? dummyPositions.map((target_index) => ({ target_index }))
      : undefined,
  };
}

async function resolveCosignerForTarget(
  target: CosignedSignTarget,
  options: Pick<PreparedCosignedGroupOptions, "cosignerClient" | "cosignerResolver" | "cosignerComponentKey">,
): Promise<CosignedCosignerResolution> {
  if (options.cosignerResolver) {
    const resolved = await options.cosignerResolver(target);
    if (!resolved.client) {
      throw new SignerError("cosigner resolver returned no client");
    }
    return resolved;
  }
  if (!options.cosignerClient) {
    throw new SignerError("cosignerClient or cosignerResolver is required");
  }
  return {
    client: options.cosignerClient,
    componentKey: options.cosignerComponentKey || "",
  };
}

/** Sign the resource dummies a plan appended, after checking each is canonical. */
function signCosignedDummies(
  firstOriginal: Transaction,
  groupID: Uint8Array | undefined,
  dummies: Transaction[],
  startIndex: number,
): CosignedPassthroughItem[] {
  if (dummies.length === 0) {
    return [];
  }
  validateCanonicalDummies(firstOriginal, groupID, dummies);
  return dummies.map((txn, offset) => ({
    target_index: startIndex + offset,
    signed_txn_hex: bytesToHex(signCanonicalDummy(txn)),
    authorization: {
      logicSigResources: cosignedDummyLogicSigResources(),
    },
  }));
}

function decodeCanonicalGroup(groupBytesHex: string[]): Transaction[] {
  if (groupBytesHex.length === 0) {
    throw new SignerError("canonical group is empty");
  }
  if (groupBytesHex.length > MAX_GROUP_SIZE) {
    throw new SignerError(
      `canonical group size ${groupBytesHex.length} exceeds max ${MAX_GROUP_SIZE}`,
    );
  }
  const txns = groupBytesHex.map((encoded, index) => {
    try {
      return decodeCanonicalTransaction(hexToBytes(encoded));
    } catch (error) {
      throw new SignerError(
        `transaction ${index}: ${errorText(error)}`,
      );
    }
  });

  if (txns.length === 1) {
    if (groupIDBytes(txns[0]) !== undefined) {
      throw new SignerError("singleton transaction must not have a group ID");
    }
    return txns;
  }

  validateCanonicalGroupID(txns);
  return txns;
}

function validateBoundedTargetFees(
  planned: Transaction[],
  maxFees: Map<number, number>,
): void {
  for (const [index, maxFee] of maxFees) {
    if (index < 0 || index >= planned.length) {
      throw new SignerError(`bounded target index ${index} is outside planned group`);
    }
    const ceiling = wholeNumber(maxFee);
    if (ceiling === undefined || ceiling < 0n) {
      throw new SignerError(`bounded target ${index} has invalid advertised max_fee`);
    }
    if (planned[index].fee > ceiling) {
      throw new SignerError(
        `bounded target ${index} fee ${planned[index].fee} exceeds advertised max_fee ${maxFee}`,
      );
    }
  }
}

function verifyBoundedAssembledGroup(
  groupBytesHex: string[],
  signedGroup: string[],
): void {
  if (signedGroup.length !== groupBytesHex.length) {
    throw new SignerError(
      `assembled group has ${signedGroup.length} transaction(s), want ${groupBytesHex.length}`,
    );
  }
  signedGroup.forEach((signedHex, index) => {
    signedTransactionMatchesCanonical(
      "assembled transaction",
      index,
      signedHex,
      groupBytesHex[index],
    );
  });
}

function boundedCosignerPublicKey(key: KeyInfo): string {
  return key.boundedAuthorization?.cosigner?.publicKeyHex || key.parameters?.cosigner_public_key || "";
}

function boundedCosignerComponentKeyType(key: KeyInfo): string {
  return key.cosignerComponentKeyType || key.boundedAuthorization?.cosigner?.componentKeyType || "";
}

async function requestBoundedPrimaryPassthrough(
  userClient: SignerClient,
  groupBytesHex: string[],
  originalCount: number,
  boundedIndices: Set<number>,
  targetResources: Map<number, LogicSigResourceUsage | undefined>,
  primaryTargets: CosignedPrimarySignTarget[],
  signal?: AbortSignal,
): Promise<{ response?: GroupSignResponse; passthrough: CosignedPassthroughItem[] }> {
  if (primaryTargets.length === 0) {
    return { passthrough: [] };
  }
  const primaryByIndex = new Map(primaryTargets.map((target) => [target.targetIndex, target]));
  const requests: SignRequest[] = groupBytesHex.map((txnHex, index) => {
    if (index >= originalCount) return {
      txn_bytes_hex: txnHex,
      lsig_resources: wireLogicSigResources(cosignedDummyLogicSigResources()),
    };
    if (boundedIndices.has(index)) {
      return {
        txn_bytes_hex: txnHex,
        lsig_resources: wireLogicSigResources(
          requireLogicSigResources(targetResources.get(index), `bounded target ${index}`),
        ),
      };
    }
    const target = primaryByIndex.get(index);
    if (!target) {
      throw new SignerError(`group position ${index} has no bounded or primary target`);
    }
    return {
      txn_bytes_hex: txnHex,
      auth_address: target.authAddress,
      txn_sender: target.txnSender,
      lsig_args: target.lsigArgs,
      app_call_info: target.appCallInfo,
    };
  });
  const response = await userClient.signRequests(requests, { signal });
  const passthrough: CosignedPassthroughItem[] = [];
  for (const index of Array.from(primaryByIndex.keys()).sort((a, b) => a - b)) {
    if (!response.signed?.[index]) {
      throw new SignerError(`primary signer returned no signed transaction for target ${index}`);
    }
    signedTransactionMatchesCanonical(
      "primary passthrough",
      index,
      response.signed[index],
      groupBytesHex[index],
    );
    passthrough.push({ target_index: index, signed_txn_hex: response.signed[index] });
  }
  return { response, passthrough };
}

/**
 * Sign and assemble a prepared group with one or more cosigned accounts
 * (cosigned1): the signer plans the group, its base components and the
 * cosigner's components are collected, and the signer assembles the result.
 * The cosigner is asked only for targets whose base component needs it.
 */
export async function signPreparedCosignedGroup(
  options: PreparedCosignedGroupOptions,
): Promise<CosignedSignResult> {
  if (!options.userClient) throw new SignerError("userClient is required");
  const prepared = options.preparedGroup.transactions || [];
  if (prepared.length === 0) throw new SignerError("prepared group is empty");

  const requests: SignRequest[] = [];
  const targets: CosignedSignTarget[] = [];
  const primaryTargets: CosignedPrimarySignTarget[] = [];
  const targetResources = new Map<number, LogicSigResourceUsage | undefined>();
  const targetKeys = new Map<number, KeyInfo>();
  const targetMaxFees = new Map<number, number>();
  // One read of the signer's keys for the whole call, refreshed when the
  // signer's keyset revision has changed: the lookup the prepare helpers make.
  const signerKeys = await options.userClient.listKeysIfKeysetChanged();
  for (let index = 0; index < prepared.length; index++) {
    const item = prepared[index];
    if (item.signedTransactionBase64) {
      throw new SignerError(
        `prepared transaction ${index}: passthrough entries are not supported in prepared bounded-cosigner groups`,
      );
    }
    if (!item.transaction) {
      throw new SignerError(`prepared transaction ${index}: transaction is required`);
    }
    // The key's flow, resources and fee ceiling decide how the position is
    // signed, so they come from the signer's own record of the key, looked up
    // as the spendable key for the position's auth address, never from the
    // caller.
    if (!item.authAddress) {
      throw new SignerError(`prepared transaction ${index}: auth address is required`);
    }
    const key = findSpendableKey(signerKeys, item.authAddress);
    if (!key) {
      throw new KeyNotFoundError(
        `prepared transaction ${index}: ${item.authAddress} is not available for signing`,
      );
    }
    if (key.signingFlow === SIGNING_FLOW_COSIGNED1) {
      const requiredResources = requireLogicSigResources(
        selectedPreparedResources(key, item.transaction),
        `prepared transaction ${index}: bounded`,
      );
      requests.push(preparedSignRequest(item, index));
      targetResources.set(index, requiredResources);
      targetKeys.set(index, key);
      if (!key.boundedAuthorization) {
        throw new SignerError(
          `prepared transaction ${index}: bounded authorization metadata is required`,
        );
      }
      const ceiling = boundedFeeCeiling(key.boundedAuthorization);
      if (ceiling !== undefined) {
        targetMaxFees.set(index, ceiling);
      }
      targets.push({
        targetIndex: index,
        cosignedAccount: item.authAddress,
        cosignerPublicKeyHex: boundedCosignerPublicKey(key),
        cosignerComponentKeyType: boundedCosignerComponentKeyType(key),
        logicSigResources: requiredResources,
        appCallInfo: item.appCallInfo,
      });
      continue;
    }
    if (key.signingFlow && key.signingFlow !== SIGNING_FLOW_BOUNDED1) {
      throw new SignerError(
        `prepared transaction ${index}: signer key requires signing flow "${key.signingFlow}", which this SDK does not support; upgrade the SDK`,
      );
    }
    // The signer holds this position's key, so it is sent as the signer's
    // own: in sign mode on /plan, and as a contextual position with
    // auth_address on /sign/component. The signer sizes it from its records
    // in both and can put the group's authorization charge on it. Sent as
    // foreign with a size hint, it was immutable, and the cosigned targets
    // paid its charge.
    requests.push(preparedSignRequest(item, index));
    primaryTargets.push({
      targetIndex: index,
      authAddress: item.authAddress,
      txnSender: item.txnSender,
      lsigArgs: item.lsigArgs ? encodeLsigArgs(item.lsigArgs) : undefined,
      appCallInfo: item.appCallInfo,
    });
  }
  if (targets.length === 0) {
    throw new SignerError("prepared group has no bounded-cosigner targets");
  }

  const planResponse = await options.userClient.planRequests(requests);
  const frozenGroup = [...(planResponse.transactions || [])];
  if (frozenGroup.length < prepared.length) {
    throw new SignerError(
      `signer returned ${frozenGroup.length} bounded group positions, want at least ${prepared.length}`,
    );
  }
  const planned = decodeCanonicalGroup(frozenGroup);
  // planRequests has already checked the plan against the requests: only
  // reported fee raises and group assignment on original positions, and
  // canonical resource dummies after them.
  validateBoundedTargetFees(planned, targetMaxFees);
  const targetIndices = new Set(targets.map((target) => target.targetIndex));
  const componentResponse = await options.userClient.requestComponents(
    {
      group_bytes_hex: frozenGroup,
      targets: requests.flatMap((request, index) => targetIndices.has(index) ? [{
        target_index: index,
        kind: "bounded-base",
        auth_address: request.auth_address || "",
        lsig_args: request.lsig_args,
        app_call_info: request.app_call_info,
      }] : []),
      // The user signer's approval shows the other positions' app calls.
      contextual_positions: requests.flatMap((request, index) => targetIndices.has(index) ? [] : [{
        target_index: index,
        auth_address: request.auth_address,
        lsig_args: request.lsig_args,
        app_call_info: prepared[index].appCallInfo,
      }]),
      dummy_positions: frozenGroup.slice(prepared.length).map((_, offset) => ({
        target_index: prepared.length + offset,
      })),
    },
    { signal: options.signal },
  );
  const targetsByIndex = new Map(targets.map((target) => [target.targetIndex, target]));
  const components = new Map<number, (typeof componentResponse.components)[number]>();
  for (const component of componentResponse.components) {
    const target = targetsByIndex.get(component.target_index);
    if (!target || component.kind !== "bounded-base" ||
        component.auth_address !== target.cosignedAccount) {
      throw new SignerError(`signer returned unexpected bounded component target ${component.target_index}`);
    }
    if (components.has(component.target_index)) {
      throw new SignerError(`signer returned duplicate bounded component target ${component.target_index}`);
    }
    components.set(component.target_index, component);
  }
  for (const target of targets) {
    const component = components.get(target.targetIndex);
    if (!component) {
      throw new SignerError(`signer returned no bounded component for target index ${target.targetIndex}`);
    }
    // Budget the position on the path the signer named, which only the signer
    // can choose: whether a rekey target is listed is not public.
    targetResources.set(
      target.targetIndex,
      componentPathResources(targetKeys.get(target.targetIndex), component.path, `prepared transaction ${target.targetIndex}`),
    );
  }

  const primary = await requestBoundedPrimaryPassthrough(
    options.userClient,
    frozenGroup,
    prepared.length,
    new Set(targetsByIndex.keys()),
    targetResources,
    primaryTargets,
    options.signal,
  );

  // The user side is complete, including ordinary primary positions. Only
  // now may the SDK disclose the frozen group to the cosigner endpoint, and
  // only for the targets that need it: a listed rekey takes no cosigner.
  const cosignerGroups: Array<{ client: SignerClient; componentKey: string; indices: number[] }> = [];
  for (const target of targets) {
    const component = components.get(target.targetIndex);
    if (component && !componentNeedsCosigner(component)) continue;
    const resolved = await resolveCosignerForTarget(target, options);
    let group = cosignerGroups.find(
      (candidate) => candidate.client === resolved.client &&
        candidate.componentKey === (resolved.componentKey || ""),
    );
    if (!group) {
      group = { client: resolved.client, componentKey: resolved.componentKey || "", indices: [] };
      cosignerGroups.push(group);
    }
    group.indices.push(target.targetIndex);
  }
  const cosignerComponentResponses: ComponentResponse[] = [];
  const cosignerSignatures: ComponentSignatureByIndex = new Map();
  // Every original position's app call description, as the caller gave it: a
  // primary slot's /plan request does not carry it.
  const appCallInfo = new Map<number, AppCallInfo | undefined>(
    prepared.map((item, index) => [index, item.appCallInfo]),
  );
  const cosignerSchemes = new Map(
    targets.map((target) => [target.targetIndex, target.cosignerComponentKeyType || ""]),
  );
  for (const group of cosignerGroups) {
    const response = await group.client.requestComponents(
      componentRequestForIndices(
        frozenGroup,
        group.indices.sort((a, b) => a - b),
        group.componentKey,
        frozenGroup.slice(prepared.length).map((_, offset) => prepared.length + offset),
        appCallInfo,
      ),
      { signal: options.signal },
    );
    cosignerComponentResponses.push(response);
    for (const [index, signature] of componentSignaturesByIndex(response, cosignerSchemes)) {
      cosignerSignatures.set(index, signature);
    }
  }

  const passthrough = [
    ...primary.passthrough,
    ...signCosignedDummies(
      prepared[0].transaction as Transaction,
      groupIDBytes(planned[0]),
      planned.slice(prepared.length),
      prepared.length,
    ),
  ];
  const assemblyTargets: AssemblyTarget[] = targets.map((target) => {
    const component = components.get(target.targetIndex);
    if (!component) {
      throw new SignerError(`missing bounded base component for target ${target.targetIndex}`);
    }
    const assemblyTarget: AssemblyTarget = {
      target_index: target.targetIndex,
      kind: "bounded-cosigner",
      auth_address: component.auth_address || "",
      base_signatures: [...(component.base_signatures || [])],
      bounded_runtime_args: component.runtime_args ? { ...component.runtime_args } : undefined,
      assembly_receipt: component.assembly_receipt || "",
      base_source_request_id: componentResponse.request_id,
    };
    if (componentNeedsCosigner(component)) {
      const cosigner = cosignerSignatures.get(target.targetIndex);
      if (!cosigner) {
        throw new SignerError(`missing cosigner component signature for target ${target.targetIndex}`);
      }
      assemblyTarget.cosigner_signature = cosigner.signature;
      assemblyTarget.cosigner_source_request_id = cosigner.requestId;
    }
    return assemblyTarget;
  });
  const assemblyResponse = await options.userClient.requestAssemble({
    request_id: options.assemblyRequestId,
    group_bytes_hex: [...frozenGroup],
    targets: assemblyTargets,
    passthrough,
  }, { signal: options.signal });
  verifyBoundedAssembledGroup(
    frozenGroup,
    assemblyResponse.signed_group,
  );
  return {
    signedGroup: [...assemblyResponse.signed_group],
    cosignerComponentResponses,
    primarySignResponse: primary.response,
    boundedComponentResponse: componentResponse,
    boundedAssemblyResponse: assemblyResponse,
    planMutations: planResponse.mutations,
  };
}

/**
 * Prepare, sign, assemble, and simulate a cosigned group through the caller's
 * algod client.
 */
export async function simulatePreparedCosignedGroup(
  algodClient: Algodv2,
  options: PreparedCosignedGroupOptions,
): Promise<CosignedSimulationResult> {
  if (!algodClient) {
    throw new SignerError("algodClient is required");
  }
  const signing = await signPreparedCosignedGroup(options);
  return {
    signing,
    simulation: await simulateSignedGroup(algodClient, signing.signedGroup),
  };
}

async function simulateSignedGroup(
  algodClient: Algodv2,
  signedGroup: string[],
  mutations?: MutationReport,
): Promise<SimulationResult> {
  if (!algodClient) {
    throw new SignerError("algodClient is required");
  }
  const { decoded: signedTransactions } = decodeExecutableSignedGroup(signedGroup);
  const response = await runSimulation(algodClient, signedTransactions, false);

  return {
    txIds: signedTransactions.map((signed) => signed.txn.txID()),
    transactions: signedGroupTransactions(signedTransactions),
    signedGroup: [...signedGroup],
    mutations,
    response,
    failed: (response.txnGroups?.[0]?.failureMessage ?? "") !== "",
  };
}

function validateComponentGroupBytes(items: string[]): void {
  if (!items || items.length === 0) {
    throw new SignerError("group_bytes_hex is empty");
  }
  if (items.length > MAX_GROUP_SIZE) {
    throw new SignerError(
      `group_bytes_hex length ${items.length} exceeds max ${MAX_GROUP_SIZE}`
    );
  }
  items.forEach((item, index) => {
    if (!item) {
      throw new SignerError(`group_bytes_hex ${index} is empty`);
    }
  });
}

function validateComponentRequest(request: ComponentRequest): void {
  const targets = request.targets || [];
  if (targets.length === 0) throw new SignerError("targets are required");
  const kind = targets[0].kind;
  targets.forEach((target, index) => {
    if (target.kind !== kind) throw new SignerError("mixed component target kinds are not supported");
    if (kind === "cosigner") {
      if (target.auth_address || target.lsig_args) {
        throw new SignerError(`target ${index + 1}: cosigner target forbids auth_address and lsig_args`);
      }
      if (index > 0 && target.component_key !== targets[0].component_key) {
        throw new SignerError("cosigner targets must share one component_key");
      }
    } else if (kind === "bounded-base") {
      if (!target.auth_address || target.component_key) {
        throw new SignerError(`target ${index + 1}: bounded-base target requires auth_address and forbids component_key`);
      }
    } else {
      throw new SignerError(`target ${index + 1}: unsupported component kind`);
    }
  });
  validateSignRequestId(request.request_id || "");
  validateComponentGroupBytes(request.group_bytes_hex || []);
  const contextual = request.contextual_positions || [];
  const dummies = request.dummy_positions || [];
  if (dummies.length > request.group_bytes_hex.length) {
    throw new SignerError("dummy_positions cannot exceed group length");
  }
  const originalCount = request.group_bytes_hex.length - dummies.length;
  const covered = new Set<number>();
  [...targets, ...contextual].forEach((position, index) => {
    if (!Number.isInteger(position.target_index) || position.target_index < 0 ||
        position.target_index >= originalCount || covered.has(position.target_index)) {
      throw new SignerError(`position ${index + 1} has invalid, duplicate, or overlapping target_index`);
    }
    covered.add(position.target_index);
  });
  contextual.forEach((position, index) => {
    // auth_address marks one of the signer's own accounts. Only a
    // bounded-base request sizes the group, so only it takes the field.
    const hasLsigArgs = position.lsig_args !== undefined && Object.keys(position.lsig_args).length > 0;
    if ((position.auth_address || hasLsigArgs) && kind !== "bounded-base") {
      throw new SignerError(
        `contextual position ${index + 1}: auth_address and lsig_args are allowed only on a bounded-base request`,
      );
    }
    // The signer sizes its own account from its records: it takes no hint.
    if (position.auth_address && (position.lsig_resources || position.pq_scheme)) {
      throw new SignerError(
        `contextual position ${index + 1}: lsig_resources and pq_scheme are allowed only without auth_address`,
      );
    }
    if (!position.auth_address && position.lsig_args && Object.keys(position.lsig_args).length > 0) {
      throw new SignerError(`contextual position ${index + 1}: lsig_args requires auth_address`);
    }
    if (position.lsig_resources && position.pq_scheme) {
      throw new SignerError(`contextual position ${index + 1} cannot specify both lsig_resources and pq_scheme`);
    }
    if (position.lsig_resources) {
      validateLogicSigResources({
        programBytes: position.lsig_resources.program_bytes,
        argumentBytes: position.lsig_resources.argument_bytes,
        maxOpcodeCost: position.lsig_resources.max_opcode_cost,
      }, `contextual position ${index + 1}`);
    }
    if (position.pq_scheme && position.pq_scheme !== PQ_SCHEME_FALCON1024) {
      throw new SignerError(`contextual position ${index + 1} has unsupported pq_scheme`);
    }
  });
  for (let index = 0; index < originalCount; index++) {
    if (!covered.has(index)) throw new SignerError(`original group position ${index} is not covered`);
  }
  dummies.forEach((dummy, offset) => {
    if (dummy.target_index !== originalCount + offset) {
      throw new SignerError(`dummy position ${offset + 1} is not in the contiguous suffix`);
    }
  });
}

function validateComponentResponse(response: ComponentResponse, request?: ComponentRequest): void {
  validateSignRequestId(response.request_id, true);
  if (!response.components?.length) throw new SignerError("components array is empty");
  const seen = new Set<number>();
  response.components.forEach((component, index) => {
    if (!Number.isInteger(component.target_index) || component.target_index < 0 || seen.has(component.target_index)) {
      throw new SignerError(`component ${index + 1} has invalid or duplicate target_index`);
    }
    if (request && component.target_index >= request.group_bytes_hex.length) {
      throw new SignerError(`component ${index + 1} target_index is outside the frozen group`);
    }
    seen.add(component.target_index);
    if (component.kind === "cosigner") {
      if (!component.signature || !component.signature_scheme || component.base_signatures?.length || component.assembly_receipt || component.path) {
        throw new SignerError(`component ${index + 1} has invalid signature material`);
      }
    } else if (component.kind === "bounded-base") {
      if (!component.auth_address || !component.base_signatures?.length || !component.assembly_receipt || !component.signature_scheme || component.signature) {
        throw new SignerError(`component ${index + 1} has invalid bounded-base material`);
      }
      if (component.path !== COMPONENT_PATH_SPEND && component.path !== COMPONENT_PATH_SPENDING_REKEY &&
          component.path !== COMPONENT_PATH_LISTED_REKEY) {
        throw new SignerError(`component ${index + 1} has unknown bounded path ${JSON.stringify(component.path)}`);
      }
    } else {
      throw new SignerError(`component ${index + 1} has unsupported kind`);
    }
  });
}

function mapRuntimeArg(raw: any): RuntimeArg {
  return {
    name: raw.name || "",
    type: raw.type || "bytes",
    description: raw.description || "",
    label: raw.label,
    required: raw.required,
    byteLength: raw.byte_length,
    maxSize: raw.max_size,
  };
}

/**
 * An account's on-chain fee ceiling: a bounded host must advertise one, a plain
 * host never has one, and a contract this SDK doesn't know fails closed.
 */
export function boundedFeeCeiling(info: BoundedAuthorizationInfo): number | undefined {
  switch (info.contract) {
    case BOUNDED_CONTRACT_BOUNDED2:
      if (info.maxFee === undefined) {
        throw new SignerError(`bounded authorization ${info.contract} has no max_fee`);
      }
      return info.maxFee;
    case BOUNDED_CONTRACT_PLAIN1:
      if (info.maxFee !== undefined) {
        throw new SignerError(
          `bounded authorization ${info.contract} has a max_fee, which a plain host never has`,
        );
      }
      return undefined;
    default:
      throw new SignerError(
        `bounded authorization contract "${info.contract}" is not supported by this SDK; upgrade it`,
      );
  }
}

function mapBoundedAuthorization(raw: any): BoundedAuthorizationInfo | undefined {
  if (!raw) return undefined;
  return {
    contract: raw.contract || "",
    baseSignatureArgLayout: {
      count: raw.base_signature_arg_layout?.count || 0,
      maxSizes: raw.base_signature_arg_layout?.max_sizes || [],
    },
    spendEffects: raw.spend_effects || [],
    // Absent on a plain host: never turned into a zero ceiling.
    maxFee: raw.max_fee ?? undefined,
    rekey: raw.rekey || "",
    rekeyList: raw.rekey_list
      ? {
          contract: raw.rekey_list.contract || "",
          depth: raw.rekey_list.depth || 0,
          rootHex: raw.rekey_list.root || undefined,
        }
      : undefined,
    cosigner: raw.cosigner
      ? {
          contract: raw.cosigner.contract || "",
          componentKeyType: raw.cosigner.component_key_type || "",
          publicKeyHex: raw.cosigner.public_key_hex || undefined,
          componentKeyId: raw.cosigner.component_key_id || undefined,
          signatureMaxSize: raw.cosigner.signature_max_size || 0,
          requiredOn: raw.cosigner.required_on || [],
        }
      : undefined,
    runtimeArgs: (raw.runtime_args || []).map(mapRuntimeArg),
    derivedArgs: (raw.derived_args || []).map((arg: any) => ({
      name: arg.name || "",
      kind: arg.kind || "",
      parameter: arg.parameter || "",
      maxSize: arg.max_size || 0,
    })),
    argumentLayout: (raw.argument_layout || []).map((slot: any) => ({
      index: slot.index || 0,
      name: slot.name || "",
      source: slot.source || "",
      maxSize: slot.max_size || 0,
      paths: {
        spend: slot.paths?.spend || "",
        spendingRekey: slot.paths?.spending_rekey || "",
        listedRekey: slot.paths?.listed_rekey || "",
      },
    })),
    layer3Policy: raw.layer3_policy || "",
  };
}

function requireLogicSigResources(
  resources: LogicSigResourceUsage | undefined,
  label: string,
): LogicSigResourceUsage {
  if (!resources) {
    throw new SignerError(`${label} LogicSig resources are unavailable`);
  }
  validateLogicSigResources(resources, label);
  return { ...resources };
}

function mapLogicSigResourceUsage(raw: any): LogicSigResourceUsage | undefined {
  if (!raw) return undefined;
  return {
    programBytes: raw.program_bytes || 0,
    argumentBytes: raw.argument_bytes || 0,
    maxOpcodeCost: raw.max_opcode_cost || 0,
  };
}

function mapLogicSigResourceProfile(raw: any): LogicSigResourceProfile | undefined {
  if (!raw) return undefined;
  return {
    default: mapLogicSigResourceUsage(raw.default),
    spend: mapLogicSigResourceUsage(raw.spend),
    spendingRekey: mapLogicSigResourceUsage(raw.spending_rekey),
    listedRekey: mapLogicSigResourceUsage(raw.listed_rekey),
  };
}

function selectedPreparedResources(
  key: KeyInfo | undefined,
  txn: Transaction | undefined,
): LogicSigResourceUsage | undefined {
  const profile = key?.logicSigResources;
  if (!profile) return undefined;
  let selected = profile.spend || profile.default;
  if (key?.boundedAuthorization && txn?.rekeyTo !== undefined) {
    const bounded = key.boundedAuthorization;
    if (bounded.rekeyList && bounded.rekey === "refused") {
      // Only these addresses: the signer checks the target and adds the proof.
      selected = profile.listedRekey;
    } else if (bounded.rekey === "spending_key") {
      // With a list too (plus cosigned) the signer moves a listed target to the
      // listed path, and its base component says so.
      selected = profile.spendingRekey;
    } else if (bounded.rekey === "refused") {
      throw new SignerError("the account refuses rekeys");
    } else {
      throw new SignerError("bounded rekey authorization metadata is unavailable");
    }
  }
  return selected ? { ...selected } : undefined;
}

/** The key's LogicSig resources for the path a base component named. */
function componentPathResources(
  key: KeyInfo | undefined,
  path: string | undefined,
  label: string,
): LogicSigResourceUsage {
  const profile = key?.logicSigResources;
  const selected = path === COMPONENT_PATH_SPEND ? profile?.spend
    : path === COMPONENT_PATH_SPENDING_REKEY ? profile?.spendingRekey
      : path === COMPONENT_PATH_LISTED_REKEY ? profile?.listedRekey
        : undefined;
  if (!selected) {
    throw new SignerError(`${label}: signer key publishes no LogicSig resources for path ${JSON.stringify(path)}`);
  }
  return { ...selected };
}

/** A prepared slot's SignRequest entry, with its index on any error. */
function preparedSignRequest(
  item: PreparedTransaction,
  index: number,
): ReturnType<typeof preparedTransactionToSignRequest> {
  try {
    return preparedTransactionToSignRequest(item);
  } catch (error) {
    if (error instanceof SignerError) {
      throw new SignerError(`prepared transaction ${index}: ${error.message}`);
    }
    throw error;
  }
}

/**
 * Normalize an index-keyed record into an integer-keyed Map.
 *
 * Object keys are strings at runtime, so a caller can supply a key that
 * `Number()` maps onto a plausible index while a numeric lookup never matches
 * it ("01", "1.0", " 1"), or one that yields NaN, which passes every
 * relational range check because NaN comparisons are all false. Either way the
 * entry would be dropped silently and the request would go out with no
 * declaration rather than an error. Only canonical decimal integer keys
 * within range are accepted.
 */
function normalizeIndexedRecord<T>(
  record: Record<number, T> | undefined,
  length: number,
  label: string,
): Map<number, T> {
  const normalized = new Map<number, T>();
  if (!record) return normalized;
  for (const [key, value] of Object.entries(record)) {
    const index = Number(key);
    if (!Number.isInteger(index) || String(index) !== key) {
      throw new SignerError(
        `${label} index ${JSON.stringify(key)} is not a canonical transaction index`,
      );
    }
    if (index < 0 || index >= length) {
      throw new SignerError(`${label} index ${index} out of range for ${length} transactions`);
    }
    normalized.set(index, value);
  }
  return normalized;
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

function validateAssemblyRequest(request: AssemblyRequest): void {
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
    if (!target.auth_address) {
      throw new SignerError(`target ${item}: auth_address is required`);
    }
    if (!target.cosigner_signature && target.cosigner_source_request_id) {
      throw new SignerError(`target ${item}: cosigner_source_request_id needs a cosigner_signature`);
    }
    if (target.kind === "bounded-cosigner") {
      if (!target.base_signatures?.length || !target.assembly_receipt) {
        throw new SignerError(`target ${item}: base_signatures and assembly_receipt are required for bounded-cosigner target`);
      }
      validateSignRequestId(target.base_source_request_id || "");
    } else {
      throw new SignerError(`target ${item}: invalid kind`);
    }
    validateSignRequestId(target.cosigner_source_request_id || "");
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

function validateAssemblyResponse(response: AssemblyResponse): void {
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
  private sshClosed = true;
  private server: net.Server | null = null;
  localPort: number = 0;

  async connect(options: {
    host: string;
    sshPort: number;
    privateKeyPath: string;
    remoteHost: string;
    remotePort: number;
    localPort: number;
    knownHostsPath: string;
    trustOnFirstUse: boolean;
    setupTimeout: number;
    signal?: AbortSignal;
  }): Promise<void> {
    if (!options.knownHostsPath) {
      throw new SignerError(
        "known_hosts path is required for SSH host key verification"
      );
    }

    // Dynamically import ssh2
    const { Client } = await import("ssh2");

    const privateKey = fs.readFileSync(options.privateKeyPath, "utf-8");
    this.localPort = options.localPort || await findFreePort();

    // Track host key error for meaningful rejection messages
    let hostKeyError = "";

    const connection = new Promise<void>((resolve, reject) => {
      this.sshClient = new Client();
      this.sshClosed = false;
      // ssh2 reports a peer that disconnects mid-handshake with close alone
      // and clears readyTimeout, so an unsettled setup must fail here.
      this.sshClient.once("close", () => {
        this.sshClosed = true;
        failSetup(new SignerUnavailableError(
          hostKeyError || "SSH connection closed before setup completed"
        ));
      });
      let settled = false;
      const cleanupSetup = () => {
        options.signal?.removeEventListener("abort", abortSetup);
      };
      const failSetup = (error: Error) => {
        if (settled) return;
        settled = true;
        cleanupSetup();
        this.server?.close();
        this.sshClosed = true;
        this.sshClient?.destroy();
        reject(error);
      };
      const abortSetup = () => {
        failSetup(new SignerUnavailableError("SSH setup canceled"));
      };
      if (options.signal?.aborted) {
        abortSetup();
        return;
      }
      options.signal?.addEventListener("abort", abortSetup, { once: true });

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
          if (settled) {
            this.server?.close();
            return;
          }
          settled = true;
          cleanupSetup();
          resolve();
        });

        this.server.on("error", (err) => {
          failSetup(new SignerUnavailableError(`SSH tunnel server error: ${err.message}`));
        });
      });

      this.sshClient.on("error", (err: Error) => {
        const msg = hostKeyError || sshConnectionFailedMessage(err);
        // A refused key under the client username is an authentication
        // failure (the key is not enrolled), not an unavailable signer.
        const notEnrolled = !hostKeyError &&
          (err as Error & { level?: string }).level === "client-authentication";
        failSetup(notEnrolled ? new AuthenticationError(msg) : new SignerUnavailableError(msg));
      });

      // The enrolled key is the only credential: public-key authentication
      // under the fixed client username, nothing else.
      this.sshClient.connect({
        host: options.host,
        port: options.sshPort,
        username: SSH_USERNAME,
        privateKey: privateKey,
        readyTimeout: options.setupTimeout,
        hostVerifier: (key: Buffer): boolean => {
          const storedKey = loadKnownHostKey(
            options.knownHostsPath, options.host, options.sshPort
          );

          if (storedKey === null) {
            if (!options.trustOnFirstUse) {
              hostKeyError =
                `Unknown SSH host key for ${formatHostEntry(options.host, options.sshPort)}; ` +
                `pass trustOnFirstUse: true for explicit first-use trust, ` +
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

    await connection;
  }

  async close(): Promise<void> {
    const server = this.server;
    const sshClient = this.sshClient;
    const sshClosed = this.sshClosed;
    this.server = null;
    this.sshClient = null;

    const closeServer = server
      ? new Promise<void>((resolve) => {
          server.close(() => resolve());
        })
      : Promise.resolve();
    const closeSSH = sshClient && !sshClosed
      ? new Promise<void>((resolve) => {
          sshClient.once("close", () => resolve());
          sshClient.end();
        })
      : Promise.resolve();

    await Promise.all([closeServer, closeSSH]);
  }
}

export interface CosignedSignTarget {
  targetIndex: number;
  cosignedAccount: string;
  cosignerPublicKeyHex?: string;
  cosignerComponentKeyType?: string;
  logicSigResources: LogicSigResourceUsage;
  appCallInfo?: AppCallInfo;
}

interface CosignedPrimarySignTarget {
  targetIndex: number;
  authAddress: string;
  txnSender?: string;
  lsigArgs?: Record<string, string>;
  appCallInfo?: { mode?: string; method?: string };
}

export interface CosignedCosignerResolution {
  client: SignerClient;
  componentKey?: string;
}

export type CosignedCosignerResolver = (
  target: CosignedSignTarget
) => CosignedCosignerResolution | Promise<CosignedCosignerResolution>;

export interface PreparedCosignedGroupOptions {
  userClient: SignerClient;
  preparedGroup: PreparedGroup;
  cosignerClient?: SignerClient;
  cosignerResolver?: CosignedCosignerResolver;
  cosignerComponentKey?: string;
  assemblyRequestId?: string;
  signal?: AbortSignal;
}

export interface CosignedSignResult {
  signedGroup: string[];
  cosignerComponentResponses: ComponentResponse[];
  primarySignResponse?: GroupSignResponse;
  boundedComponentResponse?: ComponentResponse;
  boundedAssemblyResponse?: AssemblyResponse;
  /**
   * The plan's mutation report, checked against the prepared group: what the
   * signer added to it (fees, group ID, dummies). Undefined when it changed
   * nothing.
   */
  planMutations?: MutationReport;
}

export interface CosignedSimulationResult {
  signing: CosignedSignResult;
  simulation: SimulationResult;
}

function extractAuthAddress(accountInfo: AccountInfoResult): string {
  if (!accountInfo) {
    return "";
  }
  if (typeof accountInfo === "string") {
    return accountInfo;
  }
  // algosdk v3 returns the auth address as an Address object, which never
  // compares equal to an address string; raw algod JSON carries a string.
  const info = accountInfo as {
    "auth-addr"?: AuthAddressValue | null;
    auth_addr?: AuthAddressValue | null;
    authAddr?: AuthAddressValue | null;
    authAddress?: AuthAddressValue | null;
  };
  const authAddress = info["auth-addr"] || info.auth_addr || info.authAddr || info.authAddress;
  if (authAddress) {
    return authAddress.toString();
  }
  // A lookup may return the auth address itself rather than account
  // information, and from algosdk that is an Address object too.
  const direct = String(accountInfo);
  return algosdk.isValidAddress(direct) ? direct : "";
}

function findSpendableKey(keys: KeyInfo[], address: string): KeyInfo | undefined {
  return keys.find((key) => (
    key.address === address && key.isSpendingAccount !== false
  ));
}

/** What a prepare helper reads before it builds: suggested parameters and the signer's keys. */
interface PrepParams {
  suggestedParams: any;
  /** Resolve the auth address from the keys read with the parameters. */
  resolve: (address: string, accountInfo: AccountInfoResult) => ResolvedAuthAddress;
}

/**
 * Refuse an address spelled other than canonically. algosdk reads the
 * spellings that differ only in the unused low bits of the last character as
 * the same address, and the Go SDK's decoder refuses them; the SDK compares
 * and looks addresses up as strings, so such a spelling could pass a check
 * the canonical one fails. A string that is not an address at all is left to
 * the check that already reports it.
 */
function requireCanonicalAddress(value: unknown, name: string): void {
  if (typeof value !== "string" || !algosdk.isValidAddress(value)) return;
  const canonical = algosdk.Address.fromString(value).toString();
  if (canonical !== value) {
    throw new SignerError(`${name} ${value} is not the canonical spelling of ${canonical}`);
  }
}

/** A send's result before signing fills it and submission settles its outcome. */
function emptySendResult(flow: string, originalCount: number): SendResult {
  return {
    flow,
    signedGroup: [],
    originalCount,
    txIds: [],
    groupId: "",
    fees: [],
    outcome: SEND_OUTCOME_SUBMITTED,
    confirmedRound: 0n,
  };
}

/**
 * Read a 200 answer of an approval-bearing request. A body that does not
 * parse, or parses to the wrong shape, is unreadable: the signer may have
 * acted, so it is marked as a lost answer.
 */
async function readApprovalAnswer<T>(response: Response, shape: AnswerShape): Promise<T> {
  let data: unknown;
  try {
    data = await response.json();
  } catch {
    throw markLostAnswer(new SignerError("Server returned invalid JSON"));
  }
  const problem = answerProblem(shape, data);
  if (problem) {
    throw markLostAnswer(new SignerError(`Server returned a malformed response: ${problem}`));
  }
  return data as T;
}

/** The stable signer error code an error carries, or "". */
function signerErrorCode(error: unknown): string {
  return error instanceof SignerError ? error.code : "";
}

/** Wait ms milliseconds, or until signal aborts. */
function sleepWithSignal(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(callerAborted());
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(callerAborted());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * The check that records what a position's sender can spend in ALGO. A
 * group's ALGO check reads it by this name and no other.
 */
const SPENDABLE_ALGO_CHECK = "spendable_algo";

function spendableAlgo(accountInfo: AccountInfoResult | Record<string, any>): bigint {
  const spendable = accountAmountBig(accountInfo) - accountMinBalanceBig(accountInfo);
  return spendable > 0n ? spendable : 0n;
}

function spendableAlgoCheck(accountInfo: AccountInfoResult | Record<string, any>): PreparedCheck {
  return {
    name: SPENDABLE_ALGO_CHECK,
    status: "ok",
    data: { available: spendableAlgo(accountInfo) },
  };
}

/**
 * Read a position's spendable_algo check. A position without one, or with a
 * value that is not a whole number, is an error: the group check never guesses
 * a balance and never skips a sender.
 */
function recordedSpendableAlgo(item: PreparedTransaction): bigint {
  const check = (item.checks || []).find((entry) => entry.name === SPENDABLE_ALGO_CHECK);
  if (!check) {
    throw new SignerError(`no ALGO balance on record (a ${SPENDABLE_ALGO_CHECK} check)`);
  }
  const data = check.data;
  if (!data || typeof data !== "object" || !Object.prototype.hasOwnProperty.call(data, "available")) {
    throw new SignerError(`the ${SPENDABLE_ALGO_CHECK} check has no available amount`);
  }
  return requireUint(data.available, `the ${SPENDABLE_ALGO_CHECK} check's available amount`);
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

// accountAmountBig / accountMinBalanceBig return microAlgo balances as bigint so
// sufficiency checks stay exact above 2^53 microAlgos, where Number() would lose
// precision. Account balances are integer microAlgos, so BigInt() is exact.
function accountAmountBig(accountInfo: AccountInfoResult | Record<string, any>): bigint {
  if (!accountInfo || typeof accountInfo === "string") {
    return 0n;
  }
  const raw = accountInfo as Record<string, any>;
  return BigInt(raw.amount ?? 0);
}

function accountMinBalanceBig(accountInfo: AccountInfoResult | Record<string, any>): bigint {
  if (!accountInfo || typeof accountInfo === "string") {
    return 0n;
  }
  const raw = accountInfo as Record<string, any>;
  return BigInt(raw["min-balance"] ?? raw.min_balance ?? raw.minBalance ?? 0);
}

function accountIncentiveEligible(accountInfo: AccountInfoResult | Record<string, any>): boolean {
  if (!accountInfo || typeof accountInfo === "string") {
    return false;
  }
  const raw = accountInfo as Record<string, any>;
  return Boolean(raw["incentive-eligible"] ?? raw.incentive_eligible ?? raw.incentiveEligible);
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

const UINT64_LIMIT = 1n << 64n;

/**
 * Require a whole number for an ID, an amount or a fee: a safe-integer number
 * or a bigint, below 2**64. algosdk and BigInt() would turn "123" into 123 and
 * throw an unrelated error on 123.9; a string, a fraction or a boolean is a
 * mistake in the caller, not a number to be converted.
 */
function requireUint(value: unknown, name: string, positive = false): bigint {
  const big = wholeNumber(value);
  if (big === undefined) {
    throw new SignerError(
      `${name} must be a whole number (a safe integer or a bigint), not ${
        typeof value === "number" ? value : typeof value
      }`,
    );
  }
  if (big < 0n || big >= UINT64_LIMIT || (positive && big === 0n)) {
    throw new SignerError(
      `${name} must be ${positive ? "a positive" : "a non-negative"} whole number below 2**64`,
    );
  }
  return big;
}

/**
 * Require the state schema counts and extra pages of an app create to be whole
 * numbers. One left undefined is unset and keeps algosdk's default, zero.
 */
function requireAppCreateCounts(params: {
  numLocalInts?: unknown;
  numLocalByteSlices?: unknown;
  numGlobalInts?: unknown;
  numGlobalByteSlices?: unknown;
  extraPages?: unknown;
}): void {
  for (const name of [
    "numLocalInts",
    "numLocalByteSlices",
    "numGlobalInts",
    "numGlobalByteSlices",
    "extraPages",
  ] as const) {
    if (params[name] !== undefined) {
      requireUint(params[name], name);
    }
  }
}

/** Require each box reference's app index to be a whole number. */
function requireBoxReferences(boxes: unknown): void {
  if (boxes === undefined || boxes === null) return;
  if (!Array.isArray(boxes)) {
    throw new SignerError("boxes must be an array of { appIndex, name }");
  }
  boxes.forEach((box, position) => {
    if (!box || typeof box !== "object") {
      throw new SignerError(`boxes[${position}] must be { appIndex, name }`);
    }
    requireUint((box as { appIndex?: unknown }).appIndex, `boxes[${position}].appIndex`);
  });
}

/** Require every app, asset and box reference of an app call to be a whole number. */
function requireAppReferences(params: {
  foreignApps?: unknown[];
  foreignAssets?: unknown[];
  boxes?: unknown;
}): void {
  (params.foreignApps ?? []).forEach((reference, position) =>
    requireUint(reference, `foreignApps[${position}]`, true));
  (params.foreignAssets ?? []).forEach((reference, position) =>
    requireUint(reference, `foreignAssets[${position}]`, true));
  requireBoxReferences(params.boxes);
}

function applyPrepFee(params: Record<string, any>, fee?: number): void {
  // No fee-per-byte mode: fee is always flat microAlgos, so a set fee can never
  // be silently reinterpreted as EstimateSize*fee. undefined means unset (keep
  // the suggested fee); an explicit number (including 0, used for fee pooling)
  // is applied as a flat fee.
  if (fee === undefined) {
    return;
  }
  requireUint(fee, "fee");
  params.fee = fee;
  params.flatFee = true;
  params.flat_fee = true;
}

function asaOptInChecks(
  accountInfo: AccountInfoResult | Record<string, any>,
  assetId: number | bigint,
  fee: number,
): PreparedCheck[] {
  if (accountAssetHolding(accountInfo, assetId)) {
    throw new SignerError(`sender is already opted into asset ${assetId}`);
  }
  if (accountAmountBig(accountInfo) < BigInt(fee)) {
    throw new SignerError(`insufficient funds for opt-in fee: balance ${accountAmountBig(accountInfo)}, fee ${fee}`);
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
  if (accountAmountBig(accountInfo) < BigInt(fee)) {
    throw new SignerError(`insufficient funds for close fee: balance ${accountAmountBig(accountInfo)}, fee ${fee}`);
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

// rekeyTargetFlowCheck refuses a rekey to a signer key whose signing flow
// cannot authorize another account. A rotating account's address is its
// stage 0 program, which authorizes only the account itself, and the signer
// refuses that rekey; any flow this SDK does not know is refused too, so a
// future flow fails closed here rather than at the signer.
function rekeyTargetFlowCheck(rekeyTo: string, flow: string | undefined): void {
  switch (flow ?? "") {
    case "":
    case SIGNING_FLOW_BOUNDED1:
    case SIGNING_FLOW_COSIGNED1:
      return;
    case SIGNING_FLOW_ROTATING1:
      throw new SignerError(`cannot rekey to ${rekeyTo}: it is a rotating account, and its address is a one-time stage key; an account rekeyed to it would be stuck on that stage, and every signature would reuse that key`);
    default:
      throw new SignerError(
        `cannot rekey to ${rekeyTo}: it uses signing flow "${flow}", which this SDK cannot use as another account's authorizer`,
      );
  }
}

// The protocol's minimum keyreg fee for an account to become eligible for
// consensus incentives: GoOnlineFee, 2 ALGO since consensus v40. The ledger
// grants eligibility only where payouts are enabled, as on MainNet, TestNet
// and a current LocalNet; algod doesn't report either value.
const INCENTIVE_ELIGIBILITY_FEE = 2_000_000n;

// isSetKeyregField treats undefined, null, 0 and an empty key as unset, the
// same as the Go SDK, which can't tell them apart.
function isSetKeyregField(value: unknown): boolean {
  if (value === undefined || value === null || value === "" || value === 0 || value === 0n) {
    return false;
  }
  return !(value instanceof Uint8Array && value.length === 0);
}

function validateKeyregParams(params: KeyregPrepParams): void {
  const mode: unknown = params.mode;
  if (mode === undefined || mode === null || mode === "") {
    throw new SignerError('mode is required: "online" or "offline"');
  }
  for (const [name, value] of [
    ["voteFirst", params.voteFirst],
    ["voteLast", params.voteLast],
    ["voteKeyDilution", params.voteKeyDilution],
  ] as [string, unknown][]) {
    if (value !== undefined && value !== null) {
      requireUint(value, name);
    }
  }
  if (mode === "offline") {
    if (params.incentiveEligible) {
      throw new SignerError("incentive eligibility needs an online keyreg");
    }
    const participationFields: [string, unknown][] = [
      ["voteKey", params.voteKey],
      ["selectionKey", params.selectionKey],
      ["stateProofKey", params.stateProofKey],
      ["voteFirst", params.voteFirst],
      ["voteLast", params.voteLast],
      ["voteKeyDilution", params.voteKeyDilution],
    ];
    for (const [name, value] of participationFields) {
      if (isSetKeyregField(value)) {
        throw new SignerError(
          `an offline keyreg takes no participation keys or vote rounds, but ${name} is set`,
        );
      }
    }
    return;
  }
  if (mode !== "online") {
    throw new SignerError(`mode ${JSON.stringify(mode)} is not "online" or "offline"`);
  }
  if (!params.voteKey) {
    throw new SignerError("voteKey is required");
  }
  if (!params.selectionKey) {
    throw new SignerError("selectionKey is required");
  }
  // The network refuses an online keyreg without a state proof key.
  if (!params.stateProofKey) {
    throw new SignerError("stateProofKey is required");
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

/**
 * Check each sender can cover everything it pays across the group. A sender's
 * total is the ALGO it sends plus the fee of every position it sends,
 * whatever the position's kind: an asset transfer moves no ALGO but still
 * pays a fee. The total is checked against the sender's spendable ALGO, which
 * each position records in its spendable_algo check. A position without that
 * record is refused.
 */
function validateGroupAlgoBalance(transactions: PreparedTransaction[]): PreparedCheck {
  const totals = new Map<string, { available?: bigint; required: bigint }>();
  transactions.forEach((item, index) => {
    if (!item.transaction) {
      throw new SignerError("group transaction is required");
    }
    const txn = item.transaction as any;
    const sender = txn.sender.toString();
    const total: { available?: bigint; required: bigint } =
      totals.get(sender) || { required: 0n };
    total.required += BigInt(txn.payment?.amount || 0) + BigInt(txn.fee || 0);
    try {
      // The lowest value recorded for the sender: each position read the
      // balance on its own, and the check must not depend on their order.
      const available = recordedSpendableAlgo(item);
      if (total.available === undefined || available < total.available) {
        total.available = available;
      }
    } catch (error) {
      throw new SignerError(
        `group transaction ${index}, sender ${sender}: ${(error as Error).message}`,
      );
    }
    totals.set(sender, total);
  });
  for (const [sender, total] of totals) {
    if ((total.available ?? 0n) < total.required) {
      throw new SignerError(
        `group insufficient funds for ${sender}: available ${total.available}, required ${total.required}`,
      );
    }
  }
  return {
    name: "group_algo_balance",
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
        const refAppId = requireUint(values[index], "application argument", true);
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
        const assetId = requireUint(values[index], "asset argument", true);
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
 * // SSH tunnel connection, authenticated by the enrolled client key
 * const client = await SignerClient.connectSsh(
 *   "signer.example.com",
 *   "~/aplane/apclient/.ssh/id_ed25519",
 *   { knownHostsPath: "~/aplane/apclient/.ssh/known_hosts" }
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
export class SignerClient {
  private baseUrl: string;
  private explicitTimeout?: number;
  private keyCache: Map<string, KeyInfo> = new Map();
  private keyCacheRevision?: number;
  private tunnel: SSHTunnel | null = null;
  private approvalWaitSeconds?: number;
  private approvalWaitFetchedAt?: number;
  private approvalWaitKnown = false;
  private feeCeiling?: number | bigint;

  /**
   * Create a SignerClient instance.
   *
   * baseUrl is an internal HTTP endpoint: the local end of an SSH tunnel to
   * the signer, which authenticates the tunnel by the client's enrolled key.
   * The client itself carries no credential. Prefer static methods
   * (connectSsh, fromEnv) so connection details come from explicit SSH
   * parameters or APCLIENT_DATA-derived config.
   */
  constructor(
    baseUrl: string,
    timeout?: number,
    tunnel: SSHTunnel | null = null,
    options?: SignerClientOptions | null,
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.explicitTimeout = timeout && timeout > 0 ? timeout : undefined;
    this.tunnel = tunnel;
    // A bare number here would otherwise be read as an options object with no
    // ceiling in it.
    if (options !== undefined && options !== null && typeof options !== "object") {
      throw new SignerError(
        "SignerClient options must be an object, such as { maxFeeIncrease: 200_000 }",
      );
    }
    this.feeCeiling = checkMaxFeeIncrease(options?.maxFeeIncrease);
  }

  /**
   * The ceiling, in microAlgos, on the total fee the signer may add to a
   * request, as it was set, or undefined when none is set. Assigning
   * validates the value; undefined removes the ceiling and zero means the
   * signer may not raise any fee. See SignerClientOptions.
   */
  get maxFeeIncrease(): number | bigint | undefined {
    return this.feeCeiling;
  }

  set maxFeeIncrease(microAlgos: number | bigint | undefined) {
    this.feeCeiling = checkMaxFeeIncrease(microAlgos);
  }

  /**
   * The ceiling a call starting now is held to. A call reads it before
   * sending its request, so a change made while the signer waits for approval
   * does not apply to it.
   */
  private feeCeilingSnapshot(): bigint | undefined {
    return this.feeCeiling === undefined ? undefined : BigInt(this.feeCeiling);
  }

  /**
   * Connect to remote apsigner via SSH tunnel.
   *
   * Establishes an SSH tunnel to the remote host and forwards the signer's
   * REST listener to a local port. The enrolled client key is the only
   * credential; a key the signer has not enrolled fails the handshake
   * (enroll it with requestEnrollment first).
   *
   * @param host - Remote host running apsigner
   * @param sshKeyPath - Path to SSH private key (e.g., ~/aplane/apclient/.ssh/id_ed25519)
   * @param options - Connection options
   * @returns Promise<SignerClient> instance with active SSH tunnel
   *
   * @example
   * ```typescript
   * const client = await SignerClient.connectSsh(
   *   "signer.example.com",
   *   "~/aplane/apclient/.ssh/id_ed25519",
   *   { knownHostsPath: "~/aplane/apclient/.ssh/known_hosts" }
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
    sshKeyPath: string,
    options: ConnectSshOptions = {}
  ): Promise<SignerClient> {
    const maxFeeIncrease = checkMaxFeeIncrease(options.maxFeeIncrease);
    const sshPort = options.sshPort ?? DEFAULT_SSH_PORT;
    const localPort = options.localPort ?? 0;
    const timeout = options.timeout;
    const sshSetupTimeout = normalizeSSHSetupTimeout(options.sshSetupTimeout);
    const knownHostsPath = options.knownHostsPath
      ? expandPath(options.knownHostsPath)
      : "";
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
      await tunnel.connect({
        host,
        sshPort,
        privateKeyPath: expandedKeyPath,
        // The server checks only that the destination is loopback and
        // forwards to its own REST listener, so the port is nominal.
        remoteHost: "127.0.0.1",
        remotePort: 11270,
        localPort,
        knownHostsPath,
        trustOnFirstUse,
        setupTimeout: sshSetupTimeout,
        signal: options.signal,
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
    const client = new SignerClient(baseUrl, timeout, tunnel, { maxFeeIncrease });

    // Verify connection
    const healthy = await client.health();
    if (!healthy) {
      await client.close();
      throw new SignerUnavailableError(
        "Connected via SSH but signer not responding"
      );
    }

    return client;
  }

  /**
   * Connect using the endpoint registry from a data directory.
   *
   * Data directory contents:
   *   - endpoints.yaml: Signer and cosigner routing
   *   - .ssh/id_ed25519: SSH key, the client's credential
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

    loadConfig(dataDir);
    const registry = loadClientEndpointRegistry(dataDir);
    const { endpoint } = resolveClientEndpoint(registry, options.endpoint);

    const { host, port: sshPort } = clientEndpointSshHostPort(endpoint);
    if (!fs.existsSync(endpoint.identityFile)) {
      throw new SignerError(
        `SSH key not found at ${endpoint.identityFile}`,
      );
    }
    return SignerClient.connectSsh(host, endpoint.identityFile, {
      sshPort,
      timeout,
      sshSetupTimeout: options.sshSetupTimeout,
      signal: options.signal,
      knownHostsPath: endpoint.knownHostsPath,
      trustOnFirstUse: options.trustOnFirstUse ?? false,
      maxFeeIncrease: options.maxFeeIncrease,
    });
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
    const rawProtocolVersion = data.protocol_version as Record<string, unknown> | undefined;
    const status: StatusResponse = {
      nodeRole: typeof data.node_role === "string" ? data.node_role : undefined,
      protocolVersion:
        rawProtocolVersion && typeof rawProtocolVersion === "object"
          ? {
              major: Number(rawProtocolVersion.major || 0),
              minor: Number(rawProtocolVersion.minor || 0),
            }
          : undefined,
      buildVersion: typeof data.build_version === "string" ? data.build_version : undefined,
      state: String(data.state || ""),
      signerLocked: Boolean(data.signer_locked),
      readyForSigning: Boolean(data.ready_for_signing),
      keyCount: Number(data.key_count || 0),
      keysetRevision: Number(data.keyset_revision || 0),
      approvalWaitSeconds:
        typeof data.approval_wait_seconds === "number" ? data.approval_wait_seconds : undefined,
      warnings: Array.isArray(data.warnings)
        ? data.warnings.filter((warning): warning is string => typeof warning === "string")
        : undefined,
      notes: Array.isArray(data.notes)
        ? data.notes.filter((note): note is string => typeof note === "string")
        : undefined,
      rotating: Array.isArray(data.rotating)
        ? (data.rotating.filter(
            (entry): entry is RotatingAccountStatus =>
              typeof entry === "object" && entry !== null && typeof (entry as RotatingAccountStatus).account === "string",
          ) as RotatingAccountStatus[])
        : undefined,
    };
    this.cacheApprovalWait(status.approvalWaitSeconds);
    return status;
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
      const rawArgs = (k as any).signing_args;
      if (rawArgs) {
        signingArgs = rawArgs.map((arg: any) => ({
          name: arg.name,
          type: arg.type || "bytes",
          description: arg.description || "",
          label: arg.label,
          required: arg.required,
          byteLength: arg.byte_length,
          maxSize: arg.max_size,
        }));
      }

      // Map snake_case API fields to camelCase TypeScript interface
      const raw = k as any;
      const keyInfo: KeyInfo = {
        address: k.address,
        publicKeyHex: raw.public_key_hex || "",
        keyType: raw.key_type || "",
        authorizationKind: raw.authorization_kind || undefined,
        signingFlow: raw.signing_flow || undefined,
        cosignerComponentKeyType: raw.cosigner_component_key_type || undefined,
        logicSigResources: mapLogicSigResourceProfile(raw.logic_sig_resources),
        isGenericLsig: raw.is_generic_lsig || false,
        isWitnessKey: raw.is_witness_key || false,
        isSpendingAccount: typeof raw.is_spending_account === "boolean" ? raw.is_spending_account : undefined,
        boundedAuthorization: mapBoundedAuthorization(raw.bounded_authorization),
        signingArgs,
        parameters: raw.parameters,
        templateProvenanceStatus: raw.template_provenance_status || undefined,
        templateProvenanceNote: raw.template_provenance_note || undefined,
      };
      keys.push(keyInfo);
      // One record per address. Should the signer list an address twice, the
      // first spendable row is the one kept, the row findSpendableKey picks
      // from the list itself, so a lookup answers the same from a fresh list
      // and from the cache.
      const kept = this.keyCache.get(keyInfo.address);
      if (kept && (kept.isSpendingAccount !== false || keyInfo.isSpendingAccount === false)) {
        continue;
      }
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
   *
   * A rotating account is authorized by its current stage, which the signer
   * derives from the account's key and never lists; the signer holds the
   * account itself and signs for it at any stage, so its authAddress is the
   * account and chainAuthAddress the stage's address. A rotating account
   * rekeyed to an ordinary key the signer holds has left rotation, and that
   * key signs for it like any rekey.
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
    return this.resolveFromAccountInfo(address, accountInfo, await this.listKeysIfKeysetChanged());
  }

  /** resolveAuthAddress, from account information and a key listing already read. */
  private resolveFromAccountInfo(
    address: string,
    accountInfo: AccountInfoResult,
    keys: KeyInfo[],
  ): ResolvedAuthAddress {
    const authAddress = extractAuthAddress(accountInfo);
    const signingAddress =
      authAddress && authAddress !== address ? authAddress : address;

    const own = findSpendableKey(keys, address);
    const leftRotation = signingAddress !== address && findSpendableKey(keys, signingAddress) !== undefined;
    if (own?.signingFlow === SIGNING_FLOW_ROTATING1 && !leftRotation) {
      return {
        address,
        authAddress: address,
        isRekeyed: false,
        chainAuthAddress: authAddress && authAddress !== address ? authAddress : "",
        keyInfo: own,
      };
    }

    const keyInfo = findSpendableKey(keys, signingAddress);
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
      chainAuthAddress: signingAddress !== address ? signingAddress : "",
      keyInfo,
    };
  }

  /**
   * Fetch suggested parameters for a transaction sender is about to send.
   * For a rotating account it shortens the validity window to what the
   * account's stage program accepts, so every prepare helper builds a
   * transaction a rotating account can send.
   *
   * It reads the signer's keys once for the helper: the same listing
   * resolves the sender's auth address afterwards. A signer that cannot be
   * asked is not reported here; resolution reports that failure in its
   * usual form, where it always has.
   */
  private async prepSuggestedParams(algodClient: any, sender: string): Promise<PrepParams> {
    // The sender is looked up as a string, for the rotating check and for
    // resolution: it must be the spelling the signer lists.
    requireCanonicalAddress(sender, "sender");
    const suggestedParams = await algodClient.getTransactionParams().do();
    let keys: KeyInfo[] | undefined;
    let keysError: unknown;
    try {
      keys = await this.listKeysIfKeysetChanged();
    } catch (error) {
      keysError = error;
    }
    const own = keys && sender ? findSpendableKey(keys, sender) : undefined;
    if (own?.signingFlow === SIGNING_FLOW_ROTATING1) {
      const first = wholeNumber(suggestedParams.firstValid);
      const last = wholeNumber(suggestedParams.lastValid);
      if (first !== undefined && last !== undefined && last - first > BigInt(ROTATING_MAX_VALIDITY_WINDOW)) {
        suggestedParams.lastValid = first + BigInt(ROTATING_MAX_VALIDITY_WINDOW);
      }
    }
    return {
      suggestedParams,
      resolve: (address: string, accountInfo: AccountInfoResult) => {
        if (!keys) throw keysError;
        return this.resolveFromAccountInfo(address, accountInfo, keys);
      },
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
    requireCanonicalAddress(params.receiver, "receiver");
    requireUint(params.amount, "amount");

    const { suggestedParams, resolve } = await this.prepSuggestedParams(algodClient, params.sender);
    applyPrepFee(suggestedParams, params.fee);

    const senderInfo = await algodClient.accountInformation(params.sender).do();
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: params.sender,
      receiver: params.receiver,
      amount: params.amount,
      note: params.note,
      suggestedParams,
    });

    const fee = BigInt((txn as any).fee ?? 0);
    const available = accountAmountBig(senderInfo) - accountMinBalanceBig(senderInfo);
    const required = BigInt(params.amount) + fee;
    if (available < required) {
      throw new SignerError(`insufficient funds: available ${available}, required ${required}`);
    }

    const resolved = resolve(params.sender, senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
      checks: [{
        name: "payment_balance",
        status: "ok",
        data: {
          amount: params.amount,
          fee,
          available,
        },
      }, spendableAlgoCheck(senderInfo)],
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
    requireCanonicalAddress(params.receiver, "receiver");
    if (params.assetId === undefined || params.assetId === null) {
      throw new SignerError("assetId is required");
    }
    requireUint(params.assetId, "assetId", true);
    requireUint(params.amount, "amount");

    const { suggestedParams, resolve } = await this.prepSuggestedParams(algodClient, params.sender);
    applyPrepFee(suggestedParams, params.fee);

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

    // An asset transfer moves no ALGO but pays its fee from the sender's.
    const fee = BigInt((txn as any).fee ?? 0);
    const available = spendableAlgo(senderInfo);
    if (available < fee) {
      throw new SignerError(
        `insufficient funds for asset transfer fee: available ${available}, fee ${fee}`,
      );
    }

    const resolved = resolve(params.sender, senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
      checks: [{
        name: "asa_transfer",
        status: "ok",
        data: {
          assetId: params.assetId,
          amount: params.amount,
          balance: senderAmount,
          fee,
        },
      }, spendableAlgoCheck(senderInfo)],
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
    if (params.assetId === undefined || params.assetId === null) {
      throw new SignerError("assetId is required");
    }
    requireUint(params.assetId, "assetId", true);

    const { suggestedParams, resolve } = await this.prepSuggestedParams(algodClient, params.sender);
    applyPrepFee(suggestedParams, params.fee);

    const senderInfo = await algodClient.accountInformation(params.sender).do();
    const txn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
      sender: params.sender,
      receiver: params.sender,
      amount: 0,
      assetIndex: params.assetId,
      note: params.note,
      suggestedParams,
    });
    // The balance is checked against the fee the built transaction pays. The
    // suggested fee is per byte, usually zero, and would check nothing.
    const checks = asaOptInChecks(senderInfo, params.assetId, Number(txn.fee));

    const resolved = resolve(params.sender, senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
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
    // Compared as a string: an alternate spelling of the sender would pass.
    requireCanonicalAddress(params.closeTo, "closeTo");
    requireCanonicalAddress(params.sender, "sender");
    if (params.closeTo === params.sender) {
      throw new SignerError("closeTo must differ from sender");
    }
    if (params.assetId === undefined || params.assetId === null) {
      throw new SignerError("assetId is required");
    }
    requireUint(params.assetId, "assetId", true);

    const { suggestedParams, resolve } = await this.prepSuggestedParams(algodClient, params.sender);
    applyPrepFee(suggestedParams, params.fee);

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

    const resolved = resolve(params.sender, senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
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
    // Compared as a string: an alternate spelling of the sender would pass.
    requireCanonicalAddress(params.closeTo, "closeTo");
    requireCanonicalAddress(params.sender, "sender");
    if (params.closeTo === params.sender) {
      throw new SignerError("closeTo must differ from sender");
    }

    const { suggestedParams, resolve } = await this.prepSuggestedParams(algodClient, params.sender);
    applyPrepFee(suggestedParams, params.fee);

    const senderInfo = await algodClient.accountInformation(params.sender).do();
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: params.sender,
      receiver: params.closeTo,
      amount: 0,
      closeRemainderTo: params.closeTo,
      note: params.note,
      suggestedParams,
    });
    // Checked against the fee the built transaction pays, not the suggested
    // per-byte fee.
    const checks = accountCloseChecks(senderInfo, Number(txn.fee));

    const resolved = resolve(params.sender, senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
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
    // Compared with the sender and looked up among the signer's keys as a
    // string: an alternate spelling of a rotating account would skip the
    // check that refuses a rekey to one.
    requireCanonicalAddress(params.rekeyTo, "rekeyTo");

    const { suggestedParams, resolve } = await this.prepSuggestedParams(algodClient, params.sender);
    applyPrepFee(suggestedParams, params.fee);

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

    const resolved = resolve(params.sender, senderInfo);
    // Resolution just refreshed the inventory, so the cache answers for the
    // target without another round trip.
    const target = params.rekeyTo === params.sender ? undefined : this.keyCache.get(params.rekeyTo);
    if (target) {
      rekeyTargetFlowCheck(params.rekeyTo, target.signingFlow);
    }
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
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

    const { suggestedParams, resolve } = await this.prepSuggestedParams(algodClient, params.sender);
    applyPrepFee(suggestedParams, params.fee);

    const senderInfo = await algodClient.accountInformation(params.sender).do();
    // An offline registration is a keyless one; nonParticipation is never set.
    const txn = algosdk.makeKeyRegistrationTxnWithSuggestedParamsFromObject(
      params.mode === "offline"
        ? { sender: params.sender, note: params.note, suggestedParams }
        : {
          sender: params.sender,
          voteKey: params.voteKey,
          selectionKey: params.selectionKey,
          stateProofKey: params.stateProofKey,
          voteFirst: params.voteFirst,
          voteLast: params.voteLast,
          voteKeyDilution: params.voteKeyDilution,
          note: params.note,
          suggestedParams,
        },
    );
    const chargeIncentiveFee = Boolean(params.incentiveEligible) && !accountIncentiveEligible(senderInfo);
    if (chargeIncentiveFee && txn.fee < INCENTIVE_ELIGIBILITY_FEE) {
      if (params.fee !== undefined) {
        throw new SignerError(
          `incentive eligibility needs a keyreg fee of at least ${INCENTIVE_ELIGIBILITY_FEE} microAlgos, but fee is set to ${params.fee}`,
        );
      }
      txn.fee = INCENTIVE_ELIGIBILITY_FEE;
    }
    const available = accountAmountBig(senderInfo) > accountMinBalanceBig(senderInfo)
      ? accountAmountBig(senderInfo) - accountMinBalanceBig(senderInfo)
      : 0n;
    if (available < txn.fee) {
      throw new SignerError(`insufficient funds for keyreg fee: available ${available}, fee ${txn.fee}`);
    }

    const resolved = resolve(params.sender, senderInfo);
    let message: string | undefined;
    if (chargeIncentiveFee) {
      message = "the 2 ALGO incentive eligibility fee is included";
    } else if (params.incentiveEligible) {
      message = "the account is already incentive eligible and stays eligible, so no 2 ALGO fee is added";
    }
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
      checks: [{
        name: "keyreg",
        status: "ok",
        ...(message ? { message } : {}),
        data: params.mode === "offline"
          ? { mode: "offline" }
          : {
            mode: "online",
            voteFirst: params.voteFirst || 0,
            voteLast: params.voteLast || 0,
            voteKeyDilution: params.voteKeyDilution || 0,
            incentiveEligible: Boolean(params.incentiveEligible),
            incentiveFeeCharged: chargeIncentiveFee,
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
    // Checked before the arguments are encoded, so a bad ID is reported as
    // one and never reaches BigInt() or the encoder.
    if (params.appId === undefined || params.appId === null) {
      throw new SignerError("appId is required");
    }
    requireUint(params.appId, "appId", true);
    requireAppReferences(params);
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
    if (params.appId === undefined || params.appId === null) {
      throw new SignerError("appId is required");
    }
    requireUint(params.appId, "appId", true);
    requireAppReferences(params);
    requireAppCreateCounts(params);
    const onComplete = params.onComplete ?? algosdk.OnApplicationComplete.NoOpOC;
    if (!Number.isInteger(onComplete) || onComplete < 0 || onComplete > algosdk.OnApplicationComplete.DeleteApplicationOC) {
      throw new SignerError(`invalid onComplete: ${onComplete}`);
    }

    const { suggestedParams, resolve } = await this.prepSuggestedParams(algodClient, params.sender);
    applyPrepFee(suggestedParams, params.fee);

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

    const resolved = resolve(params.sender, senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
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
    requireAppCreateCounts(params);
    requireAppReferences(params);

    const { suggestedParams, resolve } = await this.prepSuggestedParams(algodClient, params.sender);
    applyPrepFee(suggestedParams, params.fee);

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

    const resolved = resolve(params.sender, senderInfo);
    return {
      transaction: txn,
      authAddress: resolved.authAddress,
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
    checks.push(validateGroupAlgoBalance(transactions));
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
      }, validateGroupAlgoBalance(transactions)],
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
      }, validateAsaTransferGroup(transactions), validateGroupAlgoBalance(transactions)],
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

    for (const kt of (data as any).key_types || []) {
      let creationParams: CreationParam[] | undefined;
      if (kt.creation_params) {
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
        runtimeArgs = kt.runtime_args.map((arg: any) => ({
          name: arg.name,
          type: arg.type || "bytes",
          description: arg.description || "",
          label: arg.label,
          required: arg.required,
          byteLength: arg.byte_length,
          maxSize: arg.max_size,
        }));
      }

      result.push({
        keyType: kt.key_type,
        family: kt.family || "",
        displayName: kt.display_name,
        description: kt.description,
        authorizationKind: kt.authorization_kind,
        requiresLogicsig: kt.requires_logicsig,
        mnemonicWordCount: kt.mnemonic_word_count,
        mnemonicImport: kt.mnemonic_import,
        mnemonicScheme: kt.mnemonic_scheme,
        signingFlow: kt.signing_flow || undefined,
        cosignerComponentKeyType: kt.cosigner_component_key_type || undefined,
        perKeyContract: kt.per_key_contract || undefined,
        boundarySchema: kt.boundary_schema || undefined,
        boundedAuthorization: mapBoundedAuthorization(kt.bounded_authorization),
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
      isWitnessKey: Boolean(data.is_witness_key),
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

  async requestComponents(
    request: ComponentRequest,
    options?: { signal?: AbortSignal },
  ): Promise<ComponentResponse> {
    const requestBody: ComponentRequest = {
      ...request,
      request_id: request.request_id || newSignRequestId(),
    };
    try {
      validateComponentRequest(requestBody);
    } catch (error) {
      throw new SignerError(`invalid component request: ${error instanceof Error ? error.message : String(error)}`);
    }
    const approvalBearing = requestBody.targets[0].kind !== "cosigner";
    let timeout = this.timeoutFor(COMPONENT_SIGN_TIMEOUT);
    if (approvalBearing) {
      await this.discoverApprovalWait();
      timeout = Math.max(timeout, this.signRequestTimeout());
    }
    let response: Response;
    try {
      response = await this.fetch("/sign/component", {
        method: "POST",
        body: JSON.stringify(requestBody),
        timeout,
        signal: options?.signal,
      });
    } catch (error) {
      if (approvalBearing) await this.bestEffortCancelSignRequest(requestBody.request_id || "");
      // A component request releases a signature: one whose answer never
      // arrived may have released it.
      throw markLostAnswer(error);
    }
    if (response.status === 401) throw new AuthenticationError();
    if (response.status === 403) throw await this.forbiddenRejectedError(response, "Component signing request rejected");
    if (response.status === 503) throw new SignerUnavailableError(await this.errorMessage(response, "Signer unavailable"));
    if (response.status === 400) throw await this.badRequestError(response);
    if (response.status !== 200) throw await this.signerHTTPError(response, `Component signing failed: HTTP ${response.status}`);
    const data = await readApprovalAnswer<ComponentResponse & { error?: string }>(response, COMPONENT_ANSWER);
    if (data.error) throw new SignerError(data.error);
    try {
      validateComponentResponse(data, requestBody);
    } catch (error) {
      throw new SignerError(
        `invalid component response: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (data.request_id !== requestBody.request_id) throw new SignerError("component response request_id does not match request");
    const expected = new Map(requestBody.targets.map((target) => [target.target_index, target.kind]));
    const actual = new Map(data.components.map((component) => [component.target_index, component.kind]));
    if (expected.size !== actual.size || [...expected].some(([index, kind]) => actual.get(index) !== kind)) {
      throw new SignerError("component response target indices or kinds do not match request");
    }
    return data;
  }

  async requestAssemble(
    request: AssemblyRequest,
    options?: { signal?: AbortSignal },
  ): Promise<AssemblyResponse> {
    const requestBody: AssemblyRequest = {
      ...request,
      request_id: request.request_id || newSignRequestId(),
      passthrough: request.passthrough?.map(({ target_index, signed_txn_hex }) => ({
        target_index,
        signed_txn_hex,
      })),
    };
    try {
      validateAssemblyRequest(requestBody);
    } catch (error) {
      throw new SignerError(
        `invalid assembly request: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    let response: Response;
    try {
      response = await this.fetch("/sign/assemble", {
        method: "POST",
        body: JSON.stringify(requestBody),
        timeout: this.timeoutFor(COSIGNED_ASSEMBLY_TIMEOUT),
        signal: options?.signal,
      });
    } catch (error) {
      // Assembly releases the whole group: an answer that never arrived may
      // have released it.
      throw markLostAnswer(error);
    }

    if (response.status === 401) {
      throw new AuthenticationError();
    }

    if (response.status === 403) {
      throw await this.forbiddenRejectedError(response, "Assembly request rejected");
    }

    if (response.status === 503) {
      throw new SignerUnavailableError(await this.errorMessage(response, "Signer unavailable"));
    }

    if (response.status !== 200) {
      throw await this.signerHTTPError(response, `Assembly failed: HTTP ${response.status}`);
    }

    const data = await readApprovalAnswer<AssemblyResponse & { error?: string }>(response, ASSEMBLY_ANSWER);

    if (data.error) {
      throw new SignerError(data.error);
    }

    try {
      validateAssemblyResponse(data);
      // The answer must be to this request, not merely carry a well-formed ID.
      if (data.request_id !== requestBody.request_id) {
        throw new SignerError(
          `request_id ${JSON.stringify(data.request_id)} does not match the request's ${JSON.stringify(requestBody.request_id)}`,
        );
      }
    } catch (error) {
      throw new SignerError(
        `invalid assembly response: ${error instanceof Error ? error.message : String(error)}`
      );
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
   * @param lsigResources - Optional mapping of group index to independent LogicSig resource demand
   * @returns PlanGroupResponse with transactions and mutations
   */
  async planGroup(
    txns: (Transaction | null)[],
    authAddresses?: (string | null)[],
    lsigArgsMap?: LsigArgsMap,
    passthrough?: Record<number, string>,
    lsigResources?: Record<number, LogicSigResourceUsage>,
  ): Promise<PlanGroupResponse> {
    const authAddrs = authAddresses ?? txns.map((txn) => txn?.sender?.toString() ?? null);

    if (authAddrs.length !== txns.length) {
      throw new SignerError("authAddresses length must match txns length");
    }

    const requestBody = this.buildSignRequestBody(
      txns, authAddrs, lsigArgsMap, passthrough, lsigResources,
    );

    return this.planRequests(requestBody.requests);
  }

  /**
   * Preview raw per-slot signer requests without rebuilding them through the
   * address-keyed convenience API.
   */
  async planRequests(requests: SignRequest[]): Promise<PlanGroupResponse> {
    validateSignRequests(requests);
    // The slots the plan is checked against are decoded here, from the very
    // entries that are sent.
    const slots = decodeRequestSlots(requests);
    const maxFeeIncrease = this.feeCeilingSnapshot();

    const response = await this.fetch("/plan", {
      method: "POST",
      body: JSON.stringify({ requests }),
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
        mutations: normalizeMutationReport(data.mutations),
      };
    }

    try {
      validatePlanResponse(slots, data.transactions, data.mutations, maxFeeIncrease);
    } catch (error) {
      throw verificationError("verify signer plan: ", error);
    }

    return data;
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
    const auth = authAddress || txn.sender.toString();
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
   * @param lsigResources - Optional mapping of group index to independent LogicSig resource demand
   * @returns Base64-encoded concatenated signed transactions for the entire group
   */
  async signTransactions(
    txns: (Transaction | null)[],
    authAddresses?: (string | null)[],
    lsigArgsMap?: LsigArgsMap,
    passthrough?: Record<number, string>,
    lsigResources?: Record<number, LogicSigResourceUsage>,
    options?: SignOptions,
  ): Promise<string> {
    const authAddrs =
      authAddresses ?? txns.map((txn) => txn?.sender?.toString() ?? null);

    if (authAddrs.length !== txns.length) {
      throw new SignerError("authAddresses length must match txns length");
    }

    const signedList = await this.signRequest(
      txns, authAddrs, lsigArgsMap, passthrough, lsigResources, options,
    );

    // Reject if any foreign (empty) slots exist
    if (signedList.some((s) => s === "")) {
      throw new SignerError(
        "signTransactions() cannot produce a complete group when foreign " +
        "entries are present (some slots are unsigned). Plan the group with " +
        "planGroup(), have the other party sign its transaction, then sign " +
        "with that signed transaction as a passthrough position."
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
   * @param lsigResources - Optional mapping of group index to independent LogicSig resource demand
   * @returns List of base64-encoded signed transactions
   */
  async signTransactionsList(
    txns: (Transaction | null)[],
    authAddresses?: (string | null)[],
    lsigArgsMap?: LsigArgsMap,
    passthrough?: Record<number, string>,
    lsigResources?: Record<number, LogicSigResourceUsage>,
    options?: SignOptions,
  ): Promise<string[]> {
    const authAddrs =
      authAddresses ?? txns.map((txn) => txn?.sender?.toString() ?? null);

    if (authAddrs.length !== txns.length) {
      throw new SignerError("authAddresses length must match txns length");
    }

    const signedHexes = await this.signRequest(
      txns, authAddrs, lsigArgsMap, passthrough, lsigResources, options,
    );

    // Convert each hex to base64 (empty strings stay empty for foreign entries)
    return signedHexes.map((hex) => {
      if (hex === "") return "";
      return bytesToBase64(hexToBytes(hex));
    });
  }

  /**
   * Send raw signing request entries to /sign.
   *
   * Higher-level helpers build these entries from algosdk transactions;
   * integrations can use this method directly when they already own
   * transaction encoding. The mutation report is returned in its typed
   * camelCase form.
   */
  async signRequests(
    requests: SignRequest[],
    options?: SignOptions,
  ): Promise<GroupSignResponse> {
    const requestId = options?.requestId ?? newSignRequestId();
    validateSignRequestId(requestId, true);
    validateSignRequests(requests);
    // The slots the response is checked against are decoded here, from the
    // very entries that are sent.
    const slots = decodeRequestSlots(requests);
    const maxFeeIncrease = this.feeCeilingSnapshot();
    const signBody: GroupSignRequest = { request_id: requestId, requests };

    const data = await this.postApproval<GroupSignResponse>(
      "/sign",
      requestId,
      JSON.stringify(signBody),
      options?.signal,
      GROUP_SIGN_ANSWER,
      async (response) => {
        if (response.status === 401) {
          return new AuthenticationError();
        }
        if (response.status === 400) {
          return this.badRequestError(response);
        }
        if (response.status === 403) {
          return this.forbiddenRejectedError(response, "Signing request rejected by operator");
        }
        if (response.status === 503) {
          return new SignerUnavailableError(await this.errorMessage(response, "Signer unavailable"));
        }
        return this.signerHTTPError(response, `Signing failed: HTTP ${response.status}`);
      },
    );

    if (data.error) {
      throw new SignerError(data.error);
    }

    // The wire report is snake_case; callers read the typed camelCase fields.
    const result: GroupSignResponse = data.mutations
      ? { ...data, mutations: normalizeMutationReport(data.mutations) }
      : data;

    // Every sign path goes through here, so a truncated, altered or padded
    // group can never be returned for submission or simulation.
    try {
      validateSignResponse(slots, result.signed ?? [], result.mutations, maxFeeIncrease);
    } catch (error) {
      throw verificationError("verify signer response: ", error);
    }

    return result;
  }

  /**
   * Post an approval-bearing request and return its 200 answer, parsed. It
   * waits as long as the signer's approval wait allows, and cancels the
   * pending approval when the timeout or the caller's signal ends it first.
   * A signal already aborted sends nothing and is a plain stop. A non-200
   * answer is the error `refuse` makes of it. An exchange that failed, and a
   * 200 whose body cannot be read as `shape`, are marked as lost answers: the
   * signer may have acted on the request.
   */
  private async postApproval<T>(
    path: string,
    requestId: string,
    body: string,
    signal: AbortSignal | undefined,
    shape: AnswerShape,
    refuse: (response: Response) => Promise<SignerError>,
  ): Promise<T> {
    await this.discoverApprovalWait();
    if (signal?.aborted) {
      throw callerAborted();
    }

    let response: Response;
    try {
      response = await this.fetch(path, {
        method: "POST",
        body,
        timeout: this.signRequestTimeout(),
        signal,
      });
    } catch (error) {
      await this.bestEffortCancelSignRequest(requestId);
      throw markLostAnswer(error);
    }

    if (response.status !== 200) {
      throw await refuse(response);
    }
    return readApprovalAnswer<T>(response, shape);
  }

  /**
   * Sign a prepared group through the ordinary approval path, then send the
   * exact executable group to the caller-provided algod simulation endpoint.
   */
  async simulatePreparedGroup(
    algodClient: Algodv2,
    group: PreparedGroup,
    options?: SignOptions,
  ): Promise<SimulationResult> {
    if (!algodClient) {
      throw new SignerError("algodClient is required");
    }
    const response = await this.signRequests(preparedGroupToSignRequests(group), options);
    const mutations = response.mutations;
    if ((mutations?.foreignCount ?? 0) > 0) {
      throw new SignerError(
        `signed simulation requires a complete group; signer returned ${mutations?.foreignCount} foreign transaction(s)`
      );
    }
    return simulateSignedGroup(algodClient, response.signed ?? [], mutations);
  }

  /**
   * Sign and simulate one prepared transaction.
   */
  async simulatePreparedTransaction(
    algodClient: Algodv2,
    prepared: PreparedTransaction,
    options?: SignOptions,
  ): Promise<SimulationResult> {
    return this.simulatePreparedGroup(algodClient, { transactions: [prepared] }, options);
  }

  /**
   * Build an ALGO payment, then sign, submit and track it with sendPrepared.
   * It works the same way for every account type sendPrepared supports.
   */
  async sendPayment(
    algodClient: Algodv2,
    params: PaymentPrepParams,
    options?: SendOptions,
  ): Promise<SendResult> {
    checkSendOptions(options);
    const prepared = await this.preparePayment(algodClient, params);
    return this.sendPreparedGroup(algodClient, { transactions: [prepared] }, options, true);
  }

  /**
   * Sign a prepared transaction or group with the signing flow each account
   * needs, check the signed result against what was prepared, submit exactly
   * those bytes, and by default wait for confirmation.
   *
   * The flow is chosen from the signer's own record of each key, never from
   * the caller. A rotating account is signed for by another key only when
   * the chain says it is rekeyed to that key. A group of ordinary and bounded
   * accounts goes through /sign; a group with a cosigned account goes through
   * the cosigned sequence, which needs the cosigner named in options when a
   * position requires its signature. A rotating account's transaction, which
   * must be alone and ungrouped, goes through the rotating sequence: prepare,
   * check, simulate unsigned, then sign. An unknown flow, or a pre-signed or
   * foreign position, is refused before anything is signed.
   *
   * Every position must be one whose key this signer holds, and must name it
   * in authAddress, as the prepare helpers do.
   *
   * A refusal by the signer, and an answer of the signer's that the SDK
   * refuses, come back as the signing call's own error; nothing was
   * submitted. The other failures are typed: SignOutcomeUnknownError (an
   * approval-bearing request ended with no answer), SubmissionRejectedError
   * and SubmissionUncertainError (the group was signed, and the error keeps
   * the signed bytes and their IDs), RotatingPreflightError,
   * UnsupportedSigningFlowError and UnsupportedGroupError. A rotating send
   * may prepare and seek approval again, a bounded number of times, when the
   * signer says an attempt released no signature. No send ever builds a
   * replacement for a transaction whose outcome is unknown.
   */
  async sendPrepared(
    algodClient: Algodv2,
    group: PreparedGroup,
    options?: SendOptions,
  ): Promise<SendResult> {
    return this.sendPreparedGroup(algodClient, group, options, false);
  }

  /**
   * sendPrepared. intentBuilt says the SDK built the group's transactions
   * itself, so it may rebuild their validity rounds.
   */
  private async sendPreparedGroup(
    algodClient: Algodv2,
    group: PreparedGroup,
    options: SendOptions | undefined,
    intentBuilt: boolean,
  ): Promise<SendResult> {
    if (!algodClient) {
      throw new SignerError("algodClient is required");
    }
    const checked = checkSendOptions(options);
    const opts = options ?? {};
    const signal = opts.signal;
    // An aborted signal stops the send before the signer is asked anything.
    if (signal?.aborted) {
      throw callerAborted();
    }
    const { flow, leftRotation } = await this.classifySend(group);
    // A rotating account is signed for by another key only when the chain
    // says it is rekeyed to that key. Without this a caller could have an
    // ordinary key sign a rotating account's transaction, outside the
    // rotating rules: refused by the network today, but signed.
    for (const index of leftRotation) {
      const item = group.transactions[index];
      const sender = (item.transaction as Transaction).sender.toString();
      let info: AccountInfoResult;
      try {
        info = await (algodClient as any).accountInformation(sender).do(undefined, algodOptions(signal));
      } catch (error) {
        throw new SignerError(
          `prepared transaction ${index}: read the authorizer of rotating account ${sender}: ${errorText(error)}`,
        );
      }
      if (extractAuthAddress(info) !== item.authAddress) {
        throw new UnsupportedGroupError(
          `prepared transaction ${index}: group not supported by unified sending: it names auth address ` +
            `${item.authAddress}, but rotating account ${sender} is not rekeyed to it`,
        );
      }
    }
    // Nothing has been asked of the signer yet, so an aborted signal is a
    // plain stop, not an unknown outcome.
    if (signal?.aborted) {
      throw callerAborted();
    }

    if (flow === SIGNING_FLOW_ROTATING1) {
      return this.sendRotating(
        algodClient,
        group.transactions[0],
        checked,
        intentBuilt || Boolean(opts.refreshValidity),
      );
    }

    const result = emptySendResult(flow, group.transactions.length);
    if (flow === SIGNING_FLOW_COSIGNED1) {
      let signed: CosignedSignResult;
      try {
        signed = await signPreparedCosignedGroup({
          userClient: this,
          cosignerClient: opts.cosignerClient,
          cosignerResolver: opts.cosignerResolver,
          cosignerComponentKey: opts.cosignerComponentKey,
          preparedGroup: group,
          signal,
        });
      } catch (error) {
        // The sequence makes several approval-bearing requests. One that
        // ended with no answer may have released a signature, and the last
        // of them releases the whole group.
        if (isLostAnswer(error)) {
          throw new SignOutcomeUnknownError({ cause: error });
        }
        throw error;
      }
      result.signedGroup = [...signed.signedGroup];
      result.mutations = signed.planMutations;
      result.cosigned = signed;
    } else {
      const response = await this.signForSend(group, signal);
      result.signedGroup = [...(response.signed ?? [])];
      result.mutations = response.mutations;
    }

    let raw: Uint8Array[];
    try {
      raw = describeSignedGroup(result);
    } catch (error) {
      throw new SignerError(`verify signed group: ${errorText(error)}`);
    }
    await submitAndTrack(algodClient, raw, result, checked);
    return result;
  }

  /**
   * Pick the one signing flow for the whole group from the signer's records,
   * or refuse a group unified sending does not cover. Nothing has been signed
   * when it returns.
   *
   * leftRotation lists the positions whose sender is a rotating account and
   * which name another held key: the caller must confirm on the chain that
   * the account is rekeyed to that key before anything is signed.
   */
  private async classifySend(group: PreparedGroup): Promise<{ flow: string; leftRotation: number[] }> {
    const items = group?.transactions ?? [];
    if (!Array.isArray(items) || items.length === 0) {
      throw new SignerError("prepared group is empty");
    }
    const keys = await this.listKeysIfKeysetChanged();
    let flow = "";
    const leftRotation: number[] = [];
    for (let index = 0; index < items.length; index++) {
      const item = items[index];
      if (item.signedTransactionBase64) {
        throw new UnsupportedGroupError(
          `prepared transaction ${index}: group not supported by unified sending: it is already signed; ` +
            "use the lower-level signing calls for a pre-signed position",
        );
      }
      if (!item.transaction) {
        throw new SignerError(`prepared transaction ${index}: transaction is required`);
      }
      const authAddress = item.authAddress;
      if (!authAddress) {
        throw new UnsupportedGroupError(
          `prepared transaction ${index}: group not supported by unified sending: it names no auth address, ` +
            "so this signer does not sign it",
        );
      }
      // A rotating account is recognised by its own record: once it has
      // rotated, its on-chain authorizer is a stage address the signer does
      // not list. It signs alone, and as itself.
      const sender = item.transaction.sender.toString();
      // A position that names another key the signer holds says the account
      // left rotation for that key. It is routed by that key once the chain
      // confirms the rekey.
      const namesAnotherKey = authAddress !== sender && findSpendableKey(keys, authAddress) !== undefined;
      const own = findSpendableKey(keys, sender);
      const rotatingSender = own?.signingFlow === SIGNING_FLOW_ROTATING1;
      if (rotatingSender && namesAnotherKey) {
        leftRotation.push(index);
      }
      if (rotatingSender && !namesAnotherKey) {
        if (items.length !== 1) {
          throw new UnsupportedGroupError(
            `prepared transaction ${index}: group not supported by unified sending: ${sender} is a rotating ` +
              "account, which sends one transaction alone; the signer forms its group",
          );
        }
        if (authAddress !== sender) {
          throw new UnsupportedGroupError(
            `prepared transaction ${index}: group not supported by unified sending: it names auth address ` +
              `${authAddress}, but ${sender} is a rotating account and signs as itself`,
          );
        }
        return { flow: SIGNING_FLOW_ROTATING1, leftRotation: [] };
      }
      const key = findSpendableKey(keys, authAddress);
      if (!key) {
        throw new KeyNotFoundError(`prepared transaction ${index}: ${authAddress} is not available for signing`);
      }
      switch (key.signingFlow ?? "") {
        case "":
        case SIGNING_FLOW_BOUNDED1:
          break;
        case SIGNING_FLOW_COSIGNED1:
          flow = SIGNING_FLOW_COSIGNED1;
          break;
        case SIGNING_FLOW_ROTATING1:
          throw new UnsupportedGroupError(
            `prepared transaction ${index}: group not supported by unified sending: it names rotating account ` +
              `${authAddress} as the auth address of another sender; a rotating account signs only its own transactions`,
          );
        default:
          throw new UnsupportedSigningFlowError(
            `prepared transaction ${index}: unsupported signing flow: key ${authAddress} requires signing flow ` +
              `${JSON.stringify(key.signingFlow)}; upgrade the SDK`,
          );
      }
    }
    return { flow, leftRotation };
  }

  /**
   * The ordinary /sign flow for a send: signRequests, with an exchange that
   * ended with no usable answer told apart from a refusal.
   */
  private async signForSend(group: PreparedGroup, signal?: AbortSignal): Promise<GroupSignResponse> {
    const requests = preparedGroupToSignRequests(group);
    const requestId = newSignRequestId();
    try {
      return await this.signRequests(requests, { requestId, signal });
    } catch (error) {
      if (isLostAnswer(error)) {
        throw new SignOutcomeUnknownError({ requestId, requests, cause: error });
      }
      throw error;
    }
  }

  /**
   * Submit a signed group exactly as given and, unless told not to, wait for
   * confirmation. It signs nothing. Use it to submit a group from
   * signPreparedRotating, or to submit again the signedGroup a
   * SubmissionUncertainError kept: the same bytes can execute only once.
   *
   * Each entry must be one canonically encoded signed transaction, hex
   * msgpack, and a group of several must carry the group ID computed over
   * itself.
   */
  async submitSignedGroup(
    algodClient: Algodv2,
    signedGroup: string[],
    options?: SendOptions,
  ): Promise<SendResult> {
    if (!algodClient) {
      throw new SignerError("algodClient is required");
    }
    const checked = checkSendOptions(options);
    if (!Array.isArray(signedGroup)) {
      throw new SignerError("verify signed group: signed group is empty");
    }
    const result = emptySendResult("", signedGroup.length);
    result.signedGroup = [...signedGroup];
    let raw: Uint8Array[];
    try {
      raw = describeSignedGroup(result);
    } catch (error) {
      throw new SignerError(`verify signed group: ${errorText(error)}`);
    }
    await submitAndTrack(algodClient, raw, result, checked);
    return result;
  }

  /**
   * Ask the signer to prepare one transaction from a rotating account and
   * check the group it returns. The transaction must be ungrouped, set no
   * rekeyTo, not close the account, and have a validity window of at most
   * ROTATING_MAX_VALIDITY_WINDOW rounds. Nothing is signed.
   *
   * The signer may set rekeyTo to the next stage's address, raise the fee,
   * assign a group ID and append canonical resource dummies. Any other
   * change, a report that disagrees with the bytes, or a fee raise above the
   * client's max fee increase is an error.
   */
  async prepareRotating(
    txn: Transaction,
    options?: RotatingPrepareOptions,
  ): Promise<PreparedRotating> {
    if (!txn) {
      throw new SignerError("transaction is required");
    }
    checkRotatingShape(txn);
    checkRotatingWindow(txn);
    const [originalHex] = encodeTransaction(txn);
    const request: RotatingPrepareRequest = {
      account: txn.sender.toString(),
      txn_bytes_hex: originalHex,
    };
    const maxFeeIncrease = this.feeCeilingSnapshot();

    const response = await this.fetch("/sign/rotating/prepare", {
      method: "POST",
      body: JSON.stringify(request),
      timeout: this.timeoutFor(GROUP_PLAN_TIMEOUT),
      signal: options?.signal,
    });
    if (response.status !== 200) {
      throw await this.rotatingAPIError(response, "rotating prepare failed");
    }
    let data: RotatingPrepareResponse;
    try {
      data = (await response.json()) as RotatingPrepareResponse;
    } catch {
      throw new SignerError("Server returned invalid JSON");
    }
    try {
      return newPreparedRotating(originalHex, data, maxFeeIncrease, options?.appCallInfo);
    } catch (error) {
      throw verificationError("verify prepared rotating group: ", error);
    }
  }

  /**
   * Simulate the prepared group, unsigned, through the caller's algod. It
   * never signs. A failed simulation, or an answer without exactly one group
   * result, is reported in the result's `failed` field, not as an error.
   *
   * It checks the group's effects. It does not prove the stage's signatures
   * will pass: the node runs the stage program only on the signed group.
   */
  async simulatePreparedRotating(
    algodClient: Algodv2,
    prepared: PreparedRotating,
    options?: { signal?: AbortSignal },
  ): Promise<SimulationResult> {
    if (!algodClient) {
      throw new SignerError("algodClient is required");
    }
    // Only a PreparedRotating prepareRotating made is used: an object built
    // on its prototype could carry its own checks or none.
    if (!PreparedRotating.isGenuine(prepared)) {
      throw new SignerError("prepared rotating group is required: pass the PreparedRotating prepareRotating returned");
    }
    try {
      PreparedRotating.verifyBinding(prepared);
    } catch (error) {
      throw verificationError("verify prepared rotating group: ", error);
    }
    const unsigned = prepared.decoded().map((txn) => new algosdk.SignedTransaction({ txn }));
    const response = await runSimulation(algodClient, unsigned, true, options?.signal);
    return {
      txIds: prepared.txIds(),
      transactions: prepared.transactions(),
      signedGroup: [],
      mutations: prepared.mutations(),
      response,
      failed: simulationFailed(response),
    };
  }

  /**
   * Ask the signer to sign a prepared rotating group, wait for operator
   * approval, and check the signed group against the prepared one. It does
   * not submit.
   *
   * If the answer never arrives it throws a SignOutcomeUnknownError that
   * carries the prepared group. Calling signPreparedRotating again with that
   * same prepared group is the safe recovery: it asks for the same
   * transaction, with the same IDs, and builds no second spend. It needs
   * approval again, and it succeeds only while the stage is still live and
   * the window still acceptable. If that retry is refused, do not prepare a
   * replacement until the first attempt's outcome is known;
   * rotating_stage_changed in particular means a transaction from that stage
   * has confirmed.
   */
  async signPreparedRotating(
    prepared: PreparedRotating,
    options?: RotatingSignOptions,
  ): Promise<RotatingSignResult> {
    // Only a PreparedRotating prepareRotating made is signed: an object built
    // on its prototype could carry its own checks or none.
    if (!PreparedRotating.isGenuine(prepared)) {
      throw new SignerError("prepared rotating group is required: pass the PreparedRotating prepareRotating returned");
    }
    // The binding is checked again at the signing boundary.
    try {
      PreparedRotating.verifyBinding(prepared);
    } catch (error) {
      throw verificationError("verify prepared rotating group: ", error);
    }
    const requestId = options?.requestId || newSignRequestId();
    validateSignRequestId(requestId, true);

    let data: RotatingSignResponse;
    try {
      data = await this.postApproval<RotatingSignResponse>(
        "/sign/rotating/sign",
        requestId,
        JSON.stringify(prepared.signRequestBody(requestId)),
        options?.signal,
        ROTATING_SIGN_ANSWER,
        (response) => this.rotatingAPIError(response, "rotating sign failed"),
      );
    } catch (error) {
      if (isLostAnswer(error)) {
        throw new SignOutcomeUnknownError({ requestId, rotating: prepared, cause: error });
      }
      throw error;
    }
    let result: RotatingSignResult;
    try {
      result = prepared.verifySigned(data);
    } catch (error) {
      throw verificationError("verify signer response: ", error);
    }
    result.requestId = requestId;
    return result;
  }

  /**
   * Run the rotating1 flow for one transaction: prepare, check the prepared
   * group, simulate it unsigned, then sign and submit exactly those bytes. A
   * failed check or simulation happens before any key is used.
   *
   * refresh says the validity rounds may be rebuilt: always for a
   * transaction the SDK built from an intent, and for a supplied one only
   * when the caller set refreshValidity. A supplied transaction is otherwise
   * sent as given.
   *
   * An attempt is repeated, at most ROTATING_SEND_ATTEMPTS times, only when
   * the signer said that attempt released no signature: it has not found the
   * live stage yet, the account's authorizer moved between prepare and sign,
   * or the window was not current at signing. Every attempt needs approval
   * again. A sign whose answer never arrived, and any failure after
   * submission, ends the send: it never builds a replacement spend on its
   * own.
   */
  private async sendRotating(
    algodClient: Algodv2,
    item: PreparedTransaction,
    checked: CheckedSendOptions,
    refresh: boolean,
  ): Promise<SendResult> {
    if (item.lsigArgs && Object.keys(item.lsigArgs).length > 0) {
      throw new UnsupportedGroupError(
        "group not supported by unified sending: a rotating account takes no LogicSig arguments from the caller",
      );
    }
    const algod = algodClient as any;
    const signal = checked.signal;
    let txn = item.transaction as Transaction;
    // prepareRotating refuses a spend of the wrong shape, or with a window
    // over the limit, before it asks the signer anything.
    const prepareOptions: RotatingPrepareOptions = { appCallInfo: item.appCallInfo, signal };

    for (let attempt = 1; ; attempt++) {
      const last = attempt === ROTATING_SEND_ATTEMPTS;
      // The signer signs only while the window is current. Checking here
      // saves the operator an approval that could not lead to a signature.
      let round: bigint;
      try {
        const status = await algod.status().do(undefined, algodOptions(signal));
        round = algodRound(status?.lastRound, "last round");
      } catch (error) {
        throw new SignerError(`read current round: ${errorText(error)}`);
      }
      if (!rotatingWindowCurrent(txn, round)) {
        if (!refresh) {
          checkRotatingWindow(txn);
          throw new SignerError(
            `validity rounds ${txn.firstValid}-${txn.lastValid} are not current at round ${round}: ` +
              `a rotating account signs only while first valid is at most ${ROTATING_MAX_LEAD} rounds ahead ` +
              `and at least ${ROTATING_MIN_REMAINING} rounds remain (rebuild the transaction, or set refreshValidity)`,
          );
        }
        txn = await refreshRotatingValidity(algod, txn, false, algodOptions(signal));
      }

      let prepared: PreparedRotating;
      try {
        prepared = await this.prepareRotating(txn, prepareOptions);
      } catch (error) {
        if (signerErrorCode(error) === ErrorCodes.RotatingStageUnproven && !last) {
          try {
            await sleepWithSignal(attempt * rotatingTiming.unprovenBackoffMs, signal);
          } catch (waitError) {
            throw new SignerError(
              `${errorText(error)} (and the wait to retry ended: ${errorText(waitError)})`,
              signerErrorCode(error),
            );
          }
          continue;
        }
        throw error;
      }

      let simulation: SimulationResult;
      try {
        simulation = await this.simulatePreparedRotating(algodClient, prepared, { signal });
      } catch (error) {
        throw new SignerError(`simulate prepared rotating group; nothing was signed: ${errorText(error)}`);
      }
      if (simulation.failed) {
        throw new RotatingPreflightError(prepared, simulationFailure(simulation.response));
      }
      // Nothing has been asked to sign yet, so an aborted signal is a plain
      // stop, not an unknown outcome.
      if (signal?.aborted) {
        throw callerAborted();
      }

      let signed: RotatingSignResult;
      try {
        signed = await this.signPreparedRotating(prepared, { signal });
      } catch (error) {
        const code = signerErrorCode(error);
        if (code === ErrorCodes.RotatingStageChanged && !last) {
          continue;
        }
        if (code === ERROR_CODE_ROTATING_WINDOW_NOT_CURRENT && refresh && !last) {
          txn = await refreshRotatingValidity(algod, txn, true, algodOptions(signal));
          continue;
        }
        throw error;
      }

      const result = emptySendResult(SIGNING_FLOW_ROTATING1, 1);
      result.signedGroup = [...signed.signedGroup];
      result.mutations = prepared.mutations();
      result.rotating = {
        stage: signed.stage,
        target: signed.target,
        rekeyTo: prepared.rekeyTo,
        attempts: attempt,
        transaction: cloneTransaction(txn),
        requestId: signed.requestId,
      };
      let raw: Uint8Array[];
      try {
        raw = describeSignedGroup(result);
      } catch (error) {
        throw new SignerError(`verify signed group: ${errorText(error)}`);
      }
      await submitAndTrack(algodClient, raw, result, checked);
      return result;
    }
  }

  /**
   * The error for a refused rotating request: the statuses every signing
   * call maps, and otherwise a SignerError that keeps the stable code.
   */
  private async rotatingAPIError(response: Response, fallback: string): Promise<SignerError> {
    if (response.status === 401) {
      return new AuthenticationError();
    }
    if (response.status === 403) {
      return this.forbiddenRejectedError(response, fallback);
    }
    if (response.status === 503) {
      const { code, message } = await this.errorParts(response, "Signer unavailable");
      return new SignerUnavailableError(message, code);
    }
    return this.signerHTTPError(response, `${fallback}: HTTP ${response.status}`);
  }

  /**
   * Build the JSON request body for /sign and /plan endpoints.
   */
  private buildSignRequestBody(
    txns: (Transaction | null)[],
    authAddresses: (string | null)[],
    lsigArgsMap?: LsigArgsMap,
    passthrough?: Record<number, string>,
    lsigResources?: Record<number, LogicSigResourceUsage>,
    allowForeign = true,
  ): { requests: SignRequest[] } {
    if (txns.length === 0) {
      throw new SignerError("transactions must not be empty");
    }

    // Normalize index-keyed inputs once, so every later lookup is an integer
    // key that cannot silently miss its entry.
    const passthroughByIndex = normalizeIndexedRecord(passthrough, txns.length, "passthrough");
    const lsigResourcesByIndex = normalizeIndexedRecord(
      lsigResources,
      txns.length,
      "lsigResources",
    );
    for (const [idx, resources] of lsigResourcesByIndex) {
      validateLogicSigResources(resources, `lsigResources[${idx}]`);
    }

    const signRequests: SignRequest[] = [];
    const matchedLsigArgs = new Set<string>();
    for (let i = 0; i < txns.length; i++) {
      const txn = txns[i];
      const authAddr = authAddresses[i];

      // Passthrough: include pre-signed transaction as-is. It is decoded
      // strictly here to refuse a malformed one early and to match the
      // LogicSig args; what is decoded goes no further.
      const passthroughEntry = passthroughByIndex.get(i);
      if (passthroughEntry !== undefined) {
        const signedBytes = base64ToBytes(passthroughEntry, `passthrough[${i}]`);
        let slot: RequestSlot;
        try {
          slot = decodePassthroughSlot(signedBytes);
        } catch (error) {
          throw new SignerError(`invalid passthrough[${i}]: ${errorText(error)}`);
        }
        // A passthrough position's authorizer is whoever signed it: the
        // signer its bytes name, or the sender when they name none. An auth
        // address given for the position counts too. The sender of a rekeyed
        // account is not its authorizer.
        if (authAddr) matchedLsigArgs.add(authAddr);
        matchedLsigArgs.add(slot.signer ?? slot.txn.sender.toString());
        const request: SignRequest = { signed_txn_hex: bytesToHex(signedBytes) };
        const resources = lsigResourcesByIndex.get(i);
        if (resources) {
          request.lsig_resources = wireLogicSigResources(resources);
        }
        signRequests.push(request);
        continue;
      }

      // A sign or foreign position matches its auth address, or its sender
      // when none is given.
      if (authAddr) {
        matchedLsigArgs.add(authAddr);
      } else if (txn) {
        matchedLsigArgs.add(txn.sender.toString());
      }

      if (authAddr && lsigResourcesByIndex.has(i)) {
        throw new SignerError(
          `lsigResources[${i}] is allowed only for foreign or passthrough transactions`,
        );
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
        const resources = lsigResourcesByIndex.get(i);
        if (resources) {
          req.lsig_resources = wireLogicSigResources(resources);
        }
        signRequests.push(req);
        continue;
      }

      if (!txn) {
        throw new SignerError(`transaction is required for sign-mode entry at index ${i}`);
      }
      try {
        signSlot(txn, authAddr);
      } catch (error) {
        throw new SignerError(`transaction ${i + 1}: ${errorText(error)}`);
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

    // Args keyed under an address that authorizes no position are a mistake,
    // and dropping them would sign without them; an optional arg left out can
    // select a different authorization branch. A position's authorizer is its
    // auth address, never its sender when the two differ. A key that is the
    // authorizer of a passthrough or foreign position is fine: the same map
    // can serve several calls over one group. An entry with no args is
    // ignored.
    const unmatched = Object.entries(lsigArgsMap ?? {})
      .filter(([address, args]) =>
        args && Object.keys(args).length > 0 && !matchedLsigArgs.has(address))
      .map(([address]) => JSON.stringify(address))
      .sort();
    if (unmatched.length > 0) {
      throw new SignerError(
        `lsig args are keyed by auth address, and no transaction in the request has auth address ${unmatched.join(", ")}`,
      );
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
    lsigResources?: Record<number, LogicSigResourceUsage>,
    options?: SignOptions,
  ): Promise<string[]> {
    const requestBody = this.buildSignRequestBody(
      txns, authAddresses, lsigArgsMap, passthrough, lsigResources, false,
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
   * code (empty when the body is not a JSON error envelope) and
   * human-readable message.
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
   * Classify a 400 at signing/planning endpoints. Only the not_found wire
   * code maps to KeyNotFoundError; message text is never inspected.
   */
  private async badRequestError(response: Response): Promise<SignerError> {
    const { code, message } = await this.errorParts(response, "Bad request");
    if (code === ErrorCodes.NotFound) {
      return new KeyNotFoundError(message, code);
    }
    return new SignerError(`Bad request: ${message}`, code);
  }

  /**
   * Classify a 403 at endpoints that report a locked signer. Only the locked
   * wire code maps to the locked error; any other code, including an empty
   * one, is a generic SignerError.
   */
  private async forbiddenLockedError(response: Response): Promise<SignerError> {
    const { code, message } = await this.errorParts(response, "Forbidden");
    if (code === ErrorCodes.Locked) {
      return new SignerUnavailableError("Signer is locked", code);
    }
    return new SignerError(message, code);
  }

  /**
   * Classify a 403 at endpoints that report a rejected request. A locked code
   * maps to the locked error and a forbidden code to the rejection error; any
   * other code, including an empty one, is a generic SignerError.
   */
  private async forbiddenRejectedError(response: Response, fallback: string): Promise<SignerError> {
    const { code, message } = await this.errorParts(response, fallback);
    if (code === ErrorCodes.Locked) {
      return new SignerUnavailableError("Signer is locked", code);
    }
    if (code === ErrorCodes.Forbidden) {
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
      // The SSH connection carries the client's identity; no header does.
      const headers: Record<string, string> = {};

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
