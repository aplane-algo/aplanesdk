// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * APlane TypeScript SDK - Transaction signing via apsigner
 *
 * Data directory (required via APCLIENT_DATA env var or dataDir option):
 *     <data_dir>/
 *     ├── endpoints.yaml       # Signer and cosigner routing
 *     └── .ssh/id_ed25519      # SSH key: the client's credential
 *
 * Example endpoints.yaml:
 *     schema_version: 2
 *     endpoints:
 *       primary:
 *         role: signer
 *         url: ssh://signer.example.com:1127
 *
 * Usage:
 *     import { SignerClient, sendRawTransaction } from "aplanesdk";
 *
 *     const client = await SignerClient.fromEnv();
 *     const signed = await client.signTransaction(txn);
 *     const txid = await sendRawTransaction(algodClient, signed);
 *
 * A new client key is enrolled once. The request is queued for the operator
 * to approve later in apadmin; connect after that:
 *     const { fingerprint, pending } = await requestEnrollmentFromEnv({ label: "ci-runner" });
 *
 * @packageDocumentation
 */

// Main client
export {
  SignerClient,
  signPreparedCosignedGroup,
  simulatePreparedCosignedGroup,
} from "./client.js";
export { ErrorCodes } from "./types.js";
export type { ErrorCode } from "./types.js";
export type {
  CosignedSignTarget,
  CosignedCosignerResolution,
  CosignedCosignerResolver,
  CosignedSignResult,
  CosignedSimulationResult,
  PreparedCosignedGroupOptions,
} from "./client.js";

// Utilities
export {
  sendRawTransaction,
  assembleGroup,
  requestEnrollment,
  requestEnrollmentFromEnv,
  loadConfig,
  loadClientEndpointRegistry,
  resolveClientEndpoint,
  resolveDataDir,
  expandPath,
} from "./utils.js";

// Encoding utilities
export {
  encodeTransaction,
  encodeLsigArgs,
  concatenateSignedTxns,
  bytesToHex,
  hexToBytes,
} from "./encoding.js";

// Prepared transaction model
export {
  preparedTransactionToSignRequest,
  preparedGroupToSignRequests,
} from "./prepared.js";

// Errors
export {
  SignerError,
  MaxFeeIncreaseError,
  AuthenticationError,
  SigningRejectedError,
  SignerUnavailableError,
  KeyNotFoundError,
  KeyDeletionError,
  EnrollmentError,
  TransactionRejectedError,
  LogicSigRejectedError,
  InsufficientFundsError,
  InvalidTransactionError,
} from "./errors.js";

// Types
export type {
  KeyInfo,
  AuthorizationKind,
  LogicSigResourceUsage,
  LogicSigResourceProfile,
  BoundedSignatureArgLayout,
  BoundedDerivedArgInfo,
  BoundedArgumentPathMask,
  BoundedRekeyListInfo,
  BoundedArgumentSlotInfo,
  BoundedCosignerAuthorizationInfo,
  BoundedAuthorizationInfo,
  RuntimeArg,
  SigningArg,
  InputModeInfo,
  CreationParam,
  KeyTypeInfo,
  ProtocolVersion,
  StatusResponse,
  GenerateResult,
  ClientConfig,
  ClientEndpointConfig,
  ClientEndpointRegistry,
  FromEnvOptions,
  ConnectSshOptions,
  SignerClientOptions,
  LsigArgs,
  LsigArgsMap,
  SignOptions,
  SignRequest,
  GroupSignRequest,
  GroupSignResponse,
  SimulationResult,
  PreparedCheck,
  PreparedTransaction,
  PreparedGroup,
  PaymentPrepParams,
  AsaTransferPrepParams,
  AccountInfoResult,
  AuthAddressValue,
  AccountInfoLookup,
  ResolvedAuthAddress,
  ErrorResponse,
  MutationReport,
  PlanGroupResponse,
  CancelSignRequest,
  CancelSignResponse,
  SignCancelState,
  WireMutationReport,
  RotatingPrepareRequest,
  RotatingPrepareResponse,
  RotatingSignRequest,
  RotatingSignResponse,
  RotatingAccountStatus,
  RotatingRecoveryStatus,
  RotatingRecoverRequest,
  RotatingRecoverResponse,
  ComponentTargetKind,
  ComponentRequest,
  ComponentTarget,
  Component,
  ComponentResponse,
  AssemblyTargetKind,
  AssemblyRequest,
  AssemblyTarget,
  AssemblyResponse,
  CosignedPassthroughItem,
  CosignedPassthroughAuthorization,
  ComponentContextPosition,
  ComponentDummyPosition,
  ComponentPath,
} from "./types.js";

export {
  SIGNING_FLOW_BOUNDED1,
  SIGNING_FLOW_COSIGNED1,
  BOUNDED_CONTRACT_BOUNDED2,
  BOUNDED_CONTRACT_PLAIN1,
  COMPONENT_PATH_SPEND,
  COMPONENT_PATH_SPENDING_REKEY,
  COMPONENT_PATH_LISTED_REKEY,
  componentNeedsCosigner,
  SIGNING_FLOW_ROTATING1,
  KEY_TYPE_WITNESS_FALCON1024,
  PQ_SCHEME_FALCON1024,
  AUTHORIZATION_KIND_ED25519,
  AUTHORIZATION_KIND_NATIVE_PQ,
  AUTHORIZATION_KIND_LOGIC_SIG,
} from "./types.js";

export type {
  EnrollmentResult,
  RequestEnrollmentOptions,
  RequestEnrollmentFromEnvOptions,
} from "./utils.js";

// Constants
export { DEFAULT_SSH_PORT } from "./config.js";
export { CLIENT_SSH_KEY_REQUIREMENT, MAX_ENROLLMENT_LABEL_BYTES } from "./ssh.js";
