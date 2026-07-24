// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * APlane TypeScript SDK - Transaction signing via apsigner
 *
 * Data directory (required via APCLIENT_DATA env var or dataDir option):
 *     <data_dir>/
 *     ├── aplane.token         # API token
 *     └── endpoints.yaml       # Signer and sentry routing
 *
 * Example endpoints.yaml:
 *     schema_version: 1
 *     endpoints:
 *       primary:
 *         role: signer
 *         url: ssh://signer.example.com:1127
 *         signer_port: 11270
 *
 * Usage:
 *     import { SignerClient, sendRawTransaction } from "aplanesdk";
 *
 *     const client = await SignerClient.fromEnv();
 *     const signed = await client.signTransaction(txn);
 *     const txid = await sendRawTransaction(algodClient, signed);
 *
 * @packageDocumentation
 */

// Main client
export {
  SignerClient,
  signGuardedGroup,
  signPreparedGuardedGroup,
  signPreparedBoundedSentryGroup,
  simulateGuardedGroup,
  simulatePreparedGuardedGroup,
} from "./client.js";
export { ErrorCodes } from "./types.js";
export type { ErrorCode } from "./types.js";
export type {
  GuardedSignTarget,
  GuardedPrimarySignTarget,
  GuardedSentryResolution,
  GuardedSentryResolver,
  GuardedSignOptions,
  GuardedSignResult,
  GuardedSimulationResult,
  PreparedGuardedGroupOptions,
} from "./client.js";
export {
  ApsignerAlgoKitAccount,
  createApsignerAccount,
  listApsignerAccounts,
} from "./algokit.js";

// Utilities
export {
  sendRawTransaction,
  assembleGroup,
  requestToken,
  requestTokenToFile,
  loadToken,
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
  AuthenticationError,
  SigningRejectedError,
  SignerUnavailableError,
  KeyNotFoundError,
  KeyDeletionError,
  TokenProvisioningError,
  TransactionRejectedError,
  LogicSigRejectedError,
  InsufficientFundsError,
  InvalidTransactionError,
} from "./errors.js";

// Types
export type {
  KeyInfo,
  BoundedSignatureArgLayout,
  BoundedAdminOperationInfo,
  BoundedDerivedArgInfo,
  BoundedArgumentPathMask,
  BoundedArgumentSlotInfo,
  BoundedSentryAuthorizationInfo,
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
  ClientEndpointPublishedSentry,
  ClientEndpointRegistry,
  FromEnvOptions,
  ConnectSshOptions,
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
  AccountInfoLookup,
  ResolvedAuthAddress,
  ErrorResponse,
  MutationReport,
  PlanGroupResponse,
  CancelSignRequest,
  CancelSignResponse,
  SignCancelState,
  ComponentSignRole,
  ComponentSignRequest,
  ComponentSignature,
  ComponentSignResponse,
  GuardedAssemblyRequest,
  GuardedAssemblyTarget,
  GuardedPassthroughItem,
  GuardedAssemblyResponse,
  BoundedComponentRequest,
  BoundedBaseComponent,
  BoundedComponentResponse,
  BoundedAssemblyRequest,
  BoundedAssemblyTarget,
  BoundedAssemblyResponse,
  SentryReferenceCandidate,
  AdminSyncSentryReferencesRequest,
  SyncedSentryReferenceInfo,
  AdminSyncSentryReferencesResponse,
} from "./types.js";

export {
  COMPONENT_SIGN_ROLE_USER,
  COMPONENT_SIGN_ROLE_SENTRY,
  SIGNING_FLOW_SENTRY1,
  SIGNING_FLOW_BOUNDED1,
  SIGNING_FLOW_BOUNDED_SENTRY1,
  KEY_TYPE_WITNESS_FALCON1024,
  KEY_TYPE_GUARDED_FALCON1024_SENTRY1024,
} from "./types.js";

export type {
  AlgoKitAddress,
  AlgoKitTransaction,
  AlgoKitTransactionEncoder,
  AlgoKitTransactionSigner,
  ApsignerAccount,
  ApsignerAccountOptions,
} from "./algokit.js";

// Constants
export { DEFAULT_SIGNER_PORT, DEFAULT_SSH_PORT } from "./config.js";
