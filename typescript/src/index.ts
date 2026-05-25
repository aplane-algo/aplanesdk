// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * APlane TypeScript SDK - Transaction signing via apsigner
 *
 * Data directory (required via APCLIENT_DATA env var or dataDir option):
 *     <data_dir>/
 *     ├── aplane.token         # API token
 *     └── config.yaml          # Connection settings
 *
 * Example config.yaml:
 *     signer_port: 11270
 *     ssh:
 *       host: signer.example.com
 *       port: 1127
 *       identity_file: .ssh/id_ed25519
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
export { SignerClient } from "./client.js";
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
  RuntimeArg,
  SigningArg,
  InputModeInfo,
  CreationParam,
  KeyTypeInfo,
  StatusResponse,
  GenerateResult,
  ClientConfig,
  SSHConfig,
  FromEnvOptions,
  ConnectSshOptions,
  LsigArgs,
  LsigArgsMap,
  SignOptions,
  SignRequest,
  GroupSignRequest,
  GroupSignResponse,
  ErrorResponse,
  MutationReport,
  PlanGroupResponse,
  CancelSignRequest,
  CancelSignResponse,
  SignCancelState,
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
