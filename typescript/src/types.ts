// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * Runtime argument specification for a generic LogicSig.
 * Position in the array corresponds to the TEAL arg index.
 */
export interface RuntimeArg {
  /** Internal name for the argument (e.g., "preimage") */
  name: string;
  /** Argument type: "bytes", "string", or "uint64" */
  type: string;
  /** Help text describing the argument */
  description: string;
  /** Human-readable label for UI display */
  label?: string;
  /** If true, must be provided at signing time */
  required?: boolean;
  /** Expected byte length (0 = variable) */
  byteLength?: number;
}

/**
 * Key-file-owned signing argument metadata returned from /keys.
 */
export type SigningArg = RuntimeArg;

/**
 * Information about a signing key from the signer.
 */
export interface KeyInfo {
  /** Algorand address */
  address: string;
  /** Public key in hex format */
  publicKeyHex: string;
  /** Key type (e.g., "ed25519", "aplane.falcon1024.v1", "aplane.timelock.v1") */
  keyType: string;
  /** Total LogicSig size for budget calculation (bytecode + crypto sig) */
  lsigSize: number;
  /** True if this is a generic LogicSig (no cryptographic signature needed) */
  isGenericLsig: boolean;
  /** Key-file-owned signing arguments for LogicSigs */
  signingArgs?: SigningArg[];
  /** Template provenance status, when the signer reports one */
  templateProvenanceStatus?: string;
  /** Human-readable template provenance note */
  templateProvenanceNote?: string;
  /** Legacy alias for templateProvenanceStatus */
  templateStatus?: string;
  /** Legacy alias for templateProvenanceNote */
  templateWarning?: string;
}

/**
 * SSH tunnel configuration.
 */
export interface SSHConfig {
  /** Remote host to SSH to */
  host: string;
  /** SSH port (default: 1127) */
  port: number;
  /** Path to SSH private key, relative to data directory */
  identityFile: string;
  /** Path to known_hosts file, relative to data directory */
  knownHostsPath: string;
  /** If true, automatically trust and save unknown host keys (TOFU). Default: false */
  trustOnFirstUse: boolean;
}

/**
 * Client configuration for connecting to apsigner.
 */
export interface ClientConfig {
  /** Signer REST port (default: 11270) */
  signerPort: number;
  /** SSH configuration (if present, use SSH tunnel) */
  ssh?: SSHConfig;
}

/**
 * Options for SignerClient.connectSsh()
 */
export interface ConnectSshOptions {
  /** SSH port on remote (default: 1127) */
  sshPort?: number;
  /** Signer REST port on remote (default: 11270) */
  signerPort?: number;
  /** Optional explicit shorter request timeout in milliseconds */
  timeout?: number;
  /** Path to known_hosts file for SSH host key verification (required) */
  knownHostsPath?: string;
  /** If true, automatically trust and save unknown host keys (TOFU). Default: false */
  trustOnFirstUse?: boolean;
}

/**
 * Options for SignerClient.fromEnv()
 */
export interface FromEnvOptions {
  /** Override default data directory */
  dataDir?: string;
  /** Optional explicit shorter request timeout in milliseconds */
  timeout?: number;
}

/**
 * Options for high-level signing helpers.
 */
export interface SignOptions {
  /**
   * Optional caller-owned /sign request ID. Use the same ID with
   * cancelSignRequest() to cancel a pending approval from another task.
   */
  requestId?: string;
  /**
   * Optional caller cancellation signal. Aborting the signal aborts the
   * in-flight /sign request and sends a best-effort /sign/cancel.
   */
  signal?: AbortSignal;
}

/**
 * Alternate UI input mode for a creation parameter.
 */
export interface InputModeInfo {
  /** Mode name, such as "text" or "sha256" */
  name: string;
  /** Human-readable label */
  label?: string;
  /** Transform applied by this mode, such as "sha256" */
  transform?: string;
  /** Expected byte length after transform */
  byteLength?: number;
  /** Input type accepted by this mode */
  inputType?: string;
}

/**
 * Parameter specification for key generation.
 */
export interface CreationParam {
  /** Parameter name */
  name: string;
  /** Human-readable label */
  label: string;
  /** Help text */
  description?: string;
  /** Parameter type: "address", "address[]", "uint64", "string", "bytes" */
  paramType?: string;
  /** If true, must be provided */
  required?: boolean;
  /** Maximum string/byte length */
  maxLength?: number;
  /** Alternate UI input modes for this parameter */
  inputModes?: InputModeInfo[];
  /** Minimum number of items for list parameters */
  minItems?: number;
  /** Maximum number of items for list parameters */
  maxItems?: number;
  /** Minimum numeric value */
  min?: number;
  /** Maximum numeric value */
  max?: number;
  /** Example value */
  example?: string;
  /** Placeholder text for UI */
  placeholder?: string;
  /** Default value */
  default?: string;
}

/**
 * Information about an available key type.
 */
export interface KeyTypeInfo {
  /** Key type identifier (e.g., "ed25519", "aplane.falcon1024.v1") */
  keyType: string;
  /** Key family (e.g., "ed25519", "falcon") */
  family: string;
  /** Human-readable display name */
  displayName?: string;
  /** Description of the key type */
  description?: string;
  /** Whether this key type requires a LogicSig */
  requiresLogicsig?: boolean;
  /** Number of words in the mnemonic */
  mnemonicWordCount?: number;
  /** Whether mnemonic import is supported for this key type */
  mnemonicImport?: boolean;
  /** Mnemonic scheme name */
  mnemonicScheme?: string;
  /** Creation parameters */
  creationParams?: CreationParam[];
  /** Runtime arguments for generic LogicSigs */
  runtimeArgs?: RuntimeArg[];
}

/**
 * Response from the /status endpoint.
 */
export interface StatusResponse {
  /** Authenticated identity ID resolved from the signer token */
  identityId: string;
  /** Current lock state: "locked", "unlocked", or "unknown" */
  state: string;
  /** True when the signer identity is locked */
  signerLocked: boolean;
  /** True when the identity can currently sign */
  readyForSigning: boolean;
  /** Number of currently loaded keys */
  keyCount: number;
  /** Process-local keyset revision for refresh decisions */
  keysetRevision: number;
  /** Effective manual approval wait in seconds, when provided */
  approvalWaitSeconds?: number;
}

/**
 * Result of key generation.
 */
export interface GenerateResult {
  /** Algorand address of the generated key */
  address: string;
  /** Type of key generated */
  keyType: string;
  /** Creation parameters used */
  parameters?: Record<string, string>;
}

/**
 * Response from the /keytypes endpoint.
 */
export interface KeyTypesResponse {
  /** Array of key type information */
  key_types: KeyTypeInfo[];
}

/**
 * Response from the /plan endpoint.
 */
export interface PlanGroupResponse {
  /** TX-prefixed hex-encoded unsigned transactions */
  transactions?: string[];
  /** Modifications made by server */
  mutations?: MutationReport;
  /** Error message if planning failed */
  error?: string;
}

/**
 * Sign cancellation lifecycle state returned by /sign/cancel.
 */
export type SignCancelState = "canceled" | "not_found";

/**
 * Request payload for /sign/cancel.
 */
export interface CancelSignRequest {
  request_id: string;
}

/**
 * Response from the /sign/cancel endpoint.
 */
export interface CancelSignResponse {
  success: boolean;
  state?: SignCancelState;
  error?: string;
}

/**
 * LogicSig runtime arguments for a single address.
 * Maps argument name to its value as Uint8Array.
 */
export type LsigArgs = Record<string, Uint8Array>;

/**
 * LogicSig runtime arguments for multiple addresses.
 * Maps address to its argument map.
 */
export type LsigArgsMap = Record<string, LsigArgs>;

/**
 * Internal sign request structure sent to the server.
 */
export interface SignRequest {
  /** Auth address (which key to use for signing) */
  auth_address?: string;
  /** Advisory display hint; signer authority comes from txn bytes */
  txn_sender?: string;
  /** Transaction bytes (TX + msgpack) as hex */
  txn_bytes_hex?: string;
  /** Runtime args for generic LogicSigs (name -> hex value) */
  lsig_args?: Record<string, string>;
  /** Optional app-call metadata for approval rendering */
  app_call_info?: AppCallInfo;
  /** Pre-signed transaction hex (for passthrough) */
  signed_txn_hex?: string;
  /** LSig size hint for foreign transactions */
  lsig_size?: number;
}

/**
 * Request payload for /sign.
 */
export interface GroupSignRequest {
  /** Optional caller-owned request ID for cancellation. Generated when omitted. */
  request_id?: string;
  /** Transaction slots to sign or pass through. */
  requests: SignRequest[];
}

/**
 * Optional app-call metadata for approval rendering.
 */
export interface AppCallInfo {
  /** "raw" or "abi" */
  mode?: string;
  /** ABI method signature when available */
  method?: string;
}

/**
 * Describes modifications made by the server during signing.
 */
export interface MutationReport {
  /** Number of dummy transactions added for LSig budget */
  dummiesAdded?: number;
  /** True if group ID was computed/recomputed */
  groupIdChanged?: boolean;
  /** Indices of transactions with modified fees (0-based) */
  feesModified?: number[];
  /** Total fee increase in microAlgos (for dummy fees) */
  totalFeesDelta?: number;
  /** Number of transactions in original request */
  originalCount?: number;
  /** Number of transactions in signed response */
  finalCount?: number;
  /** Number of pre-signed transactions included as-is */
  passthroughCount?: number;
  /** Number of foreign transactions not signed by this signer */
  foreignCount?: number;
  /** Human-readable reason (e.g., "lsig_budget") */
  reason?: string;
}

/**
 * Response from the /sign endpoint.
 */
export interface GroupSignResponse {
  /** Array of signed transactions (hex-encoded msgpack) */
  signed?: string[];
  /** Modifications made by server (undefined if none) */
  mutations?: MutationReport;
  /** Error message if signing failed */
  error?: string;
}

/**
 * Standard signer HTTP error body for non-2xx responses.
 */
export interface ErrorResponse {
  error: string;
}

/**
 * Response from the /keys endpoint.
 */
export interface KeysResponse {
  /** Number of keys */
  count: number;
  /** Array of key information */
  keys: KeyInfo[];
}
