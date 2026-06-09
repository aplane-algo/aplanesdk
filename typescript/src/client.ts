// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import * as fs from "fs";
import * as path from "path";
import * as net from "net";
import { randomBytes } from "crypto";
import type { Transaction } from "algosdk";
import type { Client as SSHClient, ClientChannel } from "ssh2";
import type {
  KeyInfo,
  ConnectSshOptions,
  FromEnvOptions,
  SignOptions,
  LsigArgs,
  LsigArgsMap,
  SignRequest,
  GroupSignRequest,
  GroupSignResponse,
  StatusResponse,
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
  ErrorResponse,
} from "./types.js";
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
  hexToBytes,
} from "./encoding.js";
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
const SIGN_CANCEL_TIMEOUT = 5000;
const SIGN_APPROVAL_SLACK = 30000;
const DEFAULT_SIGN_REQUEST_TIMEOUT = 360000;
const MAX_DISCOVERED_APPROVAL_WAIT = 1800000;
const APPROVAL_WAIT_REFRESH = 300000;
const MAX_SIGN_REQUEST_ID_LENGTH = 128;

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
                `to trust this host, set ssh.trust_on_first_use: true in config.yaml, ` +
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
export class SignerClient {
  private baseUrl: string;
  private token: string;
  private explicitTimeout?: number;
  private keyCache: Map<string, KeyInfo> = new Map();
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
   *   - config.yaml: Connection settings (signer_port, ssh)
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
      "No ssh block in config.yaml. " +
      "Add an ssh block with host, port, and identity_file."
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
      throw new SignerError(
        await this.errorMessage(response, `Failed to get signer status: HTTP ${response.status}`)
      );
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
      throw new SignerError(
        await this.errorMessage(response, `Failed to list keys: HTTP ${response.status}`)
      );
    }

    const data = (await response.json()) as KeysResponse;
    const keys: KeyInfo[] = [];

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
      throw new SignerError(
        await this.errorMessage(response, `Failed to list key types: HTTP ${response.status}`)
      );
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
      throw new SignerUnavailableError("Signer is locked");
    }
    if (response.status === 400) {
      throw new SignerError(await this.errorMessage(response, "Bad request"));
    }
    if (response.status !== 200) {
      throw new SignerError(
        await this.errorMessage(response, `Key generation failed: HTTP ${response.status}`)
      );
    }

    const data = (await response.json()) as Record<string, unknown>;
    if (data.error) {
      throw new SignerError(String(data.error));
    }

    // Invalidate key cache
    this.keyCache.clear();

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
      throw new SignerUnavailableError("Signer is locked");
    }
    if (response.status === 404) {
      throw new KeyDeletionError(await this.errorMessage(response, `Key not found: ${address}`));
    }
    if (response.status !== 200) {
      throw new SignerError(
        await this.errorMessage(response, `Key deletion failed: HTTP ${response.status}`)
      );
    }

    const data = await this.safeJson(response);
    if (data.error) {
      throw new SignerError(String(data.error));
    }

    // Invalidate key cache
    this.keyCache.clear();
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
      throw new SignerError(
        await this.errorMessage(response, `Sign cancel failed: HTTP ${response.status}`)
      );
    }

    const data = (await response.json()) as CancelSignResponse;
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
      const error = await this.errorMessage(response, "");
      if (error.toLowerCase().includes("not found")) {
        throw new KeyNotFoundError(error);
      }
      throw new SignerError(`Bad request: ${error}`);
    }
    if (response.status === 403) {
      throw new SignerError(await this.errorMessage(response, "Forbidden"));
    }
    if (response.status !== 200) {
      throw new SignerError(await this.errorMessage(response, `Plan failed: HTTP ${response.status}`));
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
      const error = await this.errorMessage(response, "");
      if (error.toLowerCase().includes("not found")) {
        throw new KeyNotFoundError(error);
      }
      throw new SignerError(`Bad request: ${error}`);
    }

    if (response.status === 403) {
      const error = await this.errorMessage(response, "Signing request rejected by operator");
      throw new SigningRejectedError(error);
    }

    if (response.status === 503) {
      const error = await this.errorMessage(response, "Signer unavailable");
      throw new SignerUnavailableError(error);
    }

    if (response.status !== 200) {
      throw new SignerError(await this.errorMessage(response, `Signing failed: HTTP ${response.status}`));
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

    return data;
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
    try {
      const jsonResponse =
        typeof response.clone === "function" ? response.clone() : response;
      const data = (await jsonResponse.json()) as Partial<ErrorResponse>;
      if (typeof data.error === "string" && data.error.trim() !== "") {
        return data.error;
      }
    } catch {
      // Fall through to text/fallback handling.
    }

    try {
      const textResponse =
        typeof response.clone === "function" ? response.clone() : response;
      const text = (await textResponse.text()).trim();
      if (text !== "") {
        return text;
      }
    } catch {
      // Fall through to fallback.
    }

    return fallback;
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
