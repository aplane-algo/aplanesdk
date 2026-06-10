// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import type { Algodv2 } from "algosdk";
import {
  TransactionRejectedError,
  LogicSigRejectedError,
  InsufficientFundsError,
  InvalidTransactionError,
} from "./errors.js";

import * as fs from "fs";
import * as path from "path";
import {
  SignerError,
  TokenProvisioningError,
} from "./errors.js";
import {
  loadConfig,
  loadToken,
  resolveDataDir,
  expandPath,
  DEFAULT_SSH_PORT,
} from "./config.js";

// Re-export config utilities
export { loadToken, loadConfig, resolveDataDir, expandPath };

// Current product identity for token provisioning helpers.
export const DEFAULT_PRODUCT_IDENTITY = "default";

function requireCurrentProductIdentity(identity: string): void {
  if (identity !== DEFAULT_PRODUCT_IDENTITY) {
    throw new SignerError(
      `unsupported identity: ${identity} (only '${DEFAULT_PRODUCT_IDENTITY}' is currently supported)`
    );
  }
}

function parseHostKeyType(key: Buffer): string {
  if (key.length < 4) return "unknown";
  const typeLen = key.readUInt32BE(0);
  if (key.length < 4 + typeLen) return "unknown";
  return key.subarray(4, 4 + typeLen).toString("ascii");
}

function formatHostEntry(host: string, port: number): string {
  return port === 22 ? host : `[${host}]:${port}`;
}

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
 * Submit a signed transaction to the network with clean error handling.
 *
 * @param algodClient - algosdk Algodv2 client instance
 * @param signedTxn - Base64-encoded string from signTransaction()
 * @returns Transaction ID
 *
 * @throws LogicSigRejectedError - If a LogicSig program returned false
 * @throws InsufficientFundsError - If account has insufficient funds
 * @throws InvalidTransactionError - If transaction is malformed
 * @throws TransactionRejectedError - For other rejection reasons
 *
 * @example
 * ```typescript
 * const signed = await client.signTransaction(txn);
 * const txid = await sendRawTransaction(algodClient, signed);
 * console.log(`Submitted: ${txid}`);
 * ```
 *
 * Note: You can also use algodClient.sendRawTransaction() directly
 * if you don't need the clean error types.
 */
export async function sendRawTransaction(
  algodClient: Algodv2,
  signedTxn: string
): Promise<string> {
  try {
    const txnBytes = Buffer.from(signedTxn, "base64");
    const response = await algodClient.sendRawTransaction(txnBytes).do();
    return response.txid;
  } catch (error) {
    throw parseAlgodError(error);
  }
}

/**
 * Parse algod HTTP error into a clean aplane exception.
 */
function parseAlgodError(error: unknown): Error {
  const msg = String(error);

  // Try to extract transaction ID
  let txid = "unknown";
  const txidMatch = msg.match(/transaction ([A-Z0-9]{52}):/);
  if (txidMatch) {
    txid = txidMatch[1];
  }

  // LogicSig rejection
  if (msg.toLowerCase().includes("rejected by logic")) {
    return new LogicSigRejectedError(txid);
  }

  // Insufficient funds / overspend
  if (
    msg.toLowerCase().includes("overspend") ||
    msg.toLowerCase().includes("insufficient funds")
  ) {
    const balanceMatch = msg.match(/tried to spend \{(\d+)\}/);
    if (balanceMatch) {
      return new InsufficientFundsError(
        txid,
        `insufficient funds (tried to spend ${balanceMatch[1]} microAlgos)`
      );
    }
    return new InsufficientFundsError(txid);
  }

  // LogicSig pool budget exceeded
  if (
    msg.toLowerCase().includes("logicsigs") &&
    msg.toLowerCase().includes("pool")
  ) {
    const poolMatch = msg.match(/had (\d+) bytes.*pool of (\d+) bytes/);
    if (poolMatch) {
      return new InvalidTransactionError(
        txid,
        `LogicSig too large (${poolMatch[1]} bytes exceeds ${poolMatch[2]} byte pool). ` +
          "Fee pooling should be automatic - ensure you're using signTransaction() or signTransactions()."
      );
    }
    return new InvalidTransactionError(
      txid,
      "LogicSig exceeds pool budget - fee pooling should be automatic via signTransaction()"
    );
  }

  // Invalid group ID
  if (
    msg.toLowerCase().includes("group") &&
    (msg.toLowerCase().includes("invalid") ||
      msg.toLowerCase().includes("mismatch"))
  ) {
    return new InvalidTransactionError(txid, "invalid or mismatched group ID");
  }

  // Fee too low
  if (
    msg.toLowerCase().includes("fee") &&
    (msg.toLowerCase().includes("too small") ||
      msg.toLowerCase().includes("below"))
  ) {
    return new InvalidTransactionError(txid, "transaction fee too low");
  }

  // Round range errors
  if (
    msg.toLowerCase().includes("round") &&
    (msg.toLowerCase().includes("past") ||
      msg.toLowerCase().includes("future") ||
      msg.toLowerCase().includes("invalid"))
  ) {
    return new InvalidTransactionError(
      txid,
      "transaction round range invalid (expired or too far in future)"
    );
  }

  // Generic rejection - extract a cleaner message if possible
  const reasonMatch = msg.match(/\}: (.+?)(?:\s*$|\s*\{)/);
  if (reasonMatch && reasonMatch[1].trim()) {
    return new TransactionRejectedError(txid, reasonMatch[1].trim());
  }

  // Fallback: return generic error with truncated message
  const truncated = msg.length > 200 ? msg.slice(0, 200) + "..." : msg;
  return new TransactionRejectedError(txid, truncated);
}

/**
 * Merge multi-party signed outputs into one complete group.
 *
 * Each signer produces a list of base64-encoded signed transactions,
 * with empty strings ("") for slots they didn't sign (foreign entries).
 * This function merges them so each slot has exactly one non-empty entry.
 *
 * @param signedLists - List of signed transaction lists from different signers
 * @returns Base64-encoded concatenated signed transactions
 *
 * @example
 * ```typescript
 * // Alice signs her txns, gets "" for Bob's slots
 * const aliceSigned = await aliceClient.signTransactionsList(...);
 * // Bob signs his txns, gets "" for Alice's slots
 * const bobSigned = await bobClient.signTransactionsList(...);
 * // Merge and submit
 * const combined = assembleGroup([aliceSigned, bobSigned]);
 * await sendRawTransaction(algodClient, combined);
 * ```
 */
export function assembleGroup(signedLists: string[][]): string {
  if (signedLists.length === 0) {
    throw new SignerError("signedLists must not be empty");
  }

  const groupLen = signedLists[0].length;
  for (let i = 0; i < signedLists.length; i++) {
    if (signedLists[i].length !== groupLen) {
      throw new SignerError(
        `signedLists[${i}] has ${signedLists[i].length} entries, expected ${groupLen}`
      );
    }
  }

  const merged: string[] = [];
  for (let idx = 0; idx < groupLen; idx++) {
    const entries = signedLists
      .map((sl) => sl[idx])
      .filter((s) => s !== "");
    if (entries.length === 0) {
      throw new SignerError(`slot ${idx}: no signer provided a signed transaction`);
    }
    if (entries.length > 1) {
      throw new SignerError(`slot ${idx}: multiple signers provided a signed transaction`);
    }
    merged.push(entries[0]);
  }

  // Concatenate all signed txns
  const buffers = merged.map((s) => Buffer.from(s, "base64"));
  const totalLength = buffers.reduce((sum, b) => sum + b.length, 0);
  const combined = Buffer.alloc(totalLength);
  let offset = 0;
  for (const buf of buffers) {
    buf.copy(combined, offset);
    offset += buf.length;
  }
  return combined.toString("base64");
}

/**
 * Request an API token from apsigner via SSH.
 *
 * Connects to the signer's SSH server and requests a token.
 * An operator (apadmin) must approve the request on the server side.
 *
 * @param host - Signer host
 * @param sshKeyPath - Path to SSH private key
 * @param options - Optional: sshPort, identity, knownHostsPath, autoAddHost.
 * Non-product identities are rejected in the current single-operator mode.
 * @returns The provisioned token string
 */
export async function requestToken(
  host: string,
  sshKeyPath: string,
  options: {
    sshPort?: number;
    identity?: string;
    knownHostsPath?: string;
    autoAddHost?: boolean;
  } = {}
): Promise<string> {
  const sshPort = options.sshPort ?? DEFAULT_SSH_PORT;
  const identity = options.identity ?? DEFAULT_PRODUCT_IDENTITY;
  requireCurrentProductIdentity(identity);
  if (!options.knownHostsPath) {
    throw new SignerError("known_hosts path is required for SSH host key verification");
  }
  const { Client } = await import("ssh2");
  const expandedKeyPath = expandPath(sshKeyPath);
  const knownHostsPath = expandPath(options.knownHostsPath);

  if (!fs.existsSync(expandedKeyPath)) {
    throw new SignerError(`SSH key not found: ${expandedKeyPath}`);
  }

  const privateKey = fs.readFileSync(expandedKeyPath, "utf-8");
  const username = `request-token:${identity}`;

  return new Promise((resolve, reject) => {
    const client = new Client();
    let hostKeyError = "";

    client.on("ready", () => {
      client.exec("provision", (err: Error | undefined, channel: import("ssh2").ClientChannel) => {
        if (err) {
          client.end();
          reject(new TokenProvisioningError(`Failed to execute provision: ${err.message}`));
          return;
        }

        let stdout = "";
        let stderr = "";

        channel.on("data", (data: Buffer) => {
          stdout += data.toString();
        });

        channel.stderr.on("data", (data: Buffer) => {
          stderr += data.toString();
        });

        channel.on("close", (code: number) => {
          client.end();
          if (code !== 0) {
            const errorMsg = stderr.trim() || stdout.trim() || "Token provisioning rejected";
            reject(new TokenProvisioningError(errorMsg));
            return;
          }
          const token = stdout.trim();
          if (!token) {
            reject(new TokenProvisioningError("Empty token received"));
            return;
          }
          resolve(token);
        });
      });
    });

    client.on("error", (err: Error) => {
      reject(new TokenProvisioningError(hostKeyError || `SSH connection failed: ${err.message}`));
    });

    client.connect({
      host,
      port: sshPort,
      username,
      privateKey,
      hostVerifier: (key: Buffer): boolean => {
        const storedKey = loadKnownHostKey(knownHostsPath, host, sshPort);

        if (storedKey === null) {
          if (!options.autoAddHost) {
            hostKeyError =
              `Unknown SSH host key for ${formatHostEntry(host, sshPort)}; ` +
              `pass autoAddHost: true to trust on first use, or save the host key in ${knownHostsPath}`;
            return false;
          }
          saveHostKey(knownHostsPath, host, sshPort, key);
          return true;
        }

        if (storedKey.equals(key)) {
          return true;
        }

        hostKeyError =
          `SSH host key mismatch for ${formatHostEntry(host, sshPort)} ` +
          `(possible MITM attack); remove the old key from ${knownHostsPath} to connect`;
        return false;
      },
    });
  });
}

/**
 * Request a token and save it to the data directory.
 *
 * Convenience function that:
 * 1. Loads SSH key from config's identity_file
 * 2. Uses config's known_hosts_path for host verification
 * 3. Saves the token to data_dir/aplane.token
 *
 * @param options - Optional: dataDir, host, sshPort, identity, autoAddHost.
 * Non-product identities are rejected in the current single-operator mode.
 * @returns Path to the saved token file
 */
export async function requestTokenToFile(
  options: {
    dataDir?: string;
    host?: string;
    sshPort?: number;
    identity?: string;
    autoAddHost?: boolean;
  } = {}
): Promise<string> {
  const dataDir = resolveDataDir(options.dataDir);
  const config = loadConfig(dataDir);

  let host = options.host;
  if (!host) {
    if (!config.ssh?.host) {
      throw new SignerError(
        "No host specified and no endpoint.ssh.host in config.yaml. " +
        "Pass host option or add endpoint.ssh block to config.yaml."
      );
    }
    host = config.ssh.host;
  }

  const sshPort = options.sshPort ?? config.ssh?.port ?? DEFAULT_SSH_PORT;
  const sshKeyPath = config.ssh
    ? path.join(dataDir, config.ssh.identityFile)
    : path.join(dataDir, ".ssh", "id_ed25519");
  const knownHostsPath = config.ssh
    ? path.join(dataDir, config.ssh.knownHostsPath)
    : path.join(dataDir, ".ssh", "known_hosts");

  if (!fs.existsSync(sshKeyPath)) {
    throw new SignerError(
      `SSH key not found at ${sshKeyPath}\n` +
      `Create one with: ssh-keygen -t ed25519 -f ${sshKeyPath}`
    );
  }

  const token = await requestToken(host, sshKeyPath, {
    sshPort,
    identity: options.identity,
    knownHostsPath,
    autoAddHost: options.autoAddHost,
  });

  // Save token with secure permissions
  const tokenPath = path.join(dataDir, "aplane.token");
  fs.writeFileSync(tokenPath, token, { mode: 0o600 });

  return tokenPath;
}
