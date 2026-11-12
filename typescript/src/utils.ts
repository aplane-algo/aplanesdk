// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import * as fs from "fs";
import * as path from "path";
import { createHash } from "crypto";
import {
  SignerError,
  EnrollmentError,
} from "./errors.js";
import {
  loadConfig,
  isNetworkAllowed,
  loadClientEndpointRegistry,
  resolveClientEndpoint,
  clientEndpointSshHostPort,
  resolveDataDir,
  expandPath,
  DEFAULT_SSH_PORT,
} from "./config.js";
import {
  SSH_ENROLLMENT_COMMAND,
  SSH_ENROLLMENT_USERNAME,
  normalizeSSHSetupTimeout,
  sshConnectionFailedMessage,
  validateEnrollmentLabel,
} from "./ssh.js";

// Re-export config utilities
export {
  loadConfig,
  isNetworkAllowed,
  loadClientEndpointRegistry,
  resolveClientEndpoint,
  resolveDataDir,
  expandPath,
};

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

/** Options for requestEnrollment. */
export interface RequestEnrollmentOptions {
  /** SSH port on the signer (default: 1127) */
  sshPort?: number;
  /** Path to the known_hosts file that pins the signer's host key (required) */
  knownHostsPath?: string;
  /** If true, trust and save an unknown host key (TOFU). Default: false */
  autoAddHost?: boolean;
  /** Optional display label shown to the operator (printable, single line, <= 64 bytes) */
  label?: string;
  /** TCP connection and SSH authentication timeout in milliseconds (default: 60000) */
  setupTimeout?: number;
  /** Optional cancellation signal; also abandons the wait for the operator */
  signal?: AbortSignal;
}

/** The signer's answer to an enrollment request. */
export interface EnrollmentResult {
  /**
   * SHA256 fingerprint of the client key the request was made with; it
   * equals the key the client authenticated with.
   */
  fingerprint: string;
  /**
   * True when the request was queued for the operator to approve later in
   * apadmin (the normal outcome); false when the key was already enrolled.
   */
  pending: boolean;
}

/**
 * Parses the signer's answer: "pending <fingerprint>" when the request was
 * queued for the operator, "enrolled <fingerprint>" when the key was already
 * enrolled. The fingerprint must be the key this client authenticated with.
 */
export function parseEnrollmentReply(reply: string, clientFingerprint: string): EnrollmentResult {
  let result: EnrollmentResult;
  if (reply.startsWith("pending ")) {
    result = { fingerprint: reply.slice("pending ".length), pending: true };
  } else if (reply.startsWith("enrolled ")) {
    result = { fingerprint: reply.slice("enrolled ".length), pending: false };
  } else {
    throw new EnrollmentError(`Unexpected enrollment response: ${JSON.stringify(reply)}`);
  }
  if (!result.fingerprint) {
    throw new EnrollmentError(`Unexpected enrollment response: ${JSON.stringify(reply)}`);
  }
  if (result.fingerprint !== clientFingerprint) {
    throw new EnrollmentError(
      `Signer answered for ${result.fingerprint}, but this client authenticated with ${clientFingerprint}`
    );
  }
  return result;
}

/**
 * Ask the signer to enroll this client's SSH key, so the key can open API
 * connections. The signer answers at once: the request is queued for the
 * operator to approve later in apadmin (`pending: true`, the normal
 * outcome), or the key is already enrolled. Nothing waits for the operator
 * and nothing is stored on the client: the key is its credential, and the
 * client learns the outcome by connecting after approval (an unenrolled key
 * still fails the handshake).
 *
 * @param host - Signer host
 * @param sshKeyPath - Path to the client's SSH private key
 * @param options - sshPort, knownHostsPath, autoAddHost, label, setupTimeout, signal
 * @returns The key's fingerprint (SHA256:...) and whether approval is pending
 */
export async function requestEnrollment(
  host: string,
  sshKeyPath: string,
  options: RequestEnrollmentOptions = {}
): Promise<EnrollmentResult> {
  const sshPort = options.sshPort ?? DEFAULT_SSH_PORT;
  const setupTimeout = normalizeSSHSetupTimeout(options.setupTimeout);
  const label = options.label ?? "";
  try {
    validateEnrollmentLabel(label);
  } catch (error) {
    throw new SignerError(error instanceof Error ? error.message : String(error));
  }
  if (!options.knownHostsPath) {
    throw new SignerError("known_hosts path is required for SSH host key verification");
  }
  // ssh2 is CommonJS; under ESM interop only some of its exports are
  // detected as named, so take utils from the default export when needed.
  const ssh2 = await import("ssh2");
  const Client = ssh2.Client;
  const utils = ssh2.utils ?? (ssh2 as unknown as { default: typeof ssh2 }).default.utils;
  const expandedKeyPath = expandPath(sshKeyPath);
  const knownHostsPath = expandPath(options.knownHostsPath);

  if (!fs.existsSync(expandedKeyPath)) {
    throw new SignerError(`SSH key not found: ${expandedKeyPath}`);
  }

  const privateKey = fs.readFileSync(expandedKeyPath, "utf-8");
  const parsedKey = utils.parseKey(privateKey);
  if (parsedKey instanceof Error) {
    throw new SignerError(`failed to parse SSH key ${expandedKeyPath}: ${parsedKey.message}`);
  }
  const clientFingerprint = sshFingerprintSHA256(parsedKey.getPublicSSH());
  const command = label ? `${SSH_ENROLLMENT_COMMAND} ${label}` : SSH_ENROLLMENT_COMMAND;

  return new Promise((resolve, reject) => {
    const client = new Client();
    let hostKeyError = "";
    let settled = false;
    const cleanupSetup = () => options.signal?.removeEventListener("abort", abortSetup);
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      cleanupSetup();
      fn();
    };
    const abortSetup = () => {
      finish(() => {
        client.destroy();
        reject(new EnrollmentError("SSH setup canceled"));
      });
    };
    if (options.signal?.aborted) {
      abortSetup();
      return;
    }
    options.signal?.addEventListener("abort", abortSetup, { once: true });

    client.on("ready", () => {
      client.exec(command, (err: Error | undefined, channel: import("ssh2").ClientChannel) => {
        if (err) {
          client.end();
          finish(() => reject(new EnrollmentError(`Failed to start enrollment: ${err.message}`)));
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
          finish(() => {
            if (code !== 0) {
              const errorMsg = (stderr.trim() || stdout.trim() || "Enrollment rejected")
                .replace(/^ERROR: /, "");
              reject(new EnrollmentError(errorMsg));
              return;
            }
            try {
              resolve(parseEnrollmentReply(stdout.trim(), clientFingerprint));
            } catch (error) {
              reject(error);
            }
          });
        });
      });
    });

    client.on("error", (err: Error) => {
      finish(() => reject(new EnrollmentError(
        hostKeyError || sshConnectionFailedMessage(err, SSH_ENROLLMENT_USERNAME)
      )));
    });

    // ssh2 reports a peer that disconnects mid-handshake with close alone and
    // clears readyTimeout, so an unfinished setup must fail here.
    client.on("close", () => {
      finish(() => reject(new EnrollmentError(
        hostKeyError || "SSH connection closed before setup completed"
      )));
    });

    client.connect({
      host,
      port: sshPort,
      username: SSH_ENROLLMENT_USERNAME,
      privateKey,
      readyTimeout: setupTimeout,
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

/** SHA256 fingerprint of an SSH public key in wire format, as OpenSSH prints it. */
function sshFingerprintSHA256(publicKeyWire: Buffer): string {
  const digest = createHash("sha256").update(publicKeyWire).digest("base64");
  return `SHA256:${digest.replace(/=+$/, "")}`;
}

/** Options for requestEnrollmentFromEnv. */
export interface RequestEnrollmentFromEnvOptions {
  /** Client data directory (default: APCLIENT_DATA) */
  dataDir?: string;
  /** Endpoint alias (default: the registry's signer endpoint) */
  endpoint?: string;
  /** If true, trust and save an unknown host key (TOFU). Default: false */
  autoAddHost?: boolean;
  /** Optional display label shown to the operator */
  label?: string;
  /** TCP connection and SSH authentication timeout in milliseconds (default: 60000) */
  setupTimeout?: number;
  /** Optional cancellation signal */
  signal?: AbortSignal;
}

/**
 * Ask the endpoint selected from the data directory's endpoints.yaml (the
 * default signer, or `endpoint`) to enroll the client key configured for it.
 * See requestEnrollment for the result; nothing is stored.
 */
export async function requestEnrollmentFromEnv(
  options: RequestEnrollmentFromEnvOptions = {}
): Promise<EnrollmentResult> {
  const rawOptions = options as Record<string, unknown>;
  for (const removed of ["host", "sshPort", "identity"]) {
    if (removed in rawOptions) {
      throw new SignerError(
        `requestEnrollmentFromEnv option "${removed}" was removed; configure and select an endpoints.yaml alias`,
      );
    }
  }
  const dataDir = resolveDataDir(options.dataDir);
  loadConfig(dataDir);
  const registry = loadClientEndpointRegistry(dataDir);
  const { endpoint } = resolveClientEndpoint(registry, options.endpoint);
  const { host, port: sshPort } = clientEndpointSshHostPort(endpoint);
  const sshKeyPath = endpoint.identityFile;
  const knownHostsPath = endpoint.knownHostsPath;

  if (!fs.existsSync(sshKeyPath)) {
    throw new SignerError(
      `SSH key not found at ${sshKeyPath}\n` +
      `Create one with: ssh-keygen -t ed25519 -f ${sshKeyPath}`
    );
  }

  return requestEnrollment(host, sshKeyPath, {
    sshPort,
    knownHostsPath,
    autoAddHost: options.autoAddHost,
    label: options.label,
    setupTimeout: options.setupTimeout,
    signal: options.signal,
  });
}
