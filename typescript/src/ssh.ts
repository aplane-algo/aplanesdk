// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * SSH usernames the signer's SSH server recognizes: SSH_USERNAME for API
 * connections authenticated by an enrolled key, SSH_ENROLLMENT_USERNAME for
 * an enroll session.
 */
export const SSH_USERNAME = "aplane";
export const SSH_ENROLLMENT_USERNAME = "enroll";
export const DEFAULT_SSH_SETUP_TIMEOUT_MS = 60_000;
/** Largest delay Node timers represent exactly (2^31 - 1 ms). */
export const MAX_SSH_SETUP_TIMEOUT_MS = 2_147_483_647;

/**
 * The exec command an enroll session runs, and the longest
 * display label the signer accepts with it.
 */
export const SSH_ENROLLMENT_COMMAND = "enroll";
export const MAX_ENROLLMENT_LABEL_BYTES = 64;

export function normalizeSSHSetupTimeout(value?: number): number {
  if (value === undefined) {
    return DEFAULT_SSH_SETUP_TIMEOUT_MS;
  }
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error("SSH setup timeout must be a positive number of milliseconds");
  }
  if (value > MAX_SSH_SETUP_TIMEOUT_MS) {
    throw new Error(`SSH setup timeout must not exceed ${MAX_SSH_SETUP_TIMEOUT_MS} milliseconds`);
  }
  return value;
}

/**
 * Validates an enrollment label locally so a bad label fails before any
 * network activity: printable, single line, at most 64 bytes, no leading or
 * trailing whitespace.
 */
export function validateEnrollmentLabel(label: string): void {
  if (label === "") return;
  if (Buffer.byteLength(label, "utf8") > MAX_ENROLLMENT_LABEL_BYTES) {
    throw new Error(`enrollment label must be at most ${MAX_ENROLLMENT_LABEL_BYTES} bytes`);
  }
  if (label.trim() !== label) {
    throw new Error("enrollment label must not start or end with whitespace");
  }
  for (const char of label) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) {
      throw new Error("enrollment label must be printable and single-line");
    }
  }
}

/**
 * Why an SSH connection could not be set up, when the cause is the client's
 * own files or the host's key rather than the network: the host's key differs
 * from the pinned one, the host has no pinned key and trust-on-first-use is
 * off, the known_hosts file cannot be read or written, or the client's
 * identity file cannot be read.
 */
export type SshSetupFailure = "host-key-mismatch" | "unknown-host-key" | "known-hosts" | "identity";

// Under a registered symbol, so the mark is the same whichever build of the
// package made the error.
const SSH_SETUP_FAILURE = Symbol.for("aplanesdk.sshSetupFailure");

/** Mark error as an SSH setup failure of the given kind, and return it. */
export function markSshSetupFailure<T extends Error>(error: T, kind: SshSetupFailure): T {
  Object.defineProperty(error, SSH_SETUP_FAILURE, { value: kind, enumerable: false, configurable: true });
  return error;
}

/** The kind of SSH setup failure error is marked with, if any. */
export function sshSetupFailure(error: unknown): SshSetupFailure | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const kind = (error as Record<symbol, unknown>)[SSH_SETUP_FAILURE];
  return typeof kind === "string" ? (kind as SshSetupFailure) : undefined;
}

/**
 * Client SSH keys the signer accepts. The signer refuses other key types (RSA,
 * DSA, certificates) before signature verification.
 */
export const CLIENT_SSH_KEY_REQUIREMENT =
  "Ed25519, ECDSA (P-256/384/521), or hardware-backed sk- Ed25519/ECDSA";

/**
 * Formats an SSH connection error. When the failure is client
 * authentication, the message names the accepted key types and, for an API
 * connection, says the key is not enrolled: the signer refuses unsupported
 * key types before verifying a signature, so a refused supported key is one
 * it has not enrolled.
 */
export function sshConnectionFailedMessage(err: Error, username: string = SSH_USERNAME): string {
  const message = `SSH connection failed: ${err.message}`;
  if ((err as Error & { level?: string }).level === "client-authentication") {
    if (username === SSH_USERNAME) {
      return `${message}: the client's SSH key is not enrolled at the signer, or was revoked ` +
        `(the signer accepts ${CLIENT_SSH_KEY_REQUIREMENT} client keys); ` +
        "enroll it with requestEnrollment or apshell enroll";
    }
    return `${message} (the signer accepts ${CLIENT_SSH_KEY_REQUIREMENT} client keys)`;
  }
  return message;
}
