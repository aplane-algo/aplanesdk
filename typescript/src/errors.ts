// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * Base exception for signer errors.
 *
 * `code` carries the stable machine-readable wire error code from the signer
 * when one was provided (see ErrorCodes in types.ts); branch on it instead of
 * matching message text. Empty when the signer predates wire error codes or
 * the error was raised client-side.
 */
export class SignerError extends Error {
  code: string;

  constructor(message: string, code: string = "") {
    super(message);
    this.name = "SignerError";
    this.code = code;
  }
}

/**
 * Token invalid or missing (HTTP 401).
 */
export class AuthenticationError extends SignerError {
  constructor(message: string = "Invalid or missing token", code: string = "") {
    super(message, code);
    this.name = "AuthenticationError";
  }
}

/**
 * Operator rejected the signing request (HTTP 403).
 */
export class SigningRejectedError extends SignerError {
  constructor(message: string = "Signing request rejected by operator", code: string = "") {
    super(message, code);
    this.name = "SigningRejectedError";
  }
}

/**
 * Signer not reachable or locked (HTTP 503, timeout, network error).
 */
export class SignerUnavailableError extends SignerError {
  constructor(message: string = "Signer not reachable or locked", code: string = "") {
    super(message, code);
    this.name = "SignerUnavailableError";
  }
}

/**
 * Requested auth_address not found in signer.
 */
export class KeyNotFoundError extends SignerError {
  constructor(message: string = "Key not found in signer", code: string = "") {
    super(message, code);
    this.name = "KeyNotFoundError";
  }
}

/**
 * Key deletion failed (not found or other error).
 */
export class KeyDeletionError extends SignerError {
  constructor(message: string = "Key deletion failed", code: string = "") {
    super(message, code);
    this.name = "KeyDeletionError";
  }
}

/**
 * Token provisioning failed (rejected or no operator).
 */
export class TokenProvisioningError extends SignerError {
  constructor(message: string = "Token provisioning failed", code: string = "") {
    super(message, code);
    this.name = "TokenProvisioningError";
  }
}

/**
 * Transaction was rejected by the network.
 */
export class TransactionRejectedError extends SignerError {
  /** Transaction ID (if known) */
  txid: string;
  /** Rejection reason */
  reason: string;

  constructor(txid: string, reason: string) {
    super(`Transaction ${txid} rejected: ${reason}`);
    this.name = "TransactionRejectedError";
    this.txid = txid;
    this.reason = reason;
  }
}

/**
 * LogicSig program returned false.
 */
export class LogicSigRejectedError extends TransactionRejectedError {
  constructor(txid: string, reason: string = "LogicSig program returned false") {
    super(txid, reason);
    this.name = "LogicSigRejectedError";
  }
}

/**
 * Account has insufficient funds for the transaction.
 */
export class InsufficientFundsError extends TransactionRejectedError {
  constructor(txid: string, reason: string = "Insufficient funds") {
    super(txid, reason);
    this.name = "InsufficientFundsError";
  }
}

/**
 * Transaction is malformed or invalid.
 */
export class InvalidTransactionError extends TransactionRejectedError {
  constructor(txid: string, reason: string = "Invalid transaction") {
    super(txid, reason);
    this.name = "InvalidTransactionError";
  }
}
