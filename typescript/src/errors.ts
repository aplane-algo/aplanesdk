// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * Base exception for signer errors.
 */
export class SignerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignerError";
  }
}

/**
 * Token invalid or missing (HTTP 401).
 */
export class AuthenticationError extends SignerError {
  constructor(message: string = "Invalid or missing token") {
    super(message);
    this.name = "AuthenticationError";
  }
}

/**
 * Operator rejected the signing request (HTTP 403).
 */
export class SigningRejectedError extends SignerError {
  constructor(message: string = "Signing request rejected by operator") {
    super(message);
    this.name = "SigningRejectedError";
  }
}

/**
 * Signer not reachable or locked (HTTP 503, timeout, network error).
 */
export class SignerUnavailableError extends SignerError {
  constructor(message: string = "Signer not reachable or locked") {
    super(message);
    this.name = "SignerUnavailableError";
  }
}

/**
 * Requested auth_address not found in signer.
 */
export class KeyNotFoundError extends SignerError {
  constructor(message: string = "Key not found in signer") {
    super(message);
    this.name = "KeyNotFoundError";
  }
}

/**
 * Key deletion failed (not found or other error).
 */
export class KeyDeletionError extends SignerError {
  constructor(message: string = "Key deletion failed") {
    super(message);
    this.name = "KeyDeletionError";
  }
}

/**
 * Token provisioning failed (rejected or no operator).
 */
export class TokenProvisioningError extends SignerError {
  constructor(message: string = "Token provisioning failed") {
    super(message);
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
