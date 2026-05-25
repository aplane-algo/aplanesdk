// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import "errors"

// Signing errors
var (
	// ErrAuthentication indicates invalid or missing token (HTTP 401).
	ErrAuthentication = errors.New("authentication failed: invalid or missing token")

	// ErrSigningRejected indicates the operator rejected the request (HTTP 403).
	ErrSigningRejected = errors.New("signing rejected by operator")

	// ErrSignerUnavailable indicates the signer is not reachable or locked (HTTP 503).
	ErrSignerUnavailable = errors.New("signer unavailable")

	// ErrKeyNotFound indicates the requested key is not in the signer.
	ErrKeyNotFound = errors.New("key not found in signer")

	// ErrSignerLocked indicates the signer is locked and requires unlock.
	ErrSignerLocked = errors.New("signer is locked")

	// ErrKeyDeletion indicates a key deletion failed (e.g., key not found).
	ErrKeyDeletion = errors.New("key deletion failed")
)

// Transaction submission errors
var (
	// ErrLogicSigRejected indicates the LogicSig program returned false.
	ErrLogicSigRejected = errors.New("LogicSig program rejected")

	// ErrInsufficientFunds indicates the account has insufficient balance.
	ErrInsufficientFunds = errors.New("insufficient funds")

	// ErrInvalidTransaction indicates the transaction is malformed or invalid.
	ErrInvalidTransaction = errors.New("invalid transaction")

	// ErrTransactionRejected indicates the transaction was rejected by the network.
	ErrTransactionRejected = errors.New("transaction rejected")
)

// Configuration errors
var (
	// ErrConfigNotFound indicates config.yaml was not found.
	ErrConfigNotFound = errors.New("config.yaml not found")

	// ErrTokenNotFound indicates aplane.token was not found.
	ErrTokenNotFound = errors.New("aplane.token not found")
)

// TransactionError wraps a transaction rejection with details.
type TransactionError struct {
	TxID   string
	Reason string
	Err    error
}

func (e *TransactionError) Error() string {
	if e.TxID != "" {
		return e.Err.Error() + ": " + e.Reason + " (txid: " + e.TxID + ")"
	}
	return e.Err.Error() + ": " + e.Reason
}

func (e *TransactionError) Unwrap() error {
	return e.Err
}
