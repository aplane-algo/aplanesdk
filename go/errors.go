// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"errors"
	"fmt"
)

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

// Stable machine-readable error codes carried in ErrorResponse.Code.
// These mirror the signer wire contract (pkg/signerapi/error_codes.go in the
// aplane repo). An empty code means the signer predates code support.
const (
	ErrCodeBadRequest           = "bad_request"
	ErrCodeUnauthorized         = "unauthorized"
	ErrCodeForbidden            = "forbidden"
	ErrCodeLocked               = "locked"
	ErrCodeNotFound             = "not_found"
	ErrCodeInvalidPassphrase    = "invalid_passphrase"
	ErrCodeUnavailable          = "unavailable"
	ErrCodeCacheRefresh         = "cache_refresh"
	ErrCodeInternal             = "internal"
	ErrCodeBoundedAdminRequired = "bounded_admin_required"
)

// APIError preserves the HTTP status, stable wire error code, and message of
// a non-2xx signer response for callers that need to classify failures
// without matching message text. Code is empty when the signer predates wire
// error codes.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	// Op optionally names the failed operation for message formatting
	// (e.g. "plan failed"); empty means the generic "signer error" prefix.
	Op string
}

func (e *APIError) Error() string {
	if e == nil {
		return "signer error"
	}
	op := e.Op
	if op == "" {
		op = "signer error"
	}
	return fmt.Sprintf("%s (%d): %s", op, e.StatusCode, e.Message)
}

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
