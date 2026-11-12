// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"errors"
	"fmt"
)

// Signing errors
var (
	// ErrAuthentication indicates the signer refused the request as
	// unauthenticated (HTTP 401): the connection did not arrive through an
	// enrolled SSH key.
	ErrAuthentication = errors.New("authentication failed: connect through an enrolled SSH key")

	// ErrNotEnrolled indicates the signer refused the client's SSH key at the
	// handshake: it is not enrolled there, or was revoked. Enroll it with
	// RequestEnrollment (or apshell enroll) and have the operator
	// approve.
	ErrNotEnrolled = errors.New("SSH key is not enrolled at the signer")

	// ErrEnrollment indicates an enroll session failed: the
	// operator rejected it, no operator was connected, or the signer could not
	// record the key.
	ErrEnrollment = errors.New("enrollment failed")

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

	// ErrMaxFeeIncreaseExceeded matches, with errors.Is, a sign, plan or
	// simulate call refused because the signer raised fees by more than the
	// client's max fee increase. errors.As with *MaxFeeIncreaseError gives the
	// amounts.
	ErrMaxFeeIncreaseExceeded = errors.New("signer raised fees by more than the max fee increase")
)

// Configuration errors
var (
	// ErrConfigNotFound indicates config.yaml was not found.
	ErrConfigNotFound = errors.New("config.yaml not found")
)

// Stable machine-readable error codes carried in ErrorResponse.Code.
// These mirror the signer wire contract (pkg/signerapi/error_codes.go in the
// aplane repo). Every apsigner error response carries a non-empty code.
const (
	ErrCodeBadRequest              = "bad_request"
	ErrCodeUnauthorized            = "unauthorized"
	ErrCodeForbidden               = "forbidden"
	ErrCodeLocked                  = "locked"
	ErrCodeNotFound                = "not_found"
	ErrCodeInvalidPassphrase       = "invalid_passphrase"
	ErrCodeUnavailable             = "unavailable"
	ErrCodeCacheRefresh            = "cache_refresh"
	ErrCodeInternal                = "internal"
	ErrCodeBoundedCosignerRequired = "bounded_cosigner_required"
	// ErrCodeBoundedRekeyTargetNotListed: the account refuses every rekey but
	// one to an address on its rekey-to list, and the target is not on it.
	ErrCodeBoundedRekeyTargetNotListed = "bounded_rekey_target_not_listed"
	// ErrCodeRotatingSigningRequired: a rotating account (signing_flow
	// rotating1) was sent to an ordinary signing endpoint. Use SendPrepared
	// or the PrepareRotating and SignPreparedRotating calls.
	ErrCodeRotatingSigningRequired = "rotating_signing_required"
	// ErrCodeRotatingStageUnproven (409, temporary): the signer has not yet
	// found the rotating account's live stage; a retry usually succeeds.
	ErrCodeRotatingStageUnproven = "rotating_stage_unproven"
	// ErrCodeRotatingStageChanged (409): the account's authorizer moved
	// between prepare and sign; no signature was released.
	ErrCodeRotatingStageChanged = "rotating_stage_changed"
	// ErrCodeRotatingWindowNotCurrent (409): the rotating spend's validity
	// window is not acceptable at the round the signer read: its first valid
	// round is too far ahead, or too few rounds remain. This attempt released
	// no signature; rebuild the validity rounds and prepare again.
	ErrCodeRotatingWindowNotCurrent = "rotating_window_not_current"
	// ErrCodeRekeyTargetNotValid (403): a transaction rekeys an account, its
	// own address included, to an aplane key this signer holds that is not a
	// valid rekey target (KeyInfo.ValidRekeyTarget false). Nothing was signed.
	ErrCodeRekeyTargetNotValid = "rekey_target_not_valid"
)

// APIError preserves the HTTP status, stable wire error code, and message of
// a non-2xx signer response for callers that need to classify failures
// without matching message text. Code is empty only when the response body
// was not a JSON error envelope.
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

// Unwrap maps stable signer error codes to public sentinel errors.
func (e *APIError) Unwrap() error {
	if e == nil {
		return nil
	}
	if e.Code == ErrCodeNotFound {
		return ErrKeyNotFound
	}
	return nil
}

// MaxFeeIncreaseError reports a call refused because the signer raised fees
// by more than the ceiling set with SetMaxFeeIncrease. It matches
// ErrMaxFeeIncreaseExceeded.
type MaxFeeIncreaseError struct {
	// Raised is the total the signer added across the request's positions,
	// in microAlgos.
	Raised uint64
	// Limit is the ceiling the call was held to, in microAlgos.
	Limit uint64
}

func (e *MaxFeeIncreaseError) Error() string {
	return fmt.Sprintf("signer raised fees by %d microAlgos, more than the max fee increase %d set on this client", e.Raised, e.Limit)
}

// Is reports that the error is a max fee increase refusal.
func (e *MaxFeeIncreaseError) Is(target error) bool {
	return target == ErrMaxFeeIncreaseExceeded
}
