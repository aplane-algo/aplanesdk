// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common"
)

// OutcomeState says where an uncertain outcome stands. The values are the
// same in every SDK.
type OutcomeState string

const (
	// OutcomeConfirmed: the group is in a block. Do not send it again.
	OutcomeConfirmed OutcomeState = "confirmed"
	// OutcomePending: the group is in the node's pool.
	OutcomePending OutcomeState = "pending"
	// OutcomeNotSeen: the node does not have the signed group, and it can
	// still execute.
	OutcomeNotSeen OutcomeState = "not_seen"
	// OutcomeSignable: a signature may have been released, and it can still
	// execute.
	OutcomeSignable OutcomeState = "signable"
	// OutcomeExpired: nothing from the request can execute any more. It is
	// safe to build a replacement.
	OutcomeExpired OutcomeState = "expired"
	// OutcomeTooOld: the group's validity ended so long ago that the node may
	// have forgotten it. Look it up on an indexer.
	OutcomeTooOld OutcomeState = "too_old"
)

// settled reports whether a state can no longer change.
func (s OutcomeState) settled() bool {
	return s == OutcomeConfirmed || s == OutcomeExpired || s == OutcomeTooOld
}

// outcomeRememberedRounds is how many rounds past a group's last valid round
// a node is trusted to remember it. Past that, a confirmed transaction can
// look not found.
const outcomeRememberedRounds = 500

// ErrNotUncertainOutcome is ResolveOutcome's refusal of an error that is not
// a *SignOutcomeUnknownError or a *SubmissionUncertainError.
var ErrNotUncertainOutcome = errors.New("not an uncertain outcome")

// OutcomeReport says where an uncertain outcome stands, and what to do.
type OutcomeReport struct {
	State OutcomeState
	// ConfirmedRound is the round the group was confirmed in; zero unless
	// State is OutcomeConfirmed.
	ConfirmedRound uint64
	// TxIDs are the group's transaction IDs, or empty when they are not
	// known: the signer may have changed an ordinary or cosigned group's
	// transactions before signing them.
	TxIDs []string
	// LastValid is the error's earliest last valid round, and CurrentRound
	// the node's last round when it was checked.
	LastValid    uint64
	CurrentRound uint64
	// SafeToReplace says a new transaction may be built and signed for the
	// same purpose: nothing from the earlier attempt can execute.
	SafeToReplace bool
	// SignedGroup is the signed group the error carried, if any.
	SignedGroup []string
	// Rotating is the prepared rotating group the error carried, if any.
	Rotating *PreparedRotating
	// Advice is one sentence saying what to do.
	Advice string
}

// WaitOutcomeOptions configures WaitForOutcome.
type WaitOutcomeOptions struct {
	// Timeout bounds the whole wait. Zero means no limit beyond the context.
	Timeout time.Duration
}

// ResolveOutcome says where an uncertain outcome stands: err must be (or
// wrap) a *SubmissionUncertainError or a *SignOutcomeUnknownError from a
// send or a signing step. It reads the node's current round and, when the
// group's transaction IDs are known, looks the first one up. It never signs,
// never submits, and never calls the signer. A node failure is returned as an
// error, never as a state.
//
// For a signed group (*SubmissionUncertainError): confirmed, pending in the
// pool, not seen while it can still execute, expired once its last valid
// round has passed, or too old when that was more than 500 rounds ago and
// the node may no longer remember it. For a signing exchange
// (*SignOutcomeUnknownError), which submitted nothing: a rotating group is
// looked up first; otherwise it is signable until its last valid round and
// expired after, except that a rotating group, which the caller may have
// signed again and submitted, is too old more than 500 rounds after it.
func (c *SignerClient) ResolveOutcome(ctx context.Context, algodClient *algod.Client, err error) (*OutcomeReport, error) {
	var submission *SubmissionUncertainError
	var sign *SignOutcomeUnknownError
	switch {
	case err == nil:
		return nil, ErrNotUncertainOutcome
	case errors.As(err, &submission):
		if submission.LastValid == 0 {
			return nil, errors.New("the error carries no last valid round")
		}
		if len(submission.TxIDs) == 0 || submission.TxIDs[0] == "" {
			return nil, errors.New("the error carries no transaction IDs")
		}
		if algodClient == nil {
			return nil, fmt.Errorf("algod client is required")
		}
		return resolveSubmission(ctx, algodClient, submission)
	case errors.As(err, &sign):
		if sign.LastValid == 0 {
			return nil, errors.New("the error carries no last valid round")
		}
		if algodClient == nil {
			return nil, fmt.Errorf("algod client is required")
		}
		return resolveSign(ctx, algodClient, sign)
	}
	return nil, ErrNotUncertainOutcome
}

// WaitForOutcome resolves err once per round, waiting for each next round
// with the node's status-after-block call, until the state is confirmed,
// expired or too old. If the context ends or the timeout passes first, it
// returns the last report (nil if there was none yet) together with the
// context's error. It never signs, never submits, and never calls the signer.
func (c *SignerClient) WaitForOutcome(ctx context.Context, algodClient *algod.Client, err error, opts *WaitOutcomeOptions) (*OutcomeReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts != nil && opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	var last *OutcomeReport
	for {
		report, resolveErr := c.ResolveOutcome(ctx, algodClient, err)
		if resolveErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return last, ctxErr
			}
			return last, resolveErr
		}
		last = report
		if report.State.settled() {
			return report, nil
		}
		// StatusAfterBlock(n) returns once round n+1 exists.
		if _, waitErr := algodClient.StatusAfterBlock(report.CurrentRound).Do(ctx); waitErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return last, ctxErr
			}
			return last, fmt.Errorf("wait for round %d: %w", report.CurrentRound+1, waitErr)
		}
	}
}

// groupLookup is what the node says of a transaction ID.
type groupLookup int

const (
	lookupNotFound groupLookup = iota
	lookupInPool
	lookupPoolError
	lookupConfirmed
)

// lookUpGroup asks the node about a group's first transaction: a group is
// atomic, so one ID is enough. Only the node's 404 means not found; any other
// failure is an error.
func lookUpGroup(ctx context.Context, algodClient *algod.Client, txID string) (groupLookup, uint64, error) {
	info, _, err := algodClient.PendingTransactionInformation(txID).Do(ctx)
	if err != nil {
		var notFound common.NotFound
		if errors.As(err, &notFound) {
			return lookupNotFound, 0, nil
		}
		return 0, 0, fmt.Errorf("look up transaction %s: %w", txID, err)
	}
	switch {
	case info.ConfirmedRound > 0:
		return lookupConfirmed, info.ConfirmedRound, nil
	case info.PoolError != "":
		return lookupPoolError, 0, nil
	}
	return lookupInPool, 0, nil
}

// currentRound is the node's last round. It is read before the group is
// looked up: once a round past the group's last valid round is seen, every
// round the group could have gone into exists, so a lookup after it that
// finds nothing is final.
func currentRound(ctx context.Context, algodClient *algod.Client) (uint64, error) {
	status, err := algodClient.Status().Do(ctx)
	if err != nil {
		return 0, fmt.Errorf("read the node's current round: %w", err)
	}
	return status.LastRound, nil
}

func confirmedAdvice(round uint64) string {
	return fmt.Sprintf("The group was confirmed in round %d. Do not send it again.", round)
}

const pendingAdvice = "The group is in the node's pool. Wait; do not send again."

func resolveSubmission(ctx context.Context, algodClient *algod.Client, e *SubmissionUncertainError) (*OutcomeReport, error) {
	current, err := currentRound(ctx, algodClient)
	if err != nil {
		return nil, err
	}
	found, confirmedRound, err := lookUpGroup(ctx, algodClient, e.TxIDs[0])
	if err != nil {
		return nil, err
	}
	report := &OutcomeReport{
		TxIDs:        append([]string(nil), e.TxIDs...),
		LastValid:    e.LastValid,
		CurrentRound: current,
		SignedGroup:  append([]string(nil), e.SignedGroup...),
	}
	lastValid := e.LastValid
	switch {
	case found == lookupConfirmed:
		report.State, report.ConfirmedRound, report.Advice = OutcomeConfirmed, confirmedRound, confirmedAdvice(confirmedRound)
	case found == lookupInPool:
		report.State, report.Advice = OutcomePending, pendingAdvice
	// Not found, or dropped from the pool.
	case current <= lastValid:
		report.State = OutcomeNotSeen
		report.Advice = fmt.Sprintf("The node does not have the group and it can still execute until round %d. Submit the same signed group again, or wait until round %d has passed.", lastValid, lastValid)
	case current-lastValid <= outcomeRememberedRounds:
		report.State, report.SafeToReplace = OutcomeExpired, true
		report.Advice = "The group was not confirmed and can no longer execute. It is safe to build a new one."
	default:
		report.State = OutcomeTooOld
		report.Advice = "The group's validity ended more than 500 rounds ago and this node may no longer remember it. Look the transaction ID up on an indexer before sending again."
	}
	return report, nil
}

func resolveSign(ctx context.Context, algodClient *algod.Client, e *SignOutcomeUnknownError) (*OutcomeReport, error) {
	current, err := currentRound(ctx, algodClient)
	if err != nil {
		return nil, err
	}
	report := &OutcomeReport{
		// The signer may have changed an ordinary or cosigned group's
		// transactions, so their IDs are not known.
		TxIDs:        []string{},
		LastValid:    e.LastValid,
		CurrentRound: current,
		Rotating:     e.Rotating,
	}
	// A rotating group is signed exactly as prepared, so its IDs are known
	// and someone may have submitted it. Not found, or dropped from the pool,
	// falls through to the rounds.
	if e.Rotating != nil {
		report.TxIDs = e.Rotating.TxIDs()
		if len(report.TxIDs) > 0 && report.TxIDs[0] != "" {
			found, confirmedRound, err := lookUpGroup(ctx, algodClient, report.TxIDs[0])
			if err != nil {
				return nil, err
			}
			switch found {
			case lookupConfirmed:
				report.State, report.ConfirmedRound, report.Advice = OutcomeConfirmed, confirmedRound, confirmedAdvice(confirmedRound)
				return report, nil
			case lookupInPool:
				report.State, report.Advice = OutcomePending, pendingAdvice
				return report, nil
			}
		}
	}
	lastValid := e.LastValid
	switch {
	// Signing the same prepared group again gives the same IDs, so a rotating
	// group may have been submitted and confirmed, and a node only remembers
	// recent rounds.
	case e.Rotating != nil && current > lastValid && current-lastValid > outcomeRememberedRounds:
		report.State = OutcomeTooOld
		report.Advice = "The prepared group's validity ended more than 500 rounds ago and this node may no longer remember it. Look the transaction ID up on an indexer before sending again."
	case current > lastValid:
		report.State, report.SafeToReplace = OutcomeExpired, true
		report.Advice = "No signature released by that request can execute any more. It is safe to build a new one."
	case e.Rotating != nil:
		report.State = OutcomeSignable
		report.Advice = fmt.Sprintf("A signature may have been released and can execute until round %d. Sign the same prepared group again, or wait until round %d has passed.", lastValid, lastValid)
	default:
		report.State = OutcomeSignable
		report.Advice = fmt.Sprintf("A signature may have been released and can execute until round %d. Wait until round %d has passed before building a replacement.", lastValid, lastValid)
	}
	return report, nil
}
