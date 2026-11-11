// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// defaultSendWaitRounds is how many rounds SendPrepared waits for a submitted
// group to confirm when SendOptions.WaitRounds is zero.
const defaultSendWaitRounds = 10

// SendOutcome says how far a send got on the network.
type SendOutcome string

const (
	// SendOutcomeSubmitted: the node accepted the group; it was not seen in a
	// block by this call. Returned only when SendOptions.NoWait is set.
	SendOutcomeSubmitted SendOutcome = "submitted"
	// SendOutcomeConfirmed: the group was seen in a block.
	SendOutcomeConfirmed SendOutcome = "confirmed"
)

// SendOptions configures SendPrepared and the Send* conveniences. The zero
// value signs, submits and waits for confirmation.
type SendOptions struct {
	// NoWait returns as soon as the node accepts the group, with
	// SendOutcomeSubmitted, instead of waiting for confirmation.
	NoWait bool
	// WaitRounds is how many rounds to wait for confirmation. Zero means 10.
	WaitRounds uint64

	// A cosigned account's cosigner, used only when the group has a position
	// that needs one. Give a client, with the Witness Key ID it signs under,
	// or a resolver. The caller owns these clients; a send never closes them.
	CosignerClient       *SignerClient
	CosignerComponentKey string
	CosignerResolver     CosignedCosignerResolver
}

// SendResult describes a group that was signed and submitted. Every value is
// computed from the signed bytes, after they were checked against the request.
type SendResult struct {
	// Flow is the signing flow the group took: empty for the ordinary /sign
	// flow, or SigningFlowCosigned1.
	Flow string
	// SignedGroup is the exact group submitted, hex msgpack, in order. The
	// first OriginalCount entries are the caller's transactions, in the order
	// given; the rest are resource dummies the signer appended.
	SignedGroup   []string
	OriginalCount int
	// TxIDs are the IDs of the signed transactions, in SignedGroup order. A
	// signer may raise a fee or assign a group, so these can differ from the
	// IDs of the transactions the caller prepared.
	TxIDs []string
	// GroupID is the group's ID in base64, or empty for a lone transaction.
	GroupID string
	// Fees are the fees the signed transactions pay, in microAlgos.
	Fees []uint64
	// Mutations is the signer's report of what it changed, checked against
	// the signed bytes. Nil when it changed nothing.
	Mutations *MutationReport
	// Outcome and ConfirmedRound say how far the group got. ConfirmedRound is
	// zero unless Outcome is SendOutcomeConfirmed.
	Outcome        SendOutcome
	ConfirmedRound uint64
	// Cosigned carries the component responses of a cosigned send.
	Cosigned *CosignedSignResult
}

// Errors a send returns before any signature is requested.
var (
	// ErrUnsupportedSigningFlow: a key in the group needs a signing flow this
	// SDK version cannot run.
	ErrUnsupportedSigningFlow = errors.New("unsupported signing flow")
	// ErrUnsupportedGroup: the group is one unified sending does not cover,
	// such as a pre-signed or foreign position. The lower-level signing calls
	// still handle it.
	ErrUnsupportedGroup = errors.New("group not supported by unified sending")
)

// SignOutcomeUnknownError reports a sign request whose answer never arrived.
// The signer may or may not have released a signature. Nothing was submitted
// by this call. Do not build and sign a replacement transaction on the
// strength of this error alone: check the request with the operator or the
// signer's audit log first.
type SignOutcomeUnknownError struct {
	// RequestID is the sign request's ID, as the signer's audit log records it.
	RequestID string
	// Requests is what was sent to be signed.
	Requests []SignRequest
	Err      error
}

func (e *SignOutcomeUnknownError) Error() string {
	return fmt.Sprintf("sign request %s: no answer from the signer, so a signature may have been released: %v", e.RequestID, e.Err)
}

func (e *SignOutcomeUnknownError) Unwrap() error { return e.Err }

// SubmissionRejectedError reports that the network refused the signed group:
// the node rejected it on submission, or dropped it from its pool. The signed
// bytes and their IDs are kept.
type SubmissionRejectedError struct {
	SignedGroup []string
	TxIDs       []string
	Err         error
}

func (e *SubmissionRejectedError) Error() string {
	return fmt.Sprintf("network rejected transaction %s: %v", firstOrEmpty(e.TxIDs), e.Err)
}

func (e *SubmissionRejectedError) Unwrap() error { return e.Err }

// Stages at which a send's outcome can become uncertain.
const (
	// SendStageSubmit: the submission's answer never arrived, so the node may
	// or may not have the group.
	SendStageSubmit = "submit"
	// SendStageConfirm: the node accepted the group, and it was not seen in a
	// block within the wait.
	SendStageConfirm = "confirm"
)

// SubmissionUncertainError reports a signed group whose fate on the network
// is not known. The group may still confirm. Look its IDs up, or submit the
// same SignedGroup again while it is valid; never sign a replacement until
// the outcome is known, because both could execute.
type SubmissionUncertainError struct {
	Stage       string
	SignedGroup []string
	TxIDs       []string
	Err         error
}

func (e *SubmissionUncertainError) Error() string {
	return fmt.Sprintf("outcome of transaction %s is unknown (%s): %v", firstOrEmpty(e.TxIDs), e.Stage, e.Err)
}

func (e *SubmissionUncertainError) Unwrap() error { return e.Err }

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// SendPayment builds an ALGO payment, then signs, submits and tracks it with
// SendPrepared. It works the same way for every account type SendPrepared
// supports.
func (c *SignerClient) SendPayment(ctx context.Context, algodClient *algod.Client, params PaymentPrepParams, opts *SendOptions) (*SendResult, error) {
	prepared, err := c.PreparePayment(ctx, algodClient, params)
	if err != nil {
		return nil, err
	}
	return c.SendPrepared(ctx, algodClient, NewPreparedGroup(*prepared), opts)
}

// SendPrepared signs a prepared transaction or group with the signing flow
// each account needs, checks the signed result against what was prepared,
// submits exactly those bytes, and by default waits for confirmation.
//
// The flow is chosen from the signer's own record of each key, never from
// the caller. A group of ordinary and bounded accounts goes through /sign; a
// group with a cosigned account goes through the cosigned sequence, which
// needs the cosigner named in opts when a position requires its signature.
// A rotating account, an unknown flow, or a pre-signed or foreign position is
// refused before anything is signed.
//
// Every position must be one whose key this signer holds, and must name it in
// AuthAddress, as the Prepare* helpers do.
//
// A refusal comes back as the signing call's own error. Once a sign request
// has been sent, failures are typed: *SignOutcomeUnknownError,
// *SubmissionRejectedError and *SubmissionUncertainError. The last two keep
// the signed bytes and their IDs. This call never signs a second time.
func (c *SignerClient) SendPrepared(ctx context.Context, algodClient *algod.Client, group PreparedGroup, opts *SendOptions) (*SendResult, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	if opts == nil {
		opts = &SendOptions{}
	}
	flow, err := c.classifySend(ctx, group)
	if err != nil {
		return nil, err
	}

	result := &SendResult{Flow: flow, OriginalCount: len(group.Transactions)}
	switch flow {
	case SigningFlowCosigned1:
		signed, err := SignPreparedCosignedGroupWithContext(ctx, PreparedCosignedGroupOptions{
			UserClient:           c,
			CosignerClient:       opts.CosignerClient,
			CosignerResolver:     opts.CosignerResolver,
			CosignerComponentKey: opts.CosignerComponentKey,
			PreparedGroup:        group,
		})
		if err != nil {
			return nil, err
		}
		result.SignedGroup = signed.SignedGroup
		result.Mutations = signed.PlanMutations
		result.Cosigned = signed
	default:
		response, err := c.signForSend(ctx, group)
		if err != nil {
			return nil, err
		}
		result.SignedGroup = response.Signed
		result.Mutations = response.Mutations
	}

	raw, err := describeSignedGroup(result)
	if err != nil {
		return nil, fmt.Errorf("verify signed group: %w", err)
	}
	if err := submitAndTrack(ctx, algodClient, raw, result, opts); err != nil {
		return nil, err
	}
	return result, nil
}

// classifySend picks the one signing flow for the whole group from the
// signer's records, or refuses a group unified sending does not cover.
// Nothing has been signed when it returns.
func (c *SignerClient) classifySend(ctx context.Context, group PreparedGroup) (string, error) {
	if len(group.Transactions) == 0 {
		return "", fmt.Errorf("prepared group is empty")
	}
	keys, err := c.ListKeysIfKeysetChangedWithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("resolve signer keys: %w", err)
	}
	flow := ""
	for i, item := range group.Transactions {
		if item.SignedTransactionBase64 != "" {
			return "", fmt.Errorf("prepared transaction %d: %w: it is already signed; use the lower-level signing calls for a pre-signed position", i, ErrUnsupportedGroup)
		}
		if item.Transaction == nil {
			return "", fmt.Errorf("prepared transaction %d: transaction is required", i)
		}
		if item.AuthAddress == "" {
			return "", fmt.Errorf("prepared transaction %d: %w: it names no auth address, so this signer does not sign it", i, ErrUnsupportedGroup)
		}
		// A rotating account is recognised by its own record: once it has
		// rotated, its on-chain authorizer is a stage address the signer
		// does not list.
		sender := item.Transaction.Sender.String()
		if own, ok := findSpendableKey(keys, sender); ok && own.SigningFlow == SigningFlowRotating1 {
			return "", rotatingNotSupported(i, sender)
		}
		key, ok := findSpendableKey(keys, item.AuthAddress)
		if !ok {
			return "", fmt.Errorf("prepared transaction %d: %w: %s is not available for signing", i, ErrKeyNotFound, item.AuthAddress)
		}
		switch key.SigningFlow {
		case "", SigningFlowBounded1:
		case SigningFlowCosigned1:
			flow = SigningFlowCosigned1
		case SigningFlowRotating1:
			return "", rotatingNotSupported(i, item.AuthAddress)
		default:
			return "", fmt.Errorf("prepared transaction %d: %w: key %s requires signing flow %q; upgrade the SDK", i, ErrUnsupportedSigningFlow, item.AuthAddress, key.SigningFlow)
		}
	}
	return flow, nil
}

func rotatingNotSupported(index int, account string) error {
	return fmt.Errorf("prepared transaction %d: %w: %s is a rotating account (%s), which this SDK version cannot sign for", index, ErrUnsupportedSigningFlow, account, SigningFlowRotating1)
}

// signForSend runs the ordinary /sign flow for a send. It is postSign with
// the failures a send must tell apart: a refusal the signer answered with,
// and an exchange that ended with no usable answer.
func (c *SignerClient) signForSend(ctx context.Context, group PreparedGroup) (*GroupSignResponse, error) {
	requests, err := group.SignRequests()
	if err != nil {
		return nil, err
	}
	requestID, err := newSignRequestID()
	if err != nil {
		return nil, fmt.Errorf("failed to create sign request ID: %w", err)
	}
	groupReq := GroupSignRequest{RequestID: requestID, Requests: requests}
	if err := groupReq.Validate(); err != nil {
		return nil, fmt.Errorf("invalid sign request: %w", err)
	}
	response, err := c.postSign(ctx, groupReq)
	if err == nil {
		return response, nil
	}
	var transport *signTransportError
	var unread *signUnreadError
	var body *signBodyError
	var apiErr *APIError
	switch {
	case errors.As(err, &transport):
		return nil, &SignOutcomeUnknownError{RequestID: requestID, Requests: requests, Err: transport.err}
	case errors.As(err, &unread):
		return nil, &SignOutcomeUnknownError{RequestID: requestID, Requests: requests, Err: err}
	case errors.As(err, &body):
		return nil, fmt.Errorf("signing failed: %s", body.message)
	case errors.As(err, &apiErr):
		switch apiErr.StatusCode {
		case http.StatusUnauthorized:
			return nil, ErrAuthentication
		case http.StatusForbidden:
			return nil, rejectedForbidden(apiErr)
		case http.StatusServiceUnavailable:
			return nil, ErrSignerUnavailable
		}
	}
	return nil, err
}

// describeSignedGroup fills the result's IDs, fees and group ID from its
// signed bytes and returns those bytes decoded. Each entry must be one
// canonically encoded signed transaction, and a group of several must carry
// the group ID computed over itself.
func describeSignedGroup(result *SendResult) ([][]byte, error) {
	decoded, txIDs, _, err := decodeExecutableSignedGroup(result.SignedGroup)
	if err != nil {
		return nil, err
	}
	if len(decoded) < result.OriginalCount {
		return nil, fmt.Errorf("signed group has %d transaction(s), fewer than the %d prepared", len(decoded), result.OriginalCount)
	}
	txns := make([]types.Transaction, len(decoded))
	raw := make([][]byte, len(decoded))
	result.Fees = make([]uint64, len(decoded))
	for i := range decoded {
		txns[i] = decoded[i].Txn
		result.Fees[i] = uint64(decoded[i].Txn.Fee)
		// decodeExecutableSignedGroup has checked this decodes.
		raw[i], _ = hex.DecodeString(result.SignedGroup[i])
	}
	groupID, err := validateCanonicalGroupID(txns)
	if err != nil {
		return nil, err
	}
	if len(txns) == 1 {
		groupID = txns[0].Group
	}
	if groupID != (types.Digest{}) {
		result.GroupID = base64.StdEncoding.EncodeToString(groupID[:])
	}
	result.TxIDs = txIDs
	return raw, nil
}

// submitAndTrack is the one submission path of every send. It submits the
// signed bytes exactly as given and, unless told not to, waits for the first
// transaction to confirm. It never signs or rebuilds anything.
func submitAndTrack(ctx context.Context, algodClient *algod.Client, raw [][]byte, result *SendResult, opts *SendOptions) error {
	var blob []byte
	for _, entry := range raw {
		blob = append(blob, entry...)
	}
	txID := result.TxIDs[0]
	sentID, err := algodClient.SendRawTransaction(blob).Do(ctx)
	if err != nil {
		var bad common.BadRequest
		if errors.As(err, &bad) {
			return &SubmissionRejectedError{SignedGroup: result.SignedGroup, TxIDs: result.TxIDs, Err: err}
		}
		return &SubmissionUncertainError{Stage: SendStageSubmit, SignedGroup: result.SignedGroup, TxIDs: result.TxIDs, Err: err}
	}
	if sentID != txID {
		return &SubmissionUncertainError{
			Stage: SendStageSubmit, SignedGroup: result.SignedGroup, TxIDs: result.TxIDs,
			Err: fmt.Errorf("node reported transaction ID %s for a group whose first transaction is %s", sentID, txID),
		}
	}
	result.Outcome = SendOutcomeSubmitted
	if opts.NoWait {
		return nil
	}

	waitRounds := opts.WaitRounds
	if waitRounds == 0 {
		waitRounds = defaultSendWaitRounds
	}
	uncertain := func(err error) error {
		return &SubmissionUncertainError{Stage: SendStageConfirm, SignedGroup: result.SignedGroup, TxIDs: result.TxIDs, Err: err}
	}
	status, err := algodClient.Status().Do(ctx)
	if err != nil {
		return uncertain(fmt.Errorf("read current round: %w", err))
	}
	start := status.LastRound
	for round := start + 1; ; round++ {
		// A lookup error is not an answer: behind a load balancer another
		// node may not have the transaction yet.
		info, _, err := algodClient.PendingTransactionInformation(txID).Do(ctx)
		if err == nil {
			if info.PoolError != "" {
				return &SubmissionRejectedError{
					SignedGroup: result.SignedGroup, TxIDs: result.TxIDs,
					Err: fmt.Errorf("dropped from the transaction pool: %s", info.PoolError),
				}
			}
			if info.ConfirmedRound > 0 {
				result.Outcome = SendOutcomeConfirmed
				result.ConfirmedRound = info.ConfirmedRound
				return nil
			}
		}
		if round > start+waitRounds {
			return uncertain(fmt.Errorf("not confirmed after %d rounds", waitRounds))
		}
		if _, err := algodClient.StatusAfterBlock(round).Do(ctx); err != nil {
			return uncertain(fmt.Errorf("wait for round %d: %w", round, err))
		}
	}
}
