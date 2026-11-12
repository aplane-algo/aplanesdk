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
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// defaultSendWaitRounds is how many rounds a send waits for a submitted group
// to confirm when SendOptions.WaitRounds is zero.
const defaultSendWaitRounds = 10

// SendOutcome says how far a send got.
type SendOutcome string

const (
	// SendOutcomeSubmitted: go-algorand-sdk's submit call returned success,
	// and the send did not wait for confirmation. Returned only when
	// SendOptions.NoWait is set.
	SendOutcomeSubmitted SendOutcome = "submitted"
	// SendOutcomeConfirmed: go-algorand-sdk's confirmation wait returned the
	// group's first transaction confirmed.
	SendOutcomeConfirmed SendOutcome = "confirmed"
)

// SendOptions configures SendPrepared and the Send* conveniences. The zero
// value signs, submits and waits for confirmation.
type SendOptions struct {
	// NoWait returns once go-algorand-sdk's submit call returns success, with
	// SendOutcomeSubmitted, instead of waiting for confirmation.
	NoWait bool
	// WaitRounds is the round count given to go-algorand-sdk's
	// transaction.WaitForConfirmation for the group's first transaction.
	// Zero means 10.
	WaitRounds uint64

	// RefreshValidity lets a send rebuild the validity rounds of a rotating
	// account's transaction when they are stale or the window is too long.
	// That changes the transaction's ID, so it is off by default for a
	// transaction the caller supplies. Do not set it when something outside
	// the transaction, such as an app argument or a proof, binds its rounds.
	// SendPayment builds its own transaction and always may. Other accounts
	// ignore it.
	RefreshValidity bool

	// A cosigned account's cosigner, used only when the group has a position
	// that needs one. Give a client, with the Witness Key ID it signs under,
	// or a resolver. The caller owns these clients; a send never closes them.
	// With neither, a client created from a data directory (FromEnv) finds
	// the cosigner among the cosigner endpoints of its endpoints.yaml.
	CosignerClient       *SignerClient
	CosignerComponentKey string
	CosignerResolver     CosignedCosignerResolver
}

// SendResult describes a group that was signed and submitted. Every value is
// computed from the signed bytes, after they were checked against the request.
type SendResult struct {
	// Flow is the signing flow the group took: empty for the ordinary /sign
	// flow, SigningFlowCosigned1 or SigningFlowRotating1.
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
	// Confirmation is what go-algorand-sdk's transaction.WaitForConfirmation
	// returned, unchanged. It describes the first transaction of SignedGroup,
	// the one the wait followed. Read inner transactions, logs and created
	// IDs from it as in any go-algorand-sdk program. Nil unless Outcome is
	// SendOutcomeConfirmed.
	Confirmation *models.PendingTransactionInfoResponse
	// Cosigned carries the component responses of a cosigned send.
	Cosigned *CosignedSignResult
	// Rotating carries the rotation a rotating account's send performed.
	Rotating *RotatingSendDetails

	// lastValid is the earliest last valid round of the signed group.
	lastValid uint64
}

// RotatingSendDetails describes the rotation a rotating account's send
// performed.
type RotatingSendDetails struct {
	// Stage signed the spend and Target, Stage + 1, now controls the account.
	Stage  uint64
	Target uint64
	// RekeyTo is Target's address, as the signer reported it.
	RekeyTo string
	// Attempts is how many times the spend was prepared.
	Attempts int
	// Transaction is the transaction that was prepared: the one supplied,
	// with its validity rounds rebuilt if the send was allowed to.
	Transaction types.Transaction
	// RequestID is the sign request that released the signature.
	RequestID string
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

// SignOutcomeUnknownError reports a signing exchange that ended with no
// usable answer: a /sign request, or a step of the cosigned sequence. The
// signer may or may not have released a signature. Nothing was submitted by
// this call. Do not build and sign a replacement transaction until the
// network's current round is past LastValid: after it, nothing the request
// signed can execute. For a rotating account, sign Rotating again with
// SignPreparedRotating instead. RequestID lets the operator check the
// signer's audit log.
type SignOutcomeUnknownError struct {
	// RequestID is the ID of the request whose answer was lost, as the
	// signer's audit log records it: the /sign request, or for a cosigned
	// account the /sign/component, /sign/assemble or /sign request of the
	// step that ended with no answer.
	RequestID string
	// Requests is what was sent to be signed, for the ordinary flow.
	Requests []SignRequest
	// Rotating is the prepared group that was sent to be signed, for a
	// rotating account. Calling SignPreparedRotating with it again asks for
	// the same transaction and is the safe recovery.
	Rotating *PreparedRotating
	// LastValid is the earliest last valid round among the transactions
	// that were sent to be signed (for a rotating account, of the prepared
	// group). The signer never changes validity rounds, so after this round
	// no signature released by the request can execute.
	LastValid uint64
	Err       error
}

func (e *SignOutcomeUnknownError) Error() string {
	if e.RequestID == "" {
		return fmt.Sprintf("signing ended with no answer, so a signature may have been released: %v", e.Err)
	}
	return fmt.Sprintf("sign request %s: no answer from the signer, so a signature may have been released: %v", e.RequestID, e.Err)
}

// Unwrap returns the cause. A nil error has none, so errors.As can look past
// one in a chain.
func (e *SignOutcomeUnknownError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// SubmissionError reports a signed and verified group whose submission or
// confirmation wait failed. The send submits with go-algorand-sdk's
// SendRawTransaction and waits with its transaction.WaitForConfirmation, and
// Err is the error that call returned, unchanged, or the context's error when
// the context ended before the call. Read it as in any go-algorand-sdk
// program. The error makes no claim about what the node did.
//
// When Submitted is true, follow the group with
// transaction.WaitForConfirmation on TxIDs[0]. When it is false, submit the
// same SignedGroup again with SubmitSignedGroup; the node may already have it.
// The same signed bytes execute at most once. After LastValid, neither a
// node's "not found" nor a refusal proves the group never confirmed: check an
// indexer before building a replacement.
type SubmissionError struct {
	// SignedGroup is the signed group, hex msgpack, in order.
	SignedGroup []string
	// TxIDs are the IDs of the signed transactions, in SignedGroup order.
	TxIDs []string
	// LastValid is the earliest last valid round in SignedGroup: after it,
	// the group can no longer execute.
	LastValid uint64
	// Submitted is true when go-algorand-sdk's submit call returned success
	// and the failure came later. False means the submit call was not made,
	// because the context had ended, or did not return success; it does not
	// mean the node lacks the group, because the answer may have been lost.
	Submitted bool
	Err       error
}

func (e *SubmissionError) Error() string {
	if e.Submitted {
		return fmt.Sprintf("wait for confirmation of transaction %s: %v", firstOrEmpty(e.TxIDs), e.Err)
	}
	return fmt.Sprintf("submit transaction %s: %v", firstOrEmpty(e.TxIDs), e.Err)
}

// Unwrap returns the cause. A nil error has none, so errors.As can look past
// one in a chain.
func (e *SubmissionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

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
	return c.sendPrepared(ctx, algodClient, NewPreparedGroup(*prepared), opts, true)
}

// SendPrepared signs a prepared transaction or group with the signing flow
// each account needs, checks the signed result against what was prepared,
// submits exactly those bytes, and by default waits for confirmation.
//
// The flow is chosen from the signer's own record of each key, never from
// the caller. A rotating account is signed for by another key only when the
// chain says it is rekeyed to that key. A group of ordinary and bounded accounts goes through /sign; a
// group with a cosigned account goes through the cosigned sequence, which
// needs the cosigner named in opts when a position requires its signature.
// A rotating account's transaction, which must be alone and ungrouped, goes
// through the rotating sequence: prepare, check, simulate unsigned, then
// sign. An unknown flow, or a pre-signed or foreign position, is refused
// before anything is signed.
//
// Every position must be one whose key this signer holds, and must name it in
// AuthAddress, as the Prepare* helpers do.
//
// A refusal by the signer, and an answer of the signer's that the SDK
// refuses, come back as the signing call's own error; nothing was submitted.
// The other failures are typed. *SignOutcomeUnknownError: an approval-bearing
// request ended with no answer. *SubmissionError: the group was signed, and
// go-algorand-sdk's submit or confirmation wait failed, or the context ended
// before one of them; the error keeps the signed bytes, their IDs and
// go-algorand-sdk's error. A rotating send may prepare and seek approval
// again, a bounded number of times, when the signer says an attempt released
// no signature. No send ever builds a replacement for a transaction whose
// outcome is unknown.
func (c *SignerClient) SendPrepared(ctx context.Context, algodClient *algod.Client, group PreparedGroup, opts *SendOptions) (*SendResult, error) {
	return c.sendPrepared(ctx, algodClient, group, opts, false)
}

// sendPrepared is SendPrepared. intentBuilt says the SDK built the group's
// transactions itself, so it may rebuild their validity rounds.
func (c *SignerClient) sendPrepared(ctx context.Context, algodClient *algod.Client, group PreparedGroup, opts *SendOptions, intentBuilt bool) (*SendResult, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	if opts == nil {
		opts = &SendOptions{}
	}
	flow, leftRotation, err := c.classifySend(ctx, group)
	if err != nil {
		return nil, err
	}
	// A rotating account is signed for by another key only when the chain
	// says it is rekeyed to that key. Without this a caller could have an
	// ordinary key sign a rotating account's transaction, outside the
	// rotating rules: refused by the network today, but signed.
	for _, i := range leftRotation {
		item := group.Transactions[i]
		sender := item.Transaction.Sender.String()
		info, err := algodClient.AccountInformation(sender).Do(ctx)
		if err != nil {
			return nil, fmt.Errorf("prepared transaction %d: read the authorizer of rotating account %s: %w", i, sender, err)
		}
		if info.AuthAddr != item.AuthAddress {
			return nil, fmt.Errorf("prepared transaction %d: %w: it names auth address %s, but rotating account %s is not rekeyed to it", i, ErrUnsupportedGroup, item.AuthAddress, sender)
		}
	}
	// Nothing has been asked of the signer yet, so an ended context is a
	// plain stop, not an unknown outcome.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if flow == SigningFlowRotating1 {
		return c.sendRotating(ctx, algodClient, group.Transactions[0], opts, intentBuilt || opts.RefreshValidity)
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
			// The sequence makes several approval-bearing requests. One that
			// ended with no answer may have released a signature, and the
			// last of them releases the whole group.
			if requestID, lost := lostRequest(err); lost {
				return nil, &SignOutcomeUnknownError{RequestID: requestID, LastValid: group.earliestLastValid(), Err: err}
			}
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

// lostRequest reports whether err is an approval-bearing request of the
// cosigned sequence that ended with no usable answer: a component request,
// the /sign of the group's other positions, or the assembly. It returns that
// request's ID. Planning and key listing release nothing, so a failure there
// is not one.
func lostRequest(err error) (requestID string, lost bool) {
	var resolve *cosignerResolveError
	if errors.As(err, &resolve) {
		return "", false
	}
	var mark *lostAnswer
	if errors.As(err, &mark) {
		return mark.requestID, true
	}
	return "", false
}

// classifySend picks the one signing flow for the whole group from the
// signer's records, or refuses a group unified sending does not cover.
// Nothing has been signed when it returns.
//
// leftRotation lists the positions whose sender is a rotating account and
// which name another held key: the caller must confirm on the chain that the
// account is rekeyed to that key before anything is signed.
func (c *SignerClient) classifySend(ctx context.Context, group PreparedGroup) (flow string, leftRotation []int, err error) {
	if len(group.Transactions) == 0 {
		return "", nil, fmt.Errorf("prepared group is empty")
	}
	keys, err := c.ListKeysIfKeysetChangedWithContext(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("resolve signer keys: %w", err)
	}
	for i, item := range group.Transactions {
		if item.SignedTransactionBase64 != "" {
			return "", nil, fmt.Errorf("prepared transaction %d: %w: it is already signed; use the lower-level signing calls for a pre-signed position", i, ErrUnsupportedGroup)
		}
		if item.Transaction == nil {
			return "", nil, fmt.Errorf("prepared transaction %d: transaction is required", i)
		}
		if item.AuthAddress == "" {
			return "", nil, fmt.Errorf("prepared transaction %d: %w: it names no auth address, so this signer does not sign it", i, ErrUnsupportedGroup)
		}
		// A rotating account is recognised by its own record: once it has
		// rotated, its on-chain authorizer is a stage address the signer
		// does not list. It signs alone, and as itself.
		sender := item.Transaction.Sender.String()
		// A position that names another key the signer holds says the
		// account left rotation for that key. It is routed by that key once
		// the chain confirms the rekey.
		_, namesHeldKey := findSpendableKey(keys, item.AuthAddress)
		namesAnotherKey := item.AuthAddress != sender && namesHeldKey
		own, senderHeld := findSpendableKey(keys, sender)
		if senderHeld && own.SigningFlow == SigningFlowRotating1 && namesAnotherKey {
			leftRotation = append(leftRotation, i)
		}
		if senderHeld && own.SigningFlow == SigningFlowRotating1 && !namesAnotherKey {
			if len(group.Transactions) != 1 {
				return "", nil, fmt.Errorf("prepared transaction %d: %w: %s is a rotating account, which sends one transaction alone; the signer forms its group", i, ErrUnsupportedGroup, sender)
			}
			if item.AuthAddress != sender {
				return "", nil, fmt.Errorf("prepared transaction %d: %w: it names auth address %s, but %s is a rotating account and signs as itself", i, ErrUnsupportedGroup, item.AuthAddress, sender)
			}
			return SigningFlowRotating1, nil, nil
		}
		key, ok := findSpendableKey(keys, item.AuthAddress)
		if !ok {
			return "", nil, fmt.Errorf("prepared transaction %d: %w: %s is not available for signing", i, ErrKeyNotFound, item.AuthAddress)
		}
		switch key.SigningFlow {
		case "", SigningFlowBounded1:
		case SigningFlowCosigned1:
			flow = SigningFlowCosigned1
		case SigningFlowRotating1:
			return "", nil, fmt.Errorf("prepared transaction %d: %w: it names rotating account %s as the auth address of another sender; a rotating account signs only its own transactions", i, ErrUnsupportedGroup, item.AuthAddress)
		default:
			return "", nil, fmt.Errorf("prepared transaction %d: %w: key %s requires signing flow %q; upgrade the SDK", i, ErrUnsupportedSigningFlow, item.AuthAddress, key.SigningFlow)
		}
	}
	return flow, leftRotation, nil
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
		return nil, &SignOutcomeUnknownError{RequestID: requestID, Requests: requests, LastValid: group.earliestLastValid(), Err: transport.err}
	case errors.As(err, &unread):
		return nil, &SignOutcomeUnknownError{RequestID: requestID, Requests: requests, LastValid: group.earliestLastValid(), Err: err}
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
	result.lastValid = earliestLastValid(txns)
	return raw, nil
}

// earliestLastValid is the earliest last valid round among txns. A group is
// atomic, so after that round none of it can execute.
func earliestLastValid(txns []types.Transaction) uint64 {
	var earliest uint64
	for i, txn := range txns {
		if last := uint64(txn.LastValid); i == 0 || last < earliest {
			earliest = last
		}
	}
	return earliest
}

// earliestLastValid is the earliest last valid round among the group's
// transactions. The signer never changes validity rounds: the dummies it
// appends take the first transaction's.
func (g PreparedGroup) earliestLastValid() uint64 {
	txns := make([]types.Transaction, 0, len(g.Transactions))
	for _, item := range g.Transactions {
		if item.Transaction != nil {
			txns = append(txns, *item.Transaction)
		}
	}
	return earliestLastValid(txns)
}

// submitAndTrack is the one submission path of every send. It posts the
// signed bytes exactly as given with go-algorand-sdk's SendRawTransaction
// and, unless told not to, waits with its transaction.WaitForConfirmation on
// the first transaction ID. It reports their errors unchanged in a
// *SubmissionError and never signs or rebuilds anything.
func submitAndTrack(ctx context.Context, algodClient *algod.Client, raw [][]byte, result *SendResult, opts *SendOptions) error {
	fail := func(submitted bool, err error) error {
		return &SubmissionError{SignedGroup: result.SignedGroup, TxIDs: result.TxIDs, LastValid: result.lastValid, Submitted: submitted, Err: err}
	}
	if err := ctx.Err(); err != nil {
		return fail(false, err)
	}
	var blob []byte
	for _, entry := range raw {
		blob = append(blob, entry...)
	}
	if _, err := algodClient.SendRawTransaction(blob).Do(ctx); err != nil {
		return fail(false, err)
	}
	result.Outcome = SendOutcomeSubmitted
	if opts.NoWait {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return fail(true, err)
	}
	waitRounds := opts.WaitRounds
	if waitRounds == 0 {
		waitRounds = defaultSendWaitRounds
	}
	info, err := transaction.WaitForConfirmation(algodClient, result.TxIDs[0], waitRounds, ctx)
	if err != nil {
		return fail(true, err)
	}
	result.Outcome = SendOutcomeConfirmed
	result.ConfirmedRound = info.ConfirmedRound
	result.Confirmation = &info
	return nil
}

// SubmitSignedGroup submits a signed group exactly as given and, unless told
// not to, waits for confirmation. It signs nothing. Use it to submit a group
// from SignPreparedRotating, or to submit again the SignedGroup a
// *SubmissionError kept: the same bytes can execute only once.
//
// Each entry must be one canonically encoded signed transaction, hex msgpack,
// and a group of several must carry the group ID computed over itself.
func (c *SignerClient) SubmitSignedGroup(ctx context.Context, algodClient *algod.Client, signedGroup []string, opts *SendOptions) (*SendResult, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	if opts == nil {
		opts = &SendOptions{}
	}
	result := &SendResult{SignedGroup: append([]string(nil), signedGroup...), OriginalCount: len(signedGroup)}
	raw, err := describeSignedGroup(result)
	if err != nil {
		return nil, fmt.Errorf("verify signed group: %w", err)
	}
	if err := submitAndTrack(ctx, algodClient, raw, result, opts); err != nil {
		return nil, err
	}
	return result, nil
}
