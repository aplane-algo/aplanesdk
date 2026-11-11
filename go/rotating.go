// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// The rotating1 timing contract (docs/ARCH_SIGNING.md in the aplane repo,
// "Rotating accounts"). The signer enforces these; the SDK mirrors them to
// build a suitable window and to refuse an unsuitable one early.
const (
	// RotatingMaxValidityWindow is the longest LastValid - FirstValid span a
	// rotating account's transaction may have.
	RotatingMaxValidityWindow = 100
	// RotatingMaxLead is how far FirstValid may be ahead of the current
	// round when the signer signs.
	RotatingMaxLead = 2
	// RotatingMinRemaining is the fewest rounds that must remain before
	// LastValid when the signer signs.
	RotatingMinRemaining = 10

	// rotatingSendAttempts bounds how many times one send prepares a
	// rotating spend.
	rotatingSendAttempts = 3
)

// rotatingUnprovenBackoff is the wait before preparing again after the signer
// reports it has not found the account's live stage yet. It grows with each
// attempt.
var rotatingUnprovenBackoff = 2 * time.Second

// PreparedRotating is a rotating account's spend as the signer prepared it:
// the exact unsigned group it will sign, checked against the transaction the
// caller sent. It cannot be changed after it is made. Nothing has been signed
// and no one-time key has been used.
type PreparedRotating struct {
	account      string
	original     []byte // TX-prefixed bytes of the transaction the caller sent
	stage        uint64
	target       uint64
	rekeyTo      string
	transactions []string // hex, TX-prefixed, exactly as the signer returned
	mutations    *MutationReport
	appCallInfo  *AppCallInfo
	ceiling      feeCeiling
}

// Account is the rotating account.
func (p *PreparedRotating) Account() string { return p.account }

// Stage is the stage whose keys will sign, and Target the stage the spend
// hands the account to. Target is always Stage + 1.
func (p *PreparedRotating) Stage() uint64  { return p.stage }
func (p *PreparedRotating) Target() uint64 { return p.target }

// RekeyTo is the next stage's address, as the signer reported it. The SDK
// cannot derive stage addresses; it binds this address to the prepared spend,
// and the signer derives it again from the seed before it signs.
func (p *PreparedRotating) RekeyTo() string { return p.rekeyTo }

// Transactions is the prepared group, hex msgpack with the TX prefix: the
// spend first, then any resource dummies.
func (p *PreparedRotating) Transactions() []string {
	return append([]string(nil), p.transactions...)
}

// Mutations is the signer's report of what it added to the spend, checked
// against the prepared bytes. Nil when it added nothing but the rekey.
func (p *PreparedRotating) Mutations() *MutationReport {
	if p.mutations == nil {
		return nil
	}
	report := *p.mutations
	report.FeesModified = append([]int(nil), p.mutations.FeesModified...)
	return &report
}

// Original is the transaction the caller sent to be prepared.
func (p *PreparedRotating) Original() types.Transaction {
	txn, _ := decodeCanonicalTxn(p.original)
	return txn
}

// TxIDs are the IDs of the prepared transactions. Signing does not change
// them.
func (p *PreparedRotating) TxIDs() []string {
	txns, _ := p.decoded()
	ids := make([]string, len(txns))
	for i := range txns {
		ids[i] = crypto.GetTxID(txns[i])
	}
	return ids
}

// lastValid is the earliest last valid round of the prepared group. The group
// has been verified, so it decodes.
func (p *PreparedRotating) lastValid() uint64 {
	txns, _ := p.decoded()
	return earliestLastValid(txns)
}

func (p *PreparedRotating) decoded() ([]types.Transaction, error) {
	txns := make([]types.Transaction, len(p.transactions))
	for i, h := range p.transactions {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("prepared transaction %d: invalid hex: %w", i+1, err)
		}
		if txns[i], err = decodeCanonicalTxn(raw); err != nil {
			return nil, fmt.Errorf("prepared transaction %d: %w", i+1, err)
		}
	}
	return txns, nil
}

// RotatingPrepareOptions configures PrepareRotating.
type RotatingPrepareOptions struct {
	// AppCallInfo is optional app-call metadata shown to the operator when
	// the prepared spend is signed. The signer checks it against the spend's
	// bytes and does not sign it.
	AppCallInfo *AppCallInfo
}

// RotatingSignOptions configures SignPreparedRotating.
type RotatingSignOptions struct {
	// RequestID is the sign request's ID, for CancelSignRequestWithContext
	// and the signer's audit log. Empty means the SDK creates one. It is not
	// an idempotency key.
	RequestID string
}

// RotatingSignResult is a signed rotating group, checked against the
// prepared one. Submit it promptly: the stage's one-time keys are revealed
// until this transaction or a later rotation confirms.
type RotatingSignResult struct {
	// SignedGroup is the signed group, hex msgpack, in prepared order.
	SignedGroup []string
	Stage       uint64
	Target      uint64
	// TxID and GroupID are computed from the prepared bytes; the signer's
	// own report of them was checked against these.
	TxID      string
	GroupID   string
	RequestID string
}

// RotatingPreflightError reports a prepared rotating group that failed its
// unsigned simulation. Nothing was signed. The simulation fails on the node's
// own failure-message, and on an answer that does not cover the group:
// without exactly one result (none, or more than one), a result reporting
// failed-at without a message, or one whose count of transaction results is
// not the number of transactions simulated.
type RotatingPreflightError struct {
	Prepared *PreparedRotating
	// Message says why, as SimulationResult.FailureMessage does: the node's
	// failure-message, or which of the other failures it was.
	Message string
}

func (e *RotatingPreflightError) Error() string {
	return "prepared rotating group failed simulation; nothing was signed: " + e.Message
}

// checkRotatingShape applies the rotating rules about a spend's shape that
// need neither the signer nor the chain. The signer applies them too.
func checkRotatingShape(txn types.Transaction) error {
	switch {
	case txn.Group != (types.Digest{}):
		return fmt.Errorf("%w: a rotating account's transaction must be ungrouped; the signer forms the group", ErrUnsupportedGroup)
	case !txn.RekeyTo.IsZero():
		return fmt.Errorf("%w: a rotating account's transaction must not set rekey_to; the signer rotates the account itself", ErrUnsupportedGroup)
	case !txn.CloseRemainderTo.IsZero():
		return fmt.Errorf("%w: a rotating account cannot close out", ErrUnsupportedGroup)
	}
	return nil
}

// checkRotatingWindow refuses a validity window the stage program never
// accepts, whatever the current round.
func checkRotatingWindow(txn types.Transaction) error {
	if txn.LastValid < txn.FirstValid {
		return fmt.Errorf("last valid round %d is before first valid round %d", txn.LastValid, txn.FirstValid)
	}
	if window := uint64(txn.LastValid - txn.FirstValid); window > RotatingMaxValidityWindow {
		return fmt.Errorf("validity window is %d rounds; a rotating account accepts at most %d (build the transaction with a Prepare* helper, or set RefreshValidity)", window, RotatingMaxValidityWindow)
	}
	return nil
}

// PrepareRotating asks the signer to prepare one transaction from a rotating
// account and checks the group it returns. The transaction must be ungrouped,
// set no rekey_to, not close the account, and have a validity window of at
// most RotatingMaxValidityWindow rounds. Nothing is signed.
//
// The signer may set rekey_to to the next stage's address, raise the fee,
// assign a group ID and append canonical resource dummies. Any other change,
// a report that disagrees with the bytes, or a fee raise above the client's
// max fee increase is an error.
func (c *SignerClient) PrepareRotating(ctx context.Context, txn types.Transaction, opts *RotatingPrepareOptions) (*PreparedRotating, error) {
	if err := checkRotatingShape(txn); err != nil {
		return nil, err
	}
	if err := checkRotatingWindow(txn); err != nil {
		return nil, err
	}
	original := encodeTxn(txn)
	request := RotatingPrepareRequest{Account: txn.Sender.String(), TxnBytesHex: hex.EncodeToString(original)}
	jsonBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqCtx, cancel := c.requestContext(ctx, groupPlanTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/sign/rotating/prepare", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare rotating spend: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, rotatingAPIError(signerHTTPErrorOp(resp, "rotating prepare failed"))
	}
	var response RotatingPrepareResponse
	if err := readAnswer(resp.Body, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var appCallInfo *AppCallInfo
	if opts != nil {
		appCallInfo = opts.AppCallInfo
	}
	return newPreparedRotating(original, &response, c.feeCeiling(), appCallInfo)
}

// newPreparedRotating binds a prepare response to the transaction that was
// sent and checks it. Everything it keeps is a copy.
func newPreparedRotating(original []byte, response *RotatingPrepareResponse, ceiling feeCeiling, appCallInfo *AppCallInfo) (*PreparedRotating, error) {
	prepared := &PreparedRotating{
		account:      response.Account,
		original:     append([]byte(nil), original...),
		stage:        response.Stage,
		target:       response.Target,
		rekeyTo:      response.RekeyTo,
		transactions: append([]string(nil), response.Transactions...),
		ceiling:      ceiling,
	}
	if response.Mutations != nil {
		report := *response.Mutations
		report.FeesModified = append([]int(nil), response.Mutations.FeesModified...)
		prepared.mutations = &report
	}
	if appCallInfo != nil {
		info := *appCallInfo
		prepared.appCallInfo = &info
	}
	if err := prepared.verify(); err != nil {
		return nil, fmt.Errorf("verify prepared rotating group: %w", err)
	}
	return prepared, nil
}

// rotatingAPIError maps the statuses every signing call maps, and leaves the
// rest as an *APIError so its stable code can be read.
func rotatingAPIError(apiErr *APIError) error {
	switch apiErr.StatusCode {
	case http.StatusUnauthorized:
		return ErrAuthentication
	case http.StatusForbidden:
		return rejectedForbidden(apiErr)
	}
	return apiErr
}

// verify checks the prepared group against the transaction the caller sent.
// It is the client's authority boundary for a rotating spend: the signer may
// set rekey_to to the address it reports, raise the spend's fee, assign the
// canonical group ID and append canonical resource dummies, and nothing else.
func (p *PreparedRotating) verify() error {
	original, err := decodeCanonicalTxn(p.original)
	if err != nil {
		return fmt.Errorf("original transaction: %w", err)
	}
	if p.account != original.Sender.String() {
		return fmt.Errorf("prepared account %s is not the sender", p.account)
	}
	if p.stage == math.MaxUint64 || p.target != p.stage+1 {
		return fmt.Errorf("prepared target stage %d is not the stage after %d", p.target, p.stage)
	}
	rekeyTo, err := types.DecodeAddress(p.rekeyTo)
	if err != nil {
		return fmt.Errorf("invalid rekey_to: %w", err)
	}
	if rekeyTo.IsZero() || rekeyTo == original.Sender {
		return fmt.Errorf("rekey_to must be another, non-zero address")
	}
	if len(p.transactions) == 0 {
		return fmt.Errorf("prepared group is empty")
	}
	txns, err := p.decoded()
	if err != nil {
		return err
	}

	// The one change no ordinary sign response may make is applied to the
	// expectation, so the common check still refuses every unrequested rekey.
	expected := original
	expected.RekeyTo = rekeyTo
	slot, err := signSlot(expected, p.account)
	if err != nil {
		return err
	}
	returned := make([]*types.Transaction, len(txns))
	for i := range txns {
		returned[i] = &txns[i]
	}
	return validateGroupMutations([]requestSlot{slot}, returned, p.mutations, p.ceiling)
}

// SimulatePreparedRotating simulates the prepared group, unsigned, through
// the caller's algod. It never signs. A failed simulation is reported in the
// result's Failed field, not as an error.
//
// It checks the group's effects. It does not prove the stage's signatures
// will pass: the node runs the stage program only on the signed group.
func (c *SignerClient) SimulatePreparedRotating(ctx context.Context, algodClient *algod.Client, prepared *PreparedRotating) (*SimulationResult, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	if prepared == nil {
		return nil, fmt.Errorf("prepared rotating group is required")
	}
	if err := prepared.verify(); err != nil {
		return nil, fmt.Errorf("verify prepared rotating group: %w", err)
	}
	txns, err := prepared.decoded()
	if err != nil {
		return nil, err
	}
	unsigned := make([]types.SignedTxn, len(txns))
	for i := range txns {
		unsigned[i] = types.SignedTxn{Txn: txns[i]}
	}
	response, err := runSimulation(ctx, algodClient, unsigned, true)
	if err != nil {
		return nil, err
	}
	failure := simulationFailure(response, len(unsigned))
	return &SimulationResult{
		TxIDs:          prepared.TxIDs(),
		Transactions:   prepared.Transactions(),
		Mutations:      prepared.Mutations(),
		Response:       response,
		Failed:         failure != "",
		FailureMessage: failure,
	}, nil
}

// SignPreparedRotating asks the signer to sign a prepared rotating group,
// waits for operator approval, and checks the signed group against the
// prepared one. It does not submit.
//
// If the answer never arrives it returns a *SignOutcomeUnknownError that
// carries the prepared group. Calling SignPreparedRotating again with that
// same prepared group is the safe recovery: it asks for the same transaction,
// with the same IDs, and builds no second spend. It needs approval again, and
// it succeeds only while the stage is still live and the window still
// acceptable. If that retry is refused, do not prepare a replacement until
// the first attempt's outcome is known; rotating_stage_changed in particular
// means a transaction from that stage has confirmed.
func (c *SignerClient) SignPreparedRotating(ctx context.Context, prepared *PreparedRotating, opts *RotatingSignOptions) (*RotatingSignResult, error) {
	if prepared == nil {
		return nil, fmt.Errorf("prepared rotating group is required")
	}
	// The binding is checked again at the signing boundary.
	if err := prepared.verify(); err != nil {
		return nil, fmt.Errorf("verify prepared rotating group: %w", err)
	}
	requestID := ""
	if opts != nil {
		requestID = opts.RequestID
	}
	if requestID == "" {
		var err error
		if requestID, err = newSignRequestID(); err != nil {
			return nil, fmt.Errorf("failed to create sign request ID: %w", err)
		}
	}
	if err := validateSignRequestID(requestID); err != nil {
		return nil, err
	}
	request := RotatingSignRequest{
		RequestID:    requestID,
		Account:      prepared.account,
		Transactions: prepared.Transactions(),
		AppCallInfo:  prepared.appCallInfo,
	}
	jsonBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var response RotatingSignResponse
	if err := c.postApproval(ctx, "/sign/rotating/sign", requestID, jsonBody, &response); err != nil {
		var transport *signTransportError
		var unread *signUnreadError
		var apiErr *APIError
		switch {
		case errors.As(err, &transport):
			return nil, &SignOutcomeUnknownError{RequestID: requestID, Rotating: prepared, LastValid: prepared.lastValid(), Err: transport.err}
		case errors.As(err, &unread):
			return nil, &SignOutcomeUnknownError{RequestID: requestID, Rotating: prepared, LastValid: prepared.lastValid(), Err: err}
		case errors.As(err, &apiErr):
			apiErr.Op = "rotating sign failed"
			return nil, rotatingAPIError(apiErr)
		}
		return nil, err
	}
	result, err := prepared.verifySigned(&response)
	if err != nil {
		return nil, fmt.Errorf("verify signer response: %w", err)
	}
	result.RequestID = requestID
	return result, nil
}

// verifySigned checks that the signer signed exactly the prepared bytes: one
// canonically encoded signed transaction per prepared transaction, in order,
// the spend authorized by a stage program consistent with the reported stage,
// and every dummy by the dummy program.
func (p *PreparedRotating) verifySigned(response *RotatingSignResponse) (*RotatingSignResult, error) {
	txns, err := p.decoded()
	if err != nil {
		return nil, err
	}
	if len(response.Signed) != len(txns) {
		return nil, fmt.Errorf("signed group has %d transaction(s), prepared %d", len(response.Signed), len(txns))
	}
	if response.Stage != p.stage || response.Target != p.target {
		return nil, fmt.Errorf("signer reports stage %d to %d, prepared %d to %d", response.Stage, response.Target, p.stage, p.target)
	}
	spend := txns[0]
	for i, signedHex := range response.Signed {
		raw, err := hex.DecodeString(signedHex)
		if err != nil {
			return nil, fmt.Errorf("signed transaction %d: invalid hex: %w", i+1, err)
		}
		stxn, err := decodeCanonicalSignedTxn(raw)
		if err != nil {
			return nil, fmt.Errorf("signed transaction %d: %w", i+1, err)
		}
		if !bytes.Equal(encodeTxn(stxn.Txn), encodeTxn(txns[i])) {
			return nil, fmt.Errorf("signed transaction %d differs from the prepared transaction", i+1)
		}
		if i > 0 {
			want, err := signCanonicalDummy(txns[i])
			if err != nil {
				return nil, fmt.Errorf("signed transaction %d: %w", i+1, err)
			}
			if !bytes.Equal(raw, want) {
				return nil, fmt.Errorf("signed transaction %d is not the canonical signed resource dummy", i+1)
			}
			continue
		}
		// The spend is signed by the current stage's program. Its address is
		// the account itself at stage 0 and the account's authorizer after.
		// It is never the next stage's address, which is the rekey target.
		if len(stxn.Lsig.Logic) == 0 {
			return nil, fmt.Errorf("spend is not authorized by a stage program")
		}
		stageAddr := crypto.LogicSigAddress(types.LogicSig{Logic: stxn.Lsig.Logic})
		if err := validateAuthorization(stxn, stageAddr); err != nil {
			return nil, fmt.Errorf("spend %w", err)
		}
		if (stageAddr == spend.Sender) != (p.stage == 0) {
			return nil, fmt.Errorf("spend's stage program does not fit stage %d of the account", p.stage)
		}
		if stageAddr == spend.RekeyTo {
			return nil, fmt.Errorf("spend is authorized by the next stage's program")
		}
	}

	txID := crypto.GetTxID(spend)
	if response.TxID != txID {
		return nil, fmt.Errorf("signer reports transaction ID %s, the spend's is %s", response.TxID, txID)
	}
	groupID := ""
	if spend.Group != (types.Digest{}) {
		groupID = base64.StdEncoding.EncodeToString(spend.Group[:])
	}
	if response.GroupID != groupID && !(groupID == "" && response.GroupID == base64.StdEncoding.EncodeToString(spend.Group[:])) {
		return nil, fmt.Errorf("signer reports group ID %q, the spend's is %q", response.GroupID, groupID)
	}
	return &RotatingSignResult{
		SignedGroup: append([]string(nil), response.Signed...),
		Stage:       p.stage,
		Target:      p.target,
		TxID:        txID,
		GroupID:     groupID,
	}, nil
}

// rotatingWindowCurrent reports whether txn's window meets the signer's
// timing rule at round.
func rotatingWindowCurrent(txn types.Transaction, round uint64) bool {
	first, last := uint64(txn.FirstValid), uint64(txn.LastValid)
	return last >= first && last-first <= RotatingMaxValidityWindow &&
		first <= round+RotatingMaxLead && last >= round+RotatingMinRemaining
}

// refreshRotatingValidity rebuilds txn's validity rounds from current
// suggested parameters, keeping everything else. The window keeps its length
// unless that is over the rotating limit or too short to ever be signed.
// widen takes the longest window instead: after the signer found the window
// not current, the same length would leave the operator no more time.
func refreshRotatingValidity(ctx context.Context, algodClient *algod.Client, txn types.Transaction, widen bool) (types.Transaction, error) {
	sp, err := algodClient.SuggestedParams().Do(ctx)
	if err != nil {
		return txn, fmt.Errorf("failed to get suggested params: %w", err)
	}
	// A window shorter than the rounds that must remain can never be signed,
	// so it is not kept either.
	window := uint64(RotatingMaxValidityWindow)
	if !widen && txn.LastValid > txn.FirstValid {
		if length := uint64(txn.LastValid - txn.FirstValid); length >= RotatingMinRemaining && length < window {
			window = length
		}
	}
	first := uint64(sp.FirstRoundValid)
	if first > math.MaxUint64-window {
		return txn, fmt.Errorf("first valid round %d leaves no room for a validity window", first)
	}
	txn.FirstValid = types.Round(first)
	txn.LastValid = types.Round(first + window)
	return txn, nil
}

// apiErrorCode returns the stable signer error code err carries, or "".
func apiErrorCode(err error) string {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	return ""
}

// sendRotating runs the rotating1 flow for one transaction: prepare, check
// the prepared group, simulate it unsigned, then sign and submit exactly
// those bytes. A failed check or simulation happens before any key is used.
//
// refresh says the validity rounds may be rebuilt: always for a transaction
// the SDK built from an intent, and for a supplied one only when the caller
// set RefreshValidity. A supplied transaction is otherwise sent as given.
//
// An attempt is repeated, at most rotatingSendAttempts times, only when the
// signer said that attempt released no signature: it has not found the live
// stage yet, the account's authorizer moved between prepare and sign, or the
// window was not current at signing. Every attempt needs approval again. A
// sign whose answer never arrived, and any failure after submission, ends the
// send: it never builds a replacement spend on its own.
func (c *SignerClient) sendRotating(ctx context.Context, algodClient *algod.Client, item PreparedTransaction, opts *SendOptions, refresh bool) (*SendResult, error) {
	if len(item.LsigArgs) > 0 {
		return nil, fmt.Errorf("%w: a rotating account takes no LogicSig arguments from the caller", ErrUnsupportedGroup)
	}
	txn := *item.Transaction
	// PrepareRotating refuses a spend of the wrong shape, or with a window
	// over the limit, before it asks the signer anything.
	prepareOpts := &RotatingPrepareOptions{AppCallInfo: item.AppCallInfo}

	for attempt := 1; ; attempt++ {
		last := attempt == rotatingSendAttempts
		// The signer signs only while the window is current. Checking here
		// saves the operator an approval that could not lead to a signature.
		status, err := algodClient.Status().Do(ctx)
		if err != nil {
			return nil, fmt.Errorf("read current round: %w", err)
		}
		if !rotatingWindowCurrent(txn, status.LastRound) {
			if !refresh {
				if windowErr := checkRotatingWindow(txn); windowErr != nil {
					return nil, windowErr
				}
				return nil, fmt.Errorf("validity rounds %d-%d are not current at round %d: a rotating account signs only while first valid is at most %d rounds ahead and at least %d rounds remain (rebuild the transaction, or set RefreshValidity)",
					txn.FirstValid, txn.LastValid, status.LastRound, RotatingMaxLead, RotatingMinRemaining)
			}
			if txn, err = refreshRotatingValidity(ctx, algodClient, txn, false); err != nil {
				return nil, err
			}
		}

		prepared, err := c.PrepareRotating(ctx, txn, prepareOpts)
		if err != nil {
			if apiErrorCode(err) == ErrCodeRotatingStageUnproven && !last {
				if waitErr := sleepContext(ctx, time.Duration(attempt)*rotatingUnprovenBackoff); waitErr != nil {
					return nil, fmt.Errorf("%w (and the wait to retry ended: %v)", err, waitErr)
				}
				continue
			}
			return nil, err
		}

		simulation, err := c.SimulatePreparedRotating(ctx, algodClient, prepared)
		if err != nil {
			return nil, fmt.Errorf("simulate prepared rotating group; nothing was signed: %w", err)
		}
		if simulation.Failed {
			return nil, &RotatingPreflightError{Prepared: prepared, Message: simulation.FailureMessage}
		}
		// Nothing has been asked to sign yet, so an ended context is a plain
		// stop, not an unknown outcome.
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		signed, err := c.SignPreparedRotating(ctx, prepared, nil)
		if err != nil {
			switch apiErrorCode(err) {
			case ErrCodeRotatingStageChanged:
				if !last {
					continue
				}
			case ErrCodeRotatingWindowNotCurrent:
				if refresh && !last {
					if txn, err = refreshRotatingValidity(ctx, algodClient, txn, true); err != nil {
						return nil, err
					}
					continue
				}
			}
			return nil, err
		}

		result := &SendResult{
			Flow:          SigningFlowRotating1,
			SignedGroup:   signed.SignedGroup,
			OriginalCount: 1,
			Mutations:     prepared.Mutations(),
			Rotating: &RotatingSendDetails{
				Stage:       signed.Stage,
				Target:      signed.Target,
				RekeyTo:     prepared.RekeyTo(),
				Attempts:    attempt,
				Transaction: txn,
				RequestID:   signed.RequestID,
			},
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
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// prepSuggestedParams fetches suggested parameters for a transaction sender
// is about to send. For a rotating account it shortens the validity window to
// what the account's stage program accepts, so every Prepare* helper builds a
// transaction a rotating account can send.
func (c *SignerClient) prepSuggestedParams(ctx context.Context, algodClient *algod.Client, sender string) (types.SuggestedParams, error) {
	suggested, err := algodClient.SuggestedParams().Do(ctx)
	if err != nil {
		return suggested, err
	}
	// A signer that cannot be asked is not reported here: the helper's own
	// key resolution asks it next and reports the failure in its usual form.
	rotating, _ := c.isRotatingAccount(ctx, sender)
	if rotating && uint64(suggested.LastRoundValid-suggested.FirstRoundValid) > RotatingMaxValidityWindow {
		suggested.LastRoundValid = suggested.FirstRoundValid + RotatingMaxValidityWindow
	}
	return suggested, nil
}

// isRotatingAccount reports whether the signer's own record of address is a
// rotating account. An address the signer does not hold is not one.
func (c *SignerClient) isRotatingAccount(ctx context.Context, address string) (bool, error) {
	if address == "" {
		return false, nil
	}
	keys, err := c.ListKeysIfKeysetChangedWithContext(ctx)
	if err != nil {
		return false, err
	}
	key, ok := findSpendableKey(keys, address)
	return ok && key.SigningFlow == SigningFlowRotating1, nil
}
