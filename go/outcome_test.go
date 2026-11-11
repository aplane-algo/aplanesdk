// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
)

// outcomeNode is a node for the outcome helpers: a current round, an answer
// for the pending-transaction lookup, and a status-after-block call that moves
// the round on.
type outcomeNode struct {
	t *testing.T

	mu    sync.Mutex
	round uint64
	// lookup answers the pending-transaction lookup; nil answers 404.
	lookup func(round uint64) (status int, info *models.PendingTransactionInfoResponse)
	// statusFails makes the status call answer 500.
	statusFails bool
	// step is how far each status-after-block call moves the round.
	step  uint64
	calls []string
}

func (n *outcomeNode) handle(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, r.Method+" "+r.URL.Path)
	switch {
	case r.Method != http.MethodGet:
		n.t.Errorf("the outcome helper made a %s request to %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusMethodNotAllowed)
	case strings.HasPrefix(r.URL.Path, "/v2/status/wait-for-block-after/"):
		if n.step == 0 {
			// A node with no new block answers after a while.
			time.Sleep(5 * time.Millisecond)
		}
		n.round += n.step
		json.NewEncoder(w).Encode(map[string]uint64{"last-round": n.round})
	case r.URL.Path == "/v2/status":
		if n.statusFails {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"message": "node broke"})
			return
		}
		json.NewEncoder(w).Encode(map[string]uint64{"last-round": n.round})
	case strings.HasPrefix(r.URL.Path, "/v2/transactions/pending/"):
		status, info := http.StatusNotFound, (*models.PendingTransactionInfoResponse)(nil)
		if n.lookup != nil {
			status, info = n.lookup(n.round)
		}
		if info == nil {
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]string{"message": "txn not found"})
			return
		}
		w.Write(msgpack.Encode(*info))
	default:
		n.t.Errorf("unexpected node request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func (n *outcomeNode) requests() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.calls...)
}

func (n *outcomeNode) count(prefix string) int {
	count := 0
	for _, call := range n.requests() {
		if strings.HasPrefix(call, prefix) {
			count++
		}
	}
	return count
}

// outcomeFixture is a node and a signer client whose signer fails the test on
// any request: the helpers never call the signer.
func outcomeFixture(t *testing.T, node *outcomeNode) (*SignerClient, *algod.Client) {
	t.Helper()
	node.t = t
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the outcome helper called the signer: %s %s", r.Method, r.URL.Path)
	})
	t.Cleanup(server.Close)
	algodClient, closeAlgod := makeSimulationAlgodClient(t, node.handle)
	t.Cleanup(closeAlgod)
	return client, algodClient
}

func confirmedIn(round uint64) func(uint64) (int, *models.PendingTransactionInfoResponse) {
	return func(uint64) (int, *models.PendingTransactionInfoResponse) {
		return http.StatusOK, &models.PendingTransactionInfoResponse{ConfirmedRound: round}
	}
}

func inPool(uint64) (int, *models.PendingTransactionInfoResponse) {
	return http.StatusOK, &models.PendingTransactionInfoResponse{}
}

func poolError(uint64) (int, *models.PendingTransactionInfoResponse) {
	return http.StatusOK, &models.PendingTransactionInfoResponse{PoolError: "overspend"}
}

// outcomeRotating is a prepared rotating group holding txn, enough for the
// outcome helpers, which read only its IDs.
func outcomeRotating(t *testing.T) *PreparedRotating {
	t.Helper()
	txn := verifyTestPayment(t, 41, 42, 1)
	return &PreparedRotating{transactions: []string{hex.EncodeToString(encodeTxn(txn))}}
}

const outcomeLastValid = 1000

func uncertainSubmission() *SubmissionUncertainError {
	return &SubmissionUncertainError{
		Stage: SendStageConfirm, SignedGroup: []string{"aabb"}, TxIDs: []string{"TXONE", "TXTWO"},
		LastValid: outcomeLastValid, Err: errors.New("not confirmed after 10 rounds"),
	}
}

func TestResolveOutcomeOfAnUncertainSubmission(t *testing.T) {
	const (
		confirmed = "The group was confirmed in round 990. Do not send it again."
		pending   = "The group is in the node's pool. Wait; do not send again."
		notSeen   = "The node does not have the group and it can still execute until round 1000. Submit the same signed group again, or wait until round 1000 has passed."
		expired   = "The group was not confirmed and can no longer execute. It is safe to build a new one."
		tooOld    = "The group's validity ended more than 500 rounds ago and this node may no longer remember it. Look the transaction ID up on an indexer before sending again."
	)
	tests := []struct {
		name   string
		round  uint64
		lookup func(uint64) (int, *models.PendingTransactionInfoResponse)
		state  OutcomeState
		safe   bool
		advice string
	}{
		{"confirmed", 995, confirmedIn(990), OutcomeConfirmed, false, confirmed},
		{"confirmed, long after its validity", 5000, confirmedIn(990), OutcomeConfirmed, false, confirmed},
		{"in the pool", 995, inPool, OutcomePending, false, pending},
		{"not found while valid", 995, nil, OutcomeNotSeen, false, notSeen},
		{"not found at its last valid round", 1000, nil, OutcomeNotSeen, false, notSeen},
		{"a pool error while valid", 1000, poolError, OutcomeNotSeen, false, notSeen},
		{"not found one round after", 1001, nil, OutcomeExpired, true, expired},
		{"not found 500 rounds after", 1500, nil, OutcomeExpired, true, expired},
		{"a pool error 500 rounds after", 1500, poolError, OutcomeExpired, true, expired},
		{"not found 501 rounds after", 1501, nil, OutcomeTooOld, false, tooOld},
		{"a pool error 501 rounds after", 1501, poolError, OutcomeTooOld, false, tooOld},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &outcomeNode{round: tt.round, lookup: tt.lookup}
			client, algodClient := outcomeFixture(t, node)
			report, err := client.ResolveOutcome(context.Background(), algodClient, uncertainSubmission())
			if err != nil {
				t.Fatalf("ResolveOutcome() error = %v", err)
			}
			if report.State != tt.state || report.SafeToReplace != tt.safe || report.Advice != tt.advice {
				t.Fatalf("report = %+v, want %s safe=%v %q", report, tt.state, tt.safe, tt.advice)
			}
			wantConfirmed := uint64(0)
			if tt.state == OutcomeConfirmed {
				wantConfirmed = 990
			}
			if report.ConfirmedRound != wantConfirmed || report.CurrentRound != tt.round || report.LastValid != outcomeLastValid {
				t.Fatalf("rounds: confirmed %d current %d last valid %d", report.ConfirmedRound, report.CurrentRound, report.LastValid)
			}
			if strings.Join(report.TxIDs, ",") != "TXONE,TXTWO" || len(report.SignedGroup) != 1 || report.Rotating != nil {
				t.Fatalf("report = %+v, want the error's IDs and signed group", report)
			}
			// One lookup, of the first ID, after the round was read.
			calls := node.requests()
			if len(calls) != 2 || calls[0] != "GET /v2/status" || calls[1] != "GET /v2/transactions/pending/TXONE" {
				t.Fatalf("node calls = %v", calls)
			}
		})
	}
}

func TestResolveOutcomeOfAnUnknownSignOutcome(t *testing.T) {
	const (
		confirmed       = "The group was confirmed in round 990. Do not send it again."
		pending         = "The group is in the node's pool. Wait; do not send again."
		signableRotated = "A signature may have been released and can execute until round 1000. Sign the same prepared group again, or wait until round 1000 has passed."
		signablePlain   = "A signature may have been released and can execute until round 1000. Wait until round 1000 has passed before building a replacement."
		expired         = "No signature released by that request can execute any more. It is safe to build a new one."
		tooOld          = "The prepared group's validity ended more than 500 rounds ago and this node may no longer remember it. Look the transaction ID up on an indexer before sending again."
	)
	tests := []struct {
		name     string
		rotating bool
		round    uint64
		lookup   func(uint64) (int, *models.PendingTransactionInfoResponse)
		state    OutcomeState
		safe     bool
		advice   string
	}{
		{"rotating, confirmed", true, 995, confirmedIn(990), OutcomeConfirmed, false, confirmed},
		{"rotating, confirmed, looked up before the rounds", true, 1200, confirmedIn(990), OutcomeConfirmed, false, confirmed},
		{"rotating, in the pool", true, 995, inPool, OutcomePending, false, pending},
		{"rotating, not found while valid", true, 1000, nil, OutcomeSignable, false, signableRotated},
		{"rotating, a pool error while valid", true, 1000, poolError, OutcomeSignable, false, signableRotated},
		{"rotating, not found after", true, 1001, nil, OutcomeExpired, true, expired},
		{"rotating, a pool error after", true, 1001, poolError, OutcomeExpired, true, expired},
		{"rotating, not found 500 rounds after", true, 1500, nil, OutcomeExpired, true, expired},
		{"rotating, a pool error 500 rounds after", true, 1500, poolError, OutcomeExpired, true, expired},
		// Signed again, the same prepared group has the same IDs, and the node
		// may have forgotten it.
		{"rotating, not found 501 rounds after", true, 1501, nil, OutcomeTooOld, false, tooOld},
		{"rotating, a pool error 501 rounds after", true, 1501, poolError, OutcomeTooOld, false, tooOld},
		{"rotating, not found long after", true, 9000, nil, OutcomeTooOld, false, tooOld},
		{"ordinary, valid", false, 1000, nil, OutcomeSignable, false, signablePlain},
		{"ordinary, after", false, 1001, nil, OutcomeExpired, true, expired},
		{"ordinary, 501 rounds after: no too_old", false, 1501, nil, OutcomeExpired, true, expired},
		{"ordinary, long after", false, 9000, nil, OutcomeExpired, true, expired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &outcomeNode{round: tt.round, lookup: tt.lookup}
			client, algodClient := outcomeFixture(t, node)
			unknown := &SignOutcomeUnknownError{RequestID: "sdk-1", LastValid: outcomeLastValid, Err: errors.New("no answer")}
			var rotating *PreparedRotating
			if tt.rotating {
				rotating = outcomeRotating(t)
				unknown.Rotating = rotating
			}
			report, err := client.ResolveOutcome(context.Background(), algodClient, unknown)
			if err != nil {
				t.Fatalf("ResolveOutcome() error = %v", err)
			}
			if report.State != tt.state || report.SafeToReplace != tt.safe || report.Advice != tt.advice {
				t.Fatalf("report = %+v, want %s safe=%v %q", report, tt.state, tt.safe, tt.advice)
			}
			if report.CurrentRound != tt.round || report.LastValid != outcomeLastValid || report.Rotating != rotating || report.SignedGroup != nil {
				t.Fatalf("report = %+v", report)
			}
			calls := node.requests()
			if !tt.rotating {
				// The signer may have changed the transactions: no IDs, no lookup.
				if report.TxIDs == nil || len(report.TxIDs) != 0 || len(calls) != 1 || calls[0] != "GET /v2/status" {
					t.Fatalf("tx IDs %v, node calls %v; want none and the round only", report.TxIDs, calls)
				}
				return
			}
			wantID := rotating.TxIDs()[0]
			if len(report.TxIDs) != 1 || report.TxIDs[0] != wantID {
				t.Fatalf("tx IDs = %v, want the prepared group's", report.TxIDs)
			}
			if len(calls) != 2 || calls[0] != "GET /v2/status" || calls[1] != "GET /v2/transactions/pending/"+wantID {
				t.Fatalf("node calls = %v", calls)
			}
		})
	}
}

// A node that fails, other than with the lookup's 404, is an error from the
// call, never a state.
func TestResolveOutcomeNodeFailureIsAnError(t *testing.T) {
	failing := func(uint64) (int, *models.PendingTransactionInfoResponse) {
		return http.StatusInternalServerError, nil
	}
	cases := map[string]struct {
		node *outcomeNode
		err  error
	}{
		"status fails, submission":       {&outcomeNode{round: 900, statusFails: true}, uncertainSubmission()},
		"status fails, sign":             {&outcomeNode{round: 900, statusFails: true}, &SignOutcomeUnknownError{LastValid: outcomeLastValid}},
		"lookup fails, submission":       {&outcomeNode{round: 1600, lookup: failing}, uncertainSubmission()},
		"lookup fails, rotating sign":    {&outcomeNode{round: 1600, lookup: failing}, nil},
		"lookup answers 400, submission": {&outcomeNode{round: 1600, lookup: func(uint64) (int, *models.PendingTransactionInfoResponse) { return http.StatusBadRequest, nil }}, uncertainSubmission()},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			client, algodClient := outcomeFixture(t, tc.node)
			target := tc.err
			if target == nil {
				target = &SignOutcomeUnknownError{LastValid: outcomeLastValid, Rotating: outcomeRotating(t)}
			}
			report, err := client.ResolveOutcome(context.Background(), algodClient, target)
			if err == nil || report != nil {
				t.Fatalf("ResolveOutcome() = %+v, %v; want an error", report, err)
			}
		})
	}
}

func TestResolveOutcomeRefusesOtherErrors(t *testing.T) {
	node := &outcomeNode{round: 900}
	client, algodClient := outcomeFixture(t, node)
	for name, err := range map[string]error{
		"nil":      nil,
		"plain":    errors.New("signing failed"),
		"rejected": &SubmissionRejectedError{TxIDs: []string{"TX"}, Err: errors.New("overspend")},
		"locked":   ErrSignerLocked,
	} {
		t.Run(name, func(t *testing.T) {
			report, got := client.ResolveOutcome(context.Background(), algodClient, err)
			if report != nil || !errors.Is(got, ErrNotUncertainOutcome) || got.Error() != "not an uncertain outcome" {
				t.Fatalf("ResolveOutcome() = %+v, %v; want ErrNotUncertainOutcome", report, got)
			}
			if _, got := client.WaitForOutcome(context.Background(), algodClient, err, nil); !errors.Is(got, ErrNotUncertainOutcome) {
				t.Fatalf("WaitForOutcome() error = %v, want ErrNotUncertainOutcome", got)
			}
		})
	}
	if calls := node.requests(); len(calls) != 0 {
		t.Fatalf("node calls = %v, want none", calls)
	}

	// A wrapped uncertain outcome is still one.
	wrapped := fmt.Errorf("pay the invoice: %w", uncertainSubmission())
	if report, err := client.ResolveOutcome(context.Background(), algodClient, wrapped); err != nil || report.State != OutcomeNotSeen {
		t.Fatalf("ResolveOutcome(wrapped) = %+v, %v", report, err)
	}
}

// An error built without what the helper needs is refused before the node is
// asked anything.
func TestResolveOutcomeRefusesAnIncompleteError(t *testing.T) {
	noIDs := uncertainSubmission()
	noIDs.TxIDs = nil
	noLastValidSubmission := uncertainSubmission()
	noLastValidSubmission.LastValid = 0
	cases := map[string]struct {
		err  error
		text string
	}{
		"submission without IDs":        {noIDs, "the error carries no transaction IDs"},
		"submission without last valid": {noLastValidSubmission, "the error carries no last valid round"},
		"sign without last valid":       {&SignOutcomeUnknownError{RequestID: "sdk-1"}, "the error carries no last valid round"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			node := &outcomeNode{round: 900}
			client, algodClient := outcomeFixture(t, node)
			report, err := client.ResolveOutcome(context.Background(), algodClient, tc.err)
			if report != nil || err == nil || err.Error() != tc.text {
				t.Fatalf("ResolveOutcome() = %+v, %v; want %q", report, err, tc.text)
			}
			if calls := node.requests(); len(calls) != 0 {
				t.Fatalf("node calls = %v, want none", calls)
			}
		})
	}
}

func TestWaitForOutcomePollsOncePerRoundUntilSettled(t *testing.T) {
	t.Run("an unknown sign outcome waits out its validity", func(t *testing.T) {
		node := &outcomeNode{round: 997, step: 1}
		client, algodClient := outcomeFixture(t, node)
		report, err := client.WaitForOutcome(context.Background(), algodClient, &SignOutcomeUnknownError{LastValid: outcomeLastValid}, nil)
		if err != nil || report.State != OutcomeExpired || report.CurrentRound != 1001 || !report.SafeToReplace {
			t.Fatalf("WaitForOutcome() = %+v, %v", report, err)
		}
		// Rounds 997, 998, 999 and 1000 are signable; 1001 settles it.
		if waits := node.count("GET /v2/status/wait-for-block-after/"); waits != 4 {
			t.Fatalf("waited for %d rounds, want 4", waits)
		}
		if lookups := node.count("GET /v2/transactions/pending/"); lookups != 0 {
			t.Fatalf("looked up %d times, want none", lookups)
		}
	})
	t.Run("a submission confirms while waiting", func(t *testing.T) {
		node := &outcomeNode{round: 990, step: 1}
		node.lookup = func(round uint64) (int, *models.PendingTransactionInfoResponse) {
			if round < 993 {
				return inPool(round)
			}
			return confirmedIn(993)(round)
		}
		client, algodClient := outcomeFixture(t, node)
		report, err := client.WaitForOutcome(context.Background(), algodClient, uncertainSubmission(), nil)
		if err != nil || report.State != OutcomeConfirmed || report.ConfirmedRound != 993 {
			t.Fatalf("WaitForOutcome() = %+v, %v", report, err)
		}
		if waits := node.count("GET /v2/status/wait-for-block-after/"); waits != 3 {
			t.Fatalf("waited for %d rounds, want 3", waits)
		}
	})
	t.Run("an already settled outcome does not wait", func(t *testing.T) {
		node := &outcomeNode{round: 1600, step: 1}
		client, algodClient := outcomeFixture(t, node)
		report, err := client.WaitForOutcome(context.Background(), algodClient, uncertainSubmission(), nil)
		if err != nil || report.State != OutcomeTooOld || node.count("GET /v2/status/wait-for-block-after/") != 0 {
			t.Fatalf("WaitForOutcome() = %+v, %v", report, err)
		}
	})
	t.Run("a node failure ends the wait with the last report", func(t *testing.T) {
		node := &outcomeNode{round: 990, step: 1}
		node.lookup = func(round uint64) (int, *models.PendingTransactionInfoResponse) {
			if round < 992 {
				return inPool(round)
			}
			return http.StatusInternalServerError, nil
		}
		client, algodClient := outcomeFixture(t, node)
		report, err := client.WaitForOutcome(context.Background(), algodClient, uncertainSubmission(), nil)
		if err == nil || report == nil || report.State != OutcomePending || report.CurrentRound != 991 {
			t.Fatalf("WaitForOutcome() = %+v, %v; want the round-991 report and the node's error", report, err)
		}
	})
}

func TestWaitForOutcomeEndsWithTheContext(t *testing.T) {
	// The round never moves, so the outcome never settles.
	t.Run("timeout", func(t *testing.T) {
		node := &outcomeNode{round: 995}
		client, algodClient := outcomeFixture(t, node)
		report, err := client.WaitForOutcome(context.Background(), algodClient, uncertainSubmission(), &WaitOutcomeOptions{Timeout: 50 * time.Millisecond})
		if !errors.Is(err, context.DeadlineExceeded) || report == nil || report.State != OutcomeNotSeen {
			t.Fatalf("WaitForOutcome() = %+v, %v; want the last report and the deadline", report, err)
		}
	})
	t.Run("caller's context", func(t *testing.T) {
		node := &outcomeNode{round: 995}
		client, algodClient := outcomeFixture(t, node)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		report, err := client.WaitForOutcome(ctx, algodClient, &SignOutcomeUnknownError{LastValid: outcomeLastValid}, nil)
		if !errors.Is(err, context.DeadlineExceeded) || report == nil || report.State != OutcomeSignable {
			t.Fatalf("WaitForOutcome() = %+v, %v; want the last report and the deadline", report, err)
		}
	})
	t.Run("ended before the first check", func(t *testing.T) {
		node := &outcomeNode{round: 995}
		client, algodClient := outcomeFixture(t, node)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		report, err := client.WaitForOutcome(ctx, algodClient, uncertainSubmission(), nil)
		if !errors.Is(err, context.Canceled) || report != nil {
			t.Fatalf("WaitForOutcome() = %+v, %v; want no report and the cancellation", report, err)
		}
	})
}
