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
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// sendSigner is a fake signer for send tests. sign answers /sign; nil signs
// every position as its auth address.
type sendSigner struct {
	t    *testing.T
	keys []KeyInfo
	sign http.HandlerFunc
	// behaviour is what the default /sign answer does to the group.
	behaviour fakeSigner
	mu        sync.Mutex
	paths     []string
}

func (s *sendSigner) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, p := range s.paths {
		if p == path {
			n++
		}
	}
	return n
}

func (s *sendSigner) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.URL.Path)
	s.mu.Unlock()
	switch r.URL.Path {
	case "/status":
		json.NewEncoder(w).Encode(StatusResponse{State: "unlocked"})
	case "/keys":
		json.NewEncoder(w).Encode(KeysResponse{Count: len(s.keys), Keys: s.keys})
	case "/sign":
		if s.sign != nil {
			s.sign(w, r)
			return
		}
		var request GroupSignRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.t.Errorf("decode sign request: %v", err)
			return
		}
		json.NewEncoder(w).Encode(s.behaviour.sign(s.t, request.Requests))
	default:
		s.t.Errorf("unexpected signer path %s", r.URL.Path)
	}
}

// sendAlgod is a fake node for send tests.
type sendAlgod struct {
	t *testing.T
	// submit answers POST /v2/transactions; nil accepts the group and reports
	// its first transaction's ID.
	submit func(w http.ResponseWriter, blob []byte)
	// pending answers the pending-transaction lookup; nil confirms in round 12.
	pending func() models.PendingTransactionInfoResponse

	// authAddrs is the chain's auth address per account, for account lookups.
	authAddrs map[string]string
	// simulate answers the simulate endpoint; nil reports success.
	simulate func(w http.ResponseWriter, request models.SimulateRequest)
	// round is the node's current round; zero means 10.
	round uint64

	mu        sync.Mutex
	submitted [][]byte
	simulated []models.SimulateRequest
	lookups   int
	// accountReads counts account lookups.
	accountReads int
	// followed is the transaction ID of each pending-transaction lookup.
	followed []string
}

func (a *sendAlgod) currentRound() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.round == 0 {
		return 10
	}
	return a.round
}

func (a *sendAlgod) simulations() []models.SimulateRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]models.SimulateRequest(nil), a.simulated...)
}

func (a *sendAlgod) submissions() [][]byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([][]byte(nil), a.submitted...)
}

func (a *sendAlgod) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v2/transactions":
		blob, err := io.ReadAll(r.Body)
		if err != nil {
			a.t.Errorf("read submission: %v", err)
			return
		}
		a.mu.Lock()
		a.submitted = append(a.submitted, blob)
		a.mu.Unlock()
		if a.submit != nil {
			a.submit(w, blob)
			return
		}
		var first types.SignedTxn
		if err := msgpack.NewDecoder(strings.NewReader(string(blob))).Decode(&first); err != nil {
			a.t.Errorf("decode submission: %v", err)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"txId": crypto.GetTxID(first.Txn)})
	case strings.HasPrefix(r.URL.Path, "/v2/status/wait-for-block-after/"):
		json.NewEncoder(w).Encode(map[string]uint64{"last-round": a.currentRound()})
	case r.URL.Path == "/v2/status":
		json.NewEncoder(w).Encode(map[string]uint64{"last-round": a.currentRound()})
	case strings.HasPrefix(r.URL.Path, "/v2/accounts/"):
		address := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
		a.mu.Lock()
		a.accountReads++
		a.mu.Unlock()
		account := map[string]any{"address": address, "amount": 5_000_000, "min-balance": 100_000}
		if auth := a.authAddrs[address]; auth != "" {
			account["auth-addr"] = auth
		}
		json.NewEncoder(w).Encode(account)
	case r.URL.Path == "/v2/transactions/params":
		var genesisHash types.Digest
		genesisHash[0] = 7
		json.NewEncoder(w).Encode(map[string]any{
			"fee": 0, "min-fee": 1000, "last-round": a.currentRound(), "genesis-id": "testnet-v1.0",
			"genesis-hash": genesisHash[:], "consensus-version": "test",
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v2/transactions/simulate":
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			a.t.Errorf("read simulate request: %v", err)
			return
		}
		var request models.SimulateRequest
		if err := msgpack.Decode(raw, &request); err != nil {
			a.t.Errorf("decode simulate request: %v", err)
			return
		}
		a.mu.Lock()
		a.simulated = append(a.simulated, request)
		a.mu.Unlock()
		if a.simulate != nil {
			a.simulate(w, request)
			return
		}
		json.NewEncoder(w).Encode(passingSimulation(a.currentRound(), request))
	case strings.HasPrefix(r.URL.Path, "/v2/transactions/pending/"):
		a.mu.Lock()
		a.lookups++
		a.followed = append(a.followed, strings.TrimPrefix(r.URL.Path, "/v2/transactions/pending/"))
		a.mu.Unlock()
		info := models.PendingTransactionInfoResponse{ConfirmedRound: 12}
		if a.pending != nil {
			info = a.pending()
		}
		w.Write(msgpack.Encode(info))
	default:
		a.t.Errorf("unexpected algod request %s %s", r.Method, r.URL.Path)
	}
}

// passingSimulation is a node's answer for a group that passed: one group
// result holding one transaction result per transaction simulated.
func passingSimulation(round uint64, request models.SimulateRequest) models.SimulateResponse {
	group := models.SimulateTransactionGroupResult{}
	if len(request.TxnGroups) > 0 {
		group.TxnResults = make([]models.SimulateTransactionResult, len(request.TxnGroups[0].Txns))
	}
	return models.SimulateResponse{LastRound: round, Version: 2, TxnGroups: []models.SimulateTransactionGroupResult{group}}
}

func newSendFixture(t *testing.T, signer *sendSigner, node *sendAlgod) (*SignerClient, *algod.Client) {
	t.Helper()
	signer.t, node.t = t, t
	client, signerServer := newTestClient(signer.handle)
	t.Cleanup(signerServer.Close)
	algodClient, closeAlgod := makeSimulationAlgodClient(t, node.handle)
	t.Cleanup(closeAlgod)
	return client, algodClient
}

func ordinaryKey(txn types.Transaction) KeyInfo {
	return KeyInfo{Address: txn.Sender.String(), KeyType: "ed25519"}
}

func preparedFor(txn types.Transaction) PreparedGroup {
	return NewPreparedGroup(PreparedTransaction{Transaction: &txn, AuthAddress: txn.Sender.String()})
}

// hexEntries is a signed group in the signer's hex wire form, for comparing
// with a wire answer or writing a vector.
func hexEntries(group [][]byte) []string {
	entries := make([]string, len(group))
	for i, entry := range group {
		entries[i] = hex.EncodeToString(entry)
	}
	return entries
}

func TestSendPreparedSignsSubmitsAndConfirms(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}
	node := &sendAlgod{}
	client, algodClient := newSendFixture(t, signer, node)

	result, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
	if err != nil {
		t.Fatalf("SendPrepared() error = %v", err)
	}
	wantHex := fakeSignedTxnHex(txn)
	if len(result.SignedGroup) != 1 || hex.EncodeToString(result.SignedGroup[0]) != wantHex {
		t.Fatalf("signed group = %x", result.SignedGroup)
	}
	submitted := node.submissions()
	if len(submitted) != 1 || hex.EncodeToString(submitted[0]) != wantHex {
		t.Fatalf("submitted %d blob(s); want exactly the signed bytes once", len(submitted))
	}
	if result.Outcome != SendOutcomeConfirmed || result.ConfirmedRound != 12 {
		t.Fatalf("outcome = %s round %d", result.Outcome, result.ConfirmedRound)
	}
	if result.Flow != "" || result.OriginalCount != 1 || result.GroupID != "" {
		t.Fatalf("result = %+v", result)
	}
	if len(result.TxIDs) != 1 || result.TxIDs[0] != crypto.GetTxID(txn) {
		t.Fatalf("txids = %v", result.TxIDs)
	}
	if len(result.Fees) != 1 || result.Fees[0] != 1000 {
		t.Fatalf("fees = %v", result.Fees)
	}
	if signer.count("/sign") != 1 {
		t.Fatalf("sign calls = %d, want 1", signer.count("/sign"))
	}
}

func TestSendPreparedGroupReportsGroupID(t *testing.T) {
	first := verifyTestPayment(t, 41, 42, 1)
	second := verifyTestPayment(t, 43, 44, 2)
	signer := &sendSigner{keys: []KeyInfo{ordinaryKey(first), ordinaryKey(second)}}
	node := &sendAlgod{}
	client, algodClient := newSendFixture(t, signer, node)

	group := NewPreparedGroup(
		PreparedTransaction{Transaction: &first, AuthAddress: first.Sender.String()},
		PreparedTransaction{Transaction: &second, AuthAddress: second.Sender.String()},
	)
	result, err := client.SendPrepared(context.Background(), algodClient, group, nil)
	if err != nil {
		t.Fatalf("SendPrepared() error = %v", err)
	}
	if len(result.SignedGroup) != 2 || result.OriginalCount != 2 || result.GroupID == "" {
		t.Fatalf("result = %+v", result)
	}
	// The signer assigned the group, so the signed IDs are not the drafts'.
	if result.TxIDs[0] == crypto.GetTxID(first) {
		t.Fatalf("txid %s is the ungrouped draft's ID", result.TxIDs[0])
	}
	submitted := node.submissions()
	if len(submitted) != 1 || !bytes.Equal(submitted[0], bytes.Join(result.SignedGroup, nil)) {
		t.Fatalf("submission is not the signed group, in order, once")
	}
	// The wait follows the first signed transaction's ID.
	if strings.Join(node.followed, ",") != result.TxIDs[0] {
		t.Fatalf("the wait followed %v, want only %s", node.followed, result.TxIDs[0])
	}
}

func TestSendPreparedNoWaitReturnsSubmitted(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}
	node := &sendAlgod{}
	client, algodClient := newSendFixture(t, signer, node)

	result, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), &SendOptions{NoWait: true})
	if err != nil {
		t.Fatalf("SendPrepared() error = %v", err)
	}
	if result.Outcome != SendOutcomeSubmitted || result.ConfirmedRound != 0 {
		t.Fatalf("outcome = %s round %d, want submitted", result.Outcome, result.ConfirmedRound)
	}
	if node.lookups != 0 {
		t.Fatalf("pending lookups = %d, want none", node.lookups)
	}
	if result.Confirmation != nil {
		t.Fatalf("Confirmation = %+v, want nil without a wait", result.Confirmation)
	}
}

// The result carries what go-algorand-sdk's wait returned for the first
// transaction, unchanged, from a send and from SubmitSignedGroup alike.
func TestSendResultCarriesTheWaitsConfirmation(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}
	node := &sendAlgod{pending: func() models.PendingTransactionInfoResponse {
		return models.PendingTransactionInfoResponse{
			ConfirmedRound: 12, ApplicationIndex: 77, Logs: [][]byte{[]byte("log")},
			InnerTxns: []models.PendingTransactionResponse{{ConfirmedRound: 12, AssetIndex: 88}},
		}
	}}
	client, algodClient := newSendFixture(t, signer, node)

	want, err := transaction.WaitForConfirmation(algodClient, crypto.GetTxID(txn), 10, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sent, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
	if err != nil {
		t.Fatalf("SendPrepared() error = %v", err)
	}
	submitted, err := client.SubmitSignedGroup(context.Background(), algodClient, sent.SignedGroup, nil)
	if err != nil {
		t.Fatalf("SubmitSignedGroup() error = %v", err)
	}
	for name, result := range map[string]*SendResult{"SendPrepared": sent, "SubmitSignedGroup": submitted} {
		if result.Confirmation == nil || !reflect.DeepEqual(*result.Confirmation, want) {
			t.Fatalf("%s Confirmation = %+v, want go-algorand-sdk's %+v", name, result.Confirmation, want)
		}
		if result.ConfirmedRound != want.ConfirmedRound {
			t.Fatalf("%s ConfirmedRound = %d, want %d", name, result.ConfirmedRound, want.ConfirmedRound)
		}
	}
}

func TestSendPreparedRefusesBeforeSigning(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	other := verifyTestPayment(t, 45, 46, 1)
	sender := txn.Sender.String()
	holder := other.Sender.String()
	signedBytes, err := hex.DecodeString(fakeSignedTxnHex(txn))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		keys  []KeyInfo
		group PreparedGroup
		want  error
		text  string
	}{
		{
			name: "rotating sender in a group",
			keys: []KeyInfo{{Address: sender, SigningFlow: SigningFlowRotating1}, {Address: holder}},
			group: NewPreparedGroup(
				PreparedTransaction{Transaction: &txn, AuthAddress: sender},
				PreparedTransaction{Transaction: &other, AuthAddress: holder},
			),
			want: ErrUnsupportedGroup,
			text: "sends one transaction alone",
		},
		{
			// After a rotation the chain names a stage address, which the
			// signer does not hold; the sender's own record decides.
			name:  "rotating sender bound to a key the signer does not hold",
			keys:  []KeyInfo{{Address: sender, SigningFlow: SigningFlowRotating1}},
			group: NewPreparedGroup(PreparedTransaction{Transaction: &txn, AuthAddress: holder}),
			want:  ErrUnsupportedGroup,
			text:  "signs as itself",
		},
		{
			name:  "rekeyed to a rotating account",
			keys:  []KeyInfo{{Address: holder, SigningFlow: SigningFlowRotating1}},
			group: NewPreparedGroup(PreparedTransaction{Transaction: &txn, AuthAddress: holder}),
			want:  ErrUnsupportedGroup,
			text:  "signs only its own transactions",
		},
		{
			name:  "unknown flow",
			keys:  []KeyInfo{{Address: sender, SigningFlow: "future9"}},
			group: preparedFor(txn),
			want:  ErrUnsupportedSigningFlow,
			text:  "upgrade the SDK",
		},
		{
			name:  "unknown flow beside a cosigned account",
			keys:  []KeyInfo{{Address: sender, SigningFlow: SigningFlowCosigned1}, {Address: holder, SigningFlow: "future9"}},
			group: NewPreparedGroup(PreparedTransaction{Transaction: &txn, AuthAddress: sender}, PreparedTransaction{Transaction: &other, AuthAddress: holder}),
			want:  ErrUnsupportedSigningFlow,
			text:  "upgrade the SDK",
		},
		{
			name:  "pre-signed position",
			keys:  []KeyInfo{{Address: sender}},
			group: NewPreparedGroup(PreparedTransaction{SignedTransaction: signedBytes}),
			want:  ErrUnsupportedGroup,
			text:  "already signed",
		},
		{
			name:  "foreign position",
			keys:  []KeyInfo{{Address: sender}},
			group: NewPreparedGroup(PreparedTransaction{Transaction: &txn}),
			want:  ErrUnsupportedGroup,
			text:  "no auth address",
		},
		{
			name:  "key not held",
			keys:  []KeyInfo{{Address: holder}},
			group: preparedFor(txn),
			want:  ErrKeyNotFound,
			text:  "not available for signing",
		},
		{
			name:  "witness record is not a spending key",
			keys:  []KeyInfo{{Address: sender, IsSpendingAccount: new(bool)}},
			group: preparedFor(txn),
			want:  ErrKeyNotFound,
			text:  "not available for signing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := &sendSigner{keys: tt.keys}
			node := &sendAlgod{}
			client, algodClient := newSendFixture(t, signer, node)

			_, err := client.SendPrepared(context.Background(), algodClient, tt.group, nil)
			if !errors.Is(err, tt.want) || !strings.Contains(err.Error(), tt.text) {
				t.Fatalf("error = %v, want %v mentioning %q", err, tt.want, tt.text)
			}
			if signer.count("/sign") != 0 {
				t.Fatalf("sign calls = %d, want none", signer.count("/sign"))
			}
			if len(node.submissions()) != 0 {
				t.Fatalf("submissions = %d, want none", len(node.submissions()))
			}
		})
	}
}

func TestClassifySendRoutesWholeGroup(t *testing.T) {
	first := verifyTestPayment(t, 41, 42, 1)
	second := verifyTestPayment(t, 43, 44, 2)
	group := NewPreparedGroup(
		PreparedTransaction{Transaction: &first, AuthAddress: first.Sender.String()},
		PreparedTransaction{Transaction: &second, AuthAddress: second.Sender.String()},
	)
	tests := []struct {
		name        string
		firstFlow   string
		secondFlow  string
		wantGroupAs string
	}{
		{"ordinary and bounded", "", SigningFlowBounded1, ""},
		{"cosigned first", SigningFlowCosigned1, "", SigningFlowCosigned1},
		{"cosigned last", SigningFlowBounded1, SigningFlowCosigned1, SigningFlowCosigned1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := &sendSigner{keys: []KeyInfo{
				{Address: first.Sender.String(), SigningFlow: tt.firstFlow},
				{Address: second.Sender.String(), SigningFlow: tt.secondFlow},
			}}
			client, _ := newSendFixture(t, signer, &sendAlgod{})
			flow, _, err := client.classifySend(context.Background(), group)
			if err != nil || flow != tt.wantGroupAs {
				t.Fatalf("classifySend() = %q, %v; want %q", flow, err, tt.wantGroupAs)
			}
		})
	}
}

func TestSendPreparedRequiresAlgodBeforeSigner(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}
	client, _ := newSendFixture(t, signer, &sendAlgod{})

	_, err := client.SendPrepared(context.Background(), nil, preparedFor(txn), nil)
	if err == nil || !strings.Contains(err.Error(), "algod client is required") {
		t.Fatalf("error = %v", err)
	}
	if len(signer.paths) != 0 {
		t.Fatalf("signer paths = %v, want none", signer.paths)
	}
}

func TestSendPreparedSignFailures(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)

	t.Run("no answer is an unknown outcome", func(t *testing.T) {
		signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}, sign: func(w http.ResponseWriter, r *http.Request) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			conn.Close()
		}}
		node := &sendAlgod{}
		client, algodClient := newSendFixture(t, signer, node)

		_, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
		var unknown *SignOutcomeUnknownError
		if !errors.As(err, &unknown) {
			t.Fatalf("error = %v, want *SignOutcomeUnknownError", err)
		}
		if unknown.RequestID == "" || len(unknown.Requests) != 1 || unknown.Requests[0].AuthAddress != txn.Sender.String() {
			t.Fatalf("unknown outcome = %+v", unknown)
		}
		if signer.count("/sign") != 1 || len(node.submissions()) != 0 {
			t.Fatalf("sign calls = %d, submissions = %d; want 1 and 0", signer.count("/sign"), len(node.submissions()))
		}
	})

	// Unlike a cosigner's /keys, which is unreachable then, a sign answer cut
	// off inside its body may follow a released signature.
	t.Run("a 200 cut off inside its body is an unknown outcome", func(t *testing.T) {
		signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}, sign: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1000")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"signed": [`))
		}}
		node := &sendAlgod{}
		client, algodClient := newSendFixture(t, signer, node)
		_, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
		var unknown *SignOutcomeUnknownError
		if !errors.As(err, &unknown) || len(node.submissions()) != 0 {
			t.Fatalf("error = %v, submissions %d; want *SignOutcomeUnknownError and none", err, len(node.submissions()))
		}
	})

	t.Run("an unknown outcome carries the group's earliest last valid round", func(t *testing.T) {
		other := verifyTestPayment(t, 43, 42, 2)
		other.LastValid = 700
		signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn), ordinaryKey(other)}, sign: func(w http.ResponseWriter, r *http.Request) {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				conn.Close()
			}
		}}
		client, algodClient := newSendFixture(t, signer, &sendAlgod{})
		group := NewPreparedGroup(
			PreparedTransaction{Transaction: &txn, AuthAddress: txn.Sender.String()},
			PreparedTransaction{Transaction: &other, AuthAddress: other.Sender.String()},
		)
		_, err := client.SendPrepared(context.Background(), algodClient, group, nil)
		var unknown *SignOutcomeUnknownError
		if !errors.As(err, &unknown) || unknown.LastValid != 700 {
			t.Fatalf("error = %v (%+v), want an unknown outcome with LastValid 700", err, unknown)
		}
	})

	t.Run("an unreadable answer is an unknown outcome", func(t *testing.T) {
		signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}, sign: func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"signed": ["ab`))
		}}
		node := &sendAlgod{}
		client, algodClient := newSendFixture(t, signer, node)

		_, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
		var unknown *SignOutcomeUnknownError
		if !errors.As(err, &unknown) || unknown.LastValid != uint64(txn.LastValid) {
			t.Fatalf("error = %v, want *SignOutcomeUnknownError with LastValid %d", err, txn.LastValid)
		}
		if len(node.submissions()) != 0 {
			t.Fatalf("submissions = %d, want none", len(node.submissions()))
		}
	})

	t.Run("a refusal is the signer's error", func(t *testing.T) {
		signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}, sign: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "rejected", Code: ErrCodeForbidden})
		}}
		node := &sendAlgod{}
		client, algodClient := newSendFixture(t, signer, node)

		_, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
		var unknown *SignOutcomeUnknownError
		if !errors.Is(err, ErrSigningRejected) || errors.As(err, &unknown) {
			t.Fatalf("error = %v, want ErrSigningRejected", err)
		}
		if len(node.submissions()) != 0 {
			t.Fatalf("submissions = %d, want none", len(node.submissions()))
		}
	})

	t.Run("a response that fails verification is never submitted", func(t *testing.T) {
		altered := txn
		altered.Amount = 999
		signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}, sign: func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(GroupSignResponse{Signed: []string{fakeSignedTxnHex(altered)}})
		}}
		node := &sendAlgod{}
		client, algodClient := newSendFixture(t, signer, node)

		_, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
		if err == nil || !strings.Contains(err.Error(), "verify signer response") {
			t.Fatalf("error = %v, want a verification failure", err)
		}
		if len(node.submissions()) != 0 {
			t.Fatalf("submissions = %d, want none", len(node.submissions()))
		}
	})
}

// A failed submit or wait comes back as one *SubmissionError holding the
// signed group and go-algorand-sdk's own error, whatever the node answered.
func TestSendPreparedSubmissionFailuresKeepSignedBytes(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	wantHex := fakeSignedTxnHex(txn)
	wantID := crypto.GetTxID(txn)
	httpError := func(status int, message string) func(http.ResponseWriter, []byte) {
		return func(w http.ResponseWriter, _ []byte) {
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]string{"message": message})
		}
	}
	unconfirmed := func() models.PendingTransactionInfoResponse { return models.PendingTransactionInfoResponse{} }

	tests := []struct {
		name      string
		node      *sendAlgod
		opts      *SendOptions
		submitted bool
		text      string
	}{
		{
			name: "node answers 400",
			node: &sendAlgod{submit: httpError(http.StatusBadRequest, "overspend")},
			text: "overspend",
		},
		{
			name: "node answers 400 because it already has the group",
			node: &sendAlgod{submit: httpError(http.StatusBadRequest, "TransactionPool.Remember: transaction already in ledger: "+wantID)},
			text: "already in ledger",
		},
		{
			name: "node answers 500",
			node: &sendAlgod{submit: httpError(http.StatusInternalServerError, "boom")},
			text: "boom",
		},
		{
			name: "connection dropped on submission",
			node: &sendAlgod{submit: func(w http.ResponseWriter, _ []byte) {
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					conn.Close()
				}
			}},
			text: "EOF",
		},
		{
			name: "pool drops the group",
			node: &sendAlgod{pending: func() models.PendingTransactionInfoResponse {
				return models.PendingTransactionInfoResponse{PoolError: "fee too low"}
			}},
			submitted: true,
			text:      "fee too low",
		},
		{
			name:      "not confirmed within the wait",
			node:      &sendAlgod{pending: unconfirmed},
			opts:      &SendOptions{WaitRounds: 2},
			submitted: true,
			text:      "timed out",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}
			client, algodClient := newSendFixture(t, signer, tt.node)

			result, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), tt.opts)
			if result != nil || err == nil {
				t.Fatalf("SendPrepared() = %+v, %v; want an error", result, err)
			}
			var failure *SubmissionError
			if !errors.As(err, &failure) {
				t.Fatalf("error = %v, want *SubmissionError", err)
			}
			if failure.Submitted != tt.submitted || !strings.Contains(err.Error(), tt.text) {
				t.Fatalf("error = %v (submitted %v), want submitted %v mentioning %q", err, failure.Submitted, tt.submitted, tt.text)
			}
			if len(failure.SignedGroup) != 1 || hex.EncodeToString(failure.SignedGroup[0]) != wantHex || len(failure.TxIDs) != 1 || failure.TxIDs[0] != wantID {
				t.Fatalf("kept signed group %x and IDs %v", failure.SignedGroup, failure.TxIDs)
			}
			if failure.LastValid != uint64(txn.LastValid) {
				t.Fatalf("LastValid = %d, want the signed group's %d", failure.LastValid, txn.LastValid)
			}
			if errors.Unwrap(err) != failure.Err {
				t.Fatalf("Unwrap() = %v, want the cause %v", errors.Unwrap(err), failure.Err)
			}
			// Nothing is signed or submitted a second time.
			submitted := tt.node.submissions()
			if signer.count("/sign") != 1 || len(submitted) != 1 {
				t.Fatalf("sign calls = %d, submissions = %d; want 1 and 1", signer.count("/sign"), len(submitted))
			}

			// The cause is what go-algorand-sdk returns for the same call.
			var want error
			if tt.submitted {
				_, want = transaction.WaitForConfirmation(algodClient, wantID, sendWaitRounds(tt.opts), context.Background())
			} else {
				_, want = algodClient.SendRawTransaction(submitted[0]).Do(context.Background())
			}
			if fmt.Sprintf("%T", failure.Err) != fmt.Sprintf("%T", want) || failure.Err.Error() != want.Error() {
				t.Fatalf("cause = %T %v, want go-algorand-sdk's %T %v", failure.Err, failure.Err, want, want)
			}
		})
	}

	t.Run("the caller reads a 400 as go-algorand-sdk's", func(t *testing.T) {
		node := &sendAlgod{submit: httpError(http.StatusBadRequest, "overspend")}
		client, algodClient := newSendFixture(t, &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}, node)
		_, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
		var bad common.BadRequest
		if !errors.As(err, &bad) || bad.StatusCode != http.StatusBadRequest {
			t.Fatalf("error = %v, want go-algorand-sdk's common.BadRequest in the chain", err)
		}
	})
}

// sendWaitRounds is the round count a send gives go-algorand-sdk's wait.
func sendWaitRounds(opts *SendOptions) uint64 {
	if opts == nil || opts.WaitRounds == 0 {
		return defaultSendWaitRounds
	}
	return min(opts.WaitRounds, maxSendWaitRounds)
}

func TestSendPaymentPreparesThenSends(t *testing.T) {
	sender := fakeAccount(41)
	receiver := sdkTestAddress(42)
	signer := &sendSigner{keys: []KeyInfo{{Address: sender, KeyType: "ed25519"}}}
	node := &sendAlgod{}
	signer.t, node.t = t, t
	client, signerServer := newTestClient(signer.handle)
	defer signerServer.Close()
	var genesisHash types.Digest
	genesisHash[0] = 7
	algodClient, closeAlgod := makeSimulationAlgodClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/transactions/params":
			json.NewEncoder(w).Encode(map[string]any{
				"fee": 0, "min-fee": 1000, "last-round": 10, "genesis-id": "testnet-v1.0",
				"genesis-hash": genesisHash[:], "consensus-version": "test",
			})
		case r.URL.Path == "/v2/accounts/"+sender:
			json.NewEncoder(w).Encode(map[string]any{"address": sender, "amount": 5_000_000, "min-balance": 100_000})
		default:
			node.handle(w, r)
		}
	})
	defer closeAlgod()

	result, err := client.SendPayment(context.Background(), algodClient, PaymentPrepParams{Sender: sender, Receiver: receiver, Amount: 1_000_000}, nil)
	if err != nil {
		t.Fatalf("SendPayment() error = %v", err)
	}
	if result.Outcome != SendOutcomeConfirmed || len(node.submissions()) != 1 {
		t.Fatalf("result = %+v, submissions = %d", result, len(node.submissions()))
	}
	var sent types.SignedTxn
	if err := msgpack.Decode(node.submissions()[0], &sent); err != nil {
		t.Fatalf("decode submission: %v", err)
	}
	if sent.Txn.Sender.String() != sender || sent.Txn.Receiver.String() != receiver || sent.Txn.Amount != 1_000_000 {
		t.Fatalf("submitted transaction = %+v", sent.Txn)
	}
}

func TestSendPreparedReportsWhatTheSignerAdded(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}, behaviour: fakeSigner{feeRaise: map[int]uint64{0: 500}, dummies: 1}}
	node := &sendAlgod{}
	client, algodClient := newSendFixture(t, signer, node)

	result, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
	if err != nil {
		t.Fatalf("SendPrepared() error = %v", err)
	}
	if result.OriginalCount != 1 || len(result.SignedGroup) != 2 || len(result.TxIDs) != 2 || result.GroupID == "" {
		t.Fatalf("result = %+v", result)
	}
	if len(result.Fees) != 2 || result.Fees[0] != 1500 || result.Fees[1] != 0 {
		t.Fatalf("fees = %v, want the signed fees 1500 and 0", result.Fees)
	}
	if result.Mutations == nil || result.Mutations.DummiesAdded != 1 || result.Mutations.TotalFeesDelta != 500 {
		t.Fatalf("mutations = %+v", result.Mutations)
	}
	if result.TxIDs[0] == crypto.GetTxID(txn) {
		t.Fatalf("txid is the draft's, not the signed transaction's")
	}
	submitted := node.submissions()
	if len(submitted) != 1 || !bytes.Equal(submitted[0], bytes.Join(result.SignedGroup, nil)) {
		t.Fatalf("submission is not the signed group with its dummy, once")
	}
}

// The send gives the wait-rounds option to go-algorand-sdk's wait, which
// looks the first transaction up once per round, and takes the confirmed
// round from what that wait returns.
func TestSendPreparedConfirmationWait(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	unconfirmed := func() models.PendingTransactionInfoResponse { return models.PendingTransactionInfoResponse{} }

	t.Run("the wait covers WaitRounds rounds, 10 by default", func(t *testing.T) {
		for _, opts := range []*SendOptions{nil, {WaitRounds: 1}, {WaitRounds: 3}} {
			signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}
			node := &sendAlgod{pending: unconfirmed}
			client, algodClient := newSendFixture(t, signer, node)
			_, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), opts)
			var failure *SubmissionError
			if !errors.As(err, &failure) || !failure.Submitted {
				t.Fatalf("error = %v, want a *SubmissionError after a successful submit", err)
			}
			if want := sendWaitRounds(opts); uint64(node.lookups) != want {
				t.Fatalf("a wait of %d rounds made %d lookups, want %d", want, node.lookups, want)
			}
		}
	})

	// go-algorand-sdk adds the count to the current round, so the largest
	// count would wrap around there and time out before the first lookup.
	t.Run("the largest WaitRounds still waits", func(t *testing.T) {
		signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}
		node := &sendAlgod{}
		lookups := 0
		node.pending = func() models.PendingTransactionInfoResponse {
			lookups++
			if lookups < 4 {
				return models.PendingTransactionInfoResponse{}
			}
			return models.PendingTransactionInfoResponse{ConfirmedRound: 13}
		}
		client, algodClient := newSendFixture(t, signer, node)
		result, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), &SendOptions{WaitRounds: math.MaxUint64})
		if err != nil || result.ConfirmedRound != 13 || lookups != 4 {
			t.Fatalf("SendPrepared() = %+v, %v after %d lookups; want confirmed in round 13 after 4", result, err, lookups)
		}
	})

	t.Run("the confirmed round is the wait's", func(t *testing.T) {
		signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}
		node := &sendAlgod{}
		lookups := 0
		node.pending = func() models.PendingTransactionInfoResponse {
			lookups++
			if lookups < 3 {
				return models.PendingTransactionInfoResponse{}
			}
			return models.PendingTransactionInfoResponse{ConfirmedRound: 13}
		}
		client, algodClient := newSendFixture(t, signer, node)
		result, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
		if err != nil || result.Outcome != SendOutcomeConfirmed || result.ConfirmedRound != 13 || lookups != 3 {
			t.Fatalf("SendPrepared() = %+v, %v after %d lookups; want confirmed in round 13 after 3", result, err, lookups)
		}
	})
}

// cancelAfterSubmit is a transport that ends the call's context once the
// answer to a submission has been read in full: the submit call succeeds, and
// the context has ended before the wait.
type cancelAfterSubmit struct{ cancel context.CancelFunc }

func (c cancelAfterSubmit) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(r)
	if err != nil || r.Method != http.MethodPost || r.URL.Path != "/v2/transactions" {
		return response, err
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	c.cancel()
	return response, nil
}

// A context that has ended stops the send before the next go-algorand-sdk
// call: before the submit nothing is posted, and after a successful submit
// nothing is waited for.
func TestSubmitWhenTheContextHasEnded(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	signed := [][]byte{mustDecodeHex(t, fakeSignedTxnHex(txn))}

	t.Run("before the submit call", func(t *testing.T) {
		node := &sendAlgod{}
		client, algodClient := newSendFixture(t, &sendSigner{}, node)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := client.SubmitSignedGroup(ctx, algodClient, signed, nil)
		var failure *SubmissionError
		if !errors.As(err, &failure) || failure.Submitted || !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want *SubmissionError, not submitted, caused by the context", err)
		}
		if len(failure.SignedGroup) != 1 || !bytes.Equal(failure.SignedGroup[0], signed[0]) || failure.LastValid != uint64(txn.LastValid) {
			t.Fatalf("failure = %+v", failure)
		}
		if len(node.submissions()) != 0 {
			t.Fatalf("an ended context still submitted")
		}
	})

	t.Run("after a successful submit, before the wait", func(t *testing.T) {
		node := &sendAlgod{t: t}
		var mu sync.Mutex
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requests++
			mu.Unlock()
			node.handle(w, r)
		}))
		defer server.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		algodClient, err := algod.MakeClientWithTransport(server.URL, "", nil, cancelAfterSubmit{cancel})
		if err != nil {
			t.Fatal(err)
		}
		client, signerServer := newTestClient((&sendSigner{t: t}).handle)
		defer signerServer.Close()

		_, err = client.SubmitSignedGroup(ctx, algodClient, signed, nil)
		var failure *SubmissionError
		if !errors.As(err, &failure) || !failure.Submitted || !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want *SubmissionError, submitted, caused by the context", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(node.submissions()) != 1 || requests != 1 {
			t.Fatalf("submissions = %d, node requests = %d; want the submission alone", len(node.submissions()), requests)
		}
	})
}

// cosignedSend is a signer holding one cosigned account, and with primary an
// ordinary account too, its cosigner, and a node.
type cosignedSend struct {
	user, cosigner *SignerClient
	algod          *algod.Client
	node           *sendAlgod
	// txn is the cosigned account's transaction; group is what is sent.
	txn   types.Transaction
	group PreparedGroup

	mu            sync.Mutex
	cosignerCalls int
	// requestIDs is the request_id last posted to each path, the cosigner's
	// under "cosigner <path>".
	requestIDs map[string]string
	// componentKey is the Witness Key ID the cosigner expects to be asked
	// under; empty means COSIGNER_COMPONENT.
	componentKey string
}

// cosignerPublicKeyHex is the cosigned account's cosigner public key in the
// cosigned fixtures.
const cosignerPublicKeyHex = "aabb"

// posted reports whether any of paths was posted to the user signer.
func (f *cosignedSend) posted(paths ...string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var found []string
	for _, path := range paths {
		if _, ok := f.requestIDs[path]; ok {
			found = append(found, path)
		}
	}
	return found
}

func (f *cosignedSend) requestID(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requestIDs[path]
}

// record notes the request_id a request carries and leaves its body to be
// read again.
func (f *cosignedSend) record(t *testing.T, name string, r *http.Request) {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("read %s request: %v", name, err)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	var body struct {
		RequestID string `json:"request_id"`
	}
	if len(raw) > 0 && json.Unmarshal(raw, &body) == nil {
		f.mu.Lock()
		f.requestIDs[name] = body.RequestID
		f.mu.Unlock()
	}
}

// failAs answers with fault when it names this request: "<name> drop" closes
// the connection with no answer, "<name> truncate" answers 200 with a body
// cut short, and "<name> error" answers 200 with a refusal in its error
// field. name is the path, prefixed with "cosigner " on the cosigner.
func failAs(t *testing.T, w http.ResponseWriter, fault, name string) bool {
	switch fault {
	case name + " drop":
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return true
		}
		conn.Close()
		return true
	case name + " truncate":
		w.Write([]byte(`{"request_id": "x", "signed_gr`))
		return true
	case name + " error":
		w.Write([]byte(`{"error": "refused by the test signer"}`))
		return true
	}
	return false
}

func cosignedSendFixture(t *testing.T, fault string, primary bool) *cosignedSend {
	t.Helper()
	f := &cosignedSend{requestIDs: map[string]string{}}
	bounded := sdkTestAddress(21)
	key := KeyInfo{
		Address: bounded, KeyType: "aplane.falcon1024.v1", SigningFlow: SigningFlowCosigned1,
		LogicSigResources: &LogicSigResourceProfile{
			Spend: &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 3358, MaxOpcodeCost: 20000},
		},
		CosignerComponentKeyType: KeyTypeWitnessFalcon1024,
		BoundedAuthorization: &BoundedAuthorizationInfo{
			Contract: BoundedContractBounded2, MaxFee: new(uint64(1000)),
			Cosigner: &BoundedCosignerAuthorizationInfo{ComponentKeyType: KeyTypeWitnessFalcon1024, PublicKeyHex: cosignerPublicKeyHex},
		},
	}
	keys := []KeyInfo{key}

	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee: types.MicroAlgos(1000), FirstRoundValid: 1, LastRoundValid: 100,
		GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
	}
	txn, err := transaction.MakePaymentTxn(bounded, sdkTestAddress(22), 1000, nil, "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}
	f.txn = txn
	positions := []PreparedTransaction{{Transaction: &f.txn, AuthAddress: bounded}}
	if primary {
		other, err := transaction.MakePaymentTxn(fakeAccount(23), sdkTestAddress(22), 2000, nil, "", sp)
		if err != nil {
			t.Fatalf("MakePaymentTxn() error = %v", err)
		}
		// It expires first, so the group's earliest last valid round is its.
		other.LastValid = 90
		keys = append(keys, ordinaryKey(other))
		positions = append(positions, PreparedTransaction{Transaction: &other, AuthAddress: other.Sender.String()})
	}
	f.group = NewPreparedGroup(positions...)

	userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			f.record(t, r.URL.Path, r)
		}
		if failAs(t, w, fault, r.URL.Path) {
			return
		}
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{State: "unlocked", ApprovalWaitSeconds: 60})
		case "/keys":
			json.NewEncoder(w).Encode(KeysResponse{Count: len(keys), Keys: keys})
		case "/plan":
			var req GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode plan request: %v", err)
				return
			}
			json.NewEncoder(w).Encode(fakeSigner{}.plan(t, req.Requests))
		case "/sign":
			var req GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode sign request: %v", err)
				return
			}
			json.NewEncoder(w).Encode(fakeSigner{}.sign(t, req.Requests))
		case "/sign/component":
			var req ComponentRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode component request: %v", err)
				return
			}
			json.NewEncoder(w).Encode(ComponentResponse{RequestID: req.RequestID, Components: []Component{{
				TargetIndex: 0, Kind: ComponentTargetKindBoundedBase, AuthAddress: bounded,
				BaseSignatures: []string{"base-sig"}, RuntimeArgs: map[string]string{"proof": "aabb"},
				AssemblyReceipt: "receipt", SignatureScheme: "aplane.falcon1024.v1", Path: ComponentPathSpend,
			}}})
		case "/sign/assemble":
			var req AssemblyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode assembly request: %v", err)
				return
			}
			json.NewEncoder(w).Encode(AssemblyResponse{RequestID: req.RequestID, SignedGroup: signedGroupFor(t, req.GroupBytesHex)})
		default:
			t.Errorf("unexpected user path %s", r.URL.Path)
		}
	})
	t.Cleanup(userServer.Close)
	cosignerClient, cosignerServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/keys" {
			// What discovery reads: the cosigner's witness key.
			publicKey, _ := hex.DecodeString(cosignerPublicKeyHex)
			json.NewEncoder(w).Encode(KeysResponse{Count: 1, Keys: []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, publicKey)}})
			return
		}
		f.mu.Lock()
		f.cosignerCalls++
		f.mu.Unlock()
		f.record(t, "cosigner "+r.URL.Path, r)
		if failAs(t, w, fault, "cosigner "+r.URL.Path) {
			return
		}
		var req capturedComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode cosigner request: %v", err)
			return
		}
		want := "COSIGNER_COMPONENT"
		f.mu.Lock()
		if f.componentKey != "" {
			want = f.componentKey
		}
		f.mu.Unlock()
		if req.ComponentKey != want {
			t.Errorf("cosigner component key = %q, want %q", req.ComponentKey, want)
		}
		json.NewEncoder(w).Encode(ComponentResponse{RequestID: req.RequestID, Components: []Component{{
			Kind: ComponentTargetKindCosigner, TargetIndex: 0, Signature: "cosigner-sig", SignatureScheme: KeyTypeWitnessFalcon1024,
		}}})
	})
	t.Cleanup(cosignerServer.Close)
	f.node = &sendAlgod{t: t}
	algodClient, closeAlgod := makeSimulationAlgodClient(t, f.node.handle)
	t.Cleanup(closeAlgod)
	f.user, f.cosigner, f.algod = userClient, cosignerClient, algodClient
	return f
}

func (f *cosignedSend) send() (*SendResult, error) {
	return f.user.SendPrepared(context.Background(), f.algod, f.group, &SendOptions{
		CosignerClient: f.cosigner, CosignerComponentKey: "COSIGNER_COMPONENT",
	})
}

func TestSendPreparedCosignedGroup(t *testing.T) {
	for _, primary := range []bool{false, true} {
		t.Run(fmt.Sprintf("with an ordinary position %v", primary), func(t *testing.T) {
			f := cosignedSendFixture(t, "", primary)
			result, err := f.send()
			if err != nil {
				t.Fatalf("SendPrepared() error = %v", err)
			}
			if result.Flow != SigningFlowCosigned1 || result.Cosigned == nil || result.Cosigned.BoundedAssemblyResponse == nil || f.cosignerCalls != 1 {
				t.Fatalf("result = %+v, cosigner calls = %d", result, f.cosignerCalls)
			}
			if primary != (result.Cosigned.PrimarySignResponse != nil) {
				t.Fatalf("primary sign response = %+v", result.Cosigned.PrimarySignResponse)
			}
			submitted := f.node.submissions()
			if len(submitted) != 1 || !bytes.Equal(submitted[0], bytes.Join(result.SignedGroup, nil)) || result.Outcome != SendOutcomeConfirmed {
				t.Fatalf("the assembled group was not submitted once and confirmed")
			}
			// With a second position the plan groups the transaction, which
			// changes its ID.
			if (!primary && result.TxIDs[0] != crypto.GetTxID(f.txn)) || result.Fees[0] != 1000 {
				t.Fatalf("txids %v fees %v", result.TxIDs, result.Fees)
			}
		})
	}
}

func TestSendPreparedCosignedWithoutACosignerIsRefused(t *testing.T) {
	f := cosignedSendFixture(t, "", false)
	_, err := f.user.SendPrepared(context.Background(), f.algod, f.group, nil)
	var unknown *SignOutcomeUnknownError
	if err == nil || !strings.Contains(err.Error(), "cosigner client or resolver is required") || errors.As(err, &unknown) {
		t.Fatalf("error = %v, want a plain refusal naming the missing cosigner", err)
	}
	if len(f.node.submissions()) != 0 {
		t.Fatalf("submitted without a cosigner")
	}
}

// An approval-bearing step whose answer is lost makes the send's outcome
// unknown, and the error names that step's request, so the operator or the
// audit log can say whether it released anything.
func TestSendPreparedCosignedLostAnswers(t *testing.T) {
	tests := []struct {
		fault   string
		primary bool
		unknown bool
	}{
		// Approval-bearing steps: the signer may have acted.
		{"/sign/component drop", false, true},
		{"/sign/component truncate", false, true},
		{"/sign/assemble drop", false, true},
		{"/sign/assemble truncate", false, true},
		{"/sign drop", true, true},
		{"/sign truncate", true, true},
		{"cosigner /sign/component drop", false, true},
		{"cosigner /sign/component truncate", false, true},
		// Planning releases nothing, so its failure is a plain error.
		{"/plan drop", false, false},
		{"/plan truncate", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.fault, func(t *testing.T) {
			f := cosignedSendFixture(t, tt.fault, tt.primary)
			_, err := f.send()
			var unknown *SignOutcomeUnknownError
			if err == nil || errors.As(err, &unknown) != tt.unknown {
				t.Fatalf("error = %v, want unknown outcome = %v", err, tt.unknown)
			}
			if len(f.node.submissions()) != 0 {
				t.Fatalf("submitted after a failed signing step")
			}
			if !tt.unknown {
				return
			}
			name := strings.TrimSuffix(strings.TrimSuffix(tt.fault, " drop"), " truncate")
			want := f.requestID(name)
			if want == "" || unknown.RequestID != want {
				t.Fatalf("RequestID = %q, want the %s request's %q", unknown.RequestID, name, want)
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not name request %s", err, want)
			}
			wantLastValid := uint64(100)
			if tt.primary {
				wantLastValid = 90
			}
			if unknown.LastValid != wantLastValid {
				t.Fatalf("LastValid = %d, want the group's earliest %d", unknown.LastValid, wantLastValid)
			}
		})
	}
}

// A 200 answer that carries an error is the signer's refusal: it was read,
// so the send fails plainly, and nothing is submitted.
func TestSendPreparedCosignedAnswerWithAnErrorIsARefusal(t *testing.T) {
	for _, fault := range []string{"/sign/component error", "/sign/assemble error", "cosigner /sign/component error"} {
		t.Run(fault, func(t *testing.T) {
			f := cosignedSendFixture(t, fault, false)
			_, err := f.send()
			var unknown *SignOutcomeUnknownError
			if err == nil || errors.As(err, &unknown) || !strings.Contains(err.Error(), "refused by the test signer") {
				t.Fatalf("error = %v, want a plain refusal carrying the signer's error", err)
			}
			if len(f.node.submissions()) != 0 {
				t.Fatalf("submitted after a refusal")
			}
		})
	}
}

// Rotating and cosigned sends submit through the same path, so a failure
// after signing is the same *SubmissionError, and nothing is signed again.
func TestRotatingAndCosignedSendsSubmitThroughTheSamePath(t *testing.T) {
	t.Run("rotating, the submit call fails", func(t *testing.T) {
		signer, node, client, algodClient, txn := newRotatingFixture(t)
		node.submit = func(w http.ResponseWriter, _ []byte) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"message": "overspend"})
		}
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
		var failure *SubmissionError
		if !errors.As(err, &failure) || failure.Submitted || !strings.Contains(err.Error(), "overspend") {
			t.Fatalf("error = %v, want *SubmissionError, not submitted, quoting the node", err)
		}
		submitted := node.submissions()
		if len(submitted) != 1 || len(failure.SignedGroup) != 2 || !bytes.Equal(submitted[0], bytes.Join(failure.SignedGroup, nil)) {
			t.Fatalf("the error does not carry the group that was submitted once")
		}
		if signer.count("/sign/rotating/prepare") != 1 || signer.count("/sign/rotating/sign") != 1 {
			t.Fatalf("prepares %d, signs %d; want 1 and 1", signer.count("/sign/rotating/prepare"), signer.count("/sign/rotating/sign"))
		}
	})

	t.Run("cosigned, the wait fails", func(t *testing.T) {
		f := cosignedSendFixture(t, "", true)
		f.node.pending = func() models.PendingTransactionInfoResponse {
			return models.PendingTransactionInfoResponse{PoolError: "fee too low"}
		}
		_, err := f.send()
		var failure *SubmissionError
		if !errors.As(err, &failure) || !failure.Submitted || !strings.Contains(err.Error(), "fee too low") {
			t.Fatalf("error = %v, want *SubmissionError, submitted, quoting the pool error", err)
		}
		// The ordinary position expires first.
		if failure.LastValid != 90 {
			t.Fatalf("LastValid = %d, want the group's earliest 90", failure.LastValid)
		}
		submitted := f.node.submissions()
		if len(submitted) != 1 || !bytes.Equal(submitted[0], bytes.Join(failure.SignedGroup, nil)) || f.cosignerCalls != 1 {
			t.Fatalf("submissions %d, cosigner calls %d; want the assembled group once and one cosigner call", len(submitted), f.cosignerCalls)
		}
	})
}

// A rotating account rekeyed to an ordinary key the signer holds has left
// rotation: that key signs for it through the ordinary flow, once the chain
// confirms the rekey.
func TestSendPreparedRoutesAnAccountThatLeftRotationByItsKey(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	sender := txn.Sender.String()
	holder := fakeAccount(45)
	keys := []KeyInfo{{Address: sender, SigningFlow: SigningFlowRotating1}, {Address: holder, KeyType: "ed25519"}}
	group := NewPreparedGroup(PreparedTransaction{Transaction: &txn, AuthAddress: holder})

	t.Run("the chain confirms the rekey", func(t *testing.T) {
		signer := &sendSigner{keys: keys}
		node := &sendAlgod{authAddrs: map[string]string{sender: holder}}
		client, algodClient := newSendFixture(t, signer, node)
		result, err := client.SendPrepared(context.Background(), algodClient, group, nil)
		if err != nil || result.Flow != "" || signer.count("/sign") != 1 {
			t.Fatalf("SendPrepared() = %+v, %v; want the ordinary flow", result, err)
		}
		var sent types.SignedTxn
		if err := msgpack.Decode(node.submissions()[0], &sent); err != nil {
			t.Fatal(err)
		}
		if sent.AuthAddr.String() != holder {
			t.Fatalf("signed by %s, want the key the position named", sent.AuthAddr)
		}
	})

	// A caller cannot have an ordinary key sign for an account that is still
	// rotating: nothing is asked of the signer.
	for name, chainAuth := range map[string]string{"still at stage 0": "", "rotated to a stage": sdkTestAddress(77)} {
		t.Run("refused when "+name, func(t *testing.T) {
			signer := &sendSigner{keys: keys}
			node := &sendAlgod{authAddrs: map[string]string{sender: chainAuth}}
			client, algodClient := newSendFixture(t, signer, node)
			_, err := client.SendPrepared(context.Background(), algodClient, group, nil)
			if !errors.Is(err, ErrUnsupportedGroup) || !strings.Contains(err.Error(), "is not rekeyed to it") {
				t.Fatalf("error = %v", err)
			}
			if signer.count("/sign") != 0 || len(node.submissions()) != 0 {
				t.Fatalf("an ordinary key was asked to sign for a rotating account")
			}
		})
	}

	signer := &sendSigner{keys: keys}
	client, _ := newSendFixture(t, signer, &sendAlgod{})
	resolved, err := client.ResolveAuthAddress(context.Background(), sender, func(context.Context, string) (string, error) { return holder, nil })
	if err != nil || resolved.AuthAddress != holder || !resolved.IsRekeyed || resolved.ChainAuthAddress != holder {
		t.Fatalf("ResolveAuthAddress() = %+v, %v; want the held key", resolved, err)
	}
}

// The cancel a send makes when its context ends during approval is best
// effort: whatever the cancel's own answer, the send reports the signing
// exchange that ended with no answer, not the cancel.
func TestSendPreparedCancelFailureDoesNotMaskTheSend(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	answers := map[string]func(http.ResponseWriter){
		"unreadable": func(w http.ResponseWriter) { w.Write([]byte(`{"succ`)) },
		"null":       func(w http.ResponseWriter) { w.Write([]byte(`null`)) },
		"an error":   func(w http.ResponseWriter) { w.Write([]byte(`{"success":false,"error":"cancel broke"}`)) },
		"a 500": func(w http.ResponseWriter) {
			writeCodedError(w, http.StatusInternalServerError, ErrCodeInternal, "cancel broke")
		},
		"no answer": func(w http.ResponseWriter) {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				conn.Close()
			}
		},
	}
	for name, answer := range answers {
		t.Run("cancel answers "+name, func(t *testing.T) {
			signStarted := make(chan struct{})
			canceled := make(chan struct{}, 1)
			signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}, sign: func(w http.ResponseWriter, r *http.Request) {
				// The server notices the client leave only once the body is read.
				io.Copy(io.Discard, r.Body)
				close(signStarted)
				<-r.Context().Done()
			}}
			signer.t = t
			client, signerServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/sign/cancel" {
					canceled <- struct{}{}
					answer(w)
					return
				}
				signer.handle(w, r)
			})
			defer signerServer.Close()
			node := &sendAlgod{t: t}
			algodClient, closeAlgod := makeSimulationAlgodClient(t, node.handle)
			defer closeAlgod()

			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				<-signStarted
				cancel()
			}()
			_, err := client.SendPrepared(ctx, algodClient, preparedFor(txn), nil)
			var unknown *SignOutcomeUnknownError
			if !errors.As(err, &unknown) || !errors.Is(err, context.Canceled) || unknown.RequestID == "" {
				t.Fatalf("error = %v, want the unknown outcome of the canceled sign request", err)
			}
			if strings.Contains(err.Error(), "cancel broke") || strings.Contains(err.Error(), "sign cancel") {
				t.Fatalf("error = %v names the cancel", err)
			}
			select {
			case <-canceled:
			default:
				t.Fatal("no /sign/cancel was sent")
			}
			if len(node.submissions()) != 0 {
				t.Fatal("submitted")
			}
		})
	}
}

// recordingSign answers /sign as the fake signer does and records each
// request's entries.
func recordingSign(t *testing.T, seen *[][]SignRequest, mu *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request GroupSignRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode sign request: %v", err)
			return
		}
		mu.Lock()
		*seen = append(*seen, request.Requests)
		mu.Unlock()
		json.NewEncoder(w).Encode(fakeSigner{}.sign(t, request.Requests))
	}
}

func TestSendTransactionsSendsAnOrdinarySender(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	before := encodeTxn(txn)
	var seen [][]SignRequest
	var mu sync.Mutex
	signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}
	signer.sign = recordingSign(t, &seen, &mu)
	node := &sendAlgod{}
	client, algodClient := newSendFixture(t, signer, node)

	txns := []types.Transaction{txn}
	result, err := client.SendTransactions(context.Background(), algodClient, txns, nil)
	if err != nil {
		t.Fatalf("SendTransactions() error = %v", err)
	}
	if len(seen) != 1 || len(seen[0]) != 1 {
		t.Fatalf("sign requests = %+v, want one with one entry", seen)
	}
	request := seen[0][0]
	if request.AuthAddress != txn.Sender.String() || request.TxnSender != txn.Sender.String() || request.TxnBytesHex != hex.EncodeToString(before) {
		t.Fatalf("sign request = %+v, want the transaction as built, signed by its sender", request)
	}
	if request.LsigArgs != nil || request.AppCallInfo != nil || request.LsigResources != nil || request.PQScheme != "" {
		t.Fatalf("sign request = %+v, want no field but the auth address set", request)
	}
	if result.Flow != "" || result.Outcome != SendOutcomeConfirmed || len(result.SignedGroup) != 1 || result.TxIDs[0] != crypto.GetTxID(txn) {
		t.Fatalf("result = %+v", result)
	}
	submitted := node.submissions()
	if len(submitted) != 1 || !bytes.Equal(submitted[0], bytes.Join(result.SignedGroup, nil)) {
		t.Fatal("submission is not the signed group, once")
	}
	if !bytes.Equal(encodeTxn(txns[0]), before) {
		t.Fatal("SendTransactions changed the caller's transaction")
	}
}

func TestSendTransactionsUsesTheChainAuthAddressOfARekeyedSender(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	sender := txn.Sender.String()
	authorizer := fakeAccount(45)
	var seen [][]SignRequest
	var mu sync.Mutex
	signer := &sendSigner{keys: []KeyInfo{{Address: authorizer, KeyType: "ed25519"}}}
	signer.sign = recordingSign(t, &seen, &mu)
	node := &sendAlgod{authAddrs: map[string]string{sender: authorizer}}
	client, algodClient := newSendFixture(t, signer, node)

	result, err := client.SendTransactions(context.Background(), algodClient, []types.Transaction{txn}, nil)
	if err != nil {
		t.Fatalf("SendTransactions() error = %v", err)
	}
	if len(seen) != 1 || seen[0][0].AuthAddress != authorizer || seen[0][0].TxnSender != sender {
		t.Fatalf("sign requests = %+v, want the chain's auth address %s for sender %s", seen, authorizer, sender)
	}
	var signed types.SignedTxn
	if err := msgpack.Decode(result.SignedGroup[0], &signed); err != nil {
		t.Fatal(err)
	}
	if signed.AuthAddr.String() != authorizer {
		t.Fatalf("signed by %s, want %s", signed.AuthAddr, authorizer)
	}
}

func TestSendTransactionsSendsARotatingSender(t *testing.T) {
	signer, node, client, algodClient, txn := newRotatingFixture(t)
	// After a rotation the chain names a stage address, which the signer does
	// not list; the account signs as itself.
	node.authAddrs = map[string]string{signer.account: rotatingStageAddress(rotatingTestProgram).String()}

	result, err := client.SendTransactions(context.Background(), algodClient, []types.Transaction{txn}, nil)
	if err != nil {
		t.Fatalf("SendTransactions() error = %v", err)
	}
	if result.Flow != SigningFlowRotating1 || result.Rotating == nil || len(result.SignedGroup) != 2 {
		t.Fatalf("result = %+v", result)
	}
	if signer.count("/sign/rotating/prepare") != 1 || signer.count("/sign/rotating/sign") != 1 || signer.count("/sign") != 0 {
		t.Fatalf("signer paths = %v", signer.paths)
	}
	// The transaction went to the signer as built.
	if len(signer.prepareSeen) != 1 || !bytes.Equal(encodeTxn(signer.prepareSeen[0]), encodeTxn(txn)) {
		t.Fatal("the rotating prepare did not get the transaction as built")
	}
	submitted := node.submissions()
	if len(submitted) != 1 || !bytes.Equal(submitted[0], bytes.Join(result.SignedGroup, nil)) {
		t.Fatal("submission is not the signed group, once")
	}
}

func TestSendTransactionsSendsATwoTransactionGroup(t *testing.T) {
	first := verifyTestPayment(t, 41, 42, 1)
	second := verifyTestPayment(t, 43, 44, 2)

	t.Run("ungrouped", func(t *testing.T) {
		signer := &sendSigner{keys: []KeyInfo{ordinaryKey(first), ordinaryKey(second)}}
		node := &sendAlgod{}
		client, algodClient := newSendFixture(t, signer, node)

		txns := []types.Transaction{first, second}
		result, err := client.SendTransactions(context.Background(), algodClient, txns, nil)
		if err != nil {
			t.Fatalf("SendTransactions() error = %v", err)
		}
		// The signer assigned the group, so the IDs are not the drafts'.
		if len(result.SignedGroup) != 2 || result.OriginalCount != 2 || result.GroupID == "" || result.TxIDs[0] == crypto.GetTxID(first) {
			t.Fatalf("result = %+v", result)
		}
		for i, want := range []types.Transaction{first, second} {
			var signed types.SignedTxn
			if err := msgpack.Decode(result.SignedGroup[i], &signed); err != nil {
				t.Fatal(err)
			}
			if signed.Txn.Sender != want.Sender || signed.Txn.Amount != want.Amount {
				t.Fatalf("entry %d is not transaction %d", i, i)
			}
		}
		submitted := node.submissions()
		if len(submitted) != 1 || !bytes.Equal(submitted[0], bytes.Join(result.SignedGroup, nil)) {
			t.Fatal("submission is not the signed group, in order, once")
		}
	})

	t.Run("grouped by the caller", func(t *testing.T) {
		signer := &sendSigner{keys: []KeyInfo{ordinaryKey(first), ordinaryKey(second)}}
		node := &sendAlgod{}
		client, algodClient := newSendFixture(t, signer, node)

		grouped, err := transaction.AssignGroupID([]types.Transaction{first, second}, "")
		if err != nil {
			t.Fatal(err)
		}
		result, err := client.SendTransactions(context.Background(), algodClient, grouped, nil)
		if err != nil {
			t.Fatalf("SendTransactions() error = %v", err)
		}
		// The caller's group ID is kept, so the IDs are the ones built.
		if result.GroupID != base64.StdEncoding.EncodeToString(grouped[0].Group[:]) || result.TxIDs[0] != crypto.GetTxID(grouped[0]) || result.TxIDs[1] != crypto.GetTxID(grouped[1]) {
			t.Fatalf("result = %+v, want the caller's group and IDs", result)
		}
	})
}

// The call does not modify the transactions passed in, even when the signer
// raises a fee, appends a dummy and groups what it signs.
func TestSendTransactionsDoesNotModifyTheTransactions(t *testing.T) {
	first := verifyTestPayment(t, 41, 42, 1)
	second := verifyTestPayment(t, 43, 44, 2)
	first.Note = []byte("first")
	signer := &sendSigner{keys: []KeyInfo{ordinaryKey(first), ordinaryKey(second)}, behaviour: fakeSigner{feeRaise: map[int]uint64{0: 500}, dummies: 1}}
	node := &sendAlgod{}
	client, algodClient := newSendFixture(t, signer, node)

	txns := []types.Transaction{first, second}
	before := [][]byte{encodeTxn(txns[0]), encodeTxn(txns[1])}
	result, err := client.SendTransactions(context.Background(), algodClient, txns, nil)
	if err != nil {
		t.Fatalf("SendTransactions() error = %v", err)
	}
	if len(result.SignedGroup) != 3 || result.Mutations == nil || result.Mutations.TotalFeesDelta != 500 {
		t.Fatalf("result = %+v, want the signer's changes in the signed group", result)
	}
	for i := range txns {
		if !bytes.Equal(encodeTxn(txns[i]), before[i]) {
			t.Fatalf("transaction %d encodes differently after the send", i)
		}
	}
}

// Each distinct sender is resolved once per call: one account read, and the
// signer's key list read once whatever the number of transactions.
func TestSendTransactionsResolvesEachSenderOnce(t *testing.T) {
	// statusBeforeSign is how many /status requests the call made before its
	// /sign request.
	statusBeforeSign := func(signer *sendSigner) int {
		signer.mu.Lock()
		defer signer.mu.Unlock()
		n := 0
		for _, path := range signer.paths {
			if path == "/sign" {
				break
			}
			if path == "/status" {
				n++
			}
		}
		return n
	}
	send := func(t *testing.T, count int) (*sendSigner, *sendAlgod) {
		t.Helper()
		var txns []types.Transaction
		for i := 0; i < count; i++ {
			txns = append(txns, verifyTestPayment(t, 41, 42, uint64(i+1)))
		}
		signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txns[0])}}
		node := &sendAlgod{}
		client, algodClient := newSendFixture(t, signer, node)
		result, err := client.SendTransactions(context.Background(), algodClient, txns, nil)
		if err != nil {
			t.Fatalf("SendTransactions() error = %v", err)
		}
		if len(result.SignedGroup) != count {
			t.Fatalf("signed %d transaction(s), want %d", len(result.SignedGroup), count)
		}
		return signer, node
	}

	oneSigner, oneNode := send(t, 1)
	threeSigner, threeNode := send(t, 3)
	if oneNode.accountReads != 1 || threeNode.accountReads != 1 {
		t.Fatalf("account reads = %d for one transaction, %d for three from the same sender; want 1 and 1", oneNode.accountReads, threeNode.accountReads)
	}
	if one, three := statusBeforeSign(oneSigner), statusBeforeSign(threeSigner); one != three {
		t.Fatalf("status reads before signing = %d for one transaction, %d for three; the key list must be read once per call", one, three)
	}
}

// A rotating account accepts a window of at most 100 rounds. The 1000-round
// window of go-algorand-sdk's suggested parameters is refused unless the
// send may rebuild it, and either way the caller's transaction is unchanged.
func TestSendTransactionsRotatingSenderWithTheDefaultWindow(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		signer, node, client, algodClient, _ := newRotatingFixture(t)
		txns := []types.Transaction{rotatingPayment(t, signer.account, 10, 1010)}
		before := encodeTxn(txns[0])
		_, err := client.SendTransactions(context.Background(), algodClient, txns, nil)
		if err == nil || !strings.Contains(err.Error(), "validity window is 1000 rounds; a rotating account accepts at most 100") || !strings.Contains(err.Error(), "set RefreshValidity") {
			t.Fatalf("error = %v, want the window refused", err)
		}
		if signer.count("/sign/rotating/prepare") != 0 || len(node.submissions()) != 0 {
			t.Fatal("something was prepared or submitted")
		}
		if !bytes.Equal(encodeTxn(txns[0]), before) {
			t.Fatal("the caller's transaction changed")
		}
	})
	t.Run("sent with RefreshValidity", func(t *testing.T) {
		signer, node, client, algodClient, _ := newRotatingFixture(t)
		txns := []types.Transaction{rotatingPayment(t, signer.account, 10, 1010)}
		before := encodeTxn(txns[0])
		result, err := client.SendTransactions(context.Background(), algodClient, txns, &SendOptions{RefreshValidity: true})
		if err != nil {
			t.Fatalf("SendTransactions() error = %v", err)
		}
		if result.Rotating == nil || uint64(result.Rotating.Transaction.LastValid-result.Rotating.Transaction.FirstValid) > RotatingMaxValidityWindow {
			t.Fatalf("result = %+v, want a rebuilt window", result.Rotating)
		}
		if len(node.submissions()) != 1 {
			t.Fatal("the group was not submitted once")
		}
		if !bytes.Equal(encodeTxn(txns[0]), before) {
			t.Fatal("the caller's transaction changed")
		}
	})
}

func TestSendTransactionsRefusesAnEmptyList(t *testing.T) {
	signer := &sendSigner{}
	node := &sendAlgod{}
	client, algodClient := newSendFixture(t, signer, node)

	for name, txns := range map[string][]types.Transaction{"nil": nil, "empty": {}} {
		_, err := client.SendTransactions(context.Background(), algodClient, txns, nil)
		if err == nil || !strings.Contains(err.Error(), "transaction list is empty") {
			t.Fatalf("%s: error = %v, want the empty list refused", name, err)
		}
	}
	if len(signer.paths) != 0 || len(node.submissions()) != 0 {
		t.Fatalf("signer paths %v, %d submission(s); want nothing asked", signer.paths, len(node.submissions()))
	}
}

func TestSendTransactionsAccountLookupFailureSignsNothing(t *testing.T) {
	first := verifyTestPayment(t, 41, 42, 1)
	second := verifyTestPayment(t, 43, 44, 2)
	signer := &sendSigner{keys: []KeyInfo{ordinaryKey(first), ordinaryKey(second)}}
	node := &sendAlgod{t: t}
	signer.t = t
	client, signerServer := newTestClient(signer.handle)
	defer signerServer.Close()
	algodClient, closeAlgod := makeSimulationAlgodClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/accounts/"+second.Sender.String() {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"message": "lookup broke"})
			return
		}
		node.handle(w, r)
	})
	defer closeAlgod()

	_, err := client.SendTransactions(context.Background(), algodClient, []types.Transaction{first, second}, nil)
	if err == nil || !strings.Contains(err.Error(), "transaction 1: failed to get sender account info") || !strings.Contains(err.Error(), "lookup broke") {
		t.Fatalf("error = %v, want the second lookup's failure", err)
	}
	var submission *SubmissionError
	var unknown *SignOutcomeUnknownError
	if errors.As(err, &submission) || errors.As(err, &unknown) {
		t.Fatalf("error = %T, want a plain error", err)
	}
	if signer.count("/sign") != 0 || len(node.submissions()) != 0 {
		t.Fatal("something was signed or submitted")
	}
}

// A sender this signer holds no key for is refused by the auth-address
// resolution, as the Prepare* helpers refuse it, before anything is signed.
func TestSendTransactionsRefusesAKeyNotHeld(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	signer := &sendSigner{keys: []KeyInfo{{Address: fakeAccount(45), KeyType: "ed25519"}}}
	node := &sendAlgod{}
	client, algodClient := newSendFixture(t, signer, node)

	_, err := client.SendTransactions(context.Background(), algodClient, []types.Transaction{txn}, nil)
	if !errors.Is(err, ErrKeyNotFound) || !strings.Contains(err.Error(), "transaction 0") {
		t.Fatalf("error = %v, want ErrKeyNotFound for transaction 0", err)
	}
	if signer.count("/sign") != 0 || len(node.submissions()) != 0 {
		t.Fatal("something was signed or submitted")
	}
}

// Buffer ownership: a caller who changes a buffer it passed in, during the
// call or after it, changes nothing a result, an error or the SDK holds. A
// returned entry is a plain slice the caller owns; a later read of the same
// field shows the caller's own change, which Go cannot cheaply prevent.
func TestSignedGroupOwnership(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	want := mustDecodeHex(t, fakeSignedTxnHex(txn))
	accept := func(w http.ResponseWriter, _ []byte) {
		json.NewEncoder(w).Encode(map[string]string{"txId": crypto.GetTxID(txn)})
	}
	refuse := func(w http.ResponseWriter, _ []byte) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "overspend"})
	}

	// (a) The input to SubmitSignedGroup, changed while the call runs and
	// after it returns.
	for name, answer := range map[string]func(http.ResponseWriter, []byte){"result": accept, "SubmissionError": refuse} {
		t.Run("SubmitSignedGroup input, "+name, func(t *testing.T) {
			group := [][]byte{append([]byte(nil), want...)}
			node := &sendAlgod{submit: func(w http.ResponseWriter, blob []byte) {
				group[0][0] ^= 0xff // the caller changes its buffer mid-call
				answer(w, blob)
			}}
			client, algodClient := newSendFixture(t, &sendSigner{}, node)
			result, err := client.SubmitSignedGroup(context.Background(), algodClient, group, nil)
			group[0][1] ^= 0xff // and again after the call
			var held [][]byte
			var failure *SubmissionError
			switch {
			case err == nil:
				held = result.SignedGroup
			case errors.As(err, &failure):
				held = failure.SignedGroup
			default:
				t.Fatalf("SubmitSignedGroup() error = %v", err)
			}
			if len(held) != 1 || !bytes.Equal(held[0], want) {
				t.Fatalf("the %s holds %x, want the bytes as given %x", name, held, want)
			}
			if submitted := node.submissions(); len(submitted) != 1 || !bytes.Equal(submitted[0], want) {
				t.Fatal("the bytes posted are not the bytes as given")
			}
		})
	}

	// (c) A pre-signed slot's bytes.
	t.Run("prepared signed transaction", func(t *testing.T) {
		presigned := append([]byte(nil), want...)
		requests, err := NewPreparedGroup(PreparedTransaction{SignedTransaction: presigned}).SignRequests()
		if err != nil {
			t.Fatalf("SignRequests() error = %v", err)
		}
		presigned[0] ^= 0xff
		if requests[0].SignedTxnHex != hex.EncodeToString(want) {
			t.Fatal("changing the slot's bytes changed the request built from them")
		}
	})
	t.Run("passthrough changed while signing", func(t *testing.T) {
		first := verifyTestPayment(t, 43, 44, 2)
		grouped, err := transaction.AssignGroupID([]types.Transaction{first, txn}, "")
		if err != nil {
			t.Fatal(err)
		}
		passthroughWant := mustDecodeHex(t, fakeSignedTxnHex(grouped[1]))
		passthrough := append([]byte(nil), passthroughWant...)
		client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/sign" {
				passthrough[0] ^= 0xff // the caller changes its buffer mid-call
			}
			fakeSignHandler(t, fakeSigner{})(w, r)
		})
		defer server.Close()
		signed, err := client.SignTransactionsWithOptions(grouped, []string{first.Sender.String(), ""}, nil, &SignOptions{Passthrough: map[int][]byte{1: passthrough}})
		if err != nil {
			t.Fatalf("SignTransactionsWithOptions() error = %v", err)
		}
		if len(signed) != 2 || !bytes.Equal(signed[1], passthroughWant) {
			t.Fatal("the passthrough entry returned is not the bytes as given")
		}
	})
}

// Every caller-supplied entry is checked as exactly one canonical signed
// transaction: two transactions in one entry, trailing bytes and a
// non-canonical encoding are refused before anything is posted.
func TestSignedEntriesMustBeOneCanonicalSignedTransaction(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	other := verifyTestPayment(t, 43, 44, 2)
	signed := mustDecodeHex(t, fakeSignedTxnHex(txn))
	bad := map[string][]byte{
		"two transactions": append(append([]byte(nil), signed...), mustDecodeHex(t, fakeSignedTxnHex(other))...),
		"trailing bytes":   append(append([]byte(nil), signed...), 0x00),
		// The same fields, with the zero-valued signature written out.
		"non-canonical": append([]byte{0x82, 0xa3, 's', 'i', 'g', 0xc4, 0x00, 0xa3, 't', 'x', 'n'}, encodeTxn(txn)[2:]...),
		"empty":         {},
	}
	for name, entry := range bad {
		t.Run(name, func(t *testing.T) {
			node := &sendAlgod{}
			signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}
			client, algodClient := newSendFixture(t, signer, node)

			if _, err := client.SubmitSignedGroup(context.Background(), algodClient, [][]byte{entry}, nil); err == nil || !strings.Contains(err.Error(), "verify signed group") {
				t.Fatalf("SubmitSignedGroup() error = %v, want the entry refused", err)
			}
			if _, err := client.SignTransactionsWithOptions([]types.Transaction{txn}, []string{""}, nil, &SignOptions{Passthrough: map[int][]byte{0: entry}}); err == nil || !strings.Contains(err.Error(), "invalid passthrough transaction 1") {
				t.Fatalf("passthrough: error = %v, want the entry refused", err)
			}
			if _, err := client.SimulatePreparedGroup(context.Background(), algodClient, NewPreparedGroup(PreparedTransaction{SignedTransaction: entry})); err == nil {
				t.Fatal("SimulatePreparedGroup() accepted the pre-signed slot")
			}
			if len(node.submissions()) != 0 || len(node.simulations()) != 0 || signer.count("/sign") != 0 {
				t.Fatal("something was posted")
			}
		})
	}
}
