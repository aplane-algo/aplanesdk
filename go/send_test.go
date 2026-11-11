// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"math"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
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

	mu        sync.Mutex
	submitted [][]byte
	lookups   int
	// waits are the rounds each wait-for-block call asked to follow.
	waits []string
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
		a.mu.Lock()
		a.waits = append(a.waits, strings.TrimPrefix(r.URL.Path, "/v2/status/wait-for-block-after/"))
		a.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]uint64{"last-round": 10})
	case r.URL.Path == "/v2/status":
		json.NewEncoder(w).Encode(map[string]uint64{"last-round": 10})
	case strings.HasPrefix(r.URL.Path, "/v2/transactions/pending/"):
		a.mu.Lock()
		a.lookups++
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
	if len(result.SignedGroup) != 1 || result.SignedGroup[0] != wantHex {
		t.Fatalf("signed group = %v", result.SignedGroup)
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
	if len(submitted) != 1 || hex.EncodeToString(submitted[0]) != strings.Join(result.SignedGroup, "") {
		t.Fatalf("submission is not the signed group, in order, once")
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
}

func TestSendPreparedRefusesBeforeSigning(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	other := verifyTestPayment(t, 45, 46, 1)
	sender := txn.Sender.String()
	holder := other.Sender.String()
	signedBase64, err := hexArrayToBase64([]string{fakeSignedTxnHex(txn)})
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
			name:  "rotating sender",
			keys:  []KeyInfo{{Address: sender, SigningFlow: SigningFlowRotating1}},
			group: preparedFor(txn),
			want:  ErrUnsupportedSigningFlow,
			text:  "rotating account",
		},
		{
			// After a rotation the chain names a stage address, so a caller
			// may bind another key; the sender's own record still decides.
			name:  "rotating sender bound to another key",
			keys:  []KeyInfo{{Address: sender, SigningFlow: SigningFlowRotating1}, {Address: holder}},
			group: NewPreparedGroup(PreparedTransaction{Transaction: &txn, AuthAddress: holder}),
			want:  ErrUnsupportedSigningFlow,
			text:  "rotating account",
		},
		{
			name:  "rekeyed to a rotating account",
			keys:  []KeyInfo{{Address: holder, SigningFlow: SigningFlowRotating1}},
			group: NewPreparedGroup(PreparedTransaction{Transaction: &txn, AuthAddress: holder}),
			want:  ErrUnsupportedSigningFlow,
			text:  "rotating account",
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
			group: NewPreparedGroup(PreparedTransaction{SignedTransactionBase64: signedBase64}),
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
			flow, err := client.classifySend(context.Background(), group)
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

	t.Run("an unreadable answer is an unknown outcome", func(t *testing.T) {
		signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}, sign: func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"signed": ["ab`))
		}}
		node := &sendAlgod{}
		client, algodClient := newSendFixture(t, signer, node)

		_, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
		var unknown *SignOutcomeUnknownError
		if !errors.As(err, &unknown) {
			t.Fatalf("error = %v, want *SignOutcomeUnknownError", err)
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

	tests := []struct {
		name      string
		node      *sendAlgod
		opts      *SendOptions
		rejected  bool
		stage     string
		text      string
		wantLooks bool
	}{
		{
			name:     "node refuses the group",
			node:     &sendAlgod{submit: httpError(http.StatusBadRequest, "overspend")},
			rejected: true,
			text:     "overspend",
		},
		{
			name:  "node fails without an answer about the group",
			node:  &sendAlgod{submit: httpError(http.StatusInternalServerError, "boom")},
			stage: SendStageSubmit,
			text:  "boom",
		},
		{
			name: "node reports another transaction ID",
			node: &sendAlgod{submit: func(w http.ResponseWriter, _ []byte) {
				json.NewEncoder(w).Encode(map[string]string{"txId": "SOMEOTHERID"})
			}},
			stage: SendStageSubmit,
			text:  "SOMEOTHERID",
		},
		{
			name: "pool drops the group",
			node: &sendAlgod{pending: func() models.PendingTransactionInfoResponse {
				return models.PendingTransactionInfoResponse{PoolError: "fee too low"}
			}},
			rejected: true,
			text:     "fee too low",
		},
		{
			name: "not confirmed within the wait",
			node: &sendAlgod{pending: func() models.PendingTransactionInfoResponse {
				return models.PendingTransactionInfoResponse{}
			}},
			opts:  &SendOptions{WaitRounds: 2},
			stage: SendStageConfirm,
			text:  "not confirmed after 2 rounds",
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
			var signedGroup, txIDs []string
			var rejected *SubmissionRejectedError
			var uncertain *SubmissionUncertainError
			switch {
			case errors.As(err, &rejected):
				if !tt.rejected {
					t.Fatalf("error = %v, want an uncertain outcome", err)
				}
				signedGroup, txIDs = rejected.SignedGroup, rejected.TxIDs
			case errors.As(err, &uncertain):
				if tt.rejected || uncertain.Stage != tt.stage {
					t.Fatalf("error = %v (stage %q), want rejected=%v stage %q", err, uncertain.Stage, tt.rejected, tt.stage)
				}
				signedGroup, txIDs = uncertain.SignedGroup, uncertain.TxIDs
			default:
				t.Fatalf("error = %v, want a typed submission error", err)
			}
			if !strings.Contains(err.Error(), tt.text) {
				t.Fatalf("error = %v, want it to mention %q", err, tt.text)
			}
			if len(signedGroup) != 1 || signedGroup[0] != wantHex || len(txIDs) != 1 || txIDs[0] != wantID {
				t.Fatalf("kept signed group %v and IDs %v", signedGroup, txIDs)
			}
			// Nothing is signed or submitted a second time.
			if signer.count("/sign") != 1 || len(tt.node.submissions()) != 1 {
				t.Fatalf("sign calls = %d, submissions = %d; want 1 and 1", signer.count("/sign"), len(tt.node.submissions()))
			}
		})
	}
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
	if len(submitted) != 1 || hex.EncodeToString(submitted[0]) != strings.Join(result.SignedGroup, "") {
		t.Fatalf("submission is not the signed group with its dummy, once")
	}
}

func TestSendPreparedConfirmationWait(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	unconfirmed := func() models.PendingTransactionInfoResponse { return models.PendingTransactionInfoResponse{} }

	t.Run("looks once now and once after each round of the wait", func(t *testing.T) {
		for _, rounds := range []uint64{1, 3} {
			signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}
			node := &sendAlgod{pending: unconfirmed}
			client, algodClient := newSendFixture(t, signer, node)
			_, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), &SendOptions{WaitRounds: rounds})
			var uncertain *SubmissionUncertainError
			if !errors.As(err, &uncertain) || uncertain.Stage != SendStageConfirm {
				t.Fatalf("error = %v", err)
			}
			if uint64(node.lookups) != rounds+1 {
				t.Fatalf("WaitRounds %d made %d lookups, want %d", rounds, node.lookups, rounds+1)
			}
			// At round 10 the first wait follows round 10, so it ends when
			// round 11 exists; the wait covers exactly the next rounds.
			want := map[uint64]string{1: "10", 3: "10,11,12"}[rounds]
			if got := strings.Join(node.waits, ","); got != want {
				t.Fatalf("WaitRounds %d waited after rounds %s, want %s", rounds, got, want)
			}
		}
	})

	t.Run("the largest wait does not wrap around", func(t *testing.T) {
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
		if err != nil || result.ConfirmedRound != 13 {
			t.Fatalf("SendPrepared() = %+v, %v", result, err)
		}
	})
}

func TestSubmitTreatsAnAlreadyKnownGroupAsSubmitted(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}
	node := &sendAlgod{submit: func(w http.ResponseWriter, _ []byte) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "TransactionPool.Remember: transaction already in ledger: " + crypto.GetTxID(txn)})
	}}
	client, algodClient := newSendFixture(t, signer, node)

	// The node has these bytes from an earlier submission. That is not a
	// refusal: a caller told "rejected" might sign a replacement.
	result, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
	if err != nil || result.Outcome != SendOutcomeConfirmed {
		t.Fatalf("SendPrepared() = %+v, %v; want the confirmed outcome", result, err)
	}
}

func TestSubmitFailuresThatAreNotAnswers(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)

	t.Run("connection dropped on submission", func(t *testing.T) {
		signer := &sendSigner{keys: []KeyInfo{ordinaryKey(txn)}}
		node := &sendAlgod{submit: func(w http.ResponseWriter, _ []byte) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			conn.Close()
		}}
		client, algodClient := newSendFixture(t, signer, node)
		_, err := client.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
		var uncertain *SubmissionUncertainError
		if !errors.As(err, &uncertain) || uncertain.Stage != SendStageSubmit || len(uncertain.SignedGroup) != 1 {
			t.Fatalf("error = %v, want an uncertain submission", err)
		}
	})

	t.Run("context ended before submission", func(t *testing.T) {
		node := &sendAlgod{t: t}
		algodClient, closeAlgod := makeSimulationAlgodClient(t, node.handle)
		defer closeAlgod()
		result := &SendResult{SignedGroup: []string{fakeSignedTxnHex(txn)}, OriginalCount: 1}
		raw, err := describeSignedGroup(result)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err = submitAndTrack(ctx, algodClient, raw, result, &SendOptions{})
		var uncertain *SubmissionUncertainError
		if !errors.As(err, &uncertain) || uncertain.Stage != SendStageUnsent || !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want the unsent stage", err)
		}
		if len(node.submissions()) != 0 {
			t.Fatalf("an ended context still submitted")
		}
	})
}

// cosignedSendFixture is a signer holding one cosigned account, its cosigner,
// and a node. fault names a user-signer path and how it fails: "<path> drop"
// closes the connection with no answer, "<path> truncate" answers 200 with a
// body cut short.
func cosignedSendFixture(t *testing.T, fault string) (*SignerClient, *SignerClient, *algod.Client, *sendAlgod, types.Transaction, *int) {
	t.Helper()
	bounded := sdkTestAddress(21)
	key := KeyInfo{
		Address: bounded, KeyType: "aplane.falcon1024.v1", SigningFlow: SigningFlowCosigned1,
		LogicSigResources: &LogicSigResourceProfile{
			Spend: &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 3358, MaxOpcodeCost: 20000},
		},
		CosignerComponentKeyType: KeyTypeWitnessFalcon1024,
		BoundedAuthorization: &BoundedAuthorizationInfo{
			Contract: BoundedContractBounded2, MaxFee: new(uint64(1000)),
			Cosigner: &BoundedCosignerAuthorizationInfo{ComponentKeyType: KeyTypeWitnessFalcon1024, PublicKeyHex: "aabb"},
		},
	}
	userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch fault {
		case r.URL.Path + " drop":
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			conn.Close()
			return
		case r.URL.Path + " truncate":
			w.Write([]byte(`{"request_id": "x", "signed_gr`))
			return
		}
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{State: "unlocked", ApprovalWaitSeconds: 60})
		case "/keys":
			json.NewEncoder(w).Encode(KeysResponse{Count: 1, Keys: []KeyInfo{key}})
		case "/plan":
			var req GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode plan request: %v", err)
				return
			}
			json.NewEncoder(w).Encode(PlanGroupResponse{Transactions: []string{req.Requests[0].TxnBytesHex}})
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
	cosignerCalls := 0
	cosignerClient, cosignerServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		cosignerCalls++
		var req capturedComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode cosigner request: %v", err)
			return
		}
		if req.ComponentKey != "COSIGNER_COMPONENT" {
			t.Errorf("cosigner component key = %q", req.ComponentKey)
		}
		json.NewEncoder(w).Encode(ComponentResponse{RequestID: req.RequestID, Components: []Component{{
			Kind: ComponentTargetKindCosigner, TargetIndex: 0, Signature: "cosigner-sig", SignatureScheme: KeyTypeWitnessFalcon1024,
		}}})
	})
	t.Cleanup(cosignerServer.Close)
	node := &sendAlgod{t: t}
	algodClient, closeAlgod := makeSimulationAlgodClient(t, node.handle)
	t.Cleanup(closeAlgod)

	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee: types.MicroAlgos(1000), FirstRoundValid: 1, LastRoundValid: 100,
		GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
	}
	txn, err := transaction.MakePaymentTxn(bounded, sdkTestAddress(22), 1000, nil, "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}
	return userClient, cosignerClient, algodClient, node, txn, &cosignerCalls
}

func TestSendPreparedCosignedGroup(t *testing.T) {
	userClient, cosignerClient, algodClient, node, txn, cosignerCalls := cosignedSendFixture(t, "")

	result, err := userClient.SendPrepared(context.Background(), algodClient, preparedFor(txn), &SendOptions{
		CosignerClient: cosignerClient, CosignerComponentKey: "COSIGNER_COMPONENT",
	})
	if err != nil {
		t.Fatalf("SendPrepared() error = %v", err)
	}
	if result.Flow != SigningFlowCosigned1 || result.Cosigned == nil || result.Cosigned.BoundedAssemblyResponse == nil || *cosignerCalls != 1 {
		t.Fatalf("result = %+v, cosigner calls = %d", result, *cosignerCalls)
	}
	submitted := node.submissions()
	if len(submitted) != 1 || hex.EncodeToString(submitted[0]) != strings.Join(result.SignedGroup, "") || result.Outcome != SendOutcomeConfirmed {
		t.Fatalf("the assembled group was not submitted once and confirmed")
	}
	if result.TxIDs[0] != crypto.GetTxID(txn) || result.Fees[0] != 1000 {
		t.Fatalf("txids %v fees %v", result.TxIDs, result.Fees)
	}
}

func TestSendPreparedCosignedWithoutACosignerIsRefused(t *testing.T) {
	userClient, _, algodClient, node, txn, _ := cosignedSendFixture(t, "")
	_, err := userClient.SendPrepared(context.Background(), algodClient, preparedFor(txn), nil)
	var unknown *SignOutcomeUnknownError
	if err == nil || !strings.Contains(err.Error(), "cosigner client or resolver is required") || errors.As(err, &unknown) {
		t.Fatalf("error = %v, want a plain refusal naming the missing cosigner", err)
	}
	if len(node.submissions()) != 0 {
		t.Fatalf("submitted without a cosigner")
	}
}

func TestSendPreparedCosignedLostAnswers(t *testing.T) {
	tests := []struct {
		fault   string
		unknown bool
	}{
		// Approval-bearing steps: the signer may have acted.
		{"/sign/component drop", true},
		{"/sign/component truncate", true},
		{"/sign/assemble drop", true},
		{"/sign/assemble truncate", true},
		// Planning releases nothing, so its failure is a plain error.
		{"/plan drop", false},
		{"/plan truncate", false},
	}
	for _, tt := range tests {
		t.Run(tt.fault, func(t *testing.T) {
			userClient, cosignerClient, algodClient, node, txn, _ := cosignedSendFixture(t, tt.fault)
			_, err := userClient.SendPrepared(context.Background(), algodClient, preparedFor(txn), &SendOptions{
				CosignerClient: cosignerClient, CosignerComponentKey: "COSIGNER_COMPONENT",
			})
			var unknown *SignOutcomeUnknownError
			if err == nil || errors.As(err, &unknown) != tt.unknown {
				t.Fatalf("error = %v, want unknown outcome = %v", err, tt.unknown)
			}
			if len(node.submissions()) != 0 {
				t.Fatalf("submitted after a failed signing step")
			}
		})
	}
}
