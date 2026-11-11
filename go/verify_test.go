// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// fakeSigner models what apsigner's planner does to a request group, so test
// servers return responses a real signer could return: it raises the fees it
// is told to, appends resource dummies, groups an ungrouped group, reports all
// of it, and signs.
type fakeSigner struct {
	feeRaise map[int]uint64
	dummies  int
}

func (f fakeSigner) finalize(t *testing.T, requests []SignRequest) ([]requestSlot, []types.Transaction, *MutationReport) {
	t.Helper()
	slots, err := decodeRequestSlots(requests)
	if err != nil {
		t.Fatalf("fake signer: decode requests: %v", err)
	}
	final := make([]types.Transaction, 0, len(slots)+f.dummies)
	report := MutationReport{OriginalCount: len(slots)}
	preGrouped := slots[0].txn.Group != (types.Digest{})
	for i, slot := range slots {
		txn := slot.txn
		if raise := f.feeRaise[i]; raise > 0 {
			txn.Fee += types.MicroAlgos(raise)
			report.FeesModified = append(report.FeesModified, i)
			report.TotalFeesDelta += int(raise)
		}
		switch slot.mode {
		case RequestModePassthrough:
			report.PassthroughCount++
		case RequestModeForeign:
			report.ForeignCount++
		}
		final = append(final, txn)
	}
	for i := 0; i < f.dummies; i++ {
		dummy, err := canonicalDummyTxn(slots[0].txn, types.Digest{}, i)
		if err != nil {
			t.Fatalf("fake signer: build dummy: %v", err)
		}
		final = append(final, dummy)
	}
	report.DummiesAdded = f.dummies
	report.FinalCount = len(final)
	if len(final) > 1 && (!preGrouped || f.dummies > 0 || report.TotalFeesDelta > 0) {
		for i := range final {
			final[i].Group = types.Digest{}
		}
		groupID, err := crypto.ComputeGroupID(final)
		if err != nil {
			t.Fatalf("fake signer: compute group ID: %v", err)
		}
		for i := range final {
			final[i].Group = groupID
		}
		report.GroupIDChanged = true
	}
	if report.DummiesAdded == 0 && report.TotalFeesDelta == 0 && !report.GroupIDChanged &&
		report.PassthroughCount == 0 && report.ForeignCount == 0 {
		return slots, final, nil
	}
	return slots, final, &report
}

// The fake signer's accounts, by address: Ed25519 keys, LogicSig programs and
// native Falcon public keys, as the real signer holds them.
var (
	fakeKeys     = map[string]ed25519.PrivateKey{}
	fakePrograms = map[string][]byte{}
	fakePQKeys   = map[string]types.PQSig{}
	fakeKeysMu   sync.Mutex
)

// fakeAccount is the address of the fake signer's Ed25519 account for a seed.
func fakeAccount(seed byte) string {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	var address types.Address
	copy(address[:], key.Public().(ed25519.PublicKey))
	fakeKeysMu.Lock()
	defer fakeKeysMu.Unlock()
	fakeKeys[address.String()] = key
	return address.String()
}

// fakeLogicSigAccount is the address of a LogicSig account the fake signer
// holds: the hash of its program, as for a LogicSig Falcon or generic account.
func fakeLogicSigAccount(seed byte) string {
	program := []byte{0x06, 0x81, seed} // #pragma version 6; pushint seed
	address := crypto.LogicSigAddress(types.LogicSig{Logic: program}).String()
	fakeKeysMu.Lock()
	defer fakeKeysMu.Unlock()
	fakePrograms[address] = program
	return address
}

// fakePQAccount is the address of a native Falcon account the fake signer
// holds. The public key and signature are filler: nothing verifies them.
func fakePQAccount(t *testing.T, seed byte) string {
	t.Helper()
	publicKey := bytes.Repeat([]byte{seed}, 1793)
	salt, err := crypto.CanonicalSaltForPQAddress(publicKey, types.PQSchemeFalcon1024)
	if err != nil {
		t.Fatalf("canonical PQ salt: %v", err)
	}
	proof := types.PQSig{Scheme: types.PQSchemeFalcon1024, Salt: salt, PublicKey: publicKey, Signature: bytes.Repeat([]byte{9}, 1232)}
	address := crypto.PQAddressFromSig(proof).String()
	fakeKeysMu.Lock()
	defer fakeKeysMu.Unlock()
	fakePQKeys[address] = proof
	return address
}

// fakeAuthorize signs a transaction as the fake signer's account at
// authAddress would: the account's kind of authorization, and the signer
// field when the account is not the sender. An address the fake signer does
// not hold gets a signature that verifies under nothing.
func fakeAuthorize(txn types.Transaction, authAddress string) types.SignedTxn {
	stxn := types.SignedTxn{Txn: txn}
	fakeKeysMu.Lock()
	defer fakeKeysMu.Unlock()
	switch {
	case fakeKeys[authAddress] != nil:
		copy(stxn.Sig[:], ed25519.Sign(fakeKeys[authAddress], encodeTxn(txn)))
	case fakePrograms[authAddress] != nil:
		stxn.Lsig = types.LogicSig{Logic: fakePrograms[authAddress], Args: [][]byte{{1, 2, 3}}}
	case len(fakePQKeys[authAddress].PublicKey) != 0:
		stxn.PQsig = fakePQKeys[authAddress]
	default:
		stxn.Sig = types.Signature{1, 2, 3}
	}
	if auth, err := types.DecodeAddress(authAddress); err == nil && auth != txn.Sender {
		stxn.AuthAddr = auth
	}
	return stxn
}

// fakeSignedTxnHex is a transaction signed by its sender.
func fakeSignedTxnHex(txn types.Transaction) string {
	return hex.EncodeToString(msgpack.Encode(fakeAuthorize(txn, txn.Sender.String())))
}

func (f fakeSigner) sign(t *testing.T, requests []SignRequest) GroupSignResponse {
	t.Helper()
	slots, final, report := f.finalize(t, requests)
	signed := make([]string, len(final))
	for i, txn := range final {
		switch {
		case i >= len(slots):
			raw, err := signCanonicalDummy(txn)
			if err != nil {
				t.Fatalf("fake signer: sign dummy: %v", err)
			}
			signed[i] = hex.EncodeToString(raw)
		case slots[i].mode == RequestModePassthrough:
			signed[i] = requests[i].SignedTxnHex
		case slots[i].mode == RequestModeForeign:
			signed[i] = ""
		default:
			signed[i] = hex.EncodeToString(msgpack.Encode(fakeAuthorize(txn, requests[i].AuthAddress)))
		}
	}
	return GroupSignResponse{Signed: signed, Mutations: report}
}

func (f fakeSigner) plan(t *testing.T, requests []SignRequest) PlanGroupResponse {
	t.Helper()
	_, final, report := f.finalize(t, requests)
	transactions := make([]string, len(final))
	for i, txn := range final {
		transactions[i] = hex.EncodeToString(encodeTxn(txn))
	}
	return PlanGroupResponse{Transactions: transactions, Mutations: report}
}

// fakeSignHandler answers /sign as fakeSigner would and /status as unlocked.
func fakeSignHandler(t *testing.T, f fakeSigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{State: "unlocked", ApprovalWaitSeconds: 60})
		case "/sign":
			var req GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode sign request: %v", err)
			}
			json.NewEncoder(w).Encode(f.sign(t, req.Requests))
		case "/plan":
			var req GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode plan request: %v", err)
			}
			json.NewEncoder(w).Encode(f.plan(t, req.Requests))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}
}

func verifyTestPayment(t *testing.T, senderSeed, receiverSeed byte, amount uint64) types.Transaction {
	t.Helper()
	var genesisHash types.Digest
	genesisHash[0] = 7
	sp := types.SuggestedParams{
		Fee: types.MicroAlgos(1000), FirstRoundValid: 10, LastRoundValid: 1010,
		GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
	}
	txn, err := transaction.MakePaymentTxn(fakeAccount(senderSeed), sdkTestAddress(receiverSeed), amount, nil, "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}
	return txn
}

func signRequestsFor(txns ...types.Transaction) []SignRequest {
	requests := make([]SignRequest, len(txns))
	for i, txn := range txns {
		requests[i] = SignRequest{
			AuthAddress: txn.Sender.String(),
			TxnSender:   txn.Sender.String(),
			TxnBytesHex: hex.EncodeToString(encodeTxn(txn)),
		}
	}
	return requests
}

func mustDecodeSlots(t *testing.T, requests []SignRequest) []requestSlot {
	t.Helper()
	slots, err := decodeRequestSlots(requests)
	if err != nil {
		t.Fatalf("decodeRequestSlots() error = %v", err)
	}
	return slots
}

func mustDecodeSigned(t *testing.T, signedHex string) types.SignedTxn {
	t.Helper()
	raw, err := hex.DecodeString(signedHex)
	if err != nil {
		t.Fatal(err)
	}
	var stxn types.SignedTxn
	if err := msgpack.Decode(raw, &stxn); err != nil {
		t.Fatal(err)
	}
	return stxn
}

func TestValidateSignResponseAcceptsReportedMutations(t *testing.T) {
	first := verifyTestPayment(t, 41, 42, 1_000_000)
	second := verifyTestPayment(t, 43, 44, 5)
	pregrouped, err := transaction.AssignGroupID([]types.Transaction{first, second}, "")
	if err != nil {
		t.Fatal(err)
	}
	passthrough := signRequestsFor(pregrouped...)
	passthrough[1] = SignRequest{SignedTxnHex: fakeSignedTxnHex(pregrouped[1])}
	foreign := signRequestsFor(pregrouped...)
	foreign[1] = SignRequest{TxnBytesHex: foreign[1].TxnBytesHex}

	cases := []struct {
		name     string
		signer   fakeSigner
		requests []SignRequest
		want     int
	}{
		{name: "single transaction, nothing changed", requests: signRequestsFor(first), want: 1},
		{
			// A native Falcon or LogicSig account: the signer raises the fee
			// of an ungrouped transaction and leaves it ungrouped.
			name:     "single transaction, fee raised",
			signer:   fakeSigner{feeRaise: map[int]uint64{0: 3000}},
			requests: signRequestsFor(first), want: 1,
		},
		{name: "ungrouped pair is grouped", requests: signRequestsFor(first, second), want: 2},
		{
			name:     "fee raised and dummies appended",
			signer:   fakeSigner{feeRaise: map[int]uint64{0: 2000}, dummies: 2},
			requests: signRequestsFor(first), want: 3,
		},
		{name: "pre-grouped pair is returned as sent", requests: signRequestsFor(pregrouped...), want: 2},
		{name: "passthrough position", requests: passthrough, want: 2},
		{name: "foreign position", requests: foreign, want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.signer.sign(t, tc.requests)
			if len(resp.Signed) != tc.want {
				t.Fatalf("fake signer returned %d slots, want %d", len(resp.Signed), tc.want)
			}
			if err := validateSignResponse(mustDecodeSlots(t, tc.requests), resp.Signed, resp.Mutations); err != nil {
				t.Fatalf("validateSignResponse() error = %v", err)
			}
		})
	}
}

func TestValidateSignResponseRejectsTampering(t *testing.T) {
	first := verifyTestPayment(t, 41, 42, 1_000_000)
	second := verifyTestPayment(t, 43, 44, 5)
	attacker, err := types.DecodeAddress(sdkTestAddress(45))
	if err != nil {
		t.Fatal(err)
	}
	pregrouped, err := transaction.AssignGroupID([]types.Transaction{first, second}, "")
	if err != nil {
		t.Fatal(err)
	}
	single := signRequestsFor(first)
	pair := signRequestsFor(first, second)
	passthrough := signRequestsFor(pregrouped...)
	passthrough[1] = SignRequest{SignedTxnHex: fakeSignedTxnHex(pregrouped[1])}
	foreign := signRequestsFor(pregrouped...)
	foreign[1] = SignRequest{TxnBytesHex: foreign[1].TxnBytesHex}
	raised := fakeSigner{feeRaise: map[int]uint64{0: 2000}}
	withDummies := fakeSigner{feeRaise: map[int]uint64{0: 2000}, dummies: 2}

	// resign replaces the transaction inside a signed slot, signed again by
	// its sender: the signature is good, the transaction is not the request's.
	resign := func(resp *GroupSignResponse, index int, edit func(*types.Transaction)) {
		txn := mustDecodeSigned(t, resp.Signed[index]).Txn
		edit(&txn)
		resp.Signed[index] = fakeSignedTxnHex(txn)
	}

	cases := []struct {
		name     string
		signer   fakeSigner
		requests []SignRequest
		tamper   func(resp *GroupSignResponse)
		want     string
	}{
		{
			name: "substituted receiver and amount", requests: single,
			tamper: func(resp *GroupSignResponse) {
				resign(resp, 0, func(txn *types.Transaction) { txn.Receiver = attacker; txn.Amount = 100_000_000 })
			},
			want: "unreported fields at original position 1",
		},
		{
			name: "unreported fee raise", requests: single,
			tamper: func(resp *GroupSignResponse) {
				resign(resp, 0, func(txn *types.Transaction) { txn.Fee += 5000 })
			},
			want: "unreported fields at original position 1",
		},
		{
			name: "fee raise larger than reported total", signer: raised, requests: single,
			tamper: func(resp *GroupSignResponse) {
				resign(resp, 0, func(txn *types.Transaction) { txn.Fee += 1 })
			},
			want: "total_fees_delta 2000 does not match observed delta 2001",
		},
		{
			name: "reported fee index did not increase", signer: raised, requests: single,
			tamper: func(resp *GroupSignResponse) {
				resign(resp, 0, func(txn *types.Transaction) { txn.Fee = first.Fee })
			},
			want: "did not increase the fee",
		},
		{
			name: "reported fee index decreased the fee", signer: raised, requests: single,
			tamper: func(resp *GroupSignResponse) {
				resign(resp, 0, func(txn *types.Transaction) { txn.Fee = first.Fee - 1 })
			},
			want: "did not increase the fee",
		},
		{
			name: "negative total fee delta", signer: raised, requests: single,
			tamper: func(resp *GroupSignResponse) { resp.Mutations.TotalFeesDelta = -2000 },
			want:   "total_fees_delta must not be negative",
		},
		{
			name: "duplicated fee index", signer: raised, requests: single,
			tamper: func(resp *GroupSignResponse) { resp.Mutations.FeesModified = []int{0, 0} },
			want:   "fee index 0 is duplicated",
		},
		{
			name: "fee index outside the request", signer: withDummies, requests: single,
			tamper: func(resp *GroupSignResponse) { resp.Mutations.FeesModified = []int{0, 1} },
			want:   "fee index 1 is outside original positions",
		},
		{
			name: "fee index on a passthrough position", requests: passthrough,
			tamper: func(resp *GroupSignResponse) { resp.Mutations.FeesModified = []int{1} },
			want:   "fee index 1 is a passthrough position",
		},
		{
			name: "group ID that does not bind the group", requests: pair,
			tamper: func(resp *GroupSignResponse) {
				for i := range resp.Signed {
					resign(resp, i, func(txn *types.Transaction) { txn.Group = types.Digest{0x99} })
				}
			},
			want: "does not carry the canonical group ID",
		},
		{
			name: "group ID changed without a report", requests: signRequestsFor(pregrouped...),
			tamper: func(resp *GroupSignResponse) {
				resign(resp, 0, func(txn *types.Transaction) { txn.Group = types.Digest{0x99} })
			},
			want: "unreported fields at original position 1",
		},
		{
			name: "group ID change reported for one transaction", signer: raised, requests: single,
			tamper: func(resp *GroupSignResponse) { resp.Mutations.GroupIDChanged = true },
			want:   "group ID change for a single transaction",
		},
		{
			name: "appended payment that is not a dummy", signer: withDummies, requests: single,
			tamper: func(resp *GroupSignResponse) {
				// A 50 ALGO payment in the dummy's place, regrouped so the
				// group ID is still canonical.
				txns := make([]types.Transaction, len(resp.Signed))
				for i := range resp.Signed {
					txns[i] = mustDecodeSigned(t, resp.Signed[i]).Txn
					txns[i].Group = types.Digest{}
				}
				txns[1] = verifyTestPayment(t, 41, 45, 50_000_000)
				groupID, err := crypto.ComputeGroupID(txns)
				if err != nil {
					t.Fatal(err)
				}
				for i := range txns {
					txns[i].Group = groupID
					resp.Signed[i] = fakeSignedTxnHex(txns[i])
				}
			},
			want: "appended transaction 1 is not the canonical resource dummy",
		},
		{
			name: "dummy with a different authorization", signer: withDummies, requests: single,
			tamper: func(resp *GroupSignResponse) {
				resp.Signed[2] = fakeSignedTxnHex(mustDecodeSigned(t, resp.Signed[2]).Txn)
			},
			want: "appended transaction 2 does not carry the canonical resource dummy authorization",
		},
		{
			name: "dummies_added does not match appended count", signer: withDummies, requests: single,
			tamper: func(resp *GroupSignResponse) { resp.Mutations.DummiesAdded = 1 },
			want:   "dummies_added 1 does not match appended count 2",
		},
		{
			name: "final_count does not match returned count", signer: withDummies, requests: single,
			tamper: func(resp *GroupSignResponse) { resp.Mutations.FinalCount = 2 },
			want:   "final_count 2 does not match returned count 3",
		},
		{
			name: "original_count does not match request", signer: raised, requests: single,
			tamper: func(resp *GroupSignResponse) { resp.Mutations.OriginalCount = 2 },
			want:   "original_count 2 does not match request count 1",
		},
		{
			name: "appended without a mutation report", signer: withDummies, requests: single,
			tamper: func(resp *GroupSignResponse) { resp.Mutations = nil },
			want:   "appended 2 transaction(s) without a mutation report",
		},
		{
			name: "appended without a group ID change", signer: withDummies, requests: single,
			tamper: func(resp *GroupSignResponse) { resp.Mutations.GroupIDChanged = false },
			want:   "appended dummies without reporting a group ID change",
		},
		{
			name: "trailing bytes after a signed transaction", requests: single,
			tamper: func(resp *GroupSignResponse) { resp.Signed[0] += resp.Signed[0] },
			want:   "signed transaction 1: bytes are not a canonical signed transaction",
		},
		{
			name: "truncated response", requests: pair,
			tamper: func(resp *GroupSignResponse) { resp.Signed = resp.Signed[:1] },
			want:   "returned 1 signed transaction(s), want at least 2",
		},
		{
			name: "empty signed position", requests: pair,
			tamper: func(resp *GroupSignResponse) { resp.Signed[1] = "" },
			want:   "no signature for position 2",
		},
		{
			name: "empty dummy position", signer: withDummies, requests: single,
			tamper: func(resp *GroupSignResponse) { resp.Signed[2] = "" },
			want:   "empty dummy transaction at position 3",
		},
		{
			name: "empty passthrough position", requests: passthrough,
			tamper: func(resp *GroupSignResponse) { resp.Signed[1] = "" },
			want:   "no signature for position 2",
		},
		{
			name: "altered passthrough", requests: passthrough,
			tamper: func(resp *GroupSignResponse) {
				stxn := mustDecodeSigned(t, resp.Signed[1])
				stxn.Sig = types.Signature{9}
				resp.Signed[1] = hex.EncodeToString(msgpack.Encode(stxn))
			},
			want: "signer changed passthrough transaction 2",
		},
		{
			name: "passthrough not reported", requests: passthrough,
			tamper: func(resp *GroupSignResponse) { resp.Mutations = nil },
			want:   "passthrough_count 0 does not match the 1 passthrough transaction(s) requested",
		},
		{
			name: "signed foreign position", requests: foreign,
			tamper: func(resp *GroupSignResponse) { resp.Signed[1] = fakeSignedTxnHex(pregrouped[1]) },
			want:   "signed transaction for foreign position 2",
		},
		{
			name: "foreign count does not match", requests: foreign,
			tamper: func(resp *GroupSignResponse) { resp.Mutations.ForeignCount = 0 },
			want:   "foreign_count 0 does not match the 1 foreign transaction(s) requested",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.signer.sign(t, tc.requests)
			slots := mustDecodeSlots(t, tc.requests)
			if err := validateSignResponse(slots, resp.Signed, resp.Mutations); err != nil {
				t.Fatalf("untampered response rejected: %v", err)
			}
			tc.tamper(&resp)
			err := validateSignResponse(slots, resp.Signed, resp.Mutations)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateSignResponse() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidatePlanResponse(t *testing.T) {
	first := verifyTestPayment(t, 31, 32, 1000)
	second := verifyTestPayment(t, 33, 34, 5)
	requests := signRequestsFor(first, second)
	requests[1] = SignRequest{TxnBytesHex: requests[1].TxnBytesHex}
	signer := fakeSigner{feeRaise: map[int]uint64{0: 1000}, dummies: 1}
	slots := mustDecodeSlots(t, requests)

	replan := func(resp *PlanGroupResponse, edit func(txns []types.Transaction)) {
		txns := make([]types.Transaction, len(resp.Transactions))
		for i, txnHex := range resp.Transactions {
			raw, _ := hex.DecodeString(txnHex)
			txn, err := decodeCanonicalTxn(raw)
			if err != nil {
				t.Fatal(err)
			}
			txn.Group = types.Digest{}
			txns[i] = txn
		}
		edit(txns)
		groupID, err := crypto.ComputeGroupID(txns)
		if err != nil {
			t.Fatal(err)
		}
		for i := range txns {
			txns[i].Group = groupID
			resp.Transactions[i] = hex.EncodeToString(encodeTxn(txns[i]))
		}
	}

	resp := signer.plan(t, requests)
	if len(resp.Transactions) != 3 {
		t.Fatalf("fake plan returned %d transactions, want 3", len(resp.Transactions))
	}
	if err := validatePlanResponse(slots, resp.Transactions, resp.Mutations); err != nil {
		t.Fatalf("valid plan: unexpected error %v", err)
	}

	cases := []struct {
		name   string
		tamper func(resp *PlanGroupResponse)
		want   string
	}{
		{
			name: "unreported original mutation",
			tamper: func(resp *PlanGroupResponse) {
				replan(resp, func(txns []types.Transaction) { txns[0].Amount = 999_999 })
			},
			want: "unreported fields at original position 1",
		},
		{
			name: "foreign position changed",
			tamper: func(resp *PlanGroupResponse) {
				replan(resp, func(txns []types.Transaction) { txns[1].Fee += 1000 })
			},
			want: "unreported fields at original position 2",
		},
		{
			name:   "fee index on a foreign position",
			tamper: func(resp *PlanGroupResponse) { resp.Mutations.FeesModified = []int{0, 1} },
			want:   "fee index 1 is a foreign position",
		},
		{
			name:   "wrong mutation counts",
			tamper: func(resp *PlanGroupResponse) { resp.Mutations.DummiesAdded = 0 },
			want:   "dummies_added 0 does not match appended count 1",
		},
		{
			name: "non-dummy appended transaction",
			tamper: func(resp *PlanGroupResponse) {
				replan(resp, func(txns []types.Transaction) { txns[2].Amount = 1 })
			},
			want: "appended transaction 1 is not the canonical resource dummy",
		},
		{
			name: "dummy on a different validity window",
			tamper: func(resp *PlanGroupResponse) {
				replan(resp, func(txns []types.Transaction) { txns[2].LastValid++ })
			},
			want: "appended transaction 1 is not the canonical resource dummy",
		},
		{
			name: "group ID that does not bind the group",
			tamper: func(resp *PlanGroupResponse) {
				replan(resp, func([]types.Transaction) {})
				for i, txnHex := range resp.Transactions {
					raw, _ := hex.DecodeString(txnHex)
					txn, _ := decodeCanonicalTxn(raw)
					txn.Group = types.Digest{0x44}
					resp.Transactions[i] = hex.EncodeToString(encodeTxn(txn))
				}
			},
			want: "does not carry the canonical group ID",
		},
		{
			name:   "missing TX prefix",
			tamper: func(resp *PlanGroupResponse) { resp.Transactions[0] = resp.Transactions[0][4:] },
			want:   "planned transaction 1: missing TX prefix",
		},
		{
			name:   "trailing bytes",
			tamper: func(resp *PlanGroupResponse) { resp.Transactions[0] += "00" },
			want:   "planned transaction 1: bytes are not canonical",
		},
		{
			name:   "truncated plan",
			tamper: func(resp *PlanGroupResponse) { resp.Transactions = resp.Transactions[:1] },
			want:   "returned 1 planned transaction(s), want at least 2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := signer.plan(t, requests)
			tc.tamper(&resp)
			err := validatePlanResponse(slots, resp.Transactions, resp.Mutations)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validatePlanResponse() error = %v, want %q", err, tc.want)
			}
		})
	}

	t.Run("signCosignedDummies rejects a non-dummy", func(t *testing.T) {
		dummy, err := canonicalDummyTxn(first, types.Digest{0x44}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := signCosignedDummies(first, types.Digest{0x44}, []types.Transaction{dummy}, 1); err != nil {
			t.Fatalf("canonical dummy rejected: %v", err)
		}
		dummy.Amount = 1
		if _, err := signCosignedDummies(first, types.Digest{0x44}, []types.Transaction{dummy}, 1); err == nil ||
			!strings.Contains(err.Error(), "not the canonical resource dummy") {
			t.Fatalf("signCosignedDummies() error = %v, want dummy rejection", err)
		}
	})
}

func TestDecodeRequestSlotsRejectsNoncanonicalRequestBytes(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	canonical := hex.EncodeToString(encodeTxn(txn))
	cases := map[string]SignRequest{
		"missing TX prefix": {AuthAddress: "A", TxnBytesHex: canonical[4:]},
		"trailing bytes":    {AuthAddress: "A", TxnBytesHex: canonical + "00"},
		"passthrough with trailing bytes": {
			SignedTxnHex: fakeSignedTxnHex(txn) + fakeSignedTxnHex(txn),
		},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRequestSlots([]SignRequest{req}); err == nil {
				t.Fatal("decodeRequestSlots() error = nil, want rejection")
			}
		})
	}
}

// The public sign and plan calls must run the checks, not only the helpers.
func TestSignAndPlanCallsRejectASubstitutedTransaction(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1_000_000)
	other := verifyTestPayment(t, 41, 45, 100_000_000)
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{State: "unlocked", ApprovalWaitSeconds: 60})
		case "/sign":
			json.NewEncoder(w).Encode(GroupSignResponse{Signed: []string{fakeSignedTxnHex(other)}})
		case "/plan":
			json.NewEncoder(w).Encode(PlanGroupResponse{Transactions: []string{hex.EncodeToString(encodeTxn(other))}})
		}
	})
	defer server.Close()

	const want = "unreported fields at original position 1"
	if _, err := client.SignTransaction(txn, "", nil); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("SignTransaction() error = %v, want %q", err, want)
	}
	if _, err := client.SignTransactionsList([]types.Transaction{txn}, nil, nil); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("SignTransactionsList() error = %v, want %q", err, want)
	}
	if _, err := client.SignRequestsWithContext(context.Background(), signRequestsFor(txn)); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("SignRequestsWithContext() error = %v, want %q", err, want)
	}
	prepared := NewPreparedGroup(PreparedTransaction{Transaction: &txn, AuthAddress: txn.Sender.String()})
	algodClient, closeAlgod := makeSimulationAlgodClient(t, func(http.ResponseWriter, *http.Request) {
		t.Error("simulation reached algod with an unverified signer response")
	})
	defer closeAlgod()
	if _, err := client.SimulatePreparedGroup(context.Background(), algodClient, prepared); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("SimulatePreparedGroup() error = %v, want %q", err, want)
	}
	if _, err := client.PlanGroup([]types.Transaction{txn}, []string{txn.Sender.String()}, nil, nil); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("PlanGroup() error = %v, want %q", err, want)
	}
}

func TestSignTransactionAcceptsARaisedFeeAndDummies(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1_000_000)
	client, server := newTestClient(fakeSignHandler(t, fakeSigner{feeRaise: map[int]uint64{0: 2000}, dummies: 1}))
	defer server.Close()

	list, err := client.SignTransactionsList([]types.Transaction{txn}, nil, nil)
	if err != nil {
		t.Fatalf("SignTransactionsList() error = %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("SignTransactionsList() returned %d slots, want the transaction and one dummy", len(list))
	}
	raw, err := base64.StdEncoding.DecodeString(list[0])
	if err != nil {
		t.Fatal(err)
	}
	stxn, err := decodeCanonicalSignedTxn(raw)
	if err != nil {
		t.Fatal(err)
	}
	if stxn.Txn.Fee != txn.Fee+2000 {
		t.Fatalf("signed fee = %d, want the raised fee %d", stxn.Txn.Fee, txn.Fee+2000)
	}
	plan, err := client.PlanGroup([]types.Transaction{txn}, []string{txn.Sender.String()}, nil, nil)
	if err != nil {
		t.Fatalf("PlanGroup() error = %v", err)
	}
	if len(plan.Transactions) != 2 || plan.Mutations == nil || plan.Mutations.DummiesAdded != 1 {
		t.Fatalf("PlanGroup() = %+v", plan)
	}
}

func TestSignTransactionSendsLsigArgsForTheSender(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	var got []SignRequest
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sign" {
			var req GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode sign request: %v", err)
			}
			got = req.Requests
			json.NewEncoder(w).Encode(fakeSigner{}.sign(t, req.Requests))
			return
		}
		json.NewEncoder(w).Encode(StatusResponse{State: "unlocked", ApprovalWaitSeconds: 60})
	})
	defer server.Close()

	if _, err := client.SignTransaction(txn, "", LsigArgs{"preimage": []byte("secret")}); err != nil {
		t.Fatalf("SignTransaction() error = %v", err)
	}
	if len(got) != 1 || got[0].AuthAddress != txn.Sender.String() ||
		got[0].LsigArgs["preimage"] != hex.EncodeToString([]byte("secret")) {
		t.Fatalf("sign request = %+v, want the sender's request to carry the preimage", got)
	}
}

func TestBuildSignRequestsRejectsLsigArgsNoPositionMatches(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	stray := LsigArgsMap{sdkTestAddress(45): LsigArgs{"preimage": []byte("secret")}}
	const want = "no transaction in the request has auth address"

	if _, err := buildSignRequests([]types.Transaction{txn}, nil, stray); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("buildSignRequests() error = %v, want %q", err, want)
	}
	if _, err := buildSignRequests([]types.Transaction{txn}, nil, LsigArgsMap{"": LsigArgs{"a": []byte{1}}}); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("buildSignRequests() with an empty key error = %v, want %q", err, want)
	}
	if _, err := buildSignRequestsWithOptions([]types.Transaction{txn}, []string{txn.Sender.String()}, stray, nil); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("buildSignRequestsWithOptions() error = %v, want %q", err, want)
	}
	// An entry with no args has nothing to drop, so it is ignored.
	empty := LsigArgsMap{sdkTestAddress(45): nil, sdkTestAddress(46): LsigArgs{}}
	if _, err := buildSignRequests([]types.Transaction{txn}, nil, empty); err != nil {
		t.Fatalf("buildSignRequests() with empty args error = %v", err)
	}
	if _, err := buildSignRequestsWithOptions([]types.Transaction{txn}, []string{txn.Sender.String()}, empty, nil); err != nil {
		t.Fatalf("buildSignRequestsWithOptions() with empty args error = %v", err)
	}
}

// One args map serves every call over a group: the plan with a foreign
// position, and the final signing once that position has come back signed.
func TestBuildSignRequestsAcceptsAReusedLsigArgsMap(t *testing.T) {
	grouped, err := transaction.AssignGroupID([]types.Transaction{
		verifyTestPayment(t, 41, 42, 1), verifyTestPayment(t, 43, 44, 2),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	first, second := grouped[0].Sender.String(), grouped[1].Sender.String()
	args := LsigArgsMap{
		first:  LsigArgs{"preimage": []byte("one")},
		second: LsigArgs{"preimage": []byte("two")},
	}
	wantFirst := hex.EncodeToString([]byte("one"))

	// Position 2 is foreign: its sender is still a position of the group.
	requests, err := buildSignRequestsWithOptions(grouped, []string{first, ""}, args, nil)
	if err != nil {
		t.Fatalf("plan with a foreign position: %v", err)
	}
	if requests[0].LsigArgs["preimage"] != wantFirst || requests[1].LsigArgs != nil {
		t.Fatalf("requests = %+v, want args on the signed position only", requests)
	}

	// Position 2 is passthrough, with its auth address given, defaulted from
	// the transaction, or known only from the signed bytes.
	passthrough := base64.StdEncoding.EncodeToString(mustDecodeHex(t, fakeSignedTxnHex(grouped[1])))
	opts := &SignOptions{Passthrough: map[int]string{1: passthrough}}
	for name, tc := range map[string]struct {
		txns  []types.Transaction
		auths []string
	}{
		"auth address given":    {grouped, []string{first, second}},
		"sender of the slot":    {grouped, []string{first, ""}},
		"only the signed bytes": {[]types.Transaction{grouped[0], {}}, []string{first, ""}},
	} {
		requests, err := buildSignRequestsWithOptions(tc.txns, tc.auths, args, opts)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if requests[0].LsigArgs["preimage"] != wantFirst || requests[1].SignedTxnHex == "" || requests[1].LsigArgs != nil {
			t.Fatalf("%s: requests = %+v", name, requests)
		}
	}

	// The whole call goes through with the reused map.
	client, server := newTestClient(fakeSignHandler(t, fakeSigner{}))
	defer server.Close()
	if _, err := client.SignTransactionsListWithOptions(grouped, []string{first, second}, args, opts); err != nil {
		t.Fatalf("SignTransactionsListWithOptions() with a reused args map: %v", err)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSignedTransactionIdentityChecksRejectTrailingBytes(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	other := verifyTestPayment(t, 41, 45, 2)
	canonical := hex.EncodeToString(encodeTxn(txn))
	signed := fakeSignedTxnHex(txn)

	if err := signedTxnMatchesCanonical("slot", 0, signed, canonical); err != nil {
		t.Fatalf("signedTxnMatchesCanonical() error = %v", err)
	}
	if _, _, _, err := decodeExecutableSignedGroup([]string{signed}); err != nil {
		t.Fatalf("decodeExecutableSignedGroup() error = %v", err)
	}

	// A second signed transaction after the first decodes as the first alone.
	concatenated := signed + fakeSignedTxnHex(other)
	const want = "not a canonical signed transaction"
	if err := signedTxnMatchesCanonical("slot", 0, concatenated, canonical); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("signedTxnMatchesCanonical() error = %v, want %q", err, want)
	}
	if _, _, _, err := decodeExecutableSignedGroup([]string{concatenated}); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("decodeExecutableSignedGroup() error = %v, want %q", err, want)
	}
	if err := verifyAssembledGroup([]string{canonical}, []string{concatenated}); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("verifyAssembledGroup() error = %v, want %q", err, want)
	}

	// A wrapper that is not the canonical encoding: the same fields, with the
	// zero-valued signature written out instead of omitted.
	noncanonical := append([]byte{0x82, 0xa3, 's', 'i', 'g', 0xc4, 0x00, 0xa3, 't', 'x', 'n'}, encodeTxn(txn)[2:]...)
	if err := signedTxnMatchesCanonical("slot", 0, hex.EncodeToString(noncanonical), canonical); err == nil {
		t.Fatal("signedTxnMatchesCanonical() accepted a non-canonical wrapper")
	}
}

// A signed position must carry exactly one authorization, and it must be the
// requested auth address's. The Python and TypeScript suites run the same
// list of cases.
func TestValidateSignResponseChecksTheAuthorization(t *testing.T) {
	ed := fakeAccount(41)
	other := fakeAccount(45)
	lsig := fakeLogicSigAccount(1)
	otherLsig := fakeLogicSigAccount(2)
	pq := fakePQAccount(t, 3)
	otherPQ := fakePQAccount(t, 4)
	dummy := crypto.LogicSigAddress(types.LogicSig{Logic: cosignedDummyProgram}).String()
	fakeKeysMu.Lock()
	fakePrograms[dummy] = cosignedDummyProgram
	fakeKeysMu.Unlock()

	payment := func(sender string) types.Transaction {
		txn := verifyTestPayment(t, 41, 42, 1_000_000)
		address, err := types.DecodeAddress(sender)
		if err != nil {
			t.Fatal(err)
		}
		txn.Sender = address
		return txn
	}
	check := func(txn types.Transaction, auth string, stxn types.SignedTxn) error {
		request := SignRequest{AuthAddress: auth, TxnSender: txn.Sender.String(), TxnBytesHex: hex.EncodeToString(encodeTxn(txn))}
		return validateSignResponse(mustDecodeSlots(t, []SignRequest{request}), []string{hex.EncodeToString(msgpack.Encode(stxn))}, nil)
	}

	accepted := []struct{ name, sender, auth string }{
		{"ed25519, sender signs", ed, ed},
		{"ed25519, rekeyed sender", other, ed},
		{"LogicSig account", lsig, lsig},
		{"LogicSig account, rekeyed sender", ed, lsig},
		{"native Falcon account", pq, pq},
		{"native Falcon account, rekeyed sender", ed, pq},
		{"the dummy program, when it is the auth address", dummy, dummy},
	}
	for _, tc := range accepted {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			txn := payment(tc.sender)
			if err := check(txn, tc.auth, fakeAuthorize(txn, tc.auth)); err != nil {
				t.Fatalf("validateSignResponse() error = %v", err)
			}
		})
	}

	otherAddress, _ := types.DecodeAddress(other)
	refused := []struct {
		name         string
		sender, auth string
		edit         func(stxn *types.SignedTxn)
		want         string
	}{
		{"an unsigned wrapper", ed, ed, func(stxn *types.SignedTxn) { stxn.Sig = types.Signature{} }, "carries no authorization"},
		{"a signature by another key", ed, ed, func(stxn *types.SignedTxn) { *stxn = fakeAuthorize(stxn.Txn, other); stxn.AuthAddr = types.Address{} }, "signature does not verify under the requested auth address"},
		{"a signature over another transaction", ed, ed, func(stxn *types.SignedTxn) {
			stxn.Sig = fakeAuthorize(verifyTestPayment(t, 41, 45, 5), ed).Sig
		}, "signature does not verify under the requested auth address"},
		{"the dummy LogicSig on an original position", ed, ed, func(stxn *types.SignedTxn) {
			*stxn = types.SignedTxn{Txn: stxn.Txn, Lsig: types.LogicSig{Logic: cosignedDummyProgram}}
		}, "LogicSig program address " + dummy + " is not the requested auth address"},
		{"the dummy LogicSig naming itself as signer", ed, ed, func(stxn *types.SignedTxn) {
			*stxn = fakeAuthorize(stxn.Txn, dummy)
		}, "names signer " + dummy + ", but the sender signs for itself"},
		{"another LogicSig program", lsig, lsig, func(stxn *types.SignedTxn) { stxn.Lsig.Logic = fakePrograms[otherLsig] }, "is not the requested auth address"},
		{"a LogicSig delegated by a signature", lsig, lsig, func(stxn *types.SignedTxn) { stxn.Lsig.Sig = types.Signature{1} }, "LogicSig is delegated by a signature"},
		{"a wrong signer field", other, ed, func(stxn *types.SignedTxn) { stxn.AuthAddr = otherAddress; stxn.AuthAddr[0] ^= 1 }, "not the requested auth address"},
		{"a missing signer field for a rekeyed sender", other, ed, func(stxn *types.SignedTxn) { stxn.AuthAddr = types.Address{} }, "does not name its signer"},
		{"a signer field when the sender signs", ed, ed, func(stxn *types.SignedTxn) { stxn.AuthAddr = otherAddress }, "but the sender signs for itself"},
		{"a multisig", ed, ed, func(stxn *types.SignedTxn) {
			stxn.Sig = types.Signature{}
			stxn.Msig = types.MultisigSig{Version: 1, Threshold: 1, Subsigs: []types.MultisigSubsig{{Key: make([]byte, 32)}}}
		}, "carries a multisig"},
		{"two authorizations", ed, ed, func(stxn *types.SignedTxn) { stxn.Lsig = types.LogicSig{Logic: fakePrograms[lsig]} }, "carries more than one authorization"},
		{"a post-quantum proof with no signature", pq, pq, func(stxn *types.SignedTxn) { stxn.PQsig.Signature = nil }, "missing its public key or signature"},
		{"a post-quantum proof with another scheme", pq, pq, func(stxn *types.SignedTxn) { stxn.PQsig.Scheme = types.PQScheme{'x', '9'} }, "post-quantum scheme"},
		{"another post-quantum key", pq, pq, func(stxn *types.SignedTxn) { stxn.PQsig = fakePQKeys[otherPQ] }, "post-quantum key's address"},
	}
	for _, tc := range refused {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			txn := payment(tc.sender)
			stxn := fakeAuthorize(txn, tc.auth)
			if err := check(txn, tc.auth, stxn); err != nil {
				t.Fatalf("untampered response rejected: %v", err)
			}
			tc.edit(&stxn)
			err := check(txn, tc.auth, stxn)
			if err == nil || !strings.Contains(err.Error(), "signed transaction 1 ") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateSignResponse() error = %v, want %q", err, tc.want)
			}
		})
	}

	t.Run("refuses a request whose auth address is not an address", func(t *testing.T) {
		txn := payment(ed)
		request := SignRequest{AuthAddress: "AUTH", TxnBytesHex: hex.EncodeToString(encodeTxn(txn))}
		if _, err := decodeRequestSlots([]SignRequest{request}); err == nil || !strings.Contains(err.Error(), `auth_address "AUTH" is not a valid address`) {
			t.Fatalf("decodeRequestSlots() error = %v", err)
		}
	})
}

// A request that already carries a group ID is immutable to the signer, so a
// response that regroups it, raises a fee on it or appends to it is refused:
// the positions the signer did not return stay bound to the original group.
func TestValidateSignResponseRefusesMutatingAGroupedRequest(t *testing.T) {
	pregrouped, err := transaction.AssignGroupID([]types.Transaction{
		verifyTestPayment(t, 41, 42, 1_000_000), verifyTestPayment(t, 43, 44, 5),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	withForeign := signRequestsFor(pregrouped...)
	withForeign[1] = SignRequest{TxnBytesHex: withForeign[1].TxnBytesHex}
	allSigned := signRequestsFor(pregrouped...)
	single := pregrouped[:1]

	refused := []struct {
		name     string
		requests []SignRequest
		signer   fakeSigner
		want     string
	}{
		{"fee raised and regrouped, with a foreign position", withForeign, fakeSigner{feeRaise: map[int]uint64{0: 2000}}, "group ID change for a request that was already grouped"},
		{"a dummy appended, with a foreign position", withForeign, fakeSigner{dummies: 1}, "group ID change for a request that was already grouped"},
		{"fee raised and regrouped, every position signed", allSigned, fakeSigner{feeRaise: map[int]uint64{0: 2000}}, "group ID change for a request that was already grouped"},
		{"fee raised on a single grouped transaction", signRequestsFor(single...), fakeSigner{feeRaise: map[int]uint64{0: 2000}}, "fee change for a request that was already grouped"},
	}
	for _, tc := range refused {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			resp := tc.signer.sign(t, tc.requests)
			err := validateSignResponse(mustDecodeSlots(t, tc.requests), resp.Signed, resp.Mutations)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateSignResponse() error = %v, want %q", err, tc.want)
			}
			plan := tc.signer.plan(t, tc.requests)
			err = validatePlanResponse(mustDecodeSlots(t, tc.requests), plan.Transactions, plan.Mutations)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validatePlanResponse() error = %v, want %q", err, tc.want)
			}
		})
	}

	// The signer does group an ungrouped request that has a foreign position,
	// and may raise the fee of a position it signs in it.
	ungrouped := signRequestsFor(verifyTestPayment(t, 41, 42, 1_000_000), verifyTestPayment(t, 43, 44, 5))
	ungrouped[1] = SignRequest{TxnBytesHex: ungrouped[1].TxnBytesHex}
	accepted := []struct {
		name     string
		requests []SignRequest
		signer   fakeSigner
	}{
		{"a grouped request returned as sent, with a foreign position", withForeign, fakeSigner{}},
		{"a grouped request returned as sent, every position signed", allSigned, fakeSigner{}},
		{"an ungrouped request with a foreign position, grouped", ungrouped, fakeSigner{}},
		{"an ungrouped request with a foreign position, fee raised and a dummy", ungrouped, fakeSigner{feeRaise: map[int]uint64{0: 2000}, dummies: 1}},
	}
	for _, tc := range accepted {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			resp := tc.signer.sign(t, tc.requests)
			if err := validateSignResponse(mustDecodeSlots(t, tc.requests), resp.Signed, resp.Mutations); err != nil {
				t.Fatalf("validateSignResponse() error = %v", err)
			}
		})
	}
}

// realSignVectors are requests and the responses a live signer returned for
// them. The fake signer builds its dummies with the helpers under test, so
// these are what show the SDK's idea of a canonical dummy is the signer's.
func realSignVectors(t *testing.T) map[string]struct {
	KeyType string `json:"key_type"`
	Request struct {
		Requests []SignRequest `json:"requests"`
	} `json:"request"`
	Response GroupSignResponse `json:"response"`
} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "contracts", "signerapi_vectors", "real_sign_responses.json"))
	if err != nil {
		t.Fatalf("read captured signer responses: %v", err)
	}
	var vectors map[string]struct {
		KeyType string `json:"key_type"`
		Request struct {
			Requests []SignRequest `json:"requests"`
		} `json:"request"`
		Response GroupSignResponse `json:"response"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse captured signer responses: %v", err)
	}
	return vectors
}

func TestValidateSignResponseAcceptsCapturedSignerResponses(t *testing.T) {
	vectors := realSignVectors(t)
	// flipByte changes one byte of a hex string, counted from its end.
	flipByte := func(value string, fromEnd int) string {
		raw := mustDecodeHex(t, value)
		raw[len(raw)-fromEnd] ^= 0x01
		return hex.EncodeToString(raw)
	}
	// The slot whose last byte is flipped: the appended dummy where there is
	// one, otherwise the first signed transaction.
	tampers := map[string]int{
		"logicsig_falcon_single": 1,
		"logicsig_falcon_pair":   2,
		"native_falcon_single":   0,
		"ed25519_pair":           0,
	}
	if len(vectors) != len(tampers) {
		t.Fatalf("captured vectors = %d cases, want %d", len(vectors), len(tampers))
	}
	for name, vector := range vectors {
		t.Run(name, func(t *testing.T) {
			slots := mustDecodeSlots(t, vector.Request.Requests)
			if err := validateSignResponse(slots, vector.Response.Signed, vector.Response.Mutations); err != nil {
				t.Fatalf("a real signer response was refused: %v", err)
			}
			slot, ok := tampers[name]
			if !ok {
				t.Fatalf("no tamper case for vector %q", name)
			}
			signed := append([]string(nil), vector.Response.Signed...)
			signed[slot] = flipByte(signed[slot], 1)
			if err := validateSignResponse(slots, signed, vector.Response.Mutations); err == nil {
				t.Fatalf("a real response with one byte of slot %d flipped was accepted", slot+1)
			}
		})
	}

	// An Ed25519 signature with one byte changed no longer verifies.
	ed := vectors["ed25519_pair"]
	stxn := mustDecodeSigned(t, ed.Response.Signed[0])
	stxn.Sig[0] ^= 0x01
	signed := append([]string(nil), ed.Response.Signed...)
	signed[0] = hex.EncodeToString(msgpack.Encode(stxn))
	err := validateSignResponse(mustDecodeSlots(t, ed.Request.Requests), signed, ed.Response.Mutations)
	if err == nil || !strings.Contains(err.Error(), "signature does not verify under the requested auth address") {
		t.Fatalf("flipped Ed25519 signature byte: error = %v", err)
	}
	// A dummy whose authorization differs by one byte is not the signer's.
	lsig := vectors["logicsig_falcon_single"]
	dummy := mustDecodeSigned(t, lsig.Response.Signed[1])
	dummy.Lsig.Args = [][]byte{{0x01}}
	signed = append([]string(nil), lsig.Response.Signed...)
	signed[1] = hex.EncodeToString(msgpack.Encode(dummy))
	err = validateSignResponse(mustDecodeSlots(t, lsig.Request.Requests), signed, lsig.Response.Mutations)
	if err == nil || !strings.Contains(err.Error(), "appended transaction 1 does not carry the canonical resource dummy authorization") {
		t.Fatalf("dummy with a changed authorization: error = %v", err)
	}
}
