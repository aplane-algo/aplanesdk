// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
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
		groupID, err := algocrypto.ComputeGroupID(final)
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

func fakeSignedTxnHex(txn types.Transaction) string {
	return hex.EncodeToString(msgpack.Encode(types.SignedTxn{Sig: types.Signature{1, 2, 3}, Txn: txn}))
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
			signed[i] = fakeSignedTxnHex(txn)
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
	txn, err := transaction.MakePaymentTxn(sdkTestAddress(senderSeed), sdkTestAddress(receiverSeed), amount, nil, "", sp)
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
			if err := validateSignResponse(mustDecodeSlots(t, tc.requests), resp.Signed, resp.Mutations, feeCeiling{}); err != nil {
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

	// resign replaces the transaction inside a signed slot.
	resign := func(resp *GroupSignResponse, index int, edit func(*types.Transaction)) {
		stxn := mustDecodeSigned(t, resp.Signed[index])
		edit(&stxn.Txn)
		resp.Signed[index] = hex.EncodeToString(msgpack.Encode(stxn))
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
				groupID, err := algocrypto.ComputeGroupID(txns)
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
			if err := validateSignResponse(slots, resp.Signed, resp.Mutations, feeCeiling{}); err != nil {
				t.Fatalf("untampered response rejected: %v", err)
			}
			tc.tamper(&resp)
			err := validateSignResponse(slots, resp.Signed, resp.Mutations, feeCeiling{})
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
		groupID, err := algocrypto.ComputeGroupID(txns)
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
	if err := validatePlanResponse(slots, resp.Transactions, resp.Mutations, feeCeiling{}); err != nil {
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
			err := validatePlanResponse(slots, resp.Transactions, resp.Mutations, feeCeiling{})
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

func TestMaxFeeIncrease(t *testing.T) {
	first := verifyTestPayment(t, 41, 42, 1_000_000)
	second := verifyTestPayment(t, 43, 44, 5)
	u := func(v uint64) *uint64 { return &v }
	cases := []struct {
		name   string
		limit  *uint64
		signer fakeSigner
		txns   []types.Transaction
		want   string
	}{
		// Unset is unbounded: a reported raise of any size is accepted.
		{name: "unset, large raise", signer: fakeSigner{feeRaise: map[int]uint64{0: 5_000_000}}, txns: []types.Transaction{first}},
		{name: "above the raise", limit: u(200_000), signer: fakeSigner{feeRaise: map[int]uint64{0: 3000}}, txns: []types.Transaction{first}},
		{name: "equal to the raise", limit: u(3000), signer: fakeSigner{feeRaise: map[int]uint64{0: 3000}}, txns: []types.Transaction{first}},
		{
			name: "one below the raise", limit: u(2999), signer: fakeSigner{feeRaise: map[int]uint64{0: 3000}}, txns: []types.Transaction{first},
			want: "signer raised fees by 3000 microAlgos, more than the max fee increase 2999 set on this client",
		},
		{
			name: "zero with a raise", limit: u(0), signer: fakeSigner{feeRaise: map[int]uint64{0: 1}}, txns: []types.Transaction{first},
			want: "signer raised fees by 1 microAlgos, more than the max fee increase 0 set on this client",
		},
		{name: "zero with no raise", limit: u(0), txns: []types.Transaction{first, second}},
		{
			name: "raise spread over two positions is summed", limit: u(4999),
			signer: fakeSigner{feeRaise: map[int]uint64{0: 2000, 1: 3000}}, txns: []types.Transaction{first, second},
			want: "signer raised fees by 5000 microAlgos, more than the max fee increase 4999 set on this client",
		},
		{
			name: "two positions at the sum", limit: u(5000),
			signer: fakeSigner{feeRaise: map[int]uint64{0: 2000, 1: 3000}}, txns: []types.Transaction{first, second},
		},
		{
			// Dummies pay no fee; only the raise counts.
			name: "dummies add nothing", limit: u(2000),
			signer: fakeSigner{feeRaise: map[int]uint64{0: 2000}, dummies: 2}, txns: []types.Transaction{first},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := newTestClient(fakeSignHandler(t, tc.signer))
			defer server.Close()
			if tc.limit != nil {
				client.SetMaxFeeIncrease(*tc.limit)
			}
			algodClient, closeAlgod := makeSimulationAlgodClient(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.want != "" {
					t.Error("simulation reached algod with a fee raise over the ceiling")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"last-round":1,"version":2,"txn-groups":[{}]}`))
			})
			defer closeAlgod()
			auths := make([]string, len(tc.txns))
			prepared := PreparedGroup{}
			for i := range tc.txns {
				auths[i] = tc.txns[i].Sender.String()
				prepared.Transactions = append(prepared.Transactions, PreparedTransaction{Transaction: &tc.txns[i], AuthAddress: auths[i]})
			}

			check := func(call string, prefix string, err error) {
				t.Helper()
				if tc.want == "" {
					if err != nil {
						t.Fatalf("%s error = %v", call, err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), prefix+tc.want) {
					t.Fatalf("%s error = %v, want %q", call, err, prefix+tc.want)
				}
			}
			_, err := client.SignTransactions(tc.txns, nil, nil)
			check("SignTransactions()", "verify signer response: ", err)
			_, err = client.SignTransactionsList(tc.txns, nil, nil)
			check("SignTransactionsList()", "verify signer response: ", err)
			_, err = client.SignRequestsWithContext(context.Background(), signRequestsFor(tc.txns...))
			check("SignRequestsWithContext()", "verify signer response: ", err)
			_, err = client.PlanGroup(tc.txns, auths, nil, nil)
			check("PlanGroup()", "verify signer plan: ", err)
			_, err = client.SimulatePreparedGroup(context.Background(), algodClient, prepared)
			check("SimulatePreparedGroup()", "verify signer response: ", err)
		})
	}
}

func TestMaxFeeIncreaseSetAndClear(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	client, server := newTestClient(fakeSignHandler(t, fakeSigner{feeRaise: map[int]uint64{0: 3000}}))
	defer server.Close()

	if _, set := client.MaxFeeIncrease(); set {
		t.Fatal("a new client has a max fee increase; there must be no default")
	}
	client.SetMaxFeeIncrease(1000)
	if limit, set := client.MaxFeeIncrease(); !set || limit != 1000 {
		t.Fatalf("MaxFeeIncrease() = %d, %v, want 1000, true", limit, set)
	}
	if _, err := client.SignTransaction(txn, "", nil); err == nil || !strings.Contains(err.Error(), "more than the max fee increase 1000") {
		t.Fatalf("SignTransaction() error = %v, want the ceiling to refuse", err)
	}
	client.ClearMaxFeeIncrease()
	if _, set := client.MaxFeeIncrease(); set {
		t.Fatal("ClearMaxFeeIncrease() left a ceiling set")
	}
	if _, err := client.SignTransaction(txn, "", nil); err != nil {
		t.Fatalf("SignTransaction() after clearing the ceiling: %v", err)
	}
}

// A call is held to the ceiling in force when it started. Clearing it while
// the signer is still waiting for approval must not let the response through.
func TestMaxFeeIncreaseIsSnapshottedWhenTheCallStarts(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	signer := fakeSigner{feeRaise: map[int]uint64{0: 3000}}
	for _, path := range []string{"/sign", "/plan"} {
		t.Run(path, func(t *testing.T) {
			arrived := make(chan struct{})
			release := make(chan struct{})
			var held sync.Once
			client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == path {
					// Only the first call is held back.
					held.Do(func() {
						close(arrived)
						<-release
					})
				}
				fakeSignHandler(t, signer)(w, r)
			})
			defer server.Close()
			client.cacheApprovalWait(60)
			client.SetMaxFeeIncrease(1000)

			result := make(chan error, 1)
			go func() {
				var err error
				if path == "/sign" {
					_, err = client.SignTransaction(txn, "", nil)
				} else {
					_, err = client.PlanGroup([]types.Transaction{txn}, []string{txn.Sender.String()}, nil, nil)
				}
				result <- err
			}()
			<-arrived
			client.ClearMaxFeeIncrease()
			close(release)

			err := <-result
			if err == nil || !strings.Contains(err.Error(), "more than the max fee increase 1000 set on this client") {
				t.Fatalf("error = %v, want the ceiling set when the call started to refuse", err)
			}
			// The next call starts with no ceiling.
			if _, err := client.SignTransaction(txn, "", nil); err != nil {
				t.Fatalf("call started after clearing the ceiling: %v", err)
			}
		})
	}
}

func TestConnectionOptionsSetMaxFeeIncrease(t *testing.T) {
	limit := uint64(250_000)

	client := newTunnelClient(1234, nil, DefaultTimeout, &SSHConnectOptions{MaxFeeIncrease: &limit})
	if got, set := client.MaxFeeIncrease(); !set || got != limit {
		t.Fatalf("client built from SSHConnectOptions: MaxFeeIncrease() = %d, %v, want %d, true", got, set, limit)
	}
	// The client keeps its own copy.
	limit = 1
	if got, _ := client.MaxFeeIncrease(); got != 250_000 {
		t.Fatalf("MaxFeeIncrease() = %d after the caller changed its variable, want 250000", got)
	}
	for name, opts := range map[string]*SSHConnectOptions{"nil options": nil, "unset": {}} {
		if _, set := newTunnelClient(1234, nil, DefaultTimeout, opts).MaxFeeIncrease(); set {
			t.Fatalf("%s: client has a max fee increase; there must be no default", name)
		}
	}

	limit = 250_000
	sshOpts := fromEnvSSHOptions(&FromEnvOptions{MaxFeeIncrease: &limit, Timeout: 7, TrustOnFirstUse: true}, 2222, "/kh")
	if sshOpts.MaxFeeIncrease == nil || *sshOpts.MaxFeeIncrease != limit {
		t.Fatalf("FromEnvOptions.MaxFeeIncrease was not carried to the SSH options: %+v", sshOpts)
	}
	if sshOpts.SSHPort != 2222 || sshOpts.KnownHostsPath != "/kh" || sshOpts.Timeout != 7 || !sshOpts.TrustOnFirstUse {
		t.Fatalf("fromEnvSSHOptions() = %+v", sshOpts)
	}
	if got := fromEnvSSHOptions(nil, 2222, "/kh"); got.MaxFeeIncrease != nil || got.SSHPort != 2222 {
		t.Fatalf("fromEnvSSHOptions(nil) = %+v", got)
	}
	zero := uint64(0)
	if got, set := newTunnelClient(1, nil, DefaultTimeout, fromEnvSSHOptions(&FromEnvOptions{MaxFeeIncrease: &zero}, 1, "")).MaxFeeIncrease(); !set || got != 0 {
		t.Fatalf("a zero ceiling from FromEnvOptions: MaxFeeIncrease() = %d, %v, want 0, true", got, set)
	}
}
