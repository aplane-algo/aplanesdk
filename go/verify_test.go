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

func TestBuildSignRequestsRejectsLsigArgsNoPositionUses(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	stray := LsigArgsMap{sdkTestAddress(45): LsigArgs{"preimage": []byte("secret")}}
	const want = "no signed transaction has auth address"

	if _, err := buildSignRequests([]types.Transaction{txn}, nil, stray); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("buildSignRequests() error = %v, want %q", err, want)
	}
	if _, err := buildSignRequests([]types.Transaction{txn}, nil, LsigArgsMap{"": LsigArgs{"a": nil}}); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("buildSignRequests() with an empty key error = %v, want %q", err, want)
	}
	if _, err := buildSignRequestsWithOptions([]types.Transaction{txn}, []string{txn.Sender.String()}, stray, nil); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("buildSignRequestsWithOptions() error = %v, want %q", err, want)
	}
	// Args keyed to a foreign position's sender sign nothing either.
	foreignArgs := LsigArgsMap{txn.Sender.String(): LsigArgs{"preimage": []byte("secret")}}
	if _, err := buildSignRequestsWithOptions([]types.Transaction{txn}, []string{""}, foreignArgs, nil); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("buildSignRequestsWithOptions() for a foreign position error = %v, want %q", err, want)
	}
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
