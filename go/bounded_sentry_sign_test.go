// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestSignPreparedBoundedSentryGroupOneTarget(t *testing.T) {
	bounded := sdkTestAddress(21)
	receiver := sdkTestAddress(22)
	var frozenGroup []string

	userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				IdentityID: "default", State: "unlocked", ApprovalWaitSeconds: 60,
			})
		case "/sign/bounded-component":
			var req BoundedComponentRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode bounded component request: %v", err)
			}
			if len(req.Requests) != 1 || req.Requests[0].AuthAddress != bounded {
				t.Fatalf("bounded component request = %+v", req)
			}
			frozenGroup = []string{req.Requests[0].TxnBytesHex}
			json.NewEncoder(w).Encode(BoundedComponentResponse{
				RequestID:    req.RequestID,
				Transactions: frozenGroup,
				Components: []BoundedBaseComponent{{
					TargetIndex:     0,
					BoundedAccount:  bounded,
					BaseSignatures:  []string{"base-sig"},
					RuntimeArgs:     map[string]string{"proof": "aabb"},
					AssemblyReceipt: "receipt",
					SignatureScheme: "aplane.falcon1024.v1",
				}},
			})
		case "/sign/bounded-assemble":
			var req BoundedAssemblyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode bounded assembly request: %v", err)
			}
			if len(req.Targets) != 1 || req.Targets[0].AssemblyReceipt != "receipt" ||
				req.Targets[0].SentrySignature != "sentry-sig" {
				t.Fatalf("bounded assembly targets = %+v", req.Targets)
			}
			json.NewEncoder(w).Encode(BoundedAssemblyResponse{
				RequestID: req.RequestID, SignedGroup: signedGroupFor(t, req.GroupBytesHex),
			})
		default:
			t.Fatalf("unexpected user path %s", r.URL.Path)
		}
	})
	defer userServer.Close()

	sentryClient, sentryServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign/component" {
			t.Fatalf("unexpected sentry path %s", r.URL.Path)
		}
		var req ComponentSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode sentry component request: %v", err)
		}
		if req.Role != ComponentSignRoleSentry || req.ComponentKey != "SENTRY_COMPONENT" ||
			len(req.GroupBytesHex) != 1 || req.GroupBytesHex[0] != frozenGroup[0] {
			t.Fatalf("sentry component request = %+v", req)
		}
		json.NewEncoder(w).Encode(ComponentSignResponse{
			RequestID: req.RequestID,
			Signatures: []ComponentSignature{{
				TargetIndex: 0, Signature: "sentry-sig", SignatureScheme: KeyTypeWitnessFalcon1024,
			}},
		})
	})
	defer sentryServer.Close()

	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee: types.MicroAlgos(1000), FirstRoundValid: 1, LastRoundValid: 100,
		GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
	}
	txn, err := transaction.MakePaymentTxn(bounded, receiver, 1000, nil, "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}
	result, err := SignPreparedGuardedGroup(PreparedGuardedGroupOptions{
		UserClient: userClient, SentryClient: sentryClient,
		SentryComponentKey: "SENTRY_COMPONENT",
		PreparedGroup: NewPreparedGroup(PreparedTransaction{
			Transaction: &txn, AuthAddress: bounded,
			SignerKey: &KeyInfo{
				Address: bounded, KeyType: "aplane.corridor.v1",
				SigningFlow: SigningFlowBoundedSentry1, LsigSize: 9012,
				SentryComponentKeyType: KeyTypeWitnessFalcon1024,
				BoundedAuthorization: &BoundedAuthorizationInfo{
					Sentry: &BoundedSentryAuthorizationInfo{
						ComponentKeyType: KeyTypeWitnessFalcon1024, PublicKeyHex: "aabb",
					},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("SignPreparedGuardedGroup() error = %v", err)
	}
	if len(result.SignedGroup) != 1 || result.BoundedComponentResponse == nil ||
		result.BoundedAssemblyResponse == nil || result.AssemblyResponse != nil {
		t.Fatalf("result = %+v", result)
	}
}

func TestBoundedAssemblyRequestRejectsMissingCoverage(t *testing.T) {
	req := BoundedAssemblyRequest{
		GroupBytesHex: []string{"5458aa", "5458bb"},
		Targets: []BoundedAssemblyTarget{{
			TargetIndex: 0, BoundedAccount: "BOUNDED", BaseSignatures: []string{"base"},
			AssemblyReceipt: "receipt", SentrySignature: "sentry",
		}},
	}
	if err := req.Validate(); err == nil {
		t.Fatal("Validate() succeeded, want missing coverage error")
	}
}

func TestBoundedComponentRequestRejectsPassthrough(t *testing.T) {
	err := (BoundedComponentRequest{
		RequestID: "bounded-request",
		Requests:  []SignRequest{{SignedTxnHex: "abcd"}},
	}).Validate()
	if err == nil || !strings.Contains(err.Error(), "does not accept signed passthrough") {
		t.Fatalf("Validate() error = %v, want passthrough rejection", err)
	}
}

func TestBoundedComponentResponseRejectsMalformedTargets(t *testing.T) {
	valid := BoundedBaseComponent{
		TargetIndex: 0, BoundedAccount: "BOUNDED",
		BaseSignatures: []string{"base"}, AssemblyReceipt: "receipt",
		SignatureScheme: "aplane.falcon1024.v1",
	}
	tests := []struct {
		name       string
		components []BoundedBaseComponent
		want       string
	}{
		{
			name:       "duplicate",
			components: []BoundedBaseComponent{valid, valid},
			want:       "invalid or duplicate target_index",
		},
		{
			name: "out of range",
			components: []BoundedBaseComponent{func() BoundedBaseComponent {
				item := valid
				item.TargetIndex = 1
				return item
			}()},
			want: "invalid or duplicate target_index",
		},
		{
			name: "incomplete",
			components: []BoundedBaseComponent{func() BoundedBaseComponent {
				item := valid
				item.AssemblyReceipt = ""
				return item
			}()},
			want: "incomplete",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (BoundedComponentResponse{
				RequestID:    "bounded-response",
				Transactions: []string{"5458aa"},
				Components:   tt.components,
			}).Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPreparedBoundedSentryRejectsMixedFlow(t *testing.T) {
	_, err := SignPreparedGuardedGroup(PreparedGuardedGroupOptions{
		UserClient: &SignerClient{},
		PreparedGroup: NewPreparedGroup(
			PreparedTransaction{SignerKey: &KeyInfo{SigningFlow: SigningFlowBoundedSentry1}},
			PreparedTransaction{SignerKey: &KeyInfo{SigningFlow: SigningFlowSentry1}},
		),
	})
	if err == nil || !strings.Contains(err.Error(), "cannot mix sentry1 and bounded-sentry1") {
		t.Fatalf("SignPreparedGuardedGroup() error = %v, want mixed-flow rejection", err)
	}
}

func TestRequestBoundedPrimaryPassthroughVerifiesTransactionIdentity(t *testing.T) {
	sender := sdkTestAddress(41)
	receiver := sdkTestAddress(42)
	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee: types.MicroAlgos(1000), FirstRoundValid: 1, LastRoundValid: 100,
		GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
	}
	txn, err := transaction.MakePaymentTxn(sender, receiver, 1000, nil, "", sp)
	if err != nil {
		t.Fatal(err)
	}
	other, err := transaction.MakePaymentTxn(sender, receiver, 2000, nil, "", sp)
	if err != nil {
		t.Fatal(err)
	}
	canonical := hex.EncodeToString(encodeTxn(txn))
	signedTxn := txn

	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				IdentityID: "default", State: "unlocked", ApprovalWaitSeconds: 60,
			})
		case "/sign":
			json.NewEncoder(w).Encode(GroupSignResponse{
				Signed: signedGroupFor(t, []string{hex.EncodeToString(encodeTxn(signedTxn))}),
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})
	defer server.Close()

	args := func() (*primaryGuardedPassthrough, error) {
		return requestBoundedPrimaryPassthrough(
			context.Background(),
			client,
			[]string{canonical},
			1,
			map[int]GuardedSignTarget{},
			map[int]int{},
			[]GuardedPrimarySignTarget{{TargetIndex: 0, AuthAddress: sender}},
		)
	}
	if _, err := args(); err != nil {
		t.Fatalf("matching primary passthrough: %v", err)
	}
	signedTxn = other
	if _, err := args(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched primary passthrough error = %v, want identity rejection", err)
	}
}

func TestValidateBoundedComponentPlan(t *testing.T) {
	sender := sdkTestAddress(31)
	receiver := sdkTestAddress(32)
	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee: types.MicroAlgos(1000), FirstRoundValid: 1, LastRoundValid: 100,
		GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
	}
	original, err := transaction.MakePaymentTxn(sender, receiver, 1000, nil, "", sp)
	if err != nil {
		t.Fatal(err)
	}
	plannedOriginal := original
	plannedOriginal.Fee += 1000
	plannedOriginal.Group = types.Digest{0x44}
	dummies, err := createGuardedDummies(original, 1)
	if err != nil {
		t.Fatal(err)
	}
	dummies[0].Group = plannedOriginal.Group
	planned := []types.Transaction{plannedOriginal, dummies[0]}
	mutations := &MutationReport{
		DummiesAdded: 1, GroupIDChanged: true, FeesModified: []int{0},
		TotalFeesDelta: 1000, OriginalCount: 1, FinalCount: 2,
	}

	if err := validateBoundedComponentPlan([]types.Transaction{original}, planned, mutations); err != nil {
		t.Fatalf("valid plan: unexpected error %v", err)
	}

	t.Run("unreported original mutation", func(t *testing.T) {
		badPlanned := append([]types.Transaction(nil), planned...)
		badPlanned[0].Receiver, err = types.DecodeAddress(sdkTestAddress(33))
		if err != nil {
			t.Fatal(err)
		}
		if err := validateBoundedComponentPlan([]types.Transaction{original}, badPlanned, mutations); err == nil ||
			!strings.Contains(err.Error(), "unreported fields") {
			t.Fatalf("error = %v, want original mutation rejection", err)
		}
	})
	t.Run("wrong mutation counts", func(t *testing.T) {
		bad := *mutations
		bad.DummiesAdded = 0
		if err := validateBoundedComponentPlan([]types.Transaction{original}, planned, &bad); err == nil ||
			!strings.Contains(err.Error(), "dummies_added") {
			t.Fatalf("error = %v, want dummy count rejection", err)
		}
	})
	t.Run("non-dummy appended transaction", func(t *testing.T) {
		badPlanned := append([]types.Transaction(nil), planned...)
		badPlanned[1].Amount = 1
		if err := validateBoundedComponentPlan([]types.Transaction{original}, badPlanned, mutations); err == nil ||
			!strings.Contains(err.Error(), "canonical guarded budget dummy") {
			t.Fatalf("error = %v, want dummy-shape rejection", err)
		}
		if _, err := signGuardedDummies(badPlanned[1:], 1); err == nil ||
			!strings.Contains(err.Error(), "canonical guarded budget dummy") {
			t.Fatalf("signGuardedDummies() error = %v, want dummy-shape rejection", err)
		}
	})
}
