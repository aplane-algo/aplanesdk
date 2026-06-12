// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestSignGuardedGroupOneTarget(t *testing.T) {
	userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sign/component":
			var req ComponentSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode user component request: %v", err)
			}
			if req.Role != ComponentSignRoleUser || req.ComponentKey != "GUARDED" {
				t.Fatalf("user component request = %+v", req)
			}
			json.NewEncoder(w).Encode(ComponentSignResponse{
				RequestID: req.RequestID,
				Signatures: []ComponentSignature{{
					TargetIndex:     0,
					Signature:       "user-sig",
					SignatureScheme: KeyTypeSentryEd25519,
				}},
			})
		case "/sign/assemble":
			var req GuardedAssemblyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode assembly request: %v", err)
			}
			if len(req.Targets) != 1 || req.Targets[0].UserSignature != "user-sig" || req.Targets[0].SentrySignature != "sentry-sig" {
				t.Fatalf("assembly targets = %+v", req.Targets)
			}
			json.NewEncoder(w).Encode(GuardedAssemblyResponse{
				RequestID:   req.RequestID,
				SignedGroup: []string{"signed-guarded"},
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
		if req.Role != ComponentSignRoleSentry || req.ComponentKey != "SENTRY_COMPONENT" {
			t.Fatalf("sentry component request = %+v", req)
		}
		json.NewEncoder(w).Encode(ComponentSignResponse{
			RequestID: req.RequestID,
			Signatures: []ComponentSignature{{
				TargetIndex:     0,
				Signature:       "sentry-sig",
				SignatureScheme: KeyTypeSentryEd25519,
			}},
		})
	})
	defer sentryServer.Close()

	result, err := SignGuardedGroup(GuardedSignOptions{
		UserClient:         userClient,
		SentryClient:       sentryClient,
		SentryComponentKey: "SENTRY_COMPONENT",
		GroupBytesHex:      []string{"5458aa"},
		Targets: []GuardedSignTarget{{
			TargetIndex:    0,
			GuardedAccount: "GUARDED",
		}},
	})
	if err != nil {
		t.Fatalf("SignGuardedGroup() error = %v", err)
	}
	if len(result.SignedGroup) != 1 || result.SignedGroup[0] != "signed-guarded" {
		t.Fatalf("signed group = %+v", result.SignedGroup)
	}
}

func TestSignGuardedGroupBatchesSharedSentryKey(t *testing.T) {
	userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sign/component":
			var req ComponentSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode user component request: %v", err)
			}
			if len(req.TargetIndices) != 2 {
				t.Fatalf("user target indices = %+v", req.TargetIndices)
			}
			json.NewEncoder(w).Encode(ComponentSignResponse{
				RequestID: req.RequestID,
				Signatures: []ComponentSignature{
					{TargetIndex: 0, Signature: "user-0", SignatureScheme: KeyTypeSentryEd25519},
					{TargetIndex: 1, Signature: "user-1", SignatureScheme: KeyTypeSentryEd25519},
				},
			})
		case "/sign/assemble":
			json.NewEncoder(w).Encode(GuardedAssemblyResponse{
				RequestID:   "assembly",
				SignedGroup: []string{"signed-0", "signed-1"},
			})
		default:
			t.Fatalf("unexpected user path %s", r.URL.Path)
		}
	})
	defer userServer.Close()

	sentryCalls := 0
	sentryClient, sentryServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		sentryCalls++
		var req ComponentSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode sentry component request: %v", err)
		}
		if len(req.TargetIndices) != 2 {
			t.Fatalf("sentry target indices = %+v", req.TargetIndices)
		}
		json.NewEncoder(w).Encode(ComponentSignResponse{
			RequestID: req.RequestID,
			Signatures: []ComponentSignature{
				{TargetIndex: 0, Signature: "sentry-0", SignatureScheme: KeyTypeSentryEd25519},
				{TargetIndex: 1, Signature: "sentry-1", SignatureScheme: KeyTypeSentryEd25519},
			},
		})
	})
	defer sentryServer.Close()

	_, err := SignGuardedGroup(GuardedSignOptions{
		UserClient:         userClient,
		SentryClient:       sentryClient,
		SentryComponentKey: "SENTRY_COMPONENT",
		GroupBytesHex:      []string{"5458aa", "5458bb"},
		Targets: []GuardedSignTarget{
			{TargetIndex: 0, GuardedAccount: "GUARDED"},
			{TargetIndex: 1, GuardedAccount: "GUARDED"},
		},
	})
	if err != nil {
		t.Fatalf("SignGuardedGroup() error = %v", err)
	}
	if sentryCalls != 1 {
		t.Fatalf("sentry component calls = %d, want 1", sentryCalls)
	}
}

func TestSignGuardedGroupMixedPrimaryAndGuarded(t *testing.T) {
	userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				IdentityID:          "default",
				State:               "unlocked",
				ReadyForSigning:     true,
				KeysetRevision:      1,
				ApprovalWaitSeconds: 60,
			})
		case "/sign":
			var req GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode primary sign request: %v", err)
			}
			if len(req.Requests) != 2 || req.Requests[0].AuthAddress != "AUTH" || req.Requests[1].AuthAddress != "" {
				t.Fatalf("primary sign requests = %+v", req.Requests)
			}
			json.NewEncoder(w).Encode(GroupSignResponse{Signed: []string{"primary-signed", ""}})
		case "/sign/component":
			var req ComponentSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode user component request: %v", err)
			}
			json.NewEncoder(w).Encode(ComponentSignResponse{
				RequestID: req.RequestID,
				Signatures: []ComponentSignature{{
					TargetIndex:     1,
					Signature:       "user-sig",
					SignatureScheme: KeyTypeSentryEd25519,
				}},
			})
		case "/sign/assemble":
			var req GuardedAssemblyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode assembly request: %v", err)
			}
			if len(req.Passthrough) != 1 || req.Passthrough[0].TargetIndex != 0 || req.Passthrough[0].SignedTxnHex != "primary-signed" {
				t.Fatalf("assembly passthrough = %+v", req.Passthrough)
			}
			json.NewEncoder(w).Encode(GuardedAssemblyResponse{
				RequestID:   req.RequestID,
				SignedGroup: []string{"primary-signed", "guarded-signed"},
			})
		default:
			t.Fatalf("unexpected user path %s", r.URL.Path)
		}
	})
	defer userServer.Close()

	sentryClient, sentryServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		var req ComponentSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode sentry component request: %v", err)
		}
		json.NewEncoder(w).Encode(ComponentSignResponse{
			RequestID: req.RequestID,
			Signatures: []ComponentSignature{{
				TargetIndex:     1,
				Signature:       "sentry-sig",
				SignatureScheme: KeyTypeSentryEd25519,
			}},
		})
	})
	defer sentryServer.Close()

	result, err := SignGuardedGroup(GuardedSignOptions{
		UserClient:         userClient,
		SentryClient:       sentryClient,
		SentryComponentKey: "SENTRY_COMPONENT",
		GroupBytesHex:      []string{"5458aa", "5458bb"},
		PrimaryTargets: []GuardedPrimarySignTarget{{
			TargetIndex: 0,
			AuthAddress: "AUTH",
		}},
		Targets: []GuardedSignTarget{{
			TargetIndex:    1,
			GuardedAccount: "GUARDED",
		}},
	})
	if err != nil {
		t.Fatalf("SignGuardedGroup() error = %v", err)
	}
	if len(result.SignedGroup) != 2 || result.SignedGroup[1] != "guarded-signed" {
		t.Fatalf("signed group = %+v", result.SignedGroup)
	}
	if result.PrimarySignResponse == nil {
		t.Fatal("expected primary sign response")
	}
}

func TestSignPreparedGuardedGroupAllGuardedAddsDummiesWithoutPlanOrSign(t *testing.T) {
	guarded := sdkTestAddress(1)
	receiver := sdkTestAddress(2)

	userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sign/component":
			var req ComponentSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode user component request: %v", err)
			}
			if req.Role != ComponentSignRoleUser || req.ComponentKey != guarded {
				t.Fatalf("user component request = %+v", req)
			}
			if len(req.GroupBytesHex) != 4 || len(req.TargetIndices) != 1 || req.TargetIndices[0] != 0 {
				t.Fatalf("user component group/targets = len %d targets %+v", len(req.GroupBytesHex), req.TargetIndices)
			}
			json.NewEncoder(w).Encode(ComponentSignResponse{
				RequestID: req.RequestID,
				Signatures: []ComponentSignature{{
					TargetIndex:     0,
					Signature:       "user-sig",
					SignatureScheme: KeyTypeSentryEd25519,
				}},
			})
		case "/sign/assemble":
			var req GuardedAssemblyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode assembly request: %v", err)
			}
			if len(req.GroupBytesHex) != 4 {
				t.Fatalf("assembly group length = %d, want 4", len(req.GroupBytesHex))
			}
			if len(req.Passthrough) != 3 {
				t.Fatalf("assembly passthrough = %+v, want 3 dummy entries", req.Passthrough)
			}
			for i, item := range req.Passthrough {
				if item.TargetIndex != i+1 || item.SignedTxnHex == "" {
					t.Fatalf("dummy passthrough %d = %+v", i, item)
				}
			}
			json.NewEncoder(w).Encode(GuardedAssemblyResponse{
				RequestID:   req.RequestID,
				SignedGroup: []string{"guarded-signed", "dummy-1", "dummy-2", "dummy-3"},
			})
		case "/plan", "/sign":
			t.Fatalf("prepared all-guarded path must not call %s", r.URL.Path)
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
		if req.Role != ComponentSignRoleSentry || len(req.GroupBytesHex) != 4 || len(req.TargetIndices) != 1 || req.TargetIndices[0] != 0 {
			t.Fatalf("sentry component request = %+v", req)
		}
		json.NewEncoder(w).Encode(ComponentSignResponse{
			RequestID: req.RequestID,
			Signatures: []ComponentSignature{{
				TargetIndex:     0,
				Signature:       "sentry-sig",
				SignatureScheme: KeyTypeSentryEd25519,
			}},
		})
	})
	defer sentryServer.Close()

	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		FirstRoundValid: 1,
		LastRoundValid:  100,
		GenesisID:       "testnet-v1.0",
		GenesisHash:     genesisHash[:],
		FlatFee:         true,
	}
	txn, err := transaction.MakePaymentTxn(guarded, receiver, 1000, nil, "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}

	result, err := SignPreparedGuardedGroup(PreparedGuardedGroupOptions{
		UserClient:         userClient,
		SentryClient:       sentryClient,
		SentryComponentKey: "SENTRY_COMPONENT",
		PreparedGroup: NewPreparedGroup(PreparedTransaction{
			Transaction: &txn,
			AuthAddress: guarded,
			SignerKey: &KeyInfo{
				Address:                guarded,
				KeyType:                KeyTypeGuardedFalcon1024SentryEd25519,
				SigningFlow:            SigningFlowSentry1,
				SentryComponentKeyType: KeyTypeSentryEd25519,
				LsigSize:               3035,
				Parameters:             map[string]string{"sentry_public_key": "aabbcc"},
			},
		}),
	})
	if err != nil {
		t.Fatalf("SignPreparedGuardedGroup() error = %v", err)
	}
	if len(result.SignedGroup) != 4 || result.PrimarySignResponse != nil {
		t.Fatalf("result = %+v", result)
	}
}

func TestSignPreparedGuardedGroupRejectsUnsupportedSigningFlow(t *testing.T) {
	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		FirstRoundValid: 1,
		LastRoundValid:  100,
		GenesisID:       "testnet-v1.0",
		GenesisHash:     genesisHash[:],
		FlatFee:         true,
	}
	guarded := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	txn, err := transaction.MakePaymentTxn(guarded, receiver, 1000, nil, "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}

	_, err = SignPreparedGuardedGroup(PreparedGuardedGroupOptions{
		UserClient: &SignerClient{},
		PreparedGroup: NewPreparedGroup(PreparedTransaction{
			Transaction: &txn,
			AuthAddress: guarded,
			SignerKey: &KeyInfo{
				Address:     guarded,
				KeyType:     "aplane.future-guarded.v1",
				SigningFlow: "sentry2",
				LsigSize:    3035,
			},
		}),
	})
	if err == nil || !strings.Contains(err.Error(), `signing flow "sentry2"`) {
		t.Fatalf("SignPreparedGuardedGroup() error = %v, want unsupported signing flow rejection", err)
	}
}
