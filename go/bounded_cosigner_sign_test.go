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
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/algorand/go-codec/codec"
)

type sdkNoncanonicalMap []interface{}

func (sdkNoncanonicalMap) MapBySlice() {}

func TestSignPreparedCosignedGroupOneTarget(t *testing.T) {
	bounded := sdkTestAddress(21)
	receiver := sdkTestAddress(22)
	var frozenGroup []string
	componentCalls := 0

	userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				State: "unlocked", ApprovalWaitSeconds: 60,
			})
		case "/plan":
			var req GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode plan request: %v", err)
			}
			frozenGroup = []string{req.Requests[0].TxnBytesHex}
			json.NewEncoder(w).Encode(PlanGroupResponse{Transactions: frozenGroup})
		case "/sign/component":
			componentCalls++
			var req ComponentRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode bounded component request: %v", err)
			}
			if len(req.Targets) != 1 || req.Targets[0].AuthAddress != bounded {
				t.Fatalf("bounded component request = %+v", req)
			}
			json.NewEncoder(w).Encode(ComponentResponse{
				RequestID: req.RequestID,
				Components: []Component{{
					TargetIndex:     0,
					Kind:            ComponentTargetKindBoundedBase,
					AuthAddress:     bounded,
					BaseSignatures:  []string{"base-sig"},
					RuntimeArgs:     map[string]string{"proof": "aabb"},
					AssemblyReceipt: "receipt",
					SignatureScheme: "aplane.falcon1024.v1",
					Path:            ComponentPathSpend,
				}},
			})
		case "/sign/assemble":
			var req AssemblyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode bounded assembly request: %v", err)
			}
			if len(req.Targets) != 1 || req.Targets[0].AssemblyReceipt != "receipt" ||
				req.Targets[0].CosignerSignature != "cosigner-sig" {
				t.Fatalf("bounded assembly targets = %+v", req.Targets)
			}
			json.NewEncoder(w).Encode(AssemblyResponse{
				RequestID: req.RequestID, SignedGroup: signedGroupFor(t, req.GroupBytesHex),
			})
		default:
			t.Fatalf("unexpected user path %s", r.URL.Path)
		}
	})
	defer userServer.Close()

	cosignerClient, cosignerServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign/component" {
			t.Fatalf("unexpected cosigner path %s", r.URL.Path)
		}
		var req capturedComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode cosigner component request: %v", err)
		}
		if req.Role != capturedComponentRoleCosigner || req.ComponentKey != "COSIGNER_COMPONENT" ||
			len(req.GroupBytesHex) != 1 || req.GroupBytesHex[0] != frozenGroup[0] {
			t.Fatalf("cosigner component request = %+v", req)
		}
		if req.TargetAppInfo[0] == nil || req.TargetAppInfo[0].Mode != "raw" {
			t.Fatalf("cosigner target app-call metadata = %#v", req.TargetAppInfo[0])
		}
		json.NewEncoder(w).Encode(ComponentResponse{
			RequestID: req.RequestID,
			Components: []Component{{Kind: ComponentTargetKindCosigner,
				TargetIndex: 0, Signature: "cosigner-sig", SignatureScheme: KeyTypeWitnessFalcon1024,
			}},
		})
	})
	defer cosignerServer.Close()

	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee: types.MicroAlgos(1000), FirstRoundValid: 1, LastRoundValid: 100,
		GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
	}
	txn, err := transaction.MakePaymentTxn(bounded, receiver, 1000, nil, "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}
	options := PreparedCosignedGroupOptions{
		UserClient: userClient, CosignerClient: cosignerClient,
		CosignerComponentKey: "COSIGNER_COMPONENT",
		PreparedGroup: NewPreparedGroup(PreparedTransaction{
			Transaction: &txn, AuthAddress: bounded,
			AppCallInfo: &AppCallInfo{Mode: "raw"},
			SignerKey: &KeyInfo{
				Address: bounded, KeyType: "aplane.falcon1024.v1",
				SigningFlow: SigningFlowCosigned1,
				LogicSigResources: &LogicSigResourceProfile{
					Spend: &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 3358, MaxOpcodeCost: 20000},
				},
				CosignerComponentKeyType: KeyTypeWitnessFalcon1024,
				BoundedAuthorization: &BoundedAuthorizationInfo{
					Contract: BoundedContractBounded2, MaxFee: new(uint64(1000)),
					Cosigner: &BoundedCosignerAuthorizationInfo{
						ComponentKeyType: KeyTypeWitnessFalcon1024, PublicKeyHex: "aabb",
					},
				},
			},
		}),
	}
	result, err := SignPreparedCosignedGroup(options)
	if err != nil {
		t.Fatalf("SignPreparedCosignedGroup() error = %v", err)
	}
	if len(result.SignedGroup) != 1 || result.BoundedComponentResponse == nil ||
		result.BoundedAssemblyResponse == nil {
		t.Fatalf("result = %+v", result)
	}
	componentCalls = 0
	options.PreparedGroup.Transactions[0].SignerKey.BoundedAuthorization.MaxFee = new(uint64(999))
	if _, err := SignPreparedCosignedGroup(options); err == nil ||
		!strings.Contains(err.Error(), "exceeds advertised max_fee") {
		t.Fatalf("SignPreparedCosignedGroup() error = %v, want max_fee rejection", err)
	}
	if componentCalls != 0 {
		t.Fatalf("component calls = %d, want none before max_fee rejection", componentCalls)
	}
}

// A listed rekey on a cosigned account takes no cosigner component: the base
// component names the listed path, the SDK asks the cosigner nothing, and the
// assembly target carries no cosigner signature. The position is budgeted on
// the listed path's resources.
func TestSignPreparedCosignedGroupSkipsTheCosignerOnAListedRekey(t *testing.T) {
	bounded := sdkTestAddress(23)
	target := sdkTestAddress(24)
	userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{State: "unlocked", ApprovalWaitSeconds: 60})
		case "/plan":
			var req GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode plan request: %v", err)
			}
			json.NewEncoder(w).Encode(PlanGroupResponse{Transactions: []string{req.Requests[0].TxnBytesHex}})
		case "/sign/component":
			var req ComponentRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode bounded component request: %v", err)
			}
			json.NewEncoder(w).Encode(ComponentResponse{
				RequestID: req.RequestID,
				Components: []Component{{
					TargetIndex: 0, Kind: ComponentTargetKindBoundedBase, AuthAddress: bounded,
					BaseSignatures: []string{"base-sig"}, AssemblyReceipt: "receipt",
					SignatureScheme: "aplane.falcon1024.v1", Path: ComponentPathListedRekey,
				}},
			})
		case "/sign/assemble":
			var req AssemblyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode bounded assembly request: %v", err)
			}
			if len(req.Targets) != 1 || req.Targets[0].CosignerSignature != "" || req.Targets[0].CosignerSourceRequestID != "" {
				t.Fatalf("listed rekey assembly targets = %+v, want no cosigner material", req.Targets)
			}
			json.NewEncoder(w).Encode(AssemblyResponse{RequestID: req.RequestID, SignedGroup: signedGroupFor(t, req.GroupBytesHex)})
		default:
			t.Fatalf("unexpected user path %s", r.URL.Path)
		}
	})
	defer userServer.Close()
	cosignerClient, cosignerServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("the cosigner was asked about a listed rekey: %s", r.URL.Path)
	})
	defer cosignerServer.Close()

	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee: types.MicroAlgos(1000), FirstRoundValid: 1, LastRoundValid: 100,
		GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
	}
	txn, err := transaction.MakePaymentTxn(bounded, bounded, 0, nil, "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}
	txn.RekeyTo, err = types.DecodeAddress(target)
	if err != nil {
		t.Fatal(err)
	}
	key := &KeyInfo{
		Address: bounded, KeyType: "aplane.falcon1024.v1", SigningFlow: SigningFlowCosigned1,
		LogicSigResources: &LogicSigResourceProfile{
			Spend:         &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 3358, MaxOpcodeCost: 20000},
			SpendingRekey: &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 2846, MaxOpcodeCost: 20000},
			ListedRekey:   &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 1583, MaxOpcodeCost: 20000},
		},
		CosignerComponentKeyType: KeyTypeWitnessFalcon1024,
		BoundedAuthorization: &BoundedAuthorizationInfo{
			Contract: BoundedContractBounded2, MaxFee: new(uint64(1000)), Rekey: "spending_key",
			RekeyList: &BoundedRekeyListInfo{Contract: "rekey_list1", Depth: 4},
			Cosigner:  &BoundedCosignerAuthorizationInfo{ComponentKeyType: KeyTypeWitnessFalcon1024, PublicKeyHex: "aabb"},
		},
	}
	result, err := SignPreparedCosignedGroup(PreparedCosignedGroupOptions{
		UserClient: userClient, CosignerClient: cosignerClient, CosignerComponentKey: "COSIGNER_COMPONENT",
		PreparedGroup: NewPreparedGroup(PreparedTransaction{Transaction: &txn, AuthAddress: bounded, SignerKey: key}),
	})
	if err != nil {
		t.Fatalf("SignPreparedCosignedGroup() error = %v", err)
	}
	if len(result.SignedGroup) != 1 || len(result.CosignerComponentResponses) != 0 {
		t.Fatalf("result = %+v, want a signed group and no cosigner response", result)
	}
	resources, err := componentPathResources(key, ComponentPathListedRekey)
	if err != nil || resources.ArgumentBytes != 1583 {
		t.Fatalf("listed rekey resources = %+v, %v", resources, err)
	}
	if _, err := componentPathResources(key, "admin_rekey"); err == nil {
		t.Fatal("an unknown path selected resources")
	}
}

// A non-cosigned position the signer holds is sent as the signer's own: in
// sign mode on /plan, and as a contextual position with auth_address on
// /sign/component. The signer sizes it and can charge it; no hint is sent.
// Here the plan puts the group's authorization charge on the held primary,
// which the SDK must accept and sign.
func TestSignPreparedCosignedGroupSendsAHeldPrimaryAsTheSignersOwn(t *testing.T) {
	for _, rejectSign := range []bool{false, true} {
		t.Run(fmt.Sprintf("rejectSign=%v", rejectSign), func(t *testing.T) {
			var eventsMu sync.Mutex
			var events []string
			record := func(event string) {
				eventsMu.Lock()
				defer eventsMu.Unlock()
				events = append(events, event)
			}
			eventSnapshot := func() string {
				eventsMu.Lock()
				defer eventsMu.Unlock()
				return strings.Join(events, ",")
			}
			bounded := sdkTestAddress(51)
			nativePQ := fakePQAccount(t, 52)
			receiver := sdkTestAddress(53)
			var frozenGroup []string
			var primaryRequest SignRequest

			userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/status":
					json.NewEncoder(w).Encode(StatusResponse{
						State: "unlocked", ApprovalWaitSeconds: 60,
					})
				case "/plan":
					var req GroupSignRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Fatalf("decode plan request: %v", err)
					}
					primaryRequest = req.Requests[1]
					planned := make([]types.Transaction, 2)
					for i := range planned {
						raw, err := hex.DecodeString(req.Requests[i].TxnBytesHex)
						if err != nil {
							t.Fatalf("decode planned transaction: %v", err)
						}
						if planned[i], err = decodeCanonicalTxn(raw); err != nil {
							t.Fatalf("decode planned transaction: %v", err)
						}
					}
					// The bounded target stays at its 1000 fee ceiling; the
					// held primary carries the charge.
					planned[1].Fee += 2000
					planned[0].Group, planned[1].Group = types.Digest{}, types.Digest{}
					groupID, err := algocrypto.ComputeGroupID(planned)
					if err != nil {
						t.Fatalf("ComputeGroupID() error = %v", err)
					}
					planned[0].Group, planned[1].Group = groupID, groupID
					frozenGroup = []string{hex.EncodeToString(encodeTxn(planned[0])), hex.EncodeToString(encodeTxn(planned[1]))}
					json.NewEncoder(w).Encode(PlanGroupResponse{
						Transactions: frozenGroup,
						Mutations: &MutationReport{
							GroupIDChanged: true, FeesModified: []int{1}, TotalFeesDelta: 2000,
							OriginalCount: 2, FinalCount: 2,
						},
					})
				case "/sign/component":
					record("base")
					var req ComponentRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Fatalf("decode bounded component request: %v", err)
					}
					if len(req.Targets) != 1 || len(req.ContextualPositions) != 1 {
						t.Fatalf("bounded component partition = %+v", req)
					}
					if got := strings.Join(req.GroupBytesHex, ","); got != strings.Join(frozenGroup, ",") {
						t.Fatalf("component group = %s, want the planned group with the primary's charge", got)
					}
					if position := req.ContextualPositions[0]; position.AuthAddress != nativePQ || position.PQScheme != "" || position.LsigResources != nil {
						t.Fatalf("contextual position = %+v, want auth_address %s and no hint", position, nativePQ)
					}
					json.NewEncoder(w).Encode(ComponentResponse{
						RequestID: req.RequestID,
						Components: []Component{{
							TargetIndex:     0,
							Kind:            ComponentTargetKindBoundedBase,
							AuthAddress:     bounded,
							BaseSignatures:  []string{"base-sig"},
							AssemblyReceipt: "receipt",
							SignatureScheme: "aplane.falcon1024.v1",
							Path:            ComponentPathSpend,
						}},
					})
				case "/sign":
					record("sign")
					if rejectSign {
						writeCodedError(w, http.StatusForbidden, ErrCodeForbidden, "rejected by signer policy")
						return
					}
					var req GroupSignRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Fatalf("decode primary sign request: %v", err)
					}
					json.NewEncoder(w).Encode(fakeSigner{}.sign(t, req.Requests))
				case "/sign/assemble":
					record("assemble")
					var req AssemblyRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Fatalf("decode bounded assembly request: %v", err)
					}
					json.NewEncoder(w).Encode(AssemblyResponse{
						RequestID: req.RequestID, SignedGroup: signedGroupFor(t, req.GroupBytesHex),
					})
				default:
					t.Fatalf("unexpected user path %s", r.URL.Path)
				}
			})
			defer userServer.Close()

			cosignerClient, cosignerServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				record("cosigner")
				var req capturedComponentRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatalf("decode cosigner component request: %v", err)
				}
				json.NewEncoder(w).Encode(ComponentResponse{
					RequestID: req.RequestID,
					Components: []Component{{Kind: ComponentTargetKindCosigner,
						TargetIndex: 0, Signature: "cosigner-sig", SignatureScheme: KeyTypeWitnessFalcon1024,
					}},
				})
			})
			defer cosignerServer.Close()

			var genesisHash types.Digest
			sp := types.SuggestedParams{
				Fee: types.MicroAlgos(1000), FirstRoundValid: 1, LastRoundValid: 100,
				GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
			}
			corridorTxn, err := transaction.MakePaymentTxn(bounded, receiver, 1000, nil, "", sp)
			if err != nil {
				t.Fatalf("MakePaymentTxn() error = %v", err)
			}
			nativeTxn, err := transaction.MakePaymentTxn(nativePQ, receiver, 2000, nil, "", sp)
			if err != nil {
				t.Fatalf("MakePaymentTxn() error = %v", err)
			}
			// The group is sent ungrouped: the signer raises no fee on a group
			// that already carries an ID.

			result, err := SignPreparedCosignedGroup(PreparedCosignedGroupOptions{
				UserClient: userClient, CosignerClient: cosignerClient,
				CosignerComponentKey: "COSIGNER_COMPONENT",
				PreparedGroup: NewPreparedGroup(
					PreparedTransaction{
						Transaction: &corridorTxn, AuthAddress: bounded,
						SignerKey: &KeyInfo{
							Address: bounded, KeyType: "aplane.falcon1024.v1",
							AuthorizationKind: AuthorizationKindLogicSig,
							SigningFlow:       SigningFlowCosigned1,
							LogicSigResources: &LogicSigResourceProfile{
								Spend: &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 3358, MaxOpcodeCost: 20000},
							},
							CosignerComponentKeyType: KeyTypeWitnessFalcon1024,
							BoundedAuthorization: &BoundedAuthorizationInfo{
								Contract: BoundedContractBounded2, MaxFee: new(uint64(1000)),
								Cosigner: &BoundedCosignerAuthorizationInfo{
									ComponentKeyType: KeyTypeWitnessFalcon1024, PublicKeyHex: "aabb",
								},
							},
						},
					},
					PreparedTransaction{
						Transaction: &nativeTxn, AuthAddress: nativePQ,
						SignerKey: &KeyInfo{
							Address: nativePQ, KeyType: "falcon1024",
							AuthorizationKind: AuthorizationKindNativePQ,
						},
					},
				),
			})
			if rejectSign {
				if err == nil {
					t.Fatal("expected the /sign rejection to fail the group")
				}
				if got := eventSnapshot(); got != "base,sign" {
					t.Fatalf("calls = %s, want %s (cosigner must not see a group the user side rejected)", got, "base,sign")
				}
				return
			}
			if err != nil {
				t.Fatalf("SignPreparedCosignedGroup() error = %v", err)
			}
			if got := eventSnapshot(); got != "base,sign,cosigner,assemble" {
				t.Fatalf("calls = %s, want %s", got, "base,sign,cosigner,assemble")
			}
			// The result carries what the plan added, so the caller can read
			// the fee the signer charged.
			if m := result.PlanMutations; m == nil || m.TotalFeesDelta != 2000 || len(m.FeesModified) != 1 || m.FeesModified[0] != 1 {
				t.Fatalf("PlanMutations = %+v, want the plan's 2000 raise on position 1", m)
			}

			if primaryRequest.AuthAddress != nativePQ {
				t.Fatalf("primary slot AuthAddress = %q, want %s (sign mode)", primaryRequest.AuthAddress, nativePQ)
			}
			if primaryRequest.PQScheme != "" || primaryRequest.LsigResources != nil {
				t.Fatalf("primary slot carries a size hint: %+v", primaryRequest)
			}
		})
	}
}

// The signer sizes its own position from its records, so a contextual position
// with auth_address takes no size hint. The message matches the other SDKs.
func TestComponentRequestRejectsASizeHintOnTheSignersOwnPosition(t *testing.T) {
	for name, position := range map[string]ComponentContextPosition{
		"pq_scheme":      {TargetIndex: 1, AuthAddress: "PRIMARY", PQScheme: PQSchemeFalcon1024},
		"lsig_resources": {TargetIndex: 1, AuthAddress: "PRIMARY", LsigResources: &LogicSigResourceUsage{ProgramBytes: 1, MaxOpcodeCost: 1}},
	} {
		req := ComponentRequest{
			GroupBytesHex:       []string{"5458aa", "5458bb"},
			Targets:             []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindBoundedBase, AuthAddress: "BOUNDED"}},
			ContextualPositions: []ComponentContextPosition{position},
		}
		want := "contextual position 1: lsig_resources and pq_scheme are allowed only without auth_address"
		if err := req.Validate(); err == nil || err.Error() != want {
			t.Fatalf("%s: Validate() error = %v, want %q", name, err, want)
		}
	}
}

func TestUnifiedBoundedAssemblyRejectsMissingCoverage(t *testing.T) {
	req := AssemblyRequest{
		GroupBytesHex: []string{"5458aa", "5458bb"},
		Targets: []AssemblyTarget{{
			TargetIndex: 0, Kind: AssemblyTargetKindBoundedCosigner, AuthAddress: "BOUNDED", BaseSignatures: []string{"base"},
			AssemblyReceipt: "receipt", CosignerSignature: "cosigner",
		}},
	}
	if err := req.Validate(); err == nil {
		t.Fatal("Validate() succeeded, want missing coverage error")
	}
}

func TestUnifiedAssemblyRejectsMalformedSourceRequestIDs(t *testing.T) {
	tests := []struct {
		name   string
		target AssemblyTarget
		want   string
	}{
		{name: "cosigner", target: AssemblyTarget{
			TargetIndex: 0, Kind: AssemblyTargetKindBoundedCosigner, AuthAddress: "BOUNDED",
			BaseSignatures: []string{"base"}, AssemblyReceipt: "receipt", CosignerSignature: "cosigner", CosignerSourceRequestID: "bad id",
		}, want: "cosigner_source_request_id"},
		{name: "bounded base", target: AssemblyTarget{
			TargetIndex: 0, Kind: AssemblyTargetKindBoundedCosigner, AuthAddress: "BOUNDED",
			BaseSignatures: []string{"base"}, AssemblyReceipt: "receipt", BaseSourceRequestID: "bad id", CosignerSignature: "cosigner",
		}, want: "base_source_request_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (AssemblyRequest{GroupBytesHex: []string{"5458aa"}, Targets: []AssemblyTarget{tt.target}}).Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestComponentResponseValidateForRequestRejectsOutOfGroupIndex(t *testing.T) {
	request := ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindCosigner, ComponentKey: "COSIGNER"}},
	}
	response := ComponentResponse{RequestID: "response", Components: []Component{{
		TargetIndex: 1, Kind: ComponentTargetKindCosigner, Signature: "sig", SignatureScheme: KeyTypeWitnessFalcon1024,
	}}}
	if err := response.ValidateForRequest(request); err == nil || !strings.Contains(err.Error(), "indices or kinds") {
		t.Fatalf("ValidateForRequest() error = %v, want out-of-group rejection", err)
	}
}

func TestUnifiedBoundedComponentRejectsMissingFrozenGroup(t *testing.T) {
	err := (ComponentRequest{
		RequestID: "bounded-request",
		Targets:   []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindBoundedBase, AuthAddress: "AUTH"}},
	}).Validate()
	if err == nil || !strings.Contains(err.Error(), "group_bytes_hex") {
		t.Fatalf("Validate() error = %v, want frozen group rejection", err)
	}
}

func TestUnifiedBoundedComponentResponseRejectsMalformedTargets(t *testing.T) {
	valid := Component{
		TargetIndex: 0, Kind: ComponentTargetKindBoundedBase, AuthAddress: "BOUNDED",
		BaseSignatures: []string{"base"}, AssemblyReceipt: "receipt",
		SignatureScheme: "aplane.falcon1024.v1", Path: ComponentPathSpend,
	}
	tests := []struct {
		name       string
		components []Component
		want       string
	}{
		{
			name:       "duplicate",
			components: []Component{valid, valid},
			want:       "invalid or duplicate",
		},
		{
			name: "incomplete",
			components: []Component{func() Component {
				item := valid
				item.AssemblyReceipt = ""
				return item
			}()},
			want: "invalid bounded-base material",
		},
		{
			name: "no path",
			components: []Component{func() Component {
				item := valid
				item.Path = ""
				return item
			}()},
			want: "unknown bounded path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (ComponentResponse{
				RequestID:  "bounded-response",
				Components: tt.components,
			}).Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRequestBoundedKindCancelsApprovalWhenContextCanceled(t *testing.T) {
	signStarted := make(chan string, 1)
	cancelReceived := make(chan string, 1)
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sign/component":
			var req ComponentRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode bounded component request: %v", err)
			}
			signStarted <- req.RequestID
			<-r.Context().Done()
		case "/sign/cancel":
			var req CancelSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode cancel request: %v", err)
			}
			cancelReceived <- req.RequestID
			json.NewEncoder(w).Encode(CancelSignResponse{
				Success: true, State: SignCancelStateCanceled,
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})
	defer server.Close()

	client.cacheApprovalWait(60)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.RequestComponentsWithContext(ctx, ComponentRequest{
			RequestID:     "bounded-cancel-id",
			GroupBytesHex: []string{"545801"},
			Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindBoundedBase, AuthAddress: "AUTH"}},
		})
		result <- err
	}()

	select {
	case got := <-signStarted:
		if got != "bounded-cancel-id" {
			t.Fatalf("request_id = %q, want bounded-cancel-id", got)
		}
	case <-time.After(time.Second):
		t.Fatal("bounded component request was not sent")
	}
	cancel()

	select {
	case got := <-cancelReceived:
		if got != "bounded-cancel-id" {
			t.Fatalf("cancel request_id = %q, want bounded-cancel-id", got)
		}
	case <-time.After(time.Second):
		t.Fatal("/sign/cancel was not sent")
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("RequestComponentsWithContext() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RequestComponentsWithContext() did not return")
	}
}

func TestBoundedEndpointClassifiesNotFound(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign/component" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Code: ErrCodeNotFound, Error: "key not found"})
	})
	defer server.Close()

	client.cacheApprovalWait(60)
	_, err := client.RequestComponents(ComponentRequest{
		RequestID:     "bounded-not-found",
		GroupBytesHex: []string{"545801"},
		Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindBoundedBase, AuthAddress: "AUTH"}},
	})
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("RequestComponents() error = %v, want ErrKeyNotFound", err)
	}
}

func TestDecodeCanonicalGroupAnchorsGroupID(t *testing.T) {
	sender := sdkTestAddress(71)
	receiver := sdkTestAddress(72)
	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee: types.MicroAlgos(1000), FirstRoundValid: 1, LastRoundValid: 100,
		GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
	}
	first, err := transaction.MakePaymentTxn(sender, receiver, 1, nil, "", sp)
	if err != nil {
		t.Fatal(err)
	}
	second, err := transaction.MakePaymentTxn(sender, receiver, 2, nil, "", sp)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := decodeCanonicalGroup([]string{hex.EncodeToString(encodeTxn(first))}); err != nil {
		t.Fatalf("decode singleton: %v", err)
	}

	grouped := []types.Transaction{first, second}
	groupID, err := algocrypto.ComputeGroupID(grouped)
	if err != nil {
		t.Fatal(err)
	}
	for i := range grouped {
		grouped[i].Group = groupID
	}
	valid := []string{
		hex.EncodeToString(encodeTxn(grouped[0])),
		hex.EncodeToString(encodeTxn(grouped[1])),
	}
	if _, err := decodeCanonicalGroup(valid); err != nil {
		t.Fatalf("decode valid group: %v", err)
	}

	fabricated := types.Digest{0x44}
	for i := range grouped {
		grouped[i].Group = fabricated
	}
	invalid := []string{
		hex.EncodeToString(encodeTxn(grouped[0])),
		hex.EncodeToString(encodeTxn(grouped[1])),
	}
	if _, err := decodeCanonicalGroup(invalid); err == nil ||
		!strings.Contains(err.Error(), "does not carry the canonical group ID") {
		t.Fatalf("decode fabricated group error = %v", err)
	}

	grouped[0].Group = fabricated
	if _, err := decodeCanonicalGroup([]string{
		hex.EncodeToString(encodeTxn(grouped[0])),
	}); err == nil || !strings.Contains(err.Error(), "singleton") {
		t.Fatalf("decode grouped singleton error = %v", err)
	}
}

func TestDecodeCanonicalGroupRejectsNoncanonicalBytes(t *testing.T) {
	sender := sdkTestAddress(73)
	receiver := sdkTestAddress(74)
	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee: types.MicroAlgos(1000), FirstRoundValid: 1, LastRoundValid: 100,
		GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
	}
	txn, err := transaction.MakePaymentTxn(sender, receiver, 1, nil, "", sp)
	if err != nil {
		t.Fatal(err)
	}

	canonical := msgpack.Encode(txn)
	var fields map[string]interface{}
	if err := msgpack.Decode(canonical, &fields); err != nil {
		t.Fatalf("decode canonical transaction map: %v", err)
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	reversed := make(sdkNoncanonicalMap, 0, len(keys)*2)
	for _, key := range keys {
		reversed = append(reversed, key, fields[key])
	}

	handle := &codec.MsgpackHandle{}
	handle.RecursiveEmptyCheck = true
	handle.WriteExt = true
	handle.PositiveIntUnsigned = true
	var noncanonical []byte
	codec.NewEncoderBytes(&noncanonical, handle).MustEncode(reversed)
	if string(noncanonical) == string(canonical) {
		t.Fatal("test setup produced canonical transaction bytes")
	}
	var decoded types.Transaction
	if err := msgpack.Decode(noncanonical, &decoded); err != nil {
		t.Fatalf("noncanonical transaction should remain decodable: %v", err)
	}
	raw := append([]byte{'T', 'X'}, noncanonical...)
	_, err = decodeCanonicalGroup([]string{hex.EncodeToString(raw)})
	if err == nil || !strings.Contains(err.Error(), "bytes are not canonical") {
		t.Fatalf("decode noncanonical transaction error = %v", err)
	}
}

func TestRequestBoundedPrimaryPassthroughVerifiesTransactionIdentity(t *testing.T) {
	sender := fakeAccount(41)
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
	var respond func(requests []SignRequest) GroupSignResponse

	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				State: "unlocked", ApprovalWaitSeconds: 60,
			})
		case "/sign":
			var req GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode primary sign request: %v", err)
			}
			json.NewEncoder(w).Encode(respond(req.Requests))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})
	defer server.Close()

	args := func() (*primaryCosignedPassthrough, error) {
		return requestBoundedPrimaryPassthrough(
			context.Background(),
			client,
			[]string{canonical},
			1,
			map[int]cosignedSignTarget{},
			map[int]*LogicSigResourceUsage{},
			[]cosignedPrimarySignTarget{{TargetIndex: 0, AuthAddress: sender}},
		)
	}
	respond = func(requests []SignRequest) GroupSignResponse { return fakeSigner{}.sign(t, requests) }
	if _, err := args(); err != nil {
		t.Fatalf("matching primary passthrough: %v", err)
	}
	respond = func([]SignRequest) GroupSignResponse {
		return GroupSignResponse{Signed: []string{fakeSignedTxnHex(other)}}
	}
	if _, err := args(); err == nil || !strings.Contains(err.Error(), "unreported fields at original position 1") {
		t.Fatalf("substituted primary passthrough error = %v, want identity rejection", err)
	}
	// A fee raise the signer reports is acceptable on an ordinary /sign, but
	// not here: the group was frozen by /plan.
	respond = func(requests []SignRequest) GroupSignResponse {
		return fakeSigner{feeRaise: map[int]uint64{0: 1000}}.sign(t, requests)
	}
	if _, err := args(); err == nil || !strings.Contains(err.Error(), "does not match the submitted canonical bytes") {
		t.Fatalf("mutated frozen primary passthrough error = %v, want identity rejection", err)
	}
}

func TestValidateBoundedTargetFees(t *testing.T) {
	planned := []types.Transaction{{Header: types.Header{Fee: 2000}}}
	if err := validateBoundedTargetFees(planned, map[int]uint64{0: 2000}); err != nil {
		t.Fatalf("fee at the ceiling: unexpected error %v", err)
	}
	if err := validateBoundedTargetFees(planned, map[int]uint64{0: 1999}); err == nil ||
		!strings.Contains(err.Error(), "exceeds advertised max_fee") {
		t.Fatalf("error = %v, want max_fee rejection", err)
	}
}

// A plain host has no fee ceiling; a bounded host must advertise one; a contract
// this SDK doesn't know fails closed.
func TestBoundedFeeCeilingFollowsTheContract(t *testing.T) {
	for _, tc := range []struct {
		name    string
		info    BoundedAuthorizationInfo
		ceiling uint64
		has     bool
		err     string
	}{
		{"bounded host", BoundedAuthorizationInfo{Contract: BoundedContractBounded2, MaxFee: new(uint64(10_000))}, 10_000, true, ""},
		{"bounded host without a ceiling", BoundedAuthorizationInfo{Contract: BoundedContractBounded2}, 0, false, "has no max_fee"},
		{"plain host", BoundedAuthorizationInfo{Contract: BoundedContractPlain1}, 0, false, ""},
		{"plain host with a ceiling", BoundedAuthorizationInfo{Contract: BoundedContractPlain1, MaxFee: new(uint64(0))}, 0, false, "never has"},
		{"unknown contract", BoundedAuthorizationInfo{Contract: "bounded3", MaxFee: new(uint64(1))}, 0, false, "not supported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ceiling, has, err := boundedFeeCeiling(&tc.info)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("boundedFeeCeiling() error = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil || ceiling != tc.ceiling || has != tc.has {
				t.Fatalf("boundedFeeCeiling() = %d, %v, %v", ceiling, has, err)
			}
		})
	}
}

// A mixed group: a listed rekey (index 0), two spends that need the same
// cosigner key (1 and 2), and an ordinary primary slot (3). The cosigner gets
// one request for the two spends, with every other original position as
// context and its app call description; the primary /sign declares each
// cosigned position on the path its base component named; assembly carries a
// cosigner signature only where the path needs one. A cosigner signature in
// a scheme other than the account's cosigner key type is refused.
func TestSignPreparedCosignedGroupMixedPaths(t *testing.T) {
	for _, wrongScheme := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrongScheme=%v", wrongScheme), func(t *testing.T) {
			listed := sdkTestAddress(61)
			spendA := sdkTestAddress(62)
			spendB := sdkTestAddress(63)
			primary := fakeAccount(64)
			receiver := sdkTestAddress(65)
			rekeyTarget := sdkTestAddress(66)
			appInfo := map[int]*AppCallInfo{0: {Mode: "listed"}, 3: {Mode: "primary"}}
			var frozenGroup []string
			var primarySign GroupSignRequest
			var assembly AssemblyRequest
			var cosignerRequests []capturedComponentRequest

			userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/status":
					json.NewEncoder(w).Encode(StatusResponse{State: "unlocked", ApprovalWaitSeconds: 60})
				case "/plan":
					var req GroupSignRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Fatalf("decode plan request: %v", err)
					}
					frozenGroup = nil
					for _, item := range req.Requests {
						frozenGroup = append(frozenGroup, item.TxnBytesHex)
					}
					json.NewEncoder(w).Encode(PlanGroupResponse{Transactions: frozenGroup})
				case "/sign/component":
					var req ComponentRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Fatalf("decode bounded component request: %v", err)
					}
					if len(req.Targets) != 3 || len(req.ContextualPositions) != 1 || req.ContextualPositions[0].TargetIndex != 3 {
						t.Fatalf("bounded component partition = %+v", req)
					}
					// The user signer's approval shows the primary slot's app call.
					if info := req.ContextualPositions[0].AppCallInfo; info == nil || info.Mode != "primary" {
						t.Fatalf("bounded component contextual app call info = %+v, want the primary slot's", info)
					}
					base := func(index int, account, path string) Component {
						return Component{
							TargetIndex: index, Kind: ComponentTargetKindBoundedBase, AuthAddress: account,
							BaseSignatures: []string{"base-sig"}, AssemblyReceipt: "receipt",
							SignatureScheme: "aplane.falcon1024.v1", Path: path,
						}
					}
					json.NewEncoder(w).Encode(ComponentResponse{
						RequestID: req.RequestID,
						Components: []Component{
							base(0, listed, ComponentPathListedRekey),
							base(1, spendA, ComponentPathSpend),
							base(2, spendB, ComponentPathSpend),
						},
					})
				case "/sign":
					if err := json.NewDecoder(r.Body).Decode(&primarySign); err != nil {
						t.Fatalf("decode primary sign request: %v", err)
					}
					json.NewEncoder(w).Encode(fakeSigner{}.sign(t, primarySign.Requests))
				case "/sign/assemble":
					if err := json.NewDecoder(r.Body).Decode(&assembly); err != nil {
						t.Fatalf("decode bounded assembly request: %v", err)
					}
					json.NewEncoder(w).Encode(AssemblyResponse{RequestID: assembly.RequestID, SignedGroup: signedGroupFor(t, assembly.GroupBytesHex)})
				default:
					t.Fatalf("unexpected user path %s", r.URL.Path)
				}
			})
			defer userServer.Close()
			cosignerClient, cosignerServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				var req capturedComponentRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatalf("decode cosigner component request: %v", err)
				}
				cosignerRequests = append(cosignerRequests, req)
				scheme := KeyTypeWitnessFalcon1024
				if wrongScheme {
					scheme = "aplane.falcon1024.v1"
				}
				var components []Component
				for _, index := range req.TargetIndices {
					components = append(components, Component{
						TargetIndex: index, Kind: ComponentTargetKindCosigner,
						Signature: fmt.Sprintf("cosigner-sig-%d", index), SignatureScheme: scheme,
					})
				}
				json.NewEncoder(w).Encode(ComponentResponse{RequestID: req.RequestID, Components: components})
			})
			defer cosignerServer.Close()

			var genesisHash types.Digest
			sp := types.SuggestedParams{
				Fee: types.MicroAlgos(1000), FirstRoundValid: 1, LastRoundValid: 100,
				GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
			}
			rekeyTxn, err := transaction.MakePaymentTxn(listed, listed, 0, nil, "", sp)
			if err != nil {
				t.Fatal(err)
			}
			if rekeyTxn.RekeyTo, err = types.DecodeAddress(rekeyTarget); err != nil {
				t.Fatal(err)
			}
			spendATxn, err := transaction.MakePaymentTxn(spendA, receiver, 1000, nil, "", sp)
			if err != nil {
				t.Fatal(err)
			}
			spendBTxn, err := transaction.MakePaymentTxn(spendB, receiver, 2000, nil, "", sp)
			if err != nil {
				t.Fatal(err)
			}
			primaryTxn, err := transaction.MakePaymentTxn(primary, receiver, 3000, nil, "", sp)
			if err != nil {
				t.Fatal(err)
			}
			txns := []*types.Transaction{&rekeyTxn, &spendATxn, &spendBTxn, &primaryTxn}
			groupID, err := algocrypto.ComputeGroupID([]types.Transaction{rekeyTxn, spendATxn, spendBTxn, primaryTxn})
			if err != nil {
				t.Fatal(err)
			}
			for _, txn := range txns {
				txn.Group = groupID
			}
			resources := &LogicSigResourceProfile{
				Spend:         &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 3358, MaxOpcodeCost: 20000},
				SpendingRekey: &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 2846, MaxOpcodeCost: 20000},
				ListedRekey:   &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 1583, MaxOpcodeCost: 20000},
			}
			cosignedKey := func(address string) *KeyInfo {
				return &KeyInfo{
					Address: address, KeyType: "aplane.falcon1024.v1", SigningFlow: SigningFlowCosigned1,
					LogicSigResources: resources, CosignerComponentKeyType: KeyTypeWitnessFalcon1024,
					BoundedAuthorization: &BoundedAuthorizationInfo{
						Contract: BoundedContractPlain1, Rekey: "spending_key",
						RekeyList: &BoundedRekeyListInfo{Contract: "rekey_list1", Depth: 4},
						Cosigner:  &BoundedCosignerAuthorizationInfo{ComponentKeyType: KeyTypeWitnessFalcon1024, PublicKeyHex: "aabb"},
					},
				}
			}
			result, err := SignPreparedCosignedGroup(PreparedCosignedGroupOptions{
				UserClient: userClient, CosignerClient: cosignerClient, CosignerComponentKey: "COSIGNER_COMPONENT",
				PreparedGroup: NewPreparedGroup(
					PreparedTransaction{Transaction: &rekeyTxn, AuthAddress: listed, SignerKey: cosignedKey(listed), AppCallInfo: appInfo[0]},
					PreparedTransaction{Transaction: &spendATxn, AuthAddress: spendA, SignerKey: cosignedKey(spendA)},
					PreparedTransaction{Transaction: &spendBTxn, AuthAddress: spendB, SignerKey: cosignedKey(spendB)},
					PreparedTransaction{
						Transaction: &primaryTxn, AuthAddress: primary, AppCallInfo: appInfo[3],
						SignerKey: &KeyInfo{Address: primary, KeyType: "ed25519", AuthorizationKind: AuthorizationKindEd25519},
					},
				),
			})
			if wrongScheme {
				if err == nil || !strings.Contains(err.Error(), "used scheme") {
					t.Fatalf("SignPreparedCosignedGroup() error = %v, want a scheme refusal", err)
				}
				if assembly.Targets != nil {
					t.Fatal("a group with a wrong-scheme cosigner signature reached assembly")
				}
				return
			}
			if err != nil {
				t.Fatalf("SignPreparedCosignedGroup() error = %v", err)
			}

			if len(cosignerRequests) != 1 {
				t.Fatalf("cosigner requests = %d, want one for the shared key", len(cosignerRequests))
			}
			cosigner := cosignerRequests[0]
			if fmt.Sprint(cosigner.TargetIndices) != "[1 2]" || cosigner.ComponentKey != "COSIGNER_COMPONENT" {
				t.Fatalf("cosigner targets = %v under %q, want [1 2] under the shared key", cosigner.TargetIndices, cosigner.ComponentKey)
			}
			contextual := map[int]*AppCallInfo{}
			for _, position := range cosigner.Contextual {
				contextual[position.TargetIndex] = position.AppCallInfo
			}
			if len(contextual) != 2 || contextual[0] == nil || contextual[0].Mode != "listed" ||
				contextual[3] == nil || contextual[3].Mode != "primary" {
				t.Fatalf("cosigner contextual positions = %+v, want 0 and 3 with their app call info", cosigner.Contextual)
			}

			if len(primarySign.Requests) != 4 {
				t.Fatalf("primary /sign requests = %d, want 4", len(primarySign.Requests))
			}
			for index, want := range map[int]uint64{0: 1583, 1: 3358, 2: 3358} {
				got := primarySign.Requests[index]
				if got.AuthAddress != "" || got.LsigResources == nil || got.LsigResources.ArgumentBytes != want {
					t.Fatalf("primary /sign position %d = %+v, want foreign with %d argument bytes", index, got, want)
				}
			}
			if got := primarySign.Requests[3]; got.AuthAddress != primary || got.AppCallInfo == nil || got.AppCallInfo.Mode != "primary" {
				t.Fatalf("primary /sign position 3 = %+v, want the primary slot", got)
			}

			if len(assembly.Targets) != 3 {
				t.Fatalf("assembly targets = %+v", assembly.Targets)
			}
			for _, target := range assembly.Targets {
				needs := target.TargetIndex != 0
				if (target.CosignerSignature != "") != needs ||
					(needs && (target.CosignerSignature != fmt.Sprintf("cosigner-sig-%d", target.TargetIndex) || target.CosignerSourceRequestID != cosigner.RequestID)) {
					t.Fatalf("assembly target %d = %+v, want cosigner material only on a spend", target.TargetIndex, target)
				}
			}
			if len(assembly.Passthrough) != 1 || assembly.Passthrough[0].TargetIndex != 3 {
				t.Fatalf("assembly passthrough = %+v, want the primary slot", assembly.Passthrough)
			}
			if len(result.SignedGroup) != 4 || len(result.CosignerComponentResponses) != 1 {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

// The assembled group must be the frozen group, position by position.
func TestVerifyAssembledGroupRejectsMismatches(t *testing.T) {
	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee: types.MicroAlgos(1000), FirstRoundValid: 1, LastRoundValid: 100,
		GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
	}
	first, err := transaction.MakePaymentTxn(sdkTestAddress(71), sdkTestAddress(72), 1000, nil, "", sp)
	if err != nil {
		t.Fatal(err)
	}
	second, err := transaction.MakePaymentTxn(sdkTestAddress(71), sdkTestAddress(73), 1000, nil, "", sp)
	if err != nil {
		t.Fatal(err)
	}
	frozen := []string{hex.EncodeToString(encodeTxn(first)), hex.EncodeToString(encodeTxn(second))}
	good := signedGroupFor(t, frozen)
	if err := verifyAssembledGroup(frozen, good); err != nil {
		t.Fatalf("verifyAssembledGroup() error = %v for the frozen group", err)
	}
	for name, tt := range map[string]struct {
		signed []string
		want   string
	}{
		"short":       {signed: good[:1], want: "has 1 transaction(s), want 2"},
		"long":        {signed: append(append([]string(nil), good...), good[0]), want: "has 3 transaction(s), want 2"},
		"substituted": {signed: []string{good[0], good[0]}, want: "assembled transaction 1 does not match"},
		"swapped":     {signed: []string{good[1], good[0]}, want: "assembled transaction 0 does not match"},
		"not hex":     {signed: []string{good[0], "zz"}, want: "assembled transaction 1: invalid hex"},
		"not msgpack": {signed: []string{good[0], "c1"}, want: "assembled transaction 1: invalid msgpack"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyAssembledGroup(frozen, tt.signed); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("verifyAssembledGroup() error = %v, want %q", err, tt.want)
			}
		})
	}
}
