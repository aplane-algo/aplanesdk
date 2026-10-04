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

func TestSignPreparedBoundedCosignerGroupOneTarget(t *testing.T) {
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
	options := PreparedGuardedGroupOptions{
		UserClient: userClient, CosignerClient: cosignerClient,
		CosignerComponentKey: "COSIGNER_COMPONENT",
		PreparedGroup: NewPreparedGroup(PreparedTransaction{
			Transaction: &txn, AuthAddress: bounded,
			AppCallInfo: &AppCallInfo{Mode: "raw"},
			SignerKey: &KeyInfo{
				Address: bounded, KeyType: "aplane.corridor.v1",
				SigningFlow: SigningFlowBoundedCosigner1,
				LogicSigResources: &LogicSigResourceProfile{
					Spend: &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 3358, MaxOpcodeCost: 20000},
				},
				CosignerComponentKeyType: KeyTypeWitnessFalcon1024,
				BoundedAuthorization: &BoundedAuthorizationInfo{
					MaxFee: 1000,
					Cosigner: &BoundedCosignerAuthorizationInfo{
						ComponentKeyType: KeyTypeWitnessFalcon1024, PublicKeyHex: "aabb",
					},
				},
			},
		}),
	}
	result, err := SignPreparedGuardedGroup(options)
	if err != nil {
		t.Fatalf("SignPreparedGuardedGroup() error = %v", err)
	}
	if len(result.SignedGroup) != 1 || result.BoundedComponentResponse == nil ||
		result.BoundedAssemblyResponse == nil || result.AssemblyResponse != nil {
		t.Fatalf("result = %+v", result)
	}
	componentCalls = 0
	options.PreparedGroup.Transactions[0].SignerKey.BoundedAuthorization.MaxFee = 999
	if _, err := SignPreparedGuardedGroup(options); err == nil ||
		!strings.Contains(err.Error(), "exceeds advertised max_fee") {
		t.Fatalf("SignPreparedGuardedGroup() error = %v, want max_fee rejection", err)
	}
	if componentCalls != 0 {
		t.Fatalf("component calls = %d, want none before max_fee rejection", componentCalls)
	}
}

// A native-PQ primary slot is contextual to /sign/component, so
// the signer budgets its fee purely from the declared pq_scheme. Omitting it
// freezes an under-funded canonical group that the later /sign identity check
// cannot detect, because the shortfall is already inside the canonical bytes.
func TestSignPreparedBoundedCosignerGroupDeclaresNativePQPrimary(t *testing.T) {
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
			nativePQ := sdkTestAddress(52)
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
					frozenGroup = []string{req.Requests[0].TxnBytesHex, req.Requests[1].TxnBytesHex}
					json.NewEncoder(w).Encode(PlanGroupResponse{Transactions: frozenGroup})
				case "/sign/component":
					record("base")
					var req ComponentRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Fatalf("decode bounded component request: %v", err)
					}
					if len(req.Targets) != 1 || len(req.ContextualPositions) != 1 {
						t.Fatalf("bounded component partition = %+v", req)
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
						}},
					})
				case "/sign":
					record("sign")
					if rejectSign {
						writeCodedError(w, http.StatusForbidden, ErrCodeForbidden, "rejected by signer policy")
						return
					}
					json.NewEncoder(w).Encode(GroupSignResponse{Signed: signedGroupFor(t, frozenGroup)})
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
			groupID, err := algocrypto.ComputeGroupID([]types.Transaction{corridorTxn, nativeTxn})
			if err != nil {
				t.Fatalf("ComputeGroupID() error = %v", err)
			}
			corridorTxn.Group = groupID
			nativeTxn.Group = groupID

			_, err = SignPreparedGuardedGroup(PreparedGuardedGroupOptions{
				UserClient: userClient, CosignerClient: cosignerClient,
				CosignerComponentKey: "COSIGNER_COMPONENT",
				PreparedGroup: NewPreparedGroup(
					PreparedTransaction{
						Transaction: &corridorTxn, AuthAddress: bounded,
						SignerKey: &KeyInfo{
							Address: bounded, KeyType: "aplane.corridor.v1",
							AuthorizationKind: AuthorizationKindLogicSig,
							SigningFlow:       SigningFlowBoundedCosigner1,
							LogicSigResources: &LogicSigResourceProfile{
								Spend: &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 3358, MaxOpcodeCost: 20000},
							},
							CosignerComponentKeyType: KeyTypeWitnessFalcon1024,
							BoundedAuthorization: &BoundedAuthorizationInfo{
								MaxFee: 1000,
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
				t.Fatalf("SignPreparedGuardedGroup() error = %v", err)
			}
			if got := eventSnapshot(); got != "base,sign,cosigner,assemble" {
				t.Fatalf("calls = %s, want %s", got, "base,sign,cosigner,assemble")
			}

			if primaryRequest.PQScheme != PQSchemeFalcon1024 {
				t.Fatalf("primary slot PQScheme = %q, want %q", primaryRequest.PQScheme, PQSchemeFalcon1024)
			}
			if primaryRequest.LsigResources != nil {
				t.Fatalf("primary slot LsigResources = %+v, want nil", primaryRequest.LsigResources)
			}
			if primaryRequest.AuthAddress != "" {
				t.Fatalf("primary slot AuthAddress = %q, want empty (foreign mode)", primaryRequest.AuthAddress)
			}
		})
	}
}

func TestPreparedForeignPQSchemeRejectsContradictoryMetadata(t *testing.T) {
	key := &KeyInfo{AuthorizationKind: AuthorizationKindNativePQ}
	resources := &LogicSigResourceUsage{ProgramBytes: 512, ArgumentBytes: 32, MaxOpcodeCost: 20000}
	if _, err := preparedForeignPQScheme(key, resources); err == nil ||
		!strings.Contains(err.Error(), "must not declare LogicSig resources") {
		t.Fatalf("preparedForeignPQScheme() error = %v, want contradiction rejection", err)
	}

	// A key without authorization_kind declares no native-PQ scheme and
	// keeps the previous declaration rather than guessing.
	got, err := preparedForeignPQScheme(&KeyInfo{}, nil)
	if err != nil || got != "" {
		t.Fatalf("preparedForeignPQScheme() = %q, %v, want empty scheme and no error", got, err)
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
		{name: "guarded user", target: AssemblyTarget{
			TargetIndex: 0, Kind: AssemblyTargetKindGuarded, AuthAddress: "GUARDED",
			UserSignature: "user", UserSourceRequestID: "bad id", CosignerSignature: "cosigner",
		}, want: "user_source_request_id"},
		{name: "guarded cosigner", target: AssemblyTarget{
			TargetIndex: 0, Kind: AssemblyTargetKindGuarded, AuthAddress: "GUARDED",
			UserSignature: "user", CosignerSignature: "cosigner", CosignerSourceRequestID: "bad id",
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
		SignatureScheme: "aplane.falcon1024.v1",
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
		!strings.Contains(err.Error(), "does not match decoded transactions") {
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

func TestPreparedBoundedCosignerRejectsMixedFlow(t *testing.T) {
	_, err := SignPreparedGuardedGroup(PreparedGuardedGroupOptions{
		UserClient: &SignerClient{},
		PreparedGroup: NewPreparedGroup(
			PreparedTransaction{SignerKey: &KeyInfo{SigningFlow: SigningFlowBoundedCosigner1}},
			PreparedTransaction{SignerKey: &KeyInfo{SigningFlow: SigningFlowCosigner1}},
		),
	})
	if err == nil || !strings.Contains(err.Error(), "cannot mix cosigner1 and bounded-cosigner1") {
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
				State: "unlocked", ApprovalWaitSeconds: 60,
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
			map[int]*LogicSigResourceUsage{},
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
	t.Run("gratuitous existing group change", func(t *testing.T) {
		grouped := original
		grouped.Group = types.Digest{0x31}
		regrouped := grouped
		regrouped.Group = types.Digest{0x32}
		report := &MutationReport{GroupIDChanged: true, OriginalCount: 1, FinalCount: 1}
		if err := validateBoundedComponentPlan([]types.Transaction{grouped}, []types.Transaction{regrouped}, report); err == nil ||
			!strings.Contains(err.Error(), "existing bounded group ID") {
			t.Fatalf("error = %v, want gratuitous regrouping rejection", err)
		}
	})
	t.Run("fee exceeds advertised ceiling", func(t *testing.T) {
		if err := validateBoundedTargetFees(planned, map[int]uint64{0: uint64(plannedOriginal.Fee) - 1}); err == nil ||
			!strings.Contains(err.Error(), "exceeds advertised max_fee") {
			t.Fatalf("error = %v, want max_fee rejection", err)
		}
	})
}
