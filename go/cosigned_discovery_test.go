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

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// A cosigned send with no cosigner given, by a client created from a data
// directory, finds the cosigner in endpoints.yaml.
func TestSendPreparedCosignedFindsTheCosignerByDefault(t *testing.T) {
	f := cosignedSendFixture(t, "", false)
	publicKey, _ := hex.DecodeString(cosignerPublicKeyHex)
	f.componentKey = WitnessKeyID(KeyTypeWitnessFalcon1024, publicKey)
	resolver := NewEndpointCosignerResolverFromRegistry(&ClientEndpointRegistry{Endpoints: map[string]ClientEndpointConfig{
		"cos": {Role: ClientEndpointRoleCosigner, URL: "ssh://cos"},
	}}, nil)
	connects := 0
	resolver.connect = func(context.Context, ClientEndpointConfig, EndpointCosignerResolverOptions) (*SignerClient, error) {
		connects++
		return f.cosigner, nil
	}
	f.user.endpoints = resolver.registry
	f.user.cosignerResolver = resolver
	result, err := f.user.SendPrepared(context.Background(), f.algod, f.group, nil)
	if err != nil || result.Outcome != SendOutcomeConfirmed || f.cosignerCalls != 1 || connects != 1 {
		t.Fatalf("SendPrepared() = %+v, %v; cosigner calls %d, connects %d", result, err, f.cosignerCalls, connects)
	}

	// An explicit cosigner wins over the default.
	f.componentKey = "COSIGNER_COMPONENT"
	if _, err := f.user.SendPrepared(context.Background(), f.algod, f.group, &SendOptions{CosignerClient: f.cosigner, CosignerComponentKey: "COSIGNER_COMPONENT"}); err != nil || connects != 1 {
		t.Fatalf("SendPrepared(explicit) error = %v, connects %d", err, connects)
	}
}

// failingResolver fails every call, counting them.
type failingResolver struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (r *failingResolver) ResolveCosigner(context.Context, string, string) (*SignerClient, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return nil, "", r.err
}

// The cosigner of a target that needs one is found before anything is asked
// to sign: a resolver that fails leaves no approval-bearing request made, and
// the failure is a plain error, whatever it wraps.
func TestCosignedResolvesBeforeTheFirstApproval(t *testing.T) {
	cases := map[string]error{
		"a discovery failure":        fmt.Errorf("%w: no endpoint lists it", ErrCosignerDiscovery),
		"an error that marks a loss": fmt.Errorf("resolver's own call: %w", &lostAnswer{requestID: "sdk-x", err: errors.New("dropped")}),
	}
	for name, resolverErr := range cases {
		for _, primary := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, with an ordinary position %v", name, primary), func(t *testing.T) {
				f := cosignedSendFixture(t, "", primary)
				resolver := &failingResolver{err: resolverErr}
				_, err := f.user.SendPrepared(context.Background(), f.algod, f.group, &SendOptions{CosignerResolver: resolver})
				var unknown *SignOutcomeUnknownError
				if err == nil || errors.As(err, &unknown) || err.Error() != resolverErr.Error() {
					t.Fatalf("error = %v, want the resolver's error, plainly", err)
				}
				if posted := f.posted("/plan", "/sign/component", "/sign", "/sign/assemble"); len(posted) != 0 || f.cosignerCalls != 0 || resolver.calls != 1 {
					t.Fatalf("posted %v, cosigner calls %d, resolver calls %d; want nothing posted", posted, f.cosignerCalls, resolver.calls)
				}
				// The lower-level call resolves first too.
				_, err = SignPreparedCosignedGroupWithContext(context.Background(), PreparedCosignedGroupOptions{UserClient: f.user, CosignerResolver: resolver, PreparedGroup: f.group})
				if err == nil || err.Error() != resolverErr.Error() || len(f.posted("/plan", "/sign/component")) != 0 {
					t.Fatalf("SignPreparedCosignedGroup: %v, posted %v", err, f.posted("/plan", "/sign/component"))
				}
			})
		}
	}

	// With no cosigner at all, the refusal comes before anything is signed.
	f := cosignedSendFixture(t, "", false)
	_, err := f.user.SendPrepared(context.Background(), f.algod, f.group, nil)
	if err == nil || err.Error() != "cosigner client or resolver is required" || len(f.posted("/plan", "/sign/component")) != 0 {
		t.Fatalf("error = %v, posted %v", err, f.posted("/plan", "/sign/component"))
	}
}

// A rekey of an account with a rekey-to list may take the listed path, which
// needs no cosigner: its cosigner is not looked for up front, so a listed
// rekey works with no cosigner at all. If its base component names a path
// that needs one, the cosigner is looked for then, and a failure is still a
// plain error.
func TestCosignedListedRekeyNeedsNoCosignerUpFront(t *testing.T) {
	for _, path := range []string{ComponentPathListedRekey, ComponentPathSpendingRekey} {
		for _, configured := range []string{"nothing", "a failing resolver"} {
			t.Run(path+" with "+configured, func(t *testing.T) {
				bounded := sdkTestAddress(23)
				target := sdkTestAddress(24)
				var posted []string
				var mu sync.Mutex
				userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost {
						mu.Lock()
						posted = append(posted, r.URL.Path)
						mu.Unlock()
					}
					switch r.URL.Path {
					case "/status":
						json.NewEncoder(w).Encode(StatusResponse{State: "unlocked", ApprovalWaitSeconds: 60})
					case "/plan":
						var req GroupSignRequest
						json.NewDecoder(r.Body).Decode(&req)
						json.NewEncoder(w).Encode(PlanGroupResponse{Transactions: []string{req.Requests[0].TxnBytesHex}})
					case "/sign/component":
						var req ComponentRequest
						json.NewDecoder(r.Body).Decode(&req)
						json.NewEncoder(w).Encode(ComponentResponse{RequestID: req.RequestID, Components: []Component{{
							TargetIndex: 0, Kind: ComponentTargetKindBoundedBase, AuthAddress: bounded,
							BaseSignatures: []string{"base-sig"}, AssemblyReceipt: "receipt",
							SignatureScheme: "aplane.falcon1024.v1", Path: path,
						}}})
					case "/sign/assemble":
						var req AssemblyRequest
						json.NewDecoder(r.Body).Decode(&req)
						json.NewEncoder(w).Encode(AssemblyResponse{RequestID: req.RequestID, SignedGroup: signedGroupFor(t, req.GroupBytesHex)})
					default:
						t.Errorf("unexpected user path %s", r.URL.Path)
					}
				})
				defer userServer.Close()

				var genesisHash types.Digest
				sp := types.SuggestedParams{Fee: 1000, FirstRoundValid: 1, LastRoundValid: 100, GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true}
				txn, err := transaction.MakePaymentTxn(bounded, bounded, 0, nil, "", sp)
				if err != nil {
					t.Fatal(err)
				}
				if txn.RekeyTo, err = types.DecodeAddress(target); err != nil {
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
						Cosigner:  &BoundedCosignerAuthorizationInfo{ComponentKeyType: KeyTypeWitnessFalcon1024, PublicKeyHex: cosignerPublicKeyHex},
					},
				}
				opts := PreparedCosignedGroupOptions{
					UserClient:    userClient,
					PreparedGroup: NewPreparedGroup(held(PreparedTransaction{Transaction: &txn, AuthAddress: bounded}, key)),
				}
				resolver := &failingResolver{err: fmt.Errorf("%w: cosigner down", ErrCosignerDiscovery)}
				if configured != "nothing" {
					opts.CosignerResolver = resolver
				}
				result, err := signCosignedWithHeldKeys(opts)
				if path == ComponentPathListedRekey {
					if err != nil || len(result.SignedGroup) != 1 || resolver.calls != 0 {
						t.Fatalf("listed rekey: %v, resolver calls %d; want it signed with no cosigner", err, resolver.calls)
					}
					return
				}
				var mark *lostAnswer
				if err == nil || errors.As(err, &mark) {
					t.Fatalf("error = %v, want a plain error", err)
				}
				mu.Lock()
				defer mu.Unlock()
				if strings.Join(posted, ",") != "/plan,/sign/component" {
					t.Fatalf("posted %v, want the base component and no assembly", posted)
				}
				if configured != "nothing" && resolver.calls != 1 {
					t.Fatalf("resolver calls = %d, want one after the base component", resolver.calls)
				}
			})
		}
	}
}

// orderResolver records the cosigners it is asked for, as "key type/public
// key", and answers each with the client for that key. The call numbered
// failAt (from 1) fails instead.
type orderResolver struct {
	mu      sync.Mutex
	asked   []string
	clients map[string]*SignerClient // by "key type/lowercase public key"
	failAt  int
}

func (r *orderResolver) ResolveCosigner(_ context.Context, publicKeyHex, keyType string) (*SignerClient, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, keyType+"/"+publicKeyHex)
	if len(r.asked) == r.failAt {
		return nil, "", fmt.Errorf("%w: no endpoint lists %s", ErrCosignerDiscovery, publicKeyHex)
	}
	ref := keyType + "/" + strings.ToLower(publicKeyHex)
	return r.clients[ref], "COMPONENT-" + ref, nil
}

// Cosigners are resolved in (key type, lowercase public key hex, position)
// order, up front for spends and after the base component for rekeys that
// may take the listed path, so the first one found missing is the same in
// every SDK. The cosigners are still asked to sign by first position.
func TestCosignedResolvesInKeyOrderAndRequestsInPositionOrder(t *testing.T) {
	type cosignerRef struct{ keyType, publicKeyHex string }
	const typeA, typeB = "aplane.witness-a.v1", "aplane.witness-b.v1"
	// Position order, raw text order and key order all differ: "BB00" sorts
	// before "aa11" unless it is lowercased.
	refs := []cosignerRef{{typeB, "aa00"}, {typeA, "BB00"}, {typeA, "aa11"}, {typeA, "aa11"}}
	wantAsked := typeA + "/aa11," + typeA + "/aa11," + typeA + "/BB00," + typeB + "/aa00"

	for _, rekey := range []bool{false, true} {
		t.Run(fmt.Sprintf("rekey %v", rekey), func(t *testing.T) {
			accounts := make([]string, len(refs))
			for i := range refs {
				accounts[i] = sdkTestAddress(byte(70 + i))
			}
			path := ComponentPathSpend
			if rekey {
				path = ComponentPathSpendingRekey
			}
			var mu sync.Mutex
			var posted, cosignerRequests []string
			userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					mu.Lock()
					posted = append(posted, r.URL.Path)
					mu.Unlock()
				}
				switch r.URL.Path {
				case "/status":
					json.NewEncoder(w).Encode(StatusResponse{State: "unlocked", ApprovalWaitSeconds: 60})
				case "/plan":
					var req GroupSignRequest
					json.NewDecoder(r.Body).Decode(&req)
					var txns []string
					for _, item := range req.Requests {
						txns = append(txns, item.TxnBytesHex)
					}
					json.NewEncoder(w).Encode(PlanGroupResponse{Transactions: txns})
				case "/sign/component":
					var req ComponentRequest
					json.NewDecoder(r.Body).Decode(&req)
					var components []Component
					for _, target := range req.Targets {
						components = append(components, Component{
							TargetIndex: target.TargetIndex, Kind: ComponentTargetKindBoundedBase, AuthAddress: accounts[target.TargetIndex],
							BaseSignatures: []string{"base-sig"}, AssemblyReceipt: "receipt", SignatureScheme: "aplane.falcon1024.v1", Path: path,
						})
					}
					json.NewEncoder(w).Encode(ComponentResponse{RequestID: req.RequestID, Components: components})
				case "/sign/assemble":
					var req AssemblyRequest
					json.NewDecoder(r.Body).Decode(&req)
					json.NewEncoder(w).Encode(AssemblyResponse{RequestID: req.RequestID, SignedGroup: signedGroupFor(t, req.GroupBytesHex)})
				default:
					t.Errorf("unexpected user path %s", r.URL.Path)
				}
			})
			defer userServer.Close()
			cosigner := func(name string) *SignerClient {
				client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
					var req capturedComponentRequest
					json.NewDecoder(r.Body).Decode(&req)
					mu.Lock()
					cosignerRequests = append(cosignerRequests, fmt.Sprintf("%s%v", name, req.TargetIndices))
					mu.Unlock()
					var components []Component
					for _, index := range req.TargetIndices {
						components = append(components, Component{
							TargetIndex: index, Kind: ComponentTargetKindCosigner,
							Signature: fmt.Sprintf("cosigner-sig-%d", index), SignatureScheme: refs[index].keyType,
						})
					}
					json.NewEncoder(w).Encode(ComponentResponse{RequestID: req.RequestID, Components: components})
				})
				t.Cleanup(server.Close)
				return client
			}
			x, y := cosigner("x"), cosigner("y")
			clients := map[string]*SignerClient{typeA + "/aa11": x, typeA + "/bb00": x, typeB + "/aa00": y}

			var genesisHash types.Digest
			sp := types.SuggestedParams{Fee: 1000, FirstRoundValid: 1, LastRoundValid: 100, GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true}
			resources := &LogicSigResourceProfile{
				Spend:         &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 3358, MaxOpcodeCost: 20000},
				SpendingRekey: &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 2846, MaxOpcodeCost: 20000},
				ListedRekey:   &LogicSigResourceUsage{ProgramBytes: 5308, ArgumentBytes: 1583, MaxOpcodeCost: 20000},
			}
			txns := make([]types.Transaction, len(refs))
			for i, account := range accounts {
				txn, err := transaction.MakePaymentTxn(account, sdkTestAddress(80), uint64(1000+i), nil, "", sp)
				if err != nil {
					t.Fatal(err)
				}
				if rekey {
					if txn.RekeyTo, err = types.DecodeAddress(sdkTestAddress(81)); err != nil {
						t.Fatal(err)
					}
				}
				txns[i] = txn
			}
			groupID, err := algocrypto.ComputeGroupID(txns)
			if err != nil {
				t.Fatal(err)
			}
			positions := make([]PreparedTransaction, len(refs))
			for i := range txns {
				txns[i].Group = groupID
				positions[i] = held(PreparedTransaction{Transaction: &txns[i], AuthAddress: accounts[i]}, &KeyInfo{
					Address: accounts[i], KeyType: "aplane.falcon1024.v1", SigningFlow: SigningFlowCosigned1,
					LogicSigResources: resources, CosignerComponentKeyType: refs[i].keyType,
					BoundedAuthorization: &BoundedAuthorizationInfo{
						Contract: BoundedContractPlain1, Rekey: "spending_key",
						RekeyList: &BoundedRekeyListInfo{Contract: "rekey_list1", Depth: 4},
						Cosigner:  &BoundedCosignerAuthorizationInfo{ComponentKeyType: refs[i].keyType, PublicKeyHex: refs[i].publicKeyHex},
					},
				})
			}

			resolver := &orderResolver{clients: clients}
			result, err := signCosignedWithHeldKeys(PreparedCosignedGroupOptions{UserClient: userClient, CosignerResolver: resolver, PreparedGroup: NewPreparedGroup(positions...)})
			if err != nil || len(result.SignedGroup) != len(refs) {
				t.Fatalf("SignPreparedCosignedGroup() error = %v", err)
			}
			mu.Lock()
			gotRequests := strings.Join(cosignerRequests, ",")
			mu.Unlock()
			if got := strings.Join(resolver.asked, ","); got != wantAsked {
				t.Fatalf("resolved %s\nwant     %s", got, wantAsked)
			}
			if gotRequests != "y[0],x[1],x[2 3]" {
				t.Fatalf("cosigner requests = %s, want y[0],x[1],x[2 3]: by first position", gotRequests)
			}

			// The first cosigner found missing is the first in key order.
			mu.Lock()
			posted, cosignerRequests = nil, nil
			mu.Unlock()
			failing := &orderResolver{clients: clients, failAt: 1}
			_, err = signCosignedWithHeldKeys(PreparedCosignedGroupOptions{UserClient: userClient, CosignerResolver: failing, PreparedGroup: NewPreparedGroup(positions...)})
			if !errors.Is(err, ErrCosignerDiscovery) || err.Error() != "cosigner discovery: no endpoint lists aa11" || strings.Join(failing.asked, ",") != typeA+"/aa11" {
				t.Fatalf("error = %v after asking %v; want the first key in key order", err, failing.asked)
			}
			mu.Lock()
			defer mu.Unlock()
			wantPosted := ""
			if rekey {
				wantPosted = "/plan,/sign/component"
			}
			if strings.Join(posted, ",") != wantPosted || len(cosignerRequests) != 0 {
				t.Fatalf("posted %v and asked cosigners %v; want %q and none", posted, cosignerRequests, wantPosted)
			}
		})
	}
}
