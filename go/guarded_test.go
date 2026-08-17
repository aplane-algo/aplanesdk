// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// canonicalTxnHex builds a deterministic real payment transaction and returns
// its canonical TX-prefixed hex, for use as a GroupBytesHex entry that the
// post-assembly identity check (verifyAssembledGroup / signedTxnMatchesCanonical)
// can validate.
func canonicalTxnHex(seed byte) string {
	var addr types.Address
	addr[0] = seed
	txn := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: addr, Fee: 1000, FirstValid: 1, LastValid: 100},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: addr, Amount: 0},
	}
	return hex.EncodeToString(encodeTxn(txn))
}

func guardedTestResources() *LogicSigResourceUsage {
	return &LogicSigResourceUsage{ProgramBytes: 1612, ArgumentBytes: 1423, MaxOpcodeCost: 20000}
}

func TestSelectedPreparedResourcesUsesBoundedAuthorizationPath(t *testing.T) {
	spend := &LogicSigResourceUsage{ProgramBytes: 1001, ArgumentBytes: 101, MaxOpcodeCost: 10001}
	spendingRekey := &LogicSigResourceUsage{ProgramBytes: 2002, ArgumentBytes: 202, MaxOpcodeCost: 20002}
	adminRekey := &LogicSigResourceUsage{ProgramBytes: 3003, ArgumentBytes: 303, MaxOpcodeCost: 30003}
	var rekeyTo types.Address
	rekeyTo[31] = 1

	tests := []struct {
		name          string
		rekey         bool
		authorization string
		want          *LogicSigResourceUsage
	}{
		{name: "spend", want: spend},
		{name: "spending-key rekey", rekey: true, authorization: "spending_key", want: spendingRekey},
		{name: "admin-key rekey", rekey: true, authorization: "admin_key", want: adminRekey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txn := &types.Transaction{}
			operations := []BoundedAdminOperationInfo(nil)
			if tt.rekey {
				txn.RekeyTo = rekeyTo
				operations = []BoundedAdminOperationInfo{{Kind: "rekey", Authorization: tt.authorization}}
			}
			got, err := selectedPreparedResources(&KeyInfo{
				LogicSigResources: &LogicSigResourceProfile{
					Spend: spend, SpendingRekey: spendingRekey, AdminRekey: adminRekey,
				},
				BoundedAuthorization: &BoundedAuthorizationInfo{AdminOperations: operations},
			}, txn)
			if err != nil {
				t.Fatalf("selectedPreparedResources() error = %v", err)
			}
			if got == nil || *got != *tt.want {
				t.Fatalf("selectedPreparedResources() = %+v, want %+v", got, tt.want)
			}
			if got == tt.want {
				t.Fatal("selectedPreparedResources() returned shared inventory metadata")
			}
		})
	}
}

func createGuardedDummies(firstTxn types.Transaction, count int) ([]types.Transaction, error) {
	dummyAcct := crypto.LogicSigAccount{Lsig: types.LogicSig{Logic: guardedDummyProgram}}
	dummyAddr, err := dummyAcct.Address()
	if err != nil {
		return nil, err
	}
	sp := types.SuggestedParams{
		Fee: firstTxn.Fee, FirstRoundValid: types.Round(firstTxn.FirstValid),
		LastRoundValid: types.Round(firstTxn.LastValid), GenesisID: firstTxn.GenesisID,
		GenesisHash: firstTxn.GenesisHash[:], FlatFee: true,
	}
	dummies := make([]types.Transaction, count)
	for i := range dummies {
		txn, err := transaction.MakePaymentTxn(dummyAddr.String(), dummyAddr.String(), 0, []byte{byte(i)}, "", sp)
		if err != nil {
			return nil, err
		}
		txn.Fee = 0
		dummies[i] = txn
	}
	return dummies, nil
}

// signedGroupFor echoes a signed group whose inner transactions match the given
// canonical group bytes, so assembly/passthrough mock responses return bytes the
// post-assembly identity check accepts.
func signedGroupFor(t *testing.T, groupBytesHex []string) []string {
	t.Helper()
	out := make([]string, len(groupBytesHex))
	for i, h := range groupBytesHex {
		out[i] = signedTxnHexFor(t, h)
	}
	return out
}

func signedTxnHexFor(t *testing.T, canonicalHex string) string {
	t.Helper()
	raw, err := hex.DecodeString(canonicalHex)
	if err != nil {
		t.Fatalf("decode canonical hex %q: %v", canonicalHex, err)
	}
	if len(raw) < 2 || raw[0] != 'T' || raw[1] != 'X' {
		t.Fatalf("canonical hex %q missing TX prefix", canonicalHex)
	}
	var txn types.Transaction
	if err := msgpack.Decode(raw[2:], &txn); err != nil {
		t.Fatalf("decode txn from %q: %v", canonicalHex, err)
	}
	return hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn}))
}

func TestSignGuardedGroupOneTarget(t *testing.T) {
	userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sign/component":
			var req capturedComponentRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode user component request: %v", err)
			}
			if req.Role != capturedComponentRoleUser || req.ComponentKey != "GUARDED" {
				t.Fatalf("user component request = %+v", req)
			}
			json.NewEncoder(w).Encode(ComponentResponse{
				RequestID: req.RequestID,
				Components: []Component{{Kind: ComponentTargetKindUser,
					TargetIndex:     0,
					Signature:       "user-sig",
					SignatureScheme: KeyTypeWitnessFalcon1024,
				}},
			})
		case "/sign/assemble":
			var req capturedAssemblyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode assembly request: %v", err)
			}
			if len(req.Targets) != 1 || req.Targets[0].UserSignature != "user-sig" || req.Targets[0].SentrySignature != "sentry-sig" {
				t.Fatalf("assembly targets = %+v", req.Targets)
			}
			json.NewEncoder(w).Encode(AssemblyResponse{
				RequestID:   req.RequestID,
				SignedGroup: signedGroupFor(t, req.GroupBytesHex),
			})
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				IdentityID:          "default",
				State:               "unlocked",
				ApprovalWaitSeconds: 60,
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
		var req capturedComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode sentry component request: %v", err)
		}
		if req.Role != capturedComponentRoleSentry || req.ComponentKey != "SENTRY_COMPONENT" {
			t.Fatalf("sentry component request = %+v", req)
		}
		json.NewEncoder(w).Encode(ComponentResponse{
			RequestID: req.RequestID,
			Components: []Component{{Kind: ComponentTargetKindSentry,
				TargetIndex:     0,
				Signature:       "sentry-sig",
				SignatureScheme: KeyTypeWitnessFalcon1024,
			}},
		})
	})
	defer sentryServer.Close()

	group := []string{canonicalTxnHex(1)}
	result, err := SignGuardedGroup(GuardedSignOptions{
		UserClient:         userClient,
		SentryClient:       sentryClient,
		SentryComponentKey: "SENTRY_COMPONENT",
		GroupBytesHex:      group,
		Targets: []GuardedSignTarget{{
			TargetIndex:       0,
			GuardedAccount:    "GUARDED",
			LogicSigResources: guardedTestResources(),
		}},
	})
	if err != nil {
		t.Fatalf("SignGuardedGroup() error = %v", err)
	}
	if len(result.SignedGroup) != 1 || result.SignedGroup[0] != signedTxnHexFor(t, group[0]) {
		t.Fatalf("signed group = %+v", result.SignedGroup)
	}
}

func TestSignGuardedGroupBatchesSharedSentryKey(t *testing.T) {
	userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sign/component":
			var req capturedComponentRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode user component request: %v", err)
			}
			if len(req.TargetIndices) != 2 {
				t.Fatalf("user target indices = %+v", req.TargetIndices)
			}
			json.NewEncoder(w).Encode(ComponentResponse{
				RequestID: req.RequestID,
				Components: []Component{
					{TargetIndex: 0, Kind: ComponentTargetKindUser, Signature: "user-0", SignatureScheme: KeyTypeWitnessFalcon1024},
					{TargetIndex: 1, Kind: ComponentTargetKindUser, Signature: "user-1", SignatureScheme: KeyTypeWitnessFalcon1024},
				},
			})
		case "/sign/assemble":
			var req capturedAssemblyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode assembly request: %v", err)
			}
			json.NewEncoder(w).Encode(AssemblyResponse{
				RequestID:   req.RequestID,
				SignedGroup: signedGroupFor(t, req.GroupBytesHex),
			})
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				IdentityID:          "default",
				State:               "unlocked",
				ApprovalWaitSeconds: 60,
			})
		default:
			t.Fatalf("unexpected user path %s", r.URL.Path)
		}
	})
	defer userServer.Close()

	sentryCalls := 0
	sentryClient, sentryServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		sentryCalls++
		var req capturedComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode sentry component request: %v", err)
		}
		if len(req.TargetIndices) != 2 {
			t.Fatalf("sentry target indices = %+v", req.TargetIndices)
		}
		json.NewEncoder(w).Encode(ComponentResponse{
			RequestID: req.RequestID,
			Components: []Component{
				{TargetIndex: 0, Kind: ComponentTargetKindSentry, Signature: "sentry-0", SignatureScheme: KeyTypeWitnessFalcon1024},
				{TargetIndex: 1, Kind: ComponentTargetKindSentry, Signature: "sentry-1", SignatureScheme: KeyTypeWitnessFalcon1024},
			},
		})
	})
	defer sentryServer.Close()

	_, err := SignGuardedGroup(GuardedSignOptions{
		UserClient:         userClient,
		SentryClient:       sentryClient,
		SentryComponentKey: "SENTRY_COMPONENT",
		GroupBytesHex:      []string{canonicalTxnHex(1), canonicalTxnHex(2)},
		Targets: []GuardedSignTarget{
			{TargetIndex: 0, GuardedAccount: "GUARDED", LogicSigResources: guardedTestResources()},
			{TargetIndex: 1, GuardedAccount: "GUARDED", LogicSigResources: guardedTestResources()},
		},
	})
	if err != nil {
		t.Fatalf("SignGuardedGroup() error = %v", err)
	}
	if sentryCalls != 1 {
		t.Fatalf("sentry component calls = %d, want 1", sentryCalls)
	}
}

// TestSignGuardedGroupRejectsMismatchedAssembly pins the post-assembly identity
// check: an assembler that returns a wrong-length group, or a signed
// transaction whose inner txn does not match the submitted canonical bytes, is
// rejected before the caller can submit it.
func TestSignGuardedGroupRejectsMismatchedAssembly(t *testing.T) {
	mismatch := signedTxnHexFor(t, canonicalTxnHex(9)) // a different transaction

	cases := map[string][]string{
		"wrong length":          {signedTxnHexFor(t, canonicalTxnHex(1)), signedTxnHexFor(t, canonicalTxnHex(1))},
		"substituted txn":       {mismatch},
		"non-decodable garbage": {"deadbeef"},
	}

	for name, badSignedGroup := range cases {
		t.Run(name, func(t *testing.T) {
			userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/sign/component":
					var req capturedComponentRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					json.NewEncoder(w).Encode(ComponentResponse{
						RequestID:  req.RequestID,
						Components: []Component{{Kind: ComponentTargetKindUser, TargetIndex: 0, Signature: "user-sig", SignatureScheme: KeyTypeWitnessFalcon1024}},
					})
				case "/sign/assemble":
					var req capturedAssemblyRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					json.NewEncoder(w).Encode(AssemblyResponse{RequestID: req.RequestID, SignedGroup: badSignedGroup})
				case "/status":
					json.NewEncoder(w).Encode(StatusResponse{
						IdentityID:          "default",
						State:               "unlocked",
						ApprovalWaitSeconds: 60,
					})
				default:
					t.Fatalf("unexpected user path %s", r.URL.Path)
				}
			})
			defer userServer.Close()

			sentryClient, sentryServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				var req capturedComponentRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				json.NewEncoder(w).Encode(ComponentResponse{
					RequestID:  req.RequestID,
					Components: []Component{{Kind: ComponentTargetKindSentry, TargetIndex: 0, Signature: "sentry-sig", SignatureScheme: KeyTypeWitnessFalcon1024}},
				})
			})
			defer sentryServer.Close()

			_, err := SignGuardedGroup(GuardedSignOptions{
				UserClient:         userClient,
				SentryClient:       sentryClient,
				SentryComponentKey: "SENTRY_COMPONENT",
				GroupBytesHex:      []string{canonicalTxnHex(1)},
				Targets: []GuardedSignTarget{{
					TargetIndex:       0,
					GuardedAccount:    "GUARDED",
					LogicSigResources: guardedTestResources(),
				}},
			})
			if err == nil {
				t.Fatal("SignGuardedGroup() error = nil, want mismatched-assembly rejection")
			}
		})
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
			if len(req.Requests) != 3 || req.Requests[0].AuthAddress != "AUTH" || req.Requests[1].AuthAddress != "" {
				t.Fatalf("primary sign requests = %+v", req.Requests)
			}
			if got := req.Requests[1].LsigResources; got == nil || *got != *guardedTestResources() {
				t.Fatalf("guarded passthrough resources = %#v", got)
			}
			foreignResources := LogicSigResourceUsage{ProgramBytes: 5000, ArgumentBytes: 1200, MaxOpcodeCost: 30000}
			if got := req.Requests[2].LsigResources; got == nil || *got != foreignResources {
				t.Fatalf("foreign passthrough resources = %#v", got)
			}
			json.NewEncoder(w).Encode(GroupSignResponse{Signed: []string{signedTxnHexFor(t, req.Requests[0].TxnBytesHex), "", ""}})
		case "/sign/component":
			var req capturedComponentRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode user component request: %v", err)
			}
			json.NewEncoder(w).Encode(ComponentResponse{
				RequestID: req.RequestID,
				Components: []Component{{Kind: ComponentTargetKindUser,
					TargetIndex:     1,
					Signature:       "user-sig",
					SignatureScheme: KeyTypeWitnessFalcon1024,
				}},
			})
		case "/sign/assemble":
			var req capturedAssemblyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode assembly request: %v", err)
			}
			if len(req.Passthrough) != 2 {
				t.Fatalf("assembly passthrough = %+v", req.Passthrough)
			}
			seen := map[int]bool{}
			for _, item := range req.Passthrough {
				seen[item.TargetIndex] = item.SignedTxnHex != ""
			}
			if !seen[0] || !seen[2] {
				t.Fatalf("assembly passthrough = %+v", req.Passthrough)
			}
			json.NewEncoder(w).Encode(AssemblyResponse{
				RequestID:   req.RequestID,
				SignedGroup: signedGroupFor(t, req.GroupBytesHex),
			})
		default:
			t.Fatalf("unexpected user path %s", r.URL.Path)
		}
	})
	defer userServer.Close()

	sentryClient, sentryServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		var req capturedComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode sentry component request: %v", err)
		}
		json.NewEncoder(w).Encode(ComponentResponse{
			RequestID: req.RequestID,
			Components: []Component{{Kind: ComponentTargetKindSentry,
				TargetIndex:     1,
				Signature:       "sentry-sig",
				SignatureScheme: KeyTypeWitnessFalcon1024,
			}},
		})
	})
	defer sentryServer.Close()

	result, err := SignGuardedGroup(GuardedSignOptions{
		UserClient:         userClient,
		SentryClient:       sentryClient,
		SentryComponentKey: "SENTRY_COMPONENT",
		GroupBytesHex:      []string{canonicalTxnHex(1), canonicalTxnHex(2), canonicalTxnHex(3)},
		PrimaryTargets: []GuardedPrimarySignTarget{{
			TargetIndex: 0,
			AuthAddress: "AUTH",
		}},
		Targets: []GuardedSignTarget{{
			TargetIndex:       1,
			GuardedAccount:    "GUARDED",
			LogicSigResources: guardedTestResources(),
		}},
		Passthrough: []AssemblyPassthroughItem{{
			TargetIndex:  2,
			SignedTxnHex: signedTxnHexFor(t, canonicalTxnHex(3)),
			Authorization: &GuardedPassthroughAuthorization{
				LogicSigResources: &LogicSigResourceUsage{
					ProgramBytes: 5000, ArgumentBytes: 1200, MaxOpcodeCost: 30000,
				},
			},
		}},
	})
	if err != nil {
		t.Fatalf("SignGuardedGroup() error = %v", err)
	}
	if len(result.SignedGroup) != 3 || result.SignedGroup[1] != signedTxnHexFor(t, canonicalTxnHex(2)) {
		t.Fatalf("signed group = %+v", result.SignedGroup)
	}
	if result.PrimarySignResponse == nil {
		t.Fatal("expected primary sign response")
	}
}

func TestSignGuardedGroupRejectsMissingResourcesBeforeSigning(t *testing.T) {
	componentCalls := 0
	userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		componentCalls++
		t.Fatalf("unexpected request %s", r.URL.Path)
	})
	defer userServer.Close()

	_, err := SignGuardedGroup(GuardedSignOptions{
		UserClient:    userClient,
		GroupBytesHex: []string{canonicalTxnHex(1)},
		Targets:       []GuardedSignTarget{{TargetIndex: 0, GuardedAccount: "GUARDED"}},
	})
	if err == nil || !strings.Contains(err.Error(), "missing LogicSig resources") {
		t.Fatalf("expected missing-resource error, got %v", err)
	}
	if componentCalls != 0 {
		t.Fatalf("component requests = %d, want 0", componentCalls)
	}
}

func TestSignPreparedGuardedGroupUsesSignerPlan(t *testing.T) {
	guarded := sdkTestAddress(1)
	receiver := sdkTestAddress(2)

	userClient, userServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sign/component":
			var req capturedComponentRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode user component request: %v", err)
			}
			if req.Role != capturedComponentRoleUser || req.ComponentKey != guarded {
				t.Fatalf("user component request = %+v", req)
			}
			if len(req.GroupBytesHex) != 4 || len(req.TargetIndices) != 1 || req.TargetIndices[0] != 0 {
				t.Fatalf("user component group/targets = len %d targets %+v", len(req.GroupBytesHex), req.TargetIndices)
			}
			if len(req.Contextual) != 0 || len(req.Dummies) != 3 || req.Dummies[0].TargetIndex != 1 || req.Dummies[2].TargetIndex != 3 {
				t.Fatalf("user component partition = context %+v dummies %+v", req.Contextual, req.Dummies)
			}
			if info := req.TargetAppInfo[0]; info == nil || info.Mode != "raw" {
				t.Fatalf("user component app-call info = %#v, want raw", info)
			}
			json.NewEncoder(w).Encode(ComponentResponse{
				RequestID: req.RequestID,
				Components: []Component{{Kind: ComponentTargetKindUser,
					TargetIndex:     0,
					Signature:       "user-sig",
					SignatureScheme: KeyTypeWitnessFalcon1024,
				}},
			})
		case "/sign/assemble":
			var req capturedAssemblyRequest
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
			json.NewEncoder(w).Encode(AssemblyResponse{
				RequestID:   req.RequestID,
				SignedGroup: signedGroupFor(t, req.GroupBytesHex),
			})
		case "/plan":
			var req GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode plan request: %v", err)
			}
			if len(req.Requests) != 1 || req.Requests[0].AuthAddress != guarded {
				t.Fatalf("plan requests = %+v", req.Requests)
			}
			original, err := decodeCanonicalGroup([]string{req.Requests[0].TxnBytesHex})
			if err != nil {
				t.Fatal(err)
			}
			dummies, err := createGuardedDummies(original[0], 3)
			if err != nil {
				t.Fatal(err)
			}
			planned := append(original, dummies...)
			gid, err := crypto.ComputeGroupID(planned)
			if err != nil {
				t.Fatal(err)
			}
			encoded := make([]string, len(planned))
			for i := range planned {
				planned[i].Group = gid
				encoded[i] = hex.EncodeToString(encodeTxn(planned[i]))
			}
			json.NewEncoder(w).Encode(PlanGroupResponse{Transactions: encoded, Mutations: &MutationReport{
				DummiesAdded: 3, OriginalCount: 1, FinalCount: 4, GroupIDChanged: true,
			}})
		case "/sign":
			t.Fatalf("prepared all-guarded path must not call %s", r.URL.Path)
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				IdentityID:          "default",
				State:               "unlocked",
				ApprovalWaitSeconds: 60,
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
		var req capturedComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode sentry component request: %v", err)
		}
		if req.Role != capturedComponentRoleSentry || len(req.GroupBytesHex) != 4 || len(req.TargetIndices) != 1 || req.TargetIndices[0] != 0 {
			t.Fatalf("sentry component request = %+v", req)
		}
		if len(req.Contextual) != 0 || len(req.Dummies) != 3 || req.Dummies[0].TargetIndex != 1 || req.Dummies[2].TargetIndex != 3 {
			t.Fatalf("sentry component partition = context %+v dummies %+v", req.Contextual, req.Dummies)
		}
		if info := req.TargetAppInfo[0]; info == nil || info.Mode != "raw" {
			t.Fatalf("sentry component app-call info = %#v, want raw", info)
		}
		json.NewEncoder(w).Encode(ComponentResponse{
			RequestID: req.RequestID,
			Components: []Component{{Kind: ComponentTargetKindSentry,
				TargetIndex:     0,
				Signature:       "sentry-sig",
				SignatureScheme: KeyTypeWitnessFalcon1024,
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
			AppCallInfo: &AppCallInfo{Mode: "raw"},
			SignerKey: &KeyInfo{
				Address:                guarded,
				KeyType:                KeyTypeGuardedFalcon1024Sentry1024,
				SigningFlow:            SigningFlowSentry1,
				SentryComponentKeyType: KeyTypeWitnessFalcon1024,
				LogicSigResources: &LogicSigResourceProfile{
					Spend: &LogicSigResourceUsage{ProgramBytes: 1612, ArgumentBytes: 1423, MaxOpcodeCost: 20000},
				},
				Parameters: map[string]string{"sentry_public_key": "aabbcc"},
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
				LogicSigResources: &LogicSigResourceProfile{
					Spend: &LogicSigResourceUsage{ProgramBytes: 1612, ArgumentBytes: 1423, MaxOpcodeCost: 20000},
				},
			},
		}),
	})
	if err == nil || !strings.Contains(err.Error(), `signing flow "sentry2"`) {
		t.Fatalf("SignPreparedGuardedGroup() error = %v, want unsupported signing flow rejection", err)
	}
}
