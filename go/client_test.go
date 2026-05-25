// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestFromEnv_RequiresSSH(t *testing.T) {
	dir := t.TempDir()

	// Write token
	os.WriteFile(filepath.Join(dir, "aplane.token"), []byte("test-token"), 0600)

	// Write config without SSH block
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("signer_port: 11270\n"), 0600)

	_, err := FromEnv(&FromEnvOptions{DataDir: dir})
	if err == nil {
		t.Fatal("expected error when SSH not configured")
	}
	if !strings.Contains(err.Error(), "no ssh block") {
		t.Fatalf("expected 'no ssh block' error, got: %s", err)
	}
}

func TestFromEnv_RequiresSSHHost(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "aplane.token"), []byte("test-token"), 0600)

	// SSH block with empty host
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("signer_port: 11270\nssh:\n  port: 1127\n"), 0600)

	_, err := FromEnv(&FromEnvOptions{DataDir: dir})
	if err == nil {
		t.Fatal("expected error when SSH host is empty")
	}
	if !strings.Contains(err.Error(), "no ssh block") {
		t.Fatalf("expected 'no ssh block' error, got: %s", err)
	}
}

func TestBuildHostKeyCallback_RequiresKnownHosts(t *testing.T) {
	tunnel := &sshTunnel{knownHostsPath: ""}
	_, err := tunnel.buildHostKeyCallback()
	if err == nil {
		t.Fatal("expected error when knownHostsPath is empty")
	}
	if !strings.Contains(err.Error(), "known_hosts path is required") {
		t.Fatalf("expected 'known_hosts path is required' error, got: %s", err)
	}
}

func TestBuildSignRequests(t *testing.T) {
	txn := types.Transaction{}
	txn.Type = types.PaymentTx
	txn.Sender = types.Address{}

	requests := buildSignRequests(
		[]types.Transaction{txn},
		[]string{"AUTH_ADDR"},
		nil,
	)

	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}
	if requests[0].AuthAddress != "AUTH_ADDR" {
		t.Fatalf("expected auth address AUTH_ADDR, got %s", requests[0].AuthAddress)
	}
}

func TestBuildSignRequests_DefaultAuthAddress(t *testing.T) {
	txn := types.Transaction{}
	txn.Type = types.PaymentTx

	requests := buildSignRequests(
		[]types.Transaction{txn},
		nil,
		nil,
	)

	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}
	// Should use sender address when no auth address provided
	if requests[0].AuthAddress != txn.Sender.String() {
		t.Fatalf("expected sender as auth address, got %s", requests[0].AuthAddress)
	}
}

func TestBuildSignRequests_WithLsigArgs(t *testing.T) {
	txn := types.Transaction{}
	txn.Type = types.PaymentTx
	authAddr := txn.Sender.String()

	requests := buildSignRequests(
		[]types.Transaction{txn},
		nil,
		LsigArgsMap{authAddr: LsigArgs{"preimage": []byte("secret")}},
	)

	if requests[0].LsigArgs == nil {
		t.Fatal("expected lsig args")
	}
	if requests[0].LsigArgs["preimage"] != hex.EncodeToString([]byte("secret")) {
		t.Fatal("lsig args mismatch")
	}
}

func TestSignTransactionsList_ReturnsIndividualBase64(t *testing.T) {
	// Create mock server that returns two signed transactions
	signedHex1 := hex.EncodeToString([]byte("signed-txn-1"))
	signedHex2 := hex.EncodeToString([]byte("signed-txn-2"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := GroupSignResponse{
			Signed: []string{signedHex1, signedHex2},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &SignerClient{
		baseURL: server.URL,
		token:   "test",
		client:  http.DefaultClient,
	}

	txn1 := types.Transaction{Type: types.PaymentTx}
	txn2 := types.Transaction{Type: types.PaymentTx}

	result, err := client.SignTransactionsList(
		[]types.Transaction{txn1, txn2},
		nil, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result))
	}

	// Verify each is individually base64-encoded
	decoded1, err := base64.StdEncoding.DecodeString(result[0])
	if err != nil {
		t.Fatalf("result[0] is not valid base64: %v", err)
	}
	if string(decoded1) != "signed-txn-1" {
		t.Fatalf("result[0] decoded to %q, expected %q", decoded1, "signed-txn-1")
	}

	decoded2, err := base64.StdEncoding.DecodeString(result[1])
	if err != nil {
		t.Fatalf("result[1] is not valid base64: %v", err)
	}
	if string(decoded2) != "signed-txn-2" {
		t.Fatalf("result[1] decoded to %q, expected %q", decoded2, "signed-txn-2")
	}
}

func TestSignTransactions_ReturnsConcatenatedBase64(t *testing.T) {
	signedHex1 := hex.EncodeToString([]byte("signed-txn-1"))
	signedHex2 := hex.EncodeToString([]byte("signed-txn-2"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := GroupSignResponse{
			Signed: []string{signedHex1, signedHex2},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &SignerClient{
		baseURL: server.URL,
		token:   "test",
		client:  http.DefaultClient,
	}

	txn1 := types.Transaction{Type: types.PaymentTx}
	txn2 := types.Transaction{Type: types.PaymentTx}

	result, err := client.SignTransactions(
		[]types.Transaction{txn1, txn2},
		nil, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("result is not valid base64: %v", err)
	}
	expected := "signed-txn-1signed-txn-2"
	if string(decoded) != expected {
		t.Fatalf("decoded to %q, expected %q", decoded, expected)
	}
}

func TestSignTransactions_RejectsEmptySlice(t *testing.T) {
	client := &SignerClient{baseURL: "http://example.invalid", token: "test", client: http.DefaultClient}

	_, err := client.SignTransactions(nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "requests array is empty") {
		t.Fatalf("expected empty transaction error, got %v", err)
	}
}

func TestSignTransactionsList_RejectsEmptySlice(t *testing.T) {
	client := &SignerClient{baseURL: "http://example.invalid", token: "test", client: http.DefaultClient}

	_, err := client.SignTransactionsList(nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "requests array is empty") {
		t.Fatalf("expected empty transaction error, got %v", err)
	}
}

// --- Health tests ---

func newTestClient(handler http.HandlerFunc) (*SignerClient, *httptest.Server) {
	server := httptest.NewServer(handler)
	return &SignerClient{
		baseURL: server.URL,
		token:   "test-token",
		client:  http.DefaultClient,
	}, server
}

func TestHealth_Reachable(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	defer server.Close()

	ok, err := client.Health()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected healthy")
	}
}

func TestHealth_Unreachable(t *testing.T) {
	client := &SignerClient{
		baseURL: "http://localhost:1",
		token:   "test",
		client:  http.DefaultClient,
	}
	ok, err := client.Health()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected unhealthy")
	}
}

func TestHealth_NetworkError(t *testing.T) {
	client := &SignerClient{
		baseURL: "http://192.0.2.1:1", // unreachable TEST-NET address
		token:   "test",
		client:  &http.Client{Timeout: 100 * time.Millisecond},
	}
	ok, err := client.Health()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected unhealthy on network error")
	}
}

// --- GetStatus tests ---

func TestGetStatus_Success(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/status" {
			t.Fatalf("request = %s %s, want GET /status", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "aplane test-token" {
			t.Fatalf("Authorization = %q, want aplane test-token", got)
		}
		json.NewEncoder(w).Encode(StatusResponse{
			IdentityID:          "default",
			State:               "unlocked",
			ReadyForSigning:     true,
			KeyCount:            37,
			KeysetRevision:      4,
			ApprovalWaitSeconds: 60,
		})
	})
	defer server.Close()

	identity, err := client.GetStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.IdentityID != "default" {
		t.Fatalf("IdentityID = %q, want default", identity.IdentityID)
	}
	if identity.KeysetRevision != 4 {
		t.Fatalf("KeysetRevision = %d, want 4", identity.KeysetRevision)
	}
	if identity.ApprovalWaitSeconds != 60 {
		t.Fatalf("ApprovalWaitSeconds = %d, want 60", identity.ApprovalWaitSeconds)
	}
}

func TestGetStatus_LockedStateIsSuccess(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(StatusResponse{
			IdentityID:      "default",
			State:           "locked",
			SignerLocked:    true,
			ReadyForSigning: false,
			KeyCount:        0,
			KeysetRevision:  2,
		})
	})
	defer server.Close()

	identity, err := client.GetStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.State != "locked" || !identity.SignerLocked {
		t.Fatalf("identity locked state not mapped: %#v", identity)
	}
}

func TestGetStatus_AuthError(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer server.Close()

	_, err := client.GetStatus()
	if err != ErrAuthentication {
		t.Fatalf("expected ErrAuthentication, got: %v", err)
	}
}

func TestSignRequestTimeoutUsesApprovalWaitSlack(t *testing.T) {
	client := NewSignerClientWithToken("http://example.invalid", "test")
	client.cacheApprovalWait(120)

	if got := client.signRequestTimeout(); got != 150*time.Second {
		t.Fatalf("signRequestTimeout = %s, want 150s", got)
	}
}

func TestSignRequestTimeoutFallsBackForInvalidApprovalWait(t *testing.T) {
	client := NewSignerClientWithToken("http://example.invalid", "test")
	client.cacheApprovalWait(int64((31 * time.Minute) / time.Second))

	if got := client.signRequestTimeout(); got != defaultSignRequestTimeout {
		t.Fatalf("signRequestTimeout = %s, want %s", got, defaultSignRequestTimeout)
	}
}

func TestSignRequestsDiscoversApprovalWaitBeforeSigning(t *testing.T) {
	var paths []string
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				IdentityID:          "default",
				State:               "unlocked",
				ApprovalWaitSeconds: 60,
			})
		case "/sign":
			var signReq GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&signReq); err != nil {
				t.Fatalf("decode /sign request: %v", err)
			}
			if signReq.RequestID == "" {
				t.Fatal("/sign request_id is empty")
			}
			json.NewEncoder(w).Encode(GroupSignResponse{Signed: []string{"deadbeef"}})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})
	defer server.Close()

	_, err := client.SignRequestsWithContext(context.Background(), []SignRequest{
		{AuthAddress: "AUTH", TxnBytesHex: "545801"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := strings.Join(paths, ","); got != "/status,/sign" {
		t.Fatalf("paths = %s, want /status,/sign", got)
	}
}

func TestCancelSignRequestWithContext(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/sign/cancel" {
			t.Fatalf("request = %s %s, want POST /sign/cancel", r.Method, r.URL.Path)
		}
		var cancelReq CancelSignRequest
		if err := json.NewDecoder(r.Body).Decode(&cancelReq); err != nil {
			t.Fatalf("decode cancel request: %v", err)
		}
		if cancelReq.RequestID != "sdk-test" {
			t.Fatalf("RequestID = %q, want sdk-test", cancelReq.RequestID)
		}
		json.NewEncoder(w).Encode(CancelSignResponse{Success: true, State: SignCancelStateCanceled})
	})
	defer server.Close()

	resp, err := client.CancelSignRequestWithContext(context.Background(), "sdk-test")
	if err != nil {
		t.Fatalf("CancelSignRequestWithContext() error = %v", err)
	}
	if resp.State != SignCancelStateCanceled {
		t.Fatalf("State = %q, want canceled", resp.State)
	}
}

func TestSignRequestsCancelsApprovalWhenContextCanceled(t *testing.T) {
	signStarted := make(chan string, 1)
	cancelReceived := make(chan string, 1)
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sign":
			var signReq GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&signReq); err != nil {
				t.Fatalf("decode /sign request: %v", err)
			}
			if signReq.RequestID == "" {
				t.Fatal("/sign request_id is empty")
			}
			signStarted <- signReq.RequestID
			<-r.Context().Done()
		case "/sign/cancel":
			var cancelReq CancelSignRequest
			if err := json.NewDecoder(r.Body).Decode(&cancelReq); err != nil {
				t.Fatalf("decode /sign/cancel request: %v", err)
			}
			cancelReceived <- cancelReq.RequestID
			json.NewEncoder(w).Encode(CancelSignResponse{Success: true, State: SignCancelStateCanceled})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})
	defer server.Close()

	client.cacheApprovalWait(60)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.SignRequestsWithContext(ctx, []SignRequest{{AuthAddress: "AUTH", TxnBytesHex: "545801"}})
		result <- err
	}()

	var requestID string
	select {
	case requestID = <-signStarted:
	case <-time.After(time.Second):
		t.Fatal("/sign request was not sent")
	}
	cancel()

	select {
	case got := <-cancelReceived:
		if got != requestID {
			t.Fatalf("/sign/cancel request_id = %q, want %q", got, requestID)
		}
	case <-time.After(time.Second):
		t.Fatal("/sign/cancel was not sent")
	}

	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("SignRequestsWithContext() error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SignRequestsWithContext() did not return")
	}
}

func TestSignRequestsStatusFailureFallsBackToSign(t *testing.T) {
	var paths []string
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/status":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/sign":
			json.NewEncoder(w).Encode(GroupSignResponse{Signed: []string{"deadbeef"}})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})
	defer server.Close()

	_, err := client.SignRequestsWithContext(context.Background(), []SignRequest{
		{AuthAddress: "AUTH", TxnBytesHex: "545801"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := strings.Join(paths, ","); got != "/status,/sign" {
		t.Fatalf("paths = %s, want /status,/sign", got)
	}
}

// --- ListKeys tests ---

func TestListKeys_Success(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(keysResponse{
			Count: 1,
			Keys:  []KeyInfo{{Address: "ADDR1", KeyType: "ed25519", PublicKeyHex: "abcd"}},
		})
	})
	defer server.Close()

	keys, err := client.ListKeys(true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Address != "ADDR1" {
		t.Fatalf("expected ADDR1, got %s", keys[0].Address)
	}
}

func TestListKeys_AuthError(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	})
	defer server.Close()

	_, err := client.ListKeys(true)
	if err != ErrAuthentication {
		t.Fatalf("expected ErrAuthentication, got: %v", err)
	}
}

func TestListKeys_Locked(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	})
	defer server.Close()

	_, err := client.ListKeys(true)
	if err != ErrSignerLocked {
		t.Fatalf("expected ErrSignerLocked, got: %v", err)
	}
}

func TestGetKeyInfo_NotFound(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(keysResponse{
			Count: 1,
			Keys:  []KeyInfo{{Address: "ADDR1", KeyType: "ed25519", PublicKeyHex: "abcd"}},
		})
	})
	defer server.Close()

	keyInfo, err := client.GetKeyInfo("MISSING")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	if keyInfo != nil {
		t.Fatalf("expected nil key info, got %#v", keyInfo)
	}
}

// --- ListKeyTypes tests ---

func TestListKeyTypes_Success(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(keyTypesResponse{
			KeyTypes: []KeyTypeInfo{
				{KeyType: "ed25519", DisplayName: "Ed25519", MnemonicWordCount: 25, MnemonicImport: true},
				{KeyType: "aplane.falcon1024.v1", DisplayName: "Falcon-1024", RequiresLogicSig: true, MnemonicImport: true},
			},
		})
	})
	defer server.Close()

	kts, err := client.ListKeyTypes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(kts) != 2 {
		t.Fatalf("expected 2 key types, got %d", len(kts))
	}
	if kts[0].KeyType != "ed25519" {
		t.Fatalf("expected ed25519, got %s", kts[0].KeyType)
	}
	if !kts[1].RequiresLogicSig {
		t.Fatal("expected falcon to require logicsig")
	}
	if !kts[1].MnemonicImport {
		t.Fatal("expected falcon to allow mnemonic import")
	}
}

func TestListKeyTypes_AuthError(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	})
	defer server.Close()

	_, err := client.ListKeyTypes()
	if err != ErrAuthentication {
		t.Fatalf("expected ErrAuthentication, got: %v", err)
	}
}

// --- GenerateKey tests ---

func TestGenerateKey_Success(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/admin/generate" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var req generateRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.KeyType != "ed25519" {
			t.Fatalf("expected key_type ed25519, got %s", req.KeyType)
		}
		json.NewEncoder(w).Encode(GenerateResult{Address: "NEWADDR", KeyType: "ed25519"})
	})
	defer server.Close()

	result, err := client.GenerateKey("ed25519", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Address != "NEWADDR" {
		t.Fatalf("expected NEWADDR, got %s", result.Address)
	}
}

func TestGenerateKey_WithParameters(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		var req generateRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Parameters["label"] != "my-key" {
			t.Fatalf("expected parameter label=my-key, got %s", req.Parameters["label"])
		}
		json.NewEncoder(w).Encode(GenerateResult{Address: "ADDR", KeyType: "ed25519"})
	})
	defer server.Close()

	_, err := client.GenerateKey("ed25519", map[string]string{"label": "my-key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenerateKey_AuthError(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	})
	defer server.Close()

	_, err := client.GenerateKey("ed25519", nil)
	if err != ErrAuthentication {
		t.Fatalf("expected ErrAuthentication, got: %v", err)
	}
}

func TestGenerateKey_Locked(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	})
	defer server.Close()

	_, err := client.GenerateKey("ed25519", nil)
	if err != ErrSignerLocked {
		t.Fatalf("expected ErrSignerLocked, got: %v", err)
	}
}

// --- DeleteKey tests ---

func TestDeleteKey_Success(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Fatalf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Query().Get("address") != "TESTADDR" {
			t.Fatalf("expected address=TESTADDR, got %s", r.URL.Query().Get("address"))
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	})
	defer server.Close()

	err := client.DeleteKey("TESTADDR")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteKey_NotFound(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	defer server.Close()

	err := client.DeleteKey("MISSING")
	if err != ErrKeyDeletion {
		t.Fatalf("expected ErrKeyDeletion, got: %v", err)
	}
}

func TestDeleteKey_AuthError(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	})
	defer server.Close()

	err := client.DeleteKey("ADDR")
	if err != ErrAuthentication {
		t.Fatalf("expected ErrAuthentication, got: %v", err)
	}
}

// --- PlanGroup tests ---

func TestPlanGroup_Success(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/plan" {
			t.Fatalf("expected /plan, got %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(PlanGroupResponse{
			Mutations: &MutationReport{DummiesAdded: 2, GroupIDChanged: true},
		})
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	result, err := client.PlanGroup([]types.Transaction{txn}, []string{"ADDR"}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Mutations == nil {
		t.Fatal("expected mutations")
	}
	if result.Mutations.DummiesAdded != 2 {
		t.Fatalf("expected 2 dummies, got %d", result.Mutations.DummiesAdded)
	}
}

func TestPlanGroup_AuthError(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	_, err := client.PlanGroup([]types.Transaction{txn}, []string{"ADDR"}, nil, nil)
	if err != ErrAuthentication {
		t.Fatalf("expected ErrAuthentication, got: %v", err)
	}
}

func TestPlanGroup_ServerError(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(PlanGroupResponse{Error: "key not found"})
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	_, err := client.PlanGroup([]types.Transaction{txn}, []string{"ADDR"}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "key not found") {
		t.Fatalf("expected key not found error, got: %v", err)
	}
}

// --- Signing error tests ---

func TestSign_AuthError(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	_, err := client.SignTransaction(txn, "ADDR", nil)
	if err != ErrAuthentication {
		t.Fatalf("expected ErrAuthentication, got: %v", err)
	}
}

func TestSign_Rejected(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	_, err := client.SignTransaction(txn, "ADDR", nil)
	if err != ErrSigningRejected {
		t.Fatalf("expected ErrSigningRejected, got: %v", err)
	}
}

func TestSign_Unavailable(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	_, err := client.SignTransaction(txn, "ADDR", nil)
	if err != ErrSignerUnavailable {
		t.Fatalf("expected ErrSignerUnavailable, got: %v", err)
	}
}

func TestSign_ServerError(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("internal error"))
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	_, err := client.SignTransaction(txn, "ADDR", nil)
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected 500 error, got: %v", err)
	}
}

func TestSign_ServerJSONError(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "policy engine unavailable"})
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	_, err := client.SignTransaction(txn, "ADDR", nil)
	if err == nil || !strings.Contains(err.Error(), "policy engine unavailable") {
		t.Fatalf("expected JSON error body, got: %v", err)
	}
	if strings.Contains(err.Error(), `{"error"`) {
		t.Fatalf("expected parsed JSON error message, got: %v", err)
	}
}

func TestSign_ResponseError(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(GroupSignResponse{Error: "key not found"})
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	_, err := client.SignTransaction(txn, "ADDR", nil)
	if err == nil || !strings.Contains(err.Error(), "key not found") {
		t.Fatalf("expected key not found error, got: %v", err)
	}
}

// --- Passthrough/Foreign tests ---

func TestBuildSignRequestsWithOptions_Passthrough(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	signed := base64.StdEncoding.EncodeToString([]byte("pre-signed"))

	requests, err := buildSignRequestsWithOptions(
		[]types.Transaction{txn, txn},
		[]string{"ADDR1", "ADDR2"},
		nil,
		&SignOptions{Passthrough: map[int]string{1: signed}},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requests))
	}
	if requests[0].AuthAddress != "ADDR1" {
		t.Fatal("first request should be normal sign")
	}
	if requests[1].SignedTxnHex == "" {
		t.Fatal("second request should be passthrough")
	}
	if requests[1].AuthAddress != "" {
		t.Fatal("passthrough should not have auth address")
	}
}

func TestBuildSignRequestsWithOptions_Foreign(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}

	requests, err := buildSignRequestsWithOptions(
		[]types.Transaction{txn, txn},
		[]string{"ADDR1", ""},
		nil,
		&SignOptions{LsigSizes: map[int]int{1: 5000}},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if requests[1].AuthAddress != "" {
		t.Fatal("foreign request should not have auth address")
	}
	if requests[1].TxnBytesHex == "" {
		t.Fatal("foreign request should have txn bytes")
	}
	if requests[1].LsigSize != 5000 {
		t.Fatalf("expected lsig_size 5000, got %d", requests[1].LsigSize)
	}
}

func TestBuildSignRequestsWithOptions_InvalidPassthroughBase64(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}

	_, err := buildSignRequestsWithOptions(
		[]types.Transaction{txn},
		[]string{"ADDR1"},
		nil,
		&SignOptions{Passthrough: map[int]string{0: "not-base64!!!"}},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid base64") {
		t.Fatalf("expected invalid base64 error, got: %v", err)
	}
}

func TestSignTransactionsWithOptions_RejectsForeignEntries(t *testing.T) {
	client := &SignerClient{baseURL: "http://example.invalid", token: "test", client: http.DefaultClient}
	txn := types.Transaction{Type: types.PaymentTx}

	_, err := client.SignTransactionsWithOptions(
		[]types.Transaction{txn, txn},
		[]string{"AUTH1", ""},
		nil,
		&SignOptions{LsigSizes: map[int]int{1: 5000}},
	)
	if err == nil || !strings.Contains(err.Error(), "foreign entries are only supported on /plan") {
		t.Fatalf("expected foreign /plan-only error, got %v", err)
	}
}

func TestSignTransactionsListWithOptions_RejectsForeignEntries(t *testing.T) {
	client := &SignerClient{baseURL: "http://example.invalid", token: "test", client: http.DefaultClient}
	txn := types.Transaction{Type: types.PaymentTx}

	_, err := client.SignTransactionsListWithOptions(
		[]types.Transaction{txn, txn},
		[]string{"AUTH1", ""},
		nil,
		&SignOptions{LsigSizes: map[int]int{1: 5000}},
	)
	if err == nil || !strings.Contains(err.Error(), "foreign entries are only supported on /plan") {
		t.Fatalf("expected foreign /plan-only error, got %v", err)
	}
}

// --- AssembleGroup tests ---

func TestAssembleGroup_MergesTwoSigners(t *testing.T) {
	s1 := base64.StdEncoding.EncodeToString([]byte("signed-A"))
	s2 := base64.StdEncoding.EncodeToString([]byte("signed-B"))

	result, err := AssembleGroup([][]string{
		{s1, ""},
		{"", s2},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	decoded, _ := base64.StdEncoding.DecodeString(result)
	if string(decoded) != "signed-Asigned-B" {
		t.Fatalf("expected 'signed-Asigned-B', got %q", decoded)
	}
}

func TestAssembleGroup_Empty(t *testing.T) {
	_, err := AssembleGroup([][]string{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestAssembleGroup_MismatchedLengths(t *testing.T) {
	_, err := AssembleGroup([][]string{
		{"a", "b"},
		{"c"},
	})
	if err == nil || !strings.Contains(err.Error(), "expected 2") {
		t.Fatalf("expected length mismatch error, got: %v", err)
	}
}

func TestAssembleGroup_NoSigner(t *testing.T) {
	_, err := AssembleGroup([][]string{
		{"", ""},
		{"", ""},
	})
	if err == nil || !strings.Contains(err.Error(), "no signer") {
		t.Fatalf("expected no signer error, got: %v", err)
	}
}

func TestAssembleGroup_MultipleSigners(t *testing.T) {
	s := base64.StdEncoding.EncodeToString([]byte("x"))
	_, err := AssembleGroup([][]string{
		{s, ""},
		{s, ""},
	})
	if err == nil || !strings.Contains(err.Error(), "multiple signers") {
		t.Fatalf("expected multiple signers error, got: %v", err)
	}
}

// --- Config tests ---

func TestLoadConfig_Default(t *testing.T) {
	dir := t.TempDir()
	config, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if config.SignerPort != DefaultSignerPort {
		t.Fatalf("expected default port %d, got %d", DefaultSignerPort, config.SignerPort)
	}
	if config.SSH != nil {
		t.Fatal("expected no SSH config")
	}
}

func TestLoadConfig_WithSSH(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(
		"signer_port: 11271\nssh:\n  host: example.com\n  port: 1128\n  identity_file: .ssh/id\n  trust_on_first_use: true\n",
	), 0600)

	config, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if config.SSH == nil {
		t.Fatal("expected SSH config")
	}
	if config.SSH.Host != "example.com" {
		t.Fatalf("expected example.com, got %s", config.SSH.Host)
	}
	if !config.SSH.TrustOnFirstUse {
		t.Fatal("expected trust_on_first_use true")
	}
}

func TestLoadConfig_TrustOnFirstUseDefaultsFalse(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(
		"signer_port: 11270\nssh:\n  host: localhost\n  port: 1127\n",
	), 0600)

	config, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if config.SSH.TrustOnFirstUse {
		t.Fatal("expected trust_on_first_use to default to false")
	}
}

func TestLoadConfig_ParseError(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("ssh:\n  host: [\n"), 0600)

	_, err := LoadConfig(dir)
	if err == nil || !strings.Contains(err.Error(), "failed to parse config.yaml") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

// --- Encoding tests ---

func TestHexRoundTrip(t *testing.T) {
	original := []byte("hello world")
	h := BytesToHex(original)
	decoded, err := HexToBytes(h)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != string(original) {
		t.Fatalf("round trip failed: got %q", decoded)
	}
}

func TestBase64RoundTrip(t *testing.T) {
	original := []byte("hello world")
	b := BytesToBase64(original)
	decoded, err := Base64ToBytes(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != string(original) {
		t.Fatalf("round trip failed: got %q", decoded)
	}
}

func TestHexRoundTrip_Empty(t *testing.T) {
	h := BytesToHex([]byte{})
	if h != "" {
		t.Fatalf("expected empty string, got %q", h)
	}
	decoded, err := HexToBytes("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(decoded) != 0 {
		t.Fatalf("expected empty bytes, got %v", decoded)
	}
}

func TestBase64RoundTrip_Empty(t *testing.T) {
	b := BytesToBase64([]byte{})
	decoded, err := Base64ToBytes(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(decoded) != 0 {
		t.Fatalf("expected empty bytes, got %v", decoded)
	}
}

func TestHexArrayToBase64(t *testing.T) {
	h1 := hex.EncodeToString([]byte("AB"))
	h2 := hex.EncodeToString([]byte("CD"))
	result, err := hexArrayToBase64([]string{h1, h2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	decoded, _ := base64.StdEncoding.DecodeString(result)
	if string(decoded) != "ABCD" {
		t.Fatalf("expected ABCD, got %q", decoded)
	}
}

func TestHexArrayToBase64_Single(t *testing.T) {
	h := hex.EncodeToString([]byte{0xde, 0xad, 0xbe, 0xef})
	result, err := hexArrayToBase64([]string{h})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	decoded, _ := base64.StdEncoding.DecodeString(result)
	expected := []byte{0xde, 0xad, 0xbe, 0xef}
	if string(decoded) != string(expected) {
		t.Fatalf("expected %x, got %x", expected, decoded)
	}
}

func TestSignRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		request SignRequest
		wantErr string
	}{
		{name: "sign mode", request: SignRequest{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}},
		{name: "foreign mode", request: SignRequest{TxnBytesHex: "deadbeef"}},
		{name: "passthrough mode", request: SignRequest{SignedTxnHex: "cafebabe"}},
		{name: "conflict", request: SignRequest{AuthAddress: "ADDR", TxnBytesHex: "deadbeef", SignedTxnHex: "cafebabe"}, wantErr: "cannot specify both sign fields"},
		{name: "auth only", request: SignRequest{AuthAddress: "ADDR"}, wantErr: "txn_bytes_hex is required for sign mode"},
		{name: "empty", request: SignRequest{}, wantErr: "must specify either sign fields"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
