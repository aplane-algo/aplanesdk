// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestFromEnv_RequiresDefaultEndpoint(t *testing.T) {
	dir := t.TempDir()

	_, err := FromEnv(&FromEnvOptions{DataDir: dir})
	if err == nil {
		t.Fatal("expected error when no endpoint is configured")
	}
	if !strings.Contains(err.Error(), "no default signer endpoint") {
		t.Fatalf("unexpected error: %s", err)
	}
}

// FromEnv selects the named endpoint and connects with its SSH identity; the
// key is the only credential, so a missing identity file is the first
// failure.
func TestFromEnv_UsesNamedEndpointIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "endpoints.yaml"), []byte(`
schema_version: 2
endpoints:
  primary:
    role: signer
    url: ssh://signer.example.com/
  qa:
    role: cosigner
    url: ssh://127.0.0.1:1/
    identity_file: keys/qa
`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := FromEnv(&FromEnvOptions{DataDir: dir, Endpoint: "qa", Timeout: 7})
	wantKey := filepath.Join(dir, "keys", "qa")
	if err == nil || !strings.Contains(err.Error(), "failed to read SSH key") || !strings.Contains(err.Error(), wantKey) {
		t.Fatalf("FromEnv error = %v, want the qa identity %q to be read", err, wantKey)
	}
}

// RequestEnrollmentFromEnv resolves the endpoint's identity before any
// network activity and tells the caller how to create a missing key.
func TestRequestEnrollmentFromEnv_RequiresIdentityFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "endpoints.yaml"), []byte(`
schema_version: 2
endpoints:
  primary:
    role: signer
    url: ssh://signer.example.com
  qa:
    role: cosigner
    url: ssh://cosigner.example.com:2222
    identity_file: .ssh/qa
`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := RequestEnrollmentFromEnv(&FromEnvOptions{DataDir: dir, Endpoint: "qa"}, "")
	wantKey := filepath.Join(dir, ".ssh", "qa")
	if err == nil || !strings.Contains(err.Error(), "SSH key not found at "+wantKey) {
		t.Fatalf("RequestEnrollmentFromEnv error = %v, want missing key %q", err, wantKey)
	}
}

// The signer answers an enrollment request at once: queued for the operator
// (pending) or already enrolled. Either way the fingerprint must be the
// authenticating key's.
func TestParseEnrollmentReply(t *testing.T) {
	const fp = "SHA256:abc"
	for _, tc := range []struct {
		reply   string
		want    EnrollmentResult
		wantErr string
	}{
		{reply: "pending " + fp, want: EnrollmentResult{Fingerprint: fp, Pending: true}},
		{reply: "enrolled " + fp, want: EnrollmentResult{Fingerprint: fp}},
		{reply: "pending SHA256:other", wantErr: "this client authenticated with " + fp},
		{reply: "enrolled ", wantErr: "unexpected response"},
		{reply: "ok " + fp, wantErr: "unexpected response"},
		{reply: "", wantErr: "unexpected response"},
	} {
		got, err := parseEnrollmentReply(tc.reply, fp)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !errors.Is(err, ErrEnrollment) {
				t.Fatalf("parseEnrollmentReply(%q) error = %v, want ErrEnrollment with %q", tc.reply, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("parseEnrollmentReply(%q) = %+v, %v; want %+v", tc.reply, got, err, tc.want)
		}
	}
}

func TestRequestEnrollmentRejectsBadLabelsLocally(t *testing.T) {
	for _, label := range []string{strings.Repeat("x", 65), "two\nlines", " padded", "tab\tbed"} {
		if _, err := RequestEnrollment("signer.example.com", "/nonexistent/key", label, &EnrollmentOptions{KnownHostsPath: "/nonexistent/known_hosts"}); err == nil || !strings.Contains(err.Error(), "enrollment label") {
			t.Fatalf("RequestEnrollment(label=%q) error = %v, want label rejection", label, err)
		}
	}
	if _, err := RequestEnrollment("signer.example.com", "/nonexistent/key", "laptop", nil); err == nil || !strings.Contains(err.Error(), "known_hosts path is required") {
		t.Fatalf("RequestEnrollment() error = %v, want known_hosts requirement", err)
	}
}

func TestFromEnvRejectsInvalidEndpointBeforeConnecting(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		want    string
	}{
		{"invalid_self_signer.yaml", `endpoint "primary": url "self" is not supported`},
		{"invalid_self_cosigner.yaml", `endpoint "cosigner": url "self" is not supported`},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			_, err := FromEnv(&FromEnvOptions{DataDir: copyEndpointFixture(t, tc.fixture)})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("FromEnv error = %v, want %q before connecting", err, tc.want)
			}
		})
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

	requests, err := buildSignRequests(
		[]types.Transaction{txn},
		[]string{sdkTestAddress(0xA2)},
		nil,
	)
	if err != nil {
		t.Fatalf("buildSignRequests() error = %v", err)
	}

	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}
	if requests[0].AuthAddress != sdkTestAddress(0xA2) {
		t.Fatalf("expected auth address AUTH_ADDR, got %s", requests[0].AuthAddress)
	}
}

func TestBuildSignRequests_DefaultAuthAddress(t *testing.T) {
	txn := types.Transaction{}
	txn.Type = types.PaymentTx

	requests, err := buildSignRequests(
		[]types.Transaction{txn},
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("buildSignRequests() error = %v", err)
	}

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

	requests, err := buildSignRequests(
		[]types.Transaction{txn},
		nil,
		LsigArgsMap{authAddr: LsigArgs{"preimage": []byte("secret")}},
	)
	if err != nil {
		t.Fatalf("buildSignRequests() error = %v", err)
	}

	if requests[0].LsigArgs == nil {
		t.Fatal("expected lsig args")
	}
	if requests[0].LsigArgs["preimage"] != hex.EncodeToString([]byte("secret")) {
		t.Fatal("lsig args mismatch")
	}
}

func TestSignTransactions_ReturnsRawEntries(t *testing.T) {
	client, server := newTestClient(fakeSignHandler(t, fakeSigner{}))
	defer server.Close()

	txn1 := verifyTestPayment(t, 41, 42, 1)
	txn2 := verifyTestPayment(t, 43, 44, 2)

	result, err := client.SignTransactions(
		[]types.Transaction{txn1, txn2},
		nil, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result))
	}

	// Each entry is one signed transaction's msgpack bytes and signs its own
	// transaction, changed only by the group ID the signer assigned.
	for i, want := range []types.Transaction{txn1, txn2} {
		stxn, err := decodeCanonicalSignedTxn(result[i])
		if err != nil {
			t.Fatalf("result[%d]: %v", i, err)
		}
		if stxn.Txn.Group == (types.Digest{}) {
			t.Fatalf("result[%d] carries no group ID", i)
		}
		want.Group = stxn.Txn.Group
		if !bytes.Equal(encodeTxn(stxn.Txn), encodeTxn(want)) {
			t.Fatalf("result[%d] signs a different transaction", i)
		}
	}
}

// TestSignTransactions_RejectsTruncatedResponse pins that the high-level sign
// path (sign via signResponse) validates the signer reply: a response with
// fewer signed slots than requests, or an empty non-foreign slot, is rejected
// rather than silently yielding a partial group.
func TestSignTransactions_RejectsTruncatedResponse(t *testing.T) {
	cases := map[string]func(resp *GroupSignResponse){
		"too few slots":     func(resp *GroupSignResponse) { resp.Signed = resp.Signed[:1] },
		"empty signed slot": func(resp *GroupSignResponse) { resp.Signed[1] = "" },
	}
	for name, truncate := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/sign" {
					json.NewEncoder(w).Encode(StatusResponse{State: "unlocked", ApprovalWaitSeconds: 60})
					return
				}
				var req GroupSignRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Errorf("decode sign request: %v", err)
				}
				resp := fakeSigner{}.sign(t, req.Requests)
				truncate(&resp)
				json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			client := &SignerClient{baseURL: server.URL, client: http.DefaultClient}
			_, err := client.SignTransactions(
				[]types.Transaction{verifyTestPayment(t, 41, 42, 1), verifyTestPayment(t, 43, 44, 2)},
				nil, nil,
			)
			if err == nil {
				t.Fatal("SignTransactions() error = nil, want truncated-response rejection")
			}
		})
	}
}

// SignTransaction returns the whole signed group: the caller's transaction
// first, then the resource dummies the signer appended.
func TestSignTransaction_ReturnsTheWholeGroup(t *testing.T) {
	client, server := newTestClient(fakeSignHandler(t, fakeSigner{dummies: 2}))
	defer server.Close()

	txn := verifyTestPayment(t, 41, 42, 1)
	single, err := client.SignTransaction(txn, "", nil)
	if err != nil {
		t.Fatalf("SignTransaction() error = %v", err)
	}
	if len(single) != 3 {
		t.Fatalf("SignTransaction() returned %d entries, want the transaction and 2 dummies", len(single))
	}
	first, err := decodeCanonicalSignedTxn(single[0])
	if err != nil {
		t.Fatal(err)
	}
	want := txn
	want.Group = first.Txn.Group
	if want.Group == (types.Digest{}) || !bytes.Equal(encodeTxn(first.Txn), encodeTxn(want)) {
		t.Fatal("the first entry is not the caller's transaction in the signer's group")
	}
	for i, entry := range single[1:] {
		dummy, err := decodeCanonicalSignedTxn(entry)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dummy.Lsig.Logic, cosignedDummyProgram) {
			t.Fatalf("entry %d is not a resource dummy", i+1)
		}
	}
	group, err := client.SignTransactions([]types.Transaction{txn}, nil, nil)
	if err != nil {
		t.Fatalf("SignTransactions() error = %v", err)
	}
	if !reflect.DeepEqual(single, group) {
		t.Fatal("SignTransaction() and SignTransactions() of one transaction differ")
	}
}

func TestSignTransactions_RejectsEmptySlice(t *testing.T) {
	client := &SignerClient{baseURL: "http://example.invalid", client: http.DefaultClient}

	_, err := client.SignTransactions(nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "requests array is empty") {
		t.Fatalf("expected empty transaction error, got %v", err)
	}
}

// --- Health tests ---

func newTestClient(handler http.HandlerFunc) (*SignerClient, *httptest.Server) {
	server := httptest.NewServer(handler)
	return &SignerClient{
		baseURL: server.URL,
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
		// The connection, not a header, carries the client's identity.
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, want none", got)
		}
		json.NewEncoder(w).Encode(StatusResponse{
			State:               "unlocked",
			ReadyForSigning:     true,
			KeyCount:            37,
			KeysetRevision:      4,
			ApprovalWaitSeconds: 60,
		})
	})
	defer server.Close()

	status, err := client.GetStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.KeysetRevision != 4 {
		t.Fatalf("KeysetRevision = %d, want 4", status.KeysetRevision)
	}
	if status.ApprovalWaitSeconds != 60 {
		t.Fatalf("ApprovalWaitSeconds = %d, want 60", status.ApprovalWaitSeconds)
	}
}

func TestGetStatus_LockedStateIsSuccess(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(StatusResponse{
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
	client := NewSignerClient("http://example.invalid")
	client.cacheApprovalWait(120)

	if got := client.signRequestTimeout(); got != 150*time.Second {
		t.Fatalf("signRequestTimeout = %s, want 150s", got)
	}
}

func TestSignRequestTimeoutFallsBackForInvalidApprovalWait(t *testing.T) {
	client := NewSignerClient("http://example.invalid")
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
			json.NewEncoder(w).Encode(fakeSigner{}.sign(t, signReq.Requests))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})
	defer server.Close()

	_, err := client.SignRequestsWithContext(context.Background(), signRequestsFor(verifyTestPayment(t, 41, 42, 1)))
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
		_, err := client.SignRequestsWithContext(ctx, signRequestsFor(verifyTestPayment(t, 41, 42, 1)))
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

// roundTripFunc is an http.RoundTripper that never touches the network.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// recordingClient is a client whose transport records every request handed
// to it, even one whose context has ended, which it then refuses as a real
// transport would. It answers every other request with body.
func recordingClient(body string) (*SignerClient, func() []string) {
	var mu sync.Mutex
	var paths []string
	client := &SignerClient{
		baseURL: "http://signer.invalid",
		client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			mu.Lock()
			paths = append(paths, r.URL.Path)
			mu.Unlock()
			if err := r.Context().Err(); err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    r,
			}, nil
		})},
	}
	return client, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

// A context that has ended before an approval-bearing call hands the
// transport nothing: no status discovery, no approval request, and no
// /sign/cancel for a request that was never posted.
func TestApprovalRequestWithEndedContextSendsNothing(t *testing.T) {
	calls := map[string]func(context.Context, *SignerClient) error{
		"sign": func(ctx context.Context, c *SignerClient) error {
			_, err := c.SignRequestsWithContext(ctx, signRequestsFor(verifyTestPayment(t, 41, 42, 1)))
			return err
		},
		"component": func(ctx context.Context, c *SignerClient) error {
			_, err := c.RequestComponentsWithContext(ctx, ComponentRequest{
				RequestID:     "ended-context-id",
				GroupBytesHex: []string{"545801"},
				Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindBoundedBase, AuthAddress: "AUTH"}},
			})
			return err
		},
		"cosigner component": func(ctx context.Context, c *SignerClient) error {
			_, err := c.RequestComponentsWithContext(ctx, ComponentRequest{
				GroupBytesHex: []string{"545801"},
				Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindCosigner, ComponentKey: "COMPONENT"}},
			})
			return err
		},
		"assemble": func(ctx context.Context, c *SignerClient) error {
			_, err := c.RequestAssembleWithContext(ctx, AssemblyRequest{
				GroupBytesHex: []string{"5458aa"},
				Targets: []AssemblyTarget{{
					TargetIndex: 0, Kind: AssemblyTargetKindBoundedCosigner, AuthAddress: "BOUNDED",
					BaseSignatures: []string{"aabb"}, AssemblyReceipt: "eeff", CosignerSignature: "bbcc",
				}},
			})
			return err
		},
		"rotating sign": func(ctx context.Context, c *SignerClient) error {
			vector := loadRotatingVectors(t).Cases["wotsc_stage0"]
			prepared, err := preparedFromVector(vector, vector.Prepare)
			if err != nil {
				t.Fatalf("captured prepare answer refused: %v", err)
			}
			_, err = c.SignPreparedRotating(ctx, prepared, nil)
			var unknown *SignOutcomeUnknownError
			if errors.As(err, &unknown) {
				t.Errorf("rotating sign with an ended context = %v, want a plain stop", err)
			}
			return err
		},
	}
	for name, call := range calls {
		for _, waitKnown := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, approval wait known %v", name, waitKnown), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					client, paths := recordingClient(`{"success":true,"state":"not_found"}`)
					if waitKnown {
						client.cacheApprovalWait(60)
					}
					ctx, cancel := context.WithCancel(context.Background())
					cancel()

					err := call(ctx, client)
					var lost *lostAnswer
					if !errors.Is(err, context.Canceled) || errors.As(err, &lost) {
						t.Fatalf("error = %v, want a plain context.Canceled", err)
					}
					// Every goroutine the call started has finished or blocked.
					synctest.Wait()
					if got := paths(); len(got) != 0 {
						t.Fatalf("requests sent = %v, want none", got)
					}
				})
			})
		}
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
			var signReq GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&signReq); err != nil {
				t.Fatalf("decode /sign request: %v", err)
			}
			json.NewEncoder(w).Encode(fakeSigner{}.sign(t, signReq.Requests))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})
	defer server.Close()

	_, err := client.SignRequestsWithContext(context.Background(), signRequestsFor(verifyTestPayment(t, 41, 42, 1)))
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
			Keys:  []KeyInfo{{Address: sdkTestAddress(0xA3), KeyType: "ed25519", PublicKeyHex: "abcd"}},
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
	if keys[0].Address != sdkTestAddress(0xA3) {
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
		writeCodedError(w, 403, ErrCodeLocked, "signer is locked")
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
			Keys:  []KeyInfo{{Address: sdkTestAddress(0xA3), KeyType: "ed25519", PublicKeyHex: "abcd"}},
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

// The key inventory a send routes on is read by the rule the signing answers
// are: a null body or trailing data is an error, not an empty key list.
func TestListKeysRefusesNullAndTrailingData(t *testing.T) {
	key := `{"address":"` + sdkTestAddress(0xA3) + `","key_type":"ed25519","public_key_hex":"abcd"}`
	for name, body := range map[string]string{
		"null":          "null",
		"spaced null":   " null\n",
		"trailing data": `{"count":1,"keys":[` + key + `]}{"count":0,"keys":[]}`,
		"trailing junk": `{"count":1,"keys":[` + key + `]} x`,
	} {
		t.Run(name, func(t *testing.T) {
			client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(body))
			})
			defer server.Close()

			if result, err := client.GetKeysResponseWithContext(context.Background()); err == nil || !strings.Contains(err.Error(), "failed to decode response") {
				t.Fatalf("GetKeysResponseWithContext() = %+v, %v; want a decode error", result, err)
			}
			if keys, err := client.ListKeys(true); err == nil {
				t.Fatalf("ListKeys() = %v, nil; want an error", keys)
			}
		})
	}
}

// otherSpelling is address with a padding bit of its last character set: the
// same 36 bytes, checksum and all, spelled another way.
func otherSpelling(t *testing.T, address string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	last := strings.IndexByte(alphabet, address[len(address)-1])
	other := address[:len(address)-1] + string(alphabet[last^1])
	if _, err := types.DecodeAddress(other); err == nil {
		t.Fatalf("%s decodes as an address", other)
	}
	return other
}

// A /keys answer that lists an Algorand address spelled another way is
// refused whole: a lookup by the canonical address would never find the key.
// Text that is not an Algorand address, such as a witness key's ID, is kept
// exactly as sent.
func TestListKeysRefusesAnAddressSpelledAnotherWay(t *testing.T) {
	canonical := sdkTestAddress(0xA3)
	other := otherSpelling(t, canonical)
	badChecksum := canonical[:len(canonical)-2] + "AA"
	if canonical[len(canonical)-2:] == "AA" {
		badChecksum = canonical[:len(canonical)-2] + "BA"
	}
	answer := func(addresses ...string) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			keys := make([]KeyInfo, len(addresses))
			for i, address := range addresses {
				keys[i] = KeyInfo{Address: address, KeyType: "ed25519"}
			}
			json.NewEncoder(w).Encode(KeysResponse{Count: len(keys), Keys: keys})
		}
	}

	t.Run("an alternate spelling", func(t *testing.T) {
		client, server := newTestClient(answer(sdkTestAddress(0xA4), other))
		defer server.Close()
		result, err := client.GetKeysResponseWithContext(context.Background())
		want := fmt.Sprintf("failed to decode response: key 1 address %q is a non-canonical spelling of address %s", other, canonical)
		if result != nil || err == nil || err.Error() != want {
			t.Fatalf("GetKeysResponseWithContext() = %+v, %v; want %q", result, err, want)
		}
		if client.cachedKeys() != nil {
			t.Fatal("a refused answer was cached")
		}
		if _, err := client.ListKeys(true); err == nil {
			t.Fatal("ListKeys() accepted the answer")
		}
	})

	witnessID := "ROGAFDACF7ASC3EMZRWNKVM73NXHO4P6O4EB7ZXWER37SM63BMFQ"
	kept := []string{canonical, witnessID, "BOUNDEDADDR000000000000000000000000000000000000000000000", strings.ToLower(canonical), badChecksum, ""}
	t.Run("anything else is kept as sent", func(t *testing.T) {
		client, server := newTestClient(answer(kept...))
		defer server.Close()
		result, err := client.GetKeysResponseWithContext(context.Background())
		if err != nil {
			t.Fatalf("GetKeysResponseWithContext() error = %v", err)
		}
		for i, address := range kept {
			if result.Keys[i].Address != address {
				t.Fatalf("key %d address = %q, want %q as sent", i, result.Keys[i].Address, address)
			}
			if info, err := client.GetKeyInfo(address); err != nil || info.Address != address {
				t.Fatalf("GetKeyInfo(%q) = %+v, %v", address, info, err)
			}
		}
	})
}

// Every /keys contract fixture is an answer the client reads.
func TestListKeysReadsTheContractFixtures(t *testing.T) {
	matches, err := filepath.Glob(sdkContractFixturePath(t, "keys_response_*.json"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("keys fixtures = %v, %v", matches, err)
	}
	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) { w.Write(raw) })
			defer server.Close()
			result, err := client.GetKeysResponseWithContext(context.Background())
			if err != nil || len(result.Keys) == 0 {
				t.Fatalf("GetKeysResponseWithContext() = %+v, %v", result, err)
			}
		})
	}
}

// Every other 200 answer is read by the same rule.
func TestSignerAnswersRefuseNullAndTrailingData(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	requests := signRequestsFor(txn)
	plan, err := json.Marshal(fakeSigner{}.plan(t, requests))
	if err != nil {
		t.Fatal(err)
	}
	endpoints := []struct {
		path  string
		valid string
		call  func(*SignerClient) error
	}{
		{"/status", `{"state":"unlocked","keyset_revision":3}`, func(c *SignerClient) error {
			_, err := c.GetStatusWithContext(context.Background())
			return err
		}},
		{"/keytypes", `{"key_types":[{"key_type":"ed25519"}]}`, func(c *SignerClient) error {
			_, err := c.ListKeyTypes()
			return err
		}},
		{"/admin/generate", `{"address":"` + sdkTestAddress(0xA3) + `"}`, func(c *SignerClient) error {
			_, err := c.GenerateKey("ed25519", nil)
			return err
		}},
		{"/plan", string(plan), func(c *SignerClient) error {
			_, err := c.PlanRequestsWithContext(context.Background(), requests)
			return err
		}},
		{"/sign/cancel", `{"success":true,"state":"canceled"}`, func(c *SignerClient) error {
			_, err := c.CancelSignRequestWithContext(context.Background(), "sdk-test")
			return err
		}},
		{"/admin/keys", `{"success":true}`, func(c *SignerClient) error {
			return c.DeleteKey(sdkTestAddress(0xA3))
		}},
	}
	for _, endpoint := range endpoints {
		for name, body := range map[string]string{
			"valid":         endpoint.valid,
			"null":          "null",
			"trailing data": endpoint.valid + endpoint.valid,
		} {
			t.Run(strings.TrimPrefix(endpoint.path, "/")+" "+name, func(t *testing.T) {
				client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != endpoint.path {
						t.Errorf("path = %s, want %s", r.URL.Path, endpoint.path)
					}
					w.Write([]byte(body))
				})
				defer server.Close()

				err := endpoint.call(client)
				if name == "valid" {
					if err != nil {
						t.Fatalf("valid answer refused: %v", err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), "failed to decode response") {
					t.Fatalf("error = %v, want a decode error", err)
				}
			})
		}
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

// valid_rekey_target is read from /keys and /keytypes: true and false as sent,
// left out or null as false, and any other type makes the answer unreadable.
func TestValidRekeyTargetIsRead(t *testing.T) {
	address := sdkTestAddress(0xA3)
	cases := []struct {
		name  string
		field string
		want  bool
	}{
		{"true", `,"valid_rekey_target":true`, true},
		{"false", `,"valid_rekey_target":false`, false},
		{"absent", ``, false},
		{"null", `,"valid_rekey_target":null`, false},
	}
	for _, tc := range cases {
		t.Run("keys "+tc.name, func(t *testing.T) {
			body := `{"count":1,"keys":[{"address":"` + address + `","key_type":"ed25519"` + tc.field + `}]}`
			client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
			defer server.Close()
			keys, err := client.ListKeys(true)
			if err != nil || len(keys) != 1 {
				t.Fatalf("ListKeys() = %+v, %v", keys, err)
			}
			if keys[0].ValidRekeyTarget != tc.want {
				t.Fatalf("ValidRekeyTarget = %v, want %v", keys[0].ValidRekeyTarget, tc.want)
			}
		})
		t.Run("keytypes "+tc.name, func(t *testing.T) {
			body := `{"key_types":[{"key_type":"ed25519"` + tc.field + `}]}`
			client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
			defer server.Close()
			kts, err := client.ListKeyTypes()
			if err != nil || len(kts) != 1 {
				t.Fatalf("ListKeyTypes() = %+v, %v", kts, err)
			}
			if kts[0].ValidRekeyTarget != tc.want {
				t.Fatalf("ValidRekeyTarget = %v, want %v", kts[0].ValidRekeyTarget, tc.want)
			}
		})
	}
	for _, wrong := range []string{`"true"`, `1`, `{}`} {
		t.Run("keys wrong type "+wrong, func(t *testing.T) {
			body := `{"count":1,"keys":[{"address":"` + address + `","key_type":"ed25519","valid_rekey_target":` + wrong + `}]}`
			client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
			defer server.Close()
			if result, err := client.GetKeysResponseWithContext(context.Background()); err == nil || !strings.Contains(err.Error(), "failed to decode response") {
				t.Fatalf("GetKeysResponseWithContext() = %+v, %v; want a decode error", result, err)
			}
		})
		t.Run("keytypes wrong type "+wrong, func(t *testing.T) {
			body := `{"key_types":[{"key_type":"ed25519","valid_rekey_target":` + wrong + `}]}`
			client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
			defer server.Close()
			if kts, err := client.ListKeyTypes(); err == nil || !strings.Contains(err.Error(), "failed to decode response") {
				t.Fatalf("ListKeyTypes() = %+v, %v; want a decode error", kts, err)
			}
		})
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
		json.NewEncoder(w).Encode(GenerateResult{Address: sdkTestAddress(0xA0), KeyType: "ed25519"})
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
		writeCodedError(w, 403, ErrCodeLocked, "signer is locked")
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
		// What the signer's handler writes.
		w.Write([]byte("{\"success\":true}\n"))
	})
	defer server.Close()

	err := client.DeleteKey("TESTADDR")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A generate answer is the new key: one that carries an error, or names no
// address, is refused.
func TestGenerateKeyRefusesAnErrorOrNoAddress(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"address":"` + sdkTestAddress(0xA3) + `","error":"denied"}`, "key generation failed: denied"},
		{`{}`, "key generation failed: missing address"},
		{`{"address":"","key_type":"ed25519"}`, "key generation failed: missing address"},
		{`{"address":null}`, "key generation failed: missing address"},
	} {
		t.Run(tc.body, func(t *testing.T) {
			client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			})
			defer server.Close()
			if result, err := client.GenerateKey("ed25519", nil); err == nil || err.Error() != tc.want {
				t.Fatalf("GenerateKey() = %+v, %v; want %q", result, err, tc.want)
			}
		})
	}
}

// A delete answer is read as {success, error}: an error is a refusal, and a
// body that is not one such object is no answer. The signer always sends one.
func TestDeleteKeyReadsItsAnswer(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"success":true}`, ""},
		{`{"success":true,"extra":1}`, ""},
		{`{"success":false,"error":"denied"}`, "key deletion failed: denied"},
		{``, "failed to decode response"},
		{`null`, "failed to decode response"},
		{`[]`, "failed to decode response"},
		{`{"success":"yes"}`, "failed to decode response"},
		{`{"success":true} x`, "failed to decode response"},
	} {
		t.Run(tc.body, func(t *testing.T) {
			client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			})
			defer server.Close()
			err := client.DeleteKey(sdkTestAddress(0xA3))
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("DeleteKey() = %v, want success", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("DeleteKey() = %v, want %q", err, tc.want)
			}
		})
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

	err := client.DeleteKey(sdkTestAddress(0xA0))
	if err != ErrAuthentication {
		t.Fatalf("expected ErrAuthentication, got: %v", err)
	}
}

func TestRequestComponentsPostsToComponentEndpoint(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/sign/component" {
			t.Fatalf("request = %s %s, want POST /sign/component", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, want none", got)
		}
		var req ComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode component request: %v", err)
		}
		if req.RequestID == "" {
			t.Fatal("request_id was not populated")
		}
		if len(req.Targets) != 1 || req.Targets[0].Kind != ComponentTargetKindCosigner || req.Targets[0].ComponentKey != "COMPONENT" {
			t.Fatalf("component request = %+v", req)
		}
		json.NewEncoder(w).Encode(ComponentResponse{
			RequestID: req.RequestID,
			Components: []Component{{Kind: ComponentTargetKindCosigner,
				TargetIndex:     0,
				Signature:       "aabb",
				SignatureScheme: KeyTypeWitnessFalcon1024,
			}},
		})
	})
	defer server.Close()

	resp, err := client.RequestComponents(ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindCosigner, ComponentKey: "COMPONENT"}},
	})
	if err != nil {
		t.Fatalf("RequestComponents() error = %v", err)
	}
	if len(resp.Components) != 1 || resp.Components[0].Signature != "aabb" {
		t.Fatalf("component response = %+v", resp)
	}
}

func TestRequestComponentsRejectsMalformedResponse(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ComponentResponse{RequestID: "sdk-test"})
	})
	defer server.Close()

	_, err := client.RequestComponents(ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindCosigner}},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid component response") {
		t.Fatalf("expected malformed response error, got %v", err)
	}
}

func TestRequestComponentsRejectsUnrequestedTargetKind(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		var req ComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		json.NewEncoder(w).Encode(ComponentResponse{
			RequestID: req.RequestID,
			Components: []Component{{
				TargetIndex: 0, Kind: ComponentTargetKindBoundedBase, AuthAddress: "BOUNDED",
				BaseSignatures: []string{"aabb"}, AssemblyReceipt: "ccdd", SignatureScheme: KeyTypeWitnessFalcon1024,
				Path: ComponentPathSpend,
			}},
		})
	})
	defer server.Close()

	_, err := client.RequestComponents(ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets: []ComponentTarget{{
			TargetIndex: 0, Kind: ComponentTargetKindCosigner, ComponentKey: "COMPONENT",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "indices or kinds do not match") {
		t.Fatalf("expected mismatched target error, got %v", err)
	}
}

func TestRequestComponentsRejected(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		writeCodedError(w, 403, ErrCodeForbidden, "rejected by signer policy")
	})
	defer server.Close()

	_, err := client.RequestComponents(ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindCosigner}},
	})
	if err != ErrSigningRejected {
		t.Fatalf("expected ErrSigningRejected, got %v", err)
	}
}

func TestRequestAssemblePostsToAssembleEndpoint(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/sign/assemble" {
			t.Fatalf("request = %s %s, want POST /sign/assemble", r.Method, r.URL.Path)
		}
		var req AssemblyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode assembly request: %v", err)
		}
		if req.RequestID == "" {
			t.Fatal("request_id was not populated")
		}
		if len(req.Targets) != 1 || req.Targets[0].Kind != AssemblyTargetKindBoundedCosigner || req.Targets[0].AuthAddress != "BOUNDED" {
			t.Fatalf("assembly targets = %+v", req.Targets)
		}
		json.NewEncoder(w).Encode(AssemblyResponse{
			RequestID:   req.RequestID,
			SignedGroup: []string{"ccdd"},
		})
	})
	defer server.Close()

	resp, err := client.RequestAssemble(AssemblyRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets: []AssemblyTarget{{
			TargetIndex:       0,
			Kind:              AssemblyTargetKindBoundedCosigner,
			AuthAddress:       "BOUNDED",
			BaseSignatures:    []string{"aabb"},
			AssemblyReceipt:   "eeff",
			CosignerSignature: "bbcc",
		}},
	})
	if err != nil {
		t.Fatalf("RequestAssemble() error = %v", err)
	}
	if len(resp.SignedGroup) != 1 || resp.SignedGroup[0] != "ccdd" {
		t.Fatalf("assembly response = %+v", resp)
	}
}

// An error in a 200 component or assembly answer is a refusal, whatever else
// the answer holds, and never a lost answer.
func TestComponentAndAssemblyAnswersWithAnErrorAreRefused(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RequestID string `json:"request_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		switch r.URL.Path {
		case "/sign/component":
			json.NewEncoder(w).Encode(ComponentResponse{RequestID: req.RequestID, Error: "denied", Components: []Component{{
				Kind: ComponentTargetKindCosigner, TargetIndex: 0, Signature: "aabb", SignatureScheme: KeyTypeWitnessFalcon1024,
			}}})
		case "/sign/assemble":
			json.NewEncoder(w).Encode(AssemblyResponse{RequestID: req.RequestID, Error: "denied", SignedGroup: []string{"ccdd"}})
		}
	})
	defer server.Close()

	_, err := client.RequestComponents(ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindCosigner, ComponentKey: "COMPONENT"}},
	})
	var lost *lostAnswer
	if err == nil || err.Error() != "component signing failed: denied" || errors.As(err, &lost) {
		t.Fatalf("RequestComponents() error = %v, want the refusal", err)
	}
	_, err = client.RequestAssemble(AssemblyRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets: []AssemblyTarget{{
			TargetIndex: 0, Kind: AssemblyTargetKindBoundedCosigner, AuthAddress: "BOUNDED",
			BaseSignatures: []string{"aabb"}, AssemblyReceipt: "eeff", CosignerSignature: "bbcc",
		}},
	})
	if err == nil || err.Error() != "assembly failed: denied" || errors.As(err, &lost) {
		t.Fatalf("RequestAssemble() error = %v, want the refusal", err)
	}
}

func TestRequestAssembleRejectsMissingCoverage(t *testing.T) {
	client := &SignerClient{baseURL: "http://example.invalid", client: http.DefaultClient}
	_, err := client.RequestAssemble(AssemblyRequest{
		GroupBytesHex: []string{"5458aa", "5458bb"},
		Targets: []AssemblyTarget{{
			TargetIndex:       0,
			Kind:              AssemblyTargetKindBoundedCosigner,
			AuthAddress:       "BOUNDED",
			BaseSignatures:    []string{"aabb"},
			AssemblyReceipt:   "eeff",
			CosignerSignature: "bbcc",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "not covered") {
		t.Fatalf("expected coverage validation error, got %v", err)
	}
}

func TestRequestAssembleUnavailable(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	})
	defer server.Close()

	_, err := client.RequestAssemble(AssemblyRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets: []AssemblyTarget{{
			TargetIndex:       0,
			Kind:              AssemblyTargetKindBoundedCosigner,
			AuthAddress:       "BOUNDED",
			BaseSignatures:    []string{"aabb"},
			AssemblyReceipt:   "eeff",
			CosignerSignature: "bbcc",
		}},
	})
	if err != ErrSignerUnavailable {
		t.Fatalf("expected ErrSignerUnavailable, got %v", err)
	}
}

// --- PlanGroup tests ---

func TestPlanGroup_Success(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/plan" {
			t.Fatalf("expected /plan, got %s", r.URL.Path)
		}
		var req GroupSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode /plan request: %v", err)
		}
		json.NewEncoder(w).Encode(fakeSigner{feeRaise: map[int]uint64{0: 2000}, dummies: 2}.plan(t, req.Requests))
	})
	defer server.Close()

	txn := verifyTestPayment(t, 41, 42, 1)
	result, err := client.PlanGroup([]types.Transaction{txn}, []string{sdkTestAddress(0xA0)}, nil, nil)
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
	_, err := client.PlanGroup([]types.Transaction{txn}, []string{sdkTestAddress(0xA0)}, nil, nil)
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
	_, err := client.PlanGroup([]types.Transaction{txn}, []string{sdkTestAddress(0xA0)}, nil, nil)
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
	_, err := client.SignTransaction(txn, sdkTestAddress(0xA0), nil)
	if err != ErrAuthentication {
		t.Fatalf("expected ErrAuthentication, got: %v", err)
	}
}

func TestSign_Rejected(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		writeCodedError(w, 403, ErrCodeForbidden, "rejected by signer policy")
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	_, err := client.SignTransaction(txn, sdkTestAddress(0xA0), nil)
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
	_, err := client.SignTransaction(txn, sdkTestAddress(0xA0), nil)
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
	_, err := client.SignTransaction(txn, sdkTestAddress(0xA0), nil)
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
	_, err := client.SignTransaction(txn, sdkTestAddress(0xA0), nil)
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
	_, err := client.SignTransaction(txn, sdkTestAddress(0xA0), nil)
	if err == nil || !strings.Contains(err.Error(), "key not found") {
		t.Fatalf("expected key not found error, got: %v", err)
	}
}

// --- Passthrough/Foreign tests ---

func TestBuildSignRequestsWithOptions_Passthrough(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	presignedHex := fakeSignedTxnHex(verifyTestPayment(t, 43, 44, 2))
	presigned, err := hex.DecodeString(presignedHex)
	if err != nil {
		t.Fatal(err)
	}

	requests, err := buildSignRequestsWithOptions(
		[]types.Transaction{txn, txn},
		[]string{sdkTestAddress(0xA3), sdkTestAddress(0xA5)},
		nil,
		&SignOptions{
			Passthrough: map[int][]byte{1: presigned},
			LsigResources: map[int]LogicSigResourceUsage{
				1: {ProgramBytes: 3577, ArgumentBytes: 1423, MaxOpcodeCost: 20000},
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requests))
	}
	if requests[0].AuthAddress != sdkTestAddress(0xA3) {
		t.Fatal("first request should be normal sign")
	}
	if requests[1].SignedTxnHex != presignedHex {
		t.Fatal("second request should be the passthrough bytes, unchanged")
	}
	// The request holds its own copy of the caller's bytes.
	presigned[0] ^= 0xff
	if requests[1].SignedTxnHex != presignedHex {
		t.Fatal("changing the caller's bytes changed the request")
	}
	if requests[1].AuthAddress != "" {
		t.Fatal("passthrough should not have auth address")
	}
	if got := requests[1].LsigResources; got == nil || got.ProgramBytes != 3577 || got.ArgumentBytes != 1423 || got.MaxOpcodeCost != 20000 {
		t.Fatalf("passthrough LogicSig resources = %#v", got)
	}
}

func TestBuildSignRequestsWithOptions_Foreign(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}

	requests, err := buildSignRequestsWithOptions(
		[]types.Transaction{txn, txn},
		[]string{sdkTestAddress(0xA3), ""},
		nil,
		&SignOptions{LsigResources: map[int]LogicSigResourceUsage{1: {ProgramBytes: 3577, ArgumentBytes: 1423, MaxOpcodeCost: 20000}}},
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
	if got := requests[1].LsigResources; got == nil || got.ProgramBytes != 3577 || got.ArgumentBytes != 1423 {
		t.Fatalf("unexpected lsig_resources: %#v", got)
	}
}

func TestBuildSignRequestsWithOptionsRejectsInvalidIndexedResources(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	tests := []struct {
		name      string
		resources map[int]LogicSigResourceUsage
		want      string
	}{
		{name: "zero value", resources: map[int]LogicSigResourceUsage{0: {}}, want: "lsig_resources[0] is invalid"},
		{name: "out of range", resources: map[int]LogicSigResourceUsage{1: {ProgramBytes: 1, MaxOpcodeCost: 1}}, want: "index 1 out of range"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildSignRequestsWithOptions(
				[]types.Transaction{txn},
				[]string{""},
				nil,
				&SignOptions{LsigResources: tt.resources},
			)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q error, got %v", tt.want, err)
			}
		})
	}
}

func TestBuildSignRequestsWithOptionsRejectsIndexedResourcesForSignMode(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	_, err := buildSignRequestsWithOptions(
		[]types.Transaction{txn},
		[]string{sdkTestAddress(0xA2)},
		nil,
		&SignOptions{LsigResources: map[int]LogicSigResourceUsage{
			0: {ProgramBytes: 1612, ArgumentBytes: 1423, MaxOpcodeCost: 20000},
		}},
	)
	if err == nil || !strings.Contains(err.Error(), "allowed only for foreign or passthrough") {
		t.Fatalf("buildSignRequestsWithOptions() error = %v", err)
	}
}

func TestBuildSignRequestsWithOptions_RefusesBadPassthrough(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	tests := map[string]struct {
		entry []byte
		want  string
	}{
		"empty":                    {entry: nil, want: "invalid passthrough transaction 1"},
		"not a signed transaction": {entry: []byte("not msgpack"), want: "invalid passthrough transaction 1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := buildSignRequestsWithOptions(
				[]types.Transaction{txn},
				[]string{sdkTestAddress(0xA3)},
				nil,
				&SignOptions{Passthrough: map[int][]byte{0: tt.entry}},
			)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q error, got: %v", tt.want, err)
			}
		})
	}
}

func TestSignTransactionsWithOptions_RejectsForeignEntries(t *testing.T) {
	client := &SignerClient{baseURL: "http://example.invalid", client: http.DefaultClient}
	txn := types.Transaction{Type: types.PaymentTx}

	_, err := client.SignTransactionsWithOptions(
		[]types.Transaction{txn, txn},
		[]string{sdkTestAddress(0xA4), ""},
		nil,
		&SignOptions{LsigResources: map[int]LogicSigResourceUsage{1: {ProgramBytes: 3577, ArgumentBytes: 1423, MaxOpcodeCost: 20000}}},
	)
	if err == nil || !strings.Contains(err.Error(), "foreign entries are only supported on /plan") {
		t.Fatalf("expected foreign /plan-only error, got %v", err)
	}
}

// --- Config tests ---

func TestLoadConfig_Default(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfig_RejectsNestedEndpoint(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(
		"endpoint:\n  signer_port: 11271\n  ssh:\n    host: example.com\n    port: 1128\n    identity_file: .ssh/id\n    trust_on_first_use: true\n",
	), 0600)

	_, err := LoadConfig(dir)
	if err == nil || !strings.Contains(err.Error(), "configure endpoints.yaml") {
		t.Fatalf("expected endpoints.yaml migration error, got %v", err)
	}
}

func TestLoadConfig_RejectsTopLevelSignerRouting(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(
		"signer_port: 11270\n",
	), 0600)

	_, err := LoadConfig(dir)
	if err == nil || !strings.Contains(err.Error(), "configure endpoints.yaml") {
		t.Fatalf("expected endpoints.yaml migration error, got %v", err)
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

func TestSignedGroupFromHex(t *testing.T) {
	group, err := signedGroupFromHex([]string{hex.EncodeToString([]byte("AB")), "", hex.EncodeToString([]byte{0xde, 0xad})})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(group) != 3 || string(group[0]) != "AB" || len(group[1]) != 0 || !bytes.Equal(group[2], []byte{0xde, 0xad}) {
		t.Fatalf("signedGroupFromHex() = %x", group)
	}
	if _, err := signedGroupFromHex([]string{"00", "zz"}); err == nil || !strings.Contains(err.Error(), "signed transaction 2 is invalid hex") {
		t.Fatalf("expected invalid hex error, got %v", err)
	}
}

func TestCloneSignedGroupSharesNoBytes(t *testing.T) {
	group := [][]byte{[]byte("AB"), []byte("CD")}
	cloned := cloneSignedGroup(group)
	group[0][0] = 'X'
	if string(cloned[0]) != "AB" || string(cloned[1]) != "CD" {
		t.Fatalf("cloneSignedGroup() = %q, changed with the original", cloned)
	}
	if cloneSignedGroup(nil) != nil {
		t.Fatal("cloneSignedGroup(nil) is not nil")
	}
}

func TestSignRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		request SignRequest
		wantErr string
	}{
		{name: "sign mode", request: SignRequest{AuthAddress: sdkTestAddress(0xA0), TxnBytesHex: "deadbeef"}},
		{name: "foreign mode", request: SignRequest{TxnBytesHex: "deadbeef"}},
		{name: "passthrough mode", request: SignRequest{SignedTxnHex: "cafebabe"}},
		{name: "conflict", request: SignRequest{AuthAddress: sdkTestAddress(0xA0), TxnBytesHex: "deadbeef", SignedTxnHex: "cafebabe"}, wantErr: "cannot specify both sign fields"},
		{name: "auth only", request: SignRequest{AuthAddress: sdkTestAddress(0xA0)}, wantErr: "txn_bytes_hex is required for sign mode"},
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
