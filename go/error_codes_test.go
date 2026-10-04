// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func writeCodedError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: message, Code: code})
}

func TestListKeys_ForbiddenCodeIsNotLocked(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		writeCodedError(w, 403, ErrCodeForbidden, "identity decommissioned: default")
	})
	defer server.Close()

	_, err := client.ListKeys(true)
	if err == ErrSignerLocked {
		t.Fatal("403 with forbidden code misclassified as locked")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got: %v", err)
	}
	if apiErr.Code != ErrCodeForbidden || apiErr.StatusCode != 403 {
		t.Fatalf("APIError = %+v, want forbidden 403", apiErr)
	}
}

func TestListKeys_LockedCodeIsLocked(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		writeCodedError(w, 403, ErrCodeLocked, "signer is locked")
	})
	defer server.Close()

	_, err := client.ListKeys(true)
	if err != ErrSignerLocked {
		t.Fatalf("expected ErrSignerLocked, got: %v", err)
	}
}

func TestGenerateKey_ForbiddenCodeIsNotLocked(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		writeCodedError(w, 403, ErrCodeForbidden, "key generation not allowed for node role")
	})
	defer server.Close()

	_, err := client.GenerateKey("ed25519", nil)
	if err == ErrSignerLocked {
		t.Fatal("403 with forbidden code misclassified as locked")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got: %v", err)
	}
	if apiErr.Code != ErrCodeForbidden {
		t.Fatalf("APIError code = %q, want forbidden", apiErr.Code)
	}
}

func TestSign_LockedCodeIsLocked(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		writeCodedError(w, 403, ErrCodeLocked, "signer is locked")
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	_, err := client.SignTransaction(txn, "ADDR", nil)
	if err != ErrSignerLocked {
		t.Fatalf("expected ErrSignerLocked, got: %v", err)
	}
}

func TestSign_ForbiddenCodeIsRejected(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		writeCodedError(w, 403, ErrCodeForbidden, "policy engine rejected request")
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	_, err := client.SignTransaction(txn, "ADDR", nil)
	if err != ErrSigningRejected {
		t.Fatalf("expected ErrSigningRejected, got: %v", err)
	}
}

func TestRequestComponents_CosignerKeyHasNoPolicyIsRejected(t *testing.T) {
	witnessKeyID := strings.Repeat("A", 52)
	calls := 0
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/sign/component" {
			t.Errorf("request = %s %s, want POST /sign/component", r.Method, r.URL.Path)
		}
		writeCodedError(w, http.StatusForbidden, ErrCodeForbidden,
			"cosigner policy rejected request: [cosigner_policy:key_has_no_policy] cosigner key "+witnessKeyID+" has no policy")
	})
	defer server.Close()

	response, err := client.RequestComponents(ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets: []ComponentTarget{{
			TargetIndex:  0,
			Kind:         ComponentTargetKindCosigner,
			ComponentKey: witnessKeyID,
		}},
	})
	if !errors.Is(err, ErrSigningRejected) {
		t.Fatalf("expected ErrSigningRejected for missing cosigner policy, got: %v", err)
	}
	if response != nil {
		t.Fatalf("expected no component response, got: %+v", response)
	}
	if calls != 1 {
		t.Fatalf("requests = %d, want one component request without retry", calls)
	}
}

func TestGenericErrorCarriesAPIErrorCode(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		writeCodedError(w, 500, ErrCodeCacheRefresh, "failed to refresh signer key cache")
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	_, err := client.PlanGroup([]types.Transaction{txn}, []string{"ADDR"}, nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got: %v", err)
	}
	if apiErr.Code != ErrCodeCacheRefresh || apiErr.StatusCode != 500 {
		t.Fatalf("APIError = %+v, want cache_refresh 500", apiErr)
	}
	want := "plan failed (500): failed to refresh signer key cache"
	if apiErr.Error() != want {
		t.Fatalf("Error() = %q, want %q", apiErr.Error(), want)
	}
}

func TestValidateGroupSignResponse(t *testing.T) {
	signReq := SignRequest{AuthAddress: "AUTH", TxnBytesHex: "5458aa"}
	foreignReq := SignRequest{TxnBytesHex: "5458bb"}
	passthroughReq := SignRequest{SignedTxnHex: "82a3"}

	cases := []struct {
		name     string
		requests []SignRequest
		signed   []string
		wantErr  string
	}{
		{
			name:     "truncated response rejected",
			requests: []SignRequest{signReq, signReq},
			signed:   []string{"aa"},
			wantErr:  "want at least 2",
		},
		{
			name:     "empty sign slot rejected",
			requests: []SignRequest{signReq, signReq},
			signed:   []string{"aa", ""},
			wantErr:  "no signature for position 2",
		},
		{
			name:     "empty foreign slot tolerated with trailing dummies",
			requests: []SignRequest{signReq, foreignReq},
			signed:   []string{"aa", "", "dd"},
		},
		{
			name:     "empty dummy slot rejected",
			requests: []SignRequest{signReq},
			signed:   []string{"aa", ""},
			wantErr:  "empty dummy transaction at position 2",
		},
		{
			name:     "passthrough slot must be echoed",
			requests: []SignRequest{passthroughReq},
			signed:   []string{""},
			wantErr:  "no signature for position 1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGroupSignResponse(tc.requests, tc.signed)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateGroupSignResponse() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateGroupSignResponse() error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func requireUncodedAPIError(t *testing.T, err error, status int) {
	t.Helper()
	if errors.Is(err, ErrSignerLocked) || errors.Is(err, ErrSigningRejected) || errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("uncoded %d error misclassified as a sentinel: %v", status, err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got: %v", err)
	}
	if apiErr.Code != "" || apiErr.StatusCode != status {
		t.Fatalf("APIError = %+v, want empty code with status %d", apiErr, status)
	}
}

func TestForbiddenWithoutCodeIsGenericAPIError(t *testing.T) {
	for _, body := range []string{"", "forbidden"} {
		handler := func(w http.ResponseWriter, r *http.Request) {
			if body == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			writeCodedError(w, http.StatusForbidden, "", body)
		}
		t.Run("keys/"+body, func(t *testing.T) {
			client, server := newTestClient(handler)
			defer server.Close()
			result, err := client.GetKeysResponseWithContext(context.Background())
			if result != nil {
				t.Fatalf("result = %+v, want nil", result)
			}
			requireUncodedAPIError(t, err, http.StatusForbidden)
		})
		t.Run("generate/"+body, func(t *testing.T) {
			client, server := newTestClient(handler)
			defer server.Close()
			_, err := client.GenerateKey("ed25519", nil)
			requireUncodedAPIError(t, err, http.StatusForbidden)
		})
		t.Run("sign/"+body, func(t *testing.T) {
			client, server := newTestClient(handler)
			defer server.Close()
			_, err := client.SignTransaction(types.Transaction{Type: types.PaymentTx}, "ADDR", nil)
			requireUncodedAPIError(t, err, http.StatusForbidden)
		})
		t.Run("components/"+body, func(t *testing.T) {
			client, server := newTestClient(handler)
			defer server.Close()
			_, err := client.RequestComponents(ComponentRequest{
				GroupBytesHex: []string{"5458aa"},
				Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindCosigner}},
			})
			requireUncodedAPIError(t, err, http.StatusForbidden)
		})
	}
}

func TestNotFoundMessageWithoutCodeIsNotKeyNotFound(t *testing.T) {
	uncoded := &APIError{StatusCode: http.StatusNotFound, Message: "key not found"}
	if errors.Is(uncoded, ErrKeyNotFound) {
		t.Fatal("empty-code not-found message must not map to ErrKeyNotFound")
	}
	coded := &APIError{StatusCode: http.StatusNotFound, Code: ErrCodeNotFound, Message: "key not found"}
	if !errors.Is(coded, ErrKeyNotFound) {
		t.Fatal("not_found code must map to ErrKeyNotFound")
	}

	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		writeCodedError(w, http.StatusNotFound, "", "key not found")
	})
	defer server.Close()
	_, err := client.PlanGroup([]types.Transaction{{Type: types.PaymentTx}}, []string{"ADDR"}, nil, nil)
	requireUncodedAPIError(t, err, http.StatusNotFound)
}
