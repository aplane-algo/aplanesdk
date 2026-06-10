// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/json"
	"errors"
	"net/http"
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
