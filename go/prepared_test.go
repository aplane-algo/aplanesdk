// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestPreparedGroupSignRequestsSignMode(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	group := NewPreparedGroup(PreparedTransaction{
		Transaction: &txn,
		AuthAddress: "AUTH_ADDR",
		TxnSender:   "SENDER_ADDR",
		LsigArgs: LsigArgs{
			"preimage": []byte("secret"),
		},
		AppCallInfo: &AppCallInfo{
			Mode:   "abi",
			Method: "do(uint64)void",
		},
	})

	requests, err := group.SignRequests()
	if err != nil {
		t.Fatalf("SignRequests() error = %v", err)
	}
	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}
	req := requests[0]
	if req.AuthAddress != "AUTH_ADDR" {
		t.Fatalf("auth address = %q, want AUTH_ADDR", req.AuthAddress)
	}
	if req.TxnSender != "SENDER_ADDR" {
		t.Fatalf("txn sender = %q, want SENDER_ADDR", req.TxnSender)
	}
	if req.TxnBytesHex == "" {
		t.Fatal("txn bytes hex is empty")
	}
	if req.LsigArgs["preimage"] != hex.EncodeToString([]byte("secret")) {
		t.Fatalf("lsig arg mismatch: %v", req.LsigArgs)
	}
	if req.AppCallInfo == nil || req.AppCallInfo.Method != "do(uint64)void" {
		t.Fatalf("app call info mismatch: %#v", req.AppCallInfo)
	}
}

func TestPreparedGroupSignRequestsForeignMode(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	group := NewPreparedGroup(PreparedTransaction{
		Transaction:   &txn,
		LsigResources: &LogicSigResourceUsage{ProgramBytes: 1612, ArgumentBytes: 1423, MaxOpcodeCost: 20000},
	})

	requests, err := group.SignRequests()
	if err != nil {
		t.Fatalf("SignRequests() error = %v", err)
	}
	req := requests[0]
	if req.AuthAddress != "" {
		t.Fatalf("auth address = %q, want empty foreign mode", req.AuthAddress)
	}
	if req.TxnBytesHex == "" {
		t.Fatal("txn bytes hex is empty")
	}
	if req.LsigResources == nil || req.LsigResources.ProgramBytes != 1612 {
		t.Fatalf("lsig resources = %#v", req.LsigResources)
	}
}

func TestPreparedGroupSignRequestsNativePQForeignMode(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	group := NewPreparedGroup(PreparedTransaction{
		Transaction: &txn,
		PQScheme:    "f1",
	})

	requests, err := group.SignRequests()
	if err != nil {
		t.Fatalf("SignRequests() error = %v", err)
	}
	if requests[0].PQScheme != "f1" {
		t.Fatalf("pq scheme = %q, want f1", requests[0].PQScheme)
	}
}

func TestPreparedGroupSignRequestsRejectsUnsupportedNativePQScheme(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	_, err := NewPreparedGroup(PreparedTransaction{
		Transaction: &txn,
		PQScheme:    "f2",
	}).SignRequests()
	if err == nil || !strings.Contains(err.Error(), "unsupported pq_scheme") {
		t.Fatalf("expected unsupported scheme error, got %v", err)
	}
}

func TestPreparedGroupSignRequestsRejectsConflictingForeignHints(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	_, err := NewPreparedGroup(PreparedTransaction{
		Transaction:   &txn,
		LsigResources: &LogicSigResourceUsage{ProgramBytes: 1612, ArgumentBytes: 1423, MaxOpcodeCost: 20000},
		PQScheme:      "f1",
	}).SignRequests()
	if err == nil || !strings.Contains(err.Error(), "both pq_scheme and lsig_resources") {
		t.Fatalf("expected conflicting hint error, got %v", err)
	}
}

func TestPreparedGroupSignRequestsRejectsAuthorizationHintsInSignMode(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	tests := []struct {
		name     string
		prepared PreparedTransaction
		want     string
	}{
		{
			name: "native PQ",
			prepared: PreparedTransaction{
				Transaction: &txn, AuthAddress: "AUTH_ADDR", PQScheme: PQSchemeFalcon1024,
			},
			want: "pq_scheme is allowed only for foreign transactions",
		},
		{
			name: "LogicSig resources",
			prepared: PreparedTransaction{
				Transaction: &txn, AuthAddress: "AUTH_ADDR",
				LsigResources: &LogicSigResourceUsage{ProgramBytes: 1612, ArgumentBytes: 1423, MaxOpcodeCost: 20000},
			},
			want: "lsig_resources is allowed only for foreign or passthrough transactions",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPreparedGroup(tt.prepared).SignRequests()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("SignRequests() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPreparedGroupSignRequestsRejectsNativePQHintInPassthroughMode(t *testing.T) {
	_, err := NewPreparedGroup(PreparedTransaction{
		SignedTransactionBase64: base64.StdEncoding.EncodeToString([]byte("signed-txn")),
		PQScheme:                PQSchemeFalcon1024,
	}).SignRequests()
	if err == nil || !strings.Contains(err.Error(), "pq_scheme is allowed only for foreign transactions") {
		t.Fatalf("SignRequests() error = %v", err)
	}
}

func TestPreparedGroupSignRequestsPassthroughMode(t *testing.T) {
	signed := []byte("signed-txn")
	resources := &LogicSigResourceUsage{ProgramBytes: 1612, ArgumentBytes: 1423, MaxOpcodeCost: 20000}
	group := NewPreparedGroup(PreparedTransaction{
		SignedTransactionBase64: base64.StdEncoding.EncodeToString(signed),
		LsigResources:           resources,
	})

	requests, err := group.SignRequests()
	if err != nil {
		t.Fatalf("SignRequests() error = %v", err)
	}
	if requests[0].SignedTxnHex != hex.EncodeToString(signed) {
		t.Fatalf("signed txn hex = %q, want %q", requests[0].SignedTxnHex, hex.EncodeToString(signed))
	}
	if requests[0].TxnBytesHex != "" || requests[0].AuthAddress != "" {
		t.Fatalf("passthrough request should not include sign fields: %#v", requests[0])
	}
	if requests[0].LsigResources == nil || *requests[0].LsigResources != *resources {
		t.Fatalf("passthrough request resources = %#v, want %#v", requests[0].LsigResources, resources)
	}
}

func TestPreparedGroupSignRequestsRejectsEmptyGroup(t *testing.T) {
	_, err := (PreparedGroup{}).SignRequests()
	if err == nil || !strings.Contains(err.Error(), "prepared group is empty") {
		t.Fatalf("expected empty group error, got %v", err)
	}
}
