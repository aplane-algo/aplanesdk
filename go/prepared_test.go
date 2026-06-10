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
		Transaction: &txn,
		LsigSize:    3035,
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
	if req.LsigSize != 3035 {
		t.Fatalf("lsig size = %d, want 3035", req.LsigSize)
	}
}

func TestPreparedGroupSignRequestsPassthroughMode(t *testing.T) {
	signed := []byte("signed-txn")
	group := NewPreparedGroup(PreparedTransaction{
		SignedTransactionBase64: base64.StdEncoding.EncodeToString(signed),
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
}

func TestPreparedGroupSignRequestsRejectsEmptyGroup(t *testing.T) {
	_, err := (PreparedGroup{}).SignRequests()
	if err == nil || !strings.Contains(err.Error(), "prepared group is empty") {
		t.Fatalf("expected empty group error, got %v", err)
	}
}
