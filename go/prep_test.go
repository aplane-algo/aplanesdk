// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func sdkTestAddress(seed byte) string {
	var addr types.Address
	addr[31] = seed
	return addr.String()
}

func newPrepTestClients(t *testing.T, sender string, receiver string, senderAmount uint64, assetAmount uint64, receiverOptedIn bool) (*SignerClient, *algod.Client, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				State:           "unlocked",
				ReadyForSigning: true,
				KeysetRevision:  1,
			})
		case r.URL.Path == "/keys":
			json.NewEncoder(w).Encode(KeysResponse{
				Count: 1,
				Keys: []KeyInfo{{
					Address: sender,
					KeyType: "ed25519",
				}},
			})
		case r.URL.Path == "/v2/transactions/params":
			json.NewEncoder(w).Encode(map[string]any{
				"fee":               1000,
				"genesis-id":        "testnet-v1",
				"genesis-hash":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				"last-round":        100,
				"consensus-version": "future",
				"min-fee":           1000,
			})
		case strings.HasPrefix(r.URL.Path, "/v2/accounts/"):
			address := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
			resp := map[string]any{
				"address":     address,
				"amount":      uint64(2_000_000),
				"min-balance": uint64(100_000),
			}
			if address == sender {
				resp["amount"] = senderAmount
				resp["assets"] = []map[string]any{{
					"asset-id": 1001,
					"amount":   assetAmount,
				}}
			}
			if address == receiver && receiverOptedIn {
				resp["assets"] = []map[string]any{{
					"asset-id": 1001,
					"amount":   uint64(0),
				}}
			}
			json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	algodClient, err := algod.MakeClient(server.URL, "")
	if err != nil {
		server.Close()
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	signer := NewSignerClientWithToken(server.URL, "token")
	return signer, algodClient, server.Close
}

func TestPreparePayment(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 0, false)
	defer cleanup()

	prepared, err := signer.PreparePayment(context.Background(), algodClient, PaymentPrepParams{
		Sender:     sender,
		Receiver:   receiver,
		Amount:     10_000,
		Fee:        1000,
		UseFlatFee: true,
	})
	if err != nil {
		t.Fatalf("PreparePayment() error = %v", err)
	}
	if prepared.AuthAddress != sender {
		t.Fatalf("auth address = %q, want %q", prepared.AuthAddress, sender)
	}
	if prepared.Transaction == nil || prepared.Transaction.Receiver.String() != receiver {
		t.Fatalf("payment receiver mismatch: %#v", prepared.Transaction)
	}
	if uint64(prepared.Transaction.Fee) != 1000 {
		t.Fatalf("fee = %d, want 1000", prepared.Transaction.Fee)
	}
	if len(prepared.Checks) != 1 || prepared.Checks[0].Name != "payment_balance" {
		t.Fatalf("checks mismatch: %#v", prepared.Checks)
	}
}

func TestPreparePaymentRejectsInsufficientFunds(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 101_000, 0, false)
	defer cleanup()

	_, err := signer.PreparePayment(context.Background(), algodClient, PaymentPrepParams{
		Sender:   sender,
		Receiver: receiver,
		Amount:   10_000,
	})
	if err == nil || !strings.Contains(err.Error(), "insufficient funds") {
		t.Fatalf("expected insufficient funds error, got %v", err)
	}
}

func TestPrepareAsaTransfer(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 25, true)
	defer cleanup()

	prepared, err := signer.PrepareAsaTransfer(context.Background(), algodClient, AsaTransferPrepParams{
		Sender:   sender,
		Receiver: receiver,
		AssetID:  1001,
		Amount:   5,
	})
	if err != nil {
		t.Fatalf("PrepareAsaTransfer() error = %v", err)
	}
	if prepared.AuthAddress != sender {
		t.Fatalf("auth address = %q, want %q", prepared.AuthAddress, sender)
	}
	if prepared.Transaction == nil || uint64(prepared.Transaction.XferAsset) != 1001 {
		t.Fatalf("asset id mismatch: %#v", prepared.Transaction)
	}
	if prepared.Transaction.AssetAmount != 5 {
		t.Fatalf("asset amount = %d, want 5", prepared.Transaction.AssetAmount)
	}
}

func TestPrepareAsaTransferRejectsReceiverNotOptedIn(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 25, false)
	defer cleanup()

	_, err := signer.PrepareAsaTransfer(context.Background(), algodClient, AsaTransferPrepParams{
		Sender:   sender,
		Receiver: receiver,
		AssetID:  1001,
		Amount:   5,
	})
	if err == nil || !strings.Contains(err.Error(), "receiver is not opted into asset") {
		t.Fatalf("expected receiver opt-in error, got %v", err)
	}
}

func TestPreparePaymentGroupPreservesOrder(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver1 := sdkTestAddress(2)
	receiver2 := sdkTestAddress(3)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver1, 2_000_000, 0, false)
	defer cleanup()

	group, err := signer.PreparePaymentGroup(context.Background(), algodClient, []PaymentPrepParams{
		{Sender: sender, Receiver: receiver1, Amount: 10_000},
		{Sender: sender, Receiver: receiver2, Amount: 20_000},
	})
	if err != nil {
		t.Fatalf("PreparePaymentGroup() error = %v", err)
	}
	if len(group.Transactions) != 2 {
		t.Fatalf("group length = %d, want 2", len(group.Transactions))
	}
	if group.Transactions[0].Transaction.Receiver.String() != receiver1 {
		t.Fatalf("first receiver = %s, want %s", group.Transactions[0].Transaction.Receiver, receiver1)
	}
	if group.Transactions[1].Transaction.Receiver.String() != receiver2 {
		t.Fatalf("second receiver = %s, want %s", group.Transactions[1].Transaction.Receiver, receiver2)
	}
	if group.Checks[0].Name != "payment_group" {
		t.Fatalf("group check = %#v", group.Checks)
	}
}

func TestPreparePaymentGroupRejectsAggregateInsufficientFunds(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver1 := sdkTestAddress(2)
	receiver2 := sdkTestAddress(3)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver1, 121_000, 0, false)
	defer cleanup()

	_, err := signer.PreparePaymentGroup(context.Background(), algodClient, []PaymentPrepParams{
		{Sender: sender, Receiver: receiver1, Amount: 10_000, Fee: 1000, UseFlatFee: true},
		{Sender: sender, Receiver: receiver2, Amount: 10_000, Fee: 1000, UseFlatFee: true},
	})
	if err == nil || !strings.Contains(err.Error(), "payment group insufficient funds") {
		t.Fatalf("expected aggregate insufficient funds error, got %v", err)
	}
}

func TestPrepareAsaTransferGroupPreservesOrder(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 25, true)
	defer cleanup()

	group, err := signer.PrepareAsaTransferGroup(context.Background(), algodClient, []AsaTransferPrepParams{
		{Sender: sender, Receiver: receiver, AssetID: 1001, Amount: 5},
		{Sender: sender, Receiver: receiver, AssetID: 1001, Amount: 7},
	})
	if err != nil {
		t.Fatalf("PrepareAsaTransferGroup() error = %v", err)
	}
	if len(group.Transactions) != 2 {
		t.Fatalf("group length = %d, want 2", len(group.Transactions))
	}
	if group.Transactions[0].Transaction.AssetAmount != 5 {
		t.Fatalf("first amount = %d, want 5", group.Transactions[0].Transaction.AssetAmount)
	}
	if group.Transactions[1].Transaction.AssetAmount != 7 {
		t.Fatalf("second amount = %d, want 7", group.Transactions[1].Transaction.AssetAmount)
	}
	if group.Checks[0].Name != "asa_transfer_group" {
		t.Fatalf("group check = %#v", group.Checks)
	}
}

func TestPrepareAsaTransferGroupRejectsAggregateInsufficientAssetBalance(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 10, true)
	defer cleanup()

	_, err := signer.PrepareAsaTransferGroup(context.Background(), algodClient, []AsaTransferPrepParams{
		{Sender: sender, Receiver: receiver, AssetID: 1001, Amount: 6},
		{Sender: sender, Receiver: receiver, AssetID: 1001, Amount: 6},
	})
	if err == nil || !strings.Contains(err.Error(), "ASA transfer group insufficient asset balance") {
		t.Fatalf("expected aggregate asset balance error, got %v", err)
	}
}

func TestPreparePaymentAppCallGroup(t *testing.T) {
	sender := types.Address{}
	paymentTxn := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: sender}}
	appTxn := types.Transaction{Type: types.ApplicationCallTx, Header: types.Header{Sender: sender}}
	client := NewSignerClientWithToken("http://example.invalid", "token")

	group, err := client.PreparePaymentAppCallGroup(
		PreparedTransaction{Transaction: &paymentTxn, AuthAddress: "PAY_AUTH"},
		PreparedTransaction{
			Transaction: &appTxn,
			AuthAddress: "APP_AUTH",
			AppCallInfo: &AppCallInfo{Mode: "raw"},
		},
	)
	if err != nil {
		t.Fatalf("PreparePaymentAppCallGroup() error = %v", err)
	}
	if len(group.Transactions) != 2 {
		t.Fatalf("group length = %d, want 2", len(group.Transactions))
	}
	if group.Transactions[0].AuthAddress != "PAY_AUTH" {
		t.Fatalf("first auth = %s, want PAY_AUTH", group.Transactions[0].AuthAddress)
	}
	if group.Transactions[1].AppCallInfo == nil || group.Transactions[1].AppCallInfo.Mode != "raw" {
		t.Fatalf("second app info mismatch: %#v", group.Transactions[1].AppCallInfo)
	}
	if group.Checks[0].Name != "payment_app_call_order" {
		t.Fatalf("group check = %#v", group.Checks)
	}
}
