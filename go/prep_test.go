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
