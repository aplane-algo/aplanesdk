// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"context"
	"encoding/base64"
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
				if assetAmount > 0 {
					resp["assets"] = []map[string]any{{
						"asset-id": 1001,
						"amount":   assetAmount,
					}}
				}
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

func TestPrepareAsaOptIn(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 0, false)
	defer cleanup()

	prepared, err := signer.PrepareAsaOptIn(context.Background(), algodClient, AsaOptInPrepParams{
		Sender:  sender,
		AssetID: 1001,
	})
	if err != nil {
		t.Fatalf("PrepareAsaOptIn() error = %v", err)
	}
	if prepared.Transaction == nil || prepared.Transaction.Sender.String() != sender {
		t.Fatalf("transaction mismatch: %#v", prepared.Transaction)
	}
	if prepared.Transaction.AssetAmount != 0 || prepared.Transaction.AssetReceiver.String() != sender {
		t.Fatalf("opt-in transaction mismatch: %#v", prepared.Transaction)
	}
	if prepared.Checks[0].Name != "asa_opt_in" {
		t.Fatalf("checks mismatch: %#v", prepared.Checks)
	}
}

func TestPrepareAsaOptOut(t *testing.T) {
	sender := sdkTestAddress(1)
	closeTo := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, closeTo, 2_000_000, 25, true)
	defer cleanup()

	prepared, err := signer.PrepareAsaOptOut(context.Background(), algodClient, AsaOptOutPrepParams{
		Sender:  sender,
		AssetID: 1001,
		CloseTo: closeTo,
	})
	if err != nil {
		t.Fatalf("PrepareAsaOptOut() error = %v", err)
	}
	if prepared.Transaction == nil || prepared.Transaction.AssetCloseTo.String() != closeTo {
		t.Fatalf("opt-out transaction mismatch: %#v", prepared.Transaction)
	}
	if prepared.Checks[0].Name != "asa_opt_out" {
		t.Fatalf("checks mismatch: %#v", prepared.Checks)
	}
}

func TestPrepareAccountClose(t *testing.T) {
	sender := sdkTestAddress(1)
	closeTo := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, closeTo, 2_000_000, 0, false)
	defer cleanup()

	prepared, err := signer.PrepareAccountClose(context.Background(), algodClient, AccountClosePrepParams{
		Sender:  sender,
		CloseTo: closeTo,
	})
	if err != nil {
		t.Fatalf("PrepareAccountClose() error = %v", err)
	}
	if prepared.Transaction == nil || prepared.Transaction.CloseRemainderTo.String() != closeTo {
		t.Fatalf("close transaction mismatch: %#v", prepared.Transaction)
	}
	if prepared.Checks[0].Name != "account_close" {
		t.Fatalf("checks mismatch: %#v", prepared.Checks)
	}
}

func TestPrepareRekey(t *testing.T) {
	sender := sdkTestAddress(1)
	rekeyTo := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, rekeyTo, 2_000_000, 0, false)
	defer cleanup()

	prepared, err := signer.PrepareRekey(context.Background(), algodClient, RekeyPrepParams{
		Sender:  sender,
		RekeyTo: rekeyTo,
	})
	if err != nil {
		t.Fatalf("PrepareRekey() error = %v", err)
	}
	if prepared.Transaction == nil || prepared.Transaction.RekeyTo.String() != rekeyTo {
		t.Fatalf("rekey transaction mismatch: %#v", prepared.Transaction)
	}
	if prepared.Checks[0].Name != "rekey" {
		t.Fatalf("checks mismatch: %#v", prepared.Checks)
	}
}

func TestPrepareKeyRegNonparticipation(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 0, false)
	defer cleanup()

	prepared, err := signer.PrepareKeyReg(context.Background(), algodClient, KeyRegPrepParams{
		Sender:           sender,
		Nonparticipation: true,
	})
	if err != nil {
		t.Fatalf("PrepareKeyReg() error = %v", err)
	}
	if prepared.Transaction == nil || prepared.Transaction.Type != types.KeyRegistrationTx {
		t.Fatalf("keyreg transaction mismatch: %#v", prepared.Transaction)
	}
	if !prepared.Transaction.Nonparticipation {
		t.Fatal("Nonparticipation = false, want true")
	}
	if prepared.Checks[0].Name != "keyreg" {
		t.Fatalf("checks mismatch: %#v", prepared.Checks)
	}
}

func TestPrepareKeyRegOnline(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 0, false)
	defer cleanup()
	key32 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	key64 := base64.StdEncoding.EncodeToString(make([]byte, 64))

	prepared, err := signer.PrepareKeyReg(context.Background(), algodClient, KeyRegPrepParams{
		Sender:          sender,
		VoteKey:         key32,
		SelectionKey:    key32,
		StateProofKey:   key64,
		VoteFirst:       10,
		VoteLast:        20,
		VoteKeyDilution: 5,
	})
	if err != nil {
		t.Fatalf("PrepareKeyReg() error = %v", err)
	}
	if prepared.Transaction == nil || prepared.Transaction.VoteFirst != 10 || prepared.Transaction.VoteLast != 20 {
		t.Fatalf("keyreg fields mismatch: %#v", prepared.Transaction)
	}
}

func TestPrepareAppDeploy(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 0, false)
	defer cleanup()

	prepared, err := signer.PrepareAppDeploy(context.Background(), algodClient, AppDeployPrepParams{
		Sender:          sender,
		ApprovalProgram: []byte{1, 2, 3},
		ClearProgram:    []byte{1},
		GlobalSchema:    types.StateSchema{NumUint: 1},
		LocalSchema:     types.StateSchema{NumByteSlice: 1},
		ExtraPages:      1,
	})
	if err != nil {
		t.Fatalf("PrepareAppDeploy() error = %v", err)
	}
	if prepared.Transaction == nil || prepared.Transaction.Type != types.ApplicationCallTx || prepared.Transaction.ApplicationID != 0 {
		t.Fatalf("app deploy transaction mismatch: %#v", prepared.Transaction)
	}
	if prepared.AppCallInfo == nil || prepared.AppCallInfo.Mode != "raw" {
		t.Fatalf("app call info mismatch: %#v", prepared.AppCallInfo)
	}
	if prepared.Checks[0].Name != "app_deploy" {
		t.Fatalf("checks mismatch: %#v", prepared.Checks)
	}
}

func TestPrepareAppCall(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 0, false)
	defer cleanup()

	prepared, err := signer.PrepareAppCall(context.Background(), algodClient, AppCallPrepParams{
		Sender:        sender,
		AppID:         7,
		OnCompletion:  types.NoOpOC,
		AppArgs:       [][]byte{[]byte("raw")},
		Accounts:      []string{receiver},
		ForeignApps:   []uint64{8},
		ForeignAssets: []uint64{1001},
		Boxes: []types.AppBoxReference{{
			AppID: 7,
			Name:  []byte("box"),
		}},
		Fee:        1000,
		UseFlatFee: true,
	})
	if err != nil {
		t.Fatalf("PrepareAppCall() error = %v", err)
	}
	if prepared.Transaction == nil || prepared.Transaction.Type != types.ApplicationCallTx {
		t.Fatalf("transaction type mismatch: %#v", prepared.Transaction)
	}
	if uint64(prepared.Transaction.ApplicationID) != 7 {
		t.Fatalf("app id = %d, want 7", prepared.Transaction.ApplicationID)
	}
	if prepared.AppCallInfo == nil || prepared.AppCallInfo.Mode != "raw" {
		t.Fatalf("app call info mismatch: %#v", prepared.AppCallInfo)
	}
	if len(prepared.Checks) != 1 || prepared.Checks[0].Name != "app_call" {
		t.Fatalf("checks mismatch: %#v", prepared.Checks)
	}
	req, err := prepared.SignRequest()
	if err != nil {
		t.Fatalf("SignRequest() error = %v", err)
	}
	if req.AppCallInfo == nil || req.AppCallInfo.Mode != "raw" {
		t.Fatalf("request app call info mismatch: %#v", req.AppCallInfo)
	}
}

func TestPrepareABIAppCall(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 0, false)
	defer cleanup()

	prepared, err := signer.PrepareABIAppCall(context.Background(), algodClient, ABIAppCallPrepParams{
		AppCallPrepParams: AppCallPrepParams{
			Sender:      sender,
			AppID:       7,
			ForeignApps: []uint64{9},
			ForeignAssets: []uint64{
				1001,
			},
		},
		MethodSignature: "do(uint64,string,account,application,asset)void",
		Args: []any{
			uint64(42),
			"hi",
			receiver,
			uint64(8),
			uint64(1002),
		},
	})
	if err != nil {
		t.Fatalf("PrepareABIAppCall() error = %v", err)
	}
	txn := prepared.Transaction
	if txn == nil {
		t.Fatal("transaction is nil")
	}
	if prepared.AppCallInfo == nil || prepared.AppCallInfo.Mode != "abi" || prepared.AppCallInfo.Method != "do(uint64,string,account,application,asset)void" {
		t.Fatalf("app call info mismatch: %#v", prepared.AppCallInfo)
	}
	if len(txn.ApplicationArgs) != 6 {
		t.Fatalf("app args length = %d, want 6", len(txn.ApplicationArgs))
	}
	if len(txn.ApplicationArgs[0]) != 4 {
		t.Fatalf("selector length = %d, want 4", len(txn.ApplicationArgs[0]))
	}
	if len(txn.Accounts) != 1 || txn.Accounts[0].String() != receiver {
		t.Fatalf("accounts mismatch: %#v", txn.Accounts)
	}
	if len(txn.ForeignApps) != 2 || uint64(txn.ForeignApps[0]) != 9 || uint64(txn.ForeignApps[1]) != 8 {
		t.Fatalf("foreign apps mismatch: %#v", txn.ForeignApps)
	}
	if len(txn.ForeignAssets) != 2 || uint64(txn.ForeignAssets[0]) != 1001 || uint64(txn.ForeignAssets[1]) != 1002 {
		t.Fatalf("foreign assets mismatch: %#v", txn.ForeignAssets)
	}
	if !bytes.Equal(txn.ApplicationArgs[3], []byte{1}) {
		t.Fatalf("account ref arg = %x, want 01", txn.ApplicationArgs[3])
	}
	if !bytes.Equal(txn.ApplicationArgs[4], []byte{2}) {
		t.Fatalf("app ref arg = %x, want 02", txn.ApplicationArgs[4])
	}
	if !bytes.Equal(txn.ApplicationArgs[5], []byte{1}) {
		t.Fatalf("asset ref arg = %x, want 01", txn.ApplicationArgs[5])
	}
	req, err := prepared.SignRequest()
	if err != nil {
		t.Fatalf("SignRequest() error = %v", err)
	}
	if req.AppCallInfo == nil || req.AppCallInfo.Method != "do(uint64,string,account,application,asset)void" {
		t.Fatalf("request app call info mismatch: %#v", req.AppCallInfo)
	}
}

func TestPrepareSweepGroup(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 25, true)
	defer cleanup()

	group, err := signer.PrepareSweepGroup(context.Background(), algodClient, SweepPrepParams{
		AsaTransfers: []AsaTransferPrepParams{{
			Sender:   sender,
			Receiver: receiver,
			AssetID:  1001,
			Amount:   5,
		}},
		Payments: []PaymentPrepParams{{
			Sender:   sender,
			Receiver: receiver,
			Amount:   10_000,
		}},
	})
	if err != nil {
		t.Fatalf("PrepareSweepGroup() error = %v", err)
	}
	if len(group.Transactions) != 2 {
		t.Fatalf("group length = %d, want 2", len(group.Transactions))
	}
	if group.Checks[0].Name != "sweep_group" {
		t.Fatalf("checks mismatch: %#v", group.Checks)
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

// TestApplyPrepFee pins the unified fee model: a positive fee is always flat
// microAlgos (never reinterpreted as fee-per-byte), an explicit flat zero is
// applied (for fee pooling), and an unset fee leaves the suggested fee intact.
func TestApplyPrepFee(t *testing.T) {
	tests := []struct {
		name       string
		fee        uint64
		useFlatFee bool
		wantFee    types.MicroAlgos
		wantFlat   bool
	}{
		{"positive fee is flat even without UseFlatFee", 5000, false, 5000, true},
		{"positive fee with UseFlatFee is flat", 5000, true, 5000, true},
		{"explicit flat zero is applied", 0, true, 0, true},
		{"unset fee keeps suggested", 0, false, 7, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := types.SuggestedParams{Fee: 7, FlatFee: false}
			applyPrepFee(&params, tt.fee, tt.useFlatFee)
			if params.Fee != tt.wantFee {
				t.Fatalf("Fee = %d, want %d", params.Fee, tt.wantFee)
			}
			if params.FlatFee != tt.wantFlat {
				t.Fatalf("FlatFee = %v, want %v", params.FlatFee, tt.wantFlat)
			}
		})
	}
}
