// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// The opt-in and close preflights compare the balance with the fee the built
// transaction pays. The suggested fee is per byte, so comparing against it
// let through an account that could not pay.
func TestOptInAndClosePreflightsUseTheTransactionFee(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	ctx := context.Background()

	rich, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 0, false)
	optIn, err := rich.PrepareAsaOptIn(ctx, algodClient, AsaOptInPrepParams{Sender: sender, AssetID: 1001})
	if err != nil {
		t.Fatalf("PrepareAsaOptIn() error = %v", err)
	}
	optInFee := uint64(optIn.Transaction.Fee)
	if got := optIn.Checks[0].Data["fee"]; got != optInFee {
		t.Fatalf("opt-in check fee = %v, want the transaction's fee %d", got, optInFee)
	}
	closing, err := rich.PrepareAccountClose(ctx, algodClient, AccountClosePrepParams{Sender: sender, CloseTo: receiver})
	if err != nil {
		t.Fatalf("PrepareAccountClose() error = %v", err)
	}
	closeFee := uint64(closing.Transaction.Fee)
	if got := closing.Checks[0].Data["fee"]; got != closeFee {
		t.Fatalf("close check fee = %v, want the transaction's fee %d", got, closeFee)
	}
	cleanup()
	// The mock's suggested fee is 1000 per byte, so the transaction pays far
	// more than 1000.
	if optInFee <= 1000 || closeFee <= 1000 {
		t.Fatalf("test setup: fees %d and %d should exceed the suggested per-byte fee", optInFee, closeFee)
	}

	// One microAlgo short of the transaction's fee, though above the
	// suggested per-byte fee the check used to compare with.
	short, algodClient, cleanup := newPrepTestClients(t, sender, receiver, optInFee-1, 0, false)
	if _, err := short.PrepareAsaOptIn(ctx, algodClient, AsaOptInPrepParams{Sender: sender, AssetID: 1001}); err == nil ||
		!strings.Contains(err.Error(), "insufficient funds for opt-in fee") {
		t.Fatalf("PrepareAsaOptIn() error = %v, want an insufficient-funds refusal", err)
	}
	cleanup()
	short, algodClient, cleanup = newPrepTestClients(t, sender, receiver, closeFee-1, 0, false)
	if _, err := short.PrepareAccountClose(ctx, algodClient, AccountClosePrepParams{Sender: sender, CloseTo: receiver}); err == nil ||
		!strings.Contains(err.Error(), "insufficient funds for close fee") {
		t.Fatalf("PrepareAccountClose() error = %v, want an insufficient-funds refusal", err)
	}
	cleanup()

	// Exactly the fee is enough: no minimum-balance rule was added.
	exact, algodClient, cleanup := newPrepTestClients(t, sender, receiver, optInFee, 0, false)
	defer cleanup()
	if _, err := exact.PrepareAsaOptIn(ctx, algodClient, AsaOptInPrepParams{Sender: sender, AssetID: 1001}); err != nil {
		t.Fatalf("PrepareAsaOptIn() with exactly the fee: %v", err)
	}
}

func TestSweepCountsAsaTransferFeesAgainstThePayingSender(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	params := SweepPrepParams{
		AsaTransfers: []AsaTransferPrepParams{{Sender: sender, Receiver: receiver, AssetID: 1001, Amount: 5}},
		Payments:     []PaymentPrepParams{{Sender: sender, Receiver: receiver, Amount: 10_000}},
	}
	rich, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 25, true)
	group, err := rich.PrepareSweepGroup(context.Background(), algodClient, params)
	cleanup()
	if err != nil {
		t.Fatalf("PrepareSweepGroup() error = %v", err)
	}
	asaFee := uint64(group.Transactions[0].Transaction.Fee)
	payFee := uint64(group.Transactions[1].Transaction.Fee)
	// The mock's minimum balance is 100,000. The sender pays the payment, its
	// fee, and the ASA transfer's fee.
	needed := 100_000 + 10_000 + payFee + asaFee

	exact, algodClient, cleanup := newPrepTestClients(t, sender, receiver, needed, 25, true)
	if _, err := exact.PrepareSweepGroup(context.Background(), algodClient, params); err != nil {
		t.Fatalf("PrepareSweepGroup() with exactly enough: %v", err)
	}
	cleanup()
	short, algodClient, cleanup := newPrepTestClients(t, sender, receiver, needed-1, 25, true)
	defer cleanup()
	if _, err := short.PrepareSweepGroup(context.Background(), algodClient, params); err == nil ||
		!strings.Contains(err.Error(), "group insufficient funds") {
		t.Fatalf("PrepareSweepGroup() one microAlgo short: error = %v, want the ASA transfer's fee counted", err)
	}
}

func TestGroupBalanceSumsDoNotWrap(t *testing.T) {
	sender, err := types.DecodeAddress(sdkTestAddress(1))
	if err != nil {
		t.Fatal(err)
	}
	payment := func(amount, fee uint64) PreparedTransaction {
		txn := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: sender, Fee: types.MicroAlgos(fee)}}
		txn.Amount = types.MicroAlgos(amount)
		return PreparedTransaction{
			Transaction: &txn,
			Checks:      []PreparedCheck{{Name: "payment_balance", Data: map[string]any{"available": uint64(5000)}}},
		}
	}
	// Two amounts that wrap to a small total, and a fee that wraps it.
	for name, items := range map[string][]PreparedTransaction{
		"amounts": {payment(math.MaxUint64-500, 0), payment(2000, 0)},
		"a fee":   {payment(1000, 0), payment(0, math.MaxUint64-100)},
	} {
		if _, err := groupAlgoBalanceCheck(items); err == nil || !strings.Contains(err.Error(), "overflows uint64") {
			t.Fatalf("groupAlgoBalanceCheck() with wrapping %s: error = %v, want an overflow refusal", name, err)
		}
	}
	if _, err := groupAlgoBalanceCheck([]PreparedTransaction{payment(1000, 1000), payment(2000, 1000)}); err != nil {
		t.Fatalf("groupAlgoBalanceCheck() error = %v", err)
	}
	if _, err := groupAlgoBalanceCheck([]PreparedTransaction{payment(1000, 1000), payment(2001, 1000)}); err == nil ||
		!strings.Contains(err.Error(), "available 5000, required 5001") {
		t.Fatalf("groupAlgoBalanceCheck() one over: error = %v", err)
	}
	// A position with no balance on record is refused, not passed.
	bare := payment(1, 1)
	bare.Checks = nil
	if _, err := groupAlgoBalanceCheck([]PreparedTransaction{bare}); err == nil || !strings.Contains(err.Error(), "no ALGO balance on record") {
		t.Fatalf("groupAlgoBalanceCheck() with no balance: error = %v", err)
	}
	if sum, ok := addChecked(math.MaxUint64, 1); ok {
		t.Fatalf("addChecked() = %d, true for a sum that wraps", sum)
	}
	if _, err := paymentChecks(models.Account{Amount: 10}, math.MaxUint64, 1); err == nil || !strings.Contains(err.Error(), "overflows uint64") {
		t.Fatalf("paymentChecks() error = %v, want an overflow refusal", err)
	}

	transfer := func(amount uint64) PreparedTransaction {
		txn := types.Transaction{Type: types.AssetTransferTx, Header: types.Header{Sender: sender}}
		txn.XferAsset = 1001
		txn.AssetAmount = amount
		return PreparedTransaction{
			Transaction: &txn,
			Checks:      []PreparedCheck{{Name: "asa_transfer", Data: map[string]any{"balance": uint64(5000)}}},
		}
	}
	if _, err := asaTransferGroupBalanceCheck([]PreparedTransaction{transfer(math.MaxUint64), transfer(2)}); err == nil ||
		!strings.Contains(err.Error(), "overflows uint64") {
		t.Fatalf("asaTransferGroupBalanceCheck() error = %v, want an overflow refusal", err)
	}
	if _, err := asaTransferGroupBalanceCheck([]PreparedTransaction{transfer(1000), transfer(2000)}); err != nil {
		t.Fatalf("asaTransferGroupBalanceCheck() error = %v", err)
	}
}

func TestCosignedGroupRefusesASignerKeyForAnotherAddress(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	client, server := newTestClient(func(http.ResponseWriter, *http.Request) {
		t.Error("the signer was contacted for a group with a mismatched signer key")
	})
	defer server.Close()
	_, err := SignPreparedCosignedGroup(PreparedCosignedGroupOptions{
		UserClient: client,
		PreparedGroup: NewPreparedGroup(PreparedTransaction{
			Transaction: &txn, AuthAddress: txn.Sender.String(),
			SignerKey: &KeyInfo{Address: sdkTestAddress(9), KeyType: "ed25519"},
		}),
	})
	if err == nil || !strings.Contains(err.Error(), "signer key is for "+sdkTestAddress(9)+", not the position's auth address") {
		t.Fatalf("SignPreparedCosignedGroup() error = %v", err)
	}
}

func TestRequestAssembleRefusesAnotherRequestsAnswer(t *testing.T) {
	answerWith := ""
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		var req AssemblyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode assembly request: %v", err)
		}
		id := answerWith
		if id == "" {
			id = req.RequestID
		}
		json.NewEncoder(w).Encode(AssemblyResponse{RequestID: id, SignedGroup: []string{"ccdd"}})
	})
	defer server.Close()
	request := AssemblyRequest{
		RequestID:     "sdk-mine",
		GroupBytesHex: []string{"5458aa"},
		Targets: []AssemblyTarget{{
			TargetIndex: 0, Kind: AssemblyTargetKindBoundedCosigner, AuthAddress: "BOUNDED",
			BaseSignatures: []string{"aabb"}, AssemblyReceipt: "eeff", CosignerSignature: "bbcc",
		}},
	}
	if _, err := client.RequestAssemble(request); err != nil {
		t.Fatalf("RequestAssemble() error = %v", err)
	}
	answerWith = "sdk-someone-elses"
	if _, err := client.RequestAssemble(request); err == nil ||
		!strings.Contains(err.Error(), `request_id "sdk-someone-elses" does not match the request's "sdk-mine"`) {
		t.Fatalf("RequestAssemble() error = %v, want a request_id mismatch", err)
	}
}

func TestNewAlgodClientEnforcesNetworksAllowed(t *testing.T) {
	config := &Config{
		Network:         "testnet",
		NetworksAllowed: []string{"testnet"},
		Algod: AlgodConfig{
			"testnet": {Server: "http://127.0.0.1:1"},
			"mainnet": {Server: "http://127.0.0.1:1"},
		},
	}
	if _, err := config.NewAlgodClient("testnet"); err != nil {
		t.Fatalf("NewAlgodClient(testnet) error = %v", err)
	}
	if _, err := config.NewAlgodClient("mainnet"); err == nil ||
		!strings.Contains(err.Error(), `network "mainnet" is not in networks_allowed`) {
		t.Fatalf("NewAlgodClient(mainnet) error = %v, want an allowlist refusal", err)
	}
	// An empty allowlist permits every configured network.
	config.NetworksAllowed = nil
	if _, err := config.NewAlgodClient("mainnet"); err != nil {
		t.Fatalf("NewAlgodClient(mainnet) with no allowlist: %v", err)
	}
}

// The cosigned flow takes each key's flow, resources and fee ceiling from the
// signer's own record. A key supplied on the prepared transaction is checked
// for the right address and nothing more.
func TestCosignedGroupTakesTheKeyFromTheSignerNotTheCaller(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	sender := txn.Sender.String()
	lookups := 0
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keys" {
			t.Errorf("unexpected request %s: the flow must stop at the signer's key record", r.URL.Path)
			return
		}
		lookups++
		// The signer's record: this key needs a flow this SDK does not have.
		json.NewEncoder(w).Encode(KeysResponse{Count: 1, Keys: []KeyInfo{{Address: sender, KeyType: "ed25519", SigningFlow: "cosigner9"}}})
	})
	defer server.Close()

	// The caller's copy claims an ordinary key.
	supplied := &KeyInfo{Address: sender, KeyType: "ed25519"}
	for name, key := range map[string]*KeyInfo{"a supplied key": supplied, "no supplied key": nil} {
		_, err := SignPreparedCosignedGroup(PreparedCosignedGroupOptions{
			UserClient:    client,
			PreparedGroup: NewPreparedGroup(PreparedTransaction{Transaction: &txn, AuthAddress: sender, SignerKey: key}),
		})
		if err == nil || !strings.Contains(err.Error(), `signing flow "cosigner9"`) {
			t.Fatalf("%s: error = %v, want the signer's record to decide the flow", name, err)
		}
	}
	// The record is cached: two groups, one lookup.
	if lookups != 1 {
		t.Fatalf("/keys was fetched %d times, want 1", lookups)
	}

	// A key the signer does not hold stops the flow.
	other := verifyTestPayment(t, 43, 44, 1)
	_, err := SignPreparedCosignedGroup(PreparedCosignedGroupOptions{
		UserClient: client,
		PreparedGroup: NewPreparedGroup(PreparedTransaction{
			Transaction: &other, AuthAddress: other.Sender.String(),
			SignerKey: &KeyInfo{Address: other.Sender.String(), KeyType: "ed25519", SigningFlow: SigningFlowCosigned1},
		}),
	})
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("a key the signer does not hold: error = %v, want ErrKeyNotFound", err)
	}
}

// Every sender is checked against everything it pays across a group: the
// ALGO it sends and the fee of every position, payments or not.
func TestGroupChecksEverySenderAgainstEverythingItPays(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	ctx := context.Background()
	transfers := []AsaTransferPrepParams{
		{Sender: sender, Receiver: receiver, AssetID: 1001, Amount: 5},
		{Sender: sender, Receiver: receiver, AssetID: 1001, Amount: 5},
	}
	rich, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 25, true)
	group, err := rich.PrepareSweepGroup(ctx, algodClient, SweepPrepParams{AsaTransfers: transfers})
	cleanup()
	if err != nil {
		t.Fatalf("PrepareSweepGroup() error = %v", err)
	}
	if last := group.Checks[len(group.Checks)-1]; last.Name != "group_algo_balance" {
		t.Fatalf("last check = %q, want group_algo_balance", last.Name)
	}
	// The mock's minimum balance is 100,000. A sweep with no payments still
	// has to cover its two fees.
	needed := 100_000 + uint64(group.Transactions[0].Transaction.Fee) + uint64(group.Transactions[1].Transaction.Fee)

	exact, algodClient, cleanup := newPrepTestClients(t, sender, receiver, needed, 25, true)
	if _, err := exact.PrepareSweepGroup(ctx, algodClient, SweepPrepParams{AsaTransfers: transfers}); err != nil {
		t.Fatalf("PrepareSweepGroup() with exactly enough: %v", err)
	}
	if _, err := exact.PrepareAsaTransferGroup(ctx, algodClient, transfers); err != nil {
		t.Fatalf("PrepareAsaTransferGroup() with exactly enough: %v", err)
	}
	cleanup()
	short, algodClient, cleanup := newPrepTestClients(t, sender, receiver, needed-1, 25, true)
	defer cleanup()
	if _, err := short.PrepareSweepGroup(ctx, algodClient, SweepPrepParams{AsaTransfers: transfers}); err == nil ||
		!strings.Contains(err.Error(), "group insufficient funds for "+sender) {
		t.Fatalf("PrepareSweepGroup() with no payments, one microAlgo short: error = %v", err)
	}
	if _, err := short.PrepareAsaTransferGroup(ctx, algodClient, transfers); err == nil ||
		!strings.Contains(err.Error(), "group insufficient funds for "+sender) {
		t.Fatalf("PrepareAsaTransferGroup() one microAlgo short: error = %v", err)
	}
}

// Go's ABI reference arguments go through the ABI uint64 encoder, which takes
// integers only: nothing is rounded or parsed from text.
func TestABIReferenceArgumentsAreNotCoerced(t *testing.T) {
	for _, bad := range []any{123.9, "123", true, -1} {
		if _, err := marshalABIUint64(bad); err == nil {
			t.Fatalf("marshalABIUint64(%#v) accepted a value that is not an unsigned integer", bad)
		}
	}
	for _, good := range []any{uint64(123), 123, uint8(7)} {
		if got, err := marshalABIUint64(good); err != nil || (got != 123 && got != 7) {
			t.Fatalf("marshalABIUint64(%#v) = %d, %v", good, got, err)
		}
	}
}
