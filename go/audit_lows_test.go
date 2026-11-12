// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
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
			Checks:      []PreparedCheck{{Name: spendableAlgoCheckName, Data: map[string]any{"available": uint64(5000)}}},
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
	// The spendable balance comes from the spendable_algo check and nowhere
	// else. A position without it, or with a value of another type, is
	// refused, not passed, even beside a position of the same sender that has
	// one.
	for name, tc := range map[string]struct {
		checks []PreparedCheck
		want   string
	}{
		"no checks":                    {nil, "no ALGO balance on record"},
		"available under another name": {[]PreparedCheck{{Name: "payment_balance", Data: map[string]any{"available": uint64(5000)}}}, "no ALGO balance on record"},
		"no available amount":          {[]PreparedCheck{{Name: spendableAlgoCheckName, Data: map[string]any{"balance": uint64(5000)}}}, "has no available amount"},
		"nil data":                     {[]PreparedCheck{{Name: spendableAlgoCheckName}}, "has no available amount"},
		"an int":                       {[]PreparedCheck{{Name: spendableAlgoCheckName, Data: map[string]any{"available": 5000}}}, "must be a uint64, not int"},
		"a string":                     {[]PreparedCheck{{Name: spendableAlgoCheckName, Data: map[string]any{"available": "5000"}}}, "must be a uint64, not string"},
		"a float":                      {[]PreparedCheck{{Name: spendableAlgoCheckName, Data: map[string]any{"available": 5000.0}}}, "must be a uint64, not float64"},
	} {
		bare := payment(1, 1)
		bare.Checks = tc.checks
		_, err := groupAlgoBalanceCheck([]PreparedTransaction{payment(1, 1), bare})
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "group transaction 1, sender ") {
			t.Fatalf("groupAlgoBalanceCheck() with %s: error = %v, want %q", name, err, tc.want)
		}
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

// keysetSigner is a signer whose key list and keyset revision a test sets. It
// counts /keys fetches, and fails the test on any request past the key read.
type keysetSigner struct {
	revision uint64
	keys     []KeyInfo
	fetches  int
}

func (k *keysetSigner) client(t *testing.T) (*SignerClient, func()) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{State: "unlocked", KeysetRevision: k.revision})
		case "/keys":
			k.fetches++
			json.NewEncoder(w).Encode(KeysResponse{Count: len(k.keys), Keys: k.keys})
		default:
			t.Errorf("unexpected request %s: the flow must stop at the signer's key record", r.URL.Path)
		}
	})
	return client, server.Close
}

// The cosigned flow takes each key's flow, resources and fee ceiling from the
// signer's own record: the spendable key for the position's auth address, read
// from a key list that is refreshed when the signer's keyset revision changes.
// It is the lookup the prepare helpers make. A prepared transaction carries no
// key of its own.
func TestCosignedGroupTakesTheSpendableKeyFromTheSigner(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	sender := txn.Sender.String()
	notSpending := false
	attempt := func(client *SignerClient) error {
		_, err := SignPreparedCosignedGroup(PreparedCosignedGroupOptions{
			UserClient:    client,
			PreparedGroup: NewPreparedGroup(PreparedTransaction{Transaction: &txn, AuthAddress: sender}),
		})
		return err
	}

	// Two rows for one address, the non-spending one last. The spendable row
	// decides the flow, on the fresh read and again from the cache.
	// A second spendable row follows as well: the first one is the one
	// chosen, from the fresh list and from the cache alike.
	signer := &keysetSigner{revision: 1, keys: []KeyInfo{
		{Address: sender, KeyType: KeyTypeWitnessFalcon1024, IsSpendingAccount: &notSpending, SigningFlow: "witness8"},
		{Address: sender, KeyType: "ed25519", SigningFlow: "cosigner9"},
		{Address: sender, KeyType: "ed25519", SigningFlow: "cosigner11"},
		{Address: sender, KeyType: KeyTypeWitnessFalcon1024, IsSpendingAccount: &notSpending, SigningFlow: "witness9"},
	}}
	client, closeServer := signer.client(t)
	defer closeServer()
	for i := 0; i < 2; i++ {
		if err := attempt(client); err == nil || !strings.Contains(err.Error(), `signing flow "cosigner9"`) {
			t.Fatalf("attempt %d: error = %v, want the spendable row to decide the flow", i+1, err)
		}
	}
	// An unchanged keyset revision costs no further /keys request.
	if signer.fetches != 1 {
		t.Fatalf("/keys was fetched %d times for an unchanged revision, want 1", signer.fetches)
	}
	// The prepare helpers select the same row.
	resolved, err := client.ResolveAuthAddress(context.Background(), sender, func(context.Context, string) (string, error) { return "", nil })
	if err != nil || resolved.KeyInfo.SigningFlow != "cosigner9" {
		t.Fatalf("ResolveAuthAddress() = %+v, %v, want the spendable row", resolved, err)
	}
	if signer.fetches != 1 {
		t.Fatalf("/keys was fetched %d times, want the prepare helper to share the cached list", signer.fetches)
	}

	// The operator changes the key: a new revision, and the next call reads
	// the new record.
	signer.revision = 2
	signer.keys = []KeyInfo{{Address: sender, KeyType: "ed25519", SigningFlow: "cosigner10"}}
	if err := attempt(client); err == nil || !strings.Contains(err.Error(), `signing flow "cosigner10"`) {
		t.Fatalf("after a keyset change: error = %v, want the new record", err)
	}
	if signer.fetches != 2 {
		t.Fatalf("/keys was fetched %d times after one keyset change, want 2", signer.fetches)
	}

	// Only a non-spending row for the address: there is no key to sign with.
	signer.revision = 3
	signer.keys = []KeyInfo{{Address: sender, KeyType: KeyTypeWitnessFalcon1024, IsSpendingAccount: &notSpending}}
	if err := attempt(client); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("a witness-only address: error = %v, want ErrKeyNotFound", err)
	}
	// A position with no auth address has nothing to look a key up by.
	_, err = SignPreparedCosignedGroup(PreparedCosignedGroupOptions{
		UserClient:    client,
		PreparedGroup: NewPreparedGroup(PreparedTransaction{Transaction: &txn}),
	})
	if err == nil || !strings.Contains(err.Error(), "auth address is required") {
		t.Fatalf("a position with no auth address: error = %v", err)
	}
	if _, has := reflect.TypeOf(PreparedTransaction{}).FieldByName("SignerKey"); has {
		t.Fatal("PreparedTransaction still has a SignerKey field")
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

// An asset transfer moves no ALGO but pays a fee, and the transfer's own check
// compares that fee with what the sender can spend. A single transfer and a
// group of one therefore agree.
func TestAsaTransferChecksItsFeeAgainstSpendableAlgo(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	ctx := context.Background()
	transfer := AsaTransferPrepParams{Sender: sender, Receiver: receiver, AssetID: 1001, Amount: 5}

	rich, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 25, true)
	prepared, err := rich.PrepareAsaTransfer(ctx, algodClient, transfer)
	cleanup()
	if err != nil {
		t.Fatalf("PrepareAsaTransfer() error = %v", err)
	}
	fee := uint64(prepared.Transaction.Fee)
	// The two checks, and the data all three SDKs record.
	if len(prepared.Checks) != 2 || prepared.Checks[0].Name != "asa_transfer" || prepared.Checks[1].Name != spendableAlgoCheckName {
		t.Fatalf("checks = %#v, want asa_transfer then %s", prepared.Checks, spendableAlgoCheckName)
	}
	if got := prepared.Checks[0].Data["fee"]; got != fee {
		t.Fatalf("asa_transfer fee = %#v, want %d", got, fee)
	}
	if _, has := prepared.Checks[0].Data["available"]; has {
		t.Fatal("asa_transfer still records an available amount; spendable_algo is its one source")
	}
	if got := prepared.Checks[1].Data["available"]; got != uint64(1_900_000) {
		t.Fatalf("spendable_algo available = %#v, want 1900000", got)
	}

	// The mock's minimum balance is 100,000. Exactly the fee is enough.
	exact, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 100_000+fee, 25, true)
	if _, err := exact.PrepareAsaTransfer(ctx, algodClient, transfer); err != nil {
		t.Fatalf("PrepareAsaTransfer() with exactly the fee: %v", err)
	}
	if _, err := exact.PrepareAsaTransferGroup(ctx, algodClient, []AsaTransferPrepParams{transfer}); err != nil {
		t.Fatalf("PrepareAsaTransferGroup() with exactly the fee: %v", err)
	}
	cleanup()

	// One microAlgo short: the single helper and both group helpers refuse
	// with the transfer's own message.
	short, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 100_000+fee-1, 25, true)
	defer cleanup()
	want := fmt.Sprintf("insufficient funds for asset transfer fee: available %d, fee %d", fee-1, fee)
	if _, err := short.PrepareAsaTransfer(ctx, algodClient, transfer); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("PrepareAsaTransfer() one microAlgo short: error = %v, want %q", err, want)
	}
	if _, err := short.PrepareAsaTransferGroup(ctx, algodClient, []AsaTransferPrepParams{transfer}); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("PrepareAsaTransferGroup() one microAlgo short: error = %v, want %q", err, want)
	}
	if _, err := short.PrepareSweepGroup(ctx, algodClient, SweepPrepParams{AsaTransfers: []AsaTransferPrepParams{transfer}}); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("PrepareSweepGroup() one microAlgo short: error = %v, want %q", err, want)
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

// A networks_allowed that cannot be read must not become an empty list, which
// permits every network, and an entry that is not text is not a network name.
// The Python and TypeScript suites run the same cases.
func TestLoadConfigRequiresNetworksAllowedToBeAListOfText(t *testing.T) {
	load := func(value string) (*Config, error) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("network: testnet\nnetworks_allowed: "+value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig(dir)
	}
	for _, value := range []string{
		"mainnet", "{a: b}", "[testnet, [a]]", "[testnet, Mainnet]", "[testnet, 1.5]", "[testnet, -x]",
		"[testnet, 1]", "[testnet, true]", "[testnet, null]", "[testnet, ~]",
	} {
		if _, err := load(value); err == nil || !strings.Contains(err.Error(), "networks_allowed") {
			t.Fatalf("networks_allowed: %s: error = %v, want a refusal", value, err)
		}
	}
	for value, want := range map[string][]string{
		"[]": {},
		"":   {},
		// A name made of digits, or spelled like a boolean, is fine once quoted.
		`[testnet, "1"]`:      {"testnet", "1"},
		`[testnet, "true"]`:   {"testnet", "true"},
		"[testnet, my_net-2]": {"testnet", "my_net-2"},
	} {
		config, err := load(value)
		if err != nil {
			t.Fatalf("networks_allowed: %s: error = %v", value, err)
		}
		if strings.Join(config.NetworksAllowed, ",") != strings.Join(want, ",") {
			t.Fatalf("networks_allowed: %s = %q, want %q", value, config.NetworksAllowed, want)
		}
	}
}

// A zero app or asset reference names nothing. It is refused wherever the
// Python and TypeScript SDKs refuse it: foreign apps and foreign assets on a
// raw call, an ABI call and a deploy, and ABI application and asset
// reference arguments. A box's app index may be zero (the called app), and a
// deploy has no app ID to give.
func TestZeroAppAndAssetReferencesAreRefused(t *testing.T) {
	sender := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	ctx := context.Background()
	signer, algodClient, cleanup := newPrepTestClients(t, sender, receiver, 2_000_000, 0, false)
	defer cleanup()
	program := []byte{0x06, 0x81, 0x01}
	call := AppCallPrepParams{Sender: sender, AppID: 7}

	refused := map[string]func() error{
		"foreign_apps[1] must be greater than zero": func() error {
			params := call
			params.ForeignApps = []uint64{9, 0}
			_, err := signer.PrepareAppCall(ctx, algodClient, params)
			return err
		},
		"foreign_assets[0] must be greater than zero": func() error {
			params := call
			params.ForeignAssets = []uint64{0}
			_, err := signer.PrepareAppCall(ctx, algodClient, params)
			return err
		},
		"application argument must be greater than zero": func() error {
			_, err := signer.PrepareABIAppCall(ctx, algodClient, ABIAppCallPrepParams{
				AppCallPrepParams: call, MethodSignature: "f(application)void", Args: []any{uint64(0)},
			})
			return err
		},
		"asset argument must be greater than zero": func() error {
			_, err := signer.PrepareABIAppCall(ctx, algodClient, ABIAppCallPrepParams{
				AppCallPrepParams: call, MethodSignature: "f(asset)void", Args: []any{uint64(0)},
			})
			return err
		},
	}
	for want, attempt := range refused {
		if err := attempt(); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want %q", err, want)
		}
	}
	abiWithZeroForeign := call
	abiWithZeroForeign.ForeignApps = []uint64{0}
	if _, err := signer.PrepareABIAppCall(ctx, algodClient, ABIAppCallPrepParams{
		AppCallPrepParams: abiWithZeroForeign, MethodSignature: "f()void",
	}); err == nil || !strings.Contains(err.Error(), "foreign_apps[0] must be greater than zero") {
		t.Fatalf("ABI call with a zero foreign app: error = %v", err)
	}
	for _, deploy := range []AppDeployPrepParams{
		{Sender: sender, ApprovalProgram: program, ClearProgram: program, ForeignApps: []uint64{0}},
		{Sender: sender, ApprovalProgram: program, ClearProgram: program, ForeignAssets: []uint64{0}},
	} {
		if _, err := signer.PrepareAppDeploy(ctx, algodClient, deploy); err == nil || !strings.Contains(err.Error(), "must be greater than zero") {
			t.Fatalf("PrepareAppDeploy() with a zero reference: error = %v", err)
		}
	}

	// Still valid: non-zero references, a box on the called app, and a deploy,
	// which creates the app and so names no app ID.
	ok := call
	ok.ForeignApps, ok.ForeignAssets = []uint64{9}, []uint64{1001}
	ok.Boxes = []types.AppBoxReference{{AppID: 0, Name: []byte("a")}}
	if _, err := signer.PrepareAppCall(ctx, algodClient, ok); err != nil {
		t.Fatalf("PrepareAppCall() with valid references: %v", err)
	}
	if _, err := signer.PrepareABIAppCall(ctx, algodClient, ABIAppCallPrepParams{
		AppCallPrepParams: call, MethodSignature: "f(asset,application)void", Args: []any{uint64(1001), uint64(9)},
	}); err != nil {
		t.Fatalf("PrepareABIAppCall() with valid reference arguments: %v", err)
	}
	created, err := signer.PrepareAppDeploy(ctx, algodClient, AppDeployPrepParams{Sender: sender, ApprovalProgram: program, ClearProgram: program})
	if err != nil {
		t.Fatalf("PrepareAppDeploy() error = %v", err)
	}
	if created.Transaction.ApplicationID != 0 {
		t.Fatalf("deploy transaction app ID = %d, want 0 for a create", created.Transaction.ApplicationID)
	}
}

// strictBase64Cases is the case list the Python and TypeScript suites run too:
// the three SDKs accept and refuse the same strings.
var strictBase64Cases = struct{ accepted, refused []string }{
	accepted: []string{"", "QQ==", "QUI=", "QUJD", "QUJDRA==", "+/+/", "AAAA"},
	refused: []string{
		"QUJD\n",       // a trailing line feed
		"QUJD\r\n",     // a trailing CRLF
		"QU\nJD",       // a line feed inside
		"QUJD\r\nQUJD", // a wrapped line
		"\nQUJD",       // a leading line feed
		"QU JD",        // a space
		"QUJD ",        // a trailing space
		"\tQUJD",       // a tab
		"QU*D",         // a character outside the alphabet
		"-_-_",         // the URL-safe alphabet
		"QUI",          // missing padding
		"QQ=",          // short padding
		"QQ===",        // long padding
		"QUI=QUJD",     // data after the padding
		"=QUJ",         // padding first
		"Q",            // one character
	},
}

// Base64ToBytes is the SDK's one base64 decoder, and it is strict.
func TestBase64ToBytesIsStrict(t *testing.T) {
	for _, good := range strictBase64Cases.accepted {
		decoded, err := Base64ToBytes(good)
		if err != nil || BytesToBase64(decoded) != good {
			t.Fatalf("Base64ToBytes(%q) = %x, %v", good, decoded, err)
		}
	}
	for _, bad := range strictBase64Cases.refused {
		if decoded, err := Base64ToBytes(bad); err == nil || !strings.Contains(err.Error(), "not valid base64") {
			t.Fatalf("Base64ToBytes(%q) = %x, %v, want a refusal", bad, decoded, err)
		}
	}
}

// Whole config files the Python and TypeScript suites load too. A YAML alias
// is read as the value it stands for, for the list and for an entry, and the
// default network must be text like the allowlist's entries: yaml.v3 alone
// would read a bare 1 or true into the string field as "1" or "true".
func TestLoadConfigNetworkAliasesAndTextNetwork(t *testing.T) {
	load := func(content string) (*Config, error) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig(dir)
	}
	for _, tc := range []struct {
		content string
		network string
		allowed []string
	}{
		{"nets: &nets [testnet]\nnetworks_allowed: *nets\n", "testnet", []string{"testnet"}},
		{"name: &name testnet\nnetworks_allowed: [*name, mainnet]\n", "testnet", []string{"testnet", "mainnet"}},
		{"name: &name mainnet\nnetwork: *name\n", "mainnet", []string{}},
		{"network: ~\n", "testnet", []string{}},
		{"network: \"1\"\n", "1", []string{}},
		{"network: \"1\"\nnetworks_allowed: [\"1\"]\n", "1", []string{"1"}},
	} {
		config, err := load(tc.content)
		if err != nil {
			t.Fatalf("%q: error = %v", tc.content, err)
		}
		if config.Network != tc.network || strings.Join(config.NetworksAllowed, ",") != strings.Join(tc.allowed, ",") {
			t.Fatalf("%q: network = %q, allowed = %q, want %q, %q", tc.content, config.Network, config.NetworksAllowed, tc.network, tc.allowed)
		}
	}
	for _, tc := range []struct{ content, want string }{
		{"n: &n 1\nnetworks_allowed: [*n]\n", "networks_allowed"},
		{"n: &n {a: b}\nnetworks_allowed: *n\n", "networks_allowed"},
		{"network: 1\n", "invalid network in config.yaml"},
		{"network: 1\nnetworks_allowed: [testnet]\n", "invalid network in config.yaml"},
		{"network: true\n", "invalid network in config.yaml"},
		{"network: 1.5\n", "invalid network in config.yaml"},
		{"network: [a]\n", "invalid network in config.yaml"},
		{"network: Mainnet\n", "invalid network in config.yaml"},
		{"n: &n 1\nnetwork: *n\n", "invalid network in config.yaml"},
	} {
		if _, err := load(tc.content); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%q: error = %v, want a refusal naming %q", tc.content, err, tc.want)
		}
	}
}

// Several positions of one sender each read its balance on their own. The
// group check takes the lowest value recorded, whatever their order.
func TestGroupBalanceUsesTheLowestRecordedSpendableAlgo(t *testing.T) {
	sender, err := types.DecodeAddress(sdkTestAddress(1))
	if err != nil {
		t.Fatal(err)
	}
	position := func(available uint64) PreparedTransaction {
		txn := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: sender, Fee: 1000}}
		return PreparedTransaction{
			Transaction: &txn,
			Checks:      []PreparedCheck{{Name: spendableAlgoCheckName, Data: map[string]any{"available": available}}},
		}
	}
	for _, order := range [][]uint64{{5000, 1999}, {1999, 5000}} {
		_, err := groupAlgoBalanceCheck([]PreparedTransaction{position(order[0]), position(order[1])})
		if err == nil || !strings.Contains(err.Error(), "available 1999, required 2000") {
			t.Fatalf("recorded %v: error = %v, want the lowest value checked", order, err)
		}
	}
	for _, order := range [][]uint64{{5000, 2000}, {2000, 5000}, {0, 0}} {
		_, err := groupAlgoBalanceCheck([]PreparedTransaction{position(order[0]), position(order[1])})
		if (order[0] == 0) != (err != nil) {
			t.Fatalf("recorded %v: error = %v", order, err)
		}
	}
}
