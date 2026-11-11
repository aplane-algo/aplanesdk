// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/kmd"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
)

const liveRotatingKeyType = "aplane.rotating-triple-wotsc.v1"

// liveLocalNet returns a client for the LocalNet algod the suite is run
// against, or skips: a rotating send needs a real node and a funded account.
func liveLocalNet(t *testing.T) *algod.Client {
	t.Helper()
	url := strings.TrimSpace(os.Getenv("ALGOD_URL"))
	if url == "" || strings.TrimSpace(os.Getenv("APLANE_LOCALNET_KMD_URL")) == "" {
		t.Skip("needs a LocalNet algod and KMD (ALGOD_URL, APLANE_LOCALNET_KMD_URL)")
	}
	client, err := algod.MakeClient(url, os.Getenv("ALGOD_TOKEN"))
	if err != nil {
		t.Fatalf("algod client: %v", err)
	}
	return client
}

// fundFromLocalNetKMD pays receiver from the richest account of the LocalNet
// KMD wallet and waits for the payment to confirm.
func fundFromLocalNetKMD(t *testing.T, algodClient *algod.Client, receiver string, amount uint64) {
	t.Helper()
	ctx := context.Background()
	token := os.Getenv("APLANE_LOCALNET_TOKEN")
	if token == "" {
		token = os.Getenv("ALGOD_TOKEN")
	}
	kmdClient, err := kmd.MakeClient(strings.TrimSpace(os.Getenv("APLANE_LOCALNET_KMD_URL")), token)
	if err != nil {
		t.Fatalf("kmd client: %v", err)
	}
	walletName := os.Getenv("APLANE_LOCALNET_WALLET")
	if walletName == "" {
		walletName = "unencrypted-default-wallet"
	}
	password := os.Getenv("APLANE_LOCALNET_WALLET_PASSWORD")
	wallets, err := kmdClient.ListWallets()
	if err != nil {
		t.Fatalf("list KMD wallets: %v", err)
	}
	walletID := ""
	for _, wallet := range wallets.Wallets {
		if wallet.Name == walletName {
			walletID = wallet.ID
		}
	}
	if walletID == "" {
		t.Fatalf("LocalNet KMD has no wallet named %q", walletName)
	}
	handle, err := kmdClient.InitWalletHandle(walletID, password)
	if err != nil {
		t.Fatalf("open KMD wallet: %v", err)
	}
	defer kmdClient.ReleaseWalletHandle(handle.WalletHandleToken)
	keys, err := kmdClient.ListKeys(handle.WalletHandleToken)
	if err != nil {
		t.Fatalf("list KMD keys: %v", err)
	}
	funder, richest := "", uint64(0)
	for _, address := range keys.Addresses {
		info, err := algodClient.AccountInformation(address).Do(ctx)
		if err == nil && info.Amount >= richest {
			funder, richest = address, info.Amount
		}
	}
	if funder == "" {
		t.Fatal("LocalNet KMD wallet has no account")
	}
	params, err := algodClient.SuggestedParams().Do(ctx)
	if err != nil {
		t.Fatalf("suggested params: %v", err)
	}
	payment, err := transaction.MakePaymentTxn(funder, receiver, amount, nil, "", params)
	if err != nil {
		t.Fatalf("build funding payment: %v", err)
	}
	signed, err := kmdClient.SignTransaction(handle.WalletHandleToken, password, payment)
	if err != nil {
		t.Fatalf("sign funding payment: %v", err)
	}
	txID, err := algodClient.SendRawTransaction(signed.SignedTransaction).Do(ctx)
	if err != nil {
		t.Fatalf("submit funding payment: %v", err)
	}
	if _, err := transaction.WaitForConfirmation(algodClient, txID, 10, ctx); err != nil {
		t.Fatalf("confirm funding payment: %v", err)
	}
}

// A rotating account spends through SendPayment on a real node, twice in a
// row. The second spend is the one that shows the flow works after stage 0:
// the account's authorizer is then a stage address the signer does not list,
// and the unsigned simulation has to accept it.
func TestIntegrationRotatingSendOnLocalNet(t *testing.T) {
	algodClient := liveLocalNet(t)
	client := liveSignerClient(t)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	keyTypes, err := client.ListKeyTypes()
	if err != nil {
		t.Fatalf("list key types: %v", err)
	}
	if !hasKeyType(keyTypes, liveRotatingKeyType) {
		t.Skipf("key type %s is not enabled at the signer (apadmin keytype enable %s)", liveRotatingKeyType, liveRotatingKeyType)
	}
	params, err := algodClient.SuggestedParams().Do(ctx)
	if err != nil {
		t.Fatalf("suggested params: %v", err)
	}
	before, err := client.GetStatus()
	if err != nil {
		t.Fatalf("status before generate: %v", err)
	}
	generated, err := client.GenerateKey(liveRotatingKeyType, map[string]string{
		"network": base64.StdEncoding.EncodeToString(params.GenesisHash),
	})
	if err != nil {
		t.Fatalf("generate rotating account: %v", err)
	}
	account := generated.Address
	defer func() {
		if err := client.DeleteKey(account); err != nil {
			t.Logf("cleanup delete rotating key %s failed: %v", account, err)
		}
	}()
	waitForKeysetRevision(t, client, before.KeysetRevision, "rotating generate")
	fundFromLocalNetKMD(t, algodClient, account, 2_000_000)

	receiver := account // a self-payment moves nothing and still rotates
	var lastTarget uint64
	var lastRekeyTo string
	for spend := 0; spend < 2; spend++ {
		result, err := client.SendPayment(ctx, algodClient, PaymentPrepParams{Sender: account, Receiver: receiver, Amount: 0}, nil)
		if err != nil {
			t.Fatalf("spend %d: SendPayment() error = %v", spend+1, err)
		}
		details := result.Rotating
		if result.Flow != SigningFlowRotating1 || details == nil || result.Outcome != SendOutcomeConfirmed || result.ConfirmedRound == 0 {
			t.Fatalf("spend %d: result = %+v", spend+1, result)
		}
		if details.Stage != uint64(spend) || details.Target != uint64(spend)+1 {
			t.Fatalf("spend %d: stage %d to %d, want %d to %d", spend+1, details.Stage, details.Target, spend, spend+1)
		}
		if spend > 0 && details.Stage != lastTarget {
			t.Fatalf("spend %d signed with stage %d, but the account was handed to stage %d", spend+1, details.Stage, lastTarget)
		}
		// The chain agrees with what the SDK bound: the account is now
		// authorized by the address the signer reported.
		info, err := algodClient.AccountInformation(account).Do(ctx)
		if err != nil {
			t.Fatalf("spend %d: account info: %v", spend+1, err)
		}
		if info.AuthAddr != details.RekeyTo {
			t.Fatalf("spend %d: chain authorizer %s, signer reported %s", spend+1, info.AuthAddr, details.RekeyTo)
		}
		if spend > 0 && details.RekeyTo == lastRekeyTo {
			t.Fatalf("spend %d rotated to the same address as the one before", spend+1)
		}
		t.Logf("spend %d: stage %d -> %d, %d transaction(s), fee %d, attempts %d, confirmed in round %d",
			spend+1, details.Stage, details.Target, len(result.SignedGroup), result.Fees[0], details.Attempts, result.ConfirmedRound)
		lastTarget, lastRekeyTo = details.Target, details.RekeyTo
	}

	// The steps on their own: prepare and simulate use no key.
	prepared, err := client.PreparePayment(ctx, algodClient, PaymentPrepParams{Sender: account, Receiver: receiver, Amount: 0})
	if err != nil {
		t.Fatalf("PreparePayment() after two rotations error = %v", err)
	}
	if prepared.AuthAddress != account {
		t.Fatalf("auth address %s, want the rotating account itself", prepared.AuthAddress)
	}
	rotating, err := client.PrepareRotating(ctx, *prepared.Transaction, nil)
	if err != nil {
		t.Fatalf("PrepareRotating() error = %v", err)
	}
	if rotating.Stage() != lastTarget {
		t.Fatalf("prepared at stage %d, want %d", rotating.Stage(), lastTarget)
	}
	simulation, err := client.SimulatePreparedRotating(ctx, algodClient, rotating)
	if err != nil || simulation.Failed {
		t.Fatalf("SimulatePreparedRotating() = %+v, %v", simulation, err)
	}
}
