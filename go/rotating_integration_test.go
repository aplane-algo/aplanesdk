// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/kmd"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
)

// liveRotatingKeyType is the family whose answers the shared rotating
// vectors hold.
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

// liveRotatingFamilies are the rotating families the live test runs, each
// for as long as its spends may take. SLH-DSA signs slowly.
var liveRotatingFamilies = []struct {
	keyType string
	limit   time.Duration
}{
	{"aplane.rotating-triple-wotsc.v1", 5 * time.Minute},
	{"aplane.rotating-triple-xmss.v1", 5 * time.Minute},
	{"aplane.rotating-triple-slhdsa.v1", 20 * time.Minute},
}

// A rotating account of each family the signer has enabled spends through
// SendPayment on a real node, twice in a row. The second spend is the one
// that shows the flow works after stage 0: the account's authorizer is then a
// stage address the signer does not list, and the unsigned simulation has to
// accept it. A family the signer does not list is skipped by name.
func TestIntegrationRotatingSendOnLocalNet(t *testing.T) {
	algodClient := liveLocalNet(t)
	client := liveSignerClient(t)
	defer client.Close()

	keyTypes, err := client.ListKeyTypes()
	if err != nil {
		t.Fatalf("list key types: %v", err)
	}
	for _, family := range liveRotatingFamilies {
		t.Run(family.keyType, func(t *testing.T) {
			if !hasKeyType(keyTypes, family.keyType) {
				t.Skipf("key type %s is not enabled at the signer (apadmin keytype enable %s)", family.keyType, family.keyType)
			}
			ctx, cancel := liveFamilyContext(t, family.limit)
			defer cancel()
			account, lastTarget := liveRotatingSpends(t, ctx, client, algodClient, family.keyType)
			if family.keyType == liveRotatingKeyType {
				liveRotatingSteps(t, ctx, client, algodClient, account, lastTarget)
			}
		})
	}
}

// liveFamilyContext bounds one family's run by its limit, and ends it a
// little before the test binary's own deadline so a slow family fails with
// its error rather than a panic.
func liveFamilyContext(t *testing.T, limit time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	if deadline, ok := t.Deadline(); ok {
		if remaining := time.Until(deadline) - 30*time.Second; remaining < limit {
			t.Logf("the test deadline leaves %v of this family's %v; run with a longer -timeout", remaining.Round(time.Second), limit)
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), max(remaining, time.Second))
		}
	}
	return ctx, cancel
}

// liveRotatingSpends generates and funds a rotating account of keyType and
// sends two self-payments from it with SendPayment: stage 0 to 1, then 1 to
// 2. It returns the account and the stage that now controls it. The key is
// deleted when the test ends.
func liveRotatingSpends(t *testing.T, ctx context.Context, client *SignerClient, algodClient *algod.Client, keyType string) (string, uint64) {
	t.Helper()
	account := liveRotatingAccount(t, ctx, client, algodClient, keyType)
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
		t.Logf("%s spend %d: stage %d -> %d, %d transaction(s), fee %d, attempts %d, confirmed in round %d",
			keyType, spend+1, details.Stage, details.Target, len(result.SignedGroup), result.Fees[0], details.Attempts, result.ConfirmedRound)
		lastTarget, lastRekeyTo = details.Target, details.RekeyTo
	}
	return account, lastTarget
}

// liveRotatingAccount generates a rotating account of keyType on the node's
// network, funds it, and deletes its key when the test ends.
func liveRotatingAccount(t *testing.T, ctx context.Context, client *SignerClient, algodClient *algod.Client, keyType string) string {
	t.Helper()
	params, err := algodClient.SuggestedParams().Do(ctx)
	if err != nil {
		t.Fatalf("suggested params: %v", err)
	}
	before, err := client.GetStatus()
	if err != nil {
		t.Fatalf("status before generate: %v", err)
	}
	generated, err := client.GenerateKey(keyType, map[string]string{
		"network": base64.StdEncoding.EncodeToString(params.GenesisHash),
	})
	if err != nil {
		t.Fatalf("generate rotating account: %v", err)
	}
	account := generated.Address
	t.Cleanup(func() {
		if err := client.DeleteKey(account); err != nil {
			t.Logf("cleanup delete rotating key %s failed: %v", account, err)
		}
	})
	waitForKeysetRevision(t, client, before.KeysetRevision, "rotating generate")
	fundFromLocalNetKMD(t, algodClient, account, 2_000_000)
	return account
}

// liveRotatingSteps sends a third spend one step at a time, as a caller
// managing submission itself would, then checks the steps on their own. When
// asked, this is also where real signer answers are captured for the shared
// rotating vectors, which are WOTS-C answers.
func liveRotatingSteps(t *testing.T, ctx context.Context, client *SignerClient, algodClient *algod.Client, account string, lastTarget uint64) {
	t.Helper()
	steppedPrepared, steppedSigned := steppedRotatingSpend(t, ctx, client, algodClient, account)
	if steppedSigned.Stage != lastTarget {
		t.Fatalf("stepped spend signed with stage %d, want %d", steppedSigned.Stage, lastTarget)
	}
	lastTarget = steppedSigned.Target
	captureRotatingVector(t, "wotsc_stage2", steppedPrepared, steppedSigned)
	if os.Getenv("APLANE_SDK_CAPTURE_ROTATING") == "1" {
		// A stage 0 answer differs: the account signs as itself, so the
		// spend names no signer. Capture one from a fresh account.
		fresh := liveRotatingAccount(t, ctx, client, algodClient, liveRotatingKeyType)
		freshPrepared, freshSigned := steppedRotatingSpend(t, ctx, client, algodClient, fresh)
		captureRotatingVector(t, "wotsc_stage0", freshPrepared, freshSigned)
	}

	// The steps on their own: prepare and simulate use no key.
	prepared, err := client.PreparePayment(ctx, algodClient, PaymentPrepParams{Sender: account, Receiver: account, Amount: 0})
	if err != nil {
		t.Fatalf("PreparePayment() after three rotations error = %v", err)
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

// steppedRotatingSpend sends one self-payment from a rotating account with
// the step calls: prepare, simulate unsigned, sign, submit.
func steppedRotatingSpend(t *testing.T, ctx context.Context, client *SignerClient, algodClient *algod.Client, account string) (*PreparedRotating, *RotatingSignResult) {
	t.Helper()
	payment, err := client.PreparePayment(ctx, algodClient, PaymentPrepParams{Sender: account, Receiver: account, Amount: 0})
	if err != nil {
		t.Fatalf("PreparePayment() for the stepped spend error = %v", err)
	}
	prepared, err := client.PrepareRotating(ctx, *payment.Transaction, nil)
	if err != nil {
		t.Fatalf("stepped PrepareRotating() error = %v", err)
	}
	if simulation, err := client.SimulatePreparedRotating(ctx, algodClient, prepared); err != nil || simulation.Failed {
		t.Fatalf("stepped SimulatePreparedRotating() = %+v, %v", simulation, err)
	}
	signed, err := client.SignPreparedRotating(ctx, prepared, nil)
	if err != nil {
		t.Fatalf("stepped SignPreparedRotating() error = %v", err)
	}
	result, err := client.SubmitSignedGroup(ctx, algodClient, signed.SignedGroup, nil)
	if err != nil || result.Outcome != SendOutcomeConfirmed || result.TxIDs[0] != signed.TxID {
		t.Fatalf("stepped SubmitSignedGroup() = %+v, %v", result, err)
	}
	return prepared, signed
}

// captureRotatingVector writes a real prepare and sign answer into the shared
// rotating vectors when APLANE_SDK_CAPTURE_ROTATING=1. The keys are throwaway
// LocalNet keys. After capturing, regenerate the altered answers with
// APLANE_UPDATE_ROTATING_VECTORS=1 go test -run TestRotatingVectors.
func captureRotatingVector(t *testing.T, name string, prepared *PreparedRotating, signed *RotatingSignResult) {
	t.Helper()
	if os.Getenv("APLANE_SDK_CAPTURE_ROTATING") != "1" {
		return
	}
	var vectors rotatingVectors
	if raw, err := os.ReadFile(rotatingVectorsPath()); err == nil {
		if err := json.Unmarshal(raw, &vectors); err != nil {
			t.Fatalf("parse rotating vectors: %v", err)
		}
	}
	if vectors.Cases == nil {
		vectors.Cases = map[string]rotatingVectorCase{}
	}
	vectors.Cases[name] = rotatingVectorCase{
		KeyType:     liveRotatingKeyType,
		OriginalTxn: hex.EncodeToString(prepared.original),
		Prepare: RotatingPrepareResponse{
			Account: prepared.Account(), Stage: prepared.Stage(), Target: prepared.Target(),
			RekeyTo: prepared.RekeyTo(), Transactions: prepared.Transactions(), Mutations: prepared.Mutations(),
		},
		Sign: RotatingSignResponse{
			Signed: hexEntries(signed.SignedGroup), Stage: signed.Stage, Target: signed.Target,
			TxID: signed.TxID, GroupID: signed.GroupID,
		},
	}
	raw, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rotatingVectorsPath(), append(raw, '\n'), 0o644); err != nil {
		t.Fatalf("write rotating vectors: %v", err)
	}
	t.Logf("captured rotating vector %s", name)
}
