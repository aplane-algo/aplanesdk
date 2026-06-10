// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/*
Minimal validation transaction example.

Sends a 0 ALGO self-payment to validate that signing works.
Works with any key type (Ed25519, Falcon, etc.).

Setup:

 1. Create data directory: mkdir -p ~/aplane/apclient/.ssh
 2. Copy token: cp /path/to/aplane.token ~/aplane/apclient/
 3. Copy SSH key: cp ~/.ssh/your_key ~/aplane/apclient/.ssh/id_ed25519
 4. Create config.yaml (see below)
 5. Set env: export APCLIENT_DATA=~/aplane/apclient

Example config.yaml (SSH tunnel):

	endpoint:
	  signer_port: 11270
	  ssh:
	    host: 192.168.86.73
	    port: 1127
	    identity_file: .ssh/id_ed25519
*/
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/aplane-algo/aplanesdk/go"
)

// The address to validate (must exist in apsigner keystore)
// Replace with your actual address
const sender = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777"

func main() {
	// Connect using config from $APCLIENT_DATA
	signer, err := aplane.FromEnv(nil)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer signer.Close()

	algodClient, err := algod.MakeClient("https://testnet-api.4160.nodely.dev", "")
	if err != nil {
		log.Fatalf("Failed to create algod client: %v", err)
	}

	// Build 0-ALGO self-send (validation transaction)
	params, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to get params: %v", err)
	}

	txn, err := transaction.MakePaymentTxn(sender, sender, 0, nil, "", params)
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	// Resolve auth address (handles rekeyed accounts)
	acctInfo, err := algodClient.AccountInformation(sender).Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to get account info: %v", err)
	}
	authAddr := acctInfo.AuthAddr
	if authAddr == "" {
		authAddr = sender
	}

	// Sign (server handles fee pooling automatically)
	fmt.Printf("Signing validation txn for %s...\n", sender[:12])
	signed, err := signer.SignTransaction(txn, authAddr, nil)
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}

	// Submit using standard go-algorand-sdk (signed is base64)
	signedBytes, err := aplane.Base64ToBytes(signed)
	if err != nil {
		log.Fatalf("Failed to decode signed txn: %v", err)
	}
	txid, err := algodClient.SendRawTransaction(signedBytes).Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to submit: %v", err)
	}
	fmt.Printf("Submitted: %s\n", txid)

	// Wait for confirmation
	result, err := transaction.WaitForConfirmation(algodClient, txid, 4, context.Background())
	if err != nil {
		log.Fatalf("Failed to confirm: %v", err)
	}
	fmt.Printf("Confirmed in round %d\n", result.ConfirmedRound)
}
