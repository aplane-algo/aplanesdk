// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/*
Atomic swap example - exchange ALGO between two accounts in a single group.

This demonstrates signing a transaction group where both parties must sign.
Works with any combination of key types (Ed25519, Falcon, etc.).

Setup:

 1. Create data directory: mkdir -p ~/aplane/apclient/.ssh
 2. Copy token: cp /path/to/aplane.token ~/aplane/apclient/
 3. Copy SSH key: cp ~/.ssh/your_key ~/aplane/apclient/.ssh/id_ed25519
 4. Create endpoints.yaml (see below)
 5. Set env: export APCLIENT_DATA=~/aplane/apclient

Example endpoints.yaml (SSH tunnel):

	schema_version: 1
	endpoints:
	  primary:
	    role: signer
	    url: ssh://192.168.86.73:1127
	    signer_port: 11270
	    identity_file: .ssh/id_ed25519

Important:
  - Do NOT pre-assign group IDs with transaction.AssignGroupID()
  - The server computes the group ID after adding any required dummy transactions
  - The return value can be submitted directly to algod
*/
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplanesdk/go"
)

// Swap parameters (replace with your actual addresses)
const (
	alice      = "ALICEED255EXAMPLE777777777777777777777777777777777777777777" // Ed25519 account
	bob        = "BOBFALCONEXAMPLE7777777777777777777777777777777777777777777" // Falcon account
	swapAmount = 100000                                                        // 0.1 ALGO in microAlgos
)

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

	params, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to get params: %v", err)
	}

	// Build transactions (do NOT call AssignGroupID)
	txnAliceToBob, err := transaction.MakePaymentTxn(alice, bob, swapAmount, nil, "", params)
	if err != nil {
		log.Fatalf("Failed to create Alice->Bob txn: %v", err)
	}

	txnBobToAlice, err := transaction.MakePaymentTxn(bob, alice, swapAmount, nil, "", params)
	if err != nil {
		log.Fatalf("Failed to create Bob->Alice txn: %v", err)
	}

	// Resolve auth addresses (handles rekeyed accounts)
	aliceInfo, err := algodClient.AccountInformation(alice).Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to get Alice account info: %v", err)
	}
	bobInfo, err := algodClient.AccountInformation(bob).Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to get Bob account info: %v", err)
	}

	aliceAuth := aliceInfo.AuthAddr
	if aliceAuth == "" {
		aliceAuth = alice
	}
	bobAuth := bobInfo.AuthAddr
	if bobAuth == "" {
		bobAuth = bob
	}

	// Sign the group (server handles grouping and dummies for Falcon)
	fmt.Printf("Signing atomic swap: %s... <-> %s...\n", alice[:8], bob[:8])
	signed, err := signer.SignTransactions(
		[]types.Transaction{txnAliceToBob, txnBobToAlice},
		[]string{aliceAuth, bobAuth},
		nil,
	)
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
	fmt.Println("Atomic swap complete!")
}
