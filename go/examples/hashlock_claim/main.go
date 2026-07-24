// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/*
Hashlock claim example - demonstrates generic LogicSig with runtime arguments.

This example shows how to claim funds from a hashlock LogicSig by providing
the preimage that hashes to the stored hash.

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

Prerequisites:
  - A hashlock key must exist in the signer's keystore
  - The hashlock address must have funds to claim
  - You must know the preimage that hashes to the stored hash
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

// The hashlock address (must exist in apsigner keystore)
const hashlockAddress = "HASHLOCKEXAMPLE7777777777777777777777777777777777777777"

// The recipient address (where funds will be sent)
const recipient = "RECIPIENTEXAMPLE777777777777777777777777777777777777777"

// The secret preimage (must hash to the stored hash)
// For SHA256: sha256.Sum256(preimage) == stored_hash
var preimage = []byte("my_secret_preimage_32_bytes_long")

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

	// Discover required arguments for this LogicSig
	keyInfo, err := signer.GetKeyInfo(hashlockAddress)
	if err != nil {
		log.Fatalf("Failed to get key info: %v", err)
	}
	if keyInfo != nil && len(keyInfo.SigningArgs) > 0 {
		fmt.Println("Required arguments for this LogicSig:")
		for _, arg := range keyInfo.SigningArgs {
			fmt.Printf("  - %s: %s (%s)\n", arg.Name, arg.Type, arg.Description)
		}
	}

	// Build claim transaction (send all funds to recipient)
	params, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to get params: %v", err)
	}

	txn, err := transaction.MakePaymentTxn(hashlockAddress, recipient, 0, nil, recipient, params)
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	// Sign with the preimage argument
	fmt.Println("Signing hashlock claim with preimage...")
	signed, err := signer.SignTransaction(
		txn,
		hashlockAddress,
		aplane.LsigArgs{"preimage": preimage},
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
	fmt.Println("Hashlock claimed successfully!")
}
