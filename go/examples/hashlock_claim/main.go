// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/*
Hashlock claim example - demonstrates generic LogicSig with runtime arguments.

This example shows how to claim funds from a hashlock LogicSig by providing
the preimage that hashes to the stored hash. The argument travels with the
prepared transaction, and SendPrepared signs, submits and confirms it as it
does any other.

Setup:

 1. Create data directory: mkdir -p ~/aplane/apclient/.ssh
 2. Generate APlane SSH key: ssh-keygen -t ed25519 -f ~/aplane/apclient/.ssh/id_ed25519 -N ""
 3. Enroll it at the signer: run apshell enroll (or aplane.RequestEnrollmentFromEnv) and approve in apadmin
 4. Create endpoints.yaml (see below)
 5. Set env: export APCLIENT_DATA=~/aplane/apclient

Example endpoints.yaml (SSH tunnel):

	schema_version: 2
	endpoints:
	  primary:
	    role: signer
	    url: ssh://192.168.86.73:1127
	    identity_file: .ssh/id_ed25519

Prerequisites:
  - A hashlock key must exist in the signer's keystore
  - The hashlock address must have funds to claim
  - You must know the preimage that hashes to the stored hash
*/
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
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
	ctx := context.Background()
	// Connect using config from $APCLIENT_DATA
	signer, err := aplane.FromEnv(nil)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer signer.Close()

	algodClient, err := algod.MakeClient("http://localhost:4001", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
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
	prepared, err := signer.PrepareAccountClose(ctx, algodClient, aplane.AccountClosePrepParams{
		Sender: hashlockAddress, CloseTo: recipient,
	})
	if err != nil {
		log.Fatalf("Failed to prepare the claim: %v", err)
	}
	// Sign with the preimage argument
	prepared.LsigArgs = aplane.LsigArgs{"preimage": preimage}

	fmt.Println("Sending hashlock claim with preimage...")
	result, err := signer.SendPrepared(ctx, algodClient, aplane.NewPreparedGroup(*prepared), nil)
	if err != nil {
		// A group that was signed, or a signature that may have been
		// released: never build a replacement until the outcome is known,
		// because both could execute.
		var uncertain *aplane.SubmissionUncertainError
		var unknown *aplane.SignOutcomeUnknownError
		if errors.As(err, &uncertain) || errors.As(err, &unknown) {
			log.Fatalf("Outcome unknown: %v\n%s", err, advice(ctx, signer, algodClient, err))
		}
		log.Fatalf("Failed to send: %v", err)
	}
	fmt.Printf("Confirmed %s in round %d\n", result.TxIDs[0], result.ConfirmedRound)
	fmt.Println("Hashlock claimed successfully!")
}

// advice asks the node where an uncertain outcome stands. It signs and
// submits nothing.
func advice(ctx context.Context, signer *aplane.SignerClient, algodClient *algod.Client, err error) string {
	report, resolveErr := signer.ResolveOutcome(ctx, algodClient, err)
	if resolveErr != nil {
		return fmt.Sprintf("Could not check the outcome (%v); look the transaction up before sending again.", resolveErr)
	}
	return fmt.Sprintf("%s: %s", report.State, report.Advice)
}
