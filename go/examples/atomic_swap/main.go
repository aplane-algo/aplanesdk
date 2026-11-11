// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/*
Atomic swap example - exchange ALGO between two accounts in a single group.

This demonstrates signing a transaction group where both parties must sign.
Works with any combination of key types (Ed25519, Falcon, etc.), and with a
cosigned account. A rotating account cannot take part: it sends one
transaction alone, and the signer forms its group.

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

Important:
  - Do NOT pre-assign group IDs with transaction.AssignGroupID()
  - The server computes the group ID after adding any required dummy transactions
  - SendPrepared submits exactly the group the signer returned, after checking it
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

// Swap parameters (replace with your actual addresses)
const (
	alice      = "ALICEED255EXAMPLE777777777777777777777777777777777777777777" // Ed25519 account
	bob        = "BOBFALCONEXAMPLE7777777777777777777777777777777777777777777" // Falcon account
	swapAmount = 100000                                                        // 0.1 ALGO in microAlgos
)

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

	// Build both payments, ungrouped, each naming the key that signs it.
	group, err := signer.PreparePaymentGroup(ctx, algodClient, []aplane.PaymentPrepParams{
		{Sender: alice, Receiver: bob, Amount: swapAmount},
		{Sender: bob, Receiver: alice, Amount: swapAmount},
	})
	if err != nil {
		log.Fatalf("Failed to prepare the swap: %v", err)
	}

	// Sign the group (server handles grouping and dummies for Falcon), then
	// submit and confirm it.
	fmt.Printf("Sending atomic swap: %s... <-> %s...\n", alice[:8], bob[:8])
	result, err := signer.SendPrepared(ctx, algodClient, *group, nil)
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
	fmt.Printf("Confirmed group %s in round %d\n", result.GroupID, result.ConfirmedRound)
	fmt.Println("Atomic swap complete!")
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
