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
		// A signed group whose submit or wait failed, or a signature that may
		// have been released: never build a replacement while it can still
		// execute, because both could.
		var failure *aplane.SubmissionError
		if errors.As(err, &failure) {
			if !failure.Submitted {
				printSignedGroup(failure)
				log.Fatalf("%v. If the cause is algod's HTTP 400, the node answered: read its reason. Otherwise the node may or may not have the group: follow the first ID for a few rounds and, if it does not confirm, submit the signed group above again with SubmitSignedGroup.", err)
			}
			round, waitErr := waitForGroup(ctx, algodClient, failure)
			if waitErr != nil {
				printSignedGroup(failure)
				log.Fatalf("%v (wait: %v). You may follow the first ID until round %d; after it, check an indexer before building a replacement.", err, waitErr, failure.LastValid)
			}
			fmt.Printf("Confirmed %s in round %d\n", failure.TxIDs[0], round)
			return
		}
		var unknown *aplane.SignOutcomeUnknownError
		if errors.As(err, &unknown) {
			log.Fatalf("Outcome unknown: %v. Do not build a replacement until round %d has passed.", err, unknown.LastValid)
		}
		log.Fatalf("Failed to send: %v", err)
	}
	fmt.Printf("Confirmed %s in round %d\n", result.TxIDs[0], result.ConfirmedRound)
	fmt.Println("Hashlock claimed successfully!")
}

// printSignedGroup prints what acting on a *aplane.SubmissionError needs:
// each signed transaction as hex msgpack, the form SubmitSignedGroup takes,
// with its ID, and the group's last valid round.
func printSignedGroup(failure *aplane.SubmissionError) {
	for i, entry := range failure.SignedGroup {
		fmt.Printf("Signed transaction %d, ID %s:\n%s\n", i, failure.TxIDs[i], entry)
	}
	fmt.Printf("Last valid round: %d\n", failure.LastValid)
}

// waitForGroup follows a submitted group with go-algorand-sdk for 10 more
// rounds, or until its last valid round if that comes first, so the example
// does not block for most of the validity window. A group confirms as a
// whole, so its first ID is enough. A timeout means only that the wait ended.
func waitForGroup(ctx context.Context, algodClient *algod.Client, failure *aplane.SubmissionError) (uint64, error) {
	status, err := algodClient.Status().Do(ctx)
	if err != nil {
		return 0, err
	}
	rounds := uint64(1)
	if failure.LastValid > status.LastRound {
		rounds = min(failure.LastValid-status.LastRound, 10)
	}
	info, err := transaction.WaitForConfirmation(algodClient, failure.TxIDs[0], rounds, ctx)
	return info.ConfirmedRound, err
}
