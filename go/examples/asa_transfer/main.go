// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/*
ASA (Algorand Standard Asset) transfer example.

Works with any key type (Ed25519, Falcon, etc.), and for a rekeyed sender:
PrepareAsaTransfer finds the key that signs, and SendPrepared signs through
the flow that key needs, submits and waits for confirmation. The server
automatically handles fee pooling for large LogicSigs.

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

// Transaction parameters (replace with your actual addresses)
const (
	sender   = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777"
	receiver = "RECEIVEREXAMPLE777777777777777777777777777777777777777777"
	assetID  = 10458941 // replace with an ASA that exists on your LocalNet
	amount   = 1        // Amount in base units
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

	// Build the ASA transfer. The helper checks the sender holds the asset
	// and the receiver has opted in, and names the key that signs.
	prepared, err := signer.PrepareAsaTransfer(ctx, algodClient, aplane.AsaTransferPrepParams{
		Sender: sender, Receiver: receiver, AssetID: assetID, Amount: amount,
	})
	if err != nil {
		log.Fatalf("Failed to prepare the transfer: %v", err)
	}

	// Sign (server handles fee pooling automatically), submit and confirm.
	fmt.Printf("Sending ASA transfer from %s...\n", sender[:12])
	result, err := signer.SendPrepared(ctx, algodClient, aplane.NewPreparedGroup(*prepared), nil)
	if err != nil {
		// A signed group whose submit or wait failed, or a signature that may
		// have been released: never build a replacement while it can still
		// execute, because both could.
		var failure *aplane.SubmissionError
		if errors.As(err, &failure) {
			if !failure.Submitted {
				printSignedGroup(failure)
				log.Fatalf("%v. If the cause is algod's HTTP 400, the node refused the group: read the reason. Otherwise the node may or may not have it: follow the first ID for a few rounds and, if it does not confirm, submit the signed group above again with SubmitSignedGroup.", err)
			}
			round, waitErr := waitForGroup(ctx, algodClient, failure)
			if waitErr != nil {
				printSignedGroup(failure)
				log.Fatalf("%v (wait: %v). After round %d, check an indexer before building a replacement.", err, waitErr, failure.LastValid)
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

// waitForGroup follows a submitted group with go-algorand-sdk until its last
// valid round. A group confirms as a whole, so its first ID is enough. A
// timeout means only that the wait ended.
func waitForGroup(ctx context.Context, algodClient *algod.Client, failure *aplane.SubmissionError) (uint64, error) {
	status, err := algodClient.Status().Do(ctx)
	if err != nil {
		return 0, err
	}
	rounds := uint64(1)
	if failure.LastValid > status.LastRound {
		rounds = failure.LastValid - status.LastRound
	}
	info, err := transaction.WaitForConfirmation(algodClient, failure.TxIDs[0], rounds, ctx)
	return info.ConfirmedRound, err
}
