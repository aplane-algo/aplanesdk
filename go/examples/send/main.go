// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/*
Send a payment from any account the signer holds.

SendPayment builds the payment, signs it through the flow the sender's key
needs, checks the signed result, submits it and waits for confirmation. The
same call works for an Ed25519, native Falcon, LogicSig, bounded, cosigned or
rotating account, and for a rekeyed sender. A cosigned account needs nothing
extra when endpoints.yaml lists its cosigner, as in the example below: the
client finds the cosigner there.

Setup:

 1. Create data directory: mkdir -p ~/aplane/apclient/.ssh
 2. Generate APlane SSH key: ssh-keygen -t ed25519 -f ~/aplane/apclient/.ssh/id_ed25519 -N ""
 3. Enroll it at the signer: run apshell enroll (or aplane.RequestEnrollmentFromEnv) and approve in apadmin
 4. Create endpoints.yaml (see below)
 5. Set env: export APCLIENT_DATA=~/aplane/apclient

Example endpoints.yaml (SSH tunnel; the cosigner entry is needed only for a
cosigned account):

	schema_version: 2
	endpoints:
	  primary:
	    role: signer
	    url: ssh://192.168.86.73:1127
	    identity_file: .ssh/id_ed25519
	  cosigner:
	    role: cosigner
	    url: ssh://192.168.86.74:1127
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

// The account to pay from (the signer must hold its key) and the account
// to pay. Replace both.
const (
	sender   = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777"
	receiver = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777"
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

	// 1 ALGO, in microAlgos.
	result, err := signer.SendPayment(ctx, algodClient, aplane.PaymentPrepParams{
		Sender: sender, Receiver: receiver, Amount: 1_000_000,
	}, nil)
	if err != nil {
		// A signed group whose submit or wait failed keeps its bytes and IDs
		// in the error, with go-algorand-sdk's error as the cause. Never sign
		// a replacement while it can still execute: both could.
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
		// The sign answer was lost, so the signer may have released a
		// signature. Nothing was submitted.
		var unknown *aplane.SignOutcomeUnknownError
		if errors.As(err, &unknown) {
			if unknown.Rotating != nil {
				// The same prepared group signs to the same transaction IDs.
				log.Fatalf("Sign outcome unknown (request %q): %v. Sign the same prepared group again with SignPreparedRotating.", unknown.RequestID, err)
			}
			log.Fatalf("Sign outcome unknown (request %q): %v. Do not build a replacement until round %d has passed.", unknown.RequestID, err, unknown.LastValid)
		}
		log.Fatalf("Failed to send: %v", err)
	}

	// The signer may raise the fee or add transactions, so the ID comes from
	// the signed group, not from the payment as it was built.
	fmt.Printf("Confirmed %s in round %d, fee %d microAlgos\n", result.TxIDs[0], result.ConfirmedRound, result.Fees[0])
	if result.Rotating != nil {
		fmt.Printf("Rotated from stage %d to stage %d\n", result.Rotating.Stage, result.Rotating.Target)
	}
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
