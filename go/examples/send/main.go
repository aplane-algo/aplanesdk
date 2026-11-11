// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/*
Send a payment from any account the signer holds.

SendPayment builds the payment, signs it through the flow the sender's key
needs, checks the signed result, submits it and waits for confirmation. The
same call works for an Ed25519, native Falcon, LogicSig, bounded or rotating
account, and for a rekeyed sender. A cosigned account also needs its cosigner:
set SendOptions.CosignerClient and CosignerComponentKey.

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
	"github.com/aplane-algo/aplanesdk/go"
)

// The account to pay from (the signer must hold its key) and the account
// to pay. Replace both.
const (
	sender   = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777"
	receiver = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777"
)

func main() {
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
	result, err := signer.SendPayment(context.Background(), algodClient, aplane.PaymentPrepParams{
		Sender: sender, Receiver: receiver, Amount: 1_000_000,
	}, nil)
	if err != nil {
		// A group that was signed keeps its bytes and IDs in the error. Never
		// send again until its outcome is known: both could execute.
		var uncertain *aplane.SubmissionUncertainError
		if errors.As(err, &uncertain) {
			log.Fatalf("Outcome unknown for %v (%s); look it up before sending again: %v", uncertain.TxIDs, uncertain.Stage, err)
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
