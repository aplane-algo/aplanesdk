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
