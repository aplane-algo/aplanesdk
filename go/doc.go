// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/*
Package aplane provides a Go client for signing Algorand transactions via apsigner.

# Quick Start

	import (
		"bytes"

		"github.com/aplane-algo/aplanesdk/go"
		"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
		"github.com/algorand/go-algorand-sdk/v2/transaction"
	)

	// Connect to signer
	client, err := aplane.FromEnv(nil)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Build transaction with go-algorand-sdk
	algodClient, _ := algod.MakeClient("https://testnet-api.4160.nodely.dev", "")
	params, _ := algodClient.SuggestedParams().Do(context.Background())

	txn, _ := transaction.MakePaymentTxn(sender, receiver, 1000000, nil, "", params)

	// Sign via apsigner (waits for operator approval). The result is the
	// signed group: this transaction first, then any resource dummies the
	// signer appended, one signed transaction's msgpack bytes per entry.
	signed, err := client.SignTransaction(txn, "", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Submit the whole group using standard go-algorand-sdk
	txid, _ := algodClient.SendRawTransaction(bytes.Join(signed, nil)).Do(context.Background())

# Connection Methods

The SDK supports both managed SSH-backed connections and caller-owned transport.

SSH tunnel connection, authenticated by the client's enrolled SSH key:

	client, err := aplane.ConnectSSH(
		"signer.example.com",
		"~/aplane/apclient/.ssh/id_ed25519",
		&aplane.SSHConnectOptions{
			KnownHostsPath:  "~/aplane/apclient/.ssh/known_hosts",
			SSHSetupTimeout: 60 * time.Second,
		},
	)

From environment (reads endpoints.yaml and the selected endpoint's SSH
identity from APCLIENT_DATA or the data_dir passed via FromEnvOptions — the
SDK has no implicit default):

	client, err := aplane.FromEnv(nil)

A key the signer has not enrolled fails with ErrNotEnrolled. Ask for
enrollment once; the request is queued (Pending) for the operator to approve
later in apadmin, and the client connects once that has happened:

	result, err := aplane.RequestEnrollmentFromEnv(nil, "ci-runner")
	if err == nil && result.Pending {
		log.Printf("key %s queued; have the operator approve it in apadmin", result.Fingerprint)
	}

Caller-owned transport (the caller's own tunnel to the signer):

	client := aplane.NewSignerClient("http://localhost:11270")

# Signing

Single transaction:

	// Empty auth address means "use txn.Sender".
	signed, err := client.SignTransaction(txn, "", nil)

Transaction group (do NOT pre-assign group IDs):

	signed, err := client.SignTransactions(
		[]types.Transaction{txn1, txn2},
		[]string{authAddr1, authAddr2},
		nil,
	)

The result is one signed transaction's msgpack bytes per entry, in group
order, dummies included. Submit it with go-algorand-sdk:

	txid, err := algodClient.SendRawTransaction(bytes.Join(signed, nil)).Do(ctx)

With LogicSig runtime arguments:

	signed, err := client.SignTransaction(
		txn,
		hashlockAddress,
		aplane.LsigArgs{"preimage": preimageBytes},
	)
*/
package aplane
