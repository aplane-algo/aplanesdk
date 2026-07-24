// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/*
Package aplane provides a Go client for signing Algorand transactions via apsigner.

# Quick Start

	import (
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

	// Sign via apsigner (waits for operator approval)
	signed, err := client.SignTransaction(txn, "", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Submit using standard go-algorand-sdk
	signedBytes, _ := aplane.Base64ToBytes(signed)
	txid, _ := algodClient.SendRawTransaction(signedBytes).Do(context.Background())

# Connection Methods

The SDK supports both managed SSH-backed connections and caller-owned transport.

SSH tunnel connection:

	client, err := aplane.ConnectSSH(
		"signer.example.com",
		"your-token",
		"~/.ssh/id_ed25519",
		nil,
	)

From environment (reads endpoints.yaml and the selected endpoint token from
APCLIENT_DATA or the data_dir passed via FromEnvOptions — the SDK has no
implicit default):

	client, err := aplane.FromEnv(nil)

Caller-owned transport:

	client := aplane.NewSignerClientWithToken("http://localhost:11270", token)

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

With LogicSig runtime arguments:

	signed, err := client.SignTransaction(
		txn,
		hashlockAddress,
		aplane.LsigArgs{"preimage": preimageBytes},
	)
*/
package aplane
