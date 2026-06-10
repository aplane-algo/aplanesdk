// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// PreparedCheck records SDK-side preflight information collected while
// preparing a transaction intent.
type PreparedCheck struct {
	Name    string
	Status  string
	Message string
	Data    map[string]any
}

// PreparedTransaction is the SDK-side representation of one transaction slot
// after client preparation and before apsigner planning/signing.
type PreparedTransaction struct {
	Transaction             *types.Transaction
	AuthAddress             string
	TxnSender               string
	SignerKey               *KeyInfo
	LsigArgs                LsigArgs
	LsigSize                int
	AppCallInfo             *AppCallInfo
	SignedTransactionBase64 string
	Checks                  []PreparedCheck
}

// SignRequest converts the prepared slot to the signer wire request shape.
func (p PreparedTransaction) SignRequest() (SignRequest, error) {
	if p.SignedTransactionBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(p.SignedTransactionBase64)
		if err != nil {
			return SignRequest{}, fmt.Errorf("invalid passthrough transaction: invalid base64: %w", err)
		}
		return SignRequest{SignedTxnHex: hex.EncodeToString(decoded)}, nil
	}

	if p.Transaction == nil {
		return SignRequest{}, fmt.Errorf("transaction is required")
	}

	txnBytesHex := hex.EncodeToString(encodeTxn(*p.Transaction))
	if p.AuthAddress == "" {
		req := SignRequest{TxnBytesHex: txnBytesHex}
		if p.LsigSize > 0 {
			req.LsigSize = p.LsigSize
		}
		return req, nil
	}

	txnSender := p.TxnSender
	if txnSender == "" {
		txnSender = p.Transaction.Sender.String()
	}
	req := SignRequest{
		AuthAddress: p.AuthAddress,
		TxnSender:   txnSender,
		TxnBytesHex: txnBytesHex,
		AppCallInfo: p.AppCallInfo,
	}
	if len(p.LsigArgs) > 0 {
		req.LsigArgs = make(map[string]string, len(p.LsigArgs))
		for name, value := range p.LsigArgs {
			req.LsigArgs[name] = hex.EncodeToString(value)
		}
	}
	return req, nil
}

// PreparedGroup is an ordered group of prepared transaction slots.
type PreparedGroup struct {
	Transactions []PreparedTransaction
	Checks       []PreparedCheck
}

// NewPreparedGroup returns a prepared group with the provided slots.
func NewPreparedGroup(transactions ...PreparedTransaction) PreparedGroup {
	return PreparedGroup{Transactions: transactions}
}

// SignRequests converts the group to signer request entries.
func (g PreparedGroup) SignRequests() ([]SignRequest, error) {
	if len(g.Transactions) == 0 {
		return nil, fmt.Errorf("prepared group is empty")
	}
	requests := make([]SignRequest, len(g.Transactions))
	for i, txn := range g.Transactions {
		req, err := txn.SignRequest()
		if err != nil {
			return nil, fmt.Errorf("prepared transaction %d: %w", i, err)
		}
		requests[i] = req
	}
	return requests, nil
}
