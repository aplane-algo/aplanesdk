// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// PaymentPrepParams describes a payment transaction intent.
type PaymentPrepParams struct {
	Sender     string
	Receiver   string
	Amount     uint64
	Note       []byte
	Fee        uint64
	UseFlatFee bool
}

// AsaTransferPrepParams describes an ASA transfer transaction intent.
type AsaTransferPrepParams struct {
	Sender     string
	Receiver   string
	AssetID    uint64
	Amount     uint64
	Note       []byte
	Fee        uint64
	UseFlatFee bool
}

// PreparePayment builds an unsigned payment transaction and signer metadata.
func (c *SignerClient) PreparePayment(ctx context.Context, algodClient *algod.Client, params PaymentPrepParams) (*PreparedTransaction, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	if params.Sender == "" {
		return nil, fmt.Errorf("sender is required")
	}
	if params.Receiver == "" {
		return nil, fmt.Errorf("receiver is required")
	}

	suggested, err := algodClient.SuggestedParams().Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get suggested params: %w", err)
	}
	applyPrepFee(&suggested, params.Fee, params.UseFlatFee)

	senderAcct, err := algodClient.AccountInformation(params.Sender).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get sender account info: %w", err)
	}

	txn, err := transaction.MakePaymentTxn(
		params.Sender,
		params.Receiver,
		params.Amount,
		params.Note,
		"",
		suggested,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create payment transaction: %w", err)
	}
	checks, err := paymentChecks(senderAcct, params.Amount, uint64(txn.Fee))
	if err != nil {
		return nil, err
	}

	resolved, err := c.ResolveAuthAddress(ctx, params.Sender, func(context.Context, string) (string, error) {
		return senderAcct.AuthAddr, nil
	})
	if err != nil {
		return nil, err
	}

	return &PreparedTransaction{
		Transaction: &txn,
		AuthAddress: resolved.AuthAddress,
		SignerKey:   &resolved.KeyInfo,
		Checks:      checks,
	}, nil
}

// PrepareAsaTransfer builds an unsigned ASA transfer transaction and signer metadata.
func (c *SignerClient) PrepareAsaTransfer(ctx context.Context, algodClient *algod.Client, params AsaTransferPrepParams) (*PreparedTransaction, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	if params.Sender == "" {
		return nil, fmt.Errorf("sender is required")
	}
	if params.Receiver == "" {
		return nil, fmt.Errorf("receiver is required")
	}
	if params.AssetID == 0 {
		return nil, fmt.Errorf("asset_id is required")
	}

	suggested, err := algodClient.SuggestedParams().Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get suggested params: %w", err)
	}
	applyPrepFee(&suggested, params.Fee, params.UseFlatFee)

	senderAcct, err := algodClient.AccountInformation(params.Sender).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get sender account info: %w", err)
	}
	receiverAcct, err := algodClient.AccountInformation(params.Receiver).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get receiver account info: %w", err)
	}

	txn, err := transaction.MakeAssetTransferTxn(
		params.Sender,
		params.Receiver,
		params.Amount,
		params.Note,
		suggested,
		"",
		params.AssetID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ASA transfer transaction: %w", err)
	}
	checks, err := asaTransferChecks(senderAcct, receiverAcct, params.AssetID, params.Amount)
	if err != nil {
		return nil, err
	}

	resolved, err := c.ResolveAuthAddress(ctx, params.Sender, func(context.Context, string) (string, error) {
		return senderAcct.AuthAddr, nil
	})
	if err != nil {
		return nil, err
	}

	return &PreparedTransaction{
		Transaction: &txn,
		AuthAddress: resolved.AuthAddress,
		SignerKey:   &resolved.KeyInfo,
		Checks:      checks,
	}, nil
}

func applyPrepFee(params *types.SuggestedParams, fee uint64, useFlatFee bool) {
	if fee == 0 {
		return
	}
	params.Fee = types.MicroAlgos(fee)
	params.FlatFee = useFlatFee
}

func paymentChecks(sender models.Account, amount uint64, fee uint64) ([]PreparedCheck, error) {
	required := amount + fee
	available := uint64(0)
	if sender.Amount > sender.MinBalance {
		available = sender.Amount - sender.MinBalance
	}
	if available < required {
		return nil, fmt.Errorf("insufficient funds: available %d, required %d", available, required)
	}
	return []PreparedCheck{{
		Name:   "payment_balance",
		Status: "ok",
		Data: map[string]any{
			"amount":      amount,
			"fee":         fee,
			"min_balance": sender.MinBalance,
			"balance":     sender.Amount,
		},
	}}, nil
}

func asaTransferChecks(sender models.Account, receiver models.Account, assetID uint64, amount uint64) ([]PreparedCheck, error) {
	senderHolding, ok := accountAssetHolding(sender, assetID)
	if !ok {
		return nil, fmt.Errorf("sender is not opted into asset %d", assetID)
	}
	if senderHolding.Amount < amount {
		return nil, fmt.Errorf("insufficient asset balance: available %d, required %d", senderHolding.Amount, amount)
	}
	if _, ok := accountAssetHolding(receiver, assetID); !ok {
		return nil, fmt.Errorf("receiver is not opted into asset %d", assetID)
	}
	return []PreparedCheck{{
		Name:   "asa_transfer",
		Status: "ok",
		Data: map[string]any{
			"asset_id": assetID,
			"amount":   amount,
		},
	}}, nil
}

func accountAssetHolding(account models.Account, assetID uint64) (models.AssetHolding, bool) {
	for _, holding := range account.Assets {
		if holding.AssetId == assetID && !holding.Deleted {
			return holding, true
		}
	}
	return models.AssetHolding{}, false
}
