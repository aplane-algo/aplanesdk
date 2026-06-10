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

// PreparePaymentGroup builds an ordered group of prepared payment transactions.
func (c *SignerClient) PreparePaymentGroup(ctx context.Context, algodClient *algod.Client, payments []PaymentPrepParams) (*PreparedGroup, error) {
	if len(payments) == 0 {
		return nil, fmt.Errorf("payments must not be empty")
	}
	group := PreparedGroup{
		Transactions: make([]PreparedTransaction, 0, len(payments)),
		Checks: []PreparedCheck{{
			Name:   "payment_group",
			Status: "ok",
			Data: map[string]any{
				"count": len(payments),
			},
		}},
	}
	for i, payment := range payments {
		prepared, err := c.PreparePayment(ctx, algodClient, payment)
		if err != nil {
			return nil, fmt.Errorf("payment %d: %w", i, err)
		}
		group.Transactions = append(group.Transactions, *prepared)
	}
	check, err := paymentGroupBalanceCheck(group.Transactions)
	if err != nil {
		return nil, err
	}
	group.Checks = append(group.Checks, check)
	return &group, nil
}

// PrepareAsaTransferGroup builds an ordered group of prepared ASA transfers.
func (c *SignerClient) PrepareAsaTransferGroup(ctx context.Context, algodClient *algod.Client, transfers []AsaTransferPrepParams) (*PreparedGroup, error) {
	if len(transfers) == 0 {
		return nil, fmt.Errorf("transfers must not be empty")
	}
	group := PreparedGroup{
		Transactions: make([]PreparedTransaction, 0, len(transfers)),
		Checks: []PreparedCheck{{
			Name:   "asa_transfer_group",
			Status: "ok",
			Data: map[string]any{
				"count": len(transfers),
			},
		}},
	}
	for i, transfer := range transfers {
		prepared, err := c.PrepareAsaTransfer(ctx, algodClient, transfer)
		if err != nil {
			return nil, fmt.Errorf("ASA transfer %d: %w", i, err)
		}
		group.Transactions = append(group.Transactions, *prepared)
	}
	check, err := asaTransferGroupBalanceCheck(group.Transactions)
	if err != nil {
		return nil, err
	}
	group.Checks = append(group.Checks, check)
	return &group, nil
}

// PreparePaymentAppCallGroup returns the apshell-compatible payment-first
// group shape for payment plus app-call workflows.
func (c *SignerClient) PreparePaymentAppCallGroup(payment PreparedTransaction, appCall PreparedTransaction) (*PreparedGroup, error) {
	if payment.Transaction == nil {
		return nil, fmt.Errorf("payment transaction is required")
	}
	if appCall.Transaction == nil {
		return nil, fmt.Errorf("app call transaction is required")
	}
	return &PreparedGroup{
		Transactions: []PreparedTransaction{payment, appCall},
		Checks: []PreparedCheck{{
			Name:   "payment_app_call_order",
			Status: "ok",
			Data: map[string]any{
				"payment_index":  0,
				"app_call_index": 1,
			},
		}},
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
			"available":   available,
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
			"balance":  senderHolding.Amount,
		},
	}}, nil
}

func paymentGroupBalanceCheck(items []PreparedTransaction) (PreparedCheck, error) {
	type totals struct {
		available uint64
		required  uint64
	}
	bySender := map[string]*totals{}
	for _, item := range items {
		if item.Transaction == nil {
			return PreparedCheck{}, fmt.Errorf("payment group transaction is required")
		}
		sender := item.Transaction.Sender.String()
		total := bySender[sender]
		if total == nil {
			total = &totals{}
			bySender[sender] = total
		}
		total.required += uint64(item.Transaction.Amount) + uint64(item.Transaction.Fee)
		for _, check := range item.Checks {
			if check.Name != "payment_balance" || check.Data == nil {
				continue
			}
			if available, ok := check.Data["available"].(uint64); ok {
				total.available = available
			}
		}
	}
	for sender, total := range bySender {
		if total.available < total.required {
			return PreparedCheck{}, fmt.Errorf("payment group insufficient funds for %s: available %d, required %d", sender, total.available, total.required)
		}
	}
	return PreparedCheck{
		Name:   "payment_group_balance",
		Status: "ok",
		Data: map[string]any{
			"sender_count": len(bySender),
		},
	}, nil
}

func asaTransferGroupBalanceCheck(items []PreparedTransaction) (PreparedCheck, error) {
	type totals struct {
		balance uint64
		amount  uint64
	}
	byHolding := map[string]*totals{}
	for _, item := range items {
		if item.Transaction == nil {
			return PreparedCheck{}, fmt.Errorf("ASA transfer group transaction is required")
		}
		key := fmt.Sprintf("%s:%d", item.Transaction.Sender.String(), item.Transaction.XferAsset)
		total := byHolding[key]
		if total == nil {
			total = &totals{}
			byHolding[key] = total
		}
		total.amount += item.Transaction.AssetAmount
		for _, check := range item.Checks {
			if check.Name != "asa_transfer" || check.Data == nil {
				continue
			}
			if balance, ok := check.Data["balance"].(uint64); ok {
				total.balance = balance
			}
		}
	}
	for key, total := range byHolding {
		if total.balance < total.amount {
			return PreparedCheck{}, fmt.Errorf("ASA transfer group insufficient asset balance for %s: available %d, required %d", key, total.balance, total.amount)
		}
	}
	return PreparedCheck{
		Name:   "asa_transfer_group_balance",
		Status: "ok",
		Data: map[string]any{
			"holding_count": len(byHolding),
		},
	}, nil
}

func accountAssetHolding(account models.Account, assetID uint64) (models.AssetHolding, bool) {
	for _, holding := range account.Assets {
		if holding.AssetId == assetID && !holding.Deleted {
			return holding, true
		}
	}
	return models.AssetHolding{}, false
}
