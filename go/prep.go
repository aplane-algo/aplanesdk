// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/abi"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const appCallMaxAppArgs = 16
const appCallMethodArgsTupleThreshold = appCallMaxAppArgs - 2

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

// AsaOptInPrepParams describes an ASA opt-in transaction intent.
type AsaOptInPrepParams struct {
	Sender     string
	AssetID    uint64
	Note       []byte
	Fee        uint64
	UseFlatFee bool
}

// AsaOptOutPrepParams describes an ASA opt-out transaction intent.
type AsaOptOutPrepParams struct {
	Sender     string
	AssetID    uint64
	CloseTo    string
	Note       []byte
	Fee        uint64
	UseFlatFee bool
}

// AccountClosePrepParams describes an account close transaction intent.
type AccountClosePrepParams struct {
	Sender     string
	CloseTo    string
	Note       []byte
	Fee        uint64
	UseFlatFee bool
}

// RekeyPrepParams describes an account rekey transaction intent.
type RekeyPrepParams struct {
	Sender     string
	RekeyTo    string
	Note       []byte
	Fee        uint64
	UseFlatFee bool
}

// KeyRegPrepParams describes a key registration transaction intent.
type KeyRegPrepParams struct {
	Sender           string
	VoteKey          string
	SelectionKey     string
	StateProofKey    string
	VoteFirst        uint64
	VoteLast         uint64
	VoteKeyDilution  uint64
	Nonparticipation bool
	Note             []byte
	Fee              uint64
	UseFlatFee       bool
}

// AppCallPrepParams describes a raw application-call transaction intent.
type AppCallPrepParams struct {
	Sender          string
	AppID           uint64
	OnCompletion    types.OnCompletion
	AppArgs         [][]byte
	Accounts        []string
	ForeignApps     []uint64
	ForeignAssets   []uint64
	Boxes           []types.AppBoxReference
	ApprovalProgram []byte
	ClearProgram    []byte
	GlobalSchema    types.StateSchema
	LocalSchema     types.StateSchema
	ExtraPages      uint32
	Note            []byte
	Fee             uint64
	UseFlatFee      bool
}

// ABIAppCallPrepParams describes an ABI method-call transaction intent.
type ABIAppCallPrepParams struct {
	AppCallPrepParams
	MethodSignature string
	Args            []any
}

// AppDeployPrepParams describes an application create transaction intent.
type AppDeployPrepParams struct {
	Sender          string
	ApprovalProgram []byte
	ClearProgram    []byte
	GlobalSchema    types.StateSchema
	LocalSchema     types.StateSchema
	ExtraPages      uint32
	AppArgs         [][]byte
	Accounts        []string
	ForeignApps     []uint64
	ForeignAssets   []uint64
	Boxes           []types.AppBoxReference
	OptIn           bool
	Note            []byte
	Fee             uint64
	UseFlatFee      bool
}

// SweepPrepParams describes a normalized sweep group.
type SweepPrepParams struct {
	AsaTransfers []AsaTransferPrepParams
	Payments     []PaymentPrepParams
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

// PrepareAsaOptIn builds an unsigned ASA opt-in transaction and signer metadata.
func (c *SignerClient) PrepareAsaOptIn(ctx context.Context, algodClient *algod.Client, params AsaOptInPrepParams) (*PreparedTransaction, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	if params.Sender == "" {
		return nil, fmt.Errorf("sender is required")
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
	checks, err := asaOptInChecks(senderAcct, params.AssetID, uint64(suggested.Fee))
	if err != nil {
		return nil, err
	}

	txn, err := transaction.MakeAssetAcceptanceTxn(params.Sender, params.Note, suggested, params.AssetID)
	if err != nil {
		return nil, fmt.Errorf("failed to create ASA opt-in transaction: %w", err)
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

// PrepareAsaOptOut builds an unsigned ASA opt-out transaction and signer metadata.
func (c *SignerClient) PrepareAsaOptOut(ctx context.Context, algodClient *algod.Client, params AsaOptOutPrepParams) (*PreparedTransaction, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	if params.Sender == "" {
		return nil, fmt.Errorf("sender is required")
	}
	if params.CloseTo == "" {
		return nil, fmt.Errorf("close_to is required")
	}
	if params.AssetID == 0 {
		return nil, fmt.Errorf("asset_id is required")
	}
	if params.CloseTo == params.Sender {
		return nil, fmt.Errorf("close_to must differ from sender")
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
	closeAcct, err := algodClient.AccountInformation(params.CloseTo).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get close-to account info: %w", err)
	}
	checks, err := asaOptOutChecks(senderAcct, closeAcct, params.AssetID)
	if err != nil {
		return nil, err
	}

	txn, err := transaction.MakeAssetTransferTxn(params.Sender, params.Sender, 0, params.Note, suggested, params.CloseTo, params.AssetID)
	if err != nil {
		return nil, fmt.Errorf("failed to create ASA opt-out transaction: %w", err)
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

// PrepareAppCall builds an unsigned raw app-call transaction and signer metadata.
func (c *SignerClient) PrepareAppCall(ctx context.Context, algodClient *algod.Client, params AppCallPrepParams) (*PreparedTransaction, error) {
	return c.prepareAppCallWithInfo(ctx, algodClient, params, &AppCallInfo{Mode: "raw"})
}

// PrepareABIAppCall builds an unsigned ABI app-call transaction and signer metadata.
func (c *SignerClient) PrepareABIAppCall(ctx context.Context, algodClient *algod.Client, params ABIAppCallPrepParams) (*PreparedTransaction, error) {
	if params.MethodSignature == "" {
		return nil, fmt.Errorf("method_signature is required")
	}
	method, err := abi.MethodFromSignature(params.MethodSignature)
	if err != nil {
		return nil, fmt.Errorf("invalid ABI method signature: %w", err)
	}
	raw := params.AppCallPrepParams
	raw.AppArgs, raw.Accounts, raw.ForeignApps, raw.ForeignAssets, err = encodeABIMethodArgs(method, params.Args, raw.Sender, raw.AppID, raw.Accounts, raw.ForeignApps, raw.ForeignAssets)
	if err != nil {
		return nil, err
	}
	return c.prepareAppCallWithInfo(ctx, algodClient, raw, &AppCallInfo{
		Mode:   "abi",
		Method: method.GetSignature(),
	})
}

// PrepareAccountClose builds an unsigned account-close transaction and signer metadata.
func (c *SignerClient) PrepareAccountClose(ctx context.Context, algodClient *algod.Client, params AccountClosePrepParams) (*PreparedTransaction, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	if params.Sender == "" {
		return nil, fmt.Errorf("sender is required")
	}
	if params.CloseTo == "" {
		return nil, fmt.Errorf("close_to is required")
	}
	if params.CloseTo == params.Sender {
		return nil, fmt.Errorf("close_to must differ from sender")
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
	checks, err := accountCloseChecks(senderAcct, uint64(suggested.Fee))
	if err != nil {
		return nil, err
	}

	txn, err := transaction.MakePaymentTxn(params.Sender, params.CloseTo, 0, params.Note, params.CloseTo, suggested)
	if err != nil {
		return nil, fmt.Errorf("failed to create account close transaction: %w", err)
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

// PrepareRekey builds an unsigned self-payment rekey transaction and signer metadata.
func (c *SignerClient) PrepareRekey(ctx context.Context, algodClient *algod.Client, params RekeyPrepParams) (*PreparedTransaction, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	if params.Sender == "" {
		return nil, fmt.Errorf("sender is required")
	}
	if params.RekeyTo == "" {
		return nil, fmt.Errorf("rekey_to is required")
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
	targetAcct := models.Account{Address: params.RekeyTo}
	if params.RekeyTo != params.Sender {
		targetAcct, err = algodClient.AccountInformation(params.RekeyTo).Do(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get rekey target account info: %w", err)
		}
	}
	checks, err := rekeyChecks(targetAcct, params.RekeyTo)
	if err != nil {
		return nil, err
	}

	txn, err := transaction.MakePaymentTxn(params.Sender, params.Sender, 0, params.Note, "", suggested)
	if err != nil {
		return nil, fmt.Errorf("failed to create rekey transaction: %w", err)
	}
	if err := txn.Rekey(params.RekeyTo); err != nil {
		return nil, fmt.Errorf("failed to set rekey target: %w", err)
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

// PrepareKeyReg builds an unsigned key registration transaction and signer metadata.
func (c *SignerClient) PrepareKeyReg(ctx context.Context, algodClient *algod.Client, params KeyRegPrepParams) (*PreparedTransaction, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	if params.Sender == "" {
		return nil, fmt.Errorf("sender is required")
	}
	if err := validateKeyRegParams(params); err != nil {
		return nil, err
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

	txn, err := transaction.MakeKeyRegTxnWithStateProofKey(
		params.Sender,
		params.Note,
		suggested,
		params.VoteKey,
		params.SelectionKey,
		params.StateProofKey,
		params.VoteFirst,
		params.VoteLast,
		params.VoteKeyDilution,
		params.Nonparticipation,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyreg transaction: %w", err)
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
		Checks: []PreparedCheck{{
			Name:   "keyreg",
			Status: "ok",
			Data: map[string]any{
				"nonparticipation":  params.Nonparticipation,
				"vote_first":        params.VoteFirst,
				"vote_last":         params.VoteLast,
				"vote_key_dilution": params.VoteKeyDilution,
			},
		}},
	}, nil
}

// PrepareAppDeploy builds an unsigned app-create transaction and signer metadata.
func (c *SignerClient) PrepareAppDeploy(ctx context.Context, algodClient *algod.Client, params AppDeployPrepParams) (*PreparedTransaction, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	if params.Sender == "" {
		return nil, fmt.Errorf("sender is required")
	}
	if len(params.ApprovalProgram) == 0 {
		return nil, fmt.Errorf("approval_program is required")
	}
	if len(params.ClearProgram) == 0 {
		return nil, fmt.Errorf("clear_program is required")
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
	sender, err := types.DecodeAddress(params.Sender)
	if err != nil {
		return nil, fmt.Errorf("invalid sender address: %w", err)
	}

	txn, err := transaction.MakeApplicationCreateTxWithBoxes(
		params.OptIn,
		params.ApprovalProgram,
		params.ClearProgram,
		params.GlobalSchema,
		params.LocalSchema,
		params.ExtraPages,
		params.AppArgs,
		params.Accounts,
		params.ForeignApps,
		params.ForeignAssets,
		params.Boxes,
		suggested,
		sender,
		params.Note,
		types.Digest{},
		[32]byte{},
		types.Address{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create app deploy transaction: %w", err)
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
		AppCallInfo: &AppCallInfo{Mode: "raw"},
		Checks: []PreparedCheck{{
			Name:   "app_deploy",
			Status: "ok",
			Data: map[string]any{
				"extra_pages":          params.ExtraPages,
				"approval_program_len": len(params.ApprovalProgram),
				"clear_program_len":    len(params.ClearProgram),
				"opt_in":               params.OptIn,
			},
		}},
	}, nil
}

// PrepareSweepGroup builds a sweep group from normalized ASA transfers and payments.
func (c *SignerClient) PrepareSweepGroup(ctx context.Context, algodClient *algod.Client, params SweepPrepParams) (*PreparedGroup, error) {
	total := len(params.AsaTransfers) + len(params.Payments)
	if total == 0 {
		return nil, fmt.Errorf("sweep group must not be empty")
	}
	group := PreparedGroup{
		Transactions: make([]PreparedTransaction, 0, total),
		Checks: []PreparedCheck{{
			Name:   "sweep_group",
			Status: "ok",
			Data: map[string]any{
				"asa_transfer_count": len(params.AsaTransfers),
				"payment_count":      len(params.Payments),
			},
		}},
	}
	for i, transfer := range params.AsaTransfers {
		prepared, err := c.PrepareAsaTransfer(ctx, algodClient, transfer)
		if err != nil {
			return nil, fmt.Errorf("ASA transfer %d: %w", i, err)
		}
		group.Transactions = append(group.Transactions, *prepared)
	}
	for i, payment := range params.Payments {
		prepared, err := c.PreparePayment(ctx, algodClient, payment)
		if err != nil {
			return nil, fmt.Errorf("payment %d: %w", i, err)
		}
		group.Transactions = append(group.Transactions, *prepared)
	}
	if len(params.AsaTransfers) > 0 {
		check, err := asaTransferGroupBalanceCheck(group.Transactions[:len(params.AsaTransfers)])
		if err != nil {
			return nil, err
		}
		group.Checks = append(group.Checks, check)
	}
	if len(params.Payments) > 0 {
		check, err := paymentGroupBalanceCheck(group.Transactions[len(params.AsaTransfers):])
		if err != nil {
			return nil, err
		}
		group.Checks = append(group.Checks, check)
	}
	return &group, nil
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

func (c *SignerClient) prepareAppCallWithInfo(ctx context.Context, algodClient *algod.Client, params AppCallPrepParams, info *AppCallInfo) (*PreparedTransaction, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	if params.Sender == "" {
		return nil, fmt.Errorf("sender is required")
	}
	if params.AppID == 0 {
		return nil, fmt.Errorf("app_id is required")
	}
	if params.OnCompletion > types.DeleteApplicationOC {
		return nil, fmt.Errorf("invalid on_completion: %d", params.OnCompletion)
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
	sender, err := types.DecodeAddress(params.Sender)
	if err != nil {
		return nil, fmt.Errorf("invalid sender address: %w", err)
	}

	txn, err := transaction.MakeApplicationCallTxWithBoxes(
		params.AppID,
		params.AppArgs,
		params.Accounts,
		params.ForeignApps,
		params.ForeignAssets,
		params.Boxes,
		params.OnCompletion,
		params.ApprovalProgram,
		params.ClearProgram,
		params.GlobalSchema,
		params.LocalSchema,
		params.ExtraPages,
		suggested,
		sender,
		params.Note,
		types.Digest{},
		[32]byte{},
		types.Address{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create app call transaction: %w", err)
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
		AppCallInfo: info,
		Checks:      appCallChecks(params, info),
	}, nil
}

// applyPrepFee applies a caller-specified fee. The SDK has no fee-per-byte
// mode: Fee is always interpreted as flat microAlgos, so a set fee can never be
// silently reinterpreted as EstimateSize*Fee. A flat fee is applied when the
// caller explicitly opts in (UseFlatFee) — including an explicit flat zero, used
// for fee pooling — or whenever Fee is positive (UseFlatFee defaults on for
// positive fees). Fee==0 without UseFlatFee means "unset": the suggested-params
// fee stands.
func applyPrepFee(params *types.SuggestedParams, fee uint64, useFlatFee bool) {
	if !useFlatFee && fee == 0 {
		return
	}
	params.Fee = types.MicroAlgos(fee)
	params.FlatFee = true
}

func paymentChecks(sender models.Account, amount uint64, fee uint64) ([]PreparedCheck, error) {
	required := amount + fee
	if required < amount {
		return nil, fmt.Errorf("amount %d plus fee %d overflows uint64", amount, fee)
	}
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

func asaOptInChecks(sender models.Account, assetID uint64, fee uint64) ([]PreparedCheck, error) {
	if _, ok := accountAssetHolding(sender, assetID); ok {
		return nil, fmt.Errorf("sender is already opted into asset %d", assetID)
	}
	if sender.Amount < fee {
		return nil, fmt.Errorf("insufficient funds for opt-in fee: balance %d, fee %d", sender.Amount, fee)
	}
	return []PreparedCheck{{
		Name:   "asa_opt_in",
		Status: "ok",
		Data: map[string]any{
			"asset_id": assetID,
			"fee":      fee,
		},
	}}, nil
}

func asaOptOutChecks(sender models.Account, closeTo models.Account, assetID uint64) ([]PreparedCheck, error) {
	holding, ok := accountAssetHolding(sender, assetID)
	if !ok {
		return nil, fmt.Errorf("sender is not opted into asset %d", assetID)
	}
	if _, ok := accountAssetHolding(closeTo, assetID); !ok {
		return nil, fmt.Errorf("close_to is not opted into asset %d", assetID)
	}
	return []PreparedCheck{{
		Name:   "asa_opt_out",
		Status: "ok",
		Data: map[string]any{
			"asset_id": assetID,
			"balance":  holding.Amount,
			"close_to": closeTo.Address,
		},
	}}, nil
}

func accountCloseChecks(sender models.Account, fee uint64) ([]PreparedCheck, error) {
	if strings.EqualFold(sender.Status, "online") {
		return nil, fmt.Errorf("cannot close an online account")
	}
	if len(sender.Assets) > 0 || sender.TotalAssetsOptedIn > 0 {
		return nil, fmt.Errorf("cannot close account with ASA holdings")
	}
	if len(sender.CreatedAssets) > 0 || sender.TotalCreatedAssets > 0 {
		return nil, fmt.Errorf("cannot close account with created assets")
	}
	if len(sender.AppsLocalState) > 0 || sender.TotalAppsOptedIn > 0 {
		return nil, fmt.Errorf("cannot close account with app opt-ins")
	}
	if len(sender.CreatedApps) > 0 || sender.TotalCreatedApps > 0 {
		return nil, fmt.Errorf("cannot close account with created apps")
	}
	if sender.Amount < fee {
		return nil, fmt.Errorf("insufficient funds for close fee: balance %d, fee %d", sender.Amount, fee)
	}
	return []PreparedCheck{{
		Name:   "account_close",
		Status: "ok",
		Data: map[string]any{
			"balance":     sender.Amount,
			"min_balance": sender.MinBalance,
			"fee":         fee,
		},
	}}, nil
}

func rekeyChecks(target models.Account, rekeyTo string) ([]PreparedCheck, error) {
	if target.AuthAddr != "" && target.AuthAddr != rekeyTo {
		return nil, fmt.Errorf("rekey target is itself rekeyed to %s", target.AuthAddr)
	}
	return []PreparedCheck{{
		Name:   "rekey",
		Status: "ok",
		Data: map[string]any{
			"rekey_to": rekeyTo,
		},
	}}, nil
}

func validateKeyRegParams(params KeyRegPrepParams) error {
	if params.Nonparticipation {
		return nil
	}
	if params.VoteKey == "" {
		return fmt.Errorf("vote_key is required")
	}
	if params.SelectionKey == "" {
		return fmt.Errorf("selection_key is required")
	}
	if params.VoteFirst == 0 {
		return fmt.Errorf("vote_first is required")
	}
	if params.VoteLast == 0 {
		return fmt.Errorf("vote_last is required")
	}
	if params.VoteLast < params.VoteFirst {
		return fmt.Errorf("vote_last must be greater than or equal to vote_first")
	}
	if params.VoteKeyDilution == 0 {
		return fmt.Errorf("vote_key_dilution is required")
	}
	return nil
}

func appCallChecks(params AppCallPrepParams, info *AppCallInfo) []PreparedCheck {
	data := map[string]any{
		"app_id":         params.AppID,
		"on_completion":  uint64(params.OnCompletion),
		"args":           len(params.AppArgs),
		"accounts":       len(params.Accounts),
		"foreign_apps":   len(params.ForeignApps),
		"foreign_assets": len(params.ForeignAssets),
		"boxes":          len(params.Boxes),
	}
	if info != nil {
		data["mode"] = info.Mode
		if info.Method != "" {
			data["method"] = info.Method
		}
	}
	return []PreparedCheck{{
		Name:   "app_call",
		Status: "ok",
		Data:   data,
	}}
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

func encodeABIMethodArgs(method abi.Method, args []any, sender string, appID uint64, accounts []string, apps []uint64, assets []uint64) ([][]byte, []string, []uint64, []uint64, error) {
	if len(args) != len(method.Args) {
		return nil, nil, nil, nil, fmt.Errorf("incorrect number of ABI arguments: got %d, want %d", len(args), len(method.Args))
	}

	basicArgValues := make([]any, 0, len(args))
	basicArgTypes := make([]abi.Type, 0, len(args))
	refArgValues := make([]any, 0)
	refArgTypes := make([]string, 0)
	refArgIndexToBasicArgIndex := map[int]int{}

	for i, arg := range method.Args {
		argValue := args[i]
		if arg.IsTransactionArg() {
			return nil, nil, nil, nil, fmt.Errorf("ABI transaction arguments are not supported by PrepareABIAppCall")
		}

		var abiType abi.Type
		var err error
		if arg.IsReferenceArg() {
			refArgIndexToBasicArgIndex[len(refArgTypes)] = len(basicArgTypes)
			refArgValues = append(refArgValues, argValue)
			refArgTypes = append(refArgTypes, arg.Type)
			abiType, err = abi.TypeOf("uint8")
		} else {
			abiType, err = arg.GetTypeObject()
		}
		if err != nil {
			return nil, nil, nil, nil, err
		}
		basicArgValues = append(basicArgValues, argValue)
		basicArgTypes = append(basicArgTypes, abiType)
	}

	foreignAccounts := append([]string(nil), accounts...)
	foreignApps := append([]uint64(nil), apps...)
	foreignAssets := append([]uint64(nil), assets...)
	refArgsResolved, err := resolveABIReferenceArgs(sender, appID, refArgTypes, refArgValues, &foreignAccounts, &foreignApps, &foreignAssets)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for i, resolved := range refArgsResolved {
		if resolved > 255 {
			return nil, nil, nil, nil, fmt.Errorf("ABI reference index %d exceeds uint8", resolved)
		}
		basicArgValues[refArgIndexToBasicArgIndex[i]] = uint8(resolved)
	}

	if len(basicArgValues) > appCallMaxAppArgs-1 {
		typesForTuple := make([]abi.Type, len(basicArgTypes)-appCallMethodArgsTupleThreshold)
		copy(typesForTuple, basicArgTypes[appCallMethodArgsTupleThreshold:])
		valueForTuple := make([]any, len(basicArgValues)-appCallMethodArgsTupleThreshold)
		copy(valueForTuple, basicArgValues[appCallMethodArgsTupleThreshold:])
		tupleType, err := abi.MakeTupleType(typesForTuple)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		basicArgValues = append(basicArgValues[:appCallMethodArgsTupleThreshold], valueForTuple)
		basicArgTypes = append(basicArgTypes[:appCallMethodArgsTupleThreshold], tupleType)
	}

	encoded := [][]byte{method.GetSelector()}
	for i, value := range basicArgValues {
		encodedArg, err := basicArgTypes[i].Encode(value)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		encoded = append(encoded, encodedArg)
	}
	return encoded, foreignAccounts, foreignApps, foreignAssets, nil
}

func resolveABIReferenceArgs(sender string, appID uint64, types []string, values []any, accounts *[]string, apps *[]uint64, assets *[]uint64) ([]int, error) {
	resolvedIndexes := make([]int, len(types))
	for i, value := range values {
		var resolved int
		switch types[i] {
		case abi.AccountReferenceType:
			address, err := marshalABIAddress(value)
			if err != nil {
				return nil, err
			}
			if address == sender {
				resolved = 0
			} else if idx := stringIndex(*accounts, address); idx >= 0 {
				resolved = idx + 1
			} else {
				resolved = len(*accounts) + 1
				*accounts = append(*accounts, address)
			}
		case abi.ApplicationReferenceType:
			refAppID, err := marshalABIUint64(value)
			if err != nil {
				return nil, err
			}
			if refAppID == appID {
				resolved = 0
			} else if idx := uint64Index(*apps, refAppID); idx >= 0 {
				resolved = idx + 1
			} else {
				resolved = len(*apps) + 1
				*apps = append(*apps, refAppID)
			}
		case abi.AssetReferenceType:
			assetID, err := marshalABIUint64(value)
			if err != nil {
				return nil, err
			}
			if idx := uint64Index(*assets, assetID); idx >= 0 {
				resolved = idx
			} else {
				resolved = len(*assets)
				*assets = append(*assets, assetID)
			}
		default:
			return nil, fmt.Errorf("unknown reference type: %s", types[i])
		}
		resolvedIndexes[i] = resolved
	}
	return resolvedIndexes, nil
}

func marshalABIUint64(value any) (uint64, error) {
	abiType, err := abi.TypeOf("uint64")
	if err != nil {
		return 0, err
	}
	encoded, err := abiType.Encode(value)
	if err != nil {
		return 0, err
	}
	decoded, err := abiType.Decode(encoded)
	if err != nil {
		return 0, err
	}
	marshaled, ok := decoded.(uint64)
	if !ok {
		return 0, fmt.Errorf("decoded value is not a uint64")
	}
	return marshaled, nil
}

func marshalABIAddress(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		address, err := types.DecodeAddress(typed)
		if err != nil {
			return "", err
		}
		return address.String(), nil
	case types.Address:
		return typed.String(), nil
	case []byte:
		if len(typed) != len(types.ZeroAddress) {
			return "", fmt.Errorf("decoded value is not a 32-byte address")
		}
		var address types.Address
		copy(address[:], typed)
		return address.String(), nil
	case [32]byte:
		var address types.Address
		copy(address[:], typed[:])
		return address.String(), nil
	}

	abiType, err := abi.TypeOf("address")
	if err != nil {
		return "", err
	}
	encoded, err := abiType.Encode(value)
	if err != nil {
		return "", err
	}
	decoded, err := abiType.Decode(encoded)
	if err != nil {
		return "", err
	}
	marshaled, ok := decoded.([]byte)
	if !ok || len(marshaled) != len(types.ZeroAddress) {
		return "", fmt.Errorf("decoded value is not a 32-byte address")
	}
	var address types.Address
	copy(address[:], marshaled)
	return address.String(), nil
}

func stringIndex(values []string, target string) int {
	for i, value := range values {
		if value == target {
			return i
		}
	}
	return -1
}

func uint64Index(values []uint64, target uint64) int {
	for i, value := range values {
		if value == target {
			return i
		}
	}
	return -1
}

func accountAssetHolding(account models.Account, assetID uint64) (models.AssetHolding, bool) {
	for _, holding := range account.Assets {
		if holding.AssetId == assetID && !holding.Deleted {
			return holding, true
		}
	}
	return models.AssetHolding{}, false
}
