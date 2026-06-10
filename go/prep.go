// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"fmt"

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
