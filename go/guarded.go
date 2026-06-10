// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	guardedLsigBudgetBytes = 1000
	guardedMaxGroupSize    = 16
	guardedDefaultMinFee   = 1000
)

var guardedDummyProgram = []byte{0x03, 0x31, 0x20, 0x32, 0x03, 0x12}

// GuardedSentryResolver resolves a guarded target to the sentry client that
// should provide the sentry component signature.
type GuardedSentryResolver interface {
	ResolveSentry(ctx context.Context, sentryPublicKeyHex string, componentKeyType string) (*SignerClient, string, error)
}

// StaticSentryResolver routes every guarded target to one sentry client.
type StaticSentryResolver struct {
	Client       *SignerClient
	ComponentKey string
}

// ResolveSentry implements GuardedSentryResolver.
func (r StaticSentryResolver) ResolveSentry(ctx context.Context, sentryPublicKeyHex string, componentKeyType string) (*SignerClient, string, error) {
	if r.Client == nil {
		return nil, "", fmt.Errorf("sentry client is required")
	}
	return r.Client, r.ComponentKey, nil
}

// GuardedSignTarget describes one guarded-account group position.
type GuardedSignTarget struct {
	TargetIndex            int
	GuardedAccount         string
	SentryPublicKeyHex     string
	SentryComponentKeyType string
	SentryComponentKey     string
	RuntimeArgs            []string
}

// GuardedPrimarySignTarget describes one non-guarded group position that the
// primary/user signer should sign before guarded assembly.
type GuardedPrimarySignTarget struct {
	TargetIndex int
	AuthAddress string
	TxnSender   string
	LsigArgs    map[string]string
	LsigSize    int
	AppCallInfo *AppCallInfo
}

// GuardedSignOptions configures SignGuardedGroup.
type GuardedSignOptions struct {
	UserClient         *SignerClient
	SentryClient       *SignerClient
	SentryResolver     GuardedSentryResolver
	SentryComponentKey string
	GroupBytesHex      []string
	Targets            []GuardedSignTarget
	PrimaryTargets     []GuardedPrimarySignTarget
	Passthrough        []GuardedPassthroughItem
	AssemblyRequestID  string
}

// GuardedSignResult contains the final assembled group and intermediate
// component-sign responses for audit and UI correlation.
type GuardedSignResult struct {
	SignedGroup              []string
	UserComponentResponses   []*ComponentSignResponse
	SentryComponentResponses []*ComponentSignResponse
	PrimarySignResponse      *GroupSignResponse
	AssemblyResponse         *GuardedAssemblyResponse
}

// PreparedGuardedGroupOptions configures SignPreparedGuardedGroup.
type PreparedGuardedGroupOptions struct {
	UserClient         *SignerClient
	SentryClient       *SignerClient
	SentryResolver     GuardedSentryResolver
	SentryComponentKey string
	PreparedGroup      PreparedGroup
	AssemblyRequestID  string
	MinFee             uint64
}

type guardedComponentSignature struct {
	signature string
	requestID string
}

type sentrySignGroupKey struct {
	client       *SignerClient
	componentKey string
}

// SignGuardedGroup signs and assembles a guarded group using explicit signer
// clients.
func SignGuardedGroup(opts GuardedSignOptions) (*GuardedSignResult, error) {
	return SignGuardedGroupWithContext(context.Background(), opts)
}

// SignGuardedGroupWithContext signs and assembles a guarded group using
// explicit signer clients.
func SignGuardedGroupWithContext(ctx context.Context, opts GuardedSignOptions) (*GuardedSignResult, error) {
	if opts.UserClient == nil {
		return nil, fmt.Errorf("user client is required")
	}
	if len(opts.Targets) == 0 {
		return nil, fmt.Errorf("at least one guarded target is required")
	}
	if err := validateComponentGroupBytes(opts.GroupBytesHex); err != nil {
		return nil, err
	}

	targets := append([]GuardedSignTarget(nil), opts.Targets...)
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].TargetIndex < targets[j].TargetIndex
	})

	guardedByIndex := make(map[int]GuardedSignTarget, len(targets))
	userGroups := make(map[string][]int)
	for _, target := range targets {
		if target.TargetIndex < 0 || target.TargetIndex >= len(opts.GroupBytesHex) {
			return nil, fmt.Errorf("guarded target %d out of range", target.TargetIndex)
		}
		if _, ok := guardedByIndex[target.TargetIndex]; ok {
			return nil, fmt.Errorf("duplicate guarded target index %d", target.TargetIndex)
		}
		if target.GuardedAccount == "" {
			return nil, fmt.Errorf("guarded target %d missing guarded account", target.TargetIndex)
		}
		guardedByIndex[target.TargetIndex] = target
		userGroups[target.GuardedAccount] = append(userGroups[target.GuardedAccount], target.TargetIndex)
	}

	result := &GuardedSignResult{}
	userSignatures, err := requestUserComponentSignatures(ctx, opts.UserClient, opts.GroupBytesHex, userGroups, result)
	if err != nil {
		return nil, err
	}
	sentrySignatures, err := requestSentryComponentSignatures(ctx, opts, targets, result)
	if err != nil {
		return nil, err
	}

	passthrough := append([]GuardedPassthroughItem(nil), opts.Passthrough...)
	if len(opts.PrimaryTargets) > 0 {
		primary, err := requestPrimaryGuardedPassthrough(ctx, opts.UserClient, opts.GroupBytesHex, guardedByIndex, opts.PrimaryTargets)
		if err != nil {
			return nil, err
		}
		result.PrimarySignResponse = primary.response
		passthrough = append(passthrough, primary.passthrough...)
	}

	assemblyTargets := make([]GuardedAssemblyTarget, 0, len(targets))
	for _, target := range targets {
		userSig, ok := userSignatures[target.TargetIndex]
		if !ok {
			return nil, fmt.Errorf("missing user component signature for target %d", target.TargetIndex)
		}
		sentrySig, ok := sentrySignatures[target.TargetIndex]
		if !ok {
			return nil, fmt.Errorf("missing sentry component signature for target %d", target.TargetIndex)
		}
		assemblyTargets = append(assemblyTargets, GuardedAssemblyTarget{
			TargetIndex:           target.TargetIndex,
			GuardedAccount:        target.GuardedAccount,
			UserSignature:         userSig.signature,
			UserSourceRequestID:   userSig.requestID,
			SentrySignature:       sentrySig.signature,
			SentrySourceRequestID: sentrySig.requestID,
			RuntimeArgs:           append([]string(nil), target.RuntimeArgs...),
		})
	}

	assemblyResp, err := opts.UserClient.RequestGuardedAssembleWithContext(ctx, GuardedAssemblyRequest{
		RequestID:     opts.AssemblyRequestID,
		GroupBytesHex: opts.GroupBytesHex,
		Targets:       assemblyTargets,
		Passthrough:   passthrough,
	})
	if err != nil {
		return nil, err
	}
	result.AssemblyResponse = assemblyResp
	result.SignedGroup = append([]string(nil), assemblyResp.SignedGroup...)
	return result, nil
}

// SignPreparedGuardedGroup canonicalizes a prepared group locally, classifies
// guarded and primary slots, then signs and assembles it through component
// signing endpoints. This is the guarded equivalent of apshell's client-side
// prep path; it does not send all-guarded groups to /plan or /sign as
// all-foreign groups.
func SignPreparedGuardedGroup(opts PreparedGuardedGroupOptions) (*GuardedSignResult, error) {
	return SignPreparedGuardedGroupWithContext(context.Background(), opts)
}

// SignPreparedGuardedGroupWithContext is the context-aware form of
// SignPreparedGuardedGroup.
func SignPreparedGuardedGroupWithContext(ctx context.Context, opts PreparedGuardedGroupOptions) (*GuardedSignResult, error) {
	signOpts, err := buildPreparedGuardedSignOptions(opts)
	if err != nil {
		return nil, err
	}
	return SignGuardedGroupWithContext(ctx, signOpts)
}

func buildPreparedGuardedSignOptions(opts PreparedGuardedGroupOptions) (GuardedSignOptions, error) {
	if opts.UserClient == nil {
		return GuardedSignOptions{}, fmt.Errorf("user client is required")
	}
	prepared := opts.PreparedGroup.Transactions
	if len(prepared) == 0 {
		return GuardedSignOptions{}, fmt.Errorf("prepared group is empty")
	}

	txns := make([]types.Transaction, len(prepared))
	targets := make([]GuardedSignTarget, 0, len(prepared))
	primaryTargets := make([]GuardedPrimarySignTarget, 0, len(prepared))
	lsigIndices := make([]int, 0, len(prepared))
	totalLsigBytes := 0

	for i, item := range prepared {
		if item.SignedTransactionBase64 != "" {
			return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: passthrough entries are not supported in prepared guarded groups", i)
		}
		if item.Transaction == nil {
			return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: transaction is required", i)
		}
		txns[i] = *item.Transaction

		key := item.SignerKey
		if key == nil && item.AuthAddress != "" {
			var err error
			key, err = opts.UserClient.GetKeyInfo(item.AuthAddress)
			if err != nil {
				return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: resolve signer key: %w", i, err)
			}
		}
		if key == nil {
			return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: signer key metadata is required", i)
		}

		lsigSize := item.LsigSize
		if key.LsigSize > 0 {
			lsigSize = key.LsigSize
		}
		if lsigSize > 0 {
			totalLsigBytes += lsigSize
			lsigIndices = append(lsigIndices, i)
		}

		if isGuardedKeyType(key.KeyType) {
			if item.AuthAddress == "" {
				return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: guarded auth address is required", i)
			}
			targets = append(targets, GuardedSignTarget{
				TargetIndex:            i,
				GuardedAccount:         item.AuthAddress,
				SentryPublicKeyHex:     guardedSentryPublicKey(key),
				SentryComponentKeyType: guardedSentryComponentKeyType(key.KeyType),
			})
			continue
		}

		if item.AuthAddress == "" {
			return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: primary auth address is required", i)
		}
		primaryTargets = append(primaryTargets, GuardedPrimarySignTarget{
			TargetIndex: i,
			AuthAddress: item.AuthAddress,
			TxnSender:   item.TxnSender,
			LsigArgs:    encodeGuardedLsigArgs(item.LsigArgs),
			LsigSize:    lsigSize,
			AppCallInfo: item.AppCallInfo,
		})
	}

	if len(targets) == 0 {
		return GuardedSignOptions{}, fmt.Errorf("prepared group has no guarded targets")
	}

	minFee := opts.MinFee
	if minFee == 0 {
		minFee = guardedDefaultMinFee
	}
	dummiesNeeded := guardedDummiesNeeded(totalLsigBytes, len(txns))
	if len(txns)+dummiesNeeded > guardedMaxGroupSize {
		return GuardedSignOptions{}, fmt.Errorf("group would be %d transactions (max %d) - cannot add %d dummies for LSig budget",
			len(txns)+dummiesNeeded, guardedMaxGroupSize, dummiesNeeded)
	}
	if dummiesNeeded > 0 {
		if err := applyGuardedDummyFees(txns, lsigIndices, dummiesNeeded, minFee); err != nil {
			return GuardedSignOptions{}, err
		}
	}

	dummyTxns, err := createGuardedDummies(txns[0], dummiesNeeded)
	if err != nil {
		return GuardedSignOptions{}, err
	}
	allTxns := append(txns, dummyTxns...)
	if len(allTxns) > 1 {
		for i := range allTxns {
			allTxns[i].Group = types.Digest{}
		}
		gid, err := crypto.ComputeGroupID(allTxns)
		if err != nil {
			return GuardedSignOptions{}, fmt.Errorf("failed to compute group ID: %w", err)
		}
		for i := range allTxns {
			allTxns[i].Group = gid
		}
	}

	dummyPassthrough, err := signGuardedDummies(allTxns[len(txns):], len(txns))
	if err != nil {
		return GuardedSignOptions{}, err
	}

	groupBytesHex := make([]string, len(allTxns))
	for i, txn := range allTxns {
		groupBytesHex[i] = hex.EncodeToString(encodeTxn(txn))
	}

	return GuardedSignOptions{
		UserClient:         opts.UserClient,
		SentryClient:       opts.SentryClient,
		SentryResolver:     opts.SentryResolver,
		SentryComponentKey: opts.SentryComponentKey,
		GroupBytesHex:      groupBytesHex,
		Targets:            targets,
		PrimaryTargets:     primaryTargets,
		Passthrough:        dummyPassthrough,
		AssemblyRequestID:  opts.AssemblyRequestID,
	}, nil
}

func isGuardedKeyType(keyType string) bool {
	return keyType == KeyTypeGuardedFalcon1024SentryEd25519 || keyType == KeyTypeGuardedFalcon1024SentryFalcon1024
}

func guardedSentryPublicKey(key *KeyInfo) string {
	if key == nil || key.Parameters == nil {
		return ""
	}
	return key.Parameters["sentry_public_key"]
}

func guardedSentryComponentKeyType(keyType string) string {
	switch keyType {
	case KeyTypeGuardedFalcon1024SentryFalcon1024:
		return KeyTypeSentryFalcon1024
	case KeyTypeGuardedFalcon1024SentryEd25519:
		return KeyTypeSentryEd25519
	default:
		return ""
	}
}

func encodeGuardedLsigArgs(args LsigArgs) map[string]string {
	if len(args) == 0 {
		return nil
	}
	out := make(map[string]string, len(args))
	for name, value := range args {
		out[name] = hex.EncodeToString(value)
	}
	return out
}

func guardedDummiesNeeded(totalLsigBytes, txnCount int) int {
	currentBudget := txnCount * guardedLsigBudgetBytes
	if totalLsigBytes <= currentBudget {
		return 0
	}
	extraBudgetNeeded := totalLsigBytes - currentBudget
	return (extraBudgetNeeded + guardedLsigBudgetBytes - 1) / guardedLsigBudgetBytes
}

func applyGuardedDummyFees(txns []types.Transaction, lsigIndices []int, dummyCount int, minFee uint64) error {
	totalFees := uint64(dummyCount) * minFee
	if len(lsigIndices) == 0 {
		if len(txns) == 0 {
			return fmt.Errorf("no transactions to apply dummy fees to")
		}
		txns[0].Fee += types.MicroAlgos(totalFees)
		return nil
	}

	feePerLSig := totalFees / uint64(len(lsigIndices))
	remainder := totalFees % uint64(len(lsigIndices))
	for i, idx := range lsigIndices {
		extra := feePerLSig
		if i == 0 {
			extra += remainder
		}
		txns[idx].Fee += types.MicroAlgos(extra)
	}
	return nil
}

func createGuardedDummies(firstTxn types.Transaction, count int) ([]types.Transaction, error) {
	if count == 0 {
		return nil, nil
	}
	dummyAcct := crypto.LogicSigAccount{Lsig: types.LogicSig{Logic: guardedDummyProgram}}
	dummyAddr, err := dummyAcct.Address()
	if err != nil {
		return nil, fmt.Errorf("failed to compute dummy address: %w", err)
	}

	sp := types.SuggestedParams{
		Fee:             firstTxn.Fee,
		FirstRoundValid: types.Round(firstTxn.FirstValid),
		LastRoundValid:  types.Round(firstTxn.LastValid),
		GenesisID:       firstTxn.GenesisID,
		GenesisHash:     firstTxn.GenesisHash[:],
		FlatFee:         true,
	}
	dummies := make([]types.Transaction, count)
	for i := 0; i < count; i++ {
		txn, err := transaction.MakePaymentTxn(
			dummyAddr.String(),
			dummyAddr.String(),
			0,
			[]byte{byte(i)},
			"",
			sp,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create dummy transaction %d: %w", i+1, err)
		}
		txn.Fee = 0
		dummies[i] = txn
	}
	return dummies, nil
}

func signGuardedDummies(dummies []types.Transaction, startIndex int) ([]GuardedPassthroughItem, error) {
	if len(dummies) == 0 {
		return nil, nil
	}
	logicSig := types.LogicSig{Logic: guardedDummyProgram}
	passthrough := make([]GuardedPassthroughItem, len(dummies))
	for i, txn := range dummies {
		_, signedBytes, err := crypto.SignLogicSigTransaction(logicSig, txn)
		if err != nil {
			return nil, fmt.Errorf("failed to sign dummy transaction %d: %w", i+1, err)
		}
		passthrough[i] = GuardedPassthroughItem{
			TargetIndex:  startIndex + i,
			SignedTxnHex: hex.EncodeToString(signedBytes),
		}
	}
	return passthrough, nil
}

func requestUserComponentSignatures(ctx context.Context, client *SignerClient, groupBytesHex []string, userGroups map[string][]int, result *GuardedSignResult) (map[int]guardedComponentSignature, error) {
	accounts := make([]string, 0, len(userGroups))
	for account := range userGroups {
		accounts = append(accounts, account)
	}
	sort.Strings(accounts)

	signatures := make(map[int]guardedComponentSignature)
	for _, account := range accounts {
		indices := append([]int(nil), userGroups[account]...)
		sort.Ints(indices)
		resp, err := client.RequestComponentSignWithContext(ctx, ComponentSignRequest{
			Role:          ComponentSignRoleUser,
			ComponentKey:  account,
			GroupBytesHex: groupBytesHex,
			TargetIndices: indices,
		})
		if err != nil {
			return nil, err
		}
		result.UserComponentResponses = append(result.UserComponentResponses, resp)
		for _, sig := range resp.Signatures {
			signatures[sig.TargetIndex] = guardedComponentSignature{
				signature: sig.Signature,
				requestID: resp.RequestID,
			}
		}
	}
	return signatures, nil
}

func requestSentryComponentSignatures(ctx context.Context, opts GuardedSignOptions, targets []GuardedSignTarget, result *GuardedSignResult) (map[int]guardedComponentSignature, error) {
	groups := make(map[sentrySignGroupKey][]int)
	for _, target := range targets {
		client, componentKey, err := resolveGuardedSentry(ctx, opts, target)
		if err != nil {
			return nil, err
		}
		groups[sentrySignGroupKey{client: client, componentKey: componentKey}] = append(
			groups[sentrySignGroupKey{client: client, componentKey: componentKey}],
			target.TargetIndex,
		)
	}

	signatures := make(map[int]guardedComponentSignature)
	for group, indices := range groups {
		sort.Ints(indices)
		resp, err := group.client.RequestComponentSignWithContext(ctx, ComponentSignRequest{
			Role:          ComponentSignRoleSentry,
			ComponentKey:  group.componentKey,
			GroupBytesHex: opts.GroupBytesHex,
			TargetIndices: indices,
		})
		if err != nil {
			return nil, err
		}
		result.SentryComponentResponses = append(result.SentryComponentResponses, resp)
		for _, sig := range resp.Signatures {
			signatures[sig.TargetIndex] = guardedComponentSignature{
				signature: sig.Signature,
				requestID: resp.RequestID,
			}
		}
	}
	return signatures, nil
}

func resolveGuardedSentry(ctx context.Context, opts GuardedSignOptions, target GuardedSignTarget) (*SignerClient, string, error) {
	if opts.SentryResolver != nil {
		return opts.SentryResolver.ResolveSentry(ctx, target.SentryPublicKeyHex, target.SentryComponentKeyType)
	}
	if opts.SentryClient == nil {
		return nil, "", fmt.Errorf("sentry client or resolver is required")
	}
	componentKey := target.SentryComponentKey
	if componentKey == "" {
		componentKey = opts.SentryComponentKey
	}
	return opts.SentryClient, componentKey, nil
}

type primaryGuardedPassthrough struct {
	response    *GroupSignResponse
	passthrough []GuardedPassthroughItem
}

func requestPrimaryGuardedPassthrough(ctx context.Context, client *SignerClient, groupBytesHex []string, guardedByIndex map[int]GuardedSignTarget, targets []GuardedPrimarySignTarget) (*primaryGuardedPassthrough, error) {
	primaryByIndex := make(map[int]GuardedPrimarySignTarget, len(targets))
	for _, target := range targets {
		if target.TargetIndex < 0 || target.TargetIndex >= len(groupBytesHex) {
			return nil, fmt.Errorf("primary target %d out of range", target.TargetIndex)
		}
		if _, guarded := guardedByIndex[target.TargetIndex]; guarded {
			return nil, fmt.Errorf("primary target %d overlaps guarded target", target.TargetIndex)
		}
		if _, ok := primaryByIndex[target.TargetIndex]; ok {
			return nil, fmt.Errorf("duplicate primary target index %d", target.TargetIndex)
		}
		if target.AuthAddress == "" {
			return nil, fmt.Errorf("primary target %d missing auth address", target.TargetIndex)
		}
		primaryByIndex[target.TargetIndex] = target
	}

	requests := make([]SignRequest, len(groupBytesHex))
	for i, txnHex := range groupBytesHex {
		if target, ok := primaryByIndex[i]; ok {
			requests[i] = SignRequest{
				AuthAddress: target.AuthAddress,
				TxnSender:   target.TxnSender,
				TxnBytesHex: txnHex,
				LsigArgs:    target.LsigArgs,
				LsigSize:    target.LsigSize,
				AppCallInfo: target.AppCallInfo,
			}
		} else {
			requests[i] = SignRequest{TxnBytesHex: txnHex}
		}
	}

	response, err := client.SignGroupWithContext(ctx, GroupSignRequest{Requests: requests})
	if err != nil {
		return nil, err
	}
	passthrough := make([]GuardedPassthroughItem, 0, len(primaryByIndex))
	for index := range primaryByIndex {
		if index >= len(response.Signed) || response.Signed[index] == "" {
			return nil, fmt.Errorf("primary signer returned no signed transaction for target %d", index)
		}
		passthrough = append(passthrough, GuardedPassthroughItem{
			TargetIndex:  index,
			SignedTxnHex: response.Signed[index],
		})
	}
	sort.Slice(passthrough, func(i, j int) bool {
		return passthrough[i].TargetIndex < passthrough[j].TargetIndex
	})
	return &primaryGuardedPassthrough{response: response, passthrough: passthrough}, nil
}
