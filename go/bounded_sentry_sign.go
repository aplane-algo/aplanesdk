// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SignPreparedBoundedSentryGroup signs a prepared group containing one or more
// bounded-sentry1 targets. Most callers can use SignPreparedGuardedGroup,
// which dispatches to this choreography from signer inventory metadata.
func SignPreparedBoundedSentryGroup(opts PreparedGuardedGroupOptions) (*GuardedSignResult, error) {
	return SignPreparedBoundedSentryGroupWithContext(context.Background(), opts)
}

// SignPreparedBoundedSentryGroupWithContext is the context-aware form of
// SignPreparedBoundedSentryGroup.
func SignPreparedBoundedSentryGroupWithContext(ctx context.Context, opts PreparedGuardedGroupOptions) (*GuardedSignResult, error) {
	return signPreparedBoundedSentryGroupWithContext(ctx, opts)
}

func signPreparedBoundedSentryGroupWithContext(ctx context.Context, opts PreparedGuardedGroupOptions) (*GuardedSignResult, error) {
	if opts.UserClient == nil {
		return nil, fmt.Errorf("user client is required")
	}
	prepared := opts.PreparedGroup.Transactions
	if len(prepared) == 0 {
		return nil, fmt.Errorf("prepared group is empty")
	}

	requests := make([]SignRequest, len(prepared))
	targets := make([]GuardedSignTarget, 0, len(prepared))
	primaryTargets := make([]GuardedPrimarySignTarget, 0, len(prepared))
	targetLsigSizes := make(map[int]int)
	targetMaxFees := make(map[int]uint64)
	for i, item := range prepared {
		if item.SignedTransactionBase64 != "" {
			return nil, fmt.Errorf("prepared transaction %d: passthrough entries are not supported in prepared bounded-sentry groups", i)
		}
		if item.Transaction == nil {
			return nil, fmt.Errorf("prepared transaction %d: transaction is required", i)
		}
		key := item.SignerKey
		if key == nil && item.AuthAddress != "" {
			var err error
			key, err = opts.UserClient.GetKeyInfo(item.AuthAddress)
			if err != nil {
				return nil, fmt.Errorf("prepared transaction %d: resolve signer key: %w", i, err)
			}
		}
		if key == nil {
			return nil, fmt.Errorf("prepared transaction %d: signer key metadata is required", i)
		}

		lsigSize := item.LsigSize
		if key.LsigSize > 0 {
			lsigSize = key.LsigSize
		}
		switch key.SigningFlow {
		case SigningFlowBoundedSentry1:
			if item.AuthAddress == "" {
				return nil, fmt.Errorf("prepared transaction %d: bounded auth address is required", i)
			}
			req, err := item.SignRequest()
			if err != nil {
				return nil, fmt.Errorf("prepared transaction %d: %w", i, err)
			}
			requests[i] = req
			targetLsigSizes[i] = lsigSize
			if key.BoundedAuthorization == nil {
				return nil, fmt.Errorf("prepared transaction %d: bounded authorization metadata is required", i)
			}
			targetMaxFees[i] = key.BoundedAuthorization.MaxFee
			targets = append(targets, GuardedSignTarget{
				TargetIndex:            i,
				GuardedAccount:         item.AuthAddress,
				SentryPublicKeyHex:     boundedSentryPublicKey(key),
				SentryComponentKeyType: boundedSentryComponentKeyType(key),
			})
		case SigningFlowSentry1:
			return nil, fmt.Errorf("cannot mix sentry1 and bounded-sentry1 targets in one group")
		default:
			if key.SigningFlow != "" && key.SigningFlow != SigningFlowBounded1 {
				return nil, fmt.Errorf("prepared transaction %d: signer key requires signing flow %q, which this SDK does not support; upgrade the SDK", i, key.SigningFlow)
			}
			requests[i] = SignRequest{
				TxnBytesHex: hex.EncodeToString(encodeTxn(*item.Transaction)),
				LsigSize:    lsigSize,
			}
			if item.AuthAddress == "" {
				return nil, fmt.Errorf("prepared transaction %d: primary auth address is required", i)
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
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("prepared group has no bounded-sentry targets")
	}

	componentResp, err := opts.UserClient.RequestBoundedComponentWithContext(ctx, BoundedComponentRequest{Requests: requests})
	if err != nil {
		return nil, fmt.Errorf("bounded base component signing failed: %w", err)
	}
	planned, err := decodeCanonicalGroup(componentResp.Transactions)
	if err != nil {
		return nil, fmt.Errorf("signer returned invalid bounded canonical group: %w", err)
	}
	if len(planned) < len(prepared) {
		return nil, fmt.Errorf("signer returned %d bounded group positions, want at least %d", len(planned), len(prepared))
	}
	original := make([]types.Transaction, len(prepared))
	for i, item := range prepared {
		original[i] = *item.Transaction
	}
	if err := validateBoundedComponentPlan(original, planned, componentResp.Mutations); err != nil {
		return nil, err
	}
	if err := validateBoundedTargetFees(planned, targetMaxFees); err != nil {
		return nil, err
	}

	components := make(map[int]BoundedBaseComponent, len(componentResp.Components))
	targetsByIndex := make(map[int]GuardedSignTarget, len(targets))
	for _, target := range targets {
		targetsByIndex[target.TargetIndex] = target
	}
	for _, component := range componentResp.Components {
		target, ok := targetsByIndex[component.TargetIndex]
		if !ok || component.BoundedAccount != target.GuardedAccount {
			return nil, fmt.Errorf("signer returned unexpected bounded component target %d", component.TargetIndex)
		}
		if _, duplicate := components[component.TargetIndex]; duplicate {
			return nil, fmt.Errorf("signer returned duplicate bounded component target %d", component.TargetIndex)
		}
		components[component.TargetIndex] = component
	}
	for _, target := range targets {
		if _, ok := components[target.TargetIndex]; !ok {
			return nil, fmt.Errorf("signer returned no bounded component for target index %d", target.TargetIndex)
		}
	}

	result := &GuardedSignResult{BoundedComponentResponse: componentResp}
	sentryOpts := GuardedSignOptions{
		UserClient:         opts.UserClient,
		SentryClient:       opts.SentryClient,
		SentryResolver:     opts.SentryResolver,
		SentryComponentKey: opts.SentryComponentKey,
		GroupBytesHex:      componentResp.Transactions,
	}
	sentrySignatures, err := requestSentryComponentSignatures(ctx, sentryOpts, targets, result)
	if err != nil {
		return nil, err
	}

	primary, err := requestBoundedPrimaryPassthrough(
		ctx, opts.UserClient, componentResp.Transactions, len(prepared),
		targetsByIndex, targetLsigSizes, primaryTargets,
	)
	if err != nil {
		return nil, err
	}
	if primary != nil {
		result.PrimarySignResponse = primary.response
	}
	passthrough := make([]GuardedPassthroughItem, 0, len(planned)-len(targets))
	if primary != nil {
		passthrough = append(passthrough, primary.passthrough...)
	}
	dummies, err := signGuardedDummies(planned[len(prepared):], len(prepared))
	if err != nil {
		return nil, err
	}
	passthrough = append(passthrough, dummies...)

	assemblyTargets := make([]BoundedAssemblyTarget, 0, len(targets))
	for _, target := range targets {
		component := components[target.TargetIndex]
		sentry, ok := sentrySignatures[target.TargetIndex]
		if !ok {
			return nil, fmt.Errorf("missing sentry component signature for target %d", target.TargetIndex)
		}
		assemblyTargets = append(assemblyTargets, BoundedAssemblyTarget{
			TargetIndex:           target.TargetIndex,
			BoundedAccount:        target.GuardedAccount,
			BaseSignatures:        append([]string(nil), component.BaseSignatures...),
			RuntimeArgs:           cloneStringMap(component.RuntimeArgs),
			AssemblyReceipt:       component.AssemblyReceipt,
			BaseSourceRequestID:   componentResp.RequestID,
			SentrySignature:       sentry.signature,
			SentrySourceRequestID: sentry.requestID,
		})
	}

	assemblyResp, err := opts.UserClient.RequestBoundedAssembleWithContext(ctx, BoundedAssemblyRequest{
		RequestID:     opts.AssemblyRequestID,
		GroupBytesHex: append([]string(nil), componentResp.Transactions...),
		Targets:       assemblyTargets,
		Passthrough:   passthrough,
	})
	if err != nil {
		return nil, fmt.Errorf("bounded-sentry assembly failed: %w", err)
	}
	if err := verifyAssembledGroup(componentResp.Transactions, assemblyResp.SignedGroup); err != nil {
		return nil, err
	}
	result.BoundedAssemblyResponse = assemblyResp
	result.SignedGroup = append([]string(nil), assemblyResp.SignedGroup...)
	return result, nil
}

func requestBoundedPrimaryPassthrough(
	ctx context.Context,
	client *SignerClient,
	groupBytesHex []string,
	originalCount int,
	targets map[int]GuardedSignTarget,
	targetLsigSizes map[int]int,
	primaryTargets []GuardedPrimarySignTarget,
) (*primaryGuardedPassthrough, error) {
	if len(primaryTargets) == 0 {
		return nil, nil
	}
	primaryByIndex := make(map[int]GuardedPrimarySignTarget, len(primaryTargets))
	for _, target := range primaryTargets {
		if target.TargetIndex < 0 || target.TargetIndex >= originalCount {
			return nil, fmt.Errorf("primary target %d out of range", target.TargetIndex)
		}
		if _, duplicate := primaryByIndex[target.TargetIndex]; duplicate {
			return nil, fmt.Errorf("duplicate primary target index %d", target.TargetIndex)
		}
		primaryByIndex[target.TargetIndex] = target
	}
	requests := make([]SignRequest, len(groupBytesHex))
	for i, txnHex := range groupBytesHex {
		switch {
		case i >= originalCount:
			requests[i] = SignRequest{TxnBytesHex: txnHex}
		case targets[i].GuardedAccount != "":
			requests[i] = SignRequest{TxnBytesHex: txnHex, LsigSize: targetLsigSizes[i]}
		default:
			target, ok := primaryByIndex[i]
			if !ok {
				return nil, fmt.Errorf("group position %d has no bounded or primary target", i)
			}
			requests[i] = SignRequest{
				AuthAddress: target.AuthAddress,
				TxnSender:   target.TxnSender,
				TxnBytesHex: txnHex,
				LsigArgs:    cloneStringMap(target.LsigArgs),
				LsigSize:    target.LsigSize,
				AppCallInfo: target.AppCallInfo,
			}
		}
	}
	response, err := client.SignGroupWithContext(ctx, GroupSignRequest{Requests: requests})
	if err != nil {
		return nil, fmt.Errorf("signing non-bounded group positions failed: %w", err)
	}
	passthrough := make([]GuardedPassthroughItem, 0, len(primaryByIndex))
	for index := range primaryByIndex {
		if index >= len(response.Signed) || response.Signed[index] == "" {
			return nil, fmt.Errorf("primary signer returned no signed transaction for target %d", index)
		}
		if err := signedTxnMatchesCanonical("primary passthrough", index, response.Signed[index], groupBytesHex[index]); err != nil {
			return nil, err
		}
		passthrough = append(passthrough, GuardedPassthroughItem{
			TargetIndex: index, SignedTxnHex: response.Signed[index],
		})
	}
	sort.Slice(passthrough, func(i, j int) bool {
		return passthrough[i].TargetIndex < passthrough[j].TargetIndex
	})
	return &primaryGuardedPassthrough{response: response, passthrough: passthrough}, nil
}

func decodeCanonicalGroup(groupHex []string) ([]types.Transaction, error) {
	txns := make([]types.Transaction, len(groupHex))
	for i, encoded := range groupHex {
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("transaction %d is invalid hex: %w", i, err)
		}
		if len(raw) < 3 || raw[0] != 'T' || raw[1] != 'X' {
			return nil, fmt.Errorf("transaction %d is missing TX prefix", i)
		}
		if err := msgpack.Decode(raw[2:], &txns[i]); err != nil {
			return nil, fmt.Errorf("transaction %d is invalid: %w", i, err)
		}
	}
	return txns, nil
}

// validateBoundedComponentPlan permits only the planner's declared mutations
// to original positions. Appended positions must be canonical budget dummies.
func validateBoundedComponentPlan(original, planned []types.Transaction, mutations *MutationReport) error {
	if len(planned) < len(original) {
		return fmt.Errorf("signer returned %d bounded group positions, want at least %d", len(planned), len(original))
	}
	appended := len(planned) - len(original)
	if mutations == nil {
		if appended != 0 {
			return fmt.Errorf("signer appended %d bounded group positions without a mutation report", appended)
		}
	} else {
		if mutations.OriginalCount != len(original) {
			return fmt.Errorf("bounded mutation original_count %d does not match request count %d", mutations.OriginalCount, len(original))
		}
		if mutations.FinalCount != len(planned) {
			return fmt.Errorf("bounded mutation final_count %d does not match returned count %d", mutations.FinalCount, len(planned))
		}
		if mutations.DummiesAdded != appended {
			return fmt.Errorf("bounded mutation dummies_added %d does not match appended count %d", mutations.DummiesAdded, appended)
		}
	}

	feeModified := make(map[int]struct{})
	if mutations != nil {
		for _, index := range mutations.FeesModified {
			if index < 0 || index >= len(original) {
				return fmt.Errorf("bounded mutation fee index %d is outside original positions", index)
			}
			if _, duplicate := feeModified[index]; duplicate {
				return fmt.Errorf("bounded mutation fee index %d is duplicated", index)
			}
			feeModified[index] = struct{}{}
		}
	}
	if mutations != nil && mutations.GroupIDChanged && appended == 0 && len(feeModified) == 0 {
		var zero types.Digest
		requiresAssignment := false
		for i := range original {
			requiresAssignment = requiresAssignment || original[i].Group == zero
		}
		if !requiresAssignment {
			return fmt.Errorf("signer changed an existing bounded group ID without a fee or membership mutation")
		}
	}
	totalFeeDelta := uint64(0)
	for i := range original {
		want := original[i]
		got := planned[i]
		if mutations != nil && mutations.GroupIDChanged {
			want.Group = got.Group
		}
		if _, ok := feeModified[i]; ok {
			if got.Fee < want.Fee {
				return fmt.Errorf("bounded mutation decreased fee at original position %d", i)
			}
			totalFeeDelta += uint64(got.Fee - want.Fee)
			want.Fee = got.Fee
		}
		if !bytes.Equal(encodeTxn(want), encodeTxn(got)) {
			return fmt.Errorf("signer changed unreported fields at bounded original position %d", i)
		}
	}
	if mutations != nil && uint64(mutations.TotalFeesDelta) != totalFeeDelta {
		return fmt.Errorf("bounded mutation total_fees_delta %d does not match observed delta %d", mutations.TotalFeesDelta, totalFeeDelta)
	}
	if err := validateGuardedDummies(planned[len(original):]); err != nil {
		return err
	}
	return nil
}

func validateBoundedTargetFees(planned []types.Transaction, maxFees map[int]uint64) error {
	for index, maxFee := range maxFees {
		if index < 0 || index >= len(planned) {
			return fmt.Errorf("bounded target index %d is outside planned group", index)
		}
		if fee := uint64(planned[index].Fee); fee > maxFee {
			return fmt.Errorf("bounded target %d fee %d exceeds advertised max_fee %d", index, fee, maxFee)
		}
	}
	return nil
}

func boundedSentryPublicKey(key *KeyInfo) string {
	if key != nil && key.BoundedAuthorization != nil && key.BoundedAuthorization.Sentry != nil &&
		key.BoundedAuthorization.Sentry.PublicKeyHex != "" {
		return key.BoundedAuthorization.Sentry.PublicKeyHex
	}
	return guardedSentryPublicKey(key)
}

func boundedSentryComponentKeyType(key *KeyInfo) string {
	if key == nil {
		return ""
	}
	if key.SentryComponentKeyType != "" {
		return key.SentryComponentKeyType
	}
	if key.BoundedAuthorization != nil && key.BoundedAuthorization.Sentry != nil {
		return key.BoundedAuthorization.Sentry.ComponentKeyType
	}
	return ""
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
