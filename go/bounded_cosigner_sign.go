// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// signPreparedCosignedGroup is the cosigned1 choreography behind
// SignPreparedCosignedGroup, for a prepared group with one or more cosigned
// targets.
func signPreparedCosignedGroup(ctx context.Context, opts PreparedCosignedGroupOptions) (*CosignedSignResult, error) {
	if opts.UserClient == nil {
		return nil, fmt.Errorf("user client is required")
	}
	resolver := cosignerResolverFor(opts)
	prepared := opts.PreparedGroup.Transactions
	if len(prepared) == 0 {
		return nil, fmt.Errorf("prepared group is empty")
	}

	requests := make([]SignRequest, len(prepared))
	targets := make([]cosignedSignTarget, 0, len(prepared))
	primaryTargets := make([]cosignedPrimarySignTarget, 0, len(prepared))
	appCallInfo := make(map[int]*AppCallInfo, len(prepared))
	targetResources := make(map[int]*LogicSigResourceUsage)
	targetKeys := make(map[int]*KeyInfo)
	targetMaxFees := make(map[int]uint64)
	// One read of the signer's keys for the whole group, refreshed when its
	// keyset revision has changed since the list was cached.
	signerKeys, err := opts.UserClient.ListKeysIfKeysetChangedWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve signer keys: %w", err)
	}
	for i, item := range prepared {
		if item.SignedTransactionBase64 != "" {
			return nil, fmt.Errorf("prepared transaction %d: passthrough entries are not supported in prepared bounded-cosigner groups", i)
		}
		if item.Transaction == nil {
			return nil, fmt.Errorf("prepared transaction %d: transaction is required", i)
		}
		if item.AuthAddress == "" {
			return nil, fmt.Errorf("prepared transaction %d: auth address is required", i)
		}
		// The key's flow, resources and fee ceiling decide how the position
		// is signed, so they come from the signer's own record of the key,
		// never from the caller: the spendable key for the position's auth
		// address, the same selection the prepare helpers make.
		found, ok := findSpendableKey(signerKeys, item.AuthAddress)
		if !ok {
			return nil, fmt.Errorf("prepared transaction %d: %w: %s is not available for signing", i, ErrKeyNotFound, item.AuthAddress)
		}
		key := &found
		appCallInfo[i] = item.AppCallInfo

		switch key.SigningFlow {
		case SigningFlowCosigned1:
			resources, err := selectedPreparedResources(key, item.Transaction)
			if err != nil {
				return nil, fmt.Errorf("prepared transaction %d: %w", i, err)
			}
			if resources == nil {
				return nil, fmt.Errorf("prepared transaction %d: bounded LogicSig resources are unavailable", i)
			}
			req, err := item.SignRequest()
			if err != nil {
				return nil, fmt.Errorf("prepared transaction %d: %w", i, err)
			}
			requests[i] = req
			targetResources[i] = resources
			targetKeys[i] = key
			if key.BoundedAuthorization == nil {
				return nil, fmt.Errorf("prepared transaction %d: bounded authorization metadata is required", i)
			}
			maxFee, hasCeiling, err := boundedFeeCeiling(key.BoundedAuthorization)
			if err != nil {
				return nil, fmt.Errorf("prepared transaction %d: %w", i, err)
			}
			if hasCeiling {
				targetMaxFees[i] = maxFee
			}
			targets = append(targets, cosignedSignTarget{
				TargetIndex:              i,
				CosignedAccount:          item.AuthAddress,
				CosignerPublicKeyHex:     boundedCosignerPublicKey(key),
				CosignerComponentKeyType: boundedCosignerComponentKeyType(key),
				LogicSigResources:        resources,
				AppCallInfo:              item.AppCallInfo,
				MayTakeListedPath:        !item.Transaction.RekeyTo.IsZero() && key.BoundedAuthorization.RekeyList != nil,
			})
		default:
			if key.SigningFlow != "" && key.SigningFlow != SigningFlowBounded1 {
				return nil, fmt.Errorf("prepared transaction %d: signer key requires signing flow %q, which this SDK does not support; upgrade the SDK", i, key.SigningFlow)
			}
			// The signer holds this position's key, so it is sent as the
			// signer's own: in sign mode on /plan, and as a contextual
			// position with auth_address on /sign/component. The signer sizes
			// it from its records in both and can put the group's
			// authorization charge on it. Sent as foreign with a size hint,
			// it was immutable, and the cosigned targets paid its charge.
			req, err := item.SignRequest()
			if err != nil {
				return nil, fmt.Errorf("prepared transaction %d: %w", i, err)
			}
			requests[i] = req
			primaryTargets = append(primaryTargets, cosignedPrimarySignTarget{
				TargetIndex: i,
				AuthAddress: item.AuthAddress,
				TxnSender:   item.TxnSender,
				LsigArgs:    encodeCosignedLsigArgs(item.LsigArgs),
				AppCallInfo: item.AppCallInfo,
			})
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("prepared group has no bounded-cosigner targets")
	}
	// Every cosigner a target is sure to need is found before anything is
	// asked to sign, so a cosigner that cannot be found fails the call with
	// nothing signed. A target that may take the listed path needs none if
	// it does, and the listed rekey must work with no cosigner at all, so its
	// cosigner is found only once its base component says it needs one.
	resolved := make(map[int]resolvedCosigner, len(targets))
	for _, target := range inResolveOrder(targets) {
		if target.MayTakeListedPath {
			continue
		}
		cosigner, err := resolveCosigner(ctx, resolver, target)
		if err != nil {
			return nil, err
		}
		resolved[target.TargetIndex] = cosigner
	}

	planResp, err := opts.UserClient.PlanRequestsWithContext(ctx, requests)
	if err != nil {
		return nil, fmt.Errorf("bounded group planning failed: %w", err)
	}
	planned, err := decodeCanonicalGroup(planResp.Transactions)
	if err != nil {
		return nil, fmt.Errorf("signer returned invalid bounded canonical group: %w", err)
	}
	// PlanRequestsWithContext has already checked the plan against the
	// requests: only reported fee raises and group assignment on original
	// positions, and canonical resource dummies after them.
	if err := validateBoundedTargetFees(planned, targetMaxFees); err != nil {
		return nil, err
	}
	componentReq := ComponentRequest{GroupBytesHex: append([]string(nil), planResp.Transactions...)}
	targetSet := make(map[int]bool, len(targets))
	for _, target := range targets {
		targetSet[target.TargetIndex] = true
	}
	for i, request := range requests {
		if targetSet[i] {
			componentReq.Targets = append(componentReq.Targets, ComponentTarget{TargetIndex: i, Kind: ComponentTargetKindBoundedBase, AuthAddress: request.AuthAddress, LsigArgs: request.LsigArgs, AppCallInfo: request.AppCallInfo})
		} else {
			// The user signer's approval shows the other positions' app calls.
			componentReq.ContextualPositions = append(componentReq.ContextualPositions, ComponentContextPosition{TargetIndex: i, AuthAddress: request.AuthAddress, LsigArgs: request.LsigArgs, AppCallInfo: appCallInfo[i]})
		}
	}
	for i := len(prepared); i < len(planResp.Transactions); i++ {
		componentReq.DummyPositions = append(componentReq.DummyPositions, ComponentDummyPosition{TargetIndex: i})
	}
	componentResp, err := opts.UserClient.RequestComponentsWithContext(ctx, componentReq)
	if err != nil {
		return nil, fmt.Errorf("bounded base component signing failed: %w", err)
	}
	components := make(map[int]Component, len(componentResp.Components))
	targetsByIndex := make(map[int]cosignedSignTarget, len(targets))
	for _, target := range targets {
		targetsByIndex[target.TargetIndex] = target
	}
	for _, component := range componentResp.Components {
		target, ok := targetsByIndex[component.TargetIndex]
		if !ok || component.Kind != ComponentTargetKindBoundedBase || component.AuthAddress != target.CosignedAccount {
			return nil, fmt.Errorf("signer returned unexpected bounded component target %d", component.TargetIndex)
		}
		if _, duplicate := components[component.TargetIndex]; duplicate {
			return nil, fmt.Errorf("signer returned duplicate bounded component target %d", component.TargetIndex)
		}
		components[component.TargetIndex] = component
	}
	for _, target := range targets {
		component, ok := components[target.TargetIndex]
		if !ok {
			return nil, fmt.Errorf("signer returned no bounded component for target index %d", target.TargetIndex)
		}
		// Budget the position on the path the signer named, which only the
		// signer can choose: whether a rekey target is listed is not public.
		resources, err := componentPathResources(targetKeys[target.TargetIndex], component.Path)
		if err != nil {
			return nil, fmt.Errorf("prepared transaction %d: %w", target.TargetIndex, err)
		}
		targetResources[target.TargetIndex] = resources
	}

	result := &CosignedSignResult{BoundedComponentResponse: componentResp, PlanMutations: planResp.Mutations}
	primary, err := requestBoundedPrimaryPassthrough(
		ctx, opts.UserClient, planResp.Transactions, len(prepared),
		targetsByIndex, targetResources, primaryTargets,
	)
	if err != nil {
		return nil, err
	}
	if primary != nil {
		result.PrimarySignResponse = primary.response
	}

	// The user side is complete, including ordinary primary positions. Only
	// now may the SDK disclose the frozen group to the cosigner endpoint.
	cosignerOpts := cosignerRequestOptions{
		Resolver:       resolver,
		Resolved:       resolved,
		GroupBytesHex:  planResp.Transactions,
		AppCallInfo:    appCallInfo,
		DummyPositions: contiguousIndices(len(prepared), len(planResp.Transactions)),
	}
	// A listed rekey takes no cosigner component, so the cosigner sees only
	// the targets that need it, and none at all when no target does.
	cosigned := make([]cosignedSignTarget, 0, len(targets))
	for _, target := range targets {
		if components[target.TargetIndex].NeedsCosigner() {
			cosigned = append(cosigned, target)
		}
	}
	cosignerSignatures := map[int]cosignedComponentSignature{}
	if len(cosigned) > 0 {
		cosignerSignatures, err = requestCosignerComponentSignatures(ctx, cosignerOpts, cosigned, result)
		if err != nil {
			return nil, err
		}
	}
	passthrough := make([]AssemblyPassthroughItem, 0, len(planned)-len(targets))
	if primary != nil {
		passthrough = append(passthrough, primary.passthrough...)
	}
	dummies, err := signCosignedDummies(*prepared[0].Transaction, planned[0].Group, planned[len(prepared):], len(prepared))
	if err != nil {
		return nil, err
	}
	passthrough = append(passthrough, dummies...)

	assemblyTargets := make([]AssemblyTarget, 0, len(targets))
	for _, target := range targets {
		component := components[target.TargetIndex]
		assemblyTarget := AssemblyTarget{
			TargetIndex:         target.TargetIndex,
			Kind:                AssemblyTargetKindBoundedCosigner,
			AuthAddress:         target.CosignedAccount,
			BaseSignatures:      append([]string(nil), component.BaseSignatures...),
			BoundedRuntimeArgs:  cloneStringMap(component.RuntimeArgs),
			AssemblyReceipt:     component.AssemblyReceipt,
			BaseSourceRequestID: componentResp.RequestID,
		}
		if component.NeedsCosigner() {
			cosigner, ok := cosignerSignatures[target.TargetIndex]
			if !ok {
				return nil, fmt.Errorf("missing cosigner component signature for target %d", target.TargetIndex)
			}
			assemblyTarget.CosignerSignature = cosigner.signature
			assemblyTarget.CosignerSourceRequestID = cosigner.requestID
		}
		assemblyTargets = append(assemblyTargets, assemblyTarget)
	}
	assemblyResp, err := opts.UserClient.RequestAssembleWithContext(ctx, AssemblyRequest{
		RequestID:     opts.AssemblyRequestID,
		GroupBytesHex: append([]string(nil), planResp.Transactions...),
		Targets:       assemblyTargets,
		Passthrough:   passthrough,
	})
	if err != nil {
		return nil, fmt.Errorf("bounded-cosigner assembly failed: %w", err)
	}
	if err := verifyAssembledGroup(planResp.Transactions, assemblyResp.SignedGroup); err != nil {
		return nil, err
	}
	result.BoundedAssemblyResponse = assemblyResp
	result.SignedGroup = append([]string(nil), assemblyResp.SignedGroup...)
	return result, nil
}

// componentPathResources is the key's LogicSig resource profile for the path a
// base component named.
func componentPathResources(key *KeyInfo, path string) (*LogicSigResourceUsage, error) {
	if key == nil || key.LogicSigResources == nil {
		return nil, fmt.Errorf("bounded LogicSig resources are unavailable")
	}
	var selected *LogicSigResourceUsage
	switch path {
	case ComponentPathSpend:
		selected = key.LogicSigResources.Spend
	case ComponentPathSpendingRekey:
		selected = key.LogicSigResources.SpendingRekey
	case ComponentPathListedRekey:
		selected = key.LogicSigResources.ListedRekey
	}
	if selected == nil {
		return nil, fmt.Errorf("signer key publishes no LogicSig resources for path %q", path)
	}
	copy := *selected
	return &copy, nil
}

func requestBoundedPrimaryPassthrough(
	ctx context.Context,
	client *SignerClient,
	groupBytesHex []string,
	originalCount int,
	targets map[int]cosignedSignTarget,
	targetResources map[int]*LogicSigResourceUsage,
	primaryTargets []cosignedPrimarySignTarget,
) (*primaryCosignedPassthrough, error) {
	if len(primaryTargets) == 0 {
		return nil, nil
	}
	primaryByIndex := make(map[int]cosignedPrimarySignTarget, len(primaryTargets))
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
			requests[i] = SignRequest{
				TxnBytesHex: txnHex, LsigResources: cosignedDummyLogicSigResources(),
			}
		case targets[i].CosignedAccount != "":
			requests[i] = SignRequest{TxnBytesHex: txnHex, LsigResources: targetResources[i]}
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
				AppCallInfo: target.AppCallInfo,
			}
		}
	}
	response, err := client.SignGroupWithContext(ctx, GroupSignRequest{Requests: requests})
	if err != nil {
		return nil, fmt.Errorf("signing non-bounded group positions failed: %w", err)
	}
	passthrough := make([]AssemblyPassthroughItem, 0, len(primaryByIndex))
	for index := range primaryByIndex {
		if index >= len(response.Signed) || response.Signed[index] == "" {
			return nil, fmt.Errorf("primary signer returned no signed transaction for target %d", index)
		}
		// SignGroupWithContext checks the response against the request under
		// the reported mutations. This group is frozen, so no mutation is
		// acceptable: the signed position must be the planned bytes exactly.
		if err := signedTxnMatchesCanonical("primary passthrough", index, response.Signed[index], groupBytesHex[index]); err != nil {
			return nil, err
		}
		passthrough = append(passthrough, AssemblyPassthroughItem{
			TargetIndex: index, SignedTxnHex: response.Signed[index],
		})
	}
	sort.Slice(passthrough, func(i, j int) bool {
		return passthrough[i].TargetIndex < passthrough[j].TargetIndex
	})
	return &primaryCosignedPassthrough{response: response, passthrough: passthrough}, nil
}

// decodeCanonicalGroup decodes a frozen cosigned group. Beyond the shared
// canonical-bytes and canonical-group-ID checks, a single transaction must
// carry no group ID.
func decodeCanonicalGroup(groupHex []string) ([]types.Transaction, error) {
	if len(groupHex) == 0 {
		return nil, fmt.Errorf("canonical group is empty")
	}
	if len(groupHex) > types.MaxTxGroupSize {
		return nil, fmt.Errorf("canonical group size %d exceeds max %d", len(groupHex), types.MaxTxGroupSize)
	}
	txns := make([]types.Transaction, len(groupHex))
	for i, encoded := range groupHex {
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("transaction %d is invalid hex: %w", i, err)
		}
		txns[i], err = decodeCanonicalTxn(raw)
		if err != nil {
			return nil, fmt.Errorf("transaction %d: %w", i, err)
		}
	}
	if len(txns) == 1 {
		if txns[0].Group != (types.Digest{}) {
			return nil, fmt.Errorf("singleton transaction must not have a group ID")
		}
		return txns, nil
	}
	if _, err := validateCanonicalGroupID(txns); err != nil {
		return nil, err
	}
	return txns, nil
}

// Bounded authorization contracts this SDK signs for.
const (
	BoundedContractBounded2 = "bounded2"
	BoundedContractPlain1   = "plain1"
)

// boundedFeeCeiling returns an account's on-chain fee ceiling. A bounded host
// has one; a plain host has none. A contract this SDK doesn't know, or a
// bounded host without its ceiling, fails closed.
func boundedFeeCeiling(info *BoundedAuthorizationInfo) (uint64, bool, error) {
	switch info.Contract {
	case BoundedContractBounded2:
		if info.MaxFee == nil {
			return 0, false, fmt.Errorf("bounded authorization %s has no max_fee", info.Contract)
		}
		return *info.MaxFee, true, nil
	case BoundedContractPlain1:
		if info.MaxFee != nil {
			return 0, false, fmt.Errorf("bounded authorization %s has a max_fee, which a plain host never has", info.Contract)
		}
		return 0, false, nil
	default:
		return 0, false, fmt.Errorf("bounded authorization contract %q is not supported by this SDK; upgrade it", info.Contract)
	}
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

func boundedCosignerPublicKey(key *KeyInfo) string {
	if key != nil && key.BoundedAuthorization != nil && key.BoundedAuthorization.Cosigner != nil &&
		key.BoundedAuthorization.Cosigner.PublicKeyHex != "" {
		return key.BoundedAuthorization.Cosigner.PublicKeyHex
	}
	if key == nil || key.Parameters == nil {
		return ""
	}
	return key.Parameters["cosigner_public_key"]
}

func boundedCosignerComponentKeyType(key *KeyInfo) string {
	if key == nil {
		return ""
	}
	if key.CosignerComponentKeyType != "" {
		return key.CosignerComponentKeyType
	}
	if key.BoundedAuthorization != nil && key.BoundedAuthorization.Cosigner != nil {
		return key.BoundedAuthorization.Cosigner.ComponentKeyType
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
