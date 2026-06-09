// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"fmt"
	"sort"
)

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
