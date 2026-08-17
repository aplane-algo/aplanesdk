// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

var guardedDummyProgram = []byte{0x03, 0x31, 0x20, 0x32, 0x03, 0x12}

// guardedDummyLogicSigResources must exactly mirror apsigner's canonical
// dummy lsigresource.Usage. /plan and /sign must see the same declaration to
// keep fee planning idempotent across guarded assembly.
func guardedDummyLogicSigResources() *LogicSigResourceUsage {
	return &LogicSigResourceUsage{
		ProgramBytes:  uint64(len(guardedDummyProgram)),
		MaxOpcodeCost: 1,
	}
}

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
	LogicSigResources      *LogicSigResourceUsage
	AppCallInfo            *AppCallInfo
}

// GuardedPrimarySignTarget describes one non-guarded group position that the
// primary/user signer should sign before guarded assembly.
type GuardedPrimarySignTarget struct {
	TargetIndex int
	AuthAddress string
	TxnSender   string
	LsigArgs    map[string]string
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
	Passthrough        []AssemblyPassthroughItem
	DummyPositions     []int
	AssemblyRequestID  string
}

// GuardedSignResult contains the final assembled group and intermediate
// component-sign responses for audit and UI correlation.
type GuardedSignResult struct {
	SignedGroup              []string
	UserComponentResponses   []*ComponentResponse
	SentryComponentResponses []*ComponentResponse
	PrimarySignResponse      *GroupSignResponse
	AssemblyResponse         *AssemblyResponse
	BoundedComponentResponse *ComponentResponse
	BoundedAssemblyResponse  *AssemblyResponse
}

// PreparedGuardedGroupOptions configures SignPreparedGuardedGroup.
type PreparedGuardedGroupOptions struct {
	UserClient         *SignerClient
	SentryClient       *SignerClient
	SentryResolver     GuardedSentryResolver
	SentryComponentKey string
	PreparedGroup      PreparedGroup
	AssemblyRequestID  string
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
	appCallInfoByIndex := make(map[int]*AppCallInfo, len(targets)+len(opts.PrimaryTargets))
	for _, target := range opts.PrimaryTargets {
		appCallInfoByIndex[target.TargetIndex] = target.AppCallInfo
	}
	userGroups := make(map[string][]int)
	for i := range targets {
		target := &targets[i]
		if target.TargetIndex < 0 || target.TargetIndex >= len(opts.GroupBytesHex) {
			return nil, fmt.Errorf("guarded target %d out of range", target.TargetIndex)
		}
		if _, ok := guardedByIndex[target.TargetIndex]; ok {
			return nil, fmt.Errorf("duplicate guarded target index %d", target.TargetIndex)
		}
		if target.GuardedAccount == "" {
			return nil, fmt.Errorf("guarded target %d missing guarded account", target.TargetIndex)
		}
		if target.LogicSigResources == nil {
			return nil, fmt.Errorf("guarded target %d missing LogicSig resources", target.TargetIndex)
		}
		if err := target.LogicSigResources.validate(); err != nil {
			return nil, fmt.Errorf("guarded target %d has invalid LogicSig resources: %w", target.TargetIndex, err)
		}
		guardedByIndex[target.TargetIndex] = *target
		appCallInfoByIndex[target.TargetIndex] = target.AppCallInfo
		userGroups[target.GuardedAccount] = append(userGroups[target.GuardedAccount], target.TargetIndex)
	}

	result := &GuardedSignResult{}
	userSignatures, err := requestUserComponentSignatures(ctx, opts.UserClient, opts.GroupBytesHex, opts.DummyPositions, userGroups, appCallInfoByIndex, result)
	if err != nil {
		return nil, err
	}
	sentrySignatures, err := requestSentryComponentSignatures(ctx, opts, targets, result)
	if err != nil {
		return nil, err
	}

	passthrough := append([]AssemblyPassthroughItem(nil), opts.Passthrough...)
	if len(opts.PrimaryTargets) > 0 {
		primary, err := requestPrimaryGuardedPassthrough(
			ctx,
			opts.UserClient,
			opts.GroupBytesHex,
			guardedByIndex,
			opts.PrimaryTargets,
			opts.Passthrough,
		)
		if err != nil {
			return nil, err
		}
		result.PrimarySignResponse = primary.response
		passthrough = append(passthrough, primary.passthrough...)
	}

	assemblyTargets := make([]AssemblyTarget, 0, len(targets))
	for _, target := range targets {
		userSig, ok := userSignatures[target.TargetIndex]
		if !ok {
			return nil, fmt.Errorf("missing user component signature for target %d", target.TargetIndex)
		}
		sentrySig, ok := sentrySignatures[target.TargetIndex]
		if !ok {
			return nil, fmt.Errorf("missing sentry component signature for target %d", target.TargetIndex)
		}
		assemblyTargets = append(assemblyTargets, AssemblyTarget{
			TargetIndex:           target.TargetIndex,
			Kind:                  AssemblyTargetKindGuarded,
			AuthAddress:           target.GuardedAccount,
			UserSignature:         userSig.signature,
			UserSourceRequestID:   userSig.requestID,
			SentrySignature:       sentrySig.signature,
			SentrySourceRequestID: sentrySig.requestID,
			GuardedRuntimeArgs:    append([]string(nil), target.RuntimeArgs...),
		})
	}
	assemblyPassthrough := make([]AssemblyPassthroughItem, 0, len(passthrough))
	for _, item := range passthrough {
		assemblyPassthrough = append(assemblyPassthrough, AssemblyPassthroughItem(item))
	}
	assemblyResp, err := opts.UserClient.RequestAssembleWithContext(ctx, AssemblyRequest{
		RequestID:     opts.AssemblyRequestID,
		GroupBytesHex: opts.GroupBytesHex,
		Targets:       assemblyTargets,
		Passthrough:   assemblyPassthrough,
	})
	if err != nil {
		return nil, err
	}
	if err := verifyAssembledGroup(opts.GroupBytesHex, assemblyResp.SignedGroup); err != nil {
		return nil, err
	}
	result.AssemblyResponse = assemblyResp
	result.SignedGroup = append([]string(nil), assemblyResp.SignedGroup...)
	return result, nil
}

// verifyAssembledGroup cross-checks the assembler's signed group against the
// frozen canonical bytes the caller submitted. AssemblyResponse.Validate
// only confirms each slot is non-empty; this additionally pins the length and
// the per-position transaction identity, so a wrong-length or substituted
// assembled group cannot reach submission. Each signed transaction's inner Txn
// must re-encode to exactly the canonical bytes at the same index.
func verifyAssembledGroup(groupBytesHex []string, signedGroup []string) error {
	if len(signedGroup) != len(groupBytesHex) {
		return fmt.Errorf("assembled group has %d transaction(s), want %d", len(signedGroup), len(groupBytesHex))
	}
	for i, signedHex := range signedGroup {
		if err := signedTxnMatchesCanonical("assembled transaction", i, signedHex, groupBytesHex[i]); err != nil {
			return err
		}
	}
	return nil
}

// signedTxnMatchesCanonical decodes a hex-encoded SignedTxn and checks that its
// inner transaction re-encodes to exactly the canonical TX-prefixed bytes
// expected at this position. It is the per-slot identity check shared by
// assembled-group verification and primary-passthrough verification: a signer
// must return a signature over the transaction we asked it to sign, not a
// substituted one.
func signedTxnMatchesCanonical(label string, index int, signedHex, canonicalHex string) error {
	canonical, err := hex.DecodeString(canonicalHex)
	if err != nil {
		return fmt.Errorf("%s %d: canonical bytes invalid hex: %w", label, index, err)
	}
	signedBytes, err := hex.DecodeString(signedHex)
	if err != nil {
		return fmt.Errorf("%s %d: invalid hex: %w", label, index, err)
	}
	var stxn types.SignedTxn
	if err := msgpack.Decode(signedBytes, &stxn); err != nil {
		return fmt.Errorf("%s %d: decode failed: %w", label, index, err)
	}
	if reencoded := encodeTxn(stxn.Txn); !bytes.Equal(reencoded, canonical) {
		return fmt.Errorf("%s %d does not match the submitted canonical bytes", label, index)
	}
	return nil
}

// SignPreparedGuardedGroup canonicalizes a prepared group locally, classifies
// guarded and primary slots, then signs and assembles it through component
// signing endpoints. The signer /plan endpoint owns canonical group sizing and
// fee mutation before component signatures are collected.
func SignPreparedGuardedGroup(opts PreparedGuardedGroupOptions) (*GuardedSignResult, error) {
	return SignPreparedGuardedGroupWithContext(context.Background(), opts)
}

// SignPreparedGuardedGroupWithContext is the context-aware form of
// SignPreparedGuardedGroup.
func SignPreparedGuardedGroupWithContext(ctx context.Context, opts PreparedGuardedGroupOptions) (*GuardedSignResult, error) {
	resolvedOpts, hasBoundedSentry, hasLegacyGuarded, err := resolvePreparedSentryFlowKinds(ctx, opts)
	if err != nil {
		return nil, err
	}
	if hasBoundedSentry {
		if hasLegacyGuarded {
			return nil, fmt.Errorf("cannot mix sentry1 and bounded-sentry1 targets in one group")
		}
		return signPreparedBoundedSentryGroupWithContext(ctx, resolvedOpts)
	}
	signOpts, err := buildPreparedGuardedSignOptions(ctx, resolvedOpts)
	if err != nil {
		return nil, err
	}
	return SignGuardedGroupWithContext(ctx, signOpts)
}

func resolvePreparedSentryFlowKinds(ctx context.Context, opts PreparedGuardedGroupOptions) (
	resolved PreparedGuardedGroupOptions,
	boundedSentry bool,
	legacyGuarded bool,
	err error,
) {
	if opts.UserClient == nil {
		return opts, false, false, fmt.Errorf("user client is required")
	}
	resolved = opts
	resolved.PreparedGroup.Transactions = append(
		[]PreparedTransaction(nil),
		opts.PreparedGroup.Transactions...,
	)
	for i := range resolved.PreparedGroup.Transactions {
		item := &resolved.PreparedGroup.Transactions[i]
		key := item.SignerKey
		if key == nil && item.AuthAddress != "" {
			key, err = opts.UserClient.getKeyInfoWithContext(ctx, item.AuthAddress)
			if err != nil {
				return opts, false, false, fmt.Errorf("prepared transaction %d: resolve signer key: %w", i, err)
			}
			item.SignerKey = key
		}
		if key == nil {
			continue
		}
		switch key.SigningFlow {
		case SigningFlowBoundedSentry1:
			boundedSentry = true
		case SigningFlowSentry1:
			legacyGuarded = true
		}
	}
	return resolved, boundedSentry, legacyGuarded, nil
}

func buildPreparedGuardedSignOptions(ctx context.Context, opts PreparedGuardedGroupOptions) (GuardedSignOptions, error) {
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
	planRequests := make([]SignRequest, len(prepared))

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
			key, err = opts.UserClient.getKeyInfoWithContext(ctx, item.AuthAddress)
			if err != nil {
				return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: resolve signer key: %w", i, err)
			}
		}
		if key == nil {
			return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: signer key metadata is required", i)
		}

		if item.AuthAddress == "" {
			return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: auth address is required", i)
		}
		planRequest, err := item.SignRequest()
		if err != nil {
			return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: %w", i, err)
		}
		planRequests[i] = planRequest

		if key.SigningFlow != "" {
			if key.SigningFlow == SigningFlowBounded1 {
				if item.AuthAddress == "" {
					return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: primary auth address is required", i)
				}
				primaryTargets = append(primaryTargets, GuardedPrimarySignTarget{
					TargetIndex: i,
					AuthAddress: item.AuthAddress,
					TxnSender:   item.TxnSender,
					LsigArgs:    encodeGuardedLsigArgs(item.LsigArgs),
					AppCallInfo: item.AppCallInfo,
				})
				continue
			}
			if key.SigningFlow != SigningFlowSentry1 {
				return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: signer key requires signing flow %q, which this SDK does not support; upgrade the SDK", i, key.SigningFlow)
			}
			if item.AuthAddress == "" {
				return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: guarded auth address is required", i)
			}
			resources, err := selectedPreparedResources(key, item.Transaction)
			if err != nil {
				return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: %w", i, err)
			}
			if resources == nil {
				return GuardedSignOptions{}, fmt.Errorf("prepared transaction %d: guarded LogicSig resources are unavailable", i)
			}
			targets = append(targets, GuardedSignTarget{
				TargetIndex:            i,
				GuardedAccount:         item.AuthAddress,
				SentryPublicKeyHex:     guardedSentryPublicKey(key),
				SentryComponentKeyType: key.SentryComponentKeyType,
				LogicSigResources:      resources,
				AppCallInfo:            item.AppCallInfo,
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
			AppCallInfo: item.AppCallInfo,
		})
	}

	if len(targets) == 0 {
		return GuardedSignOptions{}, fmt.Errorf("prepared group has no guarded targets")
	}

	plan, err := opts.UserClient.PlanRequestsWithContext(ctx, planRequests)
	if err != nil {
		return GuardedSignOptions{}, fmt.Errorf("guarded group planning failed: %w", err)
	}
	allTxns, err := decodeCanonicalGroup(plan.Transactions)
	if err != nil {
		return GuardedSignOptions{}, fmt.Errorf("signer returned invalid guarded group plan: %w", err)
	}
	if err := validateBoundedComponentPlan(txns, allTxns, plan.Mutations); err != nil {
		return GuardedSignOptions{}, fmt.Errorf("invalid guarded group plan: %w", err)
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
		DummyPositions:     contiguousIndices(len(txns), len(allTxns)),
		AssemblyRequestID:  opts.AssemblyRequestID,
	}, nil
}

func selectedPreparedResources(key *KeyInfo, txn *types.Transaction) (*LogicSigResourceUsage, error) {
	if key == nil || key.LogicSigResources == nil {
		return nil, nil
	}
	profile := key.LogicSigResources
	selected := profile.Default
	if profile.Spend != nil {
		selected = profile.Spend
	}
	if key.BoundedAuthorization != nil && txn != nil && !txn.RekeyTo.IsZero() {
		authorization := ""
		for _, operation := range key.BoundedAuthorization.AdminOperations {
			if operation.Kind == "rekey" {
				authorization = operation.Authorization
				break
			}
		}
		switch authorization {
		case "spending_key":
			selected = profile.SpendingRekey
		case "admin_key":
			selected = profile.AdminRekey
		default:
			return nil, fmt.Errorf("bounded rekey authorization metadata is unavailable")
		}
	}
	if selected == nil {
		return nil, nil
	}
	copy := *selected
	return &copy, nil
}

// preparedForeignPQScheme returns the native-PQ scheme a foreign slot must
// declare for the given signer key. Foreign slots carry no auth address, so
// the signer budgets fees purely from what the request declares; only
// authorization_kind distinguishes a native-PQ key from an Ed25519 one,
// because neither publishes a LogicSig resource profile. An empty
// authorization_kind means an older signer that does not report it, in which
// case the slot keeps its previous declaration.
func preparedForeignPQScheme(key *KeyInfo, resources *LogicSigResourceUsage) (string, error) {
	if key == nil || key.AuthorizationKind != AuthorizationKindNativePQ {
		return "", nil
	}
	if resources != nil {
		return "", fmt.Errorf("native-PQ signer key must not declare LogicSig resources")
	}
	return PQSchemeFalcon1024, nil
}

func guardedSentryPublicKey(key *KeyInfo) string {
	if key == nil || key.Parameters == nil {
		return ""
	}
	return key.Parameters["sentry_public_key"]
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

func signGuardedDummies(dummies []types.Transaction, startIndex int) ([]AssemblyPassthroughItem, error) {
	if len(dummies) == 0 {
		return nil, nil
	}
	if err := validateGuardedDummies(dummies); err != nil {
		return nil, err
	}
	logicSig := types.LogicSig{Logic: guardedDummyProgram}
	passthrough := make([]AssemblyPassthroughItem, len(dummies))
	for i, txn := range dummies {
		_, signedBytes, err := crypto.SignLogicSigTransaction(logicSig, txn)
		if err != nil {
			return nil, fmt.Errorf("failed to sign dummy transaction %d: %w", i+1, err)
		}
		passthrough[i] = AssemblyPassthroughItem{
			TargetIndex:  startIndex + i,
			SignedTxnHex: hex.EncodeToString(signedBytes),
			Authorization: &GuardedPassthroughAuthorization{
				LogicSigResources: guardedDummyLogicSigResources(),
			},
		}
	}
	return passthrough, nil
}

func validateGuardedDummies(dummies []types.Transaction) error {
	dummyAcct := crypto.LogicSigAccount{Lsig: types.LogicSig{Logic: guardedDummyProgram}}
	dummyAddr, err := dummyAcct.Address()
	if err != nil {
		return fmt.Errorf("failed to compute dummy address: %w", err)
	}
	for i, txn := range dummies {
		if txn.Type != types.PaymentTx || txn.Sender != dummyAddr || txn.Receiver != dummyAddr ||
			txn.Amount != 0 || txn.Fee != 0 || len(txn.Note) != 1 || txn.Note[0] != byte(i) ||
			!txn.RekeyTo.IsZero() || !txn.CloseRemainderTo.IsZero() {
			return fmt.Errorf("signer-appended transaction %d is not a canonical guarded budget dummy", i)
		}
	}
	return nil
}

func requestUserComponentSignatures(ctx context.Context, client *SignerClient, groupBytesHex []string, dummyPositions []int, userGroups map[string][]int, appCallInfo map[int]*AppCallInfo, result *GuardedSignResult) (map[int]guardedComponentSignature, error) {
	accounts := make([]string, 0, len(userGroups))
	for account := range userGroups {
		accounts = append(accounts, account)
	}
	sort.Strings(accounts)

	signatures := make(map[int]guardedComponentSignature)
	for _, account := range accounts {
		indices := append([]int(nil), userGroups[account]...)
		sort.Ints(indices)
		resp, err := client.RequestComponentsWithContext(ctx, componentRequestForIndices(groupBytesHex, indices, dummyPositions, ComponentTargetKindUser, account, appCallInfo))
		if err != nil {
			return nil, err
		}
		result.UserComponentResponses = append(result.UserComponentResponses, resp)
		for _, component := range resp.Components {
			signatures[component.TargetIndex] = guardedComponentSignature{
				signature: component.Signature,
				requestID: resp.RequestID,
			}
		}
	}
	return signatures, nil
}

func requestSentryComponentSignatures(ctx context.Context, opts GuardedSignOptions, targets []GuardedSignTarget, result *GuardedSignResult) (map[int]guardedComponentSignature, error) {
	groups := make(map[sentrySignGroupKey][]int)
	appCallInfo := make(map[int]*AppCallInfo, len(targets)+len(opts.PrimaryTargets))
	for _, target := range opts.PrimaryTargets {
		appCallInfo[target.TargetIndex] = target.AppCallInfo
	}
	for _, target := range targets {
		appCallInfo[target.TargetIndex] = target.AppCallInfo
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
		resp, err := group.client.RequestComponentsWithContext(ctx, componentRequestForIndices(opts.GroupBytesHex, indices, opts.DummyPositions, ComponentTargetKindSentry, group.componentKey, appCallInfo))
		if err != nil {
			return nil, err
		}
		result.SentryComponentResponses = append(result.SentryComponentResponses, resp)
		for _, component := range resp.Components {
			signatures[component.TargetIndex] = guardedComponentSignature{
				signature: component.Signature,
				requestID: resp.RequestID,
			}
		}
	}
	return signatures, nil
}

func componentRequestForIndices(groupBytesHex []string, indices, dummyPositions []int, kind ComponentTargetKind, key string, appCallInfo map[int]*AppCallInfo) ComponentRequest {
	targetSet := make(map[int]bool, len(indices))
	request := ComponentRequest{GroupBytesHex: groupBytesHex}
	for _, index := range indices {
		targetSet[index] = true
		target := ComponentTarget{TargetIndex: index, Kind: kind}
		if kind == ComponentTargetKindUser {
			target.AuthAddress = key
		} else {
			target.ComponentKey = key
		}
		target.AppCallInfo = appCallInfo[index]
		request.Targets = append(request.Targets, target)
	}
	for index := 0; index < len(groupBytesHex)-len(dummyPositions); index++ {
		if !targetSet[index] {
			request.ContextualPositions = append(request.ContextualPositions, ComponentContextPosition{TargetIndex: index, AppCallInfo: appCallInfo[index]})
		}
	}
	for _, index := range dummyPositions {
		request.DummyPositions = append(request.DummyPositions, ComponentDummyPosition{TargetIndex: index})
	}
	return request
}

func contiguousIndices(start, end int) []int {
	indices := make([]int, 0, end-start)
	for index := start; index < end; index++ {
		indices = append(indices, index)
	}
	return indices
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
	passthrough []AssemblyPassthroughItem
}

func requestPrimaryGuardedPassthrough(
	ctx context.Context,
	client *SignerClient,
	groupBytesHex []string,
	guardedByIndex map[int]GuardedSignTarget,
	targets []GuardedPrimarySignTarget,
	passthrough []AssemblyPassthroughItem,
) (*primaryGuardedPassthrough, error) {
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
	passthroughByIndex := make(map[int]AssemblyPassthroughItem, len(passthrough))
	for _, item := range passthrough {
		if item.TargetIndex < 0 || item.TargetIndex >= len(groupBytesHex) {
			return nil, fmt.Errorf("passthrough target %d out of range", item.TargetIndex)
		}
		if _, ok := passthroughByIndex[item.TargetIndex]; ok {
			return nil, fmt.Errorf("duplicate passthrough target index %d", item.TargetIndex)
		}
		if _, ok := primaryByIndex[item.TargetIndex]; ok {
			return nil, fmt.Errorf("passthrough target %d overlaps primary target", item.TargetIndex)
		}
		if _, ok := guardedByIndex[item.TargetIndex]; ok {
			return nil, fmt.Errorf("passthrough target %d overlaps guarded target", item.TargetIndex)
		}
		if item.Authorization == nil {
			return nil, fmt.Errorf("passthrough target %d missing planning authorization", item.TargetIndex)
		}
		if item.Authorization.PQScheme != "" && item.Authorization.LogicSigResources != nil {
			return nil, fmt.Errorf("passthrough target %d cannot specify both PQ scheme and LogicSig resources", item.TargetIndex)
		}
		if item.Authorization.PQScheme != "" && item.Authorization.PQScheme != PQSchemeFalcon1024 {
			return nil, fmt.Errorf("passthrough target %d has unsupported PQ scheme %q", item.TargetIndex, item.Authorization.PQScheme)
		}
		if item.Authorization.LogicSigResources != nil {
			if err := item.Authorization.LogicSigResources.validate(); err != nil {
				return nil, fmt.Errorf("passthrough target %d has invalid LogicSig resources: %w", item.TargetIndex, err)
			}
		}
		passthroughByIndex[item.TargetIndex] = item
	}

	requests := make([]SignRequest, len(groupBytesHex))
	for i, txnHex := range groupBytesHex {
		if target, ok := primaryByIndex[i]; ok {
			requests[i] = SignRequest{
				AuthAddress: target.AuthAddress,
				TxnSender:   target.TxnSender,
				TxnBytesHex: txnHex,
				LsigArgs:    target.LsigArgs,
				AppCallInfo: target.AppCallInfo,
			}
		} else if guarded, ok := guardedByIndex[i]; ok {
			requests[i] = SignRequest{TxnBytesHex: txnHex, LsigResources: guarded.LogicSigResources}
		} else if item, ok := passthroughByIndex[i]; ok {
			requests[i] = SignRequest{
				TxnBytesHex:   txnHex,
				LsigResources: item.Authorization.LogicSigResources,
				PQScheme:      item.Authorization.PQScheme,
			}
		} else {
			return nil, fmt.Errorf("group position %d has no guarded, primary, or passthrough target", i)
		}
	}

	response, err := client.SignGroupWithContext(ctx, GroupSignRequest{Requests: requests})
	if err != nil {
		return nil, err
	}
	primaryPassthrough := make([]AssemblyPassthroughItem, 0, len(primaryByIndex))
	for index := range primaryByIndex {
		if index >= len(response.Signed) || response.Signed[index] == "" {
			return nil, fmt.Errorf("primary signer returned no signed transaction for target %d", index)
		}
		// The primary signer's output is forwarded to assembly as passthrough;
		// verify it signed the transaction we requested (not a substituted one)
		// before trusting its bytes.
		if err := signedTxnMatchesCanonical("primary passthrough", index, response.Signed[index], groupBytesHex[index]); err != nil {
			return nil, err
		}
		primaryPassthrough = append(primaryPassthrough, AssemblyPassthroughItem{
			TargetIndex:  index,
			SignedTxnHex: response.Signed[index],
		})
	}
	sort.Slice(primaryPassthrough, func(i, j int) bool {
		return primaryPassthrough[i].TargetIndex < primaryPassthrough[j].TargetIndex
	})
	return &primaryGuardedPassthrough{response: response, passthrough: primaryPassthrough}, nil
}
