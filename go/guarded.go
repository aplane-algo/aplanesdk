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

// GuardedCosignerResolver resolves a guarded target to the cosigner client that
// should provide the cosigner component signature.
type GuardedCosignerResolver interface {
	ResolveCosigner(ctx context.Context, cosignerPublicKeyHex string, componentKeyType string) (*SignerClient, string, error)
}

// StaticCosignerResolver routes every guarded target to one cosigner client.
type StaticCosignerResolver struct {
	Client       *SignerClient
	ComponentKey string
}

// ResolveCosigner implements GuardedCosignerResolver.
func (r StaticCosignerResolver) ResolveCosigner(ctx context.Context, cosignerPublicKeyHex string, componentKeyType string) (*SignerClient, string, error) {
	if r.Client == nil {
		return nil, "", fmt.Errorf("cosigner client is required")
	}
	return r.Client, r.ComponentKey, nil
}

// GuardedSignTarget describes one guarded-account group position.
type GuardedSignTarget struct {
	TargetIndex              int
	GuardedAccount           string
	CosignerPublicKeyHex     string
	CosignerComponentKeyType string
	CosignerComponentKey     string
	RuntimeArgs              []string
	LogicSigResources        *LogicSigResourceUsage
	AppCallInfo              *AppCallInfo
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

// GuardedSignOptions configures the cosigner component request of a prepared
// cosigned group: where the cosigner is, and the frozen group it signs over.
type GuardedSignOptions struct {
	UserClient           *SignerClient
	CosignerClient       *SignerClient
	CosignerResolver     GuardedCosignerResolver
	CosignerComponentKey string
	GroupBytesHex        []string
	PrimaryTargets       []GuardedPrimarySignTarget
	DummyPositions       []int
}

// GuardedSignResult contains the final assembled group and intermediate
// component-sign responses for audit and UI correlation.
type GuardedSignResult struct {
	SignedGroup                []string
	CosignerComponentResponses []*ComponentResponse
	PrimarySignResponse        *GroupSignResponse
	BoundedComponentResponse   *ComponentResponse
	BoundedAssemblyResponse    *AssemblyResponse
}

// PreparedGuardedGroupOptions configures SignPreparedGuardedGroup.
type PreparedGuardedGroupOptions struct {
	UserClient           *SignerClient
	CosignerClient       *SignerClient
	CosignerResolver     GuardedCosignerResolver
	CosignerComponentKey string
	PreparedGroup        PreparedGroup
	AssemblyRequestID    string
}

type guardedComponentSignature struct {
	signature string
	requestID string
}

type cosignerSignGroupKey struct {
	client       *SignerClient
	componentKey string
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
	return signPreparedBoundedCosignerGroupWithContext(ctx, opts)
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
		switch {
		case key.BoundedAuthorization.RekeyList != nil && key.BoundedAuthorization.Rekey == "refused":
			// Only these addresses: the signer checks the target and adds the proof.
			selected = profile.ListedRekey
		case key.BoundedAuthorization.Rekey == "spending_key":
			// With a list too (plus cosigned) the signer moves a listed target to
			// the listed path, and its base component says so.
			selected = profile.SpendingRekey
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
// because neither publishes a LogicSig resource profile. Any other
// authorization_kind, including an empty one (the key is not a spending
// account or the signer omitted the field), declares no native-PQ scheme, so
// the slot keeps its previous declaration rather than guessing.
func preparedForeignPQScheme(key *KeyInfo, resources *LogicSigResourceUsage) (string, error) {
	if key == nil || key.AuthorizationKind != AuthorizationKindNativePQ {
		return "", nil
	}
	if resources != nil {
		return "", fmt.Errorf("native-PQ signer key must not declare LogicSig resources")
	}
	return PQSchemeFalcon1024, nil
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

func requestCosignerComponentSignatures(ctx context.Context, opts GuardedSignOptions, targets []GuardedSignTarget, result *GuardedSignResult) (map[int]guardedComponentSignature, error) {
	groups := make(map[cosignerSignGroupKey][]int)
	appCallInfo := make(map[int]*AppCallInfo, len(targets)+len(opts.PrimaryTargets))
	for _, target := range opts.PrimaryTargets {
		appCallInfo[target.TargetIndex] = target.AppCallInfo
	}
	for _, target := range targets {
		appCallInfo[target.TargetIndex] = target.AppCallInfo
		client, componentKey, err := resolveGuardedCosigner(ctx, opts, target)
		if err != nil {
			return nil, err
		}
		groups[cosignerSignGroupKey{client: client, componentKey: componentKey}] = append(
			groups[cosignerSignGroupKey{client: client, componentKey: componentKey}],
			target.TargetIndex,
		)
	}

	signatures := make(map[int]guardedComponentSignature)
	for group, indices := range groups {
		sort.Ints(indices)
		resp, err := group.client.RequestComponentsWithContext(ctx, componentRequestForIndices(opts.GroupBytesHex, indices, opts.DummyPositions, group.componentKey, appCallInfo))
		if err != nil {
			return nil, err
		}
		result.CosignerComponentResponses = append(result.CosignerComponentResponses, resp)
		for _, component := range resp.Components {
			signatures[component.TargetIndex] = guardedComponentSignature{
				signature: component.Signature,
				requestID: resp.RequestID,
			}
		}
	}
	return signatures, nil
}

// componentRequestForIndices is the cosigner component request for the frozen
// group's targets at indices, under one Witness Key ID.
func componentRequestForIndices(groupBytesHex []string, indices, dummyPositions []int, componentKey string, appCallInfo map[int]*AppCallInfo) ComponentRequest {
	targetSet := make(map[int]bool, len(indices))
	request := ComponentRequest{GroupBytesHex: groupBytesHex}
	for _, index := range indices {
		targetSet[index] = true
		target := ComponentTarget{TargetIndex: index, Kind: ComponentTargetKindCosigner, ComponentKey: componentKey}
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

func resolveGuardedCosigner(ctx context.Context, opts GuardedSignOptions, target GuardedSignTarget) (*SignerClient, string, error) {
	if opts.CosignerResolver != nil {
		return opts.CosignerResolver.ResolveCosigner(ctx, target.CosignerPublicKeyHex, target.CosignerComponentKeyType)
	}
	if opts.CosignerClient == nil {
		return nil, "", fmt.Errorf("cosigner client or resolver is required")
	}
	componentKey := target.CosignerComponentKey
	if componentKey == "" {
		componentKey = opts.CosignerComponentKey
	}
	return opts.CosignerClient, componentKey, nil
}

type primaryGuardedPassthrough struct {
	response    *GroupSignResponse
	passthrough []AssemblyPassthroughItem
}
