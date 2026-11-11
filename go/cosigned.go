// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

var cosignedDummyProgram = []byte{0x03, 0x31, 0x20, 0x32, 0x03, 0x12}

// cosignedDummyOpcodeCost is the opcode cost of one run of cosignedDummyProgram:
// txn RekeyTo, global ZeroAddress and ==, three opcodes costing 1 each, with no
// branch. It matches apsigner's signing.DummyOpcodeCost. A test derives it from
// the program bytes.
const cosignedDummyOpcodeCost uint64 = 3

// cosignedDummyLogicSigResources must exactly mirror apsigner's canonical
// dummy lsigresource.Usage. /plan and /sign must see the same declaration to
// keep fee planning idempotent across cosigned assembly.
func cosignedDummyLogicSigResources() *LogicSigResourceUsage {
	return &LogicSigResourceUsage{
		ProgramBytes:  uint64(len(cosignedDummyProgram)),
		MaxOpcodeCost: cosignedDummyOpcodeCost,
	}
}

// CosignedCosignerResolver resolves a cosigned target to the cosigner client that
// should provide the cosigner component signature.
type CosignedCosignerResolver interface {
	ResolveCosigner(ctx context.Context, cosignerPublicKeyHex string, componentKeyType string) (*SignerClient, string, error)
}

// StaticCosignerResolver routes every cosigned target to one cosigner client.
type StaticCosignerResolver struct {
	Client       *SignerClient
	ComponentKey string
}

// ResolveCosigner implements CosignedCosignerResolver.
func (r StaticCosignerResolver) ResolveCosigner(ctx context.Context, cosignerPublicKeyHex string, componentKeyType string) (*SignerClient, string, error) {
	if r.Client == nil {
		return nil, "", fmt.Errorf("cosigner client is required")
	}
	return r.Client, r.ComponentKey, nil
}

// cosignedSignTarget describes one cosigned-account group position.
type cosignedSignTarget struct {
	TargetIndex              int
	CosignedAccount          string
	CosignerPublicKeyHex     string
	CosignerComponentKeyType string
	LogicSigResources        *LogicSigResourceUsage
	AppCallInfo              *AppCallInfo
}

// cosignedPrimarySignTarget describes one non-cosigned group position that the
// primary/user signer should sign before cosigned assembly.
type cosignedPrimarySignTarget struct {
	TargetIndex int
	AuthAddress string
	TxnSender   string
	LsigArgs    map[string]string
	AppCallInfo *AppCallInfo
}

// cosignerRequestOptions configures the cosigner component request of a
// prepared cosigned group: where the cosigner is, the frozen group it signs
// over, and the app call description of every original position.
type cosignerRequestOptions struct {
	CosignerClient       *SignerClient
	CosignerResolver     CosignedCosignerResolver
	CosignerComponentKey string
	GroupBytesHex        []string
	AppCallInfo          map[int]*AppCallInfo
	DummyPositions       []int
}

// CosignedSignResult contains the final assembled group and intermediate
// component-sign responses for audit and UI correlation.
type CosignedSignResult struct {
	SignedGroup                []string
	CosignerComponentResponses []*ComponentResponse
	PrimarySignResponse        *GroupSignResponse
	BoundedComponentResponse   *ComponentResponse
	BoundedAssemblyResponse    *AssemblyResponse
	// PlanMutations is the plan's mutation report, checked against the
	// prepared group: what the signer added to it (fees, group ID, dummies).
	// Nil when it changed nothing.
	PlanMutations *MutationReport
}

// PreparedCosignedGroupOptions configures SignPreparedCosignedGroup.
type PreparedCosignedGroupOptions struct {
	UserClient           *SignerClient
	CosignerClient       *SignerClient
	CosignerResolver     CosignedCosignerResolver
	CosignerComponentKey string
	PreparedGroup        PreparedGroup
	AssemblyRequestID    string
}

type cosignedComponentSignature struct {
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
// expected at this position, and that the signed bytes are themselves
// canonical, with nothing after the signed transaction. A signer must return
// a signature over the transaction we asked it to sign, not a substituted one.
func signedTxnMatchesCanonical(label string, index int, signedHex, canonicalHex string) error {
	canonical, err := hex.DecodeString(canonicalHex)
	if err != nil {
		return fmt.Errorf("%s %d: canonical bytes invalid hex: %w", label, index, err)
	}
	signedBytes, err := hex.DecodeString(signedHex)
	if err != nil {
		return fmt.Errorf("%s %d: invalid hex: %w", label, index, err)
	}
	stxn, err := decodeCanonicalSignedTxn(signedBytes)
	if err != nil {
		return fmt.Errorf("%s %d: %w", label, index, err)
	}
	if reencoded := encodeTxn(stxn.Txn); !bytes.Equal(reencoded, canonical) {
		return fmt.Errorf("%s %d does not match the submitted canonical bytes", label, index)
	}
	return nil
}

// SignPreparedCosignedGroup canonicalizes a prepared group locally, classifies
// cosigned and primary slots, then signs and assembles it through component
// signing endpoints. The signer /plan endpoint owns canonical group sizing and
// fee mutation before component signatures are collected.
func SignPreparedCosignedGroup(opts PreparedCosignedGroupOptions) (*CosignedSignResult, error) {
	return SignPreparedCosignedGroupWithContext(context.Background(), opts)
}

// SignPreparedCosignedGroupWithContext is the context-aware form of
// SignPreparedCosignedGroup.
func SignPreparedCosignedGroupWithContext(ctx context.Context, opts PreparedCosignedGroupOptions) (*CosignedSignResult, error) {
	return signPreparedCosignedGroup(ctx, opts)
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
		case key.BoundedAuthorization.Rekey == "refused":
			return nil, fmt.Errorf("the account refuses rekeys")
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

func encodeCosignedLsigArgs(args LsigArgs) map[string]string {
	if len(args) == 0 {
		return nil
	}
	out := make(map[string]string, len(args))
	for name, value := range args {
		out[name] = hex.EncodeToString(value)
	}
	return out
}

// signCosignedDummies signs the resource dummies a plan appended, after
// checking each is the canonical dummy for the group.
func signCosignedDummies(firstOriginal types.Transaction, groupID types.Digest, dummies []types.Transaction, startIndex int) ([]AssemblyPassthroughItem, error) {
	if len(dummies) == 0 {
		return nil, nil
	}
	if err := validateCanonicalDummies(firstOriginal, groupID, dummies); err != nil {
		return nil, err
	}
	passthrough := make([]AssemblyPassthroughItem, len(dummies))
	for i, txn := range dummies {
		signedBytes, err := signCanonicalDummy(txn)
		if err != nil {
			return nil, fmt.Errorf("failed to sign dummy transaction %d: %w", i+1, err)
		}
		passthrough[i] = AssemblyPassthroughItem{
			TargetIndex:  startIndex + i,
			SignedTxnHex: hex.EncodeToString(signedBytes),
			Authorization: &CosignedPassthroughAuthorization{
				LogicSigResources: cosignedDummyLogicSigResources(),
			},
		}
	}
	return passthrough, nil
}

func requestCosignerComponentSignatures(ctx context.Context, opts cosignerRequestOptions, targets []cosignedSignTarget, result *CosignedSignResult) (map[int]cosignedComponentSignature, error) {
	groups := make(map[cosignerSignGroupKey][]int)
	schemes := make(map[int]string, len(targets))
	for _, target := range targets {
		schemes[target.TargetIndex] = target.CosignerComponentKeyType
		client, componentKey, err := resolveCosignedCosigner(ctx, opts, target)
		if err != nil {
			return nil, err
		}
		groups[cosignerSignGroupKey{client: client, componentKey: componentKey}] = append(
			groups[cosignerSignGroupKey{client: client, componentKey: componentKey}],
			target.TargetIndex,
		)
	}

	signatures := make(map[int]cosignedComponentSignature)
	for group, indices := range groups {
		sort.Ints(indices)
		resp, err := group.client.RequestComponentsWithContext(ctx, componentRequestForIndices(opts.GroupBytesHex, indices, opts.DummyPositions, group.componentKey, opts.AppCallInfo))
		if err != nil {
			return nil, err
		}
		result.CosignerComponentResponses = append(result.CosignerComponentResponses, resp)
		// RequestComponents has checked the response covers exactly these
		// targets, as cosigner components. Each signature must also be in the
		// scheme the account names for its cosigner.
		for _, component := range resp.Components {
			if want := schemes[component.TargetIndex]; want != "" && component.SignatureScheme != want {
				return nil, fmt.Errorf("cosigner signature for target %d used scheme %q, want %q", component.TargetIndex, component.SignatureScheme, want)
			}
			signatures[component.TargetIndex] = cosignedComponentSignature{
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

func resolveCosignedCosigner(ctx context.Context, opts cosignerRequestOptions, target cosignedSignTarget) (*SignerClient, string, error) {
	if opts.CosignerResolver != nil {
		return opts.CosignerResolver.ResolveCosigner(ctx, target.CosignerPublicKeyHex, target.CosignerComponentKeyType)
	}
	if opts.CosignerClient == nil {
		return nil, "", fmt.Errorf("cosigner client or resolver is required")
	}
	return opts.CosignerClient, opts.CosignerComponentKey, nil
}

type primaryCosignedPassthrough struct {
	response    *GroupSignResponse
	passthrough []AssemblyPassthroughItem
}
