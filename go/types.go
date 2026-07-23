// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/json"
	"fmt"
)

const maxSignRequestIDLength = 128
const maxComponentGroupSize = 16

const (
	ComponentSignRoleUser   ComponentSignRole = "user"
	ComponentSignRoleSentry ComponentSignRole = "sentry"

	KeyTypeWitnessFalcon1024           = "aplane.witness-falcon1024.v1"
	KeyTypeGuardedFalcon1024Sentry1024 = "aplane.falcon1024-sentry1024.v1"
)

// The signer HTTP DTOs and validation semantics in this file intentionally
// mirror contracts/signerapi fixtures and server pkg/signerapi/types.go. Keep JSON
// fields, request-mode validation, and response field meanings in sync without
// adding a dependency from the standalone SDK module back to the main module.

// SignRequest is the request payload for signer signing.
// Three modes are supported (mutually exclusive):
//   - Sign mode: auth_address + txn_bytes_hex
//   - Passthrough mode: signed_txn_hex
//   - Foreign mode: txn_bytes_hex without auth_address
type SignRequest struct {
	AuthAddress  string            `json:"auth_address,omitempty"`
	TxnSender    string            `json:"txn_sender,omitempty"` // Advisory display hint; signer authority comes from txn bytes
	TxnBytesHex  string            `json:"txn_bytes_hex,omitempty"`
	LsigArgs     map[string]string `json:"lsig_args,omitempty"`
	LsigSize     int               `json:"lsig_size,omitempty"`
	AppCallInfo  *AppCallInfo      `json:"app_call_info,omitempty"`
	SignedTxnHex string            `json:"signed_txn_hex,omitempty"`
}

// AppCallInfo carries optional high-level app-call metadata.
type AppCallInfo struct {
	Mode   string `json:"mode,omitempty"`
	Method string `json:"method,omitempty"`
}

// SignResponse is the legacy single-transaction response shape.
//
// The /sign endpoint returns GroupSignResponse. This type is retained for
// source compatibility with older client code.
type SignResponse struct {
	Approved        bool     `json:"approved"`
	Signature       string   `json:"signature,omitempty"`
	LsigBytecode    string   `json:"lsig_bytecode,omitempty"`
	LsigArgsOrdered []string `json:"lsig_args_ordered,omitempty"`
	SignedTxn       string   `json:"signed_txn,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// GroupSignRequest is the request payload for the /sign endpoint.
type GroupSignRequest struct {
	RequestID string        `json:"request_id,omitempty"`
	Requests  []SignRequest `json:"requests"`
}

// ComponentSignRole is the role-specific component signature requested from
// POST /sign/component.
type ComponentSignRole string

// ComponentSignRequest is the request payload for POST /sign/component.
type ComponentSignRequest struct {
	RequestID     string            `json:"request_id,omitempty"`
	Role          ComponentSignRole `json:"role"`
	ComponentKey  string            `json:"component_key,omitempty"`
	GroupBytesHex []string          `json:"group_bytes_hex"`
	TargetIndices []int             `json:"target_indices"`
}

// ComponentSignature carries one raw role-separated component signature.
type ComponentSignature struct {
	TargetIndex     int    `json:"target_index"`
	Signature       string `json:"signature"`
	SignatureScheme string `json:"signature_scheme"`
}

// ComponentSignResponse is the response payload from POST /sign/component.
type ComponentSignResponse struct {
	RequestID    string               `json:"request_id"`
	ComponentKey string               `json:"component_key,omitempty"`
	Signatures   []ComponentSignature `json:"signatures"`
}

// GuardedAssemblyRequest is the request payload for POST /sign/assemble.
type GuardedAssemblyRequest struct {
	RequestID     string                   `json:"request_id,omitempty"`
	GroupBytesHex []string                 `json:"group_bytes_hex"`
	Targets       []GuardedAssemblyTarget  `json:"targets,omitempty"`
	Passthrough   []GuardedPassthroughItem `json:"passthrough,omitempty"`
}

// GuardedAssemblyTarget carries one guarded-account group position plus its
// user and sentry component signatures.
type GuardedAssemblyTarget struct {
	TargetIndex           int      `json:"target_index"`
	GuardedAccount        string   `json:"guarded_account"`
	UserSignature         string   `json:"user_signature"`
	UserSourceRequestID   string   `json:"user_source_request_id,omitempty"`
	SentrySignature       string   `json:"sentry_signature"`
	SentrySourceRequestID string   `json:"sentry_source_request_id,omitempty"`
	RuntimeArgs           []string `json:"runtime_args,omitempty"`
}

// GuardedPassthroughItem carries an already-signed group position to preserve
// unchanged during guarded assembly.
type GuardedPassthroughItem struct {
	TargetIndex  int    `json:"target_index"`
	SignedTxnHex string `json:"signed_txn_hex"`
}

// GuardedAssemblyResponse is the response payload from POST /sign/assemble.
type GuardedAssemblyResponse struct {
	RequestID   string   `json:"request_id"`
	SignedGroup []string `json:"signed_group"`
}

// CancelSignRequest is the request payload for /sign/cancel.
type CancelSignRequest struct {
	RequestID string `json:"request_id"`
}

// CancelSignResponse is the response payload for /sign/cancel.
type CancelSignResponse struct {
	Success bool            `json:"success"`
	State   SignCancelState `json:"state,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// RequestMode describes the mutually exclusive mode selected by a SignRequest.
type RequestMode string

// SignCancelState describes the result of a /sign/cancel lifecycle transition.
type SignCancelState string

const (
	RequestModeSign        RequestMode = "sign"
	RequestModePassthrough RequestMode = "passthrough"
	RequestModeForeign     RequestMode = "foreign"

	SignCancelStateCanceled SignCancelState = "canceled"
	SignCancelStateNotFound SignCancelState = "not_found"
)

// Mode returns the request mode selected by this SignRequest.
func (r SignRequest) Mode() (RequestMode, error) {
	hasPassthrough := r.SignedTxnHex != ""
	hasTxnBytes := r.TxnBytesHex != ""
	hasAuthAddr := r.AuthAddress != ""

	if hasPassthrough && (hasTxnBytes || hasAuthAddr) {
		return "", fmt.Errorf("cannot specify both sign fields (auth_address/txn_bytes_hex) and passthrough field (signed_txn_hex)")
	}
	if hasPassthrough {
		return RequestModePassthrough, nil
	}
	if hasTxnBytes && hasAuthAddr {
		return RequestModeSign, nil
	}
	if hasTxnBytes && !hasAuthAddr {
		return RequestModeForeign, nil
	}
	if hasAuthAddr && !hasTxnBytes {
		return "", fmt.Errorf("txn_bytes_hex is required for sign mode")
	}
	return "", fmt.Errorf("must specify either sign fields (auth_address + txn_bytes_hex), foreign fields (txn_bytes_hex), or passthrough field (signed_txn_hex)")
}

// Validate checks that the request uses exactly one supported request mode.
func (r SignRequest) Validate() error {
	_, err := r.Mode()
	return err
}

// Validate checks that all contained requests use a supported request mode.
func (r GroupSignRequest) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if len(r.Requests) == 0 {
		return fmt.Errorf("requests array is empty")
	}

	signCount := 0
	passthroughCount := 0
	foreignCount := 0
	for i, req := range r.Requests {
		mode, err := req.Mode()
		if err != nil {
			return fmt.Errorf("transaction %d: %w", i+1, err)
		}
		switch mode {
		case RequestModeSign:
			signCount++
		case RequestModePassthrough:
			passthroughCount++
		case RequestModeForeign:
			foreignCount++
		}
	}

	if passthroughCount > 0 && foreignCount > 0 {
		return fmt.Errorf("cannot mix passthrough and foreign transactions: passthrough requires pre-grouped, foreign requires server-computed group ID")
	}
	if signCount == 0 && foreignCount > 0 {
		return fmt.Errorf("no signable transactions: all entries are foreign. Build and submit this group locally instead of using apsigner")
	}
	return nil
}

// Validate checks the component-sign request shape.
func (r ComponentSignRequest) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	switch r.Role {
	case ComponentSignRoleUser:
		if r.ComponentKey == "" {
			return fmt.Errorf("component_key is required for user role")
		}
	case ComponentSignRoleSentry:
	default:
		return fmt.Errorf("role must be %q or %q", ComponentSignRoleUser, ComponentSignRoleSentry)
	}
	if err := validateComponentGroupBytes(r.GroupBytesHex); err != nil {
		return err
	}
	return validateComponentTargetIndices(r.TargetIndices, len(r.GroupBytesHex))
}

// Validate checks the component-sign response shape.
func (r ComponentSignResponse) Validate() error {
	if r.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if len(r.Signatures) == 0 {
		return fmt.Errorf("signatures array is empty")
	}
	seen := make(map[int]struct{}, len(r.Signatures))
	for i, sig := range r.Signatures {
		if sig.TargetIndex < 0 {
			return fmt.Errorf("signature %d: target_index must be non-negative", i+1)
		}
		if _, ok := seen[sig.TargetIndex]; ok {
			return fmt.Errorf("signature %d: duplicate target_index %d", i+1, sig.TargetIndex)
		}
		seen[sig.TargetIndex] = struct{}{}
		if sig.Signature == "" {
			return fmt.Errorf("signature %d: signature is required", i+1)
		}
		if sig.SignatureScheme == "" {
			return fmt.Errorf("signature %d: signature_scheme is required", i+1)
		}
	}
	return nil
}

// Validate checks the guarded assembly request shape.
func (r GuardedAssemblyRequest) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if err := validateComponentGroupBytes(r.GroupBytesHex); err != nil {
		return err
	}
	if len(r.Targets) == 0 && len(r.Passthrough) == 0 {
		return fmt.Errorf("targets or passthrough is required")
	}

	covered := make([]bool, len(r.GroupBytesHex))
	for i, target := range r.Targets {
		if err := validateAssemblyIndex(target.TargetIndex, len(r.GroupBytesHex), covered); err != nil {
			return fmt.Errorf("target %d: %w", i+1, err)
		}
		if target.GuardedAccount == "" {
			return fmt.Errorf("target %d: guarded_account is required", i+1)
		}
		if target.UserSignature == "" {
			return fmt.Errorf("target %d: user_signature is required", i+1)
		}
		if target.SentrySignature == "" {
			return fmt.Errorf("target %d: sentry_signature is required", i+1)
		}
		if err := validateSignRequestID(target.UserSourceRequestID); err != nil {
			return fmt.Errorf("target %d: user_source_request_id: %w", i+1, err)
		}
		if err := validateSignRequestID(target.SentrySourceRequestID); err != nil {
			return fmt.Errorf("target %d: sentry_source_request_id: %w", i+1, err)
		}
	}
	for i, passthrough := range r.Passthrough {
		if err := validateAssemblyIndex(passthrough.TargetIndex, len(r.GroupBytesHex), covered); err != nil {
			return fmt.Errorf("passthrough %d: %w", i+1, err)
		}
		if passthrough.SignedTxnHex == "" {
			return fmt.Errorf("passthrough %d: signed_txn_hex is required", i+1)
		}
	}
	for i, ok := range covered {
		if !ok {
			return fmt.Errorf("group position %d is not covered by targets or passthrough", i)
		}
	}
	return nil
}

// Validate checks the guarded assembly response shape.
func (r GuardedAssemblyResponse) Validate() error {
	if r.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if len(r.SignedGroup) == 0 {
		return fmt.Errorf("signed_group is empty")
	}
	for i, signed := range r.SignedGroup {
		if signed == "" {
			return fmt.Errorf("signed_group %d is empty", i)
		}
	}
	return nil
}

// Validate checks that the cancel request names a concrete sign request.
func (r CancelSignRequest) Validate() error {
	if r.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	return validateSignRequestID(r.RequestID)
}

func validateSignRequestID(id string) error {
	if id == "" {
		return nil
	}
	if len(id) > maxSignRequestIDLength {
		return fmt.Errorf("request_id is too long")
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		if (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == ':' {
			continue
		}
		return fmt.Errorf("request_id contains invalid character %q", ch)
	}
	return nil
}

func validateComponentGroupBytes(items []string) error {
	if len(items) == 0 {
		return fmt.Errorf("group_bytes_hex is empty")
	}
	if len(items) > maxComponentGroupSize {
		return fmt.Errorf("group_bytes_hex length %d exceeds max %d", len(items), maxComponentGroupSize)
	}
	for i, item := range items {
		if item == "" {
			return fmt.Errorf("group_bytes_hex %d is empty", i)
		}
	}
	return nil
}

func validateComponentTargetIndices(indices []int, groupLen int) error {
	if len(indices) == 0 {
		return fmt.Errorf("target_indices is empty")
	}
	seen := make(map[int]struct{}, len(indices))
	for _, index := range indices {
		if index < 0 || index >= groupLen {
			return fmt.Errorf("target_indices %d out of range", index)
		}
		if _, ok := seen[index]; ok {
			return fmt.Errorf("target_indices contains duplicate %d", index)
		}
		seen[index] = struct{}{}
	}
	return nil
}

func validateAssemblyIndex(index, groupLen int, covered []bool) error {
	if index < 0 || index >= groupLen {
		return fmt.Errorf("target_index %d out of range", index)
	}
	if covered[index] {
		return fmt.Errorf("duplicate target_index %d", index)
	}
	covered[index] = true
	return nil
}

// MutationReport describes modifications made by the server during signing.
// This provides observability for clients to understand what changed.
type MutationReport struct {
	DummiesAdded     int    `json:"dummies_added,omitempty"`     // Number of dummy transactions added for LSig budget
	GroupIDChanged   bool   `json:"group_id_changed,omitempty"`  // True if group ID was computed/recomputed
	FeesModified     []int  `json:"fees_modified,omitempty"`     // Indices of transactions with modified fees (0-based)
	TotalFeesDelta   int    `json:"total_fees_delta,omitempty"`  // Total fee increase in microAlgos (for dummy fees)
	OriginalCount    int    `json:"original_count,omitempty"`    // Number of transactions in original request
	FinalCount       int    `json:"final_count,omitempty"`       // Number of transactions in signed response
	PassthroughCount int    `json:"passthrough_count,omitempty"` // Number of pre-signed transactions included as-is
	ForeignCount     int    `json:"foreign_count,omitempty"`     // Number of foreign transactions (not signed by this signer)
	Reason           string `json:"reason,omitempty"`            // Human-readable reason (e.g., "lsig_budget", "passthrough", "foreign")
}

// GroupSignResponse is the response from the /sign endpoint.
type GroupSignResponse struct {
	Signed    []string        `json:"signed,omitempty"`    // Array of signed transactions (hex-encoded msgpack)
	Mutations *MutationReport `json:"mutations,omitempty"` // Modifications made by server (nil if none)
	Error     string          `json:"error,omitempty"`
}

// ErrorResponse is the standard signer HTTP error body for non-2xx responses.
// Code carries a stable machine-readable classification (see error code
// constants in errors.go); branch on Code, never on Error message text. Code
// is empty when the signer predates wire error codes.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// PlanGroupResponse is the response from the /plan endpoint.
// Returns the planned group (unsigned transactions with dummies, adjusted fees,
// group IDs) and a mutation report. No keys are touched, no approval flow is
// triggered.
type PlanGroupResponse struct {
	Transactions []string        `json:"transactions,omitempty"` // TX-prefixed hex-encoded unsigned txns (final group)
	Mutations    *MutationReport `json:"mutations,omitempty"`    // Modifications that would be made by server
	Error        string          `json:"error,omitempty"`
}

// GroupPlanResponse is kept as a compatibility alias for callers using the
// older response name.
type GroupPlanResponse = PlanGroupResponse

// ProtocolVersion identifies a signer wire-protocol version.
type ProtocolVersion struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

// HealthResponse is the response from the /health endpoint.
type HealthResponse struct {
	Status          string          `json:"status"`
	Service         string          `json:"service"`
	ProtocolVersion ProtocolVersion `json:"protocol_version"`
	BuildVersion    string          `json:"build_version"`
	SignerLocked    bool            `json:"signer_locked"`
	ReadyForSigning bool            `json:"ready_for_signing"`
	SSHEnabled      bool            `json:"ssh_enabled"`
	IPCEnabled      bool            `json:"ipc_enabled"`
}

// StatusResponse is the response from the /status endpoint.
type StatusResponse struct {
	IdentityID          string          `json:"identity_id"`
	NodeRole            string          `json:"node_role,omitempty"`
	ProtocolVersion     ProtocolVersion `json:"protocol_version"`
	BuildVersion        string          `json:"build_version"`
	State               string          `json:"state"`
	SignerLocked        bool            `json:"signer_locked"`
	ReadyForSigning     bool            `json:"ready_for_signing"`
	KeyCount            int             `json:"key_count"`
	KeysetRevision      uint64          `json:"keyset_revision"`
	ApprovalWaitSeconds int64           `json:"approval_wait_seconds,omitempty"`
}

// RuntimeArg describes a runtime argument for generic LogicSig keys.
type RuntimeArg struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	ByteLength  int    `json:"byte_length,omitempty"`
	MaxSize     int    `json:"max_size,omitempty"`
}

// RuntimeArgInfo is kept as a compatibility alias for callers using the
// older runtime-argument name.
type RuntimeArgInfo = RuntimeArg

// SigningArg describes a key-file-owned signing argument returned from /keys.
// It has the same shape as RuntimeArg but a different authority.
type SigningArg = RuntimeArg

// InputMode describes an alternate UI input mode for a creation parameter.
type InputMode struct {
	Name       string `json:"name"`
	Label      string `json:"label,omitempty"`
	Transform  string `json:"transform,omitempty"`
	ByteLength int    `json:"byte_length,omitempty"`
	InputType  string `json:"input_type,omitempty"`
}

// InputModeInfo is kept as a compatibility alias for callers using the server
// DTO name.
type InputModeInfo = InputMode

// CreationParam describes a parameter for key generation.
type CreationParam struct {
	Name        string      `json:"name"`
	Label       string      `json:"label"`
	Description string      `json:"description,omitempty"`
	Type        string      `json:"type"`
	Required    bool        `json:"required"`
	MaxLength   int         `json:"max_length,omitempty"`
	InputModes  []InputMode `json:"input_modes,omitempty"`
	MinItems    int         `json:"min_items,omitempty"`
	MaxItems    int         `json:"max_items,omitempty"`
	Options     []string    `json:"options,omitempty"`
	Min         *uint64     `json:"min,omitempty"`
	Max         *uint64     `json:"max,omitempty"`
	Example     string      `json:"example,omitempty"`
	Placeholder string      `json:"placeholder,omitempty"`
	Default     string      `json:"default,omitempty"`
}

// KeyTypeInfo describes an available key type on the signer.
type KeyTypeInfo struct {
	KeyType                string                    `json:"key_type"`
	Family                 string                    `json:"family"`
	DisplayName            string                    `json:"display_name"`
	Description            string                    `json:"description"`
	RequiresLogicSig       bool                      `json:"requires_logicsig"`
	MnemonicWordCount      int                       `json:"mnemonic_word_count"`
	MnemonicImport         bool                      `json:"mnemonic_import"`
	MnemonicScheme         string                    `json:"mnemonic_scheme"`
	SigningFlow            string                    `json:"signing_flow,omitempty"`
	SentryComponentKeyType string                    `json:"sentry_component_key_type,omitempty"`
	BoundedAuthorization   *BoundedAuthorizationInfo `json:"bounded_authorization,omitempty"`
	CreationParams         []CreationParam           `json:"creation_params"`
	RuntimeArgs            []RuntimeArg              `json:"runtime_args"`
}

// SigningFlowSentry1 names the sentry co-signed component signing
// choreography (one user plus one sentry component signature per target,
// assembled via /sign/assemble). Signer inventory labels guarded keys with
// this flow; clients route on the label and must fail fast on flow labels
// they do not implement. An empty signing_flow means the ordinary /sign path.
const SigningFlowSentry1 = "sentry1"

// SigningFlowBounded1 names the transaction-aware LogicSig choreography.
const SigningFlowBounded1 = "bounded1"

// SigningFlowBoundedSentry1 names the combined bounded spend choreography:
// user-signer bounded base release, sentry component signing, and source-bound
// bounded assembly.
const SigningFlowBoundedSentry1 = "bounded-sentry1"

type BoundedSignatureArgLayout struct {
	Count    int   `json:"count"`
	MaxSizes []int `json:"max_sizes"`
}

type BoundedAdminOperationInfo struct {
	Kind          string `json:"kind"`
	Authorization string `json:"authorization"`
	PolicyGate    string `json:"policy_gate"`
}

type BoundedDerivedArgInfo struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Parameter string `json:"parameter"`
	MaxSize   int    `json:"max_size"`
}

type BoundedArgumentPathMask struct {
	Spend         string `json:"spend"`
	SpendingRekey string `json:"spending_rekey"`
	AdminRekey    string `json:"admin_rekey"`
}

type BoundedArgumentSlotInfo struct {
	Index   int                     `json:"index"`
	Name    string                  `json:"name"`
	Source  string                  `json:"source"`
	MaxSize int                     `json:"max_size"`
	Paths   BoundedArgumentPathMask `json:"paths"`
}

// BoundedSentryAuthorizationInfo is the public non-secret projection of the
// optional sentry authority embedded in a bounded account.
type BoundedSentryAuthorizationInfo struct {
	Contract         string   `json:"contract"`
	ComponentKeyType string   `json:"component_key_type"`
	PublicKeyHex     string   `json:"public_key,omitempty"`
	ComponentKeyID   string   `json:"component_key_id,omitempty"`
	SignatureMaxSize int      `json:"signature_max_size"`
	RequiredOn       []string `json:"required_on"`
}

type BoundedAuthorizationInfo struct {
	Contract                string                          `json:"contract"`
	BaseSignatureArgLayout  BoundedSignatureArgLayout       `json:"base_signature_arg_layout"`
	SpendEffects            []string                        `json:"spend_effects"`
	MaxFee                  uint64                          `json:"max_fee"`
	AdminOperations         []BoundedAdminOperationInfo     `json:"admin_operations"`
	Sentry                  *BoundedSentryAuthorizationInfo `json:"sentry,omitempty"`
	RuntimeArgs             []RuntimeArg                    `json:"runtime_args"`
	DerivedArgs             []BoundedDerivedArgInfo         `json:"derived_args"`
	ArgumentLayout          []BoundedArgumentSlotInfo       `json:"argument_layout"`
	Layer3Policy            string                          `json:"layer3_policy"`
	AdminKeyID              string                          `json:"admin_key_id,omitempty"`
	ProgramBindingHex       string                          `json:"program_binding,omitempty"`
	PostSigningLogicSigSize int                             `json:"post_signing_lsig_size,omitempty"` // Admin-inclusive bounded size
}

// KeyInfo represents a key returned from the /keys endpoint.
type KeyInfo struct {
	Address                  string                    `json:"address"`
	PublicKeyHex             string                    `json:"public_key_hex"`
	KeyType                  string                    `json:"key_type"`
	SigningFlow              string                    `json:"signing_flow,omitempty"`
	SentryComponentKeyType   string                    `json:"sentry_component_key_type,omitempty"`
	LsigSize                 int                       `json:"lsig_size,omitempty"` // Spend-path size for bounded1
	IsGenericLsig            bool                      `json:"is_generic_lsig,omitempty"`
	IsWitnessKey             bool                      `json:"is_witness_key,omitempty"`
	BoundedAuthorization     *BoundedAuthorizationInfo `json:"bounded_authorization,omitempty"`
	IsSpendingAccount        *bool                     `json:"is_spending_account,omitempty"`
	SigningArgs              []SigningArg              `json:"signing_args,omitempty"`
	Parameters               map[string]string         `json:"parameters,omitempty"`
	TemplateProvenanceStatus string                    `json:"template_provenance_status,omitempty"`
	TemplateProvenanceNote   string                    `json:"template_provenance_note,omitempty"`
	TemplateStatus           string                    `json:"template_status,omitempty"`  // Legacy alias for TemplateProvenanceStatus
	TemplateWarning          string                    `json:"template_warning,omitempty"` // Legacy alias for TemplateProvenanceNote
}

// KeysResponse is the response from the /keys endpoint.
type KeysResponse struct {
	Count int       `json:"count"`
	Keys  []KeyInfo `json:"keys"`
}

// KeysResult wraps /keys with local locked-signer state. Locked is derived from
// a 403 locked-signer response and is not part of the /keys JSON payload.
type KeysResult struct {
	KeysResponse
	Locked bool
}

// UnmarshalJSON accepts both current template_provenance_* fields and legacy
// template_status/template_warning aliases.
func (k *KeyInfo) UnmarshalJSON(data []byte) error {
	type keyInfoAlias KeyInfo
	var aux keyInfoAlias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*k = KeyInfo(aux)
	normalizeKeyInfoTemplateAliases(k)
	return nil
}

func normalizeKeyInfoTemplateAliases(k *KeyInfo) {
	if k.TemplateProvenanceStatus == "" {
		k.TemplateProvenanceStatus = k.TemplateStatus
	}
	if k.TemplateStatus == "" {
		k.TemplateStatus = k.TemplateProvenanceStatus
	}
	if k.TemplateProvenanceNote == "" {
		k.TemplateProvenanceNote = k.TemplateWarning
	}
	if k.TemplateWarning == "" {
		k.TemplateWarning = k.TemplateProvenanceNote
	}
}

// KeyTypesResponse is the response from the /keytypes endpoint.
type KeyTypesResponse struct {
	KeyTypes []KeyTypeInfo `json:"key_types"`
}

// GenerateResult is the response from key generation.
type GenerateResult struct {
	Address           string            `json:"address,omitempty"`
	PublicKeyHex      string            `json:"public_key_hex,omitempty"`
	KeyType           string            `json:"key_type,omitempty"`
	IsWitnessKey      bool              `json:"is_witness_key,omitempty"`
	IsSpendingAccount *bool             `json:"is_spending_account,omitempty"`
	Parameters        map[string]string `json:"parameters,omitempty"`
	Error             string            `json:"error,omitempty"`
}

// SentryReferenceCandidate is public sentry metadata synced into a signer
// identity's generation reference catalog.
type SentryReferenceCandidate struct {
	EndpointAlias string `json:"endpoint_alias"`
	ComponentKey  string `json:"component_key"`
	KeyType       string `json:"key_type"`
	PublicKeyHex  string `json:"public_key_hex"`
	LastSeenAt    string `json:"last_seen_at,omitempty"`
}

// AdminSyncSentryReferencesRequest is the request payload for
// POST /admin/sentries/sync.
type AdminSyncSentryReferencesRequest struct {
	Candidates []SentryReferenceCandidate `json:"candidates"`
}

// SyncedSentryReferenceInfo describes a signer-local reference after sync.
type SyncedSentryReferenceInfo struct {
	Name          string `json:"name"`
	Source        string `json:"source"`
	EndpointAlias string `json:"endpoint_alias,omitempty"`
	ComponentKey  string `json:"component_key"`
	KeyType       string `json:"key_type"`
	PublicKeyHex  string `json:"public_key_hex"`
	LastSeenAt    string `json:"last_seen_at,omitempty"`
	SyncedAt      string `json:"synced_at,omitempty"`
}

// AdminSyncSentryReferencesResponse is the response payload for
// POST /admin/sentries/sync.
type AdminSyncSentryReferencesResponse struct {
	Added   int                         `json:"added"`
	Updated int                         `json:"updated"`
	Removed int                         `json:"removed"`
	Count   int                         `json:"count"`
	Records []SyncedSentryReferenceInfo `json:"records,omitempty"`
	Error   string                      `json:"error,omitempty"`
}

// generateRequest is the request payload for key generation.
type generateRequest struct {
	KeyType    string            `json:"key_type"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// keyTypesResponse is the internal response from the /keytypes endpoint.
type keyTypesResponse = KeyTypesResponse

// keysResponse is the internal response from the /keys endpoint.
type keysResponse = KeysResponse

// groupSignRequest is the internal request payload for the /sign endpoint.
type groupSignRequest = GroupSignRequest

// LsigArgs is a map of argument name to value for generic LogicSigs.
type LsigArgs map[string][]byte

// LsigArgsMap maps addresses to their LogicSig arguments.
type LsigArgsMap map[string]LsigArgs

// SSHConfig contains SSH tunnel configuration.
type SSHConfig struct {
	Host            string `yaml:"host"`
	Port            int    `yaml:"port"`
	IdentityFile    string `yaml:"identity_file"`
	KnownHostsPath  string `yaml:"known_hosts_path"`
	TrustOnFirstUse bool   `yaml:"trust_on_first_use"`
}

// AlgodNetworkConfig contains algod settings for one network.
type AlgodNetworkConfig struct {
	Server string `yaml:"server"`
	Token  string `yaml:"token"`
}

// AlgodConfig maps network names to algod settings.
type AlgodConfig map[string]*AlgodNetworkConfig

// NetworkConfig contains grouped settings for one network context token.
type NetworkConfig struct {
	Algod *AlgodNetworkConfig `yaml:"algod"`
}

// NetworkConfigs maps network names to grouped settings.
type NetworkConfigs map[string]*NetworkConfig

// EndpointConfig contains signer endpoint settings from config.yaml.
type EndpointConfig struct {
	SignerPort int        `yaml:"signer_port"`
	SSH        *SSHConfig `yaml:"ssh,omitempty"`
}

// Config contains client configuration loaded from config.yaml.
type Config struct {
	Network         string         `yaml:"network"`
	NetworksAllowed []string       `yaml:"networks_allowed"`
	Endpoint        EndpointConfig `yaml:"endpoint"`
	SignerPort      int            `yaml:"-"`
	Theme           string         `yaml:"theme"`
	SSH             *SSHConfig     `yaml:"-"`
	Networks        NetworkConfigs `yaml:"networks"`
	Algod           AlgodConfig    `yaml:"algod"`
}

// SSHConnectOptions contains options for SSH tunnel connections.
type SSHConnectOptions struct {
	SSHPort         int
	SignerPort      int
	Timeout         int
	KnownHostsPath  string
	TrustOnFirstUse bool
}

// FromEnvOptions contains options for FromEnv().
type FromEnvOptions struct {
	DataDir string
	Timeout int
}

// SignOptions contains options for signing with passthrough and foreign support.
type SignOptions struct {
	Passthrough map[int]string
	LsigSizes   map[int]int
}
