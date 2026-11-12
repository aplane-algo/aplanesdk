// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"fmt"
	"time"
)

const maxSignRequestIDLength = 128
const maxComponentGroupSize = 16

const (
	AuthorizationKindEd25519  = "ed25519"
	AuthorizationKindNativePQ = "native_pq"
	AuthorizationKindLogicSig = "logic_sig"

	KeyTypeWitnessFalcon1024 = "aplane.witness-falcon1024.v1"
)

// LogicSigResourceUsage is one selected authorization path's independent
// program, argument, and opcode demand.
type LogicSigResourceUsage struct {
	ProgramBytes  uint64 `json:"program_bytes"`
	ArgumentBytes uint64 `json:"argument_bytes"`
	MaxOpcodeCost uint64 `json:"max_opcode_cost"`
}

// LogicSigResourceProfile publishes either a default path or the three closed
// bounded paths for one stored LogicSig program. A rekey on an account with a
// rekey-to list takes ListedRekey.
type LogicSigResourceProfile struct {
	Default       *LogicSigResourceUsage `json:"default,omitempty"`
	Spend         *LogicSigResourceUsage `json:"spend,omitempty"`
	SpendingRekey *LogicSigResourceUsage `json:"spending_rekey,omitempty"`
	ListedRekey   *LogicSigResourceUsage `json:"listed_rekey,omitempty"`
}

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
	AuthAddress   string                 `json:"auth_address,omitempty"`
	TxnSender     string                 `json:"txn_sender,omitempty"` // Advisory display hint; signer authority comes from txn bytes
	TxnBytesHex   string                 `json:"txn_bytes_hex,omitempty"`
	LsigArgs      map[string]string      `json:"lsig_args,omitempty"`
	LsigResources *LogicSigResourceUsage `json:"lsig_resources,omitempty"`
	PQScheme      string                 `json:"pq_scheme,omitempty"`
	AppCallInfo   *AppCallInfo           `json:"app_call_info,omitempty"`
	SignedTxnHex  string                 `json:"signed_txn_hex,omitempty"`
}

// AppCallInfo carries optional high-level app-call metadata.
type AppCallInfo struct {
	Mode   string `json:"mode,omitempty"`
	Method string `json:"method,omitempty"`
}

// GroupSignRequest is the request payload for the /sign endpoint.
type GroupSignRequest struct {
	RequestID string        `json:"request_id,omitempty"`
	Requests  []SignRequest `json:"requests"`
}

type ComponentTargetKind string

const (
	ComponentTargetKindCosigner    ComponentTargetKind = "cosigner"
	ComponentTargetKindBoundedBase ComponentTargetKind = "bounded-base"
)

type ComponentRequest struct {
	RequestID           string                     `json:"request_id,omitempty"`
	GroupBytesHex       []string                   `json:"group_bytes_hex"`
	Targets             []ComponentTarget          `json:"targets"`
	ContextualPositions []ComponentContextPosition `json:"contextual_positions,omitempty"`
	DummyPositions      []ComponentDummyPosition   `json:"dummy_positions,omitempty"`
}

type ComponentTarget struct {
	TargetIndex  int                 `json:"target_index"`
	Kind         ComponentTargetKind `json:"kind"`
	AuthAddress  string              `json:"auth_address,omitempty"`
	ComponentKey string              `json:"component_key,omitempty"`
	LsigArgs     map[string]string   `json:"lsig_args,omitempty"`
	AppCallInfo  *AppCallInfo        `json:"app_call_info,omitempty"`
}

// ComponentContextPosition is an original position a component request doesn't
// sign. With AuthAddress it is one of the signer's own accounts, which the
// signer sizes from its records; LsigArgs carries what a bounded account needs
// to be classified. Without AuthAddress it is another party's position, sized
// from the LsigResources or PQScheme hint.
type ComponentContextPosition struct {
	TargetIndex   int                    `json:"target_index"`
	AuthAddress   string                 `json:"auth_address,omitempty"`
	LsigArgs      map[string]string      `json:"lsig_args,omitempty"`
	LsigResources *LogicSigResourceUsage `json:"lsig_resources,omitempty"`
	PQScheme      string                 `json:"pq_scheme,omitempty"`
	AppCallInfo   *AppCallInfo           `json:"app_call_info,omitempty"`
}

type ComponentDummyPosition struct {
	TargetIndex int `json:"target_index"`
}

type Component struct {
	TargetIndex     int                 `json:"target_index"`
	Kind            ComponentTargetKind `json:"kind"`
	Signature       string              `json:"signature,omitempty"`
	SignatureScheme string              `json:"signature_scheme"`
	AuthAddress     string              `json:"auth_address,omitempty"`
	BaseSignatures  []string            `json:"base_signatures,omitempty"`
	RuntimeArgs     map[string]string   `json:"runtime_args,omitempty"`
	AssemblyReceipt string              `json:"assembly_receipt,omitempty"`
	// Path is the path the signer classified a bounded-base target on: spend,
	// spending_rekey or listed_rekey. A listed rekey takes no cosigner
	// component. It routes the request only: assembly classifies again.
	Path string `json:"path,omitempty"`
}

// Bounded-base component paths, the names argument path masks and resource
// profiles use.
const (
	ComponentPathSpend         = "spend"
	ComponentPathSpendingRekey = "spending_rekey"
	ComponentPathListedRekey   = "listed_rekey"
)

// NeedsCosigner reports whether a bounded-base component's path takes a cosigner
// component. A path this SDK does not name fails validation first.
func (c Component) NeedsCosigner() bool {
	return c.Path != ComponentPathListedRekey
}

type ComponentResponse struct {
	RequestID  string      `json:"request_id"`
	Components []Component `json:"components"`
	// Error, when set, is a refusal carried in a 200 answer. The current
	// signer never sets it; RequestComponents refuses an answer that does.
	Error string `json:"error,omitempty"`
}

type AssemblyTargetKind string

const (
	AssemblyTargetKindBoundedCosigner AssemblyTargetKind = "bounded-cosigner"
)

// AssemblyRequest is the shared request payload for POST /sign/assemble.
type AssemblyRequest struct {
	RequestID     string                    `json:"request_id,omitempty"`
	GroupBytesHex []string                  `json:"group_bytes_hex"`
	Targets       []AssemblyTarget          `json:"targets,omitempty"`
	Passthrough   []AssemblyPassthroughItem `json:"passthrough,omitempty"`
}

type AssemblyTarget struct {
	TargetIndex int                `json:"target_index"`
	Kind        AssemblyTargetKind `json:"kind"`
	AuthAddress string             `json:"auth_address"`

	BaseSignatures      []string          `json:"base_signatures,omitempty"`
	BoundedRuntimeArgs  map[string]string `json:"bounded_runtime_args,omitempty"`
	AssemblyReceipt     string            `json:"assembly_receipt,omitempty"`
	BaseSourceRequestID string            `json:"base_source_request_id,omitempty"`

	// CosignerSignature is required on every bounded-cosigner target except a
	// listed rekey, which takes none.
	CosignerSignature       string `json:"cosigner_signature,omitempty"`
	CosignerSourceRequestID string `json:"cosigner_source_request_id,omitempty"`
}

type AssemblyPassthroughItem struct {
	TargetIndex   int                               `json:"target_index"`
	SignedTxnHex  string                            `json:"signed_txn_hex"`
	Authorization *CosignedPassthroughAuthorization `json:"-"`
}

type AssemblyResponse struct {
	RequestID   string   `json:"request_id"`
	SignedGroup []string `json:"signed_group"`
	// Error, when set, is a refusal carried in a 200 answer. The current
	// signer never sets it; RequestAssemble refuses an answer that does.
	Error string `json:"error,omitempty"`
}

// CosignedPassthroughAuthorization declares the authorization shape used to
// budget an already-signed slot while another slot is signed. An empty value
// explicitly declares ordinary Ed25519 authorization.
type CosignedPassthroughAuthorization struct {
	LogicSigResources *LogicSigResourceUsage
	PQScheme          string
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

// RotatingPrepareRequest is the request payload for /sign/rotating/prepare:
// one unsigned, ungrouped, TX-prefixed transaction from a rotating account.
// PrepareRotating sends it.
type RotatingPrepareRequest struct {
	RequestID   string `json:"request_id,omitempty"`
	Account     string `json:"account"`
	TxnBytesHex string `json:"txn_bytes_hex"`
}

// RotatingPrepareResponse is the exact unsigned group the signer will sign.
type RotatingPrepareResponse struct {
	Account      string          `json:"account"`
	Stage        uint64          `json:"stage"`
	Target       uint64          `json:"target"`
	RekeyTo      string          `json:"rekey_to"`
	Transactions []string        `json:"transactions"`
	Mutations    *MutationReport `json:"mutations,omitempty"`
}

// RotatingSignRequest is the request payload for /sign/rotating/sign.
// AppCallInfo is optional app-call metadata for the approval prompt, as on
// /sign. The signer checks it against the spend's bytes when rendering the
// prompt and does not sign it.
type RotatingSignRequest struct {
	RequestID    string       `json:"request_id,omitempty"`
	Account      string       `json:"account"`
	Transactions []string     `json:"transactions"`
	AppCallInfo  *AppCallInfo `json:"app_call_info,omitempty"`
}

// RotatingSignResponse is the response payload for /sign/rotating/sign.
type RotatingSignResponse struct {
	Signed  []string `json:"signed"`
	Stage   uint64   `json:"stage"`
	Target  uint64   `json:"target"`
	TxID    string   `json:"txid"`
	GroupID string   `json:"group_id"`
}

// RotatingAccountStatus is one rotating account's view from the signer's
// last background pass, carried on /status `rotating[]`. Classification is
// "stage", "held_key", "unknown" or "unobserved".
type RotatingAccountStatus struct {
	Account        string                  `json:"account"`
	Authorizer     string                  `json:"authorizer,omitempty"`
	Round          uint64                  `json:"round,omitempty"`
	Classification string                  `json:"classification"`
	Stage          *uint64                 `json:"stage,omitempty"`
	Preparation    string                  `json:"preparation"`
	CachedEntries  uint64                  `json:"cached_entries"`
	Recovery       *RotatingRecoveryStatus `json:"recovery,omitempty"`
}

// RotatingRecoveryStatus reports a rotating account's stage recovery: the
// active grant, why the last one stopped, and the per-unlock automatic
// allowance. The SDK carries the wire shape only; recovery is an operator
// action.
type RotatingRecoveryStatus struct {
	Active               bool    `json:"active"`
	Kind                 string  `json:"kind,omitempty"`
	GrantID              uint64  `json:"grant_id,omitempty"`
	StagesCharged        uint64  `json:"stages_charged,omitempty"`
	MaxStages            uint64  `json:"max_stages,omitempty"`
	ActiveSeconds        int64   `json:"active_seconds,omitempty"`
	Hint                 *uint64 `json:"hint,omitempty"`
	FoundStage           *uint64 `json:"found_stage,omitempty"`
	Stopped              string  `json:"stopped,omitempty"`
	StoppedKind          string  `json:"stopped_kind,omitempty"`
	StoppedGrantID       uint64  `json:"stopped_grant_id,omitempty"`
	StoppedStage         *uint64 `json:"stopped_stage,omitempty"`
	AllowanceSpent       uint64  `json:"allowance_spent"`
	AllowanceMax         uint64  `json:"allowance_max"`
	SuppressedAuthorizer string  `json:"suppressed_authorizer,omitempty"`
}

// RotatingRecoverRequest is the request payload for
// POST /admin/rotating/recover: an operator's request to start ("start",
// with an optional stage hint, window, stage budget and timeout) or cancel
// ("cancel") a bounded search for a rotating account's live stage.
type RotatingRecoverRequest struct {
	Account        string  `json:"account"`
	Action         string  `json:"action"`
	Stage          *uint64 `json:"stage,omitempty"`
	Window         uint64  `json:"window,omitempty"`
	MaxStages      uint64  `json:"max_stages,omitempty"`
	TimeoutSeconds int64   `json:"timeout_seconds,omitempty"`
}

// RotatingRecoverResponse is the response payload for
// POST /admin/rotating/recover.
type RotatingRecoverResponse struct {
	Account  string                 `json:"account"`
	Action   string                 `json:"action"`
	GrantID  uint64                 `json:"grant_id,omitempty"`
	Recovery RotatingRecoveryStatus `json:"recovery"`
}

// RequestMode describes the mutually exclusive mode selected by a SignRequest.
type RequestMode string

// SignCancelState describes the result of a /sign/cancel lifecycle transition.
type SignCancelState string

const (
	RequestModeSign        RequestMode = "sign"
	RequestModePassthrough RequestMode = "passthrough"
	RequestModeForeign     RequestMode = "foreign"
	PQSchemeFalcon1024                 = "f1"

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
	mode, err := r.Mode()
	if err != nil {
		return err
	}
	if r.PQScheme != "" && mode != RequestModeForeign {
		return fmt.Errorf("pq_scheme is allowed only for foreign transactions")
	}
	if r.PQScheme != "" && r.PQScheme != PQSchemeFalcon1024 {
		return fmt.Errorf("unsupported pq_scheme %q", r.PQScheme)
	}
	if r.LsigResources != nil && mode != RequestModeForeign && mode != RequestModePassthrough {
		return fmt.Errorf("lsig_resources is allowed only for foreign or passthrough transactions")
	}
	if r.PQScheme != "" && r.LsigResources != nil {
		return fmt.Errorf("foreign transaction cannot specify both pq_scheme and lsig_resources")
	}
	if r.LsigResources != nil {
		if err := r.LsigResources.validate(); err != nil {
			return fmt.Errorf("invalid lsig_resources: %w", err)
		}
	}
	return nil
}

func (r LogicSigResourceUsage) validate() error {
	if r.ProgramBytes == 0 || r.ProgramBytes > 16_000 {
		return fmt.Errorf("program_bytes must be between 1 and 16000")
	}
	if r.MaxOpcodeCost == 0 || r.MaxOpcodeCost > 320_000 {
		return fmt.Errorf("max_opcode_cost must be between 1 and 320000")
	}
	return nil
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
		if err := req.Validate(); err != nil {
			return fmt.Errorf("transaction %d: %w", i+1, err)
		}
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
		return fmt.Errorf("cannot mix passthrough and foreign transactions in one request")
	}
	if signCount == 0 && foreignCount > 0 {
		return fmt.Errorf("no signable transactions: all entries are foreign. Build and submit this group locally instead of using apsigner")
	}
	return nil
}

func (r AssemblyRequest) Validate() error {
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
		if target.AuthAddress == "" {
			return fmt.Errorf("target %d: auth_address is required", i+1)
		}
		if target.CosignerSignature == "" && target.CosignerSourceRequestID != "" {
			return fmt.Errorf("target %d: cosigner_source_request_id needs a cosigner_signature", i+1)
		}
		if err := validateSignRequestID(target.CosignerSourceRequestID); err != nil {
			return fmt.Errorf("target %d: cosigner_source_request_id: %w", i+1, err)
		}
		switch target.Kind {
		case AssemblyTargetKindBoundedCosigner:
			if len(target.BaseSignatures) == 0 || target.AssemblyReceipt == "" {
				return fmt.Errorf("target %d: base_signatures and assembly_receipt are required for bounded-cosigner target", i+1)
			}
			if err := validateSignRequestID(target.BaseSourceRequestID); err != nil {
				return fmt.Errorf("target %d: base_source_request_id: %w", i+1, err)
			}
		default:
			return fmt.Errorf("target %d: invalid kind %q", i+1, target.Kind)
		}
	}
	for i, item := range r.Passthrough {
		if err := validateAssemblyIndex(item.TargetIndex, len(r.GroupBytesHex), covered); err != nil {
			return fmt.Errorf("passthrough %d: %w", i+1, err)
		}
		if item.SignedTxnHex == "" {
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

func (r AssemblyResponse) Validate() error {
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
// constants in errors.go); branch on Code, never on Error message text. Every
// apsigner error response sets Code.
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
	Warnings        []string        `json:"warnings,omitempty"`
}

// StatusResponse is the response from the /status endpoint.
type StatusResponse struct {
	NodeRole            string          `json:"node_role,omitempty"`
	ProtocolVersion     ProtocolVersion `json:"protocol_version"`
	BuildVersion        string          `json:"build_version"`
	State               string          `json:"state"`
	SignerLocked        bool            `json:"signer_locked"`
	ReadyForSigning     bool            `json:"ready_for_signing"`
	KeyCount            int             `json:"key_count"`
	KeysetRevision      uint64          `json:"keyset_revision"`
	ApprovalWaitSeconds int64           `json:"approval_wait_seconds,omitempty"`
	Warnings            []string        `json:"warnings,omitempty"`
	// Notes are informational status lines that need no action, such as a
	// rotating account's release still in flight.
	Notes []string `json:"notes,omitempty"`
	// Rotating is each rotating account's view from the signer's last
	// background pass. Absent while locked or without rotating accounts.
	Rotating []RotatingAccountStatus `json:"rotating,omitempty"`
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
	KeyType                  string `json:"key_type"`
	Family                   string `json:"family"`
	DisplayName              string `json:"display_name"`
	Description              string `json:"description"`
	AuthorizationKind        string `json:"authorization_kind,omitempty"`
	RequiresLogicSig         bool   `json:"requires_logicsig"`
	MnemonicWordCount        int    `json:"mnemonic_word_count"`
	MnemonicImport           bool   `json:"mnemonic_import"`
	MnemonicScheme           string `json:"mnemonic_scheme"`
	SigningFlow              string `json:"signing_flow,omitempty"`
	CosignerComponentKeyType string `json:"cosigner_component_key_type,omitempty"`
	// PerKeyContract means each account selects its own contract at generation, so
	// this type has no fixed signing flow or bounded profile. Route by GetKeys.
	PerKeyContract bool `json:"per_key_contract,omitempty"`
	// BoundarySchema names the boundary file grammar a per-key type's requests
	// take ("aplane.boundary.v1"), and is empty for one that takes none, such as
	// a plain host.
	BoundarySchema       string                    `json:"boundary_schema,omitempty"`
	BoundedAuthorization *BoundedAuthorizationInfo `json:"bounded_authorization,omitempty"`
	// ValidRekeyTarget is the type's declaration of whether an aplane key of
	// this type may be the signing authority an account is rekeyed to, its own
	// account included. False when the signer does not report it.
	ValidRekeyTarget bool            `json:"valid_rekey_target"`
	CreationParams   []CreationParam `json:"creation_params"`
	RuntimeArgs      []RuntimeArg    `json:"runtime_args"`
}

// SigningFlowBounded1 names the transaction-aware LogicSig choreography.
const SigningFlowBounded1 = "bounded1"

// SigningFlowCosigned1 names the cosigned account choreography: user-signer base
// release, cosigner component signing, and source-bound assembly. A target may
// be a spend or a rekey. Each base component names the path the signer
// classified; a listed rekey needs no cosigner component, so the SDK asks the
// cosigner for every other target only. It replaces bounded-cosigner1, which
// carried spends only.
const SigningFlowCosigned1 = "cosigned1"

// SigningFlowRotating1 names the rotating account choreography
// (/sign/rotating/prepare then /sign/rotating/sign), in which the signer
// rekeys the account to a fresh stage on every spend. SendPrepared runs it;
// PrepareRotating and SignPreparedRotating are its steps.
const SigningFlowRotating1 = "rotating1"

type BoundedSignatureArgLayout struct {
	Count    int   `json:"count"`
	MaxSizes []int `json:"max_sizes"`
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
	ListedRekey   string `json:"listed_rekey"`
}

// BoundedRekeyListInfo says that a bounded account has a rekey-to list, and
// commits to it. The entries are never published.
type BoundedRekeyListInfo struct {
	Contract string `json:"contract"`
	Depth    int    `json:"depth"`
	RootHex  string `json:"root,omitempty"`
}

type BoundedArgumentSlotInfo struct {
	Index   int                     `json:"index"`
	Name    string                  `json:"name"`
	Source  string                  `json:"source"`
	MaxSize int                     `json:"max_size"`
	Paths   BoundedArgumentPathMask `json:"paths"`
}

// BoundedCosignerAuthorizationInfo is the public non-secret projection of the
// optional cosigner authority embedded in a bounded account.
type BoundedCosignerAuthorizationInfo struct {
	Contract         string   `json:"contract"`
	ComponentKeyType string   `json:"component_key_type"`
	PublicKeyHex     string   `json:"public_key_hex,omitempty"`
	ComponentKeyID   string   `json:"component_key_id,omitempty"`
	SignatureMaxSize int      `json:"signature_max_size"`
	RequiredOn       []string `json:"required_on"`
}

type BoundedAuthorizationInfo struct {
	Contract               string                    `json:"contract"`
	BaseSignatureArgLayout BoundedSignatureArgLayout `json:"base_signature_arg_layout"`
	SpendEffects           []string                  `json:"spend_effects"`
	// MaxFee is a bounded host's fee ceiling. A plain host (contract
	// "plain1") has none, and the field is absent.
	MaxFee *uint64 `json:"max_fee,omitempty"`
	Rekey  string  `json:"rekey"` // "refused" or "spending_key"
	// RekeyList, with Rekey "refused", is "only these": a rekey may go only to
	// an address on the account's rekey-to list.
	RekeyList      *BoundedRekeyListInfo             `json:"rekey_list,omitempty"`
	Cosigner       *BoundedCosignerAuthorizationInfo `json:"cosigner,omitempty"`
	RuntimeArgs    []RuntimeArg                      `json:"runtime_args"`
	DerivedArgs    []BoundedDerivedArgInfo           `json:"derived_args"`
	ArgumentLayout []BoundedArgumentSlotInfo         `json:"argument_layout"`
	Layer3Policy   string                            `json:"layer3_policy"`
}

// KeyInfo represents a key returned from the /keys endpoint.
type KeyInfo struct {
	Address                  string                    `json:"address"`
	PublicKeyHex             string                    `json:"public_key_hex"`
	KeyType                  string                    `json:"key_type"`
	AuthorizationKind        string                    `json:"authorization_kind,omitempty"` // account authorization envelope; empty = not reported or not a spending account
	SigningFlow              string                    `json:"signing_flow,omitempty"`
	CosignerComponentKeyType string                    `json:"cosigner_component_key_type,omitempty"`
	LogicSigResources        *LogicSigResourceProfile  `json:"logic_sig_resources,omitempty"`
	IsGenericLsig            bool                      `json:"is_generic_lsig,omitempty"`
	IsWitnessKey             bool                      `json:"is_witness_key,omitempty"`
	BoundedAuthorization     *BoundedAuthorizationInfo `json:"bounded_authorization,omitempty"`
	IsSpendingAccount        *bool                     `json:"is_spending_account,omitempty"`
	SigningArgs              []SigningArg              `json:"signing_args,omitempty"`
	Parameters               map[string]string         `json:"parameters,omitempty"`
	TemplateProvenanceStatus string                    `json:"template_provenance_status,omitempty"`
	TemplateProvenanceNote   string                    `json:"template_provenance_note,omitempty"`
	// ValidRekeyTarget is the value this aplane key recorded when it was
	// created: whether it may be the signing authority an account is rekeyed
	// to, its own account included. A rekey to it when it is false is refused
	// with ErrCodeRekeyTargetNotValid. False when the signer does not report it.
	ValidRekeyTarget bool `json:"valid_rekey_target"`
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

// Config contains client configuration loaded from config.yaml.
type Config struct {
	Network         string         `yaml:"network"`
	NetworksAllowed []string       `yaml:"networks_allowed"`
	Theme           string         `yaml:"theme"`
	Networks        NetworkConfigs `yaml:"networks"`
	Algod           AlgodConfig    `yaml:"algod"`
}

// SSHConnectOptions contains options for SSH tunnel connections. There is no
// remote REST port option: the signer's SSH server forwards every channel to
// its own REST listener. LocalPort pins the local listener; 0 picks a free
// port.
type SSHConnectOptions struct {
	SSHPort   int
	LocalPort int
	Timeout   int
	// SSHSetupTimeout bounds TCP dialing and SSH authentication. It is
	// independent of Timeout, which bounds HTTP requests after setup.
	SSHSetupTimeout time.Duration
	KnownHostsPath  string
	TrustOnFirstUse bool
	// MaxFeeIncrease, when set, is the ceiling in microAlgos on the total fee
	// the signer may add to a request, applied before the client is returned.
	// See SignerClient.SetMaxFeeIncrease. Nil sets none.
	MaxFeeIncrease *uint64
}

// FromEnvOptions contains options for FromEnv().
type FromEnvOptions struct {
	DataDir  string
	Endpoint string
	Timeout  int
	// SSHSetupTimeout bounds TCP dialing and SSH authentication.
	SSHSetupTimeout time.Duration
	TrustOnFirstUse bool
	// MaxFeeIncrease, when set, is the ceiling in microAlgos on the total fee
	// the signer may add to a request, applied before the client is returned.
	// See SignerClient.SetMaxFeeIncrease. Nil sets none.
	MaxFeeIncrease *uint64
}

// SignOptions contains options for signing with passthrough and foreign support.
type SignOptions struct {
	// Passthrough maps a position to a signed transaction from another
	// signer: canonical msgpack bytes, as go-algorand-sdk's signers return
	// them. It is sent to the signer as is.
	Passthrough   map[int][]byte
	LsigResources map[int]LogicSigResourceUsage
}
