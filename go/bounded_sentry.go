// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import "fmt"

// BoundedComponentRequest asks the account signer to approve a finalized
// group and release only the bounded base-signature arguments for its
// sentry-enabled spend positions.
type BoundedComponentRequest struct {
	RequestID string        `json:"request_id,omitempty"`
	Requests  []SignRequest `json:"requests"`
}

// Validate checks the bounded component request shape.
func (r BoundedComponentRequest) Validate() error {
	if err := GroupSignRequest(r).Validate(); err != nil {
		return err
	}
	for i, request := range r.Requests {
		mode, err := request.Mode()
		if err != nil {
			return fmt.Errorf("transaction %d: %w", i+1, err)
		}
		if mode == RequestModePassthrough {
			return fmt.Errorf("bounded-component does not accept signed passthrough entries")
		}
	}
	return nil
}

// BoundedBaseComponent is one user-signer contribution to bounded assembly.
type BoundedBaseComponent struct {
	TargetIndex     int               `json:"target_index"`
	BoundedAccount  string            `json:"bounded_account"`
	BaseSignatures  []string          `json:"base_signatures"`
	RuntimeArgs     map[string]string `json:"runtime_args,omitempty"`
	AssemblyReceipt string            `json:"assembly_receipt"`
	SignatureScheme string            `json:"signature_scheme"`
}

// BoundedComponentResponse contains the signer-finalized group and bounded
// base components that may be disclosed to the sentry only after approval.
type BoundedComponentResponse struct {
	RequestID    string                 `json:"request_id"`
	Transactions []string               `json:"transactions"`
	Components   []BoundedBaseComponent `json:"components"`
	Mutations    *MutationReport        `json:"mutations,omitempty"`
}

// Validate checks the bounded component response shape.
func (r BoundedComponentResponse) Validate() error {
	if r.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if len(r.Transactions) == 0 || len(r.Components) == 0 {
		return fmt.Errorf("transactions and components are required")
	}
	seen := make(map[int]bool, len(r.Components))
	for i, component := range r.Components {
		if component.TargetIndex < 0 || component.TargetIndex >= len(r.Transactions) || seen[component.TargetIndex] {
			return fmt.Errorf("component %d has invalid or duplicate target_index", i+1)
		}
		seen[component.TargetIndex] = true
		if component.BoundedAccount == "" || len(component.BaseSignatures) == 0 ||
			component.AssemblyReceipt == "" || component.SignatureScheme == "" {
			return fmt.Errorf("component %d is incomplete", i+1)
		}
	}
	return nil
}

// BoundedAssemblyRequest asks the user signer to combine approved bounded base
// components with sentry signatures and passthrough positions.
type BoundedAssemblyRequest struct {
	RequestID     string                   `json:"request_id,omitempty"`
	GroupBytesHex []string                 `json:"group_bytes_hex"`
	Targets       []BoundedAssemblyTarget  `json:"targets,omitempty"`
	Passthrough   []GuardedPassthroughItem `json:"passthrough,omitempty"`
}

// BoundedAssemblyTarget carries all source-bound material for one bounded
// sentry target.
type BoundedAssemblyTarget struct {
	TargetIndex           int               `json:"target_index"`
	BoundedAccount        string            `json:"bounded_account"`
	BaseSignatures        []string          `json:"base_signatures"`
	RuntimeArgs           map[string]string `json:"runtime_args,omitempty"`
	AssemblyReceipt       string            `json:"assembly_receipt"`
	BaseSourceRequestID   string            `json:"base_source_request_id,omitempty"`
	SentrySignature       string            `json:"sentry_signature"`
	SentrySourceRequestID string            `json:"sentry_source_request_id,omitempty"`
}

// BoundedAssemblyResponse contains one signed transaction per frozen group
// position.
type BoundedAssemblyResponse struct {
	RequestID   string   `json:"request_id"`
	SignedGroup []string `json:"signed_group"`
}

// Validate checks the bounded assembly response shape.
func (r BoundedAssemblyResponse) Validate() error {
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
			return fmt.Errorf("signed_group[%d] is empty", i)
		}
	}
	return nil
}

// Validate checks the bounded assembly request shape and complete group
// coverage.
func (r BoundedAssemblyRequest) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if err := validateComponentGroupBytes(r.GroupBytesHex); err != nil {
		return err
	}
	if len(r.Targets) == 0 {
		return fmt.Errorf("targets array is empty")
	}
	covered := make([]bool, len(r.GroupBytesHex))
	for i, target := range r.Targets {
		if err := validateAssemblyIndex(target.TargetIndex, len(r.GroupBytesHex), covered); err != nil {
			return fmt.Errorf("target %d: %w", i+1, err)
		}
		if target.BoundedAccount == "" || len(target.BaseSignatures) == 0 ||
			target.AssemblyReceipt == "" || target.SentrySignature == "" {
			return fmt.Errorf("target %d: bounded_account, base_signatures, assembly_receipt, and sentry_signature are required", i+1)
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
			return fmt.Errorf("group index %d is not covered by a target or passthrough", i)
		}
	}
	return nil
}
