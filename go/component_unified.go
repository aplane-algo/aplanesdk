// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import "fmt"

func (r ComponentRequest) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if err := validateComponentGroupBytes(r.GroupBytesHex); err != nil {
		return err
	}
	if len(r.Targets) == 0 || len(r.DummyPositions) > len(r.GroupBytesHex) {
		return fmt.Errorf("targets are required and dummy_positions cannot exceed group length")
	}
	originalCount := len(r.GroupBytesHex) - len(r.DummyPositions)
	covered := make([]bool, originalCount)
	kind := r.Targets[0].Kind
	for i, target := range r.Targets {
		if target.TargetIndex < 0 || target.TargetIndex >= originalCount || covered[target.TargetIndex] {
			return fmt.Errorf("target %d has invalid, duplicate, or overlapping target_index", i+1)
		}
		covered[target.TargetIndex] = true
		if target.Kind != kind {
			return fmt.Errorf("mixed component target kinds are not supported")
		}
		switch target.Kind {
		case ComponentTargetKindUser:
			if target.AuthAddress == "" || target.ComponentKey != "" || len(target.LsigArgs) != 0 {
				return fmt.Errorf("target %d: user target requires only auth_address", i+1)
			}
			if i > 0 && target.AuthAddress != r.Targets[0].AuthAddress {
				return fmt.Errorf("user targets must share one auth_address")
			}
		case ComponentTargetKindSentry:
			if target.AuthAddress != "" || len(target.LsigArgs) != 0 {
				return fmt.Errorf("target %d: sentry target forbids auth_address and lsig_args", i+1)
			}
			if i > 0 && target.ComponentKey != r.Targets[0].ComponentKey {
				return fmt.Errorf("sentry targets must share one component_key")
			}
		case ComponentTargetKindBoundedBase:
			if target.AuthAddress == "" || target.ComponentKey != "" {
				return fmt.Errorf("target %d: bounded-base target requires auth_address and forbids component_key", i+1)
			}
		default:
			return fmt.Errorf("target %d: unsupported component kind %q", i+1, target.Kind)
		}
	}
	for i, position := range r.ContextualPositions {
		if position.TargetIndex < 0 || position.TargetIndex >= originalCount || covered[position.TargetIndex] {
			return fmt.Errorf("contextual position %d has invalid, duplicate, or overlapping target_index", i+1)
		}
		covered[position.TargetIndex] = true
		probe := SignRequest{TxnBytesHex: "frozen", LsigResources: position.LsigResources, PQScheme: position.PQScheme}
		if err := probe.Validate(); err != nil {
			return fmt.Errorf("contextual position %d: %w", i+1, err)
		}
	}
	for index, ok := range covered {
		if !ok {
			return fmt.Errorf("original group position %d is not covered", index)
		}
	}
	for offset, dummy := range r.DummyPositions {
		if dummy.TargetIndex != originalCount+offset {
			return fmt.Errorf("dummy position %d is not in the contiguous suffix", offset+1)
		}
	}
	return nil
}

func (r ComponentRequest) TargetKind() ComponentTargetKind {
	if len(r.Targets) == 0 {
		return ""
	}
	return r.Targets[0].Kind
}

func (r ComponentResponse) Validate() error {
	if r.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if len(r.Components) == 0 {
		return fmt.Errorf("components array is empty")
	}
	seen := make(map[int]bool, len(r.Components))
	for i, component := range r.Components {
		if component.TargetIndex < 0 || seen[component.TargetIndex] {
			return fmt.Errorf("component %d has invalid or duplicate target_index", i+1)
		}
		seen[component.TargetIndex] = true
		switch component.Kind {
		case ComponentTargetKindUser, ComponentTargetKindSentry:
			if component.Signature == "" || component.SignatureScheme == "" || len(component.BaseSignatures) != 0 || component.AssemblyReceipt != "" {
				return fmt.Errorf("component %d has invalid signature material", i+1)
			}
		case ComponentTargetKindBoundedBase:
			if component.AuthAddress == "" || len(component.BaseSignatures) == 0 || component.AssemblyReceipt == "" || component.SignatureScheme == "" || component.Signature != "" {
				return fmt.Errorf("component %d has invalid bounded-base material", i+1)
			}
		default:
			return fmt.Errorf("component %d has unsupported kind %q", i+1, component.Kind)
		}
	}
	return nil
}

// ValidateForRequest validates response indices and kinds against the frozen
// group and exact target set that produced the response.
func (r ComponentResponse) ValidateForRequest(request ComponentRequest) error {
	if err := r.Validate(); err != nil {
		return err
	}
	expected := make(map[int]ComponentTargetKind, len(request.Targets))
	for _, target := range request.Targets {
		expected[target.TargetIndex] = target.Kind
	}
	if len(r.Components) != len(expected) {
		return fmt.Errorf("component response target indices or kinds do not match request")
	}
	for _, component := range r.Components {
		if component.TargetIndex >= len(request.GroupBytesHex) || expected[component.TargetIndex] != component.Kind {
			return fmt.Errorf("component response target indices or kinds do not match request")
		}
	}
	return nil
}
