// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/json"
	"fmt"
)

// UnmarshalJSON accepts the unified wire while keeping the legacy DTO useful
// to callers that decode requests in test transports during this migration.
func (r *ComponentSignRequest) UnmarshalJSON(data []byte) error {
	var raw struct {
		RequestID     string            `json:"request_id"`
		Role          ComponentSignRole `json:"role"`
		ComponentKey  string            `json:"component_key"`
		GroupBytesHex []string          `json:"group_bytes_hex"`
		TargetIndices []int             `json:"target_indices"`
		Targets       []ComponentTarget `json:"targets"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = ComponentSignRequest{RequestID: raw.RequestID, Role: raw.Role, ComponentKey: raw.ComponentKey, GroupBytesHex: raw.GroupBytesHex, TargetIndices: raw.TargetIndices}
	if len(raw.Targets) == 0 || r.Role != "" {
		return nil
	}
	for _, target := range raw.Targets {
		r.TargetIndices = append(r.TargetIndices, target.TargetIndex)
		if target.Kind == ComponentTargetKindUser {
			r.Role, r.ComponentKey = ComponentSignRoleUser, target.AuthAddress
		} else {
			r.Role, r.ComponentKey = ComponentSignRoleSentry, target.ComponentKey
		}
	}
	return nil
}

// UnmarshalJSON accepts both the unified response and the two pre-collapse
// response shapes so one SDK commit can interoperate across the paired rollout.
func (r *ComponentResponse) UnmarshalJSON(data []byte) error {
	var raw struct {
		RequestID  string               `json:"request_id"`
		Signatures []ComponentSignature `json:"signatures"`
		Components []struct {
			TargetIndex     int                 `json:"target_index"`
			Kind            ComponentTargetKind `json:"kind"`
			Signature       string              `json:"signature"`
			SignatureScheme string              `json:"signature_scheme"`
			AuthAddress     string              `json:"auth_address"`
			BoundedAccount  string              `json:"bounded_account"`
			BaseSignatures  []string            `json:"base_signatures"`
			RuntimeArgs     map[string]string   `json:"runtime_args"`
			AssemblyReceipt string              `json:"assembly_receipt"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.RequestID = raw.RequestID
	for _, component := range raw.Components {
		kind := component.Kind
		authAddress := component.AuthAddress
		if component.BoundedAccount != "" {
			kind, authAddress = ComponentTargetKindBoundedBase, component.BoundedAccount
		}
		if kind == "" {
			kind = ComponentTargetKindSentry
		}
		r.Components = append(r.Components, Component{
			TargetIndex: component.TargetIndex, Kind: kind, Signature: component.Signature,
			SignatureScheme: component.SignatureScheme, AuthAddress: authAddress,
			BaseSignatures: component.BaseSignatures, RuntimeArgs: component.RuntimeArgs,
			AssemblyReceipt: component.AssemblyReceipt,
		})
	}
	for _, signature := range raw.Signatures {
		r.Components = append(r.Components, Component{
			TargetIndex: signature.TargetIndex, Kind: ComponentTargetKindSentry,
			Signature: signature.Signature, SignatureScheme: signature.SignatureScheme,
		})
	}
	return nil
}

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

func (r ComponentSignRequest) ComponentRequest() ComponentRequest {
	targetSet := make(map[int]bool, len(r.TargetIndices))
	targets := make([]ComponentTarget, 0, len(r.TargetIndices))
	for _, index := range r.TargetIndices {
		targetSet[index] = true
		target := ComponentTarget{TargetIndex: index}
		if r.Role == ComponentSignRoleUser {
			target.Kind, target.AuthAddress = ComponentTargetKindUser, r.ComponentKey
		} else {
			target.Kind, target.ComponentKey = ComponentTargetKindSentry, r.ComponentKey
		}
		targets = append(targets, target)
	}
	context := make([]ComponentContextPosition, 0, len(r.GroupBytesHex)-len(targets))
	for index := range r.GroupBytesHex {
		if !targetSet[index] {
			context = append(context, ComponentContextPosition{TargetIndex: index})
		}
	}
	return ComponentRequest{RequestID: r.RequestID, GroupBytesHex: r.GroupBytesHex, Targets: targets, ContextualPositions: context}
}

func (r BoundedComponentRequest) ComponentRequest() ComponentRequest {
	targets := make([]ComponentTarget, 0, len(r.Targets))
	for _, target := range r.Targets {
		targets = append(targets, ComponentTarget{TargetIndex: target.TargetIndex, Kind: ComponentTargetKindBoundedBase, AuthAddress: target.AuthAddress, LsigArgs: target.LsigArgs})
	}
	return ComponentRequest{RequestID: r.RequestID, GroupBytesHex: r.GroupBytesHex, Targets: targets, ContextualPositions: r.ContextualPositions, DummyPositions: r.DummyPositions}
}
