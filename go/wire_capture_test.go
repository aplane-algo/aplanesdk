// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/json"
)

// These test-only shapes keep older mock handlers readable while exercising
// the unified production client. They are deliberately absent from the SDK.
type capturedComponentRole string

const (
	capturedComponentRoleCosigner capturedComponentRole = "cosigner"
	capturedComponentRoleBase     capturedComponentRole = "bounded-base"
)

type capturedComponentRequest struct {
	RequestID     string
	Role          capturedComponentRole
	ComponentKey  string
	GroupBytesHex []string
	TargetIndices []int
	TargetAppInfo map[int]*AppCallInfo
	Contextual    []ComponentContextPosition
	Dummies       []ComponentDummyPosition
}

func (r *capturedComponentRequest) UnmarshalJSON(data []byte) error {
	var unified ComponentRequest
	if err := json.Unmarshal(data, &unified); err != nil {
		return err
	}
	r.RequestID, r.GroupBytesHex = unified.RequestID, unified.GroupBytesHex
	r.Contextual, r.Dummies = unified.ContextualPositions, unified.DummyPositions
	r.TargetAppInfo = make(map[int]*AppCallInfo, len(unified.Targets))
	for _, target := range unified.Targets {
		r.TargetIndices = append(r.TargetIndices, target.TargetIndex)
		r.TargetAppInfo[target.TargetIndex] = target.AppCallInfo
		if target.Kind == ComponentTargetKindBoundedBase {
			r.Role, r.ComponentKey = capturedComponentRoleBase, target.AuthAddress
		} else {
			r.Role, r.ComponentKey = capturedComponentRoleCosigner, target.ComponentKey
		}
	}
	return nil
}
