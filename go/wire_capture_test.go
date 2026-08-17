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
	capturedComponentRoleUser   capturedComponentRole = "user"
	capturedComponentRoleSentry capturedComponentRole = "sentry"
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
		if target.Kind == ComponentTargetKindUser {
			r.Role, r.ComponentKey = capturedComponentRoleUser, target.AuthAddress
		} else {
			r.Role, r.ComponentKey = capturedComponentRoleSentry, target.ComponentKey
		}
	}
	return nil
}

type capturedAssemblyTarget struct {
	TargetIndex           int
	GuardedAccount        string
	UserSignature         string
	UserSourceRequestID   string
	SentrySignature       string
	SentrySourceRequestID string
	RuntimeArgs           []string
}

type capturedAssemblyRequest struct {
	RequestID     string
	GroupBytesHex []string
	Targets       []capturedAssemblyTarget
	Passthrough   []AssemblyPassthroughItem
}

func (r *capturedAssemblyRequest) UnmarshalJSON(data []byte) error {
	var unified AssemblyRequest
	if err := json.Unmarshal(data, &unified); err != nil {
		return err
	}
	r.RequestID, r.GroupBytesHex, r.Passthrough = unified.RequestID, unified.GroupBytesHex, unified.Passthrough
	for _, target := range unified.Targets {
		r.Targets = append(r.Targets, capturedAssemblyTarget{
			TargetIndex: target.TargetIndex, GuardedAccount: target.AuthAddress,
			UserSignature: target.UserSignature, UserSourceRequestID: target.UserSourceRequestID,
			SentrySignature: target.SentrySignature, SentrySourceRequestID: target.SentrySourceRequestID,
			RuntimeArgs: target.GuardedRuntimeArgs,
		})
	}
	return nil
}
