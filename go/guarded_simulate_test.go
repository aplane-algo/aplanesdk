// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func validGuardedSimulateRequest() GuardedSimulateRequest {
	return GuardedSimulateRequest{
		Requests: []SignRequest{
			{TxnBytesHex: "5458a16374786ea0", LsigSize: 1500},
			{AuthAddress: "AUTH", TxnBytesHex: "5458a16374786ea1"},
			{TxnBytesHex: "5458a16374786ea2"},
		},
		Targets: []GuardedSimulateTarget{{
			TargetIndex:     0,
			GuardedAccount:  "GUARDED",
			SentrySignature: "cccc",
		}},
		Passthrough: []GuardedPassthroughItem{{
			TargetIndex:  2,
			SignedTxnHex: "dddd",
		}},
	}
}

func TestGuardedSimulateRequestValidate(t *testing.T) {
	if err := validGuardedSimulateRequest().Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	mutations := map[string]func(*GuardedSimulateRequest){
		"no targets":                func(r *GuardedSimulateRequest) { r.Targets = nil },
		"missing txn bytes":         func(r *GuardedSimulateRequest) { r.Requests[0].TxnBytesHex = "" },
		"signed txn hex in request": func(r *GuardedSimulateRequest) { r.Requests[1].SignedTxnHex = "ee" },
		"uncovered position":        func(r *GuardedSimulateRequest) { r.Passthrough = nil },
		"duplicate coverage":        func(r *GuardedSimulateRequest) { r.Passthrough[0].TargetIndex = 0 },
		"missing guarded account":   func(r *GuardedSimulateRequest) { r.Targets[0].GuardedAccount = "" },
		"missing sentry signature":  func(r *GuardedSimulateRequest) { r.Targets[0].SentrySignature = "" },
		"target overlaps sign mode": func(r *GuardedSimulateRequest) { r.Requests[0].AuthAddress = "X" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			req := validGuardedSimulateRequest()
			mutate(&req)
			if err := req.Validate(); err == nil {
				t.Fatalf("Validate() error = nil, want failure")
			}
		})
	}
}

func TestRequestGuardedSimulate(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/simulate/guarded" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var req GuardedSimulateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode guarded simulate request: %v", err)
		}
		if len(req.Targets) != 1 || req.Targets[0].SentrySignature != "cccc" {
			t.Fatalf("guarded simulate targets = %+v", req.Targets)
		}
		json.NewEncoder(w).Encode(GuardedSimulateResponse{
			RequestID: req.RequestID,
			TxIDs:     []string{"A", "B", "C"},
			Output:    "ok",
		})
	})
	defer server.Close()

	resp, err := client.RequestGuardedSimulate(validGuardedSimulateRequest())
	if err != nil {
		t.Fatalf("RequestGuardedSimulate() error = %v", err)
	}
	if len(resp.TxIDs) != 3 || resp.Output != "ok" || resp.Failed {
		t.Fatalf("guarded simulate response = %+v", resp)
	}
}

func TestRequestGuardedSimulateRejectsErrorResponse(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		var req GuardedSimulateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode guarded simulate request: %v", err)
		}
		json.NewEncoder(w).Encode(GuardedSimulateResponse{
			RequestID: req.RequestID,
			Error:     "assembly rejected",
		})
	})
	defer server.Close()

	_, err := client.RequestGuardedSimulate(validGuardedSimulateRequest())
	if err == nil || !strings.Contains(err.Error(), "assembly rejected") {
		t.Fatalf("RequestGuardedSimulate() error = %v, want error-field rejection", err)
	}
}

func TestRequestComponentSignUserRoleDiscoversApprovalWait(t *testing.T) {
	var paths []string
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				IdentityID:          "default",
				State:               "unlocked",
				ApprovalWaitSeconds: 60,
			})
		case "/sign/component":
			var req ComponentSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode component request: %v", err)
			}
			json.NewEncoder(w).Encode(ComponentSignResponse{
				RequestID: req.RequestID,
				Signatures: []ComponentSignature{{
					TargetIndex:     0,
					Signature:       "sig",
					SignatureScheme: KeyTypeSentryFalcon1024,
				}},
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})
	defer server.Close()

	userReq := ComponentSignRequest{
		Role:          ComponentSignRoleUser,
		ComponentKey:  "GUARDED",
		GroupBytesHex: []string{"5458a16374786ea0"},
		TargetIndices: []int{0},
	}
	if _, err := client.RequestComponentSign(userReq); err != nil {
		t.Fatalf("RequestComponentSign(user) error = %v", err)
	}
	if len(paths) != 2 || paths[0] != "/status" || paths[1] != "/sign/component" {
		t.Fatalf("user-role request paths = %v, want approval-wait discovery before component signing", paths)
	}

	paths = nil
	sentryReq := ComponentSignRequest{
		Role:          ComponentSignRoleSentry,
		ComponentKey:  "SENTRYKEY",
		GroupBytesHex: []string{"5458a16374786ea0"},
		TargetIndices: []int{0},
	}
	if _, err := client.RequestComponentSign(sentryReq); err != nil {
		t.Fatalf("RequestComponentSign(sentry) error = %v", err)
	}
	if len(paths) != 1 || paths[0] != "/sign/component" {
		t.Fatalf("sentry-role request paths = %v, want no approval-wait discovery", paths)
	}
}
