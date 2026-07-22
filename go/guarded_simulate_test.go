// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/json"
	"net/http"
	"testing"
)

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
					SignatureScheme: KeyTypeWitnessFalcon1024,
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
