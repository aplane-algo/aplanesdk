// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestComponentRequestTimeoutKeepsTwoMinuteFloor(t *testing.T) {
	client := &SignerClient{}
	client.cacheApprovalWait(60)
	if got := client.componentRequestTimeout(context.Background(), true); got != componentSignTimeout {
		t.Fatalf("componentRequestTimeout() = %s, want %s", got, componentSignTimeout)
	}
	client.cacheApprovalWait(180)
	if got := client.componentRequestTimeout(context.Background(), true); got != 210*time.Second {
		t.Fatalf("componentRequestTimeout() = %s, want 210s", got)
	}
}

func TestRequestComponentsUserKindDiscoversApprovalWait(t *testing.T) {
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
			var req ComponentRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode component request: %v", err)
			}
			json.NewEncoder(w).Encode(ComponentResponse{
				RequestID: req.RequestID,
				Components: []Component{{Kind: req.Targets[0].Kind,
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

	userReq := ComponentRequest{
		GroupBytesHex: []string{"5458a16374786ea0"},
		Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindUser, AuthAddress: "GUARDED"}},
	}
	if _, err := client.RequestComponents(userReq); err != nil {
		t.Fatalf("RequestComponents(user) error = %v", err)
	}
	if len(paths) != 2 || paths[0] != "/status" || paths[1] != "/sign/component" {
		t.Fatalf("user-role request paths = %v, want approval-wait discovery before component signing", paths)
	}

	paths = nil
	sentryReq := ComponentRequest{
		GroupBytesHex: []string{"5458a16374786ea0"},
		Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindSentry, ComponentKey: "SENTRYKEY"}},
	}
	if _, err := client.RequestComponents(sentryReq); err != nil {
		t.Fatalf("RequestComponents(sentry) error = %v", err)
	}
	if len(paths) != 1 || paths[0] != "/sign/component" {
		t.Fatalf("sentry-role request paths = %v, want no approval-wait discovery", paths)
	}
}
