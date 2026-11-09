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

func TestRequestComponentsBoundedBaseDiscoversApprovalWait(t *testing.T) {
	var paths []string
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				State:               "unlocked",
				ApprovalWaitSeconds: 60,
			})
		case "/sign/component":
			var req ComponentRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode component request: %v", err)
			}
			component := Component{Kind: req.Targets[0].Kind, TargetIndex: 0, SignatureScheme: KeyTypeWitnessFalcon1024}
			if component.Kind == ComponentTargetKindBoundedBase {
				component.AuthAddress, component.BaseSignatures = req.Targets[0].AuthAddress, []string{"base"}
				component.AssemblyReceipt, component.Path = "receipt", ComponentPathSpend
			} else {
				component.Signature = "sig"
			}
			json.NewEncoder(w).Encode(ComponentResponse{RequestID: req.RequestID, Components: []Component{component}})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})
	defer server.Close()

	baseReq := ComponentRequest{
		GroupBytesHex: []string{"5458a16374786ea0"},
		Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindBoundedBase, AuthAddress: "BOUNDED"}},
	}
	if _, err := client.RequestComponents(baseReq); err != nil {
		t.Fatalf("RequestComponents(bounded-base) error = %v", err)
	}
	if len(paths) != 2 || paths[0] != "/status" || paths[1] != "/sign/component" {
		t.Fatalf("bounded-base request paths = %v, want approval-wait discovery before component signing", paths)
	}

	paths = nil
	cosignerReq := ComponentRequest{
		GroupBytesHex: []string{"5458a16374786ea0"},
		Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindCosigner, ComponentKey: "COSIGNERKEY"}},
	}
	if _, err := client.RequestComponents(cosignerReq); err != nil {
		t.Fatalf("RequestComponents(cosigner) error = %v", err)
	}
	if len(paths) != 1 || paths[0] != "/sign/component" {
		t.Fatalf("cosigner-role request paths = %v, want no approval-wait discovery", paths)
	}
}
