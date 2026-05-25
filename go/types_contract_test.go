// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var expectedSDKContractFixtureNames = []string{
	"admin_delete_response_success.json",
	"admin_generate_request_generic.json",
	"admin_generate_response_generic.json",
	"cancel_sign_request.json",
	"cancel_sign_response_not_found.json",
	"cancel_sign_response_success.json",
	"error_response.json",
	"group_plan_response_mutated.json",
	"group_sign_request_mixed.json",
	"group_sign_response_mutated.json",
	"health_response_ready.json",
	"keys_response_generic.json",
	"keytypes_response_full.json",
	"status_response_ready.json",
}

func sdkContractFixturePath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	return filepath.Join(filepath.Dir(file), "..", "contracts", "signerapi", name)
}

func sdkContractFixtureDir(t *testing.T) string {
	t.Helper()
	return filepath.Dir(sdkContractFixturePath(t, "README.md"))
}

func committedSDKContractFixtureNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(sdkContractFixtureDir(t))
	if err != nil {
		t.Fatalf("read contract fixture dir: %v", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names
}

func assertSDKContractRoundTrip[T any](t *testing.T, name string) {
	t.Helper()
	raw, err := os.ReadFile(sdkContractFixturePath(t, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}

	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("unmarshal %s into SDK type: %v", name, err)
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s from SDK type: %v", name, err)
	}

	var want any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("unmarshal fixture %s as generic JSON: %v", name, err)
	}
	var got any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal round-tripped %s as generic JSON: %v", name, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch for %s\nwant: %#v\n got: %#v", name, want, got)
	}
}

func TestGoSDKContractFixturesRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, string)
	}{
		{"group_sign_request_mixed.json", assertSDKContractRoundTrip[GroupSignRequest]},
		{"group_sign_response_mutated.json", assertSDKContractRoundTrip[GroupSignResponse]},
		{"group_plan_response_mutated.json", assertSDKContractRoundTrip[PlanGroupResponse]},
		{"keys_response_generic.json", assertSDKContractRoundTrip[KeysResponse]},
		{"keytypes_response_full.json", assertSDKContractRoundTrip[KeyTypesResponse]},
		{"admin_generate_request_generic.json", assertSDKContractRoundTrip[generateRequest]},
		{"admin_generate_response_generic.json", assertSDKContractRoundTrip[GenerateResult]},
		{"cancel_sign_request.json", assertSDKContractRoundTrip[CancelSignRequest]},
		{"cancel_sign_response_not_found.json", assertSDKContractRoundTrip[CancelSignResponse]},
		{"cancel_sign_response_success.json", assertSDKContractRoundTrip[CancelSignResponse]},
		{"error_response.json", assertSDKContractRoundTrip[ErrorResponse]},
		{"health_response_ready.json", assertSDKContractRoundTrip[HealthResponse]},
		{"status_response_ready.json", assertSDKContractRoundTrip[StatusResponse]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t, tt.name)
		})
	}
}

func TestGoSDKContractStatusMetadata(t *testing.T) {
	raw, err := os.ReadFile(sdkContractFixturePath(t, "status_response_ready.json"))
	if err != nil {
		t.Fatalf("read status fixture: %v", err)
	}
	var resp StatusResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal status fixture: %v", err)
	}
	if resp.IdentityID != "default" {
		t.Fatalf("IdentityID = %q, want default", resp.IdentityID)
	}
	if resp.State != "unlocked" {
		t.Fatalf("State = %q, want unlocked", resp.State)
	}
	if resp.KeysetRevision != 4 {
		t.Fatalf("KeysetRevision = %d, want 4", resp.KeysetRevision)
	}
	if resp.ApprovalWaitSeconds != 60 {
		t.Fatalf("ApprovalWaitSeconds = %d, want 60", resp.ApprovalWaitSeconds)
	}
}

func TestGoSDKContractKeyTypeMetadata(t *testing.T) {
	raw, err := os.ReadFile(sdkContractFixturePath(t, "keytypes_response_full.json"))
	if err != nil {
		t.Fatalf("read keytypes fixture: %v", err)
	}
	var resp KeyTypesResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal keytypes fixture: %v", err)
	}
	if len(resp.KeyTypes) != 2 {
		t.Fatalf("KeyTypes length = %d, want 2", len(resp.KeyTypes))
	}
	if !resp.KeyTypes[0].MnemonicImport {
		t.Fatal("ed25519 fixture should allow mnemonic import")
	}
	if resp.KeyTypes[1].KeyType != "aplane.timelock.v1" {
		t.Fatalf("generic key type = %q, want aplane.timelock.v1", resp.KeyTypes[1].KeyType)
	}
	if resp.KeyTypes[1].MnemonicImport {
		t.Fatal("generic template fixture should not allow mnemonic import")
	}
	modes := resp.KeyTypes[1].CreationParams[3].InputModes
	if len(modes) != 2 {
		t.Fatalf("InputModes length = %d, want 2", len(modes))
	}
	if modes[1].Name != "sha256" {
		t.Fatalf("InputModes[1].Name = %q, want sha256", modes[1].Name)
	}
	if modes[1].Transform != "sha256" {
		t.Fatalf("InputModes[1].Transform = %q, want sha256", modes[1].Transform)
	}
	if modes[1].ByteLength != 32 {
		t.Fatalf("InputModes[1].ByteLength = %d, want 32", modes[1].ByteLength)
	}
	if modes[1].InputType != "bytes" {
		t.Fatalf("InputModes[1].InputType = %q, want bytes", modes[1].InputType)
	}
}

func TestGoSDKMapsTemplateWarningFields(t *testing.T) {
	raw := []byte(`{
		"count": 1,
		"keys": [{
			"address": "ADDR1",
			"public_key_hex": "abcd",
			"key_type": "aplane.timelock.v1",
			"template_provenance_status": "conflict",
			"template_provenance_note": "template fingerprint differs"
		}]
	}`)
	var resp KeysResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal keys response: %v", err)
	}
	if got := resp.Keys[0].TemplateStatus; got != "conflict" {
		t.Fatalf("TemplateStatus = %q, want conflict", got)
	}
	if got := resp.Keys[0].TemplateWarning; got != "template fingerprint differs" {
		t.Fatalf("TemplateWarning = %q, want template fingerprint differs", got)
	}
	if got := resp.Keys[0].TemplateProvenanceStatus; got != "conflict" {
		t.Fatalf("TemplateProvenanceStatus = %q, want conflict", got)
	}
	if got := resp.Keys[0].TemplateProvenanceNote; got != "template fingerprint differs" {
		t.Fatalf("TemplateProvenanceNote = %q, want template fingerprint differs", got)
	}
}

func TestGoSDKContractFixtureManifest(t *testing.T) {
	if got := committedSDKContractFixtureNames(t); !reflect.DeepEqual(got, expectedSDKContractFixtureNames) {
		t.Fatalf("contract fixture manifest mismatch\nwant: %#v\n got: %#v", expectedSDKContractFixtureNames, got)
	}
	for _, name := range expectedSDKContractFixtureNames {
		raw, err := os.ReadFile(sdkContractFixturePath(t, name))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("fixture %s is not valid JSON: %v", name, err)
		}
	}
}
