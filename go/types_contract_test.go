// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const (
	contractFixtureManifestName          = "fixture_manifest.json"
	contractFixtureHashManifestName      = "SHA256SUMS"
	contractErrorCodesFixtureName        = "error_codes.json"
	contractErrorClassificationsFileName = "error_code_classifications.json"
	contractFixtureSchemaVersion         = 1
)

type contractFixtureManifest struct {
	SchemaVersion int      `json:"schema_version"`
	Fixtures      []string `json:"fixtures"`
}

type contractErrorCodesFixture struct {
	SchemaVersion int      `json:"schema_version"`
	Codes         []string `json:"codes"`
}

type contractErrorClassificationsFixture struct {
	SchemaVersion   int               `json:"schema_version"`
	Classifications map[string]string `json:"classifications"`
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
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") && !isContractMetadataFile(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names
}

func expectedSDKContractFixtureNames(t *testing.T) []string {
	t.Helper()
	var manifest contractFixtureManifest
	readContractMetadata(t, contractFixtureManifestName, &manifest)
	if manifest.SchemaVersion != contractFixtureSchemaVersion {
		t.Fatalf("%s schema_version = %d, want %d", contractFixtureManifestName, manifest.SchemaVersion, contractFixtureSchemaVersion)
	}
	names := sortedUniqueStrings(t, contractFixtureManifestName, manifest.Fixtures)
	for _, name := range names {
		if !strings.HasSuffix(name, ".json") {
			t.Fatalf("%s contains non-json fixture %q", contractFixtureManifestName, name)
		}
		if isContractMetadataFile(name) {
			t.Fatalf("%s must list API payload fixtures only, not metadata file %q", contractFixtureManifestName, name)
		}
	}
	return names
}

func isContractMetadataFile(name string) bool {
	switch name {
	case contractFixtureManifestName, contractErrorCodesFixtureName, contractErrorClassificationsFileName:
		return true
	default:
		return false
	}
}

func readContractMetadata(t *testing.T, name string, out any) {
	t.Helper()
	raw, err := os.ReadFile(sdkContractFixturePath(t, name))
	if err != nil {
		t.Fatalf("read contract metadata %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("unmarshal contract metadata %s: %v", name, err)
	}
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
		{"group_simulate_response_mutated.json", assertSDKContractRoundTrip[GroupSimulateResponse]},
		{"component_sign_request_sentry.json", assertSDKContractRoundTrip[ComponentSignRequest]},
		{"component_sign_response_sentry.json", assertSDKContractRoundTrip[ComponentSignResponse]},
		{"guarded_assembly_request_mixed.json", assertSDKContractRoundTrip[GuardedAssemblyRequest]},
		{"guarded_assembly_response.json", assertSDKContractRoundTrip[GuardedAssemblyResponse]},
		{"guarded_simulate_request_mixed.json", assertSDKContractRoundTrip[GuardedSimulateRequest]},
		{"guarded_simulate_response.json", assertSDKContractRoundTrip[GuardedSimulateResponse]},
		{"keys_response_generic.json", assertSDKContractRoundTrip[KeysResponse]},
		{"keys_response_component.json", assertSDKContractRoundTrip[KeysResponse]},
		{"keys_response_guarded.json", assertSDKContractRoundTrip[KeysResponse]},
		{"keys_response_bounded.json", assertSDKContractRoundTrip[KeysResponse]},
		{"keytypes_response_full.json", assertSDKContractRoundTrip[KeyTypesResponse]},
		{"keytypes_response_bounded.json", assertSDKContractRoundTrip[KeyTypesResponse]},
		{"admin_generate_request_generic.json", assertSDKContractRoundTrip[generateRequest]},
		{"admin_generate_response_generic.json", assertSDKContractRoundTrip[GenerateResult]},
		{"admin_generate_response_component.json", assertSDKContractRoundTrip[GenerateResult]},
		{"admin_sync_sentries_request.json", assertSDKContractRoundTrip[AdminSyncSentryReferencesRequest]},
		{"admin_sync_sentries_response.json", assertSDKContractRoundTrip[AdminSyncSentryReferencesResponse]},
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

func TestBoundedInventoryUsesSpendPathLogicSigSize(t *testing.T) {
	raw, err := os.ReadFile(sdkContractFixturePath(t, "keys_response_bounded.json"))
	if err != nil {
		t.Fatalf("read bounded keys fixture: %v", err)
	}
	var response KeysResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("decode bounded keys fixture: %v", err)
	}
	if len(response.Keys) != 1 {
		t.Fatalf("bounded key count = %d, want 1", len(response.Keys))
	}
	key := response.Keys[0]
	if key.SigningFlow != SigningFlowBounded1 {
		t.Fatalf("signing flow = %q, want %q", key.SigningFlow, SigningFlowBounded1)
	}
	if key.LsigSize != 6592 {
		t.Fatalf("spend-path lsig size = %d, want 6592", key.LsigSize)
	}
	if key.BoundedAuthorization == nil || key.BoundedAuthorization.PostSigningLogicSigSize != 7872 {
		t.Fatalf("bounded authorization = %+v, want admin-inclusive size 7872", key.BoundedAuthorization)
	}
	if key.BoundedAuthorization.ProgramBindingHex != "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" {
		t.Fatalf("program binding = %q, want fixture binding", key.BoundedAuthorization.ProgramBindingHex)
	}
	if len(key.BoundedAuthorization.SpendEffects) != 3 || len(key.BoundedAuthorization.ArgumentLayout) != 2 {
		t.Fatalf("bounded authorization = %+v, want effects and static slots", key.BoundedAuthorization)
	}
	if operation := key.BoundedAuthorization.AdminOperations[0]; operation.PolicyGate != "none" {
		t.Fatalf("admin operation = %+v, want policy_gate none", operation)
	}
}

func TestSDKProductionSurfaceExcludesBoundedAdminWorkflow(t *testing.T) {
	roots := []struct {
		path string
		ext  string
	}{
		{path: ".", ext: ".go"},
		{path: "../python/aplanesdk", ext: ".py"},
		{path: "../typescript/src", ext: ".ts"},
	}
	forbidden := []string{
		"/sign/" + "bounded-admin",
		".apbounded-" + "admin-key",
		".apbounded-" + "admin-request",
		".apbounded-" + "admin-signature",
	}

	for _, root := range roots {
		err := filepath.WalkDir(root.path, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || filepath.Ext(path) != root.ext || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			for _, token := range forbidden {
				if strings.Contains(string(content), token) {
					t.Errorf("%s exposes forbidden bounded-admin workflow token %q", path, token)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan SDK production surface %s: %v", root.path, err)
		}
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
	if resp.NodeRole != "signer" {
		t.Fatalf("NodeRole = %q, want signer", resp.NodeRole)
	}
	if resp.ProtocolVersion.Major != 1 || resp.ProtocolVersion.Minor != 0 {
		t.Fatalf("ProtocolVersion = %d.%d, want 1.0", resp.ProtocolVersion.Major, resp.ProtocolVersion.Minor)
	}
	if !strings.Contains(resp.BuildVersion, "v0.30.0") {
		t.Fatalf("BuildVersion = %q, want v0.30.0 fixture", resp.BuildVersion)
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
	if resp.KeyTypes[1].KeyType != "example.generic-policy.v1" {
		t.Fatalf("generic key type = %q, want example.generic-policy.v1", resp.KeyTypes[1].KeyType)
	}
	if resp.KeyTypes[1].DisplayName != "Generic Policy" {
		t.Fatalf("generic display name = %q, want Generic Policy", resp.KeyTypes[1].DisplayName)
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
	sentryParam := resp.KeyTypes[1].CreationParams[4]
	if sentryParam.Type != "select" {
		t.Fatalf("sentry param type = %q, want select", sentryParam.Type)
	}
	if !reflect.DeepEqual(sentryParam.Options, []string{"lab-sentry", "backup-sentry"}) {
		t.Fatalf("sentry options = %#v", sentryParam.Options)
	}
}

func TestGoSDKContractSentryKeyMetadata(t *testing.T) {
	raw, err := os.ReadFile(sdkContractFixturePath(t, "keys_response_component.json"))
	if err != nil {
		t.Fatalf("read component keys fixture: %v", err)
	}
	var component KeysResponse
	if err := json.Unmarshal(raw, &component); err != nil {
		t.Fatalf("unmarshal component keys fixture: %v", err)
	}
	if !component.Keys[0].IsComponentKey {
		t.Fatal("component key should be marked IsComponentKey")
	}
	if component.Keys[0].IsSpendingAccount == nil || *component.Keys[0].IsSpendingAccount {
		t.Fatalf("component IsSpendingAccount = %#v, want false", component.Keys[0].IsSpendingAccount)
	}

	raw, err = os.ReadFile(sdkContractFixturePath(t, "keys_response_guarded.json"))
	if err != nil {
		t.Fatalf("read guarded keys fixture: %v", err)
	}
	var guarded KeysResponse
	if err := json.Unmarshal(raw, &guarded); err != nil {
		t.Fatalf("unmarshal guarded keys fixture: %v", err)
	}
	if got := guarded.Keys[0].Parameters["sentry_public_key"]; got == "" {
		t.Fatal("guarded key missing sentry_public_key parameter")
	}
}

func TestGoSDKMapsTemplateWarningFields(t *testing.T) {
	raw := []byte(`{
		"count": 1,
		"keys": [{
			"address": "ADDR1",
			"public_key_hex": "abcd",
			"key_type": "example.generic-policy.v1",
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
	expected := expectedSDKContractFixtureNames(t)
	if got := committedSDKContractFixtureNames(t); !reflect.DeepEqual(got, expected) {
		t.Fatalf("contract fixture manifest mismatch\nwant: %#v\n got: %#v", expected, got)
	}
	for _, name := range expected {
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

func TestGoSDKContractErrorCodes(t *testing.T) {
	var fixture contractErrorCodesFixture
	readContractMetadata(t, contractErrorCodesFixtureName, &fixture)
	if fixture.SchemaVersion != contractFixtureSchemaVersion {
		t.Fatalf("%s schema_version = %d, want %d", contractErrorCodesFixtureName, fixture.SchemaVersion, contractFixtureSchemaVersion)
	}
	assertStringSetEqual(t, "signer API error codes", signerAPIErrorCodes(t), fixture.Codes)
}

func TestGoSDKContractErrorClassifications(t *testing.T) {
	var fixture contractErrorClassificationsFixture
	readContractMetadata(t, contractErrorClassificationsFileName, &fixture)
	if fixture.SchemaVersion != contractFixtureSchemaVersion {
		t.Fatalf("%s schema_version = %d, want %d", contractErrorClassificationsFileName, fixture.SchemaVersion, contractFixtureSchemaVersion)
	}

	var classifiedCodes []string
	for code, class := range fixture.Classifications {
		if strings.TrimSpace(class) == "" {
			t.Fatalf("%s has empty classification for code %q", contractErrorClassificationsFileName, code)
		}
		classifiedCodes = append(classifiedCodes, code)
	}
	assertStringSetEqual(t, "signer API error classifications", signerAPIErrorCodes(t), classifiedCodes)
}

func TestGoSDKContractHashManifest(t *testing.T) {
	want := readContractHashManifest(t)
	got := computeContractHashes(t)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("contract fixture hash manifest mismatch\nwant: %#v\n got: %#v", want, got)
	}
}

func signerAPIErrorCodes(t *testing.T) []string {
	t.Helper()
	return []string{
		ErrCodeBadRequest,
		ErrCodeUnauthorized,
		ErrCodeForbidden,
		ErrCodeLocked,
		ErrCodeNotFound,
		ErrCodeInvalidPassphrase,
		ErrCodeUnavailable,
		ErrCodeCacheRefresh,
		ErrCodeInternal,
		ErrCodeBoundedAdminRequired,
	}
}

func assertStringSetEqual(t *testing.T, label string, want, got []string) {
	t.Helper()
	wantSorted := sortedUniqueStrings(t, label+" want", want)
	gotSorted := sortedUniqueStrings(t, label+" got", got)
	if !reflect.DeepEqual(gotSorted, wantSorted) {
		t.Fatalf("%s mismatch\nwant: %#v\n got: %#v", label, wantSorted, gotSorted)
	}
}

func sortedUniqueStrings(t *testing.T, label string, values []string) []string {
	t.Helper()
	seen := make(map[string]struct{}, len(values))
	out := append([]string(nil), values...)
	sort.Strings(out)
	for _, value := range out {
		if strings.TrimSpace(value) == "" {
			t.Fatalf("%s contains an empty value", label)
		}
		if _, ok := seen[value]; ok {
			t.Fatalf("%s contains duplicate value %q", label, value)
		}
		seen[value] = struct{}{}
	}
	return out
}

func readContractHashManifest(t *testing.T) map[string]string {
	t.Helper()
	file, err := os.Open(sdkContractFixturePath(t, contractFixtureHashManifestName))
	if err != nil {
		t.Fatalf("open %s: %v", contractFixtureHashManifestName, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Fatalf("close %s: %v", contractFixtureHashManifestName, err)
		}
	}()

	hashes := map[string]string{}
	scanner := bufio.NewScanner(file)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("%s:%d: expected '<sha256>  <filename>', got %q", contractFixtureHashManifestName, lineNo, line)
		}
		hash, name := fields[0], fields[1]
		if len(hash) != sha256.Size*2 {
			t.Fatalf("%s:%d: invalid sha256 length for %q", contractFixtureHashManifestName, lineNo, name)
		}
		if _, err := hex.DecodeString(hash); err != nil {
			t.Fatalf("%s:%d: invalid sha256 for %q: %v", contractFixtureHashManifestName, lineNo, name, err)
		}
		if name == contractFixtureHashManifestName {
			t.Fatalf("%s:%d: hash manifest must not include itself", contractFixtureHashManifestName, lineNo)
		}
		if filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
			t.Fatalf("%s:%d: expected base filename, got %q", contractFixtureHashManifestName, lineNo, name)
		}
		if _, exists := hashes[name]; exists {
			t.Fatalf("%s:%d: duplicate hash entry for %q", contractFixtureHashManifestName, lineNo, name)
		}
		hashes[name] = hash
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", contractFixtureHashManifestName, err)
	}
	return hashes
}

func computeContractHashes(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(sdkContractFixtureDir(t))
	if err != nil {
		t.Fatalf("read contract fixture dir: %v", err)
	}
	hashes := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == contractFixtureHashManifestName {
			continue
		}
		raw, err := os.ReadFile(sdkContractFixturePath(t, entry.Name()))
		if err != nil {
			t.Fatalf("read contract fixture file %s: %v", entry.Name(), err)
		}
		sum := sha256.Sum256(raw)
		hashes[entry.Name()] = hex.EncodeToString(sum[:])
	}
	return hashes
}
