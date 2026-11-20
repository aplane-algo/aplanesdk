// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func copyEndpointFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "contracts", "clientconfig", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, ClientEndpointsFile), data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return dataDir
}

func TestLoadClientEndpointRegistrySharedFixture(t *testing.T) {
	dataDir := copyEndpointFixture(t, "valid.yaml")
	registry, err := LoadClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatalf("LoadClientEndpointRegistry: %v", err)
	}
	if alias, _, err := ResolveClientEndpoint(registry, ""); err != nil || alias != "primary" {
		t.Fatalf("ResolveClientEndpoint(\"\") = %q, %v; want the signer endpoint primary", alias, err)
	}
	primary := registry.Endpoints["primary"]
	if primary.URL != "ssh://signer.example.com:2222" {
		t.Fatalf("URL = %q", primary.URL)
	}
	if primary.IdentityFile != filepath.Join(dataDir, ".ssh", "primary") {
		t.Fatalf("IdentityFile = %q", primary.IdentityFile)
	}
	cosigner := registry.Endpoints["cosigner.qa"]
	if cosigner.URL != "ssh://cosigner.example.com" {
		t.Fatalf("cosigner URL = %q", cosigner.URL)
	}
	if cosigner.IdentityFile != filepath.Join(dataDir, "credentials", "cosigner") {
		t.Fatalf("cosigner IdentityFile = %q", cosigner.IdentityFile)
	}
	if cosigner.KnownHostsPath != filepath.Join(dataDir, ".ssh", "known_hosts") {
		t.Fatalf("cosigner KnownHostsPath = %q", cosigner.KnownHostsPath)
	}
}

func TestLoadClientEndpointRegistryRejectsSharedInvalidFixtures(t *testing.T) {
	for _, name := range []string{
		"invalid_default_field.yaml",
		"invalid_identity_file_type.yaml",
		"invalid_multiple_signers.yaml",
		"invalid_remote_http.yaml",
		"invalid_loopback_http.yaml",
		"invalid_https.yaml",
		"invalid_schema_version_float.yaml",
		"invalid_ssh_port_zero.yaml",
		"invalid_unknown_field.yaml",
		"invalid_unknown_tag.yaml",
		"invalid_retired_port_fields.yaml",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadClientEndpointRegistry(copyEndpointFixture(t, name))
			if err == nil {
				t.Fatal("expected fixture rejection")
			}
		})
	}
}

func TestLoadClientEndpointRegistryRequiresSchemaVersion2(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		want    string
	}{
		{"invalid_schema_version_missing.yaml", "endpoints.yaml schema_version = 0, want 2"},
		{"invalid_schema_version_zero.yaml", "endpoints.yaml schema_version = 0, want 2"},
		{"invalid_schema_version_one.yaml", "endpoints.yaml schema_version = 1, want 2"},
		{"invalid_v1_published_cosigners.yaml", "endpoints.yaml schema_version = 1, want 2"},
		{"invalid_schema_version_null.yaml", "schema_version must be !!int, got !!null"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			_, err := LoadClientEndpointRegistry(copyEndpointFixture(t, tc.fixture))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadClientEndpointRegistry error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadClientEndpointRegistryRejectsSpecificEndpointRules(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		want    string
	}{
		{"invalid_self_signer.yaml", `endpoint "primary": url "self" is not supported`},
		{"invalid_self_cosigner.yaml", `endpoint "cosigner": url "self" is not supported`},
		{"invalid_13_cosigner_endpoints.yaml", "configures 13 cosigner endpoints; maximum is 12"},
		{"invalid_v2_published_cosigners.yaml", "published_cosigners"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			_, err := LoadClientEndpointRegistry(copyEndpointFixture(t, tc.fixture))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadClientEndpointRegistry error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadClientEndpointRegistryAcceptsSharedEdgeFixtures(t *testing.T) {
	for _, name := range []string{
		"valid_12_cosigner_endpoints.yaml",
	} {
		t.Run(name, func(t *testing.T) {
			dataDir := copyEndpointFixture(t, name)
			registry, err := LoadClientEndpointRegistry(dataDir)
			if err != nil {
				t.Fatalf("LoadClientEndpointRegistry: %v", err)
			}
			if registry.SchemaVersion != ClientEndpointSchemaVersion {
				t.Fatalf("SchemaVersion = %d, want %d", registry.SchemaVersion, ClientEndpointSchemaVersion)
			}
			if name == "valid_12_cosigner_endpoints.yaml" && len(registry.Endpoints) != 12 {
				t.Fatalf("endpoint count = %d, want 12", len(registry.Endpoints))
			}
		})
	}
}

func TestLoadClientEndpointRegistryDerivesSignerDefaultAndIdentityPaths(t *testing.T) {
	dataDir := t.TempDir()
	data := []byte(`
schema_version: 2
endpoints:
  main:
    role: signer
    url: ssh://localhost
  qa:
    role: cosigner
    url: ssh://127.0.0.1:2222
`)
	if err := os.WriteFile(filepath.Join(dataDir, ClientEndpointsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if alias, _, err := ResolveClientEndpoint(registry, ""); err != nil || alias != "main" {
		t.Fatalf("ResolveClientEndpoint(\"\") = %q, %v; want the signer endpoint main", alias, err)
	}
	for _, alias := range []string{"main", "qa"} {
		endpoint := registry.Endpoints[alias]
		if endpoint.IdentityFile != filepath.Join(dataDir, ".ssh", "id_ed25519") || endpoint.KnownHostsPath != filepath.Join(dataDir, ".ssh", "known_hosts") {
			t.Fatalf("%s identity = %#v, want the default client identity", alias, endpoint)
		}
	}
}

func TestResolveClientEndpoint(t *testing.T) {
	registry := &ClientEndpointRegistry{
		Endpoints: map[string]ClientEndpointConfig{
			"primary":  {Role: ClientEndpointRoleSigner},
			"cosigner": {Role: ClientEndpointRoleCosigner},
		},
	}
	alias, endpoint, err := ResolveClientEndpoint(registry, "")
	if err != nil || alias != "primary" || endpoint.Role != ClientEndpointRoleSigner {
		t.Fatalf("default resolution = %q %+v %v", alias, endpoint, err)
	}
	alias, endpoint, err = ResolveClientEndpoint(registry, "cosigner")
	if err != nil || alias != "cosigner" || endpoint.Role != ClientEndpointRoleCosigner {
		t.Fatalf("explicit resolution = %q %+v %v", alias, endpoint, err)
	}
	_, _, err = ResolveClientEndpoint(registry, "missing")
	if err == nil || !strings.Contains(err.Error(), "not defined") {
		t.Fatalf("expected unknown alias error, got %v", err)
	}
	cosignerOnly := &ClientEndpointRegistry{Endpoints: map[string]ClientEndpointConfig{"cosigner": {Role: ClientEndpointRoleCosigner}}}
	if _, _, err := ResolveClientEndpoint(cosignerOnly, ""); err == nil || !strings.Contains(err.Error(), "has no default signer endpoint") {
		t.Fatalf("a registry without a signer endpoint = %v, want no default signer endpoint", err)
	}
}

// A registry names its signer by role alone: a default key is an unknown
// field, refused as APlane refuses it.
func TestLoadClientEndpointRegistryRefusesADefaultKey(t *testing.T) {
	_, err := LoadClientEndpointRegistry(copyEndpointFixture(t, "invalid_default_field.yaml"))
	if err == nil || !strings.Contains(err.Error(), "field default not found") {
		t.Fatalf("LoadClientEndpointRegistry error = %v, want default refused as an unknown field", err)
	}
}
