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
	if registry.Default != "primary" {
		t.Fatalf("Default = %q, want primary", registry.Default)
	}
	primary := registry.Endpoints["primary"]
	if primary.URL != "ssh://signer.example.com:2222" {
		t.Fatalf("URL = %q", primary.URL)
	}
	if primary.SignerPort != 11271 || primary.LocalPort != 18080 {
		t.Fatalf("ports = signer %d local %d", primary.SignerPort, primary.LocalPort)
	}
	if primary.IdentityFile != filepath.Join(dataDir, ".ssh", "primary") {
		t.Fatalf("IdentityFile = %q", primary.IdentityFile)
	}
	if primary.TokenFile != filepath.Join(dataDir, "aplane.token") {
		t.Fatalf("TokenFile = %q", primary.TokenFile)
	}
	sentry := registry.Endpoints["sentry.qa"]
	if sentry.URL != "https://sentry.example.com" {
		t.Fatalf("sentry URL = %q", sentry.URL)
	}
	if sentry.TokenFile != filepath.Join(dataDir, "credentials", "sentry.token") {
		t.Fatalf("sentry TokenFile = %q", sentry.TokenFile)
	}
}

func TestLoadClientEndpointRegistryRejectsSharedInvalidFixtures(t *testing.T) {
	for _, name := range []string{
		"invalid_multiple_signers.yaml",
		"invalid_remote_http.yaml",
		"invalid_ssh_port_zero.yaml",
		"invalid_unknown_field.yaml",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadClientEndpointRegistry(copyEndpointFixture(t, name))
			if err == nil {
				t.Fatal("expected fixture rejection")
			}
		})
	}
}

func TestLoadClientEndpointRegistryDerivesSignerDefaultAndTokenPaths(t *testing.T) {
	dataDir := t.TempDir()
	data := []byte(`
schema_version: 1
endpoints:
  main:
    role: signer
    url: ssh://localhost
  qa:
    role: sentry
    url: http://127.0.0.1:11271
`)
	if err := os.WriteFile(filepath.Join(dataDir, ClientEndpointsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if registry.Default != "main" {
		t.Fatalf("Default = %q, want main", registry.Default)
	}
	if got := registry.Endpoints["main"].TokenFile; got != filepath.Join(dataDir, "tokens", "main.token") {
		t.Fatalf("main token path = %q", got)
	}
	if got := registry.Endpoints["qa"].TokenFile; got != filepath.Join(dataDir, "tokens", "qa.token") {
		t.Fatalf("qa token path = %q", got)
	}
}

func TestResolveClientEndpoint(t *testing.T) {
	registry := &ClientEndpointRegistry{
		Default: "primary",
		Endpoints: map[string]ClientEndpointConfig{
			"primary": {Role: ClientEndpointRoleSigner},
			"sentry":  {Role: ClientEndpointRoleSentry},
		},
	}
	alias, endpoint, err := ResolveClientEndpoint(registry, "")
	if err != nil || alias != "primary" || endpoint.Role != ClientEndpointRoleSigner {
		t.Fatalf("default resolution = %q %+v %v", alias, endpoint, err)
	}
	alias, endpoint, err = ResolveClientEndpoint(registry, "sentry")
	if err != nil || alias != "sentry" || endpoint.Role != ClientEndpointRoleSentry {
		t.Fatalf("explicit resolution = %q %+v %v", alias, endpoint, err)
	}
	_, _, err = ResolveClientEndpoint(registry, "missing")
	if err == nil || !strings.Contains(err.Error(), "not defined") {
		t.Fatalf("expected unknown alias error, got %v", err)
	}
}
