// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig_WithClientRuntimeFields(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
network: mainnet
networks_allowed: [mainnet, testnet]
theme: light
networks:
  mainnet:
    algod:
      server: https://mainnet-api.example.com
      token: abc123
`), 0o600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Network != "mainnet" {
		t.Fatalf("expected mainnet, got %q", cfg.Network)
	}
	if !cfg.IsNetworkAllowed("testnet") {
		t.Fatal("expected testnet to be allowed")
	}
	if cfg.Theme != "light" {
		t.Fatalf("expected light theme, got %q", cfg.Theme)
	}
	algodCfg, err := cfg.GetAlgodConfig("mainnet")
	if err != nil {
		t.Fatalf("GetAlgodConfig: %v", err)
	}
	if algodCfg.Server != "https://mainnet-api.example.com" {
		t.Fatalf("unexpected algod server %q", algodCfg.Server)
	}
	if algodCfg.Token != "abc123" {
		t.Fatalf("unexpected algod token %q", algodCfg.Token)
	}
}

func TestLoadConfig_RejectsInvalidNetworks(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
network: InvalidNet
`), 0o600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = LoadConfig(dir)
	if err == nil || !strings.Contains(err.Error(), `invalid network in config.yaml`) {
		t.Fatalf("expected invalid network error, got %v", err)
	}
}

func TestLoadConfig_AcceptsCustomNetworkToken(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
network: voi_mainnet
networks_allowed: [voi_mainnet]
networks:
  voi_mainnet:
    algod:
      server: http://localhost:4001
      token: token
`), 0o600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Network != "voi_mainnet" {
		t.Fatalf("Network = %q, want voi_mainnet", cfg.Network)
	}
	if cfg.Algod["voi_mainnet"].Server != "http://localhost:4001" {
		t.Fatalf("unexpected algod config: %+v", cfg.Algod["voi_mainnet"])
	}
}

func TestLoadConfig_AcceptsGroupedNetworkAlgod(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
network: voi_mainnet
networks_allowed: [voi_mainnet]
networks:
  voi_mainnet:
    algod:
      server: http://localhost:4001
      token: token
`), 0o600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	algodCfg, err := cfg.GetAlgodConfig("voi_mainnet")
	if err != nil {
		t.Fatalf("GetAlgodConfig: %v", err)
	}
	if algodCfg.Server != "http://localhost:4001" {
		t.Fatalf("unexpected algod server %q", algodCfg.Server)
	}
}

func TestLoadConfig_RejectsNetworksAllowedMismatch(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
network: mainnet
networks_allowed: [testnet]
`), 0o600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = LoadConfig(dir)
	if err == nil || !strings.Contains(err.Error(), `network "mainnet" is not in networks_allowed`) {
		t.Fatalf("expected networks_allowed mismatch, got %v", err)
	}
}

func TestLoadConfig_RejectsInvalidAlgodKey(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
networks:
  invalid/net:
    algod:
      server: https://example.com
`), 0o600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = LoadConfig(dir)
	if err == nil || !strings.Contains(err.Error(), `invalid network in networks config`) {
		t.Fatalf("expected invalid network error, got %v", err)
	}
}

func TestGetAlgodConfig_ErrorsWhenMissing(t *testing.T) {
	cfg := &Config{}
	_, err := cfg.GetAlgodConfig("testnet")
	if err == nil || !strings.Contains(err.Error(), "algod not configured") {
		t.Fatalf("expected missing algod error, got %v", err)
	}
}

func TestNewAlgodClient_ErrorsWhenMissing(t *testing.T) {
	cfg := &Config{}
	_, err := cfg.NewAlgodClient("testnet")
	if err == nil || !strings.Contains(err.Error(), "algod not configured") {
		t.Fatalf("expected missing algod error, got %v", err)
	}
}

func TestResolveDataDir_ErrorsWhenUnset(t *testing.T) {
	t.Setenv("APCLIENT_DATA", "")
	dir, err := ResolveDataDir("")
	if err == nil {
		t.Fatal("expected error when neither param nor env set")
	}
	if dir != "" {
		t.Fatalf("expected empty dir on error, got %q", dir)
	}
}

func TestResolveDataDir_PrefersParam(t *testing.T) {
	t.Setenv("APCLIENT_DATA", "/from/env")
	dir, err := ResolveDataDir("/from/param")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dir != "/from/param" {
		t.Fatalf("expected /from/param, got %q", dir)
	}
}

func TestResolveDataDir_FallsBackToEnv(t *testing.T) {
	t.Setenv("APCLIENT_DATA", "/from/env")
	dir, err := ResolveDataDir("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dir != "/from/env" {
		t.Fatalf("expected /from/env, got %q", dir)
	}
}

func TestNewAlgodClient_SucceedsWithConfiguredNetwork(t *testing.T) {
	cfg := &Config{
		Algod: AlgodConfig{
			"testnet": {Server: "https://algod.example.com", Token: "abc"},
		},
	}
	client, err := cfg.NewAlgodClient("testnet")
	if err != nil {
		t.Fatalf("NewAlgodClient: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil algod client")
	}
}

// config.yaml is read as apshell reads it: every field apshell knows is
// accepted, and any other, the retired signer routing included, is refused
// as an unknown field with apshell's words.
func TestLoadConfigReadsTheFieldsApshellKnows(t *testing.T) {
	for _, tc := range []struct {
		name, body, unknown string
	}{
		{"apshell's fields", "network: testnet\nnetworks_allowed: [testnet]\ntheme: dark\nsigner_status_poll_interval: 10s\nnetworks:\n  testnet:\n    algod:\n      server: http://localhost:4001\n      token: t\n", ""},
		{"endpoint routing", "endpoint:\n  ssh:\n    host: signer.example.com\n", "endpoint"},
		{"ssh routing", "ssh:\n  host: signer.example.com\n", "ssh"},
		{"signer_port routing", "network: testnet\nsigner_port: 11270\n", "signer_port"},
		{"top-level algod", "algod:\n  testnet:\n    server: http://localhost:4001\n", "algod"},
		{"another unknown field", "network: testnet\nfoo: 1\n", "foo"},
		{"the retired schema_version", "schema_version: 1\nnetwork: testnet\n", "schema_version"},
		{"an unknown network setting", "networks:\n  testnet:\n    indexer:\n      server: http://localhost:8980\n", "indexer"},
		{"an unknown algod setting", "networks:\n  testnet:\n    algod:\n      server: http://localhost:4001\n      headers: {}\n", "headers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(dir)
			if tc.unknown == "" {
				if err != nil || cfg.Theme != "dark" || cfg.Algod["testnet"] == nil || cfg.Algod["testnet"].Server != "http://localhost:4001" {
					t.Fatalf("LoadConfig() = %+v, %v; want apshell's fields read", cfg, err)
				}
				return
			}
			want := `config field "` + tc.unknown + `" is unknown or no longer supported; remove it from the file`
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("LoadConfig() error = %v, want %q", err, want)
			}
		})
	}
}
