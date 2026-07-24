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
algod:
  mainnet:
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

func TestLoadConfig_RejectsObsoleteEndpointRouting(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
endpoint:
  ssh:
    host: signer.example.com
`), 0o600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = LoadConfig(dir)
	if err == nil || !strings.Contains(err.Error(), `configure endpoints.yaml`) {
		t.Fatalf("expected endpoints.yaml migration error, got %v", err)
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
algod:
  voi_mainnet:
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
algod:
  invalid/net:
    server: https://example.com
`), 0o600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = LoadConfig(dir)
	if err == nil || !strings.Contains(err.Error(), `invalid network in algod config`) {
		t.Fatalf("expected invalid algod network error, got %v", err)
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
