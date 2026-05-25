// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"gopkg.in/yaml.v3"
)

// Default ports matching apsigner defaults.
const (
	DefaultSignerPort = 11270
	DefaultSSHPort    = 1127
	DefaultTimeout    = 90 // seconds
)

const maxNetworkIDLength = 64

func validateNetworkID(id string) error {
	if id == "" {
		return fmt.Errorf("network id is required")
	}
	if len(id) > maxNetworkIDLength {
		return fmt.Errorf("network id %q is too long (max %d characters)", id, maxNetworkIDLength)
	}
	for i, r := range id {
		valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-'
		if !valid {
			return fmt.Errorf("invalid network id %q (use lowercase letters, digits, '_' or '-', starting with a letter or digit)", id)
		}
		if i == 0 && (r == '_' || r == '-') {
			return fmt.Errorf("invalid network id %q (use lowercase letters, digits, '_' or '-', starting with a letter or digit)", id)
		}
	}
	return nil
}

// ExpandPath expands ~ to the user's home directory.
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[1:])
	}
	return path
}

// LoadConfig loads client configuration from dataDir/config.yaml.
func LoadConfig(dataDir string) (*Config, error) {
	config := &Config{
		Network:    "testnet",
		SignerPort: DefaultSignerPort,
		Theme:      "auto",
	}

	configPath := filepath.Join(dataDir, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil // Return defaults if no config file
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config.yaml: %w", err)
	}
	if config.Algod == nil && len(config.Networks) > 0 {
		config.Algod = make(AlgodConfig, len(config.Networks))
	}
	for network, networkConfig := range config.Networks {
		if err := validateNetworkID(network); err != nil {
			return nil, fmt.Errorf("invalid network in networks config: %w", err)
		}
		if networkConfig == nil || networkConfig.Algod == nil {
			continue
		}
		config.Algod[network] = networkConfig.Algod
	}

	if err := validateNetworkID(config.Network); err != nil {
		return nil, fmt.Errorf("invalid network in config.yaml: %w", err)
	}
	for _, network := range config.NetworksAllowed {
		if err := validateNetworkID(network); err != nil {
			return nil, fmt.Errorf("invalid network in networks_allowed: %w", err)
		}
	}
	if len(config.NetworksAllowed) > 0 && !config.IsNetworkAllowed(config.Network) {
		return nil, fmt.Errorf("network %q is not in networks_allowed %v", config.Network, config.NetworksAllowed)
	}
	for network := range config.Algod {
		if err := validateNetworkID(network); err != nil {
			return nil, fmt.Errorf("invalid network in algod config: %w", err)
		}
	}
	if config.SignerPort == 0 {
		config.SignerPort = DefaultSignerPort
	}
	if config.Theme == "" {
		config.Theme = "auto"
	}
	if config.SSH != nil {
		if config.SSH.Port == 0 {
			config.SSH.Port = DefaultSSHPort
		}
		if config.SSH.IdentityFile == "" {
			config.SSH.IdentityFile = ".ssh/id_ed25519"
		}
		if config.SSH.KnownHostsPath == "" {
			config.SSH.KnownHostsPath = ".ssh/known_hosts"
		}
		config.SSH.IdentityFile = ResolvePath(config.SSH.IdentityFile, dataDir)
		config.SSH.KnownHostsPath = ResolvePath(config.SSH.KnownHostsPath, dataDir)
	}

	return config, nil
}

// LoadToken loads the authentication token from the given path.
func LoadToken(tokenPath string) (string, error) {
	path := ExpandPath(tokenPath)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrTokenNotFound
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// LoadTokenFromDir loads the token from dataDir/aplane.token.
func LoadTokenFromDir(dataDir string) (string, error) {
	tokenPath := filepath.Join(dataDir, "aplane.token")
	return LoadToken(tokenPath)
}

// ResolveDataDir returns the data directory from parameter > APCLIENT_DATA env var.
// Returns an error when neither is set; the SDK has no implicit default.
func ResolveDataDir(dataDir string) (string, error) {
	if dataDir != "" {
		return ExpandPath(dataDir), nil
	}
	if envDir := os.Getenv("APCLIENT_DATA"); envDir != "" {
		return ExpandPath(envDir), nil
	}
	return "", fmt.Errorf("client data directory not specified: pass data_dir or set APCLIENT_DATA")
}

// ResolvePath expands a path and, if relative, resolves it against dataDir.
func ResolvePath(path, dataDir string) string {
	if path == "" {
		return ""
	}
	expanded := ExpandPath(path)
	if filepath.IsAbs(expanded) || dataDir == "" {
		return expanded
	}
	return filepath.Join(dataDir, expanded)
}

// IsNetworkAllowed reports whether the given network is permitted by config.
func (c *Config) IsNetworkAllowed(network string) bool {
	if len(c.NetworksAllowed) == 0 {
		return true
	}
	for _, allowed := range c.NetworksAllowed {
		if allowed == network {
			return true
		}
	}
	return false
}

// GetAlgodConfig returns the algod config for one configured network.
func (c *Config) GetAlgodConfig(network string) (*AlgodNetworkConfig, error) {
	if c.Algod == nil {
		return nil, fmt.Errorf("algod not configured")
	}
	cfg, ok := c.Algod[network]
	if !ok || cfg == nil {
		return nil, fmt.Errorf("algod not configured for network %s", network)
	}
	return cfg, nil
}

const algodRequestTimeout = 30 * time.Second

// NewAlgodClient returns an algod client for the configured network.
func (c *Config) NewAlgodClient(network string) (*algod.Client, error) {
	if c == nil {
		return nil, fmt.Errorf("algod not configured: no config provided")
	}
	algodConfig, err := c.GetAlgodConfig(network)
	if err != nil {
		return nil, fmt.Errorf("algod not configured for %s: %w", network, err)
	}
	if algodConfig.Server == "" {
		return nil, fmt.Errorf("algod not configured: algod.%s.server is empty in config.yaml", network)
	}
	var rt http.RoundTripper
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		transport := t.Clone()
		transport.ResponseHeaderTimeout = algodRequestTimeout
		rt = transport
	} else {
		rt = http.DefaultTransport
	}
	return algod.MakeClientWithTransport(algodConfig.Server, algodConfig.Token, nil, rt)
}
