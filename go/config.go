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
	DefaultSSHPort = 1127
	DefaultTimeout = 90 // seconds
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

// requireNetworkNameList requires networks_allowed to be a list of text
// entries. Decoding into []string would read a bare 1 or true as a network
// named "1" or "true" and drop a null, so the YAML is checked before it is
// turned into strings. An entry that is meant as a name made of digits must
// be quoted.
func requireNetworkNameList(listNode yaml.Node) error {
	node := resolveYAMLAlias(&listNode)
	if node.Kind == yaml.ScalarNode && node.ShortTag() == "!!null" {
		return nil
	}
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("networks_allowed in config.yaml must be a list of network IDs")
	}
	for _, entry := range node.Content {
		if item := resolveYAMLAlias(entry); item.Kind != yaml.ScalarNode || item.ShortTag() != "!!str" {
			return fmt.Errorf("invalid network in networks_allowed: entry on line %d is not text (quote it if it is a network ID)", entry.Line)
		}
	}
	return nil
}

// requireNetworkName requires the config's network to be text, the rule of the
// networks_allowed entries. yaml.v3 would decode a bare 1 or true into the
// string field as "1" or "true"; the Python and TypeScript loaders refuse
// them. A null keeps the default.
func requireNetworkName(nameNode yaml.Node) error {
	node := resolveYAMLAlias(&nameNode)
	if node.Kind == yaml.ScalarNode && (node.ShortTag() == "!!null" || node.ShortTag() == "!!str") {
		return nil
	}
	return fmt.Errorf("invalid network in config.yaml: the value on line %d is not text (quote it if it is a network ID)", nameNode.Line)
}

// resolveYAMLAlias follows an alias (*name) to the node it stands for, so a
// value is checked for what it is however the file spells it.
func resolveYAMLAlias(node *yaml.Node) *yaml.Node {
	for node.Kind == yaml.AliasNode && node.Alias != nil {
		node = node.Alias
	}
	return node
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
		Network: "testnet",
		Theme:   "auto",
	}

	configPath := filepath.Join(dataDir, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil // Return defaults if no config file
		}
		return nil, err
	}

	var raw map[string]yaml.Node
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse config.yaml: %w", err)
	}
	for _, field := range []string{"endpoint", "ssh", "signer_port"} {
		if _, ok := raw[field]; ok {
			return nil, fmt.Errorf("unsupported client routing in config.yaml: remove %q and configure endpoints.yaml", field)
		}
	}
	if node, ok := raw["network"]; ok {
		if err := requireNetworkName(node); err != nil {
			return nil, err
		}
	}
	if node, ok := raw["networks_allowed"]; ok {
		if err := requireNetworkNameList(node); err != nil {
			return nil, err
		}
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
	if config.Theme == "" {
		config.Theme = "auto"
	}

	return config, nil
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
	// networks_allowed is the operator's list of networks this client may
	// work on. It is enforced here, where a client for a named network is
	// made, and not only for the default network at load.
	if !c.IsNetworkAllowed(network) {
		return nil, fmt.Errorf("network %q is not in networks_allowed %v", network, c.NetworksAllowed)
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
