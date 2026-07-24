// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

const (
	ClientEndpointsFile       = "endpoints.yaml"
	DefaultClientEndpointName = "primary"

	ClientEndpointRoleSigner = "signer"
	ClientEndpointRoleSentry = "sentry"
)

// ClientEndpointRegistry stores client-local endpoint profiles.
type ClientEndpointRegistry struct {
	SchemaVersion int                             `yaml:"schema_version"`
	Default       string                          `yaml:"default,omitempty"`
	Endpoints     map[string]ClientEndpointConfig `yaml:"endpoints,omitempty"`
}

// ClientEndpointConfig describes one signer or sentry connection profile.
type ClientEndpointConfig struct {
	Role              string                                   `yaml:"role"`
	URL               string                                   `yaml:"url"`
	SignerPort        int                                      `yaml:"signer_port,omitempty"`
	LocalPort         int                                      `yaml:"local_port,omitempty"`
	IdentityFile      string                                   `yaml:"identity_file,omitempty"`
	KnownHostsPath    string                                   `yaml:"known_hosts_path,omitempty"`
	TokenFile         string                                   `yaml:"token_file,omitempty"`
	PublishedSentries map[string]ClientEndpointPublishedSentry `yaml:"published_sentries,omitempty"`
}

// ClientEndpointPublishedSentry is endpoint-local sentry discovery metadata.
type ClientEndpointPublishedSentry struct {
	ComponentKey string `yaml:"component_key"`
	KeyType      string `yaml:"key_type"`
	LastSeenAt   string `yaml:"last_seen_at,omitempty"`
}

// LoadClientEndpointRegistry loads and normalizes dataDir/endpoints.yaml.
func LoadClientEndpointRegistry(dataDir string) (*ClientEndpointRegistry, error) {
	registry := &ClientEndpointRegistry{
		SchemaVersion: 1,
		Endpoints:     map[string]ClientEndpointConfig{},
	}
	endpointsPath := filepath.Join(dataDir, ClientEndpointsFile)
	data, err := os.ReadFile(endpointsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return registry, nil
		}
		return nil, fmt.Errorf("failed to read %s: %w", endpointsPath, err)
	}
	if err := validateClientEndpointRegistryScalarTypes(data); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", endpointsPath, err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(registry); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", endpointsPath, err)
	}
	if registry.SchemaVersion == 0 {
		registry.SchemaVersion = 1
	}
	if registry.SchemaVersion != 1 {
		return nil, fmt.Errorf("%s schema_version = %d, want 1", ClientEndpointsFile, registry.SchemaVersion)
	}
	if registry.Endpoints == nil {
		registry.Endpoints = map[string]ClientEndpointConfig{}
	}

	for alias, endpoint := range registry.Endpoints {
		if err := validateClientEndpointAlias(alias); err != nil {
			return nil, fmt.Errorf("endpoint %q: %w", alias, err)
		}
		normalized, err := normalizeClientEndpoint(dataDir, alias, endpoint)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q: %w", alias, err)
		}
		registry.Endpoints[alias] = normalized
	}
	if err := normalizeClientEndpointRoles(registry); err != nil {
		return nil, err
	}
	return registry, nil
}

func validateClientEndpointRegistryScalarTypes(data []byte) error {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return err
	}
	if err := rejectUnknownYAMLTags(&document); err != nil {
		return err
	}
	if len(document.Content) == 0 {
		return nil
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}

	if err := requireYAMLScalarType(yamlMappingValue(root, "schema_version"), "schema_version", "!!int", "!!null"); err != nil {
		return err
	}
	if err := requireYAMLScalarType(yamlMappingValue(root, "default"), "default", "!!str", "!!null"); err != nil {
		return err
	}
	endpoints := yamlMappingValue(root, "endpoints")
	if endpoints == nil || endpoints.ShortTag() == "!!null" || endpoints.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(endpoints.Content); i += 2 {
		alias := endpoints.Content[i]
		endpoint := endpoints.Content[i+1]
		if err := requireYAMLScalarType(alias, "endpoint alias", "!!str"); err != nil {
			return err
		}
		if endpoint.Kind != yaml.MappingNode {
			continue
		}
		label := fmt.Sprintf("endpoint %q", alias.Value)
		for _, field := range []string{"role", "url", "identity_file", "known_hosts_path", "token_file"} {
			if err := requireYAMLScalarType(yamlMappingValue(endpoint, field), label+" "+field, "!!str", "!!null"); err != nil {
				return err
			}
		}
		for _, field := range []string{"signer_port", "local_port"} {
			if err := requireYAMLScalarType(yamlMappingValue(endpoint, field), label+" "+field, "!!int", "!!null"); err != nil {
				return err
			}
		}
		published := yamlMappingValue(endpoint, "published_sentries")
		if published == nil || published.ShortTag() == "!!null" || published.Kind != yaml.MappingNode {
			continue
		}
		for j := 0; j+1 < len(published.Content); j += 2 {
			entry := published.Content[j+1]
			if entry.Kind != yaml.MappingNode {
				continue
			}
			for _, field := range []string{"component_key", "key_type", "last_seen_at"} {
				if err := requireYAMLScalarType(yamlMappingValue(entry, field), "published sentry "+field, "!!str", "!!null"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func rejectUnknownYAMLTags(node *yaml.Node) error {
	tag := node.ShortTag()
	if strings.HasPrefix(tag, "!") && !strings.HasPrefix(tag, "!!") {
		return fmt.Errorf("unsupported YAML tag %q", tag)
	}
	for _, child := range node.Content {
		if err := rejectUnknownYAMLTags(child); err != nil {
			return err
		}
	}
	return nil
}

func yamlMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func requireYAMLScalarType(node *yaml.Node, label string, allowed ...string) error {
	if node == nil {
		return nil
	}
	tag := node.ShortTag()
	for _, candidate := range allowed {
		if tag == candidate {
			return nil
		}
	}
	return fmt.Errorf("%s must be %s, got %s", label, strings.Join(allowed, " or "), tag)
}

func validateClientEndpointAlias(alias string) error {
	if alias == "" {
		return fmt.Errorf("alias is required")
	}
	for _, r := range alias {
		if r <= 127 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-') {
			continue
		}
		return fmt.Errorf("alias %q must contain only ASCII letters, digits, '.', '_', or '-'", alias)
	}
	return nil
}

func normalizeClientEndpoint(dataDir, alias string, endpoint ClientEndpointConfig) (ClientEndpointConfig, error) {
	endpoint.Role = strings.TrimSpace(endpoint.Role)
	if endpoint.Role != ClientEndpointRoleSigner && endpoint.Role != ClientEndpointRoleSentry {
		return endpoint, fmt.Errorf("unsupported role %q (expected %q or %q)", endpoint.Role, ClientEndpointRoleSigner, ClientEndpointRoleSentry)
	}
	endpoint.URL = strings.TrimRight(strings.TrimSpace(endpoint.URL), "/")
	if endpoint.URL == "" {
		return endpoint, fmt.Errorf("url is required")
	}
	if err := validateClientEndpointURL(alias, endpoint); err != nil {
		return endpoint, err
	}
	if endpoint.TokenFile == "" && endpoint.URL != "self" {
		if alias == DefaultClientEndpointName {
			endpoint.TokenFile = "aplane.token"
		} else {
			endpoint.TokenFile = filepath.Join("tokens", alias+".token")
		}
	}
	endpoint.TokenFile = ResolvePath(endpoint.TokenFile, dataDir)
	if strings.HasPrefix(endpoint.URL, "ssh://") {
		if endpoint.SignerPort == 0 {
			endpoint.SignerPort = DefaultSignerPort
		}
		if endpoint.IdentityFile == "" {
			endpoint.IdentityFile = ".ssh/id_ed25519"
		}
		if endpoint.KnownHostsPath == "" {
			endpoint.KnownHostsPath = ".ssh/known_hosts"
		}
		endpoint.IdentityFile = ResolvePath(endpoint.IdentityFile, dataDir)
		endpoint.KnownHostsPath = ResolvePath(endpoint.KnownHostsPath, dataDir)
	}
	if endpoint.Role != ClientEndpointRoleSentry && len(endpoint.PublishedSentries) > 0 {
		return endpoint, fmt.Errorf("published_sentries are only valid on %q endpoints", ClientEndpointRoleSentry)
	}
	return endpoint, nil
}

func validateClientEndpointURL(alias string, endpoint ClientEndpointConfig) error {
	if endpoint.SignerPort < 0 || endpoint.SignerPort > 65535 {
		return fmt.Errorf("signer_port must be 1-65535 when set")
	}
	if endpoint.LocalPort < 0 || endpoint.LocalPort > 65535 {
		return fmt.Errorf("local_port must be 1-65535 when set")
	}
	if endpoint.URL == "self" {
		return nil
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	switch parsed.Scheme {
	case "ssh", "https", "http":
	default:
		return fmt.Errorf("unsupported url scheme %q", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("url host is required")
	}
	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("invalid url port %q", parsed.Port())
		}
	}
	if parsed.Scheme == "http" && !isLoopbackEndpointHost(parsed.Hostname()) {
		return fmt.Errorf("raw http endpoints must be loopback; use ssh:// or https:// for remote endpoint %q", alias)
	}
	return nil
}

func isLoopbackEndpointHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizeClientEndpointRoles(registry *ClientEndpointRegistry) error {
	registry.Default = strings.TrimSpace(registry.Default)
	if registry.Default != "" {
		if err := validateClientEndpointAlias(registry.Default); err != nil {
			return fmt.Errorf("%s default: %w", ClientEndpointsFile, err)
		}
	}
	signerAlias := ""
	for alias, endpoint := range registry.Endpoints {
		if endpoint.Role != ClientEndpointRoleSigner {
			continue
		}
		if signerAlias != "" {
			return fmt.Errorf("%s may contain at most one %q endpoint (found %q and %q)", ClientEndpointsFile, ClientEndpointRoleSigner, signerAlias, alias)
		}
		signerAlias = alias
	}
	if signerAlias == "" {
		if registry.Default != "" {
			return fmt.Errorf("%s default endpoint %q is set but no %q endpoint is configured", ClientEndpointsFile, registry.Default, ClientEndpointRoleSigner)
		}
		return nil
	}
	if registry.Default != "" && registry.Default != signerAlias {
		return fmt.Errorf("%s default endpoint %q must be the %q endpoint %q", ClientEndpointsFile, registry.Default, ClientEndpointRoleSigner, signerAlias)
	}
	registry.Default = signerAlias
	return nil
}

// ResolveClientEndpoint selects an explicit alias or the default signer.
func ResolveClientEndpoint(registry *ClientEndpointRegistry, alias string) (string, ClientEndpointConfig, error) {
	if registry == nil {
		return "", ClientEndpointConfig{}, fmt.Errorf("%s registry is required", ClientEndpointsFile)
	}
	if alias == "" {
		alias = registry.Default
		if alias == "" {
			return "", ClientEndpointConfig{}, fmt.Errorf("%s has no default signer endpoint", ClientEndpointsFile)
		}
	}
	endpoint, ok := registry.Endpoints[alias]
	if !ok {
		return "", ClientEndpointConfig{}, fmt.Errorf("endpoint alias %q is not defined", alias)
	}
	return alias, endpoint, nil
}

// ClientEndpointSSHHostPort resolves host and SSH port from an ssh:// endpoint.
func ClientEndpointSSHHostPort(endpoint ClientEndpointConfig) (string, int, error) {
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return "", 0, fmt.Errorf("invalid endpoint URL: %w", err)
	}
	if parsed.Scheme != "ssh" {
		return "", 0, fmt.Errorf("endpoint %q requires ssh://", endpoint.URL)
	}
	port := DefaultSSHPort
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil {
			return "", 0, fmt.Errorf("invalid SSH port %q", parsed.Port())
		}
	}
	return parsed.Hostname(), port, nil
}
