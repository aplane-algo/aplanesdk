// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"fmt"
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

	ClientEndpointRoleSigner   = "signer"
	ClientEndpointRoleCosigner = "cosigner"

	ClientEndpointSchemaVersion = 2
	MaxClientCosignerEndpoints  = 12
)

// ClientEndpointRegistry stores client-local endpoint profiles.
type ClientEndpointRegistry struct {
	SchemaVersion int                             `yaml:"schema_version"`
	Default       string                          `yaml:"default,omitempty"`
	Endpoints     map[string]ClientEndpointConfig `yaml:"endpoints,omitempty"`
}

// ClientEndpointConfig describes one signer or cosigner connection profile.
// The client's SSH key (IdentityFile) is its credential; there is no token.
type ClientEndpointConfig struct {
	Role           string `yaml:"role"`
	URL            string `yaml:"url"`
	IdentityFile   string `yaml:"identity_file,omitempty"`
	KnownHostsPath string `yaml:"known_hosts_path,omitempty"`
}

// LoadClientEndpointRegistry loads and normalizes dataDir/endpoints.yaml.
func LoadClientEndpointRegistry(dataDir string) (*ClientEndpointRegistry, error) {
	registry := &ClientEndpointRegistry{
		SchemaVersion: ClientEndpointSchemaVersion,
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
	data = stripRetiredClientEndpointFields(data)
	if err := validateClientEndpointRegistryScalarTypes(data); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", endpointsPath, err)
	}

	var header struct {
		SchemaVersion int `yaml:"schema_version"`
	}
	if err := yaml.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", endpointsPath, err)
	}
	if header.SchemaVersion != ClientEndpointSchemaVersion {
		return nil, fmt.Errorf("%s schema_version = %d, want %d", ClientEndpointsFile, header.SchemaVersion, ClientEndpointSchemaVersion)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(registry); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", endpointsPath, err)
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

	if err := requireYAMLScalarType(yamlMappingValue(root, "schema_version"), "schema_version", "!!int"); err != nil {
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
		for _, field := range []string{"role", "url", "identity_file", "known_hosts_path"} {
			if err := requireYAMLScalarType(yamlMappingValue(endpoint, field), label+" "+field, "!!str", "!!null"); err != nil {
				return err
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
	if endpoint.Role != ClientEndpointRoleSigner && endpoint.Role != ClientEndpointRoleCosigner {
		return endpoint, fmt.Errorf("unsupported role %q (expected %q or %q)", endpoint.Role, ClientEndpointRoleSigner, ClientEndpointRoleCosigner)
	}
	endpoint.URL = strings.TrimRight(strings.TrimSpace(endpoint.URL), "/")
	if endpoint.URL == "" {
		return endpoint, fmt.Errorf("url is required")
	}
	if err := validateClientEndpointURL(alias, endpoint); err != nil {
		return endpoint, err
	}
	if endpoint.IdentityFile == "" {
		endpoint.IdentityFile = ".ssh/id_ed25519"
	}
	if endpoint.KnownHostsPath == "" {
		endpoint.KnownHostsPath = ".ssh/known_hosts"
	}
	endpoint.IdentityFile = ResolvePath(endpoint.IdentityFile, dataDir)
	endpoint.KnownHostsPath = ResolvePath(endpoint.KnownHostsPath, dataDir)
	return endpoint, nil
}

// validateClientEndpointURL accepts only ssh:// endpoints. A node is reached
// through its SSH server, which authenticates the client's enrolled key and
// hands the API channel to the node's REST handler with that identity; there
// is no credential a raw HTTP endpoint could present.
func validateClientEndpointURL(alias string, endpoint ClientEndpointConfig) error {
	if endpoint.URL == "self" {
		return fmt.Errorf("url %q is not supported; configure an explicit ssh://host[:port] endpoint", endpoint.URL)
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if parsed.Scheme != "ssh" {
		return fmt.Errorf("unsupported url scheme %q for endpoint %q; a node is reached only through its SSH server (ssh://host[:port])", parsed.Scheme, alias)
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
	return nil
}

func normalizeClientEndpointRoles(registry *ClientEndpointRegistry) error {
	registry.Default = strings.TrimSpace(registry.Default)
	if registry.Default != "" {
		if err := validateClientEndpointAlias(registry.Default); err != nil {
			return fmt.Errorf("%s default: %w", ClientEndpointsFile, err)
		}
	}
	signerAlias := ""
	cosignerCount := 0
	for alias, endpoint := range registry.Endpoints {
		if endpoint.Role == ClientEndpointRoleCosigner {
			cosignerCount++
		}
		if endpoint.Role != ClientEndpointRoleSigner {
			continue
		}
		if signerAlias != "" {
			return fmt.Errorf("%s may contain at most one %q endpoint (found %q and %q)", ClientEndpointsFile, ClientEndpointRoleSigner, signerAlias, alias)
		}
		signerAlias = alias
	}
	if cosignerCount > MaxClientCosignerEndpoints {
		return fmt.Errorf("%s configures %d cosigner endpoints; maximum is %d; remove or consolidate endpoint profiles", ClientEndpointsFile, cosignerCount, MaxClientCosignerEndpoints)
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

// retiredClientEndpointFields are endpoint keys earlier builds wrote and
// nothing reads: the node's SSH server forwards every channel to its own REST
// listener, the local tunnel port is chosen at connect time, and the client's
// enrolled SSH key is its only credential, so there is no token file. They
// are ignored on load, as APlane ignores them, so a registry written before
// they were retired keeps working.
var retiredClientEndpointFields = []string{"signer_port", "local_port", "token_file"}

// stripRetiredClientEndpointFields removes retiredClientEndpointFields from
// every endpoint entry on the YAML node tree, so every other value is
// re-emitted exactly as written. Anything it cannot parse, and a document
// with nothing to remove, is returned unchanged for the strict decoder.
func stripRetiredClientEndpointFields(data []byte) []byte {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil || len(document.Content) == 0 {
		return data
	}
	endpoints := yamlMappingValue(document.Content[0], "endpoints")
	if endpoints == nil || endpoints.Kind != yaml.MappingNode {
		return data
	}
	changed := false
	for i := 1; i < len(endpoints.Content); i += 2 {
		entry := endpoints.Content[i]
		if entry.Kind != yaml.MappingNode {
			continue
		}
		kept := entry.Content[:0]
		for j := 0; j+1 < len(entry.Content); j += 2 {
			key, value := entry.Content[j], entry.Content[j+1]
			if key.Kind == yaml.ScalarNode && isRetiredClientEndpointField(key.Value) {
				changed = true
				continue
			}
			kept = append(kept, key, value)
		}
		entry.Content = kept
	}
	if !changed {
		return data
	}
	stripped, err := yaml.Marshal(&document)
	if err != nil {
		return data
	}
	return stripped
}

func isRetiredClientEndpointField(name string) bool {
	for _, field := range retiredClientEndpointFields {
		if name == field {
			return true
		}
	}
	return false
}
