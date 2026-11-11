// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrCosignerDiscovery marks every failure of an EndpointCosignerResolver.
// Match it with errors.Is; the message says what was found.
var ErrCosignerDiscovery = errors.New("cosigner discovery")

// Limits of a discovery sweep. The time limits are variables for tests.
var (
	cosignerDiscoveryEndpointTimeout = 10 * time.Second
	cosignerDiscoveryTotalTimeout    = 30 * time.Second
)

const cosignerDiscoveryWorkers = 4

// The state of a cosigner endpoint after a sweep, as a discovery error names
// it.
const (
	cosignerEndpointOK              = "ok"
	cosignerEndpointUnreachable     = "unreachable"
	cosignerEndpointLocked          = "locked"
	cosignerEndpointAuthFailed      = "authentication failed"
	cosignerEndpointInvalidMetadata = "invalid cosigner metadata"
	cosignerEndpointConfigInvalid   = "configuration invalid"
)

const witnessKeyIDDomain = "APLANE_WITNESS_KEY_ID_V1"

// WitnessKeyID derives the 52-character Witness Key ID of a witness key: the
// unpadded RFC 4648 base32 of SHA-512/256 over the domain
// APLANE_WITNESS_KEY_ID_V1, the key type and the raw public key, each
// prefixed by its length as a 4-byte big-endian integer. The key type is
// opaque here: the public key's length is not checked against it.
func WitnessKeyID(keyType string, publicKey []byte) string {
	var encoded []byte
	for _, field := range [][]byte{[]byte(witnessKeyIDDomain), []byte(keyType), publicKey} {
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(field)))
		encoded = append(encoded, field...)
	}
	digest := sha512.Sum512_256(encoded)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])
}

// EndpointCosignerResolverOptions are the connection options an
// EndpointCosignerResolver uses for every cosigner endpoint, as
// SSHConnectOptions are for a signer.
type EndpointCosignerResolverOptions struct {
	// Timeout bounds each HTTP request after setup, in seconds. Zero means
	// DefaultTimeout.
	Timeout int
	// SSHSetupTimeout bounds TCP dialing and SSH authentication.
	SSHSetupTimeout time.Duration
	// TrustOnFirstUse trusts and saves the host key of an endpoint its known
	// hosts file does not list yet. A key that differs from a saved one is
	// never trusted.
	TrustOnFirstUse bool
}

// EndpointCosignerResolver finds a cosigned account's cosigner among the
// cosigner endpoints of the client's endpoint registry (endpoints.yaml). On
// first use it connects to every endpoint with role "cosigner", each with its
// own identity file and known hosts file, reads its /keys, and keeps the
// witness keys each lists. A witness key must be listed by exactly one live
// endpoint.
//
// The connections it opens belong to it: Close closes them. The sweep's
// result is kept; a key it does not hold makes one fresh sweep per
// ResolveCosigner call. Every failure matches ErrCosignerDiscovery.
type EndpointCosignerResolver struct {
	registry *ClientEndpointRegistry
	options  EndpointCosignerResolverOptions
	// connect opens a client to one endpoint. Tests replace it.
	connect func(ctx context.Context, endpoint ClientEndpointConfig, options EndpointCosignerResolverOptions) (*SignerClient, error)

	mu        sync.Mutex
	closed    bool
	endpoints map[string]*cosignerEndpoint // the last sweep, by alias; nil before one
	sweeps    int
}

var _ CosignedCosignerResolver = (*EndpointCosignerResolver)(nil)

// cosignerEndpoint is one endpoint as the last sweep found it.
type cosignerEndpoint struct {
	alias  string
	client *SignerClient // open only while state is ok
	state  string
	err    error
	// keys maps each witness key the endpoint lists to its Witness Key ID.
	keys map[witnessKey]string
}

// witnessKey names a witness key by its key type and its public key in
// lowercase hex.
type witnessKey struct {
	keyType      string
	publicKeyHex string
}

// NewEndpointCosignerResolver builds a resolver from the endpoint registry in
// dataDir, the data directory FromEnv uses (empty means the environment's).
// It connects to nothing until it is first asked.
func NewEndpointCosignerResolver(dataDir string, opts *EndpointCosignerResolverOptions) (*EndpointCosignerResolver, error) {
	dataDir, err := ResolveDataDir(dataDir)
	if err != nil {
		return nil, err
	}
	registry, err := LoadClientEndpointRegistry(dataDir)
	if err != nil {
		return nil, err
	}
	return NewEndpointCosignerResolverFromRegistry(registry, opts), nil
}

// NewEndpointCosignerResolverFromRegistry builds a resolver from a loaded
// endpoint registry. It connects to nothing until it is first asked.
func NewEndpointCosignerResolverFromRegistry(registry *ClientEndpointRegistry, opts *EndpointCosignerResolverOptions) *EndpointCosignerResolver {
	r := &EndpointCosignerResolver{registry: registry, connect: connectCosignerEndpoint}
	if opts != nil {
		r.options = *opts
	}
	return r
}

// Close closes every connection the resolver opened. A closed resolver
// resolves nothing.
func (r *EndpointCosignerResolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.closeEndpointsLocked()
}

func (r *EndpointCosignerResolver) closeEndpointsLocked() {
	for _, endpoint := range r.endpoints {
		if endpoint.client != nil {
			endpoint.client.Close()
			endpoint.client = nil
		}
	}
	r.endpoints = nil
}

// ResolveCosigner implements CosignedCosignerResolver. It returns the client
// of the one endpoint that lists the witness key, and the key's Witness Key ID
// as that endpoint lists it.
func (r *EndpointCosignerResolver) ResolveCosigner(ctx context.Context, cosignerPublicKeyHex string, componentKeyType string) (*SignerClient, string, error) {
	publicKey, err := hex.DecodeString(cosignerPublicKeyHex)
	if err != nil || len(publicKey) == 0 {
		return nil, "", fmt.Errorf("%w: the account's cosigner public key %q is not valid hex", ErrCosignerDiscovery, cosignerPublicKeyHex)
	}
	if componentKeyType == "" {
		return nil, "", fmt.Errorf("%w: the account names no cosigner key type", ErrCosignerDiscovery)
	}
	required := witnessKey{keyType: componentKeyType, publicKeyHex: hex.EncodeToString(publicKey)}
	id := WitnessKeyID(componentKeyType, publicKey)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, "", fmt.Errorf("%w: the resolver is closed", ErrCosignerDiscovery)
	}
	swept := false
	if r.endpoints == nil {
		if err := r.sweepLocked(ctx); err != nil {
			return nil, "", err
		}
		swept = true
	}
	for {
		matches := r.listingLocked(required)
		switch {
		case len(matches) == 1:
			return matches[0].client, matches[0].keys[required], nil
		case len(matches) > 1:
			aliases := make([]string, len(matches))
			for i, endpoint := range matches {
				aliases[i] = `"` + endpoint.alias + `"`
			}
			return nil, "", fmt.Errorf("%w: Witness Key ID %s (%s) is listed by endpoints %s; each witness key needs exactly one endpoint", ErrCosignerDiscovery, id, componentKeyType, strings.Join(aliases, ", "))
		}
		if swept {
			return nil, "", r.notListedLocked(id, componentKeyType)
		}
		// Not in the kept result: sweep once more, then answer from that.
		if err := r.sweepLocked(ctx); err != nil {
			return nil, "", err
		}
		swept = true
	}
}

// listingLocked returns the live endpoints that list key, sorted by alias.
func (r *EndpointCosignerResolver) listingLocked(key witnessKey) []*cosignerEndpoint {
	var matches []*cosignerEndpoint
	for _, alias := range sortedEndpointAliases(r.endpoints) {
		endpoint := r.endpoints[alias]
		if _, ok := endpoint.keys[key]; ok && endpoint.state == cosignerEndpointOK {
			matches = append(matches, endpoint)
		}
	}
	return matches
}

// notListedLocked is the error for a key no live endpoint lists. It names
// every cosigner endpoint with its state.
func (r *EndpointCosignerResolver) notListedLocked(id, keyType string) error {
	states := make([]string, 0, len(r.endpoints))
	for _, alias := range sortedEndpointAliases(r.endpoints) {
		states = append(states, fmt.Sprintf("%q %s", alias, r.endpoints[alias].state))
	}
	return fmt.Errorf("%w: no endpoint lists Witness Key ID %s (%s); endpoints: %s", ErrCosignerDiscovery, id, keyType, strings.Join(states, ", "))
}

func sortedEndpointAliases(endpoints map[string]*cosignerEndpoint) []string {
	aliases := make([]string, 0, len(endpoints))
	for alias := range endpoints {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	return aliases
}

// sweepLocked connects to every cosigner endpoint and reads its /keys, at
// most cosignerDiscoveryWorkers at once, each within
// cosignerDiscoveryEndpointTimeout and all within
// cosignerDiscoveryTotalTimeout. It replaces the kept result. An endpoint
// that was live keeps its connection and is read again; if that read fails,
// it is connected afresh. An SSH host key that differs from the pinned one
// on any endpoint ends the sweep with that error, and nothing is kept.
func (r *EndpointCosignerResolver) sweepLocked(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var aliases []string
	if r.registry != nil {
		for alias, endpoint := range r.registry.Endpoints {
			if endpoint.Role == ClientEndpointRoleCosigner {
				aliases = append(aliases, alias)
			}
		}
	}
	sort.Strings(aliases)
	if len(aliases) == 0 {
		return fmt.Errorf("%w: %s lists no cosigner endpoint", ErrCosignerDiscovery, ClientEndpointsFile)
	}
	if len(aliases) > MaxClientCosignerEndpoints {
		return fmt.Errorf("%w: %s lists %d cosigner endpoints; the limit is %d", ErrCosignerDiscovery, ClientEndpointsFile, len(aliases), MaxClientCosignerEndpoints)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrCosignerDiscovery, err)
	}
	r.sweeps++
	previous := r.endpoints
	r.endpoints = nil

	sweepCtx, cancel := context.WithTimeout(ctx, cosignerDiscoveryTotalTimeout)
	defer cancel()
	results := make([]*cosignerEndpoint, len(aliases))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for range min(cosignerDiscoveryWorkers, len(aliases)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				alias := aliases[index]
				var reuse *SignerClient
				if earlier := previous[alias]; earlier != nil {
					reuse = earlier.client
				}
				endpointCtx, endpointCancel := context.WithTimeout(sweepCtx, cosignerDiscoveryEndpointTimeout)
				result := r.probe(endpointCtx, alias, r.registry.Endpoints[alias], reuse)
				endpointCancel()
				results[index] = result
				if result.state == "" {
					// A host key mismatch: nothing else matters.
					cancel()
				}
			}
		}()
	}
dispatch:
	for index := range aliases {
		select {
		case jobs <- index:
		case <-sweepCtx.Done():
			break dispatch
		}
	}
	close(jobs)
	workers.Wait()

	endpoints := make(map[string]*cosignerEndpoint, len(aliases))
	live := map[*SignerClient]bool{}
	var mismatch error
	for index, alias := range aliases {
		result := results[index]
		if result == nil {
			// The sweep's time ran out before this endpoint was probed.
			result = &cosignerEndpoint{alias: alias, state: cosignerEndpointUnreachable, err: sweepCtx.Err()}
		}
		if result.state == "" && mismatch == nil {
			mismatch = fmt.Errorf("%w: endpoint %q: %s", ErrCosignerDiscovery, alias, hostKeyMismatchText(result.err))
		}
		if result.client != nil {
			live[result.client] = true
		}
		endpoints[alias] = result
	}
	// A connection the earlier sweep kept and this one did not is closed.
	for _, earlier := range previous {
		if earlier.client != nil && !live[earlier.client] {
			earlier.client.Close()
		}
	}
	// The caller's own end is not a finding about the endpoints.
	failure := mismatch
	if failure == nil && ctx.Err() != nil {
		failure = fmt.Errorf("%w: %w", ErrCosignerDiscovery, ctx.Err())
	}
	if failure != nil {
		for client := range live {
			client.Close()
		}
		return failure
	}
	r.endpoints = endpoints
	return nil
}

// hostKeyMismatchText is the SSH error's own text for a host key mismatch.
func hostKeyMismatchText(err error) string {
	var setup *sshSetupError
	if errors.As(err, &setup) {
		return setup.err.Error()
	}
	return err.Error()
}

// probe connects to one endpoint, or reuses its live connection, and reads
// its witness keys. A result with an empty state is a host key mismatch.
func (r *EndpointCosignerResolver) probe(ctx context.Context, alias string, config ClientEndpointConfig, reuse *SignerClient) *cosignerEndpoint {
	if reuse != nil {
		result := readCosignerKeys(ctx, alias, reuse)
		if result.state == cosignerEndpointOK {
			return result
		}
		reuse.Close()
		if ctx.Err() != nil {
			return result
		}
	}
	client, err := r.connect(ctx, config, r.options)
	if err != nil {
		return &cosignerEndpoint{alias: alias, state: classifyCosignerConnect(err), err: err}
	}
	result := readCosignerKeys(ctx, alias, client)
	if result.state != cosignerEndpointOK {
		client.Close()
	}
	return result
}

// connectCosignerEndpoint connects to a cosigner endpoint exactly as FromEnv
// connects to a signer endpoint: by its ssh:// URL, with its own identity
// file and known hosts file.
func connectCosignerEndpoint(ctx context.Context, endpoint ClientEndpointConfig, options EndpointCosignerResolverOptions) (*SignerClient, error) {
	host, sshPort, err := ClientEndpointSSHHostPort(endpoint)
	if err != nil {
		return nil, &sshSetupError{kind: sshSetupConfig, err: err}
	}
	return ConnectSSHWithContext(ctx, host, endpoint.IdentityFile, &SSHConnectOptions{
		SSHPort:         sshPort,
		KnownHostsPath:  endpoint.KnownHostsPath,
		Timeout:         options.Timeout,
		SSHSetupTimeout: options.SSHSetupTimeout,
		TrustOnFirstUse: options.TrustOnFirstUse,
	})
}

// classifyCosignerConnect names the state of an endpoint whose connection
// failed, or "" for a host key mismatch.
func classifyCosignerConnect(err error) string {
	switch {
	case sshSetupKindOf(err) == sshSetupHostKeyMismatch:
		return ""
	case sshSetupKindOf(err) == sshSetupConfig:
		return cosignerEndpointConfigInvalid
	case errors.Is(err, ErrNotEnrolled):
		return cosignerEndpointAuthFailed
	}
	return cosignerEndpointUnreachable
}

// readCosignerKeys reads an endpoint's /keys and keeps its witness keys. A
// witness key record whose public key is not hex, or whose address is not
// the Witness Key ID of its key type and public key, makes the whole listing
// invalid.
func readCosignerKeys(ctx context.Context, alias string, client *SignerClient) *cosignerEndpoint {
	result := &cosignerEndpoint{alias: alias, client: client}
	keys, err := client.GetKeysResponseWithContext(ctx)
	if err != nil {
		result.client, result.err, result.state = nil, err, classifyCosignerKeysError(err)
		return result
	}
	if keys.Locked {
		result.client, result.err, result.state = nil, ErrSignerLocked, cosignerEndpointLocked
		return result
	}
	result.keys = map[witnessKey]string{}
	for i, key := range keys.Keys {
		if !key.IsWitnessKey || key.KeyType == "" {
			continue
		}
		publicKey, err := hex.DecodeString(key.PublicKeyHex)
		if err == nil && len(publicKey) == 0 {
			err = errors.New("it is empty")
		}
		if err != nil {
			result.client, result.state = nil, cosignerEndpointInvalidMetadata
			result.err = fmt.Errorf("witness key %d: public_key_hex is not valid hex: %v", i, err)
			return result
		}
		if want := WitnessKeyID(key.KeyType, publicKey); key.Address != want {
			result.client, result.state = nil, cosignerEndpointInvalidMetadata
			result.err = fmt.Errorf("witness key %d: address %q is not the Witness Key ID %s of its key type and public key", i, key.Address, want)
			return result
		}
		result.keys[witnessKey{keyType: key.KeyType, publicKeyHex: hex.EncodeToString(publicKey)}] = key.Address
	}
	result.state = cosignerEndpointOK
	return result
}

// classifyCosignerKeysError names the state of an endpoint whose /keys read
// failed.
func classifyCosignerKeysError(err error) string {
	var apiErr *APIError
	var unread *unreadableAnswer
	switch {
	case errors.Is(err, ErrAuthentication):
		return cosignerEndpointAuthFailed
	case errors.As(err, &unread):
		return cosignerEndpointInvalidMetadata
	case errors.As(err, &apiErr):
		switch {
		case apiErr.Code == ErrCodeLocked:
			return cosignerEndpointLocked
		case apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden:
			return cosignerEndpointAuthFailed
		case apiErr.StatusCode >= 500:
			return cosignerEndpointUnreachable
		}
		return cosignerEndpointConfigInvalid
	}
	return cosignerEndpointUnreachable
}
