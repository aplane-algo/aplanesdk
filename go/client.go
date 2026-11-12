// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SignerClient is the client for connecting to apsigner.
type SignerClient struct {
	baseURL               string
	client                *http.Client
	sshTunnel             *sshTunnel
	keyMu                 sync.RWMutex
	keyCache              map[string]*KeyInfo
	keyCacheRevision      uint64
	keyCacheRevisionKnown bool

	requestTimeout      time.Duration
	requestTimeoutSet   bool
	approvalMu          sync.RWMutex
	approvalWaitSeconds int64
	approvalWaitFetched time.Time
	approvalWaitKnown   bool

	maxFeeIncrease atomic.Pointer[uint64]

	// endpoints and endpointOptions are set when the client was created from
	// a data directory: its endpoint registry, and the connection options it
	// was created with, for its own cosigner resolver.
	endpoints        *ClientEndpointRegistry
	endpointOptions  EndpointCosignerResolverOptions
	resolverMu       sync.Mutex
	cosignerResolver *EndpointCosignerResolver

	// closed is set by Close.
	closed atomic.Bool
}

const (
	healthTimeout             = 3 * time.Second
	statusTimeout             = 5 * time.Second
	inventoryTimeout          = 30 * time.Second
	mutationTimeout           = 60 * time.Second
	groupPlanTimeout          = 60 * time.Second
	componentSignTimeout      = 2 * time.Minute
	cosignedAssemblyTimeout   = 2 * time.Minute
	signCancelTimeout         = 5 * time.Second
	signApprovalSlack         = 30 * time.Second
	defaultSignRequestTimeout = 6 * time.Minute
	maxDiscoveredApprovalWait = 30 * time.Minute
	approvalWaitRefresh       = 5 * time.Minute
)

func newSignRequestID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "sdk-" + hex.EncodeToString(random[:]), nil
}

// NewSignerClient creates a signer client for an already-known base URL. This
// is useful when the caller owns the transport or tunnel lifecycle: the
// signer authenticates the SSH connection the requests arrive through, so the
// client itself carries no credential.
func NewSignerClient(baseURL string) *SignerClient {
	return &SignerClient{
		baseURL:  baseURL,
		client:   &http.Client{},
		keyCache: nil,
	}
}

// SetMaxFeeIncrease sets a ceiling, in microAlgos, on the total fee the signer
// may add to a request. Every sign, plan and simulate call through this client
// fails and returns nothing when the signer's fee raises across the request's
// positions add up to more than this. On a sign or simulate call the signer
// has already answered by then; its signature is discarded. Each request is held to
// the ceiling in force when it started. Zero means the signer may not
// raise any fee. There is no default: until this is called, a reported raise
// of any size is accepted.
func (c *SignerClient) SetMaxFeeIncrease(microAlgos uint64) {
	c.maxFeeIncrease.Store(&microAlgos)
}

// ClearMaxFeeIncrease removes the ceiling set by SetMaxFeeIncrease.
func (c *SignerClient) ClearMaxFeeIncrease() {
	c.maxFeeIncrease.Store(nil)
}

// MaxFeeIncrease returns the ceiling set by SetMaxFeeIncrease, and whether one
// is set.
func (c *SignerClient) MaxFeeIncrease() (uint64, bool) {
	ceiling := c.feeCeiling()
	return ceiling.limit, ceiling.set
}

// feeCeiling reads the ceiling once. A call takes it before sending its
// request, so the ceiling it is held to is the one in force when it started,
// whatever another goroutine sets while the signer waits for approval.
func (c *SignerClient) feeCeiling() feeCeiling {
	limit := c.maxFeeIncrease.Load()
	if limit == nil {
		return feeCeiling{}
	}
	return feeCeiling{limit: *limit, set: true}
}

// SetHTTPClient overrides the HTTP client used for requests.
func (c *SignerClient) SetHTTPClient(client *http.Client) {
	if client != nil {
		c.client = client
	}
}

func readErrorBody(resp *http.Response) string {
	_, message := readErrorParts(resp)
	return message
}

// readErrorParts reads a non-2xx body and returns the stable wire error code
// (empty when the body is not a JSON error envelope) and the human-readable
// message.
func readErrorParts(resp *http.Response) (code, message string) {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Sprintf("<failed to read error body: %v>", err)
	}
	body := strings.TrimSpace(string(bodyBytes))
	if body == "" {
		return "", http.StatusText(resp.StatusCode)
	}

	// A code is kept only beside a message: an envelope whose message is
	// empty or only whitespace is not one, and neither is a JSON value that
	// is not an object. The body text stands for the message then.
	var errorResp ErrorResponse
	if err := json.Unmarshal(bodyBytes, &errorResp); err == nil && strings.TrimSpace(errorResp.Error) != "" {
		return errorResp.Code, errorResp.Error
	}
	return "", body
}

// signerHTTPError reads a non-2xx response into a typed *APIError carrying
// status, wire code, and message.
func signerHTTPError(resp *http.Response) *APIError {
	return signerHTTPErrorOp(resp, "")
}

// signerHTTPErrorOp is signerHTTPError with an operation-specific message
// prefix (e.g. "plan failed").
func signerHTTPErrorOp(resp *http.Response, op string) *APIError {
	code, message := readErrorParts(resp)
	return &APIError{StatusCode: resp.StatusCode, Code: code, Message: message, Op: op}
}

// lockedForbiddenError classifies a 403 at endpoints that report a locked
// signer. Only the locked wire code maps to ErrSignerLocked; any other code,
// including an empty one, is returned as an *APIError.
func lockedForbiddenError(resp *http.Response) error {
	apiErr := signerHTTPError(resp)
	switch apiErr.Code {
	case ErrCodeLocked:
		return ErrSignerLocked
	default:
		return apiErr
	}
}

// rejectedForbiddenError classifies a 403 at endpoints that report a rejected
// request. A locked code maps to ErrSignerLocked and a forbidden code to
// ErrSigningRejected; any other code, including an empty one, is returned as
// an *APIError.
func rejectedForbiddenError(resp *http.Response) error {
	return rejectedForbidden(signerHTTPError(resp))
}

// rejectedForbidden is rejectedForbiddenError for an already-read response.
func rejectedForbidden(apiErr *APIError) error {
	switch apiErr.Code {
	case ErrCodeLocked:
		return ErrSignerLocked
	case ErrCodeForbidden:
		return ErrSigningRejected
	default:
		return apiErr
	}
}

func (c *SignerClient) requestContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return withDefaultTimeout(ctx, c.timeoutFor(timeout))
}

func (c *SignerClient) timeoutFor(defaultTimeout time.Duration) time.Duration {
	if c.requestTimeoutSet && c.requestTimeout > 0 && c.requestTimeout < defaultTimeout {
		return c.requestTimeout
	}
	return defaultTimeout
}

func withDefaultTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}
	defaultDeadline := time.Now().Add(timeout)
	if callerDeadline, ok := ctx.Deadline(); ok && !callerDeadline.After(defaultDeadline) {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// ConnectSSH creates a client connected via SSH tunnel, authenticated by the
// enrolled client key at sshKeyPath. A key the signer has not enrolled fails
// with ErrNotEnrolled; enroll it with RequestEnrollment first.
func ConnectSSH(host, sshKeyPath string, opts *SSHConnectOptions) (*SignerClient, error) {
	return ConnectSSHWithContext(context.Background(), host, sshKeyPath, opts)
}

// ConnectSSHWithContext creates a client connected via SSH tunnel and allows
// the caller to cancel TCP dialing or SSH authentication. Once connected, the
// returned client's lifetime is independent of ctx.
func ConnectSSHWithContext(ctx context.Context, host, sshKeyPath string, opts *SSHConnectOptions) (*SignerClient, error) {
	sshPort := DefaultSSHPort
	timeout := DefaultTimeout
	sshSetupTimeout := defaultSSHSetupTimeout
	localPort := 0

	var knownHostsPath string

	if opts != nil {
		if opts.SSHPort > 0 {
			sshPort = opts.SSHPort
		}
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
		if opts.SSHSetupTimeout > 0 {
			sshSetupTimeout = opts.SSHSetupTimeout
		}
		if opts.LocalPort > 0 {
			localPort = opts.LocalPort
		}
		if opts.KnownHostsPath != "" {
			knownHostsPath = opts.KnownHostsPath
		}
	}

	trustOnFirstUse := opts != nil && opts.TrustOnFirstUse
	knownHostsPath = ExpandPath(knownHostsPath)
	tunnel := &sshTunnel{knownHostsPath: knownHostsPath, trustOnFirstUse: trustOnFirstUse}
	resolvedLocalPort, err := tunnel.connect(ctx, host, sshPort, localPort, ExpandPath(sshKeyPath), sshSetupTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to establish SSH tunnel: %w", err)
	}

	return newTunnelClient(resolvedLocalPort, tunnel, timeout, opts), nil
}

// newTunnelClient builds the client for an established tunnel. Everything the
// options set on a client is applied here, before the client is returned, so
// it is never usable without them.
func newTunnelClient(localPort int, tunnel *sshTunnel, timeout int, opts *SSHConnectOptions) *SignerClient {
	client := &SignerClient{
		baseURL:           fmt.Sprintf("http://localhost:%d", localPort),
		client:            &http.Client{},
		sshTunnel:         tunnel,
		requestTimeout:    time.Duration(timeout) * time.Second,
		requestTimeoutSet: opts != nil && opts.Timeout > 0,
	}
	if opts != nil && opts.MaxFeeIncrease != nil {
		client.SetMaxFeeIncrease(*opts.MaxFeeIncrease)
	}
	return client
}

// FromEnv creates a client from environment configuration. Routing and the
// client SSH identity come from dataDir/endpoints.yaml. An empty endpoint
// option selects the default signer.
func FromEnv(opts *FromEnvOptions) (*SignerClient, error) {
	return FromEnvWithContext(context.Background(), opts)
}

// FromEnvWithContext is the context-aware form of FromEnv. The context bounds
// SSH connection setup only; established clients remain valid until Close.
func FromEnvWithContext(ctx context.Context, opts *FromEnvOptions) (*SignerClient, error) {
	dataDir := ""
	endpointAlias := ""

	if opts != nil {
		dataDir = opts.DataDir
		endpointAlias = opts.Endpoint
	}

	dataDir, err := ResolveDataDir(dataDir)
	if err != nil {
		return nil, err
	}

	if _, err := LoadConfig(dataDir); err != nil {
		return nil, err
	}
	registry, err := LoadClientEndpointRegistry(dataDir)
	if err != nil {
		return nil, err
	}
	_, endpoint, err := ResolveClientEndpoint(registry, endpointAlias)
	if err != nil {
		return nil, err
	}

	host, sshPort, err := ClientEndpointSSHHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	sshOpts := fromEnvSSHOptions(opts, sshPort, endpoint.KnownHostsPath)
	client, err := ConnectSSHWithContext(ctx, host, endpoint.IdentityFile, sshOpts)
	if err != nil {
		return nil, err
	}
	client.endpoints = registry
	client.endpointOptions = EndpointCosignerResolverOptions{
		Timeout:         sshOpts.Timeout,
		SSHSetupTimeout: sshOpts.SSHSetupTimeout,
		TrustOnFirstUse: sshOpts.TrustOnFirstUse,
	}
	return client, nil
}

// defaultCosignerResolver is the client's own cosigner resolver, over the
// endpoint registry it was created from, made on first use. It is nil for a
// client not created from a data directory. Once the client is closed, the
// resolver is closed too, even one made after: it opens no connections.
func (c *SignerClient) defaultCosignerResolver() *EndpointCosignerResolver {
	if c == nil || c.endpoints == nil {
		return nil
	}
	c.resolverMu.Lock()
	defer c.resolverMu.Unlock()
	if c.cosignerResolver == nil {
		c.cosignerResolver = NewEndpointCosignerResolverFromRegistry(c.endpoints, &c.endpointOptions)
		if c.closed.Load() {
			c.cosignerResolver.Close()
		}
	}
	return c.cosignerResolver
}

// fromEnvSSHOptions carries a FromEnv caller's options over to the SSH
// connection that builds the client.
func fromEnvSSHOptions(opts *FromEnvOptions, sshPort int, knownHostsPath string) *SSHConnectOptions {
	sshOpts := &SSHConnectOptions{SSHPort: sshPort, KnownHostsPath: knownHostsPath}
	if opts == nil {
		return sshOpts
	}
	if opts.Timeout > 0 {
		sshOpts.Timeout = opts.Timeout
	}
	sshOpts.SSHSetupTimeout = opts.SSHSetupTimeout
	sshOpts.TrustOnFirstUse = opts.TrustOnFirstUse
	sshOpts.MaxFeeIncrease = opts.MaxFeeIncrease
	return sshOpts
}

// Close closes the client and any SSH tunnel, and the connections its own
// cosigner resolver opened.
func (c *SignerClient) Close() {
	c.resolverMu.Lock()
	c.closed.Store(true)
	resolver := c.cosignerResolver
	c.resolverMu.Unlock()
	if resolver != nil {
		resolver.Close()
	}
	if c.sshTunnel != nil {
		c.sshTunnel.close()
	}
}

// connectionOpen reports, asking nothing of the signer, whether the client
// can still reach it: it has not been closed, and its SSH tunnel, if it has
// one, is up. A client on a caller's own base URL has no connection of its
// own to lose, so it is open until it is closed.
func (c *SignerClient) connectionOpen() bool {
	return !c.closed.Load() && (c.sshTunnel == nil || c.sshTunnel.open())
}

// Health checks if the signer is reachable.
func (c *SignerClient) Health() (bool, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/health", nil)
	if err != nil {
		return false, err
	}

	reqCtx, cancel := c.requestContext(context.Background(), healthTimeout)
	defer cancel()

	resp, err := c.client.Do(req.WithContext(reqCtx))
	if err != nil {
		return false, nil // Not reachable
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200, nil
}

// GetStatus fetches authenticated signer status and keyset revision.
func (c *SignerClient) GetStatus() (*StatusResponse, error) {
	return c.GetStatusWithContext(context.Background())
}

// GetStatusWithContext fetches authenticated signer status and keyset revision.
func (c *SignerClient) GetStatusWithContext(ctx context.Context) (*StatusResponse, error) {
	reqCtx, cancel := c.requestContext(ctx, statusTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", c.baseURL+"/status", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrAuthentication
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, ErrSignerUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		return nil, signerHTTPError(resp)
	}

	var statusResp StatusResponse
	if err := readAnswer(resp.Body, &statusResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	c.cacheApprovalWait(statusResp.ApprovalWaitSeconds)

	return &statusResp, nil
}

func (c *SignerClient) cacheApprovalWait(seconds int64) {
	wait := int64(0)
	if seconds > 0 && seconds <= int64(maxDiscoveredApprovalWait/time.Second) {
		wait = seconds
	}
	c.approvalMu.Lock()
	defer c.approvalMu.Unlock()
	c.approvalWaitSeconds = wait
	c.approvalWaitFetched = time.Now()
	c.approvalWaitKnown = true
}

func (c *SignerClient) cachedApprovalWait(now time.Time) (time.Duration, bool) {
	c.approvalMu.RLock()
	defer c.approvalMu.RUnlock()
	if !c.approvalWaitKnown || c.approvalWaitSeconds <= 0 {
		return 0, false
	}
	if now.Sub(c.approvalWaitFetched) > approvalWaitRefresh {
		return 0, false
	}
	return time.Duration(c.approvalWaitSeconds) * time.Second, true
}

func (c *SignerClient) needsApprovalWaitDiscovery(now time.Time) bool {
	c.approvalMu.RLock()
	defer c.approvalMu.RUnlock()
	if !c.approvalWaitKnown {
		return true
	}
	return now.Sub(c.approvalWaitFetched) > approvalWaitRefresh
}

func (c *SignerClient) discoverApprovalWait(ctx context.Context) {
	if !c.needsApprovalWaitDiscovery(time.Now()) {
		return
	}
	_, _ = c.GetStatusWithContext(ctx)
}

func (c *SignerClient) signRequestTimeout() time.Duration {
	wait, ok := c.cachedApprovalWait(time.Now())
	if !ok {
		return defaultSignRequestTimeout
	}
	return wait + signApprovalSlack
}

// ListKeys returns all available signing keys.
func (c *SignerClient) ListKeys(refresh bool) ([]KeyInfo, error) {
	if !refresh {
		if keys := c.cachedKeys(); keys != nil {
			return keys, nil
		}
	}

	keysResp, err := c.GetKeysResponseWithContext(context.Background())
	if err != nil {
		if err == ErrSignerLocked || err == ErrAuthentication {
			return nil, err
		}
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	if keysResp.Locked {
		return nil, ErrSignerLocked
	}
	return keysResp.Keys, nil
}

// GetKeyInfo returns info for a specific key address.
func (c *SignerClient) GetKeyInfo(address string) (*KeyInfo, error) {
	return c.getKeyInfoWithContext(context.Background(), address)
}

func (c *SignerClient) getKeyInfoWithContext(ctx context.Context, address string) (*KeyInfo, error) {
	c.keyMu.RLock()
	if c.keyCache != nil {
		if k, ok := c.keyCache[address]; ok {
			c.keyMu.RUnlock()
			return k, nil
		}
	}
	c.keyMu.RUnlock()

	keys, err := c.GetKeysResponseWithContext(ctx)
	if err != nil {
		return nil, err
	}
	if keys.Locked {
		return nil, ErrSignerLocked
	}

	c.keyMu.RLock()
	defer c.keyMu.RUnlock()
	if k, ok := c.keyCache[address]; ok {
		return k, nil
	}
	return nil, ErrKeyNotFound
}

func (c *SignerClient) cachedKeys() []KeyInfo {
	c.keyMu.RLock()
	defer c.keyMu.RUnlock()
	if c.keyCache == nil {
		return nil
	}
	keys := make([]KeyInfo, 0, len(c.keyCache))
	for _, k := range c.keyCache {
		keys = append(keys, *k)
	}
	return keys
}

func (c *SignerClient) cachedKeysForRevision(revision uint64) ([]KeyInfo, bool) {
	c.keyMu.RLock()
	defer c.keyMu.RUnlock()
	if c.keyCache == nil || !c.keyCacheRevisionKnown || c.keyCacheRevision != revision {
		return nil, false
	}
	keys := make([]KeyInfo, 0, len(c.keyCache))
	for _, k := range c.keyCache {
		keys = append(keys, *k)
	}
	return keys, true
}

func (c *SignerClient) cacheKeysRevision(revision uint64) {
	c.keyMu.Lock()
	defer c.keyMu.Unlock()
	c.keyCacheRevision = revision
	c.keyCacheRevisionKnown = true
}

func (c *SignerClient) invalidateKeyCacheRevisionLocked() {
	c.keyCacheRevision = 0
	c.keyCacheRevisionKnown = false
}

// GetKeysResponseWithContext fetches /keys with local locked-state reporting.
func (c *SignerClient) GetKeysResponseWithContext(ctx context.Context) (*KeysResult, error) {
	reqCtx, cancel := c.requestContext(ctx, inventoryTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", c.baseURL+"/keys", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		apiErr := signerHTTPError(resp)
		if apiErr.Code == ErrCodeLocked {
			return &KeysResult{Locked: true}, nil
		}
		return nil, apiErr
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrAuthentication
	}
	if resp.StatusCode != http.StatusOK {
		return nil, signerHTTPError(resp)
	}

	// A body that stalls or is cut off is a failed exchange, as a request that
	// never got an answer is; only a body read in full can be unreadable.
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read keys: %w", err)
	}
	var keysResp keysResponse
	if err := decodeAnswer(raw, &keysResp); err != nil {
		return nil, &unreadableAnswer{err: fmt.Errorf("failed to decode response: %w", err)}
	}
	// An address is looked up by its exact text, so an Algorand address the
	// signer spelled another way would never match the key's account. Any
	// other text, such as a witness key's ID, is kept as sent.
	for i, key := range keysResp.Keys {
		if canonical, ok := alternateAddressSpelling(key.Address); ok {
			return nil, &unreadableAnswer{err: fmt.Errorf("failed to decode response: key %d address %q is a non-canonical spelling of address %s", i, key.Address, canonical)}
		}
	}

	cache := make(map[string]*KeyInfo, len(keysResp.Keys))
	for i := range keysResp.Keys {
		k := &keysResp.Keys[i]
		// One record per address. Should the signer list an address twice,
		// the first spendable row is the one kept, the row findSpendableKey
		// picks from the list itself, so a lookup answers the same from a
		// fresh list and from the cache. A row is displaced only by the first
		// spendable row after a non-spending one.
		if kept, ok := cache[k.Address]; ok && (isSpendableKey(*kept) || !isSpendableKey(*k)) {
			continue
		}
		cache[k.Address] = k
	}
	c.keyMu.Lock()
	c.keyCache = cache
	c.invalidateKeyCacheRevisionLocked()
	c.keyMu.Unlock()

	return &KeysResult{
		KeysResponse: KeysResponse{
			Count: keysResp.Count,
			Keys:  keysResp.Keys,
		},
	}, nil
}

// alternateAddressSpelling reports whether text is an Algorand address spelled
// other than canonically, and returns the canonical spelling: 58 characters
// that decode, as base32 without padding, to 36 bytes whose last 4 are the
// checksum of the first 32, but that do not re-encode to text. DecodeAddress
// refuses such text, so it cannot tell it from text that is no address.
func alternateAddressSpelling(text string) (string, bool) {
	if len(text) != 58 {
		return "", false
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(text)
	if err != nil || len(decoded) != 36 {
		return "", false
	}
	checksum := sha512.Sum512_256(decoded[:32])
	if !bytes.Equal(checksum[len(checksum)-4:], decoded[32:]) {
		return "", false
	}
	var address types.Address
	copy(address[:], decoded[:32])
	canonical := address.String()
	return canonical, canonical != text
}

// ListKeyTypes returns available key types and their creation parameters.
func (c *SignerClient) ListKeyTypes() ([]KeyTypeInfo, error) {
	reqCtx, cancel := c.requestContext(context.Background(), inventoryTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", c.baseURL+"/keytypes", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list key types: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, ErrAuthentication
	}
	if resp.StatusCode == 403 {
		return nil, rejectedForbiddenError(resp)
	}
	if resp.StatusCode == 503 {
		return nil, ErrSignerUnavailable
	}
	if resp.StatusCode != 200 {
		return nil, signerHTTPError(resp)
	}

	var ktResp keyTypesResponse
	if err := readAnswer(resp.Body, &ktResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return ktResp.KeyTypes, nil
}

// GenerateKey generates a new key on the signer.
func (c *SignerClient) GenerateKey(keyType string, parameters map[string]string) (*GenerateResult, error) {
	genReq := generateRequest{KeyType: keyType, Parameters: parameters}
	jsonBody, err := json.Marshal(genReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqCtx, cancel := c.requestContext(context.Background(), mutationTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/admin/generate", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, ErrAuthentication
	}
	if resp.StatusCode == 403 {
		return nil, lockedForbiddenError(resp)
	}
	if resp.StatusCode != 200 {
		return nil, signerHTTPErrorOp(resp, "key generation failed")
	}
	// The signer answered, so its keys may have changed whatever the answer
	// says.
	c.invalidateKeyCache()

	var result GenerateResult
	if err := readAnswer(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if result.Error != "" {
		return nil, fmt.Errorf("key generation failed: %s", result.Error)
	}
	if result.Address == "" {
		return nil, fmt.Errorf("key generation failed: missing address")
	}
	return &result, nil
}

func (c *SignerClient) invalidateKeyCache() {
	c.keyMu.Lock()
	c.keyCache = nil
	c.invalidateKeyCacheRevisionLocked()
	c.keyMu.Unlock()
}

// deleteKeyResponse is the answer of DELETE /admin/keys. The signer answers
// {"success":true}; an error, which it never sets today, is a refusal.
type deleteKeyResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// DeleteKey deletes a key from the signer.
func (c *SignerClient) DeleteKey(address string) error {
	reqCtx, cancel := c.requestContext(context.Background(), mutationTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "DELETE", c.baseURL+"/admin/keys?"+url.Values{"address": []string{address}}.Encode(), nil)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return ErrAuthentication
	}
	if resp.StatusCode == 403 {
		return lockedForbiddenError(resp)
	}
	if resp.StatusCode == 404 {
		return ErrKeyDeletion
	}
	if resp.StatusCode != 200 {
		return signerHTTPErrorOp(resp, "key deletion failed")
	}
	c.invalidateKeyCache()

	var result deleteKeyResponse
	if err := readAnswer(resp.Body, &result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	if result.Error != "" {
		return fmt.Errorf("key deletion failed: %s", result.Error)
	}
	return nil
}

func (c *SignerClient) RequestAssemble(req AssemblyRequest) (*AssemblyResponse, error) {
	return c.RequestAssembleWithContext(context.Background(), req)
}

func (c *SignerClient) RequestAssembleWithContext(ctx context.Context, reqBody AssemblyRequest) (*AssemblyResponse, error) {
	if reqBody.RequestID == "" {
		requestID, err := newSignRequestID()
		if err != nil {
			return nil, fmt.Errorf("failed to create assembly request ID: %w", err)
		}
		reqBody.RequestID = requestID
	}
	if err := reqBody.Validate(); err != nil {
		return nil, fmt.Errorf("invalid assembly request: %w", err)
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// A context that has already ended sends nothing, as in postApproval: it
	// is a plain stop, not an exchange whose outcome is unknown.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	reqCtx, cancel := c.requestContext(ctx, cosignedAssemblyTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/sign/assemble", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := reqCtx.Err(); err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to Signer: %w", &lostAnswer{requestID: reqBody.RequestID, err: err})
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, ErrAuthentication
	}
	if resp.StatusCode == 403 {
		return nil, rejectedForbiddenError(resp)
	}
	if resp.StatusCode == 503 {
		return nil, ErrSignerUnavailable
	}
	if resp.StatusCode != 200 {
		return nil, signerHTTPError(resp)
	}

	var assemblyResp AssemblyResponse
	if err := readAnswer(resp.Body, &assemblyResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", &lostAnswer{requestID: reqBody.RequestID, err: err})
	}
	if assemblyResp.Error != "" {
		return nil, fmt.Errorf("assembly failed: %s", assemblyResp.Error)
	}
	if err := assemblyResp.Validate(); err != nil {
		return nil, fmt.Errorf("invalid assembly response: %w", err)
	}
	// The answer must be to this request, not merely carry a well-formed ID.
	if assemblyResp.RequestID != reqBody.RequestID {
		return nil, fmt.Errorf("invalid assembly response: request_id %q does not match the request's %q", assemblyResp.RequestID, reqBody.RequestID)
	}
	return &assemblyResp, nil
}

// PlanGroup previews group building without signing or approval.
func (c *SignerClient) PlanGroup(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap, opts *SignOptions) (*PlanGroupResponse, error) {
	requests, err := buildSignRequestsWithOptions(txns, authAddresses, lsigArgsMap, opts)
	if err != nil {
		return nil, err
	}
	return c.PlanRequestsWithContext(context.Background(), requests)
}

// PlanRequestsWithContext posts raw /plan requests without rebuilding them from transactions.
func (c *SignerClient) PlanRequestsWithContext(ctx context.Context, requests []SignRequest) (*PlanGroupResponse, error) {
	if err := validateRequests(requests); err != nil {
		return nil, err
	}
	slots, err := decodeRequestSlots(requests)
	if err != nil {
		return nil, fmt.Errorf("invalid plan request: %w", err)
	}
	// The slots the plan is checked against are decoded here, from the very
	// entries that are sent.
	ceiling := c.feeCeiling()
	groupReq := groupSignRequest{Requests: requests}

	jsonBody, err := json.Marshal(groupReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqCtx, cancel := c.requestContext(ctx, groupPlanTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/plan", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to plan group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, ErrAuthentication
	}
	if resp.StatusCode != 200 {
		return nil, signerHTTPErrorOp(resp, "plan failed")
	}

	var planResp PlanGroupResponse
	if err := readAnswer(resp.Body, &planResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if planResp.Error != "" {
		return nil, fmt.Errorf("plan failed: %s", planResp.Error)
	}

	if err := validatePlanResponse(slots, planResp.Transactions, planResp.Mutations, ceiling); err != nil {
		return nil, fmt.Errorf("verify signer plan: %w", err)
	}

	return &planResp, nil
}

// SignTransaction signs a single transaction. It returns the signed group as
// SignTransactions does: the first entry is the caller's transaction, and any
// further entries are resource dummies the signer appended. The whole list is
// what must be submitted, as SendRawTransaction(bytes.Join(signed, nil)).
// An empty authAddress means the sender signs for itself; lsigArgs then apply
// to the sender.
func (c *SignerClient) SignTransaction(txn types.Transaction, authAddress string, lsigArgs LsigArgs) ([][]byte, error) {
	if authAddress == "" {
		authAddress = txn.Sender.String()
	}
	return c.SignTransactions([]types.Transaction{txn}, []string{authAddress}, lsigArgsToMap(authAddress, lsigArgs))
}

// SignTransactions signs multiple transactions as a group. It returns the
// signed group, one canonical msgpack-encoded signed transaction per entry, in
// group order: the transactions given, then any resource dummies the signer
// appended. Submit it with go-algorand-sdk as
// SendRawTransaction(bytes.Join(signed, nil)).
func (c *SignerClient) SignTransactions(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap) ([][]byte, error) {
	requests, err := buildSignRequests(txns, authAddresses, lsigArgsMap)
	if err != nil {
		return nil, err
	}
	return c.sign(requests)
}

// SignTransactionsWithOptions signs transactions with passthrough support. It
// returns the signed group as SignTransactions does, passthrough positions
// included.
func (c *SignerClient) SignTransactionsWithOptions(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap, opts *SignOptions) ([][]byte, error) {
	requests, err := buildSignRequestsWithOptions(txns, authAddresses, lsigArgsMap, opts)
	if err != nil {
		return nil, err
	}
	if hasForeignRequests(requests) {
		return nil, fmt.Errorf("foreign entries are only supported on /plan; use PlanGroup first, then resubmit foreign slots as passthrough")
	}
	return c.sign(requests)
}

// buildSignRequestsWithOptions converts transactions into sign requests with
// passthrough/foreign support: a position with no auth address is foreign.
func buildSignRequestsWithOptions(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap, opts *SignOptions) ([]SignRequest, error) {
	return buildRequests(txns, authAddresses, lsigArgsMap, opts, false)
}

// buildSignRequests converts transactions into sign requests: a position with
// no auth address is signed by its sender.
func buildSignRequests(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap) ([]SignRequest, error) {
	return buildRequests(txns, authAddresses, lsigArgsMap, nil, true)
}

// buildRequests is the one request builder. It refuses early what the signer
// could not use (an auth address that is not an address, a passthrough that is
// not a canonical signed transaction) and matches the LogicSig args against
// the positions. What it decodes to do that goes no further: the slots a
// response is checked against are decoded from the entries actually sent.
func buildRequests(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap, opts *SignOptions, senderSigns bool) ([]SignRequest, error) {
	if opts == nil {
		opts = &SignOptions{}
	}
	if err := validateIndexedLogicSigResources(opts.LsigResources, len(txns)); err != nil {
		return nil, err
	}
	requests := make([]SignRequest, len(txns))
	matchedArgs := make(map[string]bool, len(lsigArgsMap))

	for i, txn := range txns {
		authAddr := ""
		if i < len(authAddresses) {
			authAddr = authAddresses[i]
		}
		var resources *LogicSigResourceUsage
		if usage, ok := opts.LsigResources[i]; ok {
			resources = &usage
		}

		// Passthrough: include pre-signed transaction as-is
		if signed, ok := opts.Passthrough[i]; ok {
			decoded := append([]byte(nil), signed...)
			req := SignRequest{SignedTxnHex: hex.EncodeToString(decoded), LsigResources: resources}
			if err := req.Validate(); err != nil {
				return nil, fmt.Errorf("invalid passthrough transaction %d: %w", i+1, err)
			}
			slot, err := decodePassthroughSlot(decoded)
			if err != nil {
				return nil, fmt.Errorf("invalid passthrough transaction %d: %w", i+1, err)
			}
			// A passthrough position's authorizer is whoever signed it: the
			// signer its bytes name, or the sender when they name none. An
			// auth address given for the position counts too. The sender of a
			// rekeyed account is not its authorizer.
			if authAddr != "" {
				matchedArgs[authAddr] = true
			}
			if slot.signer.IsZero() {
				matchedArgs[slot.txn.Sender.String()] = true
			} else {
				matchedArgs[slot.signer.String()] = true
			}
			requests[i] = req
			continue
		}

		if authAddr == "" && senderSigns {
			authAddr = txn.Sender.String()
		}
		txnBytesHex := hex.EncodeToString(encodeTxn(txn))

		// Foreign mode: no auth address. Nothing names its authorizer, so
		// the sender stands for it.
		if authAddr == "" {
			matchedArgs[txn.Sender.String()] = true
			requests[i] = SignRequest{TxnBytesHex: txnBytesHex, LsigResources: resources}
			continue
		}

		if resources != nil {
			return nil, fmt.Errorf("lsig_resources[%d] is allowed only for foreign or passthrough transactions", i)
		}
		if _, err := signSlot(txn, authAddr); err != nil {
			return nil, fmt.Errorf("transaction %d: %w", i+1, err)
		}
		matchedArgs[authAddr] = true
		requests[i] = SignRequest{
			AuthAddress: authAddr,
			TxnSender:   txn.Sender.String(),
			TxnBytesHex: txnBytesHex,
			LsigArgs:    encodeLsigArgs(lsigArgsMap, authAddr),
		}
	}

	if err := requireLsigArgsMatched(lsigArgsMap, matchedArgs); err != nil {
		return nil, err
	}
	return requests, nil
}

// encodeLsigArgs returns the wire form of the args keyed to an auth address,
// or nil when the map has no entry for it.
func encodeLsigArgs(lsigArgsMap LsigArgsMap, authAddr string) map[string]string {
	args, ok := lsigArgsMap[authAddr]
	if !ok {
		return nil
	}
	encoded := make(map[string]string, len(args))
	for name, value := range args {
		encoded[name] = hex.EncodeToString(value)
	}
	return encoded
}

// requireLsigArgsMatched rejects LogicSig args keyed under an address that
// authorizes no position. Such a key is a mistake, and dropping its args
// would sign without them; an optional arg left out can select a different
// authorization branch. A position's authorizer is its auth address, never
// its sender when the two differ: args keyed under the sender of a rekeyed
// account would otherwise be dropped unnoticed. A key that is the authorizer
// of a passthrough or foreign position is fine: the same map can serve
// several calls over one group. An entry with no args is ignored.
func requireLsigArgsMatched(lsigArgsMap LsigArgsMap, matched map[string]bool) error {
	unmatched := make([]string, 0)
	for address, args := range lsigArgsMap {
		if len(args) > 0 && !matched[address] {
			unmatched = append(unmatched, fmt.Sprintf("%q", address))
		}
	}
	if len(unmatched) == 0 {
		return nil
	}
	sort.Strings(unmatched)
	return fmt.Errorf("lsig args are keyed by auth address, and no transaction in the request has auth address %s", strings.Join(unmatched, ", "))
}

func validateIndexedLogicSigResources(resources map[int]LogicSigResourceUsage, txnCount int) error {
	for index, usage := range resources {
		if index < 0 || index >= txnCount {
			return fmt.Errorf("lsig_resources index %d out of range for %d transactions", index, txnCount)
		}
		if err := usage.validate(); err != nil {
			return fmt.Errorf("lsig_resources[%d] is invalid: %w", index, err)
		}
	}
	return nil
}

func hasForeignRequests(requests []SignRequest) bool {
	for _, req := range requests {
		if req.TxnBytesHex != "" && req.AuthAddress == "" && req.SignedTxnHex == "" {
			return true
		}
	}
	return false
}

func validateRequests(requests []SignRequest) error {
	groupReq := groupSignRequest{Requests: requests}
	if err := groupReq.Validate(); err != nil {
		return fmt.Errorf("invalid sign request: %w", err)
	}
	return nil
}

// SignRequestsWithContext posts raw /sign requests and returns the server response.
func (c *SignerClient) SignRequestsWithContext(ctx context.Context, requests []SignRequest) (*GroupSignResponse, error) {
	requestID, err := newSignRequestID()
	if err != nil {
		return nil, fmt.Errorf("failed to create sign request ID: %w", err)
	}
	return c.SignGroupWithContext(ctx, GroupSignRequest{RequestID: requestID, Requests: requests})
}

// SignGroupWithContext posts a server-shaped /sign request and returns the server response.
func (c *SignerClient) SignGroupWithContext(ctx context.Context, groupReq GroupSignRequest) (*GroupSignResponse, error) {
	if groupReq.RequestID == "" {
		requestID, err := newSignRequestID()
		if err != nil {
			return nil, fmt.Errorf("failed to create sign request ID: %w", err)
		}
		groupReq.RequestID = requestID
	}
	if err := groupReq.Validate(); err != nil {
		return nil, err
	}
	resp, err := c.postSign(ctx, groupReq)
	var transport *signTransportError
	var unread *signUnreadError
	var body *signBodyError
	switch {
	case errors.As(err, &transport):
		return nil, fmt.Errorf("failed to make request to Signer: %w", &lostAnswer{requestID: groupReq.RequestID, err: transport.err})
	case errors.As(err, &unread):
		return nil, &lostAnswer{requestID: groupReq.RequestID, err: err}
	case errors.As(err, &body):
		return nil, fmt.Errorf("group signing failed: %s", body.message)
	}
	return resp, err
}

// readAnswer reads a 200 body as exactly one JSON value of out's shape. A
// failure to read the body and a body that does not decode are both errors;
// decodeAnswer is the decoding alone, for a caller that tells them apart.
func readAnswer(body io.Reader, out any) error {
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	return decodeAnswer(raw, out)
}

// decodeAnswer decodes a 200 body, read in full, as exactly one JSON value of
// out's shape. A null body, or anything after the value, is not an answer:
// json.Decoder would read null as an empty answer and stop at the end of the
// first value.
func decodeAnswer(raw []byte, out any) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("the answer is null")
	}
	return json.Unmarshal(raw, out)
}

// unreadableAnswer marks a 200 answer the SDK could not read, or refused as
// malformed. It reads as the error it wraps.
type unreadableAnswer struct{ err error }

func (e *unreadableAnswer) Error() string { return e.err.Error() }
func (e *unreadableAnswer) Unwrap() error { return e.err }

// lostAnswer marks an approval-bearing request that ended with no usable
// answer: the exchange failed, or a 200 arrived whose body could not be read.
// The signer may have acted on the request. requestID is that request's ID,
// as the signer's audit log records it. It reads as the error it wraps.
type lostAnswer struct {
	requestID string
	err       error
}

func (e *lostAnswer) Error() string { return e.err.Error() }
func (e *lostAnswer) Unwrap() error { return e.err }

// signTransportError is postSign's report that the HTTP exchange itself
// failed. Each caller words it its own way.
type signTransportError struct{ err error }

func (e *signTransportError) Error() string { return e.err.Error() }
func (e *signTransportError) Unwrap() error { return e.err }

// signUnreadError is postSign's report that the signer answered 200 and the
// body could not be read. The signer may have released a signature.
type signUnreadError struct{ err error }

func (e *signUnreadError) Error() string { return "failed to decode response: " + e.err.Error() }
func (e *signUnreadError) Unwrap() error { return e.err }

// signBodyError is postSign's report of an error carried in a 200 body, a
// legacy field the current server never sets.
type signBodyError struct{ message string }

func (e *signBodyError) Error() string { return e.message }

// postSign is the one /sign implementation. It decodes the slots a response
// is checked against from the very entries it sends, posts them, cancels a
// pending approval when the deadline or the caller's context ends first, and
// checks the response against the request, so a truncated, altered or padded
// group can never be returned for submission or simulation. groupReq must
// already be validated. A non-200 answer comes back as an *APIError, and a
// transport or body failure as its own type, for the caller to word and
// classify.
func (c *SignerClient) postSign(ctx context.Context, groupReq GroupSignRequest) (*GroupSignResponse, error) {
	slots, err := decodeRequestSlots(groupReq.Requests)
	if err != nil {
		return nil, fmt.Errorf("invalid sign request: %w", err)
	}
	ceiling := c.feeCeiling()
	jsonBody, err := json.Marshal(groupReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var groupResp GroupSignResponse
	if err := c.postApproval(ctx, "/sign", groupReq.RequestID, jsonBody, &groupResp); err != nil {
		return nil, err
	}

	if groupResp.Error != "" {
		return nil, &signBodyError{message: groupResp.Error}
	}

	if err := validateSignResponse(slots, groupResp.Signed, groupResp.Mutations, ceiling); err != nil {
		return nil, fmt.Errorf("verify signer response: %w", err)
	}

	return &groupResp, nil
}

// postApproval posts an approval-bearing request and decodes its 200 answer
// into out. It waits as long as the signer's approval wait allows, and
// cancels the pending approval when the deadline or the caller's context ends
// first. A context that has ended before the request is posted sends nothing
// and returns its own error. A non-200 answer comes back as an *APIError, a
// failed exchange as a *signTransportError, and a 200 whose body could not be
// read as a *signUnreadError.
func (c *SignerClient) postApproval(ctx context.Context, path, requestID string, jsonBody []byte, out any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// A context that has already ended sends nothing, not even the status
	// discovery, so it is a plain stop and not an exchange whose outcome is
	// unknown.
	if err := ctx.Err(); err != nil {
		return err
	}
	c.discoverApprovalWait(ctx)

	reqCtx, cancel := c.requestContext(ctx, c.signRequestTimeout())
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+path, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Checked again before the cancel watcher starts: a watcher started on an
	// ended context could cancel a request that was never posted.
	if err := reqCtx.Err(); err != nil {
		return err
	}

	var cancelOnce sync.Once
	sendCancel := func() {
		cancelOnce.Do(func() {
			cancelCtx, cancel := context.WithTimeout(context.Background(), signCancelTimeout)
			defer cancel()
			_, _ = c.CancelSignRequestWithContext(cancelCtx, requestID)
		})
	}
	// done is closed the moment the request returns so a deadline landing in
	// the same instant as a successful response cannot fire a spurious cancel
	// for a request the server already processed.
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
			return
		case <-reqCtx.Done():
		}
		select {
		case <-done:
			// Request finished in the same instant; nothing to cancel.
		default:
			sendCancel()
		}
	}()

	resp, err := c.client.Do(req)
	close(done)
	if err != nil {
		if reqCtx.Err() != nil {
			sendCancel()
		}
		return &signTransportError{err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return signerHTTPError(resp)
	}
	if err := readAnswer(resp.Body, out); err != nil {
		return &signUnreadError{err: err}
	}
	return nil
}

// CancelSignRequest asks apsigner to cancel a pending manual approval request.
func (c *SignerClient) CancelSignRequest(requestID string) (*CancelSignResponse, error) {
	return c.CancelSignRequestWithContext(context.Background(), requestID)
}

// CancelSignRequestWithContext asks apsigner to cancel a pending manual approval request.
func (c *SignerClient) CancelSignRequestWithContext(ctx context.Context, requestID string) (*CancelSignResponse, error) {
	cancelReq := CancelSignRequest{RequestID: requestID}
	if err := cancelReq.Validate(); err != nil {
		return nil, fmt.Errorf("invalid sign cancel request: %w", err)
	}

	jsonBody, err := json.Marshal(cancelReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqCtx, cancel := c.requestContext(ctx, signCancelTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/sign/cancel", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to cancel sign request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, ErrAuthentication
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer cancel error (%d): %s", resp.StatusCode, readErrorBody(resp))
	}

	var cancelResp CancelSignResponse
	if err := readAnswer(resp.Body, &cancelResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if cancelResp.Error != "" {
		return &cancelResp, fmt.Errorf("sign cancel failed: %s", cancelResp.Error)
	}
	return &cancelResp, nil
}

// sign performs the actual signing request and returns the signed group, one
// raw signed transaction per entry.
func (c *SignerClient) sign(requests []SignRequest) ([][]byte, error) {
	groupResp, err := c.signResponse(requests)
	if err != nil {
		return nil, err
	}
	return signedGroupFromHex(groupResp.Signed)
}

// signResponse is the /sign call behind SignTransactions and its variants. It
// maps 401, 403 and 503 to the SDK's sentinel errors.
func (c *SignerClient) signResponse(requests []SignRequest) (*GroupSignResponse, error) {
	requestID, err := newSignRequestID()
	if err != nil {
		return nil, fmt.Errorf("failed to create sign request ID: %w", err)
	}
	groupReq := groupSignRequest{RequestID: requestID, Requests: requests}
	if err := groupReq.Validate(); err != nil {
		return nil, fmt.Errorf("invalid sign request: %w", err)
	}
	resp, err := c.postSign(context.Background(), groupReq)
	var transport *signTransportError
	var body *signBodyError
	var apiErr *APIError
	switch {
	case errors.As(err, &transport):
		return nil, fmt.Errorf("failed to sign: %w", transport.err)
	case errors.As(err, &body):
		return nil, fmt.Errorf("signing failed: %s", body.message)
	case errors.As(err, &apiErr):
		switch apiErr.StatusCode {
		case http.StatusUnauthorized:
			return nil, ErrAuthentication
		case http.StatusForbidden:
			return nil, rejectedForbidden(apiErr)
		case http.StatusServiceUnavailable:
			return nil, ErrSignerUnavailable
		}
	}
	return resp, err
}

// lsigArgsToMap converts single LsigArgs to LsigArgsMap.
func lsigArgsToMap(authAddress string, args LsigArgs) LsigArgsMap {
	if args == nil {
		return nil
	}
	return LsigArgsMap{authAddress: args}
}
