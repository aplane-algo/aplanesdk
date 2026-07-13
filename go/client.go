// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SignerClient is the client for connecting to apsigner.
type SignerClient struct {
	baseURL               string
	token                 string
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
}

const (
	healthTimeout             = 3 * time.Second
	statusTimeout             = 5 * time.Second
	inventoryTimeout          = 30 * time.Second
	mutationTimeout           = 60 * time.Second
	groupPlanTimeout          = 60 * time.Second
	groupSimulateTimeout      = 60 * time.Second
	componentSignTimeout      = 2 * time.Minute
	guardedSimulateTimeout    = 2 * time.Minute
	guardedAssemblyTimeout    = 2 * time.Minute
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

// NewSignerClientWithToken creates a signer client for an already-known base URL.
// This is useful when the caller owns the transport or tunnel lifecycle.
func NewSignerClientWithToken(baseURL, token string) *SignerClient {
	return &SignerClient{
		baseURL:  baseURL,
		token:    token,
		client:   &http.Client{},
		keyCache: nil,
	}
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
// (empty on pre-code signers) and the human-readable message.
func readErrorParts(resp *http.Response) (code, message string) {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Sprintf("<failed to read error body: %v>", err)
	}
	body := strings.TrimSpace(string(bodyBytes))
	if body == "" {
		return "", http.StatusText(resp.StatusCode)
	}

	var errorResp ErrorResponse
	if err := json.Unmarshal(bodyBytes, &errorResp); err == nil && errorResp.Error != "" {
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

// lockedForbiddenError classifies a 403 at endpoints that historically
// reported the signer as locked. The wire code distinguishes a genuinely
// locked signer from other forbidden conditions; pre-code signers send no
// code and keep the legacy locked mapping.
func lockedForbiddenError(resp *http.Response) error {
	apiErr := signerHTTPError(resp)
	switch apiErr.Code {
	case "", ErrCodeLocked:
		return ErrSignerLocked
	default:
		return apiErr
	}
}

// rejectedForbiddenError classifies a 403 at endpoints that historically
// reported the request as rejected. A locked code maps to ErrSignerLocked;
// forbidden (or no code, for pre-code signers) keeps the rejection sentinel.
func rejectedForbiddenError(resp *http.Response) error {
	apiErr := signerHTTPError(resp)
	switch apiErr.Code {
	case ErrCodeLocked:
		return ErrSignerLocked
	case "", ErrCodeForbidden:
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

// ConnectSSH creates a client connected via SSH tunnel.
func ConnectSSH(host, token, sshKeyPath string, opts *SSHConnectOptions) (*SignerClient, error) {
	sshPort := DefaultSSHPort
	signerPort := DefaultSignerPort
	timeout := DefaultTimeout

	var knownHostsPath string

	if opts != nil {
		if opts.SSHPort > 0 {
			sshPort = opts.SSHPort
		}
		if opts.SignerPort > 0 {
			signerPort = opts.SignerPort
		}
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
		if opts.KnownHostsPath != "" {
			knownHostsPath = opts.KnownHostsPath
		}
	}

	trustOnFirstUse := opts != nil && opts.TrustOnFirstUse
	tunnel := &sshTunnel{knownHostsPath: knownHostsPath, trustOnFirstUse: trustOnFirstUse}
	localPort, err := tunnel.connect(host, sshPort, signerPort, token, ExpandPath(sshKeyPath))
	if err != nil {
		return nil, fmt.Errorf("failed to establish SSH tunnel: %w", err)
	}

	return &SignerClient{
		baseURL:           fmt.Sprintf("http://localhost:%d", localPort),
		token:             token,
		client:            &http.Client{},
		sshTunnel:         tunnel,
		requestTimeout:    time.Duration(timeout) * time.Second,
		requestTimeoutSet: opts != nil && opts.Timeout > 0,
	}, nil
}

// FromEnv creates a client from environment configuration.
// Reads token from dataDir/aplane.token and config from dataDir/config.yaml.
// If config contains SSH settings, connects via SSH tunnel.
func FromEnv(opts *FromEnvOptions) (*SignerClient, error) {
	dataDir := ""
	timeout := 0

	if opts != nil {
		if opts.DataDir != "" {
			dataDir = opts.DataDir
		}
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
	}

	dataDir, err := ResolveDataDir(dataDir)
	if err != nil {
		return nil, err
	}

	// Load token
	token, err := LoadTokenFromDir(dataDir)
	if err != nil {
		return nil, err
	}

	// Load config
	config, err := LoadConfig(dataDir)
	if err != nil {
		return nil, err
	}

	// SSH is required
	if config.SSH == nil || config.SSH.Host == "" {
		return nil, fmt.Errorf("no endpoint.ssh block in config.yaml; add endpoint.ssh with host, port, and identity_file")
	}

	sshKeyPath := ResolvePath(config.SSH.IdentityFile, dataDir)
	knownHostsPath := ResolvePath(config.SSH.KnownHostsPath, dataDir)
	sshOpts := &SSHConnectOptions{
		SSHPort:         config.SSH.Port,
		SignerPort:      config.SignerPort,
		KnownHostsPath:  knownHostsPath,
		TrustOnFirstUse: config.SSH.TrustOnFirstUse,
	}
	if timeout > 0 {
		sshOpts.Timeout = timeout
	}
	return ConnectSSH(config.SSH.Host, token, sshKeyPath, sshOpts)
}

// Close closes the client and any SSH tunnel.
func (c *SignerClient) Close() {
	if c.sshTunnel != nil {
		c.sshTunnel.close()
	}
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
	req.Header.Set("Authorization", "aplane "+c.token)

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

	var identityResp StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&identityResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	c.cacheApprovalWait(identityResp.ApprovalWaitSeconds)

	return &identityResp, nil
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
	c.keyMu.RLock()
	if c.keyCache != nil {
		if k, ok := c.keyCache[address]; ok {
			c.keyMu.RUnlock()
			return k, nil
		}
	}
	c.keyMu.RUnlock()

	if _, err := c.ListKeys(true); err != nil {
		return nil, err
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
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		apiErr := signerHTTPError(resp)
		switch apiErr.Code {
		case "", ErrCodeLocked:
			return &KeysResult{Locked: true}, nil
		default:
			return nil, apiErr
		}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrAuthentication
	}
	if resp.StatusCode != http.StatusOK {
		return nil, signerHTTPError(resp)
	}

	var keysResp keysResponse
	if err := json.NewDecoder(resp.Body).Decode(&keysResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	cache := make(map[string]*KeyInfo, len(keysResp.Keys))
	for i := range keysResp.Keys {
		k := &keysResp.Keys[i]
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

// ListKeyTypes returns available key types and their creation parameters.
func (c *SignerClient) ListKeyTypes() ([]KeyTypeInfo, error) {
	reqCtx, cancel := c.requestContext(context.Background(), inventoryTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", c.baseURL+"/keytypes", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "aplane "+c.token)

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
	if err := json.NewDecoder(resp.Body).Decode(&ktResp); err != nil {
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
	req.Header.Set("Authorization", "aplane "+c.token)

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

	var result GenerateResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Invalidate key cache
	c.keyMu.Lock()
	c.keyCache = nil
	c.invalidateKeyCacheRevisionLocked()
	c.keyMu.Unlock()

	return &result, nil
}

// DeleteKey deletes a key from the signer.
func (c *SignerClient) DeleteKey(address string) error {
	reqCtx, cancel := c.requestContext(context.Background(), mutationTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "DELETE", c.baseURL+"/admin/keys?"+url.Values{"address": []string{address}}.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "aplane "+c.token)

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

	// Invalidate key cache
	c.keyMu.Lock()
	c.keyCache = nil
	c.invalidateKeyCacheRevisionLocked()
	c.keyMu.Unlock()

	return nil
}

// RequestComponentSign sends a role-specific component signing request to
// /sign/component.
func (c *SignerClient) RequestComponentSign(req ComponentSignRequest) (*ComponentSignResponse, error) {
	return c.RequestComponentSignWithContext(context.Background(), req)
}

// RequestComponentSignWithContext sends a role-specific component signing
// request to /sign/component.
func (c *SignerClient) RequestComponentSignWithContext(ctx context.Context, reqBody ComponentSignRequest) (*ComponentSignResponse, error) {
	if reqBody.RequestID == "" {
		requestID, err := newSignRequestID()
		if err != nil {
			return nil, fmt.Errorf("failed to create component sign request ID: %w", err)
		}
		reqBody.RequestID = requestID
	}
	if err := reqBody.Validate(); err != nil {
		return nil, fmt.Errorf("invalid component sign request: %w", err)
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// User-role component signing runs the signer-domain approval gates and
	// can block on a manual approval decision, so it needs the same
	// approval-aware deadline as /sign. Sentry-role requests are deterministic
	// and keep the short component deadline.
	timeout := componentSignTimeout
	if reqBody.Role == ComponentSignRoleUser {
		c.discoverApprovalWait(ctx)
		if signTimeout := c.signRequestTimeout(); signTimeout > timeout {
			timeout = signTimeout
		}
	}

	reqCtx, cancel := c.requestContext(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/sign/component", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to Signer: %w", err)
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

	var componentResp ComponentSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&componentResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if err := componentResp.Validate(); err != nil {
		return nil, fmt.Errorf("invalid component sign response: %w", err)
	}
	return &componentResp, nil
}

// RequestGuardedSimulate sends a contained guarded simulation request to
// /simulate/guarded.
func (c *SignerClient) RequestGuardedSimulate(req GuardedSimulateRequest) (*GuardedSimulateResponse, error) {
	return c.RequestGuardedSimulateWithContext(context.Background(), req)
}

// RequestGuardedSimulateWithContext sends a contained guarded simulation
// request to /simulate/guarded. The signer produces user component signatures
// internally and returns only simulation results, never signed bytes.
func (c *SignerClient) RequestGuardedSimulateWithContext(ctx context.Context, reqBody GuardedSimulateRequest) (*GuardedSimulateResponse, error) {
	if reqBody.RequestID == "" {
		requestID, err := newSignRequestID()
		if err != nil {
			return nil, fmt.Errorf("failed to create guarded simulate request ID: %w", err)
		}
		reqBody.RequestID = requestID
	}
	if err := reqBody.Validate(); err != nil {
		return nil, fmt.Errorf("invalid guarded simulate request: %w", err)
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqCtx, cancel := c.requestContext(ctx, guardedSimulateTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/simulate/guarded", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to Signer: %w", err)
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

	var simulateResp GuardedSimulateResponse
	if err := json.NewDecoder(resp.Body).Decode(&simulateResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if simulateResp.Error != "" {
		return nil, fmt.Errorf("guarded simulation failed: %s", simulateResp.Error)
	}
	if err := simulateResp.Validate(); err != nil {
		return nil, fmt.Errorf("invalid guarded simulate response: %w", err)
	}
	return &simulateResp, nil
}

// RequestGuardedAssemble sends a guarded transaction assembly request to
// /sign/assemble.
func (c *SignerClient) RequestGuardedAssemble(req GuardedAssemblyRequest) (*GuardedAssemblyResponse, error) {
	return c.RequestGuardedAssembleWithContext(context.Background(), req)
}

// RequestGuardedAssembleWithContext sends a guarded transaction assembly
// request to /sign/assemble.
func (c *SignerClient) RequestGuardedAssembleWithContext(ctx context.Context, reqBody GuardedAssemblyRequest) (*GuardedAssemblyResponse, error) {
	if reqBody.RequestID == "" {
		requestID, err := newSignRequestID()
		if err != nil {
			return nil, fmt.Errorf("failed to create guarded assembly request ID: %w", err)
		}
		reqBody.RequestID = requestID
	}
	if err := reqBody.Validate(); err != nil {
		return nil, fmt.Errorf("invalid guarded assembly request: %w", err)
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqCtx, cancel := c.requestContext(ctx, guardedAssemblyTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/sign/assemble", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to Signer: %w", err)
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

	var assemblyResp GuardedAssemblyResponse
	if err := json.NewDecoder(resp.Body).Decode(&assemblyResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if err := assemblyResp.Validate(); err != nil {
		return nil, fmt.Errorf("invalid guarded assembly response: %w", err)
	}
	return &assemblyResp, nil
}

// AdminSyncSentryReferences syncs public sentry reference candidates into the
// connected signer identity.
func (c *SignerClient) AdminSyncSentryReferences(candidates []SentryReferenceCandidate) (*AdminSyncSentryReferencesResponse, error) {
	return c.AdminSyncSentryReferencesWithContext(context.Background(), candidates)
}

// AdminSyncSentryReferencesWithContext syncs public sentry reference
// candidates into the connected signer identity.
func (c *SignerClient) AdminSyncSentryReferencesWithContext(ctx context.Context, candidates []SentryReferenceCandidate) (*AdminSyncSentryReferencesResponse, error) {
	reqBody := AdminSyncSentryReferencesRequest{Candidates: candidates}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqCtx, cancel := c.requestContext(ctx, mutationTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/admin/sentries/sync", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to sync sentry references: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, ErrAuthentication
	}
	if resp.StatusCode == 403 {
		return nil, lockedForbiddenError(resp)
	}
	if resp.StatusCode != 200 {
		return nil, signerHTTPError(resp)
	}

	var syncResp AdminSyncSentryReferencesResponse
	if err := json.NewDecoder(resp.Body).Decode(&syncResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if syncResp.Error != "" {
		return nil, fmt.Errorf("sentry reference sync failed: %s", syncResp.Error)
	}
	return &syncResp, nil
}

// PlanGroup previews group building without signing or approval.
func (c *SignerClient) PlanGroup(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap, opts *SignOptions) (*PlanGroupResponse, error) {
	requests, err := buildSignRequestsWithOptions(txns, authAddresses, lsigArgsMap, opts)
	if err != nil {
		return nil, err
	}
	if err := validateRequests(requests); err != nil {
		return nil, err
	}
	return c.PlanRequestsWithContext(context.Background(), requests)
}

// PlanRequestsWithContext posts raw /plan requests without rebuilding them from transactions.
func (c *SignerClient) PlanRequestsWithContext(ctx context.Context, requests []SignRequest) (*PlanGroupResponse, error) {
	if err := validateRequests(requests); err != nil {
		return nil, err
	}
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
	req.Header.Set("Authorization", "aplane "+c.token)

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
	if err := json.NewDecoder(resp.Body).Decode(&planResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if planResp.Error != "" {
		return nil, fmt.Errorf("plan failed: %s", planResp.Error)
	}

	return &planResp, nil
}

// SimulateGroup performs signer-managed simulation for a caller-built group.
func (c *SignerClient) SimulateGroup(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap, opts *SignOptions) (*GroupSimulateResponse, error) {
	requests, err := buildSignRequestsWithOptions(txns, authAddresses, lsigArgsMap, opts)
	if err != nil {
		return nil, err
	}
	return c.SimulateRequestsWithContext(context.Background(), requests)
}

// SimulatePreparedTransaction performs signer-managed simulation for one prepared transaction.
func (c *SignerClient) SimulatePreparedTransaction(ctx context.Context, prepared PreparedTransaction) (*GroupSimulateResponse, error) {
	return c.SimulatePreparedGroup(ctx, NewPreparedGroup(prepared))
}

// SimulatePreparedGroup performs signer-managed simulation for a prepared group.
func (c *SignerClient) SimulatePreparedGroup(ctx context.Context, group PreparedGroup) (*GroupSimulateResponse, error) {
	requests, err := group.SignRequests()
	if err != nil {
		return nil, err
	}
	return c.SimulateRequestsWithContext(ctx, requests)
}

// SimulateRequests posts raw /simulate requests without rebuilding them from transactions.
func (c *SignerClient) SimulateRequests(requests []SignRequest) (*GroupSimulateResponse, error) {
	return c.SimulateRequestsWithContext(context.Background(), requests)
}

// SimulateRequestsWithContext posts raw /simulate requests without rebuilding them from transactions.
func (c *SignerClient) SimulateRequestsWithContext(ctx context.Context, requests []SignRequest) (*GroupSimulateResponse, error) {
	if err := validateRequests(requests); err != nil {
		return nil, err
	}
	groupReq := groupSignRequest{Requests: requests}

	jsonBody, err := json.Marshal(groupReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqCtx, cancel := c.requestContext(ctx, groupSimulateTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/simulate", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to simulate group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, ErrAuthentication
	}
	if resp.StatusCode != 200 {
		return nil, signerHTTPErrorOp(resp, "simulate failed")
	}

	var simulateResp GroupSimulateResponse
	if err := json.NewDecoder(resp.Body).Decode(&simulateResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if simulateResp.Error != "" {
		return nil, fmt.Errorf("simulate failed: %s", simulateResp.Error)
	}

	return &simulateResp, nil
}

// SignTransaction signs a single transaction.
// Returns the signed transaction as base64.
func (c *SignerClient) SignTransaction(txn types.Transaction, authAddress string, lsigArgs LsigArgs) (string, error) {
	signed, err := c.SignTransactions([]types.Transaction{txn}, []string{authAddress}, lsigArgsToMap(authAddress, lsigArgs))
	return signed, err
}

// SignTransactions signs multiple transactions as a group.
// Returns concatenated signed transactions as base64.
func (c *SignerClient) SignTransactions(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap) (string, error) {
	return c.sign(buildSignRequests(txns, authAddresses, lsigArgsMap))
}

// SignTransactionsWithOptions signs transactions with passthrough support.
// Returns concatenated signed transactions as base64.
func (c *SignerClient) SignTransactionsWithOptions(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap, opts *SignOptions) (string, error) {
	requests, err := buildSignRequestsWithOptions(txns, authAddresses, lsigArgsMap, opts)
	if err != nil {
		return "", err
	}
	if hasForeignRequests(requests) {
		return "", fmt.Errorf("foreign entries are only supported on /plan; use PlanGroup first, then resubmit foreign slots as passthrough")
	}
	return c.sign(requests)
}

// SignTransactionsList signs transactions and returns individual base64 strings.
func (c *SignerClient) SignTransactionsList(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap) ([]string, error) {
	return c.signList(buildSignRequests(txns, authAddresses, lsigArgsMap))
}

// SignTransactionsListWithOptions signs transactions with passthrough support
// and returns individual base64 strings.
func (c *SignerClient) SignTransactionsListWithOptions(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap, opts *SignOptions) ([]string, error) {
	requests, err := buildSignRequestsWithOptions(txns, authAddresses, lsigArgsMap, opts)
	if err != nil {
		return nil, err
	}
	if hasForeignRequests(requests) {
		return nil, fmt.Errorf("foreign entries are only supported on /plan; use PlanGroup first, then resubmit foreign slots as passthrough")
	}
	return c.signList(requests)
}

// buildSignRequestsWithOptions converts transactions into sign requests with passthrough/foreign support.
func buildSignRequestsWithOptions(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap, opts *SignOptions) ([]SignRequest, error) {
	requests := make([]SignRequest, len(txns))

	for i, txn := range txns {
		// Passthrough: include pre-signed transaction as-is
		if opts != nil && opts.Passthrough != nil {
			if b64, ok := opts.Passthrough[i]; ok {
				decoded, err := base64.StdEncoding.DecodeString(b64)
				if err != nil {
					return nil, fmt.Errorf("invalid passthrough transaction %d: invalid base64: %w", i+1, err)
				}
				requests[i] = SignRequest{SignedTxnHex: hex.EncodeToString(decoded)}
				continue
			}
		}

		txnBytes := encodeTxn(txn)
		txnBytesHex := hex.EncodeToString(txnBytes)

		authAddr := ""
		if i < len(authAddresses) {
			authAddr = authAddresses[i]
		}

		// Foreign mode: no auth address
		if authAddr == "" {
			req := SignRequest{TxnBytesHex: txnBytesHex}
			if opts != nil && opts.LsigSizes != nil {
				if size, ok := opts.LsigSizes[i]; ok {
					req.LsigSize = size
				}
			}
			requests[i] = req
			continue
		}

		req := SignRequest{
			AuthAddress: authAddr,
			TxnSender:   txn.Sender.String(),
			TxnBytesHex: txnBytesHex,
		}

		if lsigArgsMap != nil {
			if args, ok := lsigArgsMap[authAddr]; ok {
				req.LsigArgs = make(map[string]string)
				for name, value := range args {
					req.LsigArgs[name] = hex.EncodeToString(value)
				}
			}
		}

		requests[i] = req
	}

	return requests, nil
}

func hasForeignRequests(requests []SignRequest) bool {
	for _, req := range requests {
		if req.TxnBytesHex != "" && req.AuthAddress == "" && req.SignedTxnHex == "" {
			return true
		}
	}
	return false
}

// buildSignRequests converts transactions into sign requests.
func buildSignRequests(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap) []SignRequest {
	requests := make([]SignRequest, len(txns))

	for i, txn := range txns {
		txnBytes := encodeTxn(txn)
		txnBytesHex := hex.EncodeToString(txnBytes)

		authAddr := txn.Sender.String()
		if i < len(authAddresses) && authAddresses[i] != "" {
			authAddr = authAddresses[i]
		}

		req := SignRequest{
			AuthAddress: authAddr,
			TxnSender:   txn.Sender.String(),
			TxnBytesHex: txnBytesHex,
		}

		if lsigArgsMap != nil {
			if args, ok := lsigArgsMap[authAddr]; ok {
				req.LsigArgs = make(map[string]string)
				for name, value := range args {
					req.LsigArgs[name] = hex.EncodeToString(value)
				}
			}
		}

		requests[i] = req
	}

	return requests
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

	jsonBody, err := json.Marshal(groupReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	c.discoverApprovalWait(ctx)

	reqCtx, cancel := c.requestContext(ctx, c.signRequestTimeout())
	defer cancel()

	var cancelOnce sync.Once
	sendCancel := func() {
		cancelOnce.Do(func() {
			cancelCtx, cancel := context.WithTimeout(context.Background(), signCancelTimeout)
			defer cancel()
			_, _ = c.CancelSignRequestWithContext(cancelCtx, groupReq.RequestID)
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

	req, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/sign", bytes.NewBuffer(jsonBody))
	if err != nil {
		close(done)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	close(done)
	if err != nil {
		if reqCtx.Err() != nil {
			sendCancel()
		}
		return nil, fmt.Errorf("failed to make request to Signer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, signerHTTPError(resp)
	}

	var groupResp GroupSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&groupResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if groupResp.Error != "" {
		return nil, fmt.Errorf("group signing failed: %s", groupResp.Error)
	}

	if err := validateGroupSignResponse(groupReq.Requests, groupResp.Signed); err != nil {
		return nil, err
	}

	return &groupResp, nil
}

// validateGroupSignResponse rejects truncated or partially empty /sign
// responses so a malformed signer reply can never submit an incomplete
// group. The server may append signed dummy transactions after the request
// slots, and foreign-mode slots are returned empty by design.
func validateGroupSignResponse(requests []SignRequest, signed []string) error {
	if len(signed) < len(requests) {
		return fmt.Errorf("signer returned %d signed transaction(s), want at least %d", len(signed), len(requests))
	}
	for i, req := range requests {
		mode, err := req.Mode()
		if err != nil {
			continue
		}
		if mode == RequestModeForeign {
			continue
		}
		if signed[i] == "" {
			return fmt.Errorf("signer returned no signature for position %d", i+1)
		}
	}
	for i := len(requests); i < len(signed); i++ {
		if signed[i] == "" {
			return fmt.Errorf("signer returned empty dummy transaction at position %d", i+1)
		}
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
	req.Header.Set("Authorization", "aplane "+c.token)

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
	if err := json.NewDecoder(resp.Body).Decode(&cancelResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if cancelResp.Error != "" {
		return &cancelResp, fmt.Errorf("sign cancel failed: %s", cancelResp.Error)
	}
	return &cancelResp, nil
}

// sign performs the actual signing request.
func (c *SignerClient) sign(requests []SignRequest) (string, error) {
	groupResp, err := c.signResponse(requests)
	if err != nil {
		return "", err
	}

	// Concatenate signed transactions and convert to base64
	return hexArrayToBase64(groupResp.Signed)
}

// signList performs a signing request and returns individual base64 strings.
func (c *SignerClient) signList(requests []SignRequest) ([]string, error) {
	groupResp, err := c.signResponse(requests)
	if err != nil {
		return nil, err
	}

	// Convert each signed transaction individually
	result := make([]string, len(groupResp.Signed))
	for i, h := range groupResp.Signed {
		decoded, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signed transaction %d: %w", i, err)
		}
		result[i] = base64.StdEncoding.EncodeToString(decoded)
	}
	return result, nil
}

func (c *SignerClient) signResponse(requests []SignRequest) (*GroupSignResponse, error) {
	requestID, err := newSignRequestID()
	if err != nil {
		return nil, fmt.Errorf("failed to create sign request ID: %w", err)
	}
	groupReq := groupSignRequest{RequestID: requestID, Requests: requests}
	if err := groupReq.Validate(); err != nil {
		return nil, fmt.Errorf("invalid sign request: %w", err)
	}

	jsonBody, err := json.Marshal(groupReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	ctx := context.Background()
	c.discoverApprovalWait(ctx)

	reqCtx, cancel := c.requestContext(ctx, c.signRequestTimeout())
	defer cancel()

	var cancelOnce sync.Once
	sendCancel := func() {
		cancelOnce.Do(func() {
			cancelCtx, cancel := context.WithTimeout(context.Background(), signCancelTimeout)
			defer cancel()
			_, _ = c.CancelSignRequestWithContext(cancelCtx, requestID)
		})
	}
	// done is closed the moment the request returns so a deadline landing in the
	// same instant as a successful response cannot fire a spurious cancel for a
	// request the server already processed. Mirrors SignGroupWithContext.
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
			return
		case <-reqCtx.Done():
		}
		select {
		case <-done:
		default:
			sendCancel()
		}
	}()

	req, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/sign", bytes.NewBuffer(jsonBody))
	if err != nil {
		close(done)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	close(done)
	if err != nil {
		if reqCtx.Err() != nil {
			sendCancel()
		}
		return nil, fmt.Errorf("failed to sign: %w", err)
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

	var groupResp GroupSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&groupResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if groupResp.Error != "" {
		return nil, fmt.Errorf("signing failed: %s", groupResp.Error)
	}

	// Shape-validate here so every legacy sign path (sign/signList and their
	// public callers SignTransactions*/SignTransactionsList*) gets the same
	// truncated/empty-slot protection that SignGroupWithContext has; otherwise
	// hexArrayToBase64 below would silently decode an empty hex slot to empty
	// bytes and yield a partial group.
	if err := validateGroupSignResponse(requests, groupResp.Signed); err != nil {
		return nil, err
	}

	return &groupResp, nil
}

// lsigArgsToMap converts single LsigArgs to LsigArgsMap.
func lsigArgsToMap(authAddress string, args LsigArgs) LsigArgsMap {
	if args == nil {
		return nil
	}
	return LsigArgsMap{authAddress: args}
}
