// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// maxEnrollmentLabelBytes bounds the display label a client may attach to
// its enrollment request; the signer refuses longer labels.
const maxEnrollmentLabelBytes = 64

// enrollmentCommand is the exec command a request-enrollment session runs.
const enrollmentCommand = "enroll"

// EnrollmentResult is the signer's answer to an enrollment request.
type EnrollmentResult struct {
	// Fingerprint is the SHA256 fingerprint of the client key the request
	// was made with; it equals the key the client authenticated with.
	Fingerprint string
	// Pending reports that the request was queued for the operator to
	// approve later in apadmin (the normal outcome). False means the key was
	// already enrolled.
	Pending bool
}

// EnrollmentOptions configures RequestEnrollment.
type EnrollmentOptions struct {
	// SSHPort is the signer's SSH port (default DefaultSSHPort).
	SSHPort int
	// KnownHostsPath pins the signer's host key; it is required.
	KnownHostsPath string
	// TrustOnFirstUse lets this call trust and save an unknown host key.
	TrustOnFirstUse bool
	// SSHSetupTimeout bounds TCP dialing and SSH authentication, not the
	// wait for operator approval.
	SSHSetupTimeout time.Duration
}

// RequestEnrollment asks the signer at host to enroll the client SSH key at
// sshKeyPath, so that key can open API connections. The signer answers at
// once: the request is queued for the operator to approve later in apadmin
// (Pending), or the key is already enrolled. Nothing waits for the operator
// and nothing is stored on the client: the key is its credential, and the
// client learns the outcome by connecting after approval (an unenrolled key
// still fails the handshake with ErrNotEnrolled). label is an optional
// display label for the operator (printable, single line, at most 64 bytes).
func RequestEnrollment(host, sshKeyPath, label string, opts *EnrollmentOptions) (EnrollmentResult, error) {
	return RequestEnrollmentWithContext(context.Background(), host, sshKeyPath, label, opts)
}

// RequestEnrollmentWithContext is the context-aware form of
// RequestEnrollment.
func RequestEnrollmentWithContext(ctx context.Context, host, sshKeyPath, label string, opts *EnrollmentOptions) (EnrollmentResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateEnrollmentLabel(label); err != nil {
		return EnrollmentResult{}, err
	}
	sshPort := DefaultSSHPort
	setupTimeout := defaultSSHSetupTimeout
	knownHostsPath := ""
	trustOnFirstUse := false
	if opts != nil {
		if opts.SSHPort > 0 {
			sshPort = opts.SSHPort
		}
		if opts.SSHSetupTimeout > 0 {
			setupTimeout = opts.SSHSetupTimeout
		}
		knownHostsPath = opts.KnownHostsPath
		trustOnFirstUse = opts.TrustOnFirstUse
	}
	tunnel := &sshTunnel{knownHostsPath: ExpandPath(knownHostsPath), trustOnFirstUse: trustOnFirstUse}
	hostKeyCallback, err := tunnel.buildHostKeyCallback()
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("failed to set up host key verification: %w", err)
	}

	keyData, err := os.ReadFile(ExpandPath(sshKeyPath))
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("failed to read SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("failed to parse SSH key: %w", err)
	}
	clientFingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	config := &ssh.ClientConfig{
		User:            enrollmentSSHUsername,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
	}
	addr := fmt.Sprintf("%s:%d", host, sshPort)
	client, err := dialSSHHandshake(ctx, "tcp", addr, config, setupTimeout)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("%w: failed to connect to SSH server: %v", ErrEnrollment, err)
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("%w: failed to create session: %v", ErrEnrollment, err)
	}
	defer func() { _ = session.Close() }()
	stop := context.AfterFunc(ctx, func() {
		_ = session.Close()
		_ = client.Close()
	})
	defer stop()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("%w: %v", ErrEnrollment, err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("%w: %v", ErrEnrollment, err)
	}
	command := enrollmentCommand
	if label != "" {
		command += " " + label
	}
	if err := session.Start(command); err != nil {
		if ctx.Err() != nil {
			return EnrollmentResult{}, ctx.Err()
		}
		return EnrollmentResult{}, fmt.Errorf("%w: failed to start enrollment: %v", ErrEnrollment, err)
	}

	// Drain both pipes concurrently: reading them in sequence can deadlock
	// when the remote fills the unread pipe's window before closing the other.
	var errOutput []byte
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		errOutput, _ = io.ReadAll(stderr)
	}()
	output, err := io.ReadAll(stdout)
	<-stderrDone
	if ctx.Err() != nil {
		return EnrollmentResult{}, ctx.Err()
	}
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("%w: failed to read response: %v", ErrEnrollment, err)
	}
	if err := session.Wait(); err != nil {
		if ctx.Err() != nil {
			return EnrollmentResult{}, ctx.Err()
		}
		message := strings.TrimSpace(string(errOutput))
		if message == "" {
			message = strings.TrimSpace(string(output))
		}
		message = strings.TrimPrefix(message, "ERROR: ")
		if message == "" {
			message = err.Error()
		}
		return EnrollmentResult{}, fmt.Errorf("%w: %s", ErrEnrollment, message)
	}

	result, err := parseEnrollmentReply(strings.TrimSpace(string(output)), clientFingerprint)
	if err != nil {
		return EnrollmentResult{}, err
	}
	return result, nil
}

// parseEnrollmentReply reads the signer's answer: "pending <fingerprint>"
// when the request was queued for the operator, "enrolled <fingerprint>"
// when the key was already enrolled. The fingerprint must be the key this
// client authenticated with.
func parseEnrollmentReply(reply, clientFingerprint string) (EnrollmentResult, error) {
	var result EnrollmentResult
	switch {
	case strings.HasPrefix(reply, "pending "):
		result = EnrollmentResult{Fingerprint: strings.TrimPrefix(reply, "pending "), Pending: true}
	case strings.HasPrefix(reply, "enrolled "):
		result = EnrollmentResult{Fingerprint: strings.TrimPrefix(reply, "enrolled ")}
	default:
		return EnrollmentResult{}, fmt.Errorf("%w: unexpected response %q", ErrEnrollment, reply)
	}
	if result.Fingerprint == "" {
		return EnrollmentResult{}, fmt.Errorf("%w: unexpected response %q", ErrEnrollment, reply)
	}
	if result.Fingerprint != clientFingerprint {
		return EnrollmentResult{}, fmt.Errorf("%w: signer answered for %s, but this client authenticated with %s", ErrEnrollment, result.Fingerprint, clientFingerprint)
	}
	return result, nil
}

// RequestEnrollmentFromEnv asks the endpoint selected by opts (the default
// signer, or opts.Endpoint) to enroll the client key configured for it in
// dataDir/endpoints.yaml. See RequestEnrollment for the result.
func RequestEnrollmentFromEnv(opts *FromEnvOptions, label string) (EnrollmentResult, error) {
	return RequestEnrollmentFromEnvWithContext(context.Background(), opts, label)
}

// RequestEnrollmentFromEnvWithContext is the context-aware form of
// RequestEnrollmentFromEnv.
func RequestEnrollmentFromEnvWithContext(ctx context.Context, opts *FromEnvOptions, label string) (EnrollmentResult, error) {
	dataDir := ""
	endpointAlias := ""
	sshSetupTimeout := time.Duration(0)
	trustOnFirstUse := false
	if opts != nil {
		dataDir = opts.DataDir
		endpointAlias = opts.Endpoint
		sshSetupTimeout = opts.SSHSetupTimeout
		trustOnFirstUse = opts.TrustOnFirstUse
	}
	dataDir, err := ResolveDataDir(dataDir)
	if err != nil {
		return EnrollmentResult{}, err
	}
	if _, err := LoadConfig(dataDir); err != nil {
		return EnrollmentResult{}, err
	}
	registry, err := LoadClientEndpointRegistry(dataDir)
	if err != nil {
		return EnrollmentResult{}, err
	}
	_, endpoint, err := ResolveClientEndpoint(registry, endpointAlias)
	if err != nil {
		return EnrollmentResult{}, err
	}
	host, sshPort, err := ClientEndpointSSHHostPort(endpoint)
	if err != nil {
		return EnrollmentResult{}, err
	}
	if _, err := os.Stat(endpoint.IdentityFile); err != nil {
		return EnrollmentResult{}, fmt.Errorf("SSH key not found at %s; create one with: ssh-keygen -t ed25519 -f %s", endpoint.IdentityFile, endpoint.IdentityFile)
	}
	return RequestEnrollmentWithContext(ctx, host, endpoint.IdentityFile, label, &EnrollmentOptions{
		SSHPort:         sshPort,
		KnownHostsPath:  endpoint.KnownHostsPath,
		TrustOnFirstUse: trustOnFirstUse,
		SSHSetupTimeout: sshSetupTimeout,
	})
}

// validateEnrollmentLabel enforces the signer's label rules locally so a bad
// label fails before any network activity.
func validateEnrollmentLabel(label string) error {
	if label == "" {
		return nil
	}
	if len(label) > maxEnrollmentLabelBytes {
		return fmt.Errorf("enrollment label must be at most %d bytes", maxEnrollmentLabelBytes)
	}
	if strings.TrimSpace(label) != label {
		return fmt.Errorf("enrollment label must not start or end with whitespace")
	}
	for _, r := range label {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("enrollment label must be printable and single-line")
		}
	}
	return nil
}
