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
// sshKeyPath, so that key can open API connections. The call blocks until
// the operator approves or rejects the request in apadmin and returns the
// enrolled key's SHA256 fingerprint. Nothing is stored on the client: the
// key is its credential. label is an optional display label for the
// operator (printable, single line, at most 64 bytes).
func RequestEnrollment(host, sshKeyPath, label string, opts *EnrollmentOptions) (string, error) {
	return RequestEnrollmentWithContext(context.Background(), host, sshKeyPath, label, opts)
}

// RequestEnrollmentWithContext is the context-aware form of
// RequestEnrollment. Cancelling ctx abandons the request, including while it
// waits for the operator.
func RequestEnrollmentWithContext(ctx context.Context, host, sshKeyPath, label string, opts *EnrollmentOptions) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateEnrollmentLabel(label); err != nil {
		return "", err
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
		return "", fmt.Errorf("failed to set up host key verification: %w", err)
	}

	keyData, err := os.ReadFile(ExpandPath(sshKeyPath))
	if err != nil {
		return "", fmt.Errorf("failed to read SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return "", fmt.Errorf("failed to parse SSH key: %w", err)
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
		return "", fmt.Errorf("%w: failed to connect to SSH server: %v", ErrEnrollment, err)
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("%w: failed to create session: %v", ErrEnrollment, err)
	}
	defer func() { _ = session.Close() }()
	stop := context.AfterFunc(ctx, func() {
		_ = session.Close()
		_ = client.Close()
	})
	defer stop()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEnrollment, err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEnrollment, err)
	}
	command := enrollmentCommand
	if label != "" {
		command += " " + label
	}
	if err := session.Start(command); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("%w: failed to start enrollment: %v", ErrEnrollment, err)
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
		return "", ctx.Err()
	}
	if err != nil {
		return "", fmt.Errorf("%w: failed to read response: %v", ErrEnrollment, err)
	}
	if err := session.Wait(); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		message := strings.TrimSpace(string(errOutput))
		if message == "" {
			message = strings.TrimSpace(string(output))
		}
		message = strings.TrimPrefix(message, "ERROR: ")
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("%w: %s", ErrEnrollment, message)
	}

	fingerprint, ok := strings.CutPrefix(strings.TrimSpace(string(output)), "enrolled ")
	if !ok || fingerprint == "" {
		return "", fmt.Errorf("%w: unexpected response %q", ErrEnrollment, strings.TrimSpace(string(output)))
	}
	if fingerprint != clientFingerprint {
		return "", fmt.Errorf("%w: signer enrolled %s, but this client authenticated with %s", ErrEnrollment, fingerprint, clientFingerprint)
	}
	return fingerprint, nil
}

// RequestEnrollmentFromEnv asks the endpoint selected by opts (the default
// signer, or opts.Endpoint) to enroll the client key configured for it in
// dataDir/endpoints.yaml, and returns the enrolled key's fingerprint.
func RequestEnrollmentFromEnv(opts *FromEnvOptions, label string) (string, error) {
	return RequestEnrollmentFromEnvWithContext(context.Background(), opts, label)
}

// RequestEnrollmentFromEnvWithContext is the context-aware form of
// RequestEnrollmentFromEnv.
func RequestEnrollmentFromEnvWithContext(ctx context.Context, opts *FromEnvOptions, label string) (string, error) {
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
		return "", err
	}
	if _, err := LoadConfig(dataDir); err != nil {
		return "", err
	}
	registry, err := LoadClientEndpointRegistry(dataDir)
	if err != nil {
		return "", err
	}
	_, endpoint, err := ResolveClientEndpoint(registry, endpointAlias)
	if err != nil {
		return "", err
	}
	host, sshPort, err := ClientEndpointSSHHostPort(endpoint)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(endpoint.IdentityFile); err != nil {
		return "", fmt.Errorf("SSH key not found at %s; create one with: ssh-keygen -t ed25519 -f %s", endpoint.IdentityFile, endpoint.IdentityFile)
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
