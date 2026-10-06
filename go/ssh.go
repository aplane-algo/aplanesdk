// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// clientSSHKeyRequirement names the client SSH keys the signer accepts. It
// refuses other key types (RSA, DSA, certificates) before verifying a
// signature, so authentication with one fails.
const clientSSHKeyRequirement = "Ed25519, ECDSA (P-256/384/521), or hardware-backed sk- Ed25519/ECDSA"

const defaultSSHSetupTimeout = 60 * time.Second

// sshTunnel manages an SSH tunnel to the signer.
type sshTunnel struct {
	client          *ssh.Client
	listener        net.Listener
	done            chan struct{}
	wg              sync.WaitGroup
	knownHostsPath  string
	trustOnFirstUse bool
}

// connect establishes an SSH tunnel to the signer.
// The bearer token is proven through a host-key-bound challenge and is never
// sent as the SSH username.
// Returns the local port that forwards to the signer.
func (t *sshTunnel) connect(
	ctx context.Context,
	host string,
	sshPort, localPort int,
	token, sshKeyPath string,
	setupTimeout time.Duration,
) (int, error) {
	// Load SSH private key
	keyData, err := os.ReadFile(sshKeyPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read SSH key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return 0, fmt.Errorf("failed to parse SSH key: %w", err)
	}

	// Build host key callback (TOFU)
	hostKeyCallback, err := t.buildHostKeyCallback()
	if err != nil {
		return 0, fmt.Errorf("failed to set up host key verification: %w", err)
	}

	proof := newSSHTokenProofClient(token)
	defer proof.clear()
	verifiedHostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := hostKeyCallback(hostname, remote, key); err != nil {
			return err
		}
		return proof.captureHostKey(key)
	}

	config := &ssh.ClientConfig{
		User: sshTokenProofUsername,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
			ssh.KeyboardInteractive(proof.challenge),
		},
		HostKeyCallback: verifiedHostKeyCallback,
	}

	// Bound TCP dialing and SSH authentication together. The setup context is
	// detached after authentication so it cannot terminate the established
	// tunnel or a later approval-bearing HTTP request.
	addr := fmt.Sprintf("%s:%d", host, sshPort)
	client, err := dialSSHHandshake(ctx, "tcp", addr, config, setupTimeout)
	if err != nil {
		return 0, fmt.Errorf("failed to connect to SSH server: %w", err)
	}
	if !proof.serverVerified() {
		_ = client.Close()
		return 0, fmt.Errorf("SSH server accepted authentication without completing token proof")
	}
	t.client = client

	// Create local listener on random port
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		client.Close()
		return 0, fmt.Errorf("failed to create local listener: %w", err)
	}
	t.listener = listener
	t.done = make(chan struct{})

	boundPort := listener.Addr().(*net.TCPAddr).Port
	// The server checks only that the channel destination is loopback and
	// forwards to its own REST listener, so the port named here is nominal.
	remoteAddr := "127.0.0.1:11270"

	// Start accepting connections
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		for {
			localConn, err := listener.Accept()
			if err != nil {
				select {
				case <-t.done:
					return
				default:
					continue
				}
			}

			// Forward to remote
			remoteConn, err := client.Dial("tcp", remoteAddr)
			if err != nil {
				localConn.Close()
				continue
			}

			// Bidirectional copy
			go func() {
				defer localConn.Close()
				defer remoteConn.Close()
				go io.Copy(remoteConn, localConn)
				io.Copy(localConn, remoteConn)
			}()
		}
	}()

	return boundPort, nil
}

func dialSSHHandshake(
	ctx context.Context,
	network, addr string,
	config *ssh.ClientConfig,
	setupTimeout time.Duration,
) (*ssh.Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if setupTimeout <= 0 {
		setupTimeout = defaultSSHSetupTimeout
	}
	setupCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(setupCtx, network, addr)
	if err != nil {
		return nil, err
	}
	stopCancellation := context.AfterFunc(setupCtx, func() { _ = conn.Close() })
	sshConn, channels, requests, err := ssh.NewClientConn(conn, addr, config)
	detached := stopCancellation()
	if err != nil || !detached || setupCtx.Err() != nil {
		_ = conn.Close()
		if setupErr := setupCtx.Err(); setupErr != nil {
			return nil, setupErr
		}
		if err == nil {
			err = context.Canceled
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			err = fmt.Errorf("%w (the signer accepts %s client keys)", err, clientSSHKeyRequirement)
		}
		return nil, err
	}
	return ssh.NewClient(sshConn, channels, requests), nil
}

// close closes the SSH tunnel.
func (t *sshTunnel) close() {
	if t.done != nil {
		close(t.done)
	}
	if t.listener != nil {
		t.listener.Close()
	}
	if t.client != nil {
		t.client.Close()
	}
	t.wg.Wait()
}

// buildHostKeyCallback returns an ssh.HostKeyCallback implementing TOFU (Trust On First Use).
func (t *sshTunnel) buildHostKeyCallback() (ssh.HostKeyCallback, error) {
	if t.knownHostsPath == "" {
		return nil, fmt.Errorf("known_hosts path is required for SSH host key verification")
	}

	// Try to load existing known_hosts file
	var existingCallback ssh.HostKeyCallback
	if _, err := os.Stat(t.knownHostsPath); err == nil {
		cb, err := knownhosts.New(t.knownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load known_hosts %s: %w", t.knownHostsPath, err)
		}
		existingCallback = cb
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// Check against existing known_hosts if available
		if existingCallback != nil {
			err := existingCallback(hostname, remote, key)
			if err == nil {
				return nil // Host is known and key matches
			}
			if keyErr, ok := err.(*knownhosts.KeyError); ok {
				if len(keyErr.Want) > 0 {
					// Key mismatch — possible MITM attack
					return fmt.Errorf("SSH host key mismatch for %s (possible MITM attack); remove the old key from %s to connect", hostname, t.knownHostsPath)
				}
				// Host not in known_hosts — fall through to TOFU
			} else {
				return err
			}
		}

		// Unknown host
		if !t.trustOnFirstUse {
			return fmt.Errorf("unknown SSH host key for %s; pass TrustOnFirstUse for explicit first-use trust, or connect via apshell first to save the host key to %s", hostname, t.knownHostsPath)
		}

		// TOFU enabled — trust and save key
		if err := t.saveHostKey(hostname, key); err != nil {
			return fmt.Errorf("failed to save host key: %w", err)
		}
		return nil
	}, nil
}

// saveHostKey appends a host key to the known_hosts file.
func (t *sshTunnel) saveHostKey(hostname string, key ssh.PublicKey) error {
	dir := filepath.Dir(t.knownHostsPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	line := knownhosts.Line([]string{hostname}, key)

	f, err := os.OpenFile(t.knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts: %w", err)
	}

	if _, err := f.WriteString(line + "\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write host key: %w", err)
	}

	return f.Close()
}
