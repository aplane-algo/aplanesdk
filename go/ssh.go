// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

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
func (t *sshTunnel) connect(host string, sshPort, signerPort, localPort int, token, sshKeyPath string) (int, error) {
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
		User: sshTokenProofIdentity,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
			ssh.KeyboardInteractive(proof.challenge),
		},
		HostKeyCallback: verifiedHostKeyCallback,
	}

	// Connect to SSH server
	addr := fmt.Sprintf("%s:%d", host, sshPort)
	client, err := ssh.Dial("tcp", addr, config)
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
	remoteAddr := fmt.Sprintf("127.0.0.1:%d", signerPort)

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
