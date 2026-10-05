// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHHandshakeInterruptsStalledPeer(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()

			accepted := make(chan net.Conn, 1)
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr == nil {
					accepted <- conn
				}
			}()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timeout := time.Second
			if mode == "timeout" {
				timeout = 50 * time.Millisecond
			}
			done := make(chan error, 1)
			go func() {
				_, dialErr := dialSSHHandshake(ctx, "tcp", listener.Addr().String(), &ssh.ClientConfig{
					User:            "aplane",
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Test peer never sends a host key.
				}, timeout)
				done <- dialErr
			}()

			var peer net.Conn
			select {
			case peer = <-accepted:
			case <-time.After(time.Second):
				t.Fatal("client did not connect")
			}
			defer func() { _ = peer.Close() }()
			if mode == "cancel" {
				cancel()
			}

			select {
			case err := <-done:
				want := context.Canceled
				if mode == "timeout" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) {
					t.Fatalf("error = %v, want %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("stalled SSH handshake did not terminate")
			}
		})
	}
}

// A refused client key reports the key types the signer accepts.
func TestSSHAuthFailureNamesAcceptedKeyTypes(t *testing.T) {
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("key type not accepted")
		},
	}
	serverConfig.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _, _, _ = ssh.NewServerConn(conn, serverConfig)
	}()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = dialSSHHandshake(context.Background(), "tcp", listener.Addr().String(), &ssh.ClientConfig{
		User:            "aplane",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
	}, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), clientSSHKeyRequirement) {
		t.Fatalf("dialSSHHandshake() error = %v, want the accepted key types", err)
	}
}
