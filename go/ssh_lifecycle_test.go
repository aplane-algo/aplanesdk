// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"errors"
	"net"
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
