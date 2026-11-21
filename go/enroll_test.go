// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A refused enrollment reaches the caller as the node's ERROR line, which the
// node writes to the session's standard output with a non-zero exit status.
func TestRequestEnrollmentReportsTheRefusalLine(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	writeClientKey(t, keyPath)
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, nil
	}}
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go serveRefusingEnrollment(listener, config, "ERROR: \"enrollment queue is full\"\n")

	knownHosts := filepath.Join(dir, "known_hosts")
	writeKnownHost(t, knownHosts, listener.Addr().String(), hostSigner.PublicKey())
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	result, err := RequestEnrollment(host, keyPath, "", &EnrollmentOptions{SSHPort: port, KnownHostsPath: knownHosts})
	if !errors.Is(err, ErrEnrollment) {
		t.Fatalf("RequestEnrollment() = %+v, %v; want ErrEnrollment", result, err)
	}
	if want := ErrEnrollment.Error() + `: "enrollment queue is full"`; err.Error() != want {
		t.Fatalf("RequestEnrollment() error = %q, want %q", err.Error(), want)
	}
}

// serveRefusingEnrollment answers one enroll exec with reply on stdout and
// exit status 1, as the node does when it refuses a request.
func serveRefusingEnrollment(listener net.Listener, config *ssh.ServerConfig, reply string) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			return
		}
		for request := range channelRequests {
			if request.Type != "exec" {
				_ = request.Reply(false, nil)
				continue
			}
			_ = request.Reply(true, nil)
			_, _ = channel.Write([]byte(reply))
			_, _ = channel.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, 1))
			_ = channel.Close()
			break
		}
		return
	}
}
