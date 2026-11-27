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
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A refused enrollment reaches the caller as the node's ERROR line, which the
// node writes to the session's standard output with a non-zero exit status.
func TestRequestEnrollmentReportsTheRefusalLine(t *testing.T) {
	_, err := requestFromFakeEnrollmentServer(t, false, "ERROR: \"enrollment queue is full\"\n", 1)
	if !errors.Is(err, ErrEnrollment) {
		t.Fatalf("RequestEnrollment() error = %v; want ErrEnrollment", err)
	}
	if want := ErrEnrollment.Error() + `: "enrollment queue is full"`; err.Error() != want {
		t.Fatalf("RequestEnrollment() error = %q, want %q", err.Error(), want)
	}
}

// The key signs during authentication, so the observed signer lets an
// ordinary answer through.
func TestRequestEnrollmentAcceptsAnAnswerForTheAuthenticatedKey(t *testing.T) {
	result, err := requestFromFakeEnrollmentServer(t, false, "pending {fp}\n", 0)
	if err != nil || !result.Pending || !strings.HasPrefix(result.Fingerprint, "SHA256:") {
		t.Fatalf("RequestEnrollment() = %+v, %v; want a pending request", result, err)
	}
}

// A server that lets the client in without asking for its key's signature
// could answer for a key the client never proved it holds.
func TestRequestEnrollmentRefusesAServerThatSkipsKeyAuthentication(t *testing.T) {
	_, err := requestFromFakeEnrollmentServer(t, true, "pending {fp}\n", 0)
	if !errors.Is(err, ErrEnrollment) || !strings.Contains(err.Error(), "did not authenticate this client's SSH key") {
		t.Fatalf("RequestEnrollment() error = %v; want the unauthenticated-key refusal", err)
	}
}

// A real answer is one short line, so a longer one is refused unread.
func TestRequestEnrollmentRefusesAnOversizedReply(t *testing.T) {
	_, err := requestFromFakeEnrollmentServer(t, false, strings.Repeat("x", maxEnrollmentReplyBytes+1), 0)
	if !errors.Is(err, ErrEnrollment) || !strings.Contains(err.Error(), "response exceeded 4096 bytes") {
		t.Fatalf("RequestEnrollment() error = %v; want the oversized-reply refusal", err)
	}
}

// The server's refusal text is escaped and capped before it reaches an error
// a caller may print.
func TestRequestEnrollmentEscapesAndCapsTheRefusalText(t *testing.T) {
	_, err := requestFromFakeEnrollmentServer(t, false, "ERROR: \x1b[2Jqueue\u202efull "+strings.Repeat("y", 400)+"\n", 1)
	if !errors.Is(err, ErrEnrollment) {
		t.Fatalf("RequestEnrollment() error = %v; want ErrEnrollment", err)
	}
	message := strings.TrimPrefix(err.Error(), ErrEnrollment.Error()+": ")
	if !strings.HasPrefix(message, `\x1b[2Jqueue\u202efull yyy`) || strings.ContainsAny(message, "\x1b\u202e") {
		t.Fatalf("refusal text not escaped: %q", message)
	}
	if !strings.HasSuffix(message, "...") || len(message) != maxEnrollmentErrorBytes+len("...") {
		t.Fatalf("refusal text not capped at %d bytes: %d bytes", maxEnrollmentErrorBytes, len(message))
	}
}

func TestSafeEnrollmentText(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"queue is full", "queue is full"},
		{"tab\there\nnewline", `tab\there\nnewline`},
		{"bell\a esc\x1b del\x7f", `bell\a esc\x1b del\x7f`},
		{"c1\u0085 bidi\u202e zero-width\u200b", `c1\u0085 bidi\u202e zero-width\u200b`},
		{"bad\xffbyte", `bad\xffbyte`},
		{"café ✓", "café ✓"},
	} {
		if got := safeEnrollmentText(tc.in); got != tc.want {
			t.Errorf("safeEnrollmentText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The cut falls between characters: neither an escape nor a multi-byte
	// character is split.
	long := strings.Repeat("a", maxEnrollmentErrorBytes-2) + "\x1b"
	if got, want := safeEnrollmentText(long), strings.Repeat("a", maxEnrollmentErrorBytes-2)+"..."; got != want {
		t.Errorf("safeEnrollmentText split an escape: %q", got)
	}
	long = strings.Repeat("a", maxEnrollmentErrorBytes-1) + "é"
	if got, want := safeEnrollmentText(long), strings.Repeat("a", maxEnrollmentErrorBytes-1)+"..."; got != want {
		t.Errorf("safeEnrollmentText split a character: %q", got)
	}
}

// requestFromFakeEnrollmentServer enrolls against a server that answers the
// enroll exec with reply on stdout and the given exit status; {fp} in reply
// is the client key's fingerprint. noClientAuth makes the server let any
// client in without authentication.
func requestFromFakeEnrollmentServer(t *testing.T, noClientAuth bool, reply string, status uint32) (EnrollmentResult, error) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	reply = strings.ReplaceAll(reply, "{fp}", ssh.FingerprintSHA256(writeClientKey(t, keyPath)))
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		NoClientAuth: noClientAuth,
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go serveEnrollment(listener, config, reply, status)

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
	return RequestEnrollment(host, keyPath, "", &EnrollmentOptions{SSHPort: port, KnownHostsPath: knownHosts})
}

// serveEnrollment answers one enroll exec with reply on stdout and exit
// status, as the node does (status 1 when it refuses a request).
func serveEnrollment(listener net.Listener, config *ssh.ServerConfig, reply string, status uint32) {
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
			_, _ = channel.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, status))
			_ = channel.Close()
			break
		}
		return
	}
}
