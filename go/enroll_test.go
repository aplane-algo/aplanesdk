// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A refused enrollment reaches the caller as the node's ERROR line, which the
// node writes to the session's standard output with a non-zero exit status.
func TestRequestEnrollmentReportsTheRefusalLine(t *testing.T) {
	_, err := enrollAgainstFakeServer(t, &fakeEnrollment{respond: answer("ERROR: \"enrollment queue is full\"\n", 1)})
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
	result, err := enrollAgainstFakeServer(t, &fakeEnrollment{respond: answer("pending {fp}\n", 0)})
	if err != nil || !result.Pending || !strings.HasPrefix(result.Fingerprint, "SHA256:") {
		t.Fatalf("RequestEnrollment() = %+v, %v; want a pending request", result, err)
	}
}

// An answer of exactly the cap is read whole.
func TestRequestEnrollmentAcceptsAnAnswerOfExactlyTheCap(t *testing.T) {
	// "pending SHA256:" plus 43 base64 characters, padded to the cap.
	padding := maxEnrollmentReplyBytes - len("pending SHA256:") - 43 - 1
	result, err := enrollAgainstFakeServer(t, &fakeEnrollment{respond: answer("pending {fp}"+strings.Repeat(" ", padding)+"\n", 0)})
	if err != nil || !result.Pending {
		t.Fatalf("RequestEnrollment() = %+v, %v; want a pending request", result, err)
	}
}

// A server that lets the client in without asking for its key's signature
// could answer for a key the client never proved it holds, so the client
// refuses it before it sends the enroll command.
func TestRequestEnrollmentRefusesAServerThatSkipsKeyAuthentication(t *testing.T) {
	fake := &fakeEnrollment{noClientAuth: true, respond: answer("pending {fp}\n", 0)}
	_, err := enrollAgainstFakeServer(t, fake)
	if !errors.Is(err, ErrEnrollment) || !strings.Contains(err.Error(), "did not authenticate this client's SSH key") {
		t.Fatalf("RequestEnrollment() error = %v; want the unauthenticated-key refusal", err)
	}
	if n := fake.execs(); n != 0 {
		t.Fatalf("client sent %d enroll command(s) to a server that skipped key authentication", n)
	}
}

// A real answer is one short line, so a longer one is refused as soon as it
// passes the cap, whether or not the server ever exits.
func TestRequestEnrollmentRefusesAnOversizedReply(t *testing.T) {
	for _, tc := range []struct {
		name    string
		respond func(ssh.Channel, string)
	}{
		{"exits", answer(strings.Repeat("x", maxEnrollmentReplyBytes+1), 0)},
		{"goes silent", writeAndHold(strings.Repeat("x", maxEnrollmentReplyBytes+1))},
		{"streams without end", streamWithoutEnd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := time.Now()
			_, err := enrollAgainstFakeServer(t, &fakeEnrollment{respond: tc.respond})
			if !errors.Is(err, ErrEnrollment) || !strings.Contains(err.Error(), "response exceeded 4096 bytes") {
				t.Fatalf("RequestEnrollment() error = %v; want the oversized-reply refusal", err)
			}
			if elapsed := time.Since(started); elapsed > 3*time.Second {
				t.Fatalf("refusal took %v; it should not wait on the server", elapsed)
			}
		})
	}
}

// The server's refusal text is escaped and capped before it reaches an error
// a caller may print.
func TestRequestEnrollmentEscapesAndCapsTheRefusalText(t *testing.T) {
	_, err := enrollAgainstFakeServer(t, &fakeEnrollment{respond: answer("ERROR: \x1b[2Jqueue\u202efull "+strings.Repeat("y", 400)+"\n", 1)})
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

// With no output, the error is x/crypto's exit text, which carries the
// server's signal name and message, so it is escaped too.
func TestRequestEnrollmentEscapesTheExitSignalText(t *testing.T) {
	respond := func(channel ssh.Channel, _ string) {
		payload := ssh.Marshal(struct {
			Signal     string
			CoreDumped bool
			Message    string
			Lang       string
		}{"KILL", false, "killed\x1b[2J\u202e", ""})
		_, _ = channel.SendRequest("exit-signal", false, payload)
		_ = channel.Close()
	}
	_, err := enrollAgainstFakeServer(t, &fakeEnrollment{respond: respond})
	if !errors.Is(err, ErrEnrollment) || !strings.Contains(err.Error(), `killed\x1b[2J\u202e`) || strings.ContainsAny(err.Error(), "\x1b\u202e") {
		t.Fatalf("RequestEnrollment() error = %q; want the exit text escaped", err)
	}
}

// The observed signer keeps the algorithm interfaces of the signer it wraps,
// so it cannot change which signature algorithm is negotiated, and it reports
// each signature, whichever method makes it.
func TestObserveAuthSignerKeepsTheSignerInterfaces(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	signed := 0
	observed := observeAuthSigner(base, func() { signed++ })
	algorithm, ok := observed.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("observed signer dropped ssh.AlgorithmSigner")
	}
	if _, err := observed.Sign(rand.Reader, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if _, err := algorithm.SignWithAlgorithm(rand.Reader, []byte("data"), ssh.KeyAlgoED25519); err != nil {
		t.Fatal(err)
	}
	if signed != 2 {
		t.Fatalf("signatures reported = %d, want 2", signed)
	}

	multi, err := ssh.NewSignerWithAlgorithms(base.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoED25519})
	if err != nil {
		t.Fatal(err)
	}
	observedMulti, ok := observeAuthSigner(multi, func() {}).(ssh.MultiAlgorithmSigner)
	if !ok {
		t.Fatal("observed signer dropped ssh.MultiAlgorithmSigner")
	}
	if got := observedMulti.Algorithms(); len(got) != 1 || got[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("Algorithms() = %v, want [%s]", got, ssh.KeyAlgoED25519)
	}

	if _, ok := observeAuthSigner(plainSigner{base}, func() {}).(ssh.AlgorithmSigner); ok {
		t.Fatal("observed signer added ssh.AlgorithmSigner to a signer without it")
	}
}

// plainSigner hides every interface but ssh.Signer.
type plainSigner struct{ signer ssh.Signer }

func (s plainSigner) PublicKey() ssh.PublicKey { return s.signer.PublicKey() }
func (s plainSigner) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	return s.signer.Sign(random, data)
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

// fakeEnrollment is a server that answers the enroll exec with respond, which
// gets the client key's fingerprint. noClientAuth makes it let any client in
// without authentication.
type fakeEnrollment struct {
	noClientAuth bool
	respond      func(channel ssh.Channel, fingerprint string)
	execCount    atomic.Int32
}

func (f *fakeEnrollment) execs() int32 { return f.execCount.Load() }

// answer writes reply ({fp} is the client key's fingerprint) and exits with
// status, as the node does (status 1 when it refuses a request).
func answer(reply string, status uint32) func(ssh.Channel, string) {
	return func(channel ssh.Channel, fingerprint string) {
		_, _ = channel.Write([]byte(strings.ReplaceAll(reply, "{fp}", fingerprint)))
		_, _ = channel.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, status))
		_ = channel.Close()
	}
}

// writeAndHold writes reply and then says nothing, leaving the session open
// until the client ends it.
func writeAndHold(reply string) func(ssh.Channel, string) {
	return func(channel ssh.Channel, _ string) {
		_, _ = channel.Write([]byte(reply))
		_, _ = io.Copy(io.Discard, channel)
	}
}

func streamWithoutEnd(channel ssh.Channel, _ string) {
	chunk := []byte(strings.Repeat("x", 1024))
	for {
		if _, err := channel.Write(chunk); err != nil {
			return
		}
	}
}

func enrollAgainstFakeServer(t *testing.T, fake *fakeEnrollment) (EnrollmentResult, error) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	fingerprint := ssh.FingerprintSHA256(writeClientKey(t, keyPath))
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		NoClientAuth: fake.noClientAuth,
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
	go serveEnrollment(listener, config, fake, fingerprint)

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

// serveEnrollment serves one connection, answering its enroll exec with
// fake.respond and counting the exec requests it sees.
func serveEnrollment(listener net.Listener, config *ssh.ServerConfig, fake *fakeEnrollment, fingerprint string) {
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
			fake.execCount.Add(1)
			_ = request.Reply(true, nil)
			go ssh.DiscardRequests(channelRequests)
			fake.respond(channel, fingerprint)
			break
		}
		return
	}
}
