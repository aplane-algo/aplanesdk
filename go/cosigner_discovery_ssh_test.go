// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// testSSHNode is an SSH server that accepts one client key and forwards
// every channel to an HTTP backend, as a signer node's SSH server does.
type testSSHNode struct {
	addr    string
	hostKey ssh.PublicKey
}

func startTestSSHNode(t *testing.T, enrolled ssh.PublicKey, backend http.HandlerFunc) *testSSHNode {
	t.Helper()
	server := httptest.NewServer(backend)
	t.Cleanup(server.Close)
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(key.Marshal(), enrolled.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("not enrolled")
	}}
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	backendAddr := server.Listener.Addr().String()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveTestSSH(conn, config, backendAddr)
		}
	}()
	return &testSSHNode{addr: listener.Addr().String(), hostKey: hostSigner.PublicKey()}
}

func serveTestSSH(conn net.Conn, config *ssh.ServerConfig, backend string) {
	defer conn.Close()
	serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "direct-tcpip" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only direct-tcpip")
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(channelRequests)
		go func() {
			defer channel.Close()
			upstream, err := net.Dial("tcp", backend)
			if err != nil {
				return
			}
			defer upstream.Close()
			go func() { _, _ = io.Copy(upstream, channel) }()
			_, _ = io.Copy(channel, upstream)
		}()
	}
}

// writeClientKey writes a new Ed25519 client key in OpenSSH form and returns
// its public half.
func writeClientKey(t *testing.T, path string) ssh.PublicKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return sshPublic
}

// writeKnownHost pins key for addr in the known hosts file at path.
func writeKnownHost(t *testing.T, path, addr string, key ssh.PublicKey) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, key) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

// witnessKeysBackend answers /keys with one witness key.
func witnessKeysBackend(publicKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/keys":
			json.NewEncoder(w).Encode(KeysResponse{Count: 1, Keys: []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, publicKey)}})
		default:
			http.NotFound(w, r)
		}
	}
}

// A client created by FromEnv finds a cosigner over SSH with each cosigner
// endpoint's own identity and known hosts file, and with the connection
// options the client was created with.
func TestFromEnvDefaultResolverConnectsOverSSH(t *testing.T) {
	for _, pinned := range []bool{true, false} {
		t.Run(fmt.Sprintf("host key pinned %v", pinned), func(t *testing.T) {
			dir := t.TempDir()
			signerKey := writeClientKey(t, filepath.Join(dir, "keys", "signer"))
			cosignerKey := writeClientKey(t, filepath.Join(dir, "keys", "cosigner"))
			signer := startTestSSHNode(t, signerKey, func(w http.ResponseWriter, r *http.Request) {})
			cosigner := startTestSSHNode(t, cosignerKey, witnessKeysBackend(witnessOne))
			writeKnownHost(t, filepath.Join(dir, "hosts", "signer"), signer.addr, signer.hostKey)
			if pinned {
				writeKnownHost(t, filepath.Join(dir, "hosts", "cosigner"), cosigner.addr, cosigner.hostKey)
			}
			registry := fmt.Sprintf(`
schema_version: 2
endpoints:
  primary:
    role: signer
    url: ssh://%s
    identity_file: keys/signer
    known_hosts_path: hosts/signer
  cos:
    role: cosigner
    url: ssh://%s
    identity_file: keys/cosigner
    known_hosts_path: hosts/cosigner
`, signer.addr, cosigner.addr)
			if err := os.WriteFile(filepath.Join(dir, "endpoints.yaml"), []byte(registry), 0o600); err != nil {
				t.Fatal(err)
			}

			// Trust on first use is carried over to the cosigner: without it an
			// unpinned cosigner cannot be reached.
			client, err := FromEnv(&FromEnvOptions{DataDir: dir, Timeout: 7, SSHSetupTimeout: 5 * time.Second, TrustOnFirstUse: !pinned})
			if err != nil {
				t.Fatalf("FromEnv() error = %v", err)
			}
			defer client.Close()
			want := EndpointCosignerResolverOptions{Timeout: 7, SSHSetupTimeout: 5 * time.Second, TrustOnFirstUse: !pinned}
			if client.endpoints == nil || client.endpointOptions != want {
				t.Fatalf("client kept registry %v and options %+v, want %+v", client.endpoints != nil, client.endpointOptions, want)
			}
			resolver := client.defaultCosignerResolver()
			cosignerClient, componentKey, err := resolver.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024)
			if err != nil || componentKey != WitnessKeyID(KeyTypeWitnessFalcon1024, witnessOne) {
				t.Fatalf("ResolveCosigner() = %s, %v", componentKey, err)
			}
			if cosignerClient.timeoutFor(time.Hour) != 7*time.Second {
				t.Fatalf("the cosigner client's request timeout is not the client's")
			}
			client.Close()
			// The cosigner connection closed with the client.
			if _, err := cosignerClient.GetKeysResponseWithContext(context.Background()); err == nil {
				t.Fatal("the cosigner connection outlived the client")
			}
		})
	}
}

// The connection failures discovery tells apart, through a real SSH server.
func TestConnectCosignerEndpointClassifiesFailures(t *testing.T) {
	dir := t.TempDir()
	enrolledKey := writeClientKey(t, filepath.Join(dir, "enrolled"))
	writeClientKey(t, filepath.Join(dir, "stranger"))
	node := startTestSSHNode(t, enrolledKey, witnessKeysBackend(witnessOne))
	other := startTestSSHNode(t, enrolledKey, witnessKeysBackend(witnessTwo))
	pinned := filepath.Join(dir, "pinned")
	writeKnownHost(t, pinned, node.addr, node.hostKey)
	wrongPin := filepath.Join(dir, "wrong")
	writeKnownHost(t, wrongPin, node.addr, other.hostKey)
	idle, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := idle.Addr().String()
	idle.Close()

	endpoint := func(addr, identity, knownHosts string) ClientEndpointConfig {
		return ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://" + addr, IdentityFile: filepath.Join(dir, identity), KnownHostsPath: knownHosts}
	}
	cases := map[string]struct {
		endpoint ClientEndpointConfig
		state    string
	}{
		"host key mismatch":      {endpoint(node.addr, "enrolled", wrongPin), ""},
		"unknown host, no TOFU":  {endpoint(node.addr, "enrolled", filepath.Join(dir, "absent")), cosignerEndpointConfigInvalid},
		"unreadable known hosts": {endpoint(node.addr, "enrolled", dir), cosignerEndpointConfigInvalid},
		"identity missing":       {endpoint(node.addr, "missing", pinned), cosignerEndpointConfigInvalid},
		"not an ssh url":         {ClientEndpointConfig{URL: "http://" + node.addr}, cosignerEndpointConfigInvalid},
		"key not enrolled":       {endpoint(node.addr, "stranger", pinned), cosignerEndpointAuthFailed},
		"nothing listening":      {endpoint(closedAddr, "enrolled", pinned), cosignerEndpointUnreachable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, err := connectCosignerEndpoint(ctx, tc.endpoint, EndpointCosignerResolverOptions{})
			if err == nil {
				client.Close()
				t.Fatal("connected")
			}
			if state := classifyCosignerConnect(err); state != tc.state {
				t.Fatalf("state = %q, want %q (%v)", state, tc.state, err)
			}
			if tc.state == "" && !strings.HasPrefix(hostKeyMismatchText(err), "SSH host key mismatch for ") {
				t.Fatalf("mismatch text = %q", hostKeyMismatchText(err))
			}
		})
	}

	// The same mismatch ends a whole sweep, though the endpoint that lists
	// the key is fine.
	registry := &ClientEndpointRegistry{Endpoints: map[string]ClientEndpointConfig{
		"good": endpoint(node.addr, "enrolled", pinned),
		"bad":  endpoint(node.addr, "enrolled", wrongPin),
	}}
	resolver := NewEndpointCosignerResolverFromRegistry(registry, nil)
	defer resolver.Close()
	_, _, err = resolver.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024)
	if !errors.Is(err, ErrCosignerDiscovery) || !strings.HasPrefix(err.Error(), `cosigner discovery: endpoint "bad": SSH host key mismatch for `) {
		t.Fatalf("error = %v", err)
	}
}
