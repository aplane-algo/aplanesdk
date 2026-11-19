// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// listeningSockets counts the TCP sockets this process has listening, from
// /proc (Linux only).
func listeningSockets(t *testing.T) int {
	t.Helper()
	listening := map[string]bool{}
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(table)
		if err != nil {
			if table == "/proc/net/tcp" {
				t.Fatalf("cannot count listening sockets: %v", err)
			}
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) > 9 && fields[3] == "0A" {
				listening[fields[9]] = true
			}
		}
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil || !strings.HasPrefix(target, "socket:[") {
			continue
		}
		if listening[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] {
			count++
		}
	}
	return count
}

// connectTestSSHClient connects a client to a test SSH node whose signer
// counts the requests it serves and checks the host they name. beforeConnect,
// if set, runs once the node is up, just before the client connects.
func connectTestSSHClient(t *testing.T, beforeConnect func()) (*SignerClient, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	key := writeClientKey(t, filepath.Join(dir, "id"))
	served := &atomic.Int32{}
	node := startTestSSHNode(t, key, func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		if r.Host != tunnelAuthority {
			t.Errorf("request named host %q, want %q", r.Host, tunnelAuthority)
		}
		_, _ = io.WriteString(w, "ok")
	})
	knownHosts := filepath.Join(dir, "known_hosts")
	writeKnownHost(t, knownHosts, node.addr, node.hostKey)
	host, portText, err := net.SplitHostPort(node.addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	if beforeConnect != nil {
		beforeConnect()
	}
	client, err := ConnectSSH(host, filepath.Join(dir, "id"), &SSHConnectOptions{SSHPort: port, KnownHostsPath: knownHosts})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, served
}

func getHealth(t *testing.T, client *SignerClient) {
	t.Helper()
	resp, err := client.client.Get(client.baseURL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// A client connected over SSH listens on no local port another process
// could use.
func TestSSHClientOpensNoLocalListener(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("counts listening sockets through /proc")
	}
	var before int
	client, served := connectTestSSHClient(t, func() { before = listeningSockets(t) })
	for range 2 {
		getHealth(t, client)
	}
	if got := served.Load(); got != 2 {
		t.Fatalf("signer served %d requests, want 2", got)
	}
	if after := listeningSockets(t); after != before {
		t.Fatalf("listening sockets went from %d to %d after connecting", before, after)
	}
}

// A client connected over SSH carries its requests over SSH channels to the
// signer only, and none after Close.
func TestSSHClientCarriesRequestsOnlyToTheSigner(t *testing.T) {
	client, served := connectTestSSHClient(t, nil)
	getHealth(t, client)
	if got := served.Load(); got != 1 {
		t.Fatalf("signer served %d requests, want 1", got)
	}
	if _, err := client.client.Get("http://127.0.0.1:1/"); err == nil || !strings.Contains(err.Error(), "unexpected signer dial target") {
		t.Fatalf("request to another host: err = %v, want it refused", err)
	}
	client.Close()
	if _, err := client.client.Get(client.baseURL + "/health"); err == nil {
		t.Fatal("a request after Close succeeded")
	}
}

type countingRoundTripper struct{ calls atomic.Int32 }

func (c *countingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return nil, errors.New("the caller's transport was used")
}

// An HTTP client set on an SSH-connected client keeps the tunnel's
// transport: a caller's transport (or a proxy it would use) never sees the
// requests.
func TestSetHTTPClientKeepsTheTunnelTransport(t *testing.T) {
	client, served := connectTestSSHClient(t, nil)
	caller := &countingRoundTripper{}
	client.SetHTTPClient(&http.Client{Timeout: 30 * time.Second, Transport: caller})
	getHealth(t, client)
	if got := served.Load(); got != 1 || caller.calls.Load() != 0 {
		t.Fatalf("signer served %d, caller transport saw %d; want 1 and 0", got, caller.calls.Load())
	}
	if client.client.Timeout != 30*time.Second {
		t.Fatalf("timeout = %v, want the caller's 30s", client.client.Timeout)
	}
}
