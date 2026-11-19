// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
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
)

// listeningSockets counts the TCP sockets this process has listening, from
// /proc (Linux only).
func listeningSockets(t *testing.T) int {
	t.Helper()
	listening := map[string]bool{}
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(table)
		if err != nil {
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

// A client connected over SSH carries every request on an SSH channel it
// opens itself, and listens on no local port another process could use.
func TestSSHClientOpensNoLocalListener(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("counts listening sockets through /proc")
	}
	dir := t.TempDir()
	key := writeClientKey(t, filepath.Join(dir, "id"))
	var served atomic.Int32
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

	before := listeningSockets(t)
	client, err := ConnectSSH(host, filepath.Join(dir, "id"), &SSHConnectOptions{SSHPort: port, KnownHostsPath: knownHosts})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		resp, err := client.client.Get(client.baseURL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if got := served.Load(); got != 2 {
		t.Fatalf("signer served %d requests, want 2", got)
	}
	if after := listeningSockets(t); after != before {
		t.Fatalf("listening sockets went from %d to %d after connecting", before, after)
	}

	// The transport dials nothing but the signer.
	if _, err := client.client.Get("http://127.0.0.1:1/"); err == nil || !strings.Contains(err.Error(), "unexpected signer dial target") {
		t.Fatalf("request to another host: err = %v, want it refused", err)
	}

	client.Close()
	if _, err := client.client.Get(client.baseURL + "/health"); err == nil {
		t.Fatal("a request after Close succeeded")
	}
}
