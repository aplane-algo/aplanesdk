// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestResolveAuthAddressSelfSigning(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				State:           "unlocked",
				ReadyForSigning: true,
				KeysetRevision:  1,
			})
		case "/keys":
			json.NewEncoder(w).Encode(KeysResponse{
				Count: 1,
				Keys: []KeyInfo{{
					Address: "SENDER",
					KeyType: "ed25519",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	})
	defer server.Close()

	resolved, err := client.ResolveAuthAddress(context.Background(), "SENDER", func(context.Context, string) (string, error) {
		return "", nil
	})
	if err != nil {
		t.Fatalf("ResolveAuthAddress() error = %v", err)
	}
	if resolved.Address != "SENDER" || resolved.AuthAddress != "SENDER" || resolved.IsRekeyed {
		t.Fatalf("resolved auth mismatch: %#v", resolved)
	}
	if resolved.KeyInfo.KeyType != "ed25519" {
		t.Fatalf("key type = %q, want ed25519", resolved.KeyInfo.KeyType)
	}
}

func TestResolveAuthAddressRekeyedAccount(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				State:           "unlocked",
				ReadyForSigning: true,
				KeysetRevision:  1,
			})
		case "/keys":
			json.NewEncoder(w).Encode(KeysResponse{
				Count: 1,
				Keys: []KeyInfo{{
					Address: "AUTH",
					KeyType: "ed25519",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	})
	defer server.Close()

	resolved, err := client.ResolveAuthAddress(context.Background(), "SENDER", func(context.Context, string) (string, error) {
		return "AUTH", nil
	})
	if err != nil {
		t.Fatalf("ResolveAuthAddress() error = %v", err)
	}
	if resolved.Address != "SENDER" || resolved.AuthAddress != "AUTH" || !resolved.IsRekeyed {
		t.Fatalf("resolved auth mismatch: %#v", resolved)
	}
}

func TestResolveAuthAddressRejectsRekeyedNotSignable(t *testing.T) {
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				State:           "unlocked",
				ReadyForSigning: true,
				KeysetRevision:  1,
			})
		case "/keys":
			json.NewEncoder(w).Encode(KeysResponse{
				Count: 1,
				Keys: []KeyInfo{{
					Address: "SENDER",
					KeyType: "ed25519",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	})
	defer server.Close()

	_, err := client.ResolveAuthAddress(context.Background(), "SENDER", func(context.Context, string) (string, error) {
		return "AUTH", nil
	})
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), "not signable") {
		t.Fatalf("expected not signable error, got %v", err)
	}
}

func TestListKeysIfKeysetChangedUsesRevision(t *testing.T) {
	revision := uint64(1)
	keyAddress := "ADDR1"
	keyCalls := 0
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{
				State:           "unlocked",
				ReadyForSigning: true,
				KeysetRevision:  revision,
			})
		case "/keys":
			keyCalls++
			json.NewEncoder(w).Encode(KeysResponse{
				Count: 1,
				Keys: []KeyInfo{{
					Address: keyAddress,
					KeyType: "ed25519",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	})
	defer server.Close()

	keys, err := client.ListKeysIfKeysetChanged()
	if err != nil {
		t.Fatalf("ListKeysIfKeysetChanged() error = %v", err)
	}
	if keyCalls != 1 || keys[0].Address != "ADDR1" {
		t.Fatalf("first fetch keyCalls=%d keys=%#v", keyCalls, keys)
	}

	keys, err = client.ListKeysIfKeysetChanged()
	if err != nil {
		t.Fatalf("ListKeysIfKeysetChanged() second error = %v", err)
	}
	if keyCalls != 1 || keys[0].Address != "ADDR1" {
		t.Fatalf("same revision should use cache, keyCalls=%d keys=%#v", keyCalls, keys)
	}

	revision = 2
	keyAddress = "ADDR2"
	keys, err = client.ListKeysIfKeysetChanged()
	if err != nil {
		t.Fatalf("ListKeysIfKeysetChanged() changed revision error = %v", err)
	}
	if keyCalls != 2 || keys[0].Address != "ADDR2" {
		t.Fatalf("changed revision should refresh, keyCalls=%d keys=%#v", keyCalls, keys)
	}
}
