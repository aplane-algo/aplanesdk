// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"gopkg.in/yaml.v3"
)

type liveSignerConfig struct {
	Endpoint struct {
		SignerPort int `yaml:"signer_port"`
	} `yaml:"endpoint"`
}

func liveSignerClient(t *testing.T) (*SignerClient, string) {
	t.Helper()

	if os.Getenv("APLANE_SDK_INTEGRATION") != "1" {
		t.Skip("set APLANE_SDK_INTEGRATION=1 to run live signer integration tests")
	}

	token := liveSignerToken(t)
	keyType := os.Getenv("APLANE_SDK_KEY_TYPE")
	if keyType == "" {
		keyType = "ed25519"
	}

	if host := strings.TrimSpace(os.Getenv("APLANE_SDK_SSH_HOST")); host != "" {
		client, err := ConnectSSH(host, token, liveRequiredEnv(t, "APLANE_SDK_SSH_KEY_PATH"), &SSHConnectOptions{
			SSHPort:        liveRequiredPort(t, "APLANE_SDK_SSH_PORT"),
			SignerPort:     liveRequiredPort(t, "APLANE_SDK_SIGNER_PORT"),
			KnownHostsPath: liveRequiredEnv(t, "APLANE_SDK_KNOWN_HOSTS_PATH"),
		})
		if err != nil {
			t.Fatalf("connect to live signer over SSH: %v", err)
		}
		return client, keyType
	}

	baseURL := strings.TrimRight(os.Getenv("APLANE_SDK_SIGNER_URL"), "/")
	if baseURL == "" {
		port := liveSignerPort(t)
		baseURL = fmt.Sprintf("http://127.0.0.1:%d", port)
	}
	return NewSignerClientWithToken(baseURL, token), keyType
}

func liveRequiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s must be set when APLANE_SDK_SSH_HOST is set", name)
	}
	return value
}

func liveRequiredPort(t *testing.T, name string) int {
	t.Helper()
	value := liveRequiredEnv(t, name)
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		t.Fatalf("%s must be a valid TCP port, got %q", name, value)
	}
	return port
}

func liveSignerPort(t *testing.T) int {
	t.Helper()

	dataDir := os.Getenv("APSIGNER_DATA")
	if dataDir == "" {
		t.Fatal("APLANE_SDK_SIGNER_URL or APSIGNER_DATA must be set")
	}

	data, err := os.ReadFile(filepath.Join(dataDir, "config.yaml"))
	if err != nil {
		t.Fatalf("failed to read signer config: %v", err)
	}

	var cfg liveSignerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to parse signer config: %v", err)
	}
	if cfg.Endpoint.SignerPort == 0 {
		t.Fatal("endpoint.signer_port not set in signer config")
	}
	return cfg.Endpoint.SignerPort
}

func liveSignerToken(t *testing.T) string {
	t.Helper()

	if token := strings.TrimSpace(os.Getenv("APLANE_SDK_TOKEN")); token != "" {
		return token
	}

	candidates := []string{
		os.Getenv("APLANE_SDK_TOKEN_FILE"),
	}
	if clientData := os.Getenv("APCLIENT_DATA"); clientData != "" {
		candidates = append(candidates, filepath.Join(clientData, "aplane.token"))
	}
	if signerData := os.Getenv("APSIGNER_DATA"); signerData != "" {
		candidates = append(candidates, filepath.Join(signerData, "identities", "default", "aplane.token"))
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		data, err := os.ReadFile(candidate)
		if err == nil {
			token := strings.TrimSpace(string(data))
			if token != "" {
				return token
			}
		}
	}

	t.Fatal("APLANE_SDK_TOKEN, APLANE_SDK_TOKEN_FILE, APCLIENT_DATA, or APSIGNER_DATA must provide a token")
	return ""
}

func TestIntegrationLiveSignerClientWorkflow(t *testing.T) {
	client, keyType := liveSignerClient(t)
	defer client.Close()

	healthy, err := client.Health()
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	if !healthy {
		t.Fatal("signer is not healthy")
	}

	before, err := client.GetStatus()
	if err != nil {
		t.Fatalf("get identity before generate: %v", err)
	}
	if !before.ReadyForSigning || before.SignerLocked {
		t.Fatalf("signer is not ready: state=%s locked=%v ready=%v", before.State, before.SignerLocked, before.ReadyForSigning)
	}

	keyTypes, err := client.ListKeyTypes()
	if err != nil {
		t.Fatalf("list key types: %v", err)
	}
	if !hasKeyType(keyTypes, keyType) {
		t.Fatalf("key type %q not advertised by signer", keyType)
	}

	generated, err := client.GenerateKey(keyType, map[string]string{})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	address := generated.Address
	if address == "" {
		t.Fatal("generated key returned empty address")
	}

	cleanup := true
	defer func() {
		if cleanup {
			if err := client.DeleteKey(address); err != nil {
				t.Logf("cleanup delete key %s failed: %v", address, err)
			}
		}
	}()

	afterGenerate := waitForKeysetRevision(t, client, before.KeysetRevision, "generate")

	keys, err := client.ListKeys(true)
	if err != nil {
		t.Fatalf("list keys after generate: %v", err)
	}
	if !hasKey(keys, address) {
		t.Fatalf("generated key %s was not returned by list keys", address)
	}

	txn, err := selfPaymentTxn(address)
	if err != nil {
		t.Fatalf("build self-payment txn: %v", err)
	}
	signed, err := client.SignTransaction(txn, address, nil)
	if err != nil {
		t.Fatalf("sign transaction: %v", err)
	}
	signedBytes, err := base64.StdEncoding.DecodeString(signed)
	if err != nil {
		t.Fatalf("signed transaction is not base64: %v", err)
	}
	if len(signedBytes) == 0 {
		t.Fatal("signed transaction is empty")
	}

	if err := client.DeleteKey(address); err != nil {
		t.Fatalf("delete key: %v", err)
	}
	cleanup = false

	waitForKeysetRevision(t, client, afterGenerate.KeysetRevision, "delete")

	keys, err = client.ListKeys(true)
	if err != nil {
		t.Fatalf("list keys after delete: %v", err)
	}
	if hasKey(keys, address) {
		t.Fatalf("deleted key %s was still returned by list keys", address)
	}
}

func selfPaymentTxn(address string) (types.Transaction, error) {
	genesisHash, err := base64.StdEncoding.DecodeString("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=")
	if err != nil {
		return types.Transaction{}, err
	}
	params := types.SuggestedParams{
		Fee:             1000,
		GenesisID:       "testnet-v1.0",
		GenesisHash:     genesisHash,
		FirstRoundValid: 1,
		LastRoundValid:  1000,
		FlatFee:         true,
	}
	return transaction.MakePaymentTxn(address, address, 0, nil, "", params)
}

func hasKeyType(keyTypes []KeyTypeInfo, keyType string) bool {
	for _, item := range keyTypes {
		if item.KeyType == keyType {
			return true
		}
	}
	return false
}

func hasKey(keys []KeyInfo, address string) bool {
	for _, key := range keys {
		if key.Address == address {
			return true
		}
	}
	return false
}

func waitForKeysetRevision(t *testing.T, client *SignerClient, previous uint64, action string) *StatusResponse {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	var last *StatusResponse
	var lastErr error
	for time.Now().Before(deadline) {
		identity, err := client.GetStatus()
		if err == nil {
			last = identity
			if identity.KeysetRevision > previous {
				return identity
			}
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("get identity after %s: %v", action, lastErr)
	}
	if last == nil {
		t.Fatalf("identity was unavailable after %s", action)
	}
	t.Fatalf("keyset revision did not advance after %s: before=%d after=%d", action, previous, last.KeysetRevision)
	return nil
}
