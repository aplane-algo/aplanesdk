// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	sshTokenProofDomain      = "aplane-ssh-token-proof-v1"
	sshTokenProofIdentity    = "default"
	sshTokenProofNonceSize   = 32
	sshTokenProofMessageSize = 1024
)

type sshTokenProofClient struct {
	mu          sync.Mutex
	token       string
	hostHash    []byte
	clientNonce []byte
	round       int
	verified    bool
}

func newSSHTokenProofClient(token string) *sshTokenProofClient {
	return &sshTokenProofClient{token: token}
}

func (a *sshTokenProofClient) captureHostKey(key ssh.PublicKey) error {
	if key == nil {
		return fmt.Errorf("SSH host key is nil")
	}
	hash := sha256.Sum256(key.Marshal())
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.hostHash) != 0 && !bytes.Equal(a.hostHash, hash[:]) {
		return fmt.Errorf("SSH host key changed during authentication")
	}
	a.hostHash = append(a.hostHash[:0], hash[:]...)
	return nil
}

func (a *sshTokenProofClient) challenge(name, instruction string, questions []string, echos []bool) ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if name != sshTokenProofDomain || instruction != "" || len(questions) != 1 || len(echos) != 1 || echos[0] {
		return nil, fmt.Errorf("unexpected SSH token proof challenge shape")
	}
	if len(a.hostHash) != sha256.Size {
		return nil, fmt.Errorf("SSH host key was not verified before token proof")
	}

	switch a.round {
	case 0:
		fields, err := parseTokenProofObject(questions[0], "version", "step")
		if err != nil || jsonInt(fields["version"]) != 1 || jsonString(fields["step"]) != "client_nonce" {
			return nil, fmt.Errorf("unexpected token proof client-nonce question")
		}
		a.clientNonce = make([]byte, sshTokenProofNonceSize)
		if _, err := rand.Read(a.clientNonce); err != nil {
			return nil, fmt.Errorf("generate token proof client nonce: %w", err)
		}
		a.round = 1
		return []string{fmt.Sprintf(`{"client_nonce":"%s"}`, encodeTokenProofBytes(a.clientNonce))}, nil
	case 1:
		fields, err := parseTokenProofObject(questions[0], "version", "step", "server_nonce", "proof")
		if err != nil || jsonInt(fields["version"]) != 1 || jsonString(fields["step"]) != "server_proof" {
			return nil, fmt.Errorf("unexpected token proof server-proof question")
		}
		serverNonce, err := decodeTokenProofBytes(jsonString(fields["server_nonce"]), sshTokenProofNonceSize)
		if err != nil {
			return nil, fmt.Errorf("invalid token proof server nonce: %w", err)
		}
		serverProof, err := decodeTokenProofBytes(jsonString(fields["proof"]), sha256.Size)
		if err != nil {
			return nil, fmt.Errorf("invalid SSH server token proof: %w", err)
		}
		transcript, err := encodeTokenProofTranscript(sshTokenProofIdentity, a.hostHash, a.clientNonce, serverNonce)
		if err != nil {
			return nil, err
		}
		expected := computeTokenProof(a.token, "server", transcript)
		if !hmac.Equal(expected, serverProof) {
			return nil, fmt.Errorf("SSH server token proof is invalid")
		}
		proof := computeTokenProof(a.token, "client", transcript)
		a.round = 2
		a.verified = true
		return []string{fmt.Sprintf(`{"client_proof":"%s"}`, encodeTokenProofBytes(proof))}, nil
	default:
		return nil, fmt.Errorf("unexpected additional SSH token proof challenge")
	}
}

func (a *sshTokenProofClient) serverVerified() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.verified && a.round == 2
}

func (a *sshTokenProofClient) clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.hostHash {
		a.hostHash[i] = 0
	}
	for i := range a.clientNonce {
		a.clientNonce[i] = 0
	}
	a.hostHash = nil
	a.clientNonce = nil
	a.token = ""
}

func encodeTokenProofTranscript(identity string, hostHash, clientNonce, serverNonce []byte) ([]byte, error) {
	if identity == "" || len(identity) > 128 || len(hostHash) != sha256.Size || len(clientNonce) != sshTokenProofNonceSize || len(serverNonce) != sshTokenProofNonceSize {
		return nil, fmt.Errorf("invalid SSH token proof transcript")
	}
	var out bytes.Buffer
	for _, field := range [][]byte{[]byte(sshTokenProofDomain), []byte(identity), hostHash, clientNonce, serverNonce} {
		writeTokenProofField(&out, field)
	}
	return out.Bytes(), nil
}

func computeTokenProof(token, role string, transcript []byte) []byte {
	var input bytes.Buffer
	writeTokenProofField(&input, []byte(role))
	writeTokenProofField(&input, transcript)
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(input.Bytes())
	return mac.Sum(nil)
}

func writeTokenProofField(w io.Writer, field []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(field)))
	_, _ = w.Write(length[:])
	_, _ = w.Write(field)
}

func encodeTokenProofBytes(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func decodeTokenProofBytes(value string, size int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || encodeTokenProofBytes(decoded) != value {
		return nil, fmt.Errorf("expected canonical base64url encoding of %d bytes", size)
	}
	return decoded, nil
}

func parseTokenProofObject(value string, required ...string) (map[string]json.RawMessage, error) {
	if value == "" || len(value) > sshTokenProofMessageSize {
		return nil, fmt.Errorf("invalid token proof message size")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(value))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("token proof message must be an object")
	}
	allowed := make(map[string]bool, len(required))
	for _, field := range required {
		allowed[field] = true
	}
	fields := make(map[string]json.RawMessage, len(required))
	for decoder.More() {
		fieldToken, err := decoder.Token()
		field, ok := fieldToken.(string)
		if err != nil || !ok || !allowed[field] {
			return nil, fmt.Errorf("unexpected token proof field")
		}
		if _, duplicate := fields[field]; duplicate {
			return nil, fmt.Errorf("duplicate token proof field %q", field)
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("decode token proof field: %w", err)
		}
		fields[field] = raw
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("decode token proof message: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF || len(fields) != len(required) {
		return nil, fmt.Errorf("invalid token proof message")
	}
	return fields, nil
}

func jsonString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func jsonInt(raw json.RawMessage) int {
	var value int
	_ = json.Unmarshal(raw, &value)
	return value
}
