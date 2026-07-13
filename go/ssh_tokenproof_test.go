// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type tokenProofVector struct {
	Token               string `json:"token"`
	IdentityID          string `json:"identity_id"`
	HostKeyHash         string `json:"host_key_hash"`
	ClientNonce         string `json:"client_nonce"`
	ServerNonce         string `json:"server_nonce"`
	TranscriptHex       string `json:"transcript_hex"`
	ServerProof         string `json:"server_proof"`
	ClientProof         string `json:"client_proof"`
	ServerProofQuestion string `json:"server_proof_question"`
	ClientProofAnswer   string `json:"client_proof_answer"`
}

func TestSSHTokenProofContractVector(t *testing.T) {
	data, err := os.ReadFile("../contracts/sshtunnel/token_proof_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector tokenProofVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	decode := func(value string) []byte {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	transcript, err := encodeTokenProofTranscript(vector.IdentityID, decode(vector.HostKeyHash), decode(vector.ClientNonce), decode(vector.ServerNonce))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(transcript); got != vector.TranscriptHex {
		t.Fatalf("transcript = %s", got)
	}
	if got := encodeTokenProofBytes(computeTokenProof(vector.Token, "server", transcript)); got != vector.ServerProof {
		t.Fatalf("server proof = %s", got)
	}

	auth := newSSHTokenProofClient(vector.Token)
	auth.hostHash = decode(vector.HostKeyHash)
	auth.clientNonce = decode(vector.ClientNonce)
	auth.round = 1
	answers, err := auth.challenge(sshTokenProofDomain, "", []string{vector.ServerProofQuestion}, []bool{false})
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 1 || answers[0] != vector.ClientProofAnswer || !auth.serverVerified() {
		t.Fatalf("unexpected proof answer: %v", answers)
	}
}

func TestSSHTokenProofRejectsDuplicateAndPaddedFields(t *testing.T) {
	if _, err := parseTokenProofObject(`{"version":1,"version":1,"step":"client_nonce"}`, "version", "step"); err == nil {
		t.Fatal("duplicate field accepted")
	}
	if _, err := decodeTokenProofBytes("ERERERERERERERERERERERERERERERERERERERERERE=", 32); err == nil {
		t.Fatal("padded base64url accepted")
	}
}
