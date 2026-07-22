// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func makeSimulationSignedTxn(t *testing.T, txn types.Transaction) string {
	t.Helper()
	return hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn}))
}

func makeSimulationAlgodClient(t *testing.T, handler http.HandlerFunc) (*algod.Client, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		server.Close()
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	return client, server.Close
}

func TestSimulatePreparedGroupUsesOrdinarySignThenClientAlgod(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	signedHex := makeSimulationSignedTxn(t, txn)
	var signerPaths []string
	signer, signerServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		signerPaths = append(signerPaths, r.URL.Path)
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{State: "unlocked"})
		case "/sign":
			var request GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode sign request: %v", err)
			}
			if len(request.Requests) != 1 || request.Requests[0].AuthAddress != "AUTH" {
				t.Fatalf("sign request = %+v", request.Requests)
			}
			json.NewEncoder(w).Encode(GroupSignResponse{
				Signed: []string{signedHex},
				Mutations: &MutationReport{
					OriginalCount: 1,
					FinalCount:    1,
				},
			})
		default:
			t.Fatalf("unexpected signer path %s", r.URL.Path)
		}
	})
	defer signerServer.Close()

	algodCalls := 0
	algodClient, closeAlgod := makeSimulationAlgodClient(t, func(w http.ResponseWriter, r *http.Request) {
		algodCalls++
		if r.URL.Path != "/v2/transactions/simulate" || r.Method != http.MethodPost {
			t.Fatalf("algod request = %s %s", r.Method, r.URL.Path)
		}
		var request models.SimulateRequest
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read simulate request: %v", err)
		}
		if err := msgpack.Decode(raw, &request); err != nil {
			t.Fatalf("decode simulate request: %v", err)
		}
		if request.AllowEmptySignatures || request.FixSigners {
			t.Fatalf("signed simulation enabled unsigned overrides: %+v", request)
		}
		if len(request.TxnGroups) != 1 || len(request.TxnGroups[0].Txns) != 1 {
			t.Fatalf("simulate groups = %+v", request.TxnGroups)
		}
		got := hex.EncodeToString(msgpack.Encode(request.TxnGroups[0].Txns[0]))
		if got != signedHex {
			t.Fatalf("algod signed transaction = %s, want %s", got, signedHex)
		}
		json.NewEncoder(w).Encode(models.SimulateResponse{
			LastRound: 7,
			Version:   2,
			TxnGroups: []models.SimulateTransactionGroupResult{{
				FailureMessage: "logic eval error",
			}},
		})
	})
	defer closeAlgod()

	result, err := signer.SimulatePreparedGroup(context.Background(), algodClient, NewPreparedGroup(PreparedTransaction{
		Transaction: &txn,
		AuthAddress: "AUTH",
	}))
	if err != nil {
		t.Fatalf("SimulatePreparedGroup() error = %v", err)
	}
	if strings.Join(signerPaths, ",") != "/status,/sign" {
		t.Fatalf("signer paths = %v, want ordinary /sign flow", signerPaths)
	}
	if algodCalls != 1 || !result.Failed || result.Response.LastRound != 7 {
		t.Fatalf("simulation result = %+v, algod calls = %d", result, algodCalls)
	}
	if len(result.SignedGroup) != 1 || result.SignedGroup[0] != signedHex {
		t.Fatalf("signed group = %v", result.SignedGroup)
	}
	if result.Mutations == nil || result.Mutations.FinalCount != 1 {
		t.Fatalf("mutations = %+v", result.Mutations)
	}
}

func TestSimulatePreparedGroupRequiresAlgodBeforeSigner(t *testing.T) {
	signerCalls := 0
	signer, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		signerCalls++
		http.Error(w, "unexpected signer request", http.StatusInternalServerError)
	})
	defer server.Close()

	txn := types.Transaction{Type: types.PaymentTx}
	_, err := signer.SimulatePreparedGroup(context.Background(), nil, NewPreparedGroup(PreparedTransaction{
		Transaction: &txn,
		AuthAddress: "AUTH",
	}))
	if err == nil || !strings.Contains(err.Error(), "algod client is required") {
		t.Fatalf("SimulatePreparedGroup() error = %v", err)
	}
	if signerCalls != 0 {
		t.Fatalf("signer calls = %d, want 0", signerCalls)
	}
}

func TestSimulateGuardedGroupRequiresAlgodBeforeSigning(t *testing.T) {
	_, err := SimulateGuardedGroup(nil, GuardedSignOptions{})
	if err == nil || !strings.Contains(err.Error(), "algod client is required") {
		t.Fatalf("SimulateGuardedGroup() error = %v", err)
	}
}

func TestDecodeExecutableSignedGroupRejectsEmptyPosition(t *testing.T) {
	_, _, _, err := decodeExecutableSignedGroup([]string{""})
	if err == nil || !strings.Contains(err.Error(), "position 1 is empty") {
		t.Fatalf("decodeExecutableSignedGroup() error = %v", err)
	}
}
