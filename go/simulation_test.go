// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	txn := verifyTestPayment(t, 41, 42, 1)
	signedHex := fakeSignedTxnHex(txn)
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
			if len(request.Requests) != 1 || request.Requests[0].AuthAddress != txn.Sender.String() {
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
				TxnResults:     make([]models.SimulateTransactionResult, 1),
			}},
		})
	})
	defer closeAlgod()

	result, err := signer.SimulatePreparedGroup(context.Background(), algodClient, NewPreparedGroup(PreparedTransaction{
		Transaction: &txn,
		AuthAddress: txn.Sender.String(),
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

// simulationVerdicts are raw node answers for a group of submitted
// transactions and how the classifier reads each, word for word as in the
// other SDKs. A result passes only as one group result with no failure
// message, no failed-at and one transaction result per transaction.
func simulationVerdicts(submitted int) []struct{ name, body, message string } {
	results := func(n int) string {
		return "[" + strings.TrimSuffix(strings.Repeat(`{"txn-result":{"pool-error":""}},`, n), ",") + "]"
	}
	group := func(fields string) string {
		return `{"last-round":7,"version":2,"txn-groups":[` + fields + `]}`
	}
	return []struct{ name, body, message string }{
		{"one result per transaction", group(`{"txn-results":` + results(submitted) + `}`), ""},
		{"no group result", `{"last-round":7,"version":2}`, "the node returned no result for the group"},
		{"an empty list of group results", group(``), "the node returned no result for the group"},
		{"two group results", group(`{"txn-results":` + results(submitted) + `},{"txn-results":` + results(submitted) + `}`), "the node returned 2 results for one group"},
		// The decoder reads a null group result as an empty one.
		{"a null group result", group(`null`), fmt.Sprintf("the node returned 0 transaction results for %d transactions", submitted)},
		{"an empty group result", group(`{}`), fmt.Sprintf("the node returned 0 transaction results for %d transactions", submitted)},
		{"one transaction result too many", group(`{"txn-results":` + results(submitted+1) + `}`), fmt.Sprintf("the node returned %d transaction results for %d transactions", submitted+1, submitted)},
		{"a failure message", group(`{"failure-message":"logic eval error","failed-at":[0],"txn-results":` + results(submitted) + `}`), "logic eval error"},
		{"a failure message and no transaction results", group(`{"failure-message":"logic eval error"}`), "logic eval error"},
		{"failed-at without a message", group(`{"failed-at":[0],"txn-results":` + results(submitted) + `}`), "the node reported a failure without a message"},
		{"an empty failed-at", group(`{"failed-at":[],"txn-results":` + results(submitted) + `}`), ""},
	}
}

// A signed simulation fails unless the node's answer covers the whole group.
func TestSimulatePreparedGroupClassifiesTheNodesAnswer(t *testing.T) {
	txn := verifyTestPayment(t, 41, 42, 1)
	for _, tc := range simulationVerdicts(1) {
		t.Run(tc.name, func(t *testing.T) {
			signer, signerServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/status":
					json.NewEncoder(w).Encode(StatusResponse{State: "unlocked"})
				case "/sign":
					json.NewEncoder(w).Encode(GroupSignResponse{Signed: []string{fakeSignedTxnHex(txn)}})
				default:
					t.Errorf("unexpected signer path %s", r.URL.Path)
				}
			})
			defer signerServer.Close()
			algodClient, closeAlgod := makeSimulationAlgodClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			})
			defer closeAlgod()

			result, err := signer.SimulatePreparedGroup(context.Background(), algodClient, NewPreparedGroup(PreparedTransaction{
				Transaction: &txn,
				AuthAddress: txn.Sender.String(),
			}))
			if err != nil {
				t.Fatalf("SimulatePreparedGroup() error = %v", err)
			}
			if result.Failed != (tc.message != "") || result.FailureMessage != tc.message {
				t.Fatalf("Failed = %v, FailureMessage = %q; want %q", result.Failed, result.FailureMessage, tc.message)
			}
		})
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
		AuthAddress: sdkTestAddress(0xA1),
	}))
	if err == nil || !strings.Contains(err.Error(), "algod client is required") {
		t.Fatalf("SimulatePreparedGroup() error = %v", err)
	}
	if signerCalls != 0 {
		t.Fatalf("signer calls = %d, want 0", signerCalls)
	}
}

func TestSimulatePreparedCosignedGroupRequiresAlgodBeforeSigning(t *testing.T) {
	_, err := SimulatePreparedCosignedGroup(nil, PreparedCosignedGroupOptions{})
	if err == nil || !strings.Contains(err.Error(), "algod client is required") {
		t.Fatalf("SimulatePreparedCosignedGroup() error = %v", err)
	}
}

func TestDecodeExecutableSignedGroupRejectsEmptyPosition(t *testing.T) {
	_, _, _, err := decodeExecutableSignedGroup([]string{""})
	if err == nil || !strings.Contains(err.Error(), "position 1 is empty") {
		t.Fatalf("decodeExecutableSignedGroup() error = %v", err)
	}
}
