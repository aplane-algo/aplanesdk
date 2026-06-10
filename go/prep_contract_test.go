// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

type prepParityFixture struct {
	Cases []prepParityCase `json:"cases"`
}

type prepParityCase struct {
	Name             string        `json:"name"`
	ExpectedRequests []SignRequest `json:"expected_requests"`
}

func prepFixturePath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	return filepath.Join(filepath.Dir(file), "..", "contracts", "prep", name)
}

func loadPrepParityFixture(t *testing.T) prepParityFixture {
	t.Helper()
	raw, err := os.ReadFile(prepFixturePath(t, "sign_request_shapes.json"))
	if err != nil {
		t.Fatalf("read prep fixture: %v", err)
	}
	var fixture prepParityFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("unmarshal prep fixture: %v", err)
	}
	return fixture
}

func TestPreparedSignRequestParityFixture(t *testing.T) {
	builders := prepParityBuilders(t)
	for _, tc := range loadPrepParityFixture(t).Cases {
		t.Run(tc.Name, func(t *testing.T) {
			builder, ok := builders[tc.Name]
			if !ok {
				t.Fatalf("no builder for fixture case %q", tc.Name)
			}
			requests, err := builder().SignRequests()
			if err != nil {
				t.Fatalf("SignRequests() error = %v", err)
			}
			if !reflect.DeepEqual(requests, tc.ExpectedRequests) {
				want, _ := json.MarshalIndent(tc.ExpectedRequests, "", "  ")
				got, _ := json.MarshalIndent(requests, "", "  ")
				t.Fatalf("request shape mismatch\nwant: %s\n got: %s", want, got)
			}
		})
	}
}

func prepParityBuilders(t *testing.T) map[string]func() PreparedGroup {
	t.Helper()
	const (
		sender     = "AEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEA5RCDXMI"
		receiver   = "AIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBMXPWWNQ"
		auth       = "AMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMB5DBBASI"
		closeTo    = "AQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCABXO5EU"
		rekeyTo    = "AUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUC7CN5SGQ"
		foreign    = "AYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDADPLZKY"
		appAccount = "A4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DVZ36IB4"
	)
	passthrough := base64.StdEncoding.EncodeToString([]byte{0x82, 0xa3, 0x73, 0x69, 0x67, 0xc4, 0x40})

	signed := func(txn types.Transaction, extras ...func(*PreparedTransaction)) PreparedTransaction {
		prepared := PreparedTransaction{Transaction: &txn, AuthAddress: auth}
		for _, apply := range extras {
			apply(&prepared)
		}
		return prepared
	}
	foreignSlot := func(txn types.Transaction) PreparedTransaction {
		return PreparedTransaction{Transaction: &txn, LsigSize: 3035}
	}
	passthroughSlot := func() PreparedTransaction {
		return PreparedTransaction{SignedTransactionBase64: passthrough}
	}
	must := func(txn types.Transaction, err error) types.Transaction {
		t.Helper()
		if err != nil {
			t.Fatalf("build transaction: %v", err)
		}
		return txn
	}

	payment := must(transaction.MakePaymentTxn(sender, receiver, 12345, []byte("pay"), "", prepSuggestedParams()))
	asa := must(transaction.MakeAssetTransferTxn(sender, receiver, 5, []byte("asa"), prepSuggestedParams(), "", 1001))
	optIn := must(transaction.MakeAssetTransferTxn(sender, sender, 0, []byte("optin"), prepSuggestedParams(), "", 1001))
	optOut := must(transaction.MakeAssetTransferTxn(sender, sender, 0, []byte("optout"), prepSuggestedParams(), closeTo, 1001))
	closeTxn := must(transaction.MakePaymentTxn(sender, closeTo, 0, []byte("close"), closeTo, prepSuggestedParams()))
	rekey := must(transaction.MakePaymentTxn(sender, sender, 0, []byte("rekey"), "", prepSuggestedParams()))
	if err := rekey.Rekey(rekeyTo); err != nil {
		t.Fatalf("set rekey target: %v", err)
	}
	keyreg := must(transaction.MakeKeyRegTxnWithStateProofKey(sender, []byte("keyreg"), prepSuggestedParams(), "", "", "", 0, 0, 0, true))
	rawApp := prepAppCallTxn(t, sender, appAccount, [][]byte{[]byte("raw")}, []byte("rawapp"))
	abiApp := prepAppCallTxn(t, sender, appAccount, [][]byte{{0x01, 0x02, 0x03, 0x04}, {0, 0, 0, 0, 0, 0, 0, 42}}, []byte("abiapp"))
	appDeploy := prepAppDeployTxn(t, sender)
	foreignPayment := must(transaction.MakePaymentTxn(foreign, receiver, 500, []byte("foreign"), "", prepSuggestedParams()))
	secondPayment := must(transaction.MakePaymentTxn(sender, closeTo, 6789, []byte("pay2"), "", prepSuggestedParams()))

	return map[string]func() PreparedGroup{
		"payment_sign_mode_lsig_args": func() PreparedGroup {
			return NewPreparedGroup(signed(payment, func(p *PreparedTransaction) {
				p.LsigArgs = LsigArgs{
					"preimage":  []byte("secret"),
					"recipient": []byte{0xaa, 0xbb, 0xcc, 0xdd},
				}
			}))
		},
		"asa_transfer": func() PreparedGroup {
			return NewPreparedGroup(signed(asa))
		},
		"asa_opt_in": func() PreparedGroup {
			return NewPreparedGroup(signed(optIn))
		},
		"asa_opt_out": func() PreparedGroup {
			return NewPreparedGroup(signed(optOut))
		},
		"account_close": func() PreparedGroup {
			return NewPreparedGroup(signed(closeTxn))
		},
		"rekey": func() PreparedGroup {
			return NewPreparedGroup(signed(rekey))
		},
		"keyreg_nonparticipation": func() PreparedGroup {
			return NewPreparedGroup(signed(keyreg))
		},
		"raw_app_call_info": func() PreparedGroup {
			return NewPreparedGroup(signed(rawApp, func(p *PreparedTransaction) {
				p.AppCallInfo = &AppCallInfo{Mode: "raw"}
			}))
		},
		"abi_app_call_info": func() PreparedGroup {
			return NewPreparedGroup(signed(abiApp, func(p *PreparedTransaction) {
				p.AppCallInfo = &AppCallInfo{Mode: "abi", Method: "do(uint64)void"}
			}))
		},
		"app_deploy": func() PreparedGroup {
			return NewPreparedGroup(signed(appDeploy, func(p *PreparedTransaction) {
				p.AppCallInfo = &AppCallInfo{Mode: "raw"}
			}))
		},
		"payment_plus_app_group": func() PreparedGroup {
			return NewPreparedGroup(signed(payment), signed(rawApp, func(p *PreparedTransaction) {
				p.AppCallInfo = &AppCallInfo{Mode: "raw"}
			}))
		},
		"grouped_payments": func() PreparedGroup {
			return NewPreparedGroup(signed(payment), signed(secondPayment))
		},
		"foreign_lsig_context": func() PreparedGroup {
			return NewPreparedGroup(foreignSlot(foreignPayment))
		},
		"passthrough_signed_slot": func() PreparedGroup {
			return NewPreparedGroup(passthroughSlot())
		},
		"mixed_sign_foreign_passthrough": func() PreparedGroup {
			return NewPreparedGroup(signed(payment), foreignSlot(foreignPayment), passthroughSlot())
		},
	}
}

func prepSuggestedParams() types.SuggestedParams {
	var genesisHash types.Digest
	for i := range genesisHash {
		genesisHash[i] = 9
	}
	return types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		FirstRoundValid: 100,
		LastRoundValid:  200,
		GenesisID:       "testnet-v1",
		GenesisHash:     genesisHash[:],
		FlatFee:         true,
	}
}

func prepAppCallTxn(t *testing.T, sender string, appAccount string, args [][]byte, note []byte) types.Transaction {
	t.Helper()
	senderAddr, err := types.DecodeAddress(sender)
	if err != nil {
		t.Fatalf("decode sender: %v", err)
	}
	txn, err := transaction.MakeApplicationCallTx(
		7,
		args,
		[]string{appAccount},
		[]uint64{8},
		[]uint64{1001},
		types.NoOpOC,
		nil,
		nil,
		types.StateSchema{},
		types.StateSchema{},
		prepSuggestedParams(),
		senderAddr,
		note,
		types.Digest{},
		[32]byte{},
		types.Address{},
	)
	return mustTxn(t, txn, err)
}

func prepAppDeployTxn(t *testing.T, sender string) types.Transaction {
	t.Helper()
	senderAddr, err := types.DecodeAddress(sender)
	if err != nil {
		t.Fatalf("decode sender: %v", err)
	}
	txn, err := transaction.MakeApplicationCreateTxWithExtraPages(
		false,
		[]byte{0x01, 0x20, 0x01, 0x01, 0x22},
		[]byte{0x01, 0x20, 0x01, 0x01, 0x22},
		types.StateSchema{NumUint: 1},
		types.StateSchema{NumByteSlice: 1},
		[][]byte{[]byte("init")},
		nil,
		nil,
		nil,
		prepSuggestedParams(),
		senderAddr,
		[]byte("deploy"),
		types.Digest{},
		[32]byte{},
		types.Address{},
		1,
	)
	return mustTxn(t, txn, err)
}

func mustTxn(t *testing.T, txn types.Transaction, err error) types.Transaction {
	t.Helper()
	if err != nil {
		t.Fatalf("build transaction: %v", err)
	}
	return txn
}
