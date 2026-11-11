// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func boundedResourceTestKey(spend, spendingRekey *LogicSigResourceUsage, rekey string) *KeyInfo {
	return &KeyInfo{
		LogicSigResources: &LogicSigResourceProfile{
			Spend: spend, SpendingRekey: spendingRekey,
		},
		BoundedAuthorization: &BoundedAuthorizationInfo{Rekey: rekey},
	}
}

func TestSelectedPreparedResourcesUsesBoundedAuthorizationPath(t *testing.T) {
	spend := &LogicSigResourceUsage{ProgramBytes: 1001, ArgumentBytes: 101, MaxOpcodeCost: 10001}
	spendingRekey := &LogicSigResourceUsage{ProgramBytes: 2002, ArgumentBytes: 202, MaxOpcodeCost: 20002}
	var rekeyTo types.Address
	rekeyTo[31] = 1

	tests := []struct {
		name         string
		rekey        bool
		rekeySetting string
		want         *LogicSigResourceUsage
	}{
		{name: "spend on a refused account", rekeySetting: "refused", want: spend},
		{name: "spend on a spending-key account", rekeySetting: "spending_key", want: spend},
		{name: "spending-key rekey", rekey: true, rekeySetting: "spending_key", want: spendingRekey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txn := &types.Transaction{}
			if tt.rekey {
				txn.RekeyTo = rekeyTo
			}
			got, err := selectedPreparedResources(boundedResourceTestKey(spend, spendingRekey, tt.rekeySetting), txn)
			if err != nil {
				t.Fatalf("selectedPreparedResources() error = %v", err)
			}
			if got == nil || *got != *tt.want {
				t.Fatalf("selectedPreparedResources() = %+v, want %+v", got, tt.want)
			}
			if got == tt.want {
				t.Fatal("selectedPreparedResources() returned shared inventory metadata")
			}
		})
	}
}

func TestSelectedPreparedResourcesRejectsRekeyWithoutSpendingKeyAuthorization(t *testing.T) {
	spend := &LogicSigResourceUsage{ProgramBytes: 1001, ArgumentBytes: 101, MaxOpcodeCost: 10001}
	spendingRekey := &LogicSigResourceUsage{ProgramBytes: 2002, ArgumentBytes: 202, MaxOpcodeCost: 20002}
	var rekeyTo types.Address
	rekeyTo[31] = 1
	txn := &types.Transaction{Header: types.Header{RekeyTo: rekeyTo}}

	// Only spending_key authorizes a rekey without a list. refused says so; a
	// missing setting and any other value (such as the removed admin_key
	// authorization) are unavailable metadata.
	for rekey, want := range map[string]string{
		"refused":   "the account refuses rekeys",
		"":          "bounded rekey authorization metadata is unavailable",
		"admin_key": "bounded rekey authorization metadata is unavailable",
	} {
		t.Run(fmt.Sprintf("rekey=%q", rekey), func(t *testing.T) {
			got, err := selectedPreparedResources(boundedResourceTestKey(spend, spendingRekey, rekey), txn)
			if err == nil {
				t.Fatalf("selectedPreparedResources() = %+v, want error for rekey setting %q", got, rekey)
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("selectedPreparedResources() error = %v, want %q", err, want)
			}
		})
	}
}

func createCosignedDummies(firstTxn types.Transaction, count int) ([]types.Transaction, error) {
	dummyAcct := crypto.LogicSigAccount{Lsig: types.LogicSig{Logic: cosignedDummyProgram}}
	dummyAddr, err := dummyAcct.Address()
	if err != nil {
		return nil, err
	}
	sp := types.SuggestedParams{
		Fee: firstTxn.Fee, FirstRoundValid: types.Round(firstTxn.FirstValid),
		LastRoundValid: types.Round(firstTxn.LastValid), GenesisID: firstTxn.GenesisID,
		GenesisHash: firstTxn.GenesisHash[:], FlatFee: true,
	}
	dummies := make([]types.Transaction, count)
	for i := range dummies {
		txn, err := transaction.MakePaymentTxn(dummyAddr.String(), dummyAddr.String(), 0, []byte{byte(i)}, "", sp)
		if err != nil {
			return nil, err
		}
		txn.Fee = 0
		dummies[i] = txn
	}
	return dummies, nil
}

// signedGroupFor echoes a signed group whose inner transactions match the given
// canonical group bytes, so assembly/passthrough mock responses return bytes the
// post-assembly identity check accepts.
func signedGroupFor(t *testing.T, groupBytesHex []string) []string {
	t.Helper()
	out := make([]string, len(groupBytesHex))
	for i, h := range groupBytesHex {
		out[i] = signedTxnHexFor(t, h)
	}
	return out
}

func signedTxnHexFor(t *testing.T, canonicalHex string) string {
	t.Helper()
	raw, err := hex.DecodeString(canonicalHex)
	if err != nil {
		t.Fatalf("decode canonical hex %q: %v", canonicalHex, err)
	}
	if len(raw) < 2 || raw[0] != 'T' || raw[1] != 'X' {
		t.Fatalf("canonical hex %q missing TX prefix", canonicalHex)
	}
	var txn types.Transaction
	if err := msgpack.Decode(raw[2:], &txn); err != nil {
		t.Fatalf("decode txn from %q: %v", canonicalHex, err)
	}
	return hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn}))
}

func TestSignPreparedCosignedGroupRejectsUnsupportedSigningFlow(t *testing.T) {
	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		FirstRoundValid: 1,
		LastRoundValid:  100,
		GenesisID:       "testnet-v1.0",
		GenesisHash:     genesisHash[:],
		FlatFee:         true,
	}
	cosigned := sdkTestAddress(1)
	receiver := sdkTestAddress(2)
	txn, err := transaction.MakePaymentTxn(cosigned, receiver, 1000, nil, "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}

	// The flow reads the signer's keyset revision, and nothing else here.
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(StatusResponse{State: "unlocked"})
	})
	defer server.Close()
	_, err = signCosignedWithHeldKeys(PreparedCosignedGroupOptions{
		UserClient: client,
		PreparedGroup: NewPreparedGroup(held(PreparedTransaction{
			Transaction: &txn,
			AuthAddress: cosigned,
		}, &KeyInfo{
			Address:     cosigned,
			KeyType:     "aplane.future-cosigned.v1",
			SigningFlow: "cosigner2",
			LogicSigResources: &LogicSigResourceProfile{
				Spend: &LogicSigResourceUsage{ProgramBytes: 1612, ArgumentBytes: 1423, MaxOpcodeCost: 20000},
			},
		})),
	})
	if err == nil || !strings.Contains(err.Error(), `signing flow "cosigner2"`) {
		t.Fatalf("SignPreparedCosignedGroup() error = %v, want unsupported signing flow rejection", err)
	}
}

// cosigner1, the retired dedicated cosigned flow, is an unknown flow like any
// other: the prepared flow refuses the key before it sends any request.
func TestSignPreparedCosignedGroupRefusesCosigner1AsUnknown(t *testing.T) {
	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee: types.MicroAlgos(1000), FirstRoundValid: 1, LastRoundValid: 100,
		GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
	}
	account := sdkTestAddress(1)
	txn, err := transaction.MakePaymentTxn(account, sdkTestAddress(2), 1000, nil, "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}
	requests := 0
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		// Reading the signer's keyset revision is not a signing request.
		if r.URL.Path == "/status" {
			json.NewEncoder(w).Encode(StatusResponse{State: "unlocked"})
			return
		}
		requests++
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	})
	defer server.Close()
	_, err = signCosignedWithHeldKeys(PreparedCosignedGroupOptions{
		UserClient: client,
		PreparedGroup: NewPreparedGroup(held(PreparedTransaction{
			Transaction: &txn,
			AuthAddress: account,
		}, &KeyInfo{
			Address: account, KeyType: "aplane.falcon1024-cosigner1024.v1", SigningFlow: "cosigner1",
			CosignerComponentKeyType: KeyTypeWitnessFalcon1024,
			LogicSigResources: &LogicSigResourceProfile{
				Spend: &LogicSigResourceUsage{ProgramBytes: 1612, ArgumentBytes: 1423, MaxOpcodeCost: 20000},
			},
		})),
	})
	if err == nil || !strings.Contains(err.Error(), `signing flow "cosigner1", which this SDK does not support`) {
		t.Fatalf("SignPreparedCosignedGroup() error = %v, want cosigner1 refused as an unknown flow", err)
	}
	if requests != 0 {
		t.Fatalf("sent %d request(s) before refusing the flow", requests)
	}
}

// A rekey on an "only these" account is sized from the listed path: the signer
// checks the target against the account's list and adds the proof.
func TestSelectedPreparedResourcesUsesTheListedPathForOnlyThese(t *testing.T) {
	spend := &LogicSigResourceUsage{ProgramBytes: 1001, ArgumentBytes: 101, MaxOpcodeCost: 10001}
	listed := &LogicSigResourceUsage{ProgramBytes: 1001, ArgumentBytes: 1583, MaxOpcodeCost: 20003}
	key := boundedResourceTestKey(spend, spend, "refused")
	key.LogicSigResources.ListedRekey = listed
	key.BoundedAuthorization.RekeyList = &BoundedRekeyListInfo{Contract: "rekey_list1", Depth: 4}
	var rekeyTo types.Address
	rekeyTo[31] = 1
	got, err := selectedPreparedResources(key, &types.Transaction{Header: types.Header{RekeyTo: rekeyTo}})
	if err != nil || got == nil || *got != *listed {
		t.Fatalf("selectedPreparedResources() = %+v, %v; want the listed path", got, err)
	}
	if got, err := selectedPreparedResources(key, &types.Transaction{}); err != nil || *got != *spend {
		t.Fatalf("a spend on a list account = %+v, %v", got, err)
	}
}

// testHeldKeys are the keys the signer of a cosigned test holds, by address.
// The cosigned flow reads each key from the signer by the position's auth
// address, so a test names the signer's key beside the position that uses it
// with held, and signCosignedWithHeldKeys serves those to the flow.
var testHeldKeys = map[string]*KeyInfo{}

// held records key as the signer's key for a position and returns the
// position unchanged.
func held(position PreparedTransaction, key *KeyInfo) PreparedTransaction {
	if key != nil {
		testHeldKeys[key.Address] = key
	}
	return position
}

// signCosignedWithHeldKeys is SignPreparedCosignedGroup against a signer that
// holds the keys named with held.
func signCosignedWithHeldKeys(opts PreparedCosignedGroupOptions) (*CosignedSignResult, error) {
	if opts.UserClient != nil {
		cache := make(map[string]*KeyInfo, len(testHeldKeys))
		for address, key := range testHeldKeys {
			copied := *key
			cache[address] = &copied
		}
		// Cached at the keyset revision the test signers report, so the flow's
		// key read is served from here.
		opts.UserClient.keyMu.Lock()
		opts.UserClient.keyCache = cache
		opts.UserClient.keyCacheRevision = 0
		opts.UserClient.keyCacheRevisionKnown = true
		opts.UserClient.keyMu.Unlock()
	}
	return SignPreparedCosignedGroup(opts)
}

// cosignedDummyProgramOpcodes holds exactly the opcodes the dummy program
// uses: the immediate bytes each takes and its cost, which is 1 in every AVM
// version. None branches, so a program built only from them is straight-line
// and the sum of its opcode costs is the cost of every run. An opcode missing
// here fails the test rather than being guessed at.
var cosignedDummyProgramOpcodes = map[byte]struct {
	name       string
	immediates int
	cost       uint64
	fields     map[byte]string
}{
	0x12: {name: "==", cost: 1},
	0x31: {name: "txn", immediates: 1, cost: 1, fields: map[byte]string{32: "RekeyTo"}},
	0x32: {name: "global", immediates: 1, cost: 1, fields: map[byte]string{3: "ZeroAddress"}},
}

func TestCosignedDummyOpcodeCostMatchesProgram(t *testing.T) {
	program := cosignedDummyProgram
	version, pc := binary.Uvarint(program)
	if pc <= 0 || version != 3 {
		t.Fatalf("dummy program version = %d (prefix %d bytes), want 3", version, pc)
	}
	var cost uint64
	var listing []string
	for pc < len(program) {
		op, ok := cosignedDummyProgramOpcodes[program[pc]]
		if !ok {
			t.Fatalf("dummy program opcode 0x%02x at pc %d has no cost in this test's table", program[pc], pc)
		}
		if pc+1+op.immediates > len(program) {
			t.Fatalf("dummy program opcode %s at pc %d is truncated", op.name, pc)
		}
		text := op.name
		if op.immediates == 1 {
			field, known := op.fields[program[pc+1]]
			if !known {
				t.Fatalf("dummy program %s field %d at pc %d is not in this test's table", op.name, program[pc+1], pc)
			}
			text += " " + field
		}
		listing = append(listing, text)
		cost += op.cost
		pc += 1 + op.immediates
	}
	if got, want := strings.Join(listing, "; "), "txn RekeyTo; global ZeroAddress; =="; got != want {
		t.Fatalf("dummy program = %q, want %q", got, want)
	}
	if cost != cosignedDummyOpcodeCost {
		t.Fatalf("dummy program costs %d, cosignedDummyOpcodeCost is %d", cost, cosignedDummyOpcodeCost)
	}
}

// The signer plans one LogicSig declaring 39,999 with two dummies, not one:
// counted at the program's real 3, one dummy leaves the group at 40,002, over
// two transactions' 40,000, and two give 40,005 within three transactions'
// 60,000. apsigner's planner tests pin the same case. The SDK declares each
// dummy it hands back at /sign the same way, so the signer re-plans the frozen
// group at the size it planned it.
func TestCosignedDummyDeclarationCountsTheProgramCost(t *testing.T) {
	dummy := cosignedDummyLogicSigResources()
	if dummy.ProgramBytes != uint64(len(cosignedDummyProgram)) || dummy.ArgumentBytes != 0 || dummy.MaxOpcodeCost != cosignedDummyOpcodeCost {
		t.Fatalf("dummy declaration = %+v, want the program's %d bytes, no arguments and cost %d", dummy, len(cosignedDummyProgram), cosignedDummyOpcodeCost)
	}
	const target, perTransaction = 39_999, 20_000
	if total := target + dummy.MaxOpcodeCost; total != 40_002 || total <= 2*perTransaction {
		t.Fatalf("one LogicSig at %d and one dummy declare %d, want 40002, over two transactions' budget", target, total)
	}
	if total := target + 2*dummy.MaxOpcodeCost; total != 40_005 || total > 3*perTransaction {
		t.Fatalf("one LogicSig at %d and two dummies declare %d, want 40005, within three transactions' budget", target, total)
	}
}
