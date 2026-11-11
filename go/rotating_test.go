// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// A stage program for tests. Its address stands for a stage's.
var rotatingTestProgram = []byte{0x0a, 0x81, 0x01}

func rotatingStageAddress(program []byte) types.Address {
	return crypto.LogicSigAddress(types.LogicSig{Logic: program})
}

// rotatingSigner is a fake signer holding one rotating account. It prepares
// and signs as the real one does, and lets a test alter either answer.
type rotatingSigner struct {
	t       *testing.T
	account string
	stage   uint64
	program []byte // the current stage's program
	dummies int
	charge  uint64

	// alterPrepare and alterSign change an answer before it is sent.
	alterPrepare func(response *RotatingPrepareResponse, txns []types.Transaction)
	alterSign    func(response *RotatingSignResponse, signed []types.SignedTxn)
	// prepareErrors and signErrors are answered, in order, before any
	// success. A nil entry closes the connection with no answer.
	prepareErrors []*ErrorResponse
	signErrors    []*ErrorResponse
	errorStatus   int

	mu           sync.Mutex
	paths        []string
	prepareSeen  []types.Transaction
	signRequests []RotatingSignRequest
}

func (s *rotatingSigner) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, p := range s.paths {
		if p == path {
			n++
		}
	}
	return n
}

func (s *rotatingSigner) nextTarget() types.Address {
	var next types.Address
	next[0], next[31] = 0xaa, byte(s.stage+1)
	return next
}

func (s *rotatingSigner) fail(w http.ResponseWriter, queue *[]*ErrorResponse) bool {
	s.mu.Lock()
	if len(*queue) == 0 {
		s.mu.Unlock()
		return false
	}
	failure := (*queue)[0]
	*queue = (*queue)[1:]
	s.mu.Unlock()
	if failure == nil {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			s.t.Errorf("hijack: %v", err)
			return true
		}
		conn.Close()
		return true
	}
	status := s.errorStatus
	if status == 0 {
		status = http.StatusConflict
	}
	if failure.Code == ErrCodeBadRequest {
		status = http.StatusBadRequest
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(failure)
	return true
}

func (s *rotatingSigner) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.URL.Path)
	s.mu.Unlock()
	switch r.URL.Path {
	case "/status":
		json.NewEncoder(w).Encode(StatusResponse{State: "unlocked"})
	case "/keys":
		json.NewEncoder(w).Encode(KeysResponse{Count: 1, Keys: []KeyInfo{{
			Address: s.account, KeyType: "aplane.rotating-triple-wotsc.v1", SigningFlow: SigningFlowRotating1,
		}}})
	case "/sign/rotating/prepare":
		var request RotatingPrepareRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.t.Errorf("decode prepare request: %v", err)
			return
		}
		raw, _ := hex.DecodeString(request.TxnBytesHex)
		txn, err := decodeCanonicalTxn(raw)
		if err != nil {
			s.t.Errorf("prepare request transaction: %v", err)
			return
		}
		s.mu.Lock()
		s.prepareSeen = append(s.prepareSeen, txn)
		s.mu.Unlock()
		if s.fail(w, &s.prepareErrors) {
			return
		}
		response, txns := s.prepare(txn)
		if s.alterPrepare != nil {
			s.alterPrepare(response, txns)
		}
		json.NewEncoder(w).Encode(response)
	case "/sign/rotating/sign":
		var request RotatingSignRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.t.Errorf("decode sign request: %v", err)
			return
		}
		s.mu.Lock()
		s.signRequests = append(s.signRequests, request)
		s.mu.Unlock()
		if s.fail(w, &s.signErrors) {
			return
		}
		response, signed := s.sign(request)
		if s.alterSign != nil {
			s.alterSign(response, signed)
		}
		json.NewEncoder(w).Encode(response)
	default:
		s.t.Errorf("unexpected signer path %s", r.URL.Path)
	}
}

// prepare builds the group the real signer would: the spend with the rotation
// rekey and the authorization charge, then canonical dummies, grouped.
func (s *rotatingSigner) prepare(original types.Transaction) (*RotatingPrepareResponse, []types.Transaction) {
	spend := original
	spend.RekeyTo = s.nextTarget()
	spend.Fee += types.MicroAlgos(s.charge)
	txns := []types.Transaction{spend}
	for i := 0; i < s.dummies; i++ {
		dummy, err := canonicalDummyTxn(original, types.Digest{}, i)
		if err != nil {
			s.t.Fatalf("fake signer: dummy: %v", err)
		}
		txns = append(txns, dummy)
	}
	var report *MutationReport
	if s.dummies > 0 || s.charge > 0 {
		report = &MutationReport{OriginalCount: 1, FinalCount: len(txns), DummiesAdded: s.dummies}
		if s.charge > 0 {
			report.FeesModified = []int{0}
			report.TotalFeesDelta = int(s.charge)
		}
	}
	if len(txns) > 1 {
		groupID, err := crypto.ComputeGroupID(txns)
		if err != nil {
			s.t.Fatalf("fake signer: group ID: %v", err)
		}
		for i := range txns {
			txns[i].Group = groupID
		}
		report.GroupIDChanged = true
	}
	response := &RotatingPrepareResponse{
		Account: s.account, Stage: s.stage, Target: s.stage + 1,
		RekeyTo: s.nextTarget().String(), Mutations: report,
	}
	setPreparedTransactions(response, txns)
	return response, txns
}

func setPreparedTransactions(response *RotatingPrepareResponse, txns []types.Transaction) {
	response.Transactions = make([]string, len(txns))
	for i := range txns {
		response.Transactions[i] = hex.EncodeToString(encodeTxn(txns[i]))
	}
}

// regroup recomputes the group ID over txns, as a signer that changed a
// member would have to.
func regroup(t *testing.T, txns []types.Transaction) {
	t.Helper()
	if len(txns) < 2 {
		return
	}
	for i := range txns {
		txns[i].Group = types.Digest{}
	}
	groupID, err := crypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("regroup: %v", err)
	}
	for i := range txns {
		txns[i].Group = groupID
	}
}

func (s *rotatingSigner) sign(request RotatingSignRequest) (*RotatingSignResponse, []types.SignedTxn) {
	signed := make([]types.SignedTxn, len(request.Transactions))
	for i, h := range request.Transactions {
		raw, _ := hex.DecodeString(h)
		txn, err := decodeCanonicalTxn(raw)
		if err != nil {
			s.t.Fatalf("fake signer: sign request transaction %d: %v", i, err)
		}
		if i == 0 {
			signed[i] = types.SignedTxn{Txn: txn, Lsig: types.LogicSig{Logic: s.program, Args: [][]byte{{1, 2, 3}}}}
			if stage := rotatingStageAddress(s.program); stage != txn.Sender {
				signed[i].AuthAddr = stage
			}
			continue
		}
		signed[i] = types.SignedTxn{Txn: txn, Lsig: types.LogicSig{Logic: cosignedDummyProgram}}
	}
	spend := signed[0].Txn
	response := &RotatingSignResponse{
		Stage: s.stage, Target: s.stage + 1, TxID: crypto.GetTxID(spend),
		GroupID: base64.StdEncoding.EncodeToString(spend.Group[:]),
	}
	setSignedTransactions(response, signed)
	return response, signed
}

func setSignedTransactions(response *RotatingSignResponse, signed []types.SignedTxn) {
	response.Signed = make([]string, len(signed))
	for i := range signed {
		response.Signed[i] = hex.EncodeToString(msgpack.Encode(signed[i]))
	}
}

// rotatingPayment is a payment from sender with the given validity rounds.
func rotatingPayment(t *testing.T, sender string, first, last uint64) types.Transaction {
	t.Helper()
	var genesisHash types.Digest
	genesisHash[0] = 7
	sp := types.SuggestedParams{
		Fee: types.MicroAlgos(1000), FirstRoundValid: types.Round(first), LastRoundValid: types.Round(last),
		GenesisID: "testnet-v1.0", GenesisHash: genesisHash[:], FlatFee: true,
	}
	txn, err := transaction.MakePaymentTxn(sender, sdkTestAddress(42), 5000, nil, "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}
	return txn
}

// newRotatingFixture is a rotating account at stage 3 whose spends need one
// dummy and a 1,000 microAlgo charge, and a node at round 10.
func newRotatingFixture(t *testing.T) (*rotatingSigner, *sendAlgod, *SignerClient, *algod.Client, types.Transaction) {
	t.Helper()
	signer := &rotatingSigner{t: t, account: fakeAccount(41), stage: 3, program: rotatingTestProgram, dummies: 1, charge: 1000}
	node := &sendAlgod{t: t}
	client, signerServer := newTestClient(signer.handle)
	t.Cleanup(signerServer.Close)
	algodClient, closeAlgod := makeSimulationAlgodClient(t, node.handle)
	t.Cleanup(closeAlgod)
	return signer, node, client, algodClient, rotatingPayment(t, signer.account, 10, 110)
}

func rotatingGroup(txn types.Transaction) PreparedGroup {
	return NewPreparedGroup(PreparedTransaction{Transaction: &txn, AuthAddress: txn.Sender.String()})
}

func TestSendPreparedRotatingPreparesSimulatesSignsSubmits(t *testing.T) {
	signer, node, client, algodClient, txn := newRotatingFixture(t)

	result, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
	if err != nil {
		t.Fatalf("SendPrepared() error = %v", err)
	}
	if signer.count("/sign/rotating/prepare") != 1 || signer.count("/sign/rotating/sign") != 1 || signer.count("/sign") != 0 {
		t.Fatalf("signer paths = %v", signer.paths)
	}
	// The group was simulated once, unsigned, exactly as prepared.
	simulations := node.simulations()
	// FixSigners has the node take the sender's authorizer from the chain;
	// without it an account that has rotated fails its own simulation.
	if len(simulations) != 1 || !simulations[0].AllowEmptySignatures || !simulations[0].FixSigners {
		t.Fatalf("%d simulation(s); want one, unsigned, with the node fixing signers", len(simulations))
	}
	prepared := signer.signRequests[0].Transactions
	simulated := simulations[0].TxnGroups[0].Txns
	if len(simulated) != 2 || len(prepared) != 2 {
		t.Fatalf("simulated %d, prepared %d transactions; want 2 and 2", len(simulated), len(prepared))
	}
	for i := range simulated {
		if !simulated[i].Lsig.Blank() || simulated[i].Sig != (types.Signature{}) {
			t.Fatalf("simulated transaction %d carries a signature", i)
		}
		if hex.EncodeToString(encodeTxn(simulated[i].Txn)) != prepared[i] {
			t.Fatalf("simulated transaction %d is not the prepared one", i)
		}
	}

	if result.Flow != SigningFlowRotating1 || result.OriginalCount != 1 || len(result.SignedGroup) != 2 || result.GroupID == "" {
		t.Fatalf("result = %+v", result)
	}
	submitted := node.submissions()
	if len(submitted) != 1 || hex.EncodeToString(submitted[0]) != strings.Join(result.SignedGroup, "") {
		t.Fatalf("submission is not the signed group, once")
	}
	var spend types.SignedTxn
	if err := msgpack.Decode(submitted[0], &spend); err != nil {
		t.Fatal(err)
	}
	if spend.Txn.RekeyTo != signer.nextTarget() || spend.Txn.Fee != 2000 || spend.AuthAddr != rotatingStageAddress(rotatingTestProgram) {
		t.Fatalf("submitted spend = %+v auth %s", spend.Txn, spend.AuthAddr)
	}
	// The ID is the signed spend's, not the draft's.
	if result.TxIDs[0] != crypto.GetTxID(spend.Txn) || result.TxIDs[0] == crypto.GetTxID(txn) {
		t.Fatalf("txid = %s", result.TxIDs[0])
	}
	if result.Fees[0] != 2000 || result.Fees[1] != 0 {
		t.Fatalf("fees = %v", result.Fees)
	}
	details := result.Rotating
	if details == nil || details.Stage != 3 || details.Target != 4 || details.RekeyTo != signer.nextTarget().String() || details.Attempts != 1 || details.RequestID == "" {
		t.Fatalf("rotating details = %+v", details)
	}
	if result.Outcome != SendOutcomeConfirmed {
		t.Fatalf("outcome = %s", result.Outcome)
	}
}

func TestSendPreparedRotatingStageZeroWithoutDummies(t *testing.T) {
	account := rotatingStageAddress(rotatingTestProgram).String()
	signer := &rotatingSigner{t: t, account: account, stage: 0, program: rotatingTestProgram}
	node := &sendAlgod{t: t}
	client, signerServer := newTestClient(signer.handle)
	defer signerServer.Close()
	algodClient, closeAlgod := makeSimulationAlgodClient(t, node.handle)
	defer closeAlgod()

	result, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(rotatingPayment(t, account, 10, 110)), nil)
	if err != nil {
		t.Fatalf("SendPrepared() error = %v", err)
	}
	var spend types.SignedTxn
	if err := msgpack.Decode(node.submissions()[0], &spend); err != nil {
		t.Fatal(err)
	}
	if !spend.AuthAddr.IsZero() || len(result.SignedGroup) != 1 || result.GroupID != "" || result.Mutations != nil {
		t.Fatalf("stage 0 spend auth %s, result %+v", spend.AuthAddr, result)
	}
}

// TestPrepareRotatingRefusesAlteredGroup covers the client's authority
// boundary for a prepared group: each case is one thing the signer may not do.
// None reaches simulation or signing.
// rotatingTestElsewhere is an address no fixture uses.
var rotatingTestElsewhere = types.Address{0x55}

// alternateSpelling writes an address another way. The last base32 character
// of an address has two bits that carry nothing, so three other strings
// decode to the same 32 bytes and checksum under a lenient decoder. The
// Algorand Go library refuses them; the JavaScript and Python ones do not.
func alternateSpelling(address string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	last := strings.IndexByte(alphabet, address[len(address)-1])
	return address[:len(address)-1] + string(alphabet[last^1])
}

// respendPrepared changes the prepared spend, regroups, and writes the group
// back into the response, as a signer that altered the spend would have to.
func respendPrepared(t *testing.T, response *RotatingPrepareResponse, txns []types.Transaction, change func(*types.Transaction)) {
	change(&txns[0])
	regroup(t, txns)
	setPreparedTransactions(response, txns)
}

// rotatingPrepareTampers are the things a signer may not do to a prepared
// group. Each alters a correct prepare response; text is what the Go check
// says. They also generate the shared vectors every SDK must refuse.
var rotatingPrepareTampers = []struct {
	name  string
	alter func(t *testing.T, response *RotatingPrepareResponse, txns []types.Transaction)
	text  string
}{
	{"receiver changed", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		respendPrepared(t, r, txns, func(spend *types.Transaction) { spend.Receiver = rotatingTestElsewhere })
	}, "changed unreported fields"},
	{"amount changed", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		respendPrepared(t, r, txns, func(spend *types.Transaction) { spend.Amount++ })
	}, "changed unreported fields"},
	{"note added", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		respendPrepared(t, r, txns, func(spend *types.Transaction) { spend.Note = []byte("x") })
	}, "changed unreported fields"},
	{"close-out added", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		respendPrepared(t, r, txns, func(spend *types.Transaction) { spend.CloseRemainderTo = rotatingTestElsewhere })
	}, "changed unreported fields"},
	{"validity rounds changed", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		respendPrepared(t, r, txns, func(spend *types.Transaction) { spend.LastValid-- })
	}, "changed unreported fields"},
	{"network changed", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		respendPrepared(t, r, txns, func(spend *types.Transaction) { spend.GenesisHash[1] ^= 1 })
	}, "changed unreported fields"},
	{"rekey to an address other than the one reported", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		respendPrepared(t, r, txns, func(spend *types.Transaction) { spend.RekeyTo = rotatingTestElsewhere })
	}, "changed unreported fields"},
	{"rekey left out", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		respendPrepared(t, r, txns, func(spend *types.Transaction) { spend.RekeyTo = types.Address{} })
	}, "changed unreported fields"},
	{"reported rekey target is the zero address", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.RekeyTo = types.Address{}.String()
	}, "rekey_to must be another, non-zero address"},
	{"reported rekey target is the account", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.RekeyTo = r.Account
	}, "rekey_to must be another, non-zero address"},
	{"reported rekey target in another spelling of its address", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.RekeyTo = alternateSpelling(r.RekeyTo)
	}, "invalid rekey_to"},
	{"account in another spelling of the sender", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.Account = alternateSpelling(r.Account)
	}, "is not the sender"},
	{"reported rekey target is not an address", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.RekeyTo = "nonsense"
	}, "invalid rekey_to"},
	{"fee raised more than reported", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		respendPrepared(t, r, txns, func(spend *types.Transaction) { spend.Fee += 500 })
	}, "total_fees_delta"},
	{"fee raised with no fee report", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.Mutations.FeesModified, r.Mutations.TotalFeesDelta = nil, 0
	}, "changed unreported fields"},
	{"fee lowered", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		respendPrepared(t, r, txns, func(spend *types.Transaction) { spend.Fee = 500 })
	}, "did not increase the fee"},
	{"group ID not the group's", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		for i := range txns {
			txns[i].Group[0] ^= 1
		}
		setPreparedTransactions(r, txns)
	}, "canonical group ID"},
	{"dummy pays the account's money", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		txns[1].Amount = 1
		regroup(t, txns)
		setPreparedTransactions(r, txns)
	}, "not the canonical resource dummy"},
	{"dummy on other rounds", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		txns[1].LastValid++
		regroup(t, txns)
		setPreparedTransactions(r, txns)
	}, "not the canonical resource dummy"},
	{"extra transaction beyond the report", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		extra, _ := canonicalDummyTxn(txns[0], types.Digest{}, len(txns)-1)
		txns = append(txns, extra)
		regroup(t, txns)
		setPreparedTransactions(r, txns)
	}, "final_count"},
	{"dummies with no report", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.Mutations = nil
	}, "without a mutation report"},
	{"no transactions", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.Transactions = nil
	}, "prepared group is empty"},
	{"another account", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.Account = sdkTestAddress(9)
	}, "is not the sender"},
	{"target is not the next stage", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.Target = r.Stage + 2
	}, "not the stage after"},
	{"target equals the stage", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.Target = r.Stage
	}, "not the stage after"},
	{"stage number overflows", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.Stage, r.Target = ^uint64(0), 0
	}, "not the stage after"},
	{"trailing bytes after the spend", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.Transactions[0] += "00"
	}, "not canonical"},
	{"spend without the TX prefix", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.Transactions[0] = r.Transactions[0][4:]
	}, "missing TX prefix"},
	{"spend is not hex", func(t *testing.T, r *RotatingPrepareResponse, txns []types.Transaction) {
		r.Transactions[0] = "zz"
	}, "invalid hex"},
}

func TestPrepareRotatingRefusesAlteredGroup(t *testing.T) {
	tests := rotatingPrepareTampers
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, node, client, algodClient, txn := newRotatingFixture(t)
			signer.alterPrepare = func(response *RotatingPrepareResponse, txns []types.Transaction) {
				tt.alter(t, response, txns)
			}

			_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
			if err == nil || !strings.Contains(err.Error(), "verify prepared rotating group") || !strings.Contains(err.Error(), tt.text) {
				t.Fatalf("error = %v, want a prepared-group refusal mentioning %q", err, tt.text)
			}
			if len(node.simulations()) != 0 || signer.count("/sign/rotating/sign") != 0 || len(node.submissions()) != 0 {
				t.Fatalf("simulations %d, sign calls %d, submissions %d; want none", len(node.simulations()), signer.count("/sign/rotating/sign"), len(node.submissions()))
			}
		})
	}
}

func TestPrepareRotatingHoldsTheFeeCeiling(t *testing.T) {
	signer, node, client, algodClient, txn := newRotatingFixture(t)
	client.SetMaxFeeIncrease(999)

	_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
	var tooHigh *MaxFeeIncreaseError
	if !errors.As(err, &tooHigh) || tooHigh.Raised != 1000 || tooHigh.Limit != 999 {
		t.Fatalf("error = %v, want a max fee increase refusal", err)
	}
	if len(node.simulations()) != 0 || signer.count("/sign/rotating/sign") != 0 {
		t.Fatalf("a spend over the fee ceiling reached simulation or signing")
	}

	client.SetMaxFeeIncrease(1000)
	if _, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil); err != nil {
		t.Fatalf("SendPrepared() at the ceiling error = %v", err)
	}
}

// TestSignPreparedRotatingRefusesAlteredResponse covers the signed response:
// each case is a signed group that is not exactly the prepared one, properly
// authorized. None is submitted.
// rotatingNextProgram is a program other than the stage that signs.
var rotatingNextProgram = []byte{0x0a, 0x81, 0x02}

// rotatingSignTampers are signed responses that are not exactly the prepared
// group, properly authorized. Each alters a correct sign response.
var rotatingSignTampers = []struct {
	name  string
	alter func(t *testing.T, signer *rotatingSigner, response *RotatingSignResponse, signed []types.SignedTxn)
	text  string
}{
	{"spend changed after preparation", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		signed[0].Txn.Amount++
		setSignedTransactions(r, signed)
	}, "differs from the prepared transaction"},
	{"dummy changed after preparation", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		signed[1].Txn.Note = []byte{9}
		setSignedTransactions(r, signed)
	}, "differs from the prepared transaction"},
	{"transactions reordered", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		r.Signed[0], r.Signed[1] = r.Signed[1], r.Signed[0]
	}, "differs from the prepared transaction"},
	{"transaction missing", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		r.Signed = r.Signed[:1]
	}, "signed group has 1 transaction(s), prepared 2"},
	{"extra transaction", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		r.Signed = append(r.Signed, r.Signed[1])
	}, "signed group has 3 transaction(s), prepared 2"},
	{"trailing bytes", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		r.Signed[0] += "00"
	}, "not a canonical signed transaction"},
	{"spend not signed", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		signed[0].Lsig = types.LogicSig{}
		setSignedTransactions(r, signed)
	}, "not authorized by a stage program"},
	{"spend signed by a plain key instead", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		signed[0].Lsig = types.LogicSig{}
		signed[0].Sig = types.Signature{1}
		setSignedTransactions(r, signed)
	}, "not authorized by a stage program"},
	{"spend carries two authorizations", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		signed[0].Sig = types.Signature{1}
		setSignedTransactions(r, signed)
	}, "more than one authorization"},
	{"stage program delegated by a signature", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		signed[0].Lsig.Sig = types.Signature{1}
		setSignedTransactions(r, signed)
	}, "delegated by a signature"},
	{"signer of the spend not named", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		signed[0].AuthAddr = types.Address{}
		setSignedTransactions(r, signed)
	}, "does not name its signer"},
	{"named signer is not the program's address", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		signed[0].AuthAddr = rotatingStageAddress(rotatingNextProgram)
		setSignedTransactions(r, signed)
	}, "not the requested auth address"},
	{"dummy not signed", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		signed[1].Lsig = types.LogicSig{}
		setSignedTransactions(r, signed)
	}, "not the canonical signed resource dummy"},
	{"dummy signed by another program", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		signed[1].Lsig = types.LogicSig{Logic: rotatingNextProgram}
		setSignedTransactions(r, signed)
	}, "not the canonical signed resource dummy"},
	{"another stage reported, target unchanged", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		r.Stage++
	}, "signer reports stage"},
	{"another target reported, stage unchanged", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		r.Target++
	}, "signer reports stage"},
	{"another stage reported", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		r.Stage, r.Target = r.Stage+1, r.Target+1
	}, "signer reports stage 4 to 5, prepared 3 to 4"},
	{"another transaction ID reported", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		r.TxID = crypto.GetTxID(signed[1].Txn)
	}, "signer reports transaction ID"},
	{"another group ID reported", func(t *testing.T, s *rotatingSigner, r *RotatingSignResponse, signed []types.SignedTxn) {
		r.GroupID = base64.StdEncoding.EncodeToString(make([]byte, 32))
	}, "signer reports group ID"},
}

func TestSignPreparedRotatingRefusesAlteredResponse(t *testing.T) {
	tests := rotatingSignTampers
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, node, client, algodClient, txn := newRotatingFixture(t)
			signer.alterSign = func(response *RotatingSignResponse, signed []types.SignedTxn) {
				tt.alter(t, signer, response, signed)
			}

			_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
			if err == nil || !strings.Contains(err.Error(), "verify signer response") || !strings.Contains(err.Error(), tt.text) {
				t.Fatalf("error = %v, want a signed-response refusal mentioning %q", err, tt.text)
			}
			if len(node.submissions()) != 0 || signer.count("/sign/rotating/sign") != 1 {
				t.Fatalf("submissions %d, sign calls %d; want 0 and 1", len(node.submissions()), signer.count("/sign/rotating/sign"))
			}
		})
	}
}

func TestSignPreparedRotatingStageProgramMustFitTheStage(t *testing.T) {
	t.Run("stage 0 signs as the account itself", func(t *testing.T) {
		// The signer claims stage 0, but the program is not the account's.
		signer, node, client, algodClient, txn := newRotatingFixture(t)
		signer.stage = 0
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
		if err == nil || !strings.Contains(err.Error(), "does not fit stage 0") {
			t.Fatalf("error = %v", err)
		}
		if len(node.submissions()) != 0 {
			t.Fatalf("submitted a spend whose stage program does not fit")
		}
	})
	t.Run("a later stage does not sign as the account", func(t *testing.T) {
		account := rotatingStageAddress(rotatingTestProgram).String()
		signer := &rotatingSigner{t: t, account: account, stage: 2, program: rotatingTestProgram}
		node := &sendAlgod{t: t}
		client, signerServer := newTestClient(signer.handle)
		defer signerServer.Close()
		algodClient, closeAlgod := makeSimulationAlgodClient(t, node.handle)
		defer closeAlgod()
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(rotatingPayment(t, account, 10, 110)), nil)
		if err == nil || !strings.Contains(err.Error(), "does not fit stage 2") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("the next stage's program does not sign", func(t *testing.T) {
		signer, node, client, algodClient, txn := newRotatingFixture(t)
		signer.alterPrepare = func(response *RotatingPrepareResponse, txns []types.Transaction) {
			// The reported target is the address of the program that signs.
			target := rotatingStageAddress(rotatingTestProgram)
			response.RekeyTo = target.String()
			txns[0].RekeyTo = target
			regroup(t, txns)
			setPreparedTransactions(response, txns)
		}
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
		if err == nil || !strings.Contains(err.Error(), "authorized by the next stage's program") {
			t.Fatalf("error = %v", err)
		}
		if len(node.submissions()) != 0 {
			t.Fatalf("submitted a spend signed by its own rekey target")
		}
	})
}

func TestSendPreparedRotatingFailedPreflightSignsNothing(t *testing.T) {
	t.Run("simulation fails", func(t *testing.T) {
		signer, node, client, algodClient, txn := newRotatingFixture(t)
		node.simulate = func(w http.ResponseWriter, _ models.SimulateRequest) {
			w.Write([]byte(`{"last-round":10,"version":2,"txn-groups":[{"failure-message":"logic eval error: rekey not allowed"}]}`))
		}
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
		var preflight *RotatingPreflightError
		if !errors.As(err, &preflight) || !strings.Contains(preflight.Message, "rekey not allowed") || preflight.Prepared == nil {
			t.Fatalf("error = %v, want *RotatingPreflightError", err)
		}
		if signer.count("/sign/rotating/sign") != 0 || len(node.submissions()) != 0 {
			t.Fatalf("a failed preflight reached signing or submission")
		}
	})
	t.Run("simulation cannot be run", func(t *testing.T) {
		signer, node, client, algodClient, txn := newRotatingFixture(t)
		node.simulate = func(w http.ResponseWriter, _ models.SimulateRequest) { w.WriteHeader(http.StatusInternalServerError) }
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
		if err == nil || !strings.Contains(err.Error(), "nothing was signed") {
			t.Fatalf("error = %v", err)
		}
		if signer.count("/sign/rotating/sign") != 0 {
			t.Fatalf("signed without a preflight")
		}
	})
	t.Run("simulate only never signs", func(t *testing.T) {
		signer, node, client, algodClient, txn := newRotatingFixture(t)
		prepared, err := client.PrepareRotating(context.Background(), txn, nil)
		if err != nil {
			t.Fatalf("PrepareRotating() error = %v", err)
		}
		simulation, err := client.SimulatePreparedRotating(context.Background(), algodClient, prepared)
		if err != nil || simulation.Failed || len(simulation.TxIDs) != 2 {
			t.Fatalf("SimulatePreparedRotating() = %+v, %v", simulation, err)
		}
		if signer.count("/sign/rotating/sign") != 0 || len(node.submissions()) != 0 {
			t.Fatalf("simulate-only signed or submitted")
		}
	})
}

func rotatingRefusal(code, message string) *ErrorResponse {
	return &ErrorResponse{Error: message, Code: code}
}

func TestSendPreparedRotatingRetries(t *testing.T) {
	oldBackoff := rotatingUnprovenBackoff
	rotatingUnprovenBackoff = time.Millisecond
	defer func() { rotatingUnprovenBackoff = oldBackoff }()
	stageChanged := rotatingRefusal(ErrCodeRotatingStageChanged, "the account's authorizer changed")
	notCurrent := rotatingRefusal(ErrCodeRotatingWindowNotCurrent, "fewer than 10 rounds remain before last valid round")
	unproven := rotatingRefusal(ErrCodeRotatingStageUnproven, "the account's live stage has not been found yet")

	t.Run("stage not found yet, then found", func(t *testing.T) {
		signer, _, client, algodClient, txn := newRotatingFixture(t)
		signer.prepareErrors = []*ErrorResponse{unproven}
		result, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
		if err != nil || result.Rotating.Attempts != 2 {
			t.Fatalf("SendPrepared() = %+v, %v", result, err)
		}
		if signer.count("/sign/rotating/prepare") != 2 || signer.count("/sign/rotating/sign") != 1 {
			t.Fatalf("signer paths = %v", signer.paths)
		}
	})

	t.Run("authorizer moved before signing, then signed", func(t *testing.T) {
		signer, node, client, algodClient, txn := newRotatingFixture(t)
		signer.signErrors = []*ErrorResponse{stageChanged}
		result, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
		if err != nil || result.Rotating.Attempts != 2 {
			t.Fatalf("SendPrepared() = %+v, %v", result, err)
		}
		// Every attempt is prepared, simulated and presented for approval again.
		if signer.count("/sign/rotating/prepare") != 2 || signer.count("/sign/rotating/sign") != 2 || len(node.simulations()) != 2 || len(node.submissions()) != 1 {
			t.Fatalf("prepares %d, signs %d, simulations %d, submissions %d", signer.count("/sign/rotating/prepare"), signer.count("/sign/rotating/sign"), len(node.simulations()), len(node.submissions()))
		}
		// The supplied transaction was not rebuilt.
		if result.Rotating.Transaction.FirstValid != txn.FirstValid || result.Rotating.Transaction.LastValid != txn.LastValid {
			t.Fatalf("validity rounds were rebuilt without permission")
		}
	})

	t.Run("gives up after three attempts", func(t *testing.T) {
		signer, node, client, algodClient, txn := newRotatingFixture(t)
		signer.signErrors = []*ErrorResponse{stageChanged, stageChanged, stageChanged, stageChanged}
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
		if apiErrorCode(err) != ErrCodeRotatingStageChanged {
			t.Fatalf("error = %v, want the signer's refusal", err)
		}
		if signer.count("/sign/rotating/sign") != 3 || len(node.submissions()) != 0 {
			t.Fatalf("signs %d, submissions %d; want 3 and 0", signer.count("/sign/rotating/sign"), len(node.submissions()))
		}
	})

	t.Run("window not current: supplied input is returned, not rebuilt", func(t *testing.T) {
		signer, node, client, algodClient, txn := newRotatingFixture(t)
		signer.signErrors = []*ErrorResponse{notCurrent}
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
		if apiErrorCode(err) != ErrCodeRotatingWindowNotCurrent {
			t.Fatalf("error = %v, want the timing refusal", err)
		}
		if signer.count("/sign/rotating/prepare") != 1 || signer.count("/sign/rotating/sign") != 1 || len(node.submissions()) != 0 {
			t.Fatalf("a supplied transaction was prepared again after a timing refusal")
		}
	})

	t.Run("window not current: rebuilt when refresh is allowed", func(t *testing.T) {
		signer, node, client, algodClient, txn := newRotatingFixture(t)
		signer.signErrors = []*ErrorResponse{notCurrent}
		node.round = 50
		txn = rotatingPayment(t, signer.account, 50, 150)
		result, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), &SendOptions{RefreshValidity: true})
		if err != nil || result.Rotating.Attempts != 2 {
			t.Fatalf("SendPrepared() = %+v, %v", result, err)
		}
		if signer.count("/sign/rotating/sign") != 2 || len(signer.prepareSeen) != 2 {
			t.Fatalf("signs %d, prepares %d; want 2 and 2", signer.count("/sign/rotating/sign"), len(signer.prepareSeen))
		}
	})

	t.Run("an uncoded bad request is not retried", func(t *testing.T) {
		signer, _, client, algodClient, txn := newRotatingFixture(t)
		// The old wording of a timing refusal, without the code.
		signer.signErrors = []*ErrorResponse{rotatingRefusal(ErrCodeBadRequest, "fewer than 10 rounds remain before last valid round 110")}
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), &SendOptions{RefreshValidity: true})
		if apiErrorCode(err) != ErrCodeBadRequest {
			t.Fatalf("error = %v", err)
		}
		if signer.count("/sign/rotating/sign") != 1 || signer.count("/sign/rotating/prepare") != 1 {
			t.Fatalf("a bad request was retried")
		}
	})

	t.Run("a policy refusal is not retried", func(t *testing.T) {
		signer, _, client, algodClient, txn := newRotatingFixture(t)
		signer.errorStatus = http.StatusForbidden
		signer.signErrors = []*ErrorResponse{rotatingRefusal(ErrCodeForbidden, "rejected")}
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
		if !errors.Is(err, ErrSigningRejected) {
			t.Fatalf("error = %v, want ErrSigningRejected", err)
		}
		if signer.count("/sign/rotating/sign") != 1 || signer.count("/sign/rotating/prepare") != 1 {
			t.Fatalf("a refusal was retried")
		}
	})
}

func TestSendPreparedRotatingValidityRounds(t *testing.T) {
	t.Run("a supplied window over the limit is refused before the signer", func(t *testing.T) {
		signer, _, client, algodClient, _ := newRotatingFixture(t)
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(rotatingPayment(t, signer.account, 10, 1010)), nil)
		if err == nil || !strings.Contains(err.Error(), "validity window is 1000 rounds") {
			t.Fatalf("error = %v", err)
		}
		if signer.count("/sign/rotating/prepare") != 0 {
			t.Fatalf("an overlong window reached the signer")
		}
	})
	t.Run("refresh rebuilds an overlong or stale window", func(t *testing.T) {
		for _, rounds := range [][2]uint64{{10, 1010}, {1, 12}} {
			signer, node, client, algodClient, _ := newRotatingFixture(t)
			node.round = 40
			result, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(rotatingPayment(t, signer.account, rounds[0], rounds[1])), &SendOptions{RefreshValidity: true})
			if err != nil {
				t.Fatalf("SendPrepared(%v) error = %v", rounds, err)
			}
			sent := signer.prepareSeen[0]
			if sent.FirstValid != 40 || sent.LastValid < 50 || sent.LastValid-sent.FirstValid > RotatingMaxValidityWindow {
				t.Fatalf("rounds %v were rebuilt to %d-%d", rounds, sent.FirstValid, sent.LastValid)
			}
			if result.Rotating.Transaction.FirstValid != sent.FirstValid {
				t.Fatalf("result does not report the transaction that was prepared")
			}
		}
	})
	t.Run("a current window is left alone even when refresh is allowed", func(t *testing.T) {
		signer, _, client, algodClient, txn := newRotatingFixture(t)
		if _, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), &SendOptions{RefreshValidity: true}); err != nil {
			t.Fatalf("SendPrepared() error = %v", err)
		}
		if sent := signer.prepareSeen[0]; sent.FirstValid != txn.FirstValid || sent.LastValid != txn.LastValid {
			t.Fatalf("a current window was rebuilt to %d-%d", sent.FirstValid, sent.LastValid)
		}
	})
}

func TestSendPreparedRotatingRefusesUnsupportedShapes(t *testing.T) {
	var elsewhere types.Address
	elsewhere[0] = 0x55
	tests := []struct {
		name   string
		change func(item *PreparedTransaction)
		text   string
	}{
		{"already grouped", func(item *PreparedTransaction) { item.Transaction.Group[0] = 1 }, "must be ungrouped"},
		{"sets its own rekey", func(item *PreparedTransaction) { item.Transaction.RekeyTo = elsewhere }, "must not set rekey_to"},
		{"closes the account", func(item *PreparedTransaction) { item.Transaction.CloseRemainderTo = elsewhere }, "cannot close out"},
		{"carries LogicSig arguments", func(item *PreparedTransaction) { item.LsigArgs = LsigArgs{"x": []byte{1}} }, "takes no LogicSig arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, _, client, algodClient, txn := newRotatingFixture(t)
			group := rotatingGroup(txn)
			tt.change(&group.Transactions[0])
			_, err := client.SendPrepared(context.Background(), algodClient, group, &SendOptions{RefreshValidity: true})
			if !errors.Is(err, ErrUnsupportedGroup) || !strings.Contains(err.Error(), tt.text) {
				t.Fatalf("error = %v, want ErrUnsupportedGroup mentioning %q", err, tt.text)
			}
			if signer.count("/sign/rotating/prepare") != 0 {
				t.Fatalf("an unsupported spend reached the signer")
			}
		})
	}
}

func TestSignPreparedRotatingLostAnswerThenIdenticalRetry(t *testing.T) {
	signer, node, client, algodClient, txn := newRotatingFixture(t)
	signer.signErrors = []*ErrorResponse{nil} // the first sign gets no answer

	_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), &SendOptions{RefreshValidity: true})
	var unknown *SignOutcomeUnknownError
	if !errors.As(err, &unknown) || unknown.Rotating == nil || unknown.RequestID == "" {
		t.Fatalf("error = %v, want *SignOutcomeUnknownError carrying the prepared group", err)
	}
	if want := preparedLastValid(t, unknown.Rotating); want == 0 || unknown.LastValid != want {
		t.Fatalf("LastValid = %d, want the prepared group's %d", unknown.LastValid, want)
	}
	// The send stops: no second prepare, no second sign, nothing submitted.
	if signer.count("/sign/rotating/prepare") != 1 || signer.count("/sign/rotating/sign") != 1 || len(node.submissions()) != 0 {
		t.Fatalf("a lost sign answer was followed by another attempt")
	}

	// The caller's recovery: the same prepared group, signed again.
	signed, err := client.SignPreparedRotating(context.Background(), unknown.Rotating, nil)
	if err != nil {
		t.Fatalf("SignPreparedRotating() retry error = %v", err)
	}
	first, second := signer.signRequests[0], signer.signRequests[1]
	if strings.Join(first.Transactions, ",") != strings.Join(second.Transactions, ",") || first.Account != second.Account {
		t.Fatalf("the retry did not send the identical prepared group")
	}
	if first.RequestID == second.RequestID {
		t.Fatalf("the retry reused the request ID %s", first.RequestID)
	}
	if signer.count("/sign/rotating/prepare") != 1 {
		t.Fatalf("the retry prepared again")
	}
	result, err := client.SubmitSignedGroup(context.Background(), algodClient, signed.SignedGroup, nil)
	if err != nil || result.Outcome != SendOutcomeConfirmed || result.TxIDs[0] != signed.TxID || result.TxIDs[0] != unknown.Rotating.TxIDs()[0] {
		t.Fatalf("SubmitSignedGroup() = %+v, %v", result, err)
	}
}

func TestSignPreparedRotatingRefusedRetryMakesNoFurtherCall(t *testing.T) {
	signer, node, client, _, txn := newRotatingFixture(t)
	prepared, err := client.PrepareRotating(context.Background(), txn, nil)
	if err != nil {
		t.Fatalf("PrepareRotating() error = %v", err)
	}
	signer.signErrors = []*ErrorResponse{rotatingRefusal(ErrCodeRotatingStageChanged, "the account's authorizer changed")}
	_, err = client.SignPreparedRotating(context.Background(), prepared, nil)
	if apiErrorCode(err) != ErrCodeRotatingStageChanged {
		t.Fatalf("error = %v, want the stage-changed refusal", err)
	}
	if signer.count("/sign/rotating/prepare") != 1 || signer.count("/sign/rotating/sign") != 1 || len(node.submissions()) != 0 {
		t.Fatalf("a refused sign of a prepared group led to another call")
	}
}

func TestPreparedRotatingCannotBeChangedByItsHolder(t *testing.T) {
	signer, _, client, _, txn := newRotatingFixture(t)
	prepared, err := client.PrepareRotating(context.Background(), txn, nil)
	if err != nil {
		t.Fatalf("PrepareRotating() error = %v", err)
	}
	want := strings.Join(prepared.Transactions(), ",")
	// Everything handed out is a copy.
	prepared.Transactions()[0] = "00"
	prepared.Mutations().FeesModified[0] = 7
	original := prepared.Original()
	original.Amount = 999999
	txn.Amount = 999999

	if _, err := client.SignPreparedRotating(context.Background(), prepared, &RotatingSignOptions{RequestID: "client-chosen-id"}); err != nil {
		t.Fatalf("SignPreparedRotating() error = %v", err)
	}
	request := signer.signRequests[0]
	if strings.Join(request.Transactions, ",") != want || request.RequestID != "client-chosen-id" {
		t.Fatalf("sign request = %+v", request)
	}
	if prepared.Original().Amount != 5000 {
		t.Fatalf("the prepared original changed to %d", prepared.Original().Amount)
	}
}

func TestPrepareHelpersBuildARotatingWindow(t *testing.T) {
	stage := rotatingStageAddress(rotatingTestProgram).String()
	rotating := fakeAccount(41)
	ordinary := fakeAccount(43)
	keys := []KeyInfo{
		{Address: rotating, KeyType: "aplane.rotating-triple-wotsc.v1", SigningFlow: SigningFlowRotating1},
		{Address: ordinary, KeyType: "ed25519"},
	}
	client, signerServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{State: "unlocked"})
		case "/keys":
			json.NewEncoder(w).Encode(KeysResponse{Count: len(keys), Keys: keys})
		default:
			t.Errorf("unexpected signer path %s", r.URL.Path)
		}
	})
	defer signerServer.Close()
	var genesisHash types.Digest
	genesisHash[0] = 7
	algodClient, closeAlgod := makeSimulationAlgodClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/transactions/params":
			json.NewEncoder(w).Encode(map[string]any{
				"fee": 0, "min-fee": 1000, "last-round": 500, "genesis-id": "testnet-v1.0",
				"genesis-hash": genesisHash[:], "consensus-version": "test",
			})
		case "/v2/accounts/" + rotating:
			// The account has rotated: the chain names a stage address the
			// signer does not list.
			json.NewEncoder(w).Encode(map[string]any{"address": rotating, "amount": 5_000_000, "min-balance": 100_000, "auth-addr": stage})
		case "/v2/accounts/" + ordinary:
			json.NewEncoder(w).Encode(map[string]any{"address": ordinary, "amount": 5_000_000, "min-balance": 100_000})
		default:
			t.Errorf("unexpected algod path %s", r.URL.Path)
		}
	})
	defer closeAlgod()
	ctx := context.Background()

	prepared, err := client.PreparePayment(ctx, algodClient, PaymentPrepParams{Sender: rotating, Receiver: sdkTestAddress(42), Amount: 1})
	if err != nil {
		t.Fatalf("PreparePayment(rotating) error = %v", err)
	}
	txn := prepared.Transaction
	if prepared.AuthAddress != rotating {
		t.Fatalf("auth address = %s, want the rotating account itself", prepared.AuthAddress)
	}
	if txn.FirstValid != 500 || txn.LastValid != 500+RotatingMaxValidityWindow {
		t.Fatalf("rotating window = %d-%d, want 500-600", txn.FirstValid, txn.LastValid)
	}
	if err := checkRotatingWindow(*txn); err != nil {
		t.Fatalf("a helper-built rotating transaction fails the window rule: %v", err)
	}

	prepared, err = client.PreparePayment(ctx, algodClient, PaymentPrepParams{Sender: ordinary, Receiver: sdkTestAddress(42), Amount: 1})
	if err != nil {
		t.Fatalf("PreparePayment(ordinary) error = %v", err)
	}
	if got := prepared.Transaction.LastValid - prepared.Transaction.FirstValid; got != 1000 {
		t.Fatalf("ordinary window = %d rounds, want the node's 1000", got)
	}

	resolved, err := client.ResolveAuthAddress(ctx, rotating, func(context.Context, string) (string, error) { return stage, nil })
	if err != nil || resolved.AuthAddress != rotating || resolved.ChainAuthAddress != stage || resolved.IsRekeyed {
		t.Fatalf("ResolveAuthAddress(rotating) = %+v, %v", resolved, err)
	}
}

func TestRotatingTimingConstantsMatchTheContract(t *testing.T) {
	// docs/ARCH_SIGNING.md, "Rotating accounts": a window of at most 100
	// rounds, first valid at most 2 rounds ahead, at least 10 rounds left.
	if RotatingMaxValidityWindow != 100 || RotatingMaxLead != 2 || RotatingMinRemaining != 10 {
		t.Fatalf("rotating timing constants = %d, %d, %d", RotatingMaxValidityWindow, RotatingMaxLead, RotatingMinRemaining)
	}
	txn := types.Transaction{Header: types.Header{FirstValid: 12, LastValid: 112}}
	for round, want := range map[uint64]bool{9: false, 10: true, 102: true, 103: false} {
		if got := rotatingWindowCurrent(txn, round); got != want {
			t.Errorf("rotatingWindowCurrent(12-112, round %d) = %v, want %v", round, got, want)
		}
	}
	txn.LastValid = 113
	if rotatingWindowCurrent(txn, 10) {
		t.Errorf("a 101-round window was accepted")
	}
}

func TestSignPreparedRotatingChecksTheBindingAgain(t *testing.T) {
	signer, node, client, algodClient, txn := newRotatingFixture(t)
	prepared, err := client.PrepareRotating(context.Background(), txn, nil)
	if err != nil {
		t.Fatalf("PrepareRotating() error = %v", err)
	}
	// Nothing outside the package can change a prepared group. If one were
	// changed all the same, neither simulation nor signing may use it.
	altered := txn
	altered.Amount = 999999
	prepared.original = encodeTxn(altered)

	if _, err := client.SignPreparedRotating(context.Background(), prepared, nil); err == nil || !strings.Contains(err.Error(), "verify prepared rotating group") {
		t.Fatalf("SignPreparedRotating() error = %v, want the binding refused", err)
	}
	if _, err := client.SimulatePreparedRotating(context.Background(), algodClient, prepared); err == nil || !strings.Contains(err.Error(), "verify prepared rotating group") {
		t.Fatalf("SimulatePreparedRotating() error = %v, want the binding refused", err)
	}
	if signer.count("/sign/rotating/sign") != 0 || len(node.simulations()) != 0 {
		t.Fatalf("an altered prepared group reached the signer or the node")
	}
}

func TestSendPreparedRotatingRetryBounds(t *testing.T) {
	oldBackoff := rotatingUnprovenBackoff
	rotatingUnprovenBackoff = time.Millisecond
	defer func() { rotatingUnprovenBackoff = oldBackoff }()
	repeat := func(refusal *ErrorResponse) []*ErrorResponse {
		return []*ErrorResponse{refusal, refusal, refusal, refusal, refusal, refusal}
	}

	t.Run("a stage that is never found ends after three prepares", func(t *testing.T) {
		signer, _, client, algodClient, txn := newRotatingFixture(t)
		signer.prepareErrors = repeat(rotatingRefusal(ErrCodeRotatingStageUnproven, "not found yet"))
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
		if apiErrorCode(err) != ErrCodeRotatingStageUnproven || signer.count("/sign/rotating/prepare") != 3 || signer.count("/sign/rotating/sign") != 0 {
			t.Fatalf("error = %v after %d prepares", err, signer.count("/sign/rotating/prepare"))
		}
	})

	t.Run("a window that is never current ends after three signs", func(t *testing.T) {
		signer, node, client, algodClient, txn := newRotatingFixture(t)
		signer.signErrors = repeat(rotatingRefusal(ErrCodeRotatingWindowNotCurrent, "too few rounds remain"))
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), &SendOptions{RefreshValidity: true})
		if apiErrorCode(err) != ErrCodeRotatingWindowNotCurrent || signer.count("/sign/rotating/sign") != 3 || len(node.submissions()) != 0 {
			t.Fatalf("error = %v after %d signs", err, signer.count("/sign/rotating/sign"))
		}
	})

	t.Run("the wait to retry honors the context", func(t *testing.T) {
		rotatingUnprovenBackoff = time.Hour
		defer func() { rotatingUnprovenBackoff = time.Millisecond }()
		signer, _, client, algodClient, txn := newRotatingFixture(t)
		signer.prepareErrors = repeat(rotatingRefusal(ErrCodeRotatingStageUnproven, "not found yet"))
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, err := client.SendPrepared(ctx, algodClient, rotatingGroup(txn), nil)
		if apiErrorCode(err) != ErrCodeRotatingStageUnproven || signer.count("/sign/rotating/prepare") != 1 {
			t.Fatalf("error = %v after %d prepares; want the refusal after one", err, signer.count("/sign/rotating/prepare"))
		}
		// Both are readable: the signer's refusal and the deadline.
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want it to match context.DeadlineExceeded too", err)
		}
	})
}

func TestSendPaymentMayRebuildARotatingWindow(t *testing.T) {
	signer, node, client, _, _ := newRotatingFixture(t)
	signer.signErrors = []*ErrorResponse{rotatingRefusal(ErrCodeRotatingWindowNotCurrent, "too few rounds remain")}
	algodClient, closeAlgod := makeSimulationAlgodClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/accounts/"+signer.account {
			json.NewEncoder(w).Encode(map[string]any{"address": signer.account, "amount": 5_000_000, "min-balance": 100_000, "auth-addr": rotatingStageAddress(rotatingTestProgram).String()})
			return
		}
		node.handle(w, r)
	})
	defer closeAlgod()

	// SendPayment built the transaction, so it may rebuild its rounds with no
	// option set; and the helper gave a rotated account a window it can use.
	result, err := client.SendPayment(context.Background(), algodClient, PaymentPrepParams{Sender: signer.account, Receiver: sdkTestAddress(42), Amount: 5000}, nil)
	if err != nil || result.Rotating == nil || result.Rotating.Attempts != 2 {
		t.Fatalf("SendPayment() = %+v, %v", result, err)
	}
	if sent := signer.prepareSeen[0]; sent.LastValid-sent.FirstValid != RotatingMaxValidityWindow {
		t.Fatalf("window = %d rounds", sent.LastValid-sent.FirstValid)
	}
}

func TestSendPreparedRotatingChecksTheRoundBeforeTheOperatorIsAsked(t *testing.T) {
	t.Run("stale rounds are refused when they may not be rebuilt", func(t *testing.T) {
		signer, node, client, algodClient, _ := newRotatingFixture(t)
		node.round = 105 // fewer than 10 rounds left of 10-110
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(rotatingPayment(t, signer.account, 10, 110)), nil)
		if err == nil || !strings.Contains(err.Error(), "are not current at round 105") {
			t.Fatalf("error = %v", err)
		}
		if signer.count("/sign/rotating/prepare") != 0 {
			t.Fatalf("stale rounds reached the signer")
		}
	})
	t.Run("a window too short to sign is not kept when rebuilding", func(t *testing.T) {
		signer, node, client, algodClient, _ := newRotatingFixture(t)
		node.round = 40
		if _, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(rotatingPayment(t, signer.account, 40, 45)), &SendOptions{RefreshValidity: true}); err != nil {
			t.Fatalf("SendPrepared() error = %v", err)
		}
		if sent := signer.prepareSeen[0]; sent.FirstValid != 40 || sent.LastValid != 40+RotatingMaxValidityWindow {
			t.Fatalf("a 5-round window was rebuilt to %d-%d", sent.FirstValid, sent.LastValid)
		}
	})
}

func TestSendPreparedRotatingStopsBeforeSigning(t *testing.T) {
	t.Run("simulation reports no group", func(t *testing.T) {
		signer, node, client, algodClient, txn := newRotatingFixture(t)
		node.simulate = func(w http.ResponseWriter, _ models.SimulateRequest) {
			w.Write([]byte(`{"last-round":10,"version":2}`))
		}
		_, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
		var preflight *RotatingPreflightError
		if !errors.As(err, &preflight) || !strings.Contains(err.Error(), "no result for the group") || signer.count("/sign/rotating/sign") != 0 {
			t.Fatalf("error = %v, sign calls %d", err, signer.count("/sign/rotating/sign"))
		}
	})
	t.Run("context ended after simulation", func(t *testing.T) {
		signer, node, client, algodClient, txn := newRotatingFixture(t)
		// A context that reports itself ended once the simulation has been
		// answered, without interrupting the requests already made.
		ctx := &endsAfter{Context: context.Background()}
		node.simulate = func(w http.ResponseWriter, request models.SimulateRequest) {
			json.NewEncoder(w).Encode(passingSimulation(10, request))
			ctx.ended.Store(true)
		}
		_, err := client.SendPrepared(ctx, algodClient, rotatingGroup(txn), nil)
		var unknown *SignOutcomeUnknownError
		if !errors.Is(err, context.Canceled) || errors.As(err, &unknown) {
			t.Fatalf("error = %v, want a plain stop, not an unknown sign outcome", err)
		}
		if len(node.simulations()) != 1 || signer.count("/sign/rotating/sign") != 0 {
			t.Fatalf("simulations %d, sign calls %d; want 1 and 0", len(node.simulations()), signer.count("/sign/rotating/sign"))
		}
	})
	t.Run("the steps report an empty simulation answer as failed", func(t *testing.T) {
		_, node, client, algodClient, txn := newRotatingFixture(t)
		node.simulate = func(w http.ResponseWriter, _ models.SimulateRequest) {
			w.Write([]byte(`{"last-round":10,"version":2}`))
		}
		prepared, err := client.PrepareRotating(context.Background(), txn, nil)
		if err != nil {
			t.Fatal(err)
		}
		simulation, err := client.SimulatePreparedRotating(context.Background(), algodClient, prepared)
		if err != nil || !simulation.Failed || simulation.FailureMessage != "the node returned no result for the group" {
			t.Fatalf("SimulatePreparedRotating() = %+v, %v; want Failed with no result", simulation, err)
		}
	})
}

// The unsigned rotating simulation reads the node's answer by the rule the
// signed one does, and a send stops before signing on any failure.
func TestSimulatePreparedRotatingClassifiesTheNodesAnswer(t *testing.T) {
	_, _, client, _, txn := newRotatingFixture(t)
	prepared, err := client.PrepareRotating(context.Background(), txn, nil)
	if err != nil {
		t.Fatal(err)
	}
	submitted := len(prepared.Transactions())
	if submitted < 2 {
		t.Fatalf("the fixture's group has %d transaction(s); a dummy makes the count meaningful", submitted)
	}
	for _, tc := range simulationVerdicts(submitted) {
		t.Run(tc.name, func(t *testing.T) {
			signer, node, client, algodClient, txn := newRotatingFixture(t)
			node.simulate = func(w http.ResponseWriter, _ models.SimulateRequest) { w.Write([]byte(tc.body)) }
			prepared, err := client.PrepareRotating(context.Background(), txn, nil)
			if err != nil {
				t.Fatal(err)
			}
			simulation, err := client.SimulatePreparedRotating(context.Background(), algodClient, prepared)
			if err != nil {
				t.Fatalf("SimulatePreparedRotating() error = %v", err)
			}
			if simulation.Failed != (tc.message != "") || simulation.FailureMessage != tc.message {
				t.Fatalf("Failed = %v, FailureMessage = %q; want %q", simulation.Failed, simulation.FailureMessage, tc.message)
			}
			if tc.message == "" {
				return
			}
			_, err = client.SendPrepared(context.Background(), algodClient, rotatingGroup(txn), nil)
			var preflight *RotatingPreflightError
			if !errors.As(err, &preflight) || preflight.Message != tc.message {
				t.Fatalf("SendPrepared() error = %v, want *RotatingPreflightError with %q", err, tc.message)
			}
			if signer.count("/sign/rotating/sign") != 0 || len(node.submissions()) != 0 {
				t.Fatalf("a failed simulation reached signing or submission")
			}
		})
	}
}

// endsAfter is a context whose Err reports cancellation once ended is set.
// Its Done channel never closes, so requests in flight are not interrupted.
type endsAfter struct {
	context.Context
	ended atomic.Bool
}

func (c *endsAfter) Err() error {
	if c.ended.Load() {
		return context.Canceled
	}
	return nil
}

func TestSignPreparedRotatingAnswerClassification(t *testing.T) {
	t.Run("an unreadable answer is an unknown outcome", func(t *testing.T) {
		signer, _, client, _, txn := newRotatingFixture(t)
		prepared, err := client.PrepareRotating(context.Background(), txn, nil)
		if err != nil {
			t.Fatal(err)
		}
		signer.alterSign = nil
		signer.signErrors = nil
		handler := signer.handle
		truncating, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/sign/rotating/sign" {
				w.Write([]byte(`{"signed": ["ab`))
				return
			}
			handler(w, r)
		})
		defer server.Close()
		_, err = truncating.SignPreparedRotating(context.Background(), prepared, nil)
		var unknown *SignOutcomeUnknownError
		if !errors.As(err, &unknown) || unknown.Rotating != prepared {
			t.Fatalf("error = %v, want *SignOutcomeUnknownError carrying the prepared group", err)
		}
		if want := preparedLastValid(t, prepared); want == 0 || unknown.LastValid != want {
			t.Fatalf("LastValid = %d, want the prepared group's %d", unknown.LastValid, want)
		}
	})
	t.Run("an unauthenticated connection is ErrAuthentication", func(t *testing.T) {
		signer, _, client, _, txn := newRotatingFixture(t)
		signer.errorStatus = http.StatusUnauthorized
		signer.prepareErrors = []*ErrorResponse{rotatingRefusal(ErrCodeUnauthorized, "no")}
		if _, err := client.PrepareRotating(context.Background(), txn, nil); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("error = %v, want ErrAuthentication", err)
		}
	})
}

func TestPrepareHelpersAllUseTheSenderAwareParameters(t *testing.T) {
	// Every Prepare* helper must fetch its parameters through
	// prepSuggestedParams, which fits a rotating sender's window. A direct
	// fetch in prep.go would build a transaction a rotating account can't send.
	source, err := os.ReadFile("prep.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(source), "SuggestedParams().Do(") {
		t.Fatalf("prep.go fetches suggested parameters directly; use prepSuggestedParams")
	}
	if n := strings.Count(string(source), "c.prepSuggestedParams(ctx, algodClient, params.Sender)"); n != 9 {
		t.Fatalf("prep.go has %d sender-aware parameter fetches, want 9", n)
	}
}

func TestPrepSuggestedParamsDoesNotReportSignerFailures(t *testing.T) {
	// A locked or unreachable signer is reported by the helper's key
	// resolution, in its usual form, not by the parameter fetch.
	client, signerServer := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	defer signerServer.Close()
	node := &sendAlgod{t: t}
	algodClient, closeAlgod := makeSimulationAlgodClient(t, node.handle)
	defer closeAlgod()
	params, err := client.prepSuggestedParams(context.Background(), algodClient, fakeAccount(41))
	if err != nil || params.LastRoundValid-params.FirstRoundValid != 1000 {
		t.Fatalf("prepSuggestedParams() = %d rounds, %v", params.LastRoundValid-params.FirstRoundValid, err)
	}
}

func TestResolveAuthAddressReportsTheChainAuthorizer(t *testing.T) {
	sender, holder := fakeAccount(41), fakeAccount(45)
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(StatusResponse{State: "unlocked"})
		case "/keys":
			json.NewEncoder(w).Encode(KeysResponse{Count: 2, Keys: []KeyInfo{{Address: sender}, {Address: holder}}})
		}
	})
	defer server.Close()
	rekeyed, err := client.ResolveAuthAddress(context.Background(), sender, func(context.Context, string) (string, error) { return holder, nil })
	if err != nil || rekeyed.ChainAuthAddress != holder || rekeyed.AuthAddress != holder || !rekeyed.IsRekeyed {
		t.Fatalf("rekeyed = %+v, %v", rekeyed, err)
	}
	own, err := client.ResolveAuthAddress(context.Background(), sender, func(context.Context, string) (string, error) { return "", nil })
	if err != nil || own.ChainAuthAddress != "" || own.AuthAddress != sender || own.IsRekeyed {
		t.Fatalf("self-signing = %+v, %v", own, err)
	}
}

func TestSendPreparedRotatingWidensTheWindowAfterATimingRefusal(t *testing.T) {
	signer, node, client, algodClient, _ := newRotatingFixture(t)
	signer.signErrors = []*ErrorResponse{rotatingRefusal(ErrCodeRotatingWindowNotCurrent, "too few rounds remain")}
	node.round = 40
	// A 12-round window is current, and leaves the operator two rounds.
	result, err := client.SendPrepared(context.Background(), algodClient, rotatingGroup(rotatingPayment(t, signer.account, 40, 52)), &SendOptions{RefreshValidity: true})
	if err != nil || result.Rotating.Attempts != 2 {
		t.Fatalf("SendPrepared() = %+v, %v", result, err)
	}
	first, second := signer.prepareSeen[0], signer.prepareSeen[1]
	if first.LastValid-first.FirstValid != 12 {
		t.Fatalf("a current window was changed before the first attempt: %d-%d", first.FirstValid, first.LastValid)
	}
	if second.LastValid-second.FirstValid != RotatingMaxValidityWindow {
		t.Fatalf("after a timing refusal the window is %d rounds, want the longest", second.LastValid-second.FirstValid)
	}
}

func TestSignPreparedRotatingWithAnEndedContextSendsNothing(t *testing.T) {
	signer, _, client, _, txn := newRotatingFixture(t)
	prepared, err := client.PrepareRotating(context.Background(), txn, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.SignPreparedRotating(ctx, prepared, nil)
	var unknown *SignOutcomeUnknownError
	if !errors.Is(err, context.Canceled) || errors.As(err, &unknown) {
		t.Fatalf("error = %v, want a plain context error", err)
	}
	if signer.count("/sign/rotating/sign") != 0 {
		t.Fatalf("a sign request went out on an ended context")
	}
}

// preparedLastValid is the earliest last valid round of a prepared rotating
// group, read from its bytes.
func preparedLastValid(t *testing.T, prepared *PreparedRotating) uint64 {
	t.Helper()
	var earliest uint64
	for i, h := range prepared.Transactions() {
		raw, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		txn, err := decodeCanonicalTxn(raw)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 || uint64(txn.LastValid) < earliest {
			earliest = uint64(txn.LastValid)
		}
	}
	return earliest
}
