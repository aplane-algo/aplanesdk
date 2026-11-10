// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// requestSlot is one decoded /sign or /plan request entry: its mode, the
// transaction it carries, and for passthrough the signed bytes as sent.
type requestSlot struct {
	mode        RequestMode
	txn         types.Transaction
	signedBytes []byte
}

// decodeCanonicalTxn decodes TX-prefixed unsigned transaction bytes and
// requires them to be the canonical encoding of the decoded transaction.
func decodeCanonicalTxn(raw []byte) (types.Transaction, error) {
	var txn types.Transaction
	if len(raw) < 3 || raw[0] != 'T' || raw[1] != 'X' {
		return txn, fmt.Errorf("missing TX prefix")
	}
	if err := msgpack.Decode(raw[2:], &txn); err != nil {
		return txn, fmt.Errorf("invalid msgpack: %w", err)
	}
	if !bytes.Equal(raw, encodeTxn(txn)) {
		return txn, fmt.Errorf("bytes are not canonical")
	}
	return txn, nil
}

// decodeCanonicalSignedTxn decodes signed transaction bytes and requires them
// to be the canonical encoding of the decoded value. msgpack.Decode alone
// stops at the end of the first object, so trailing bytes and non-canonical
// wrappers would otherwise pass unnoticed.
func decodeCanonicalSignedTxn(raw []byte) (types.SignedTxn, error) {
	var stxn types.SignedTxn
	if len(raw) == 0 {
		return stxn, fmt.Errorf("empty signed transaction")
	}
	if err := msgpack.Decode(raw, &stxn); err != nil {
		return stxn, fmt.Errorf("invalid msgpack: %w", err)
	}
	if !bytes.Equal(raw, msgpack.Encode(stxn)) {
		return stxn, fmt.Errorf("bytes are not a canonical signed transaction")
	}
	return stxn, nil
}

// decodeRequestSlots decodes every request entry. It runs before a request is
// sent, so malformed transaction bytes never reach the signer.
func decodeRequestSlots(requests []SignRequest) ([]requestSlot, error) {
	slots := make([]requestSlot, len(requests))
	for i, req := range requests {
		mode, err := req.Mode()
		if err != nil {
			return nil, fmt.Errorf("transaction %d: %w", i+1, err)
		}
		slots[i].mode = mode
		if mode == RequestModePassthrough {
			raw, err := hex.DecodeString(req.SignedTxnHex)
			if err != nil {
				return nil, fmt.Errorf("transaction %d: signed_txn_hex is invalid hex: %w", i+1, err)
			}
			stxn, err := decodeCanonicalSignedTxn(raw)
			if err != nil {
				return nil, fmt.Errorf("transaction %d: passthrough transaction: %w", i+1, err)
			}
			slots[i].txn = stxn.Txn
			slots[i].signedBytes = raw
			continue
		}
		raw, err := hex.DecodeString(req.TxnBytesHex)
		if err != nil {
			return nil, fmt.Errorf("transaction %d: txn_bytes_hex is invalid hex: %w", i+1, err)
		}
		txn, err := decodeCanonicalTxn(raw)
		if err != nil {
			return nil, fmt.Errorf("transaction %d: txn_bytes_hex: %w", i+1, err)
		}
		slots[i].txn = txn
	}
	return slots, nil
}

// validateGroupMutations is the client-side authority boundary for a /sign or
// /plan result. The signer may raise the fees it reports on positions it
// signs, assign a canonical group ID, and append reported canonical resource
// dummies. It may not alter any other transaction field.
//
// returned holds the transaction observed at each final position. A nil entry
// is a foreign position /sign returned empty: nothing was observed, and the
// position is taken as the request's transaction in the final group.
func validateGroupMutations(slots []requestSlot, returned []*types.Transaction, mutations *MutationReport) error {
	if len(returned) < len(slots) {
		return fmt.Errorf("signer returned %d transaction(s), want at least %d", len(returned), len(slots))
	}
	if len(returned) > types.MaxTxGroupSize {
		return fmt.Errorf("signer returned %d transaction(s), more than the maximum group size %d", len(returned), types.MaxTxGroupSize)
	}
	appended := len(returned) - len(slots)
	passthroughCount, foreignCount := 0, 0
	for _, slot := range slots {
		switch slot.mode {
		case RequestModePassthrough:
			passthroughCount++
		case RequestModeForeign:
			foreignCount++
		}
	}

	report := MutationReport{}
	if mutations == nil {
		if appended != 0 {
			return fmt.Errorf("signer appended %d transaction(s) without a mutation report", appended)
		}
	} else {
		report = *mutations
		if report.OriginalCount != len(slots) {
			return fmt.Errorf("mutation original_count %d does not match request count %d", report.OriginalCount, len(slots))
		}
		if report.FinalCount != len(returned) {
			return fmt.Errorf("mutation final_count %d does not match returned count %d", report.FinalCount, len(returned))
		}
		if report.DummiesAdded != appended {
			return fmt.Errorf("mutation dummies_added %d does not match appended count %d", report.DummiesAdded, appended)
		}
		if report.TotalFeesDelta < 0 {
			return fmt.Errorf("mutation total_fees_delta must not be negative")
		}
		if appended > 0 && !report.GroupIDChanged {
			return fmt.Errorf("mutation appended dummies without reporting a group ID change")
		}
		if len(returned) == 1 && report.GroupIDChanged {
			return fmt.Errorf("mutation reported a group ID change for a single transaction")
		}
	}
	if report.PassthroughCount != passthroughCount {
		return fmt.Errorf("mutation passthrough_count %d does not match the %d passthrough transaction(s) requested", report.PassthroughCount, passthroughCount)
	}
	if report.ForeignCount != foreignCount {
		return fmt.Errorf("mutation foreign_count %d does not match the %d foreign transaction(s) requested", report.ForeignCount, foreignCount)
	}

	feeModified := make(map[int]struct{}, len(report.FeesModified))
	for _, index := range report.FeesModified {
		if index < 0 || index >= len(slots) {
			return fmt.Errorf("mutation fee index %d is outside original positions", index)
		}
		if _, duplicate := feeModified[index]; duplicate {
			return fmt.Errorf("mutation fee index %d is duplicated", index)
		}
		if slots[index].mode != RequestModeSign {
			return fmt.Errorf("mutation fee index %d is a %s position, whose fee the signer cannot change", index, slots[index].mode)
		}
		feeModified[index] = struct{}{}
	}

	var assigned types.Digest
	if report.GroupIDChanged {
		observed := false
		for _, txn := range returned {
			if txn != nil {
				assigned = txn.Group
				observed = true
				break
			}
		}
		if !observed {
			return fmt.Errorf("signer reported a group ID change but returned no transaction that carries it")
		}
	}

	final := make([]types.Transaction, len(returned))
	var totalFeeDelta uint64
	for i, slot := range slots {
		want := slot.txn
		if report.GroupIDChanged {
			want.Group = assigned
		}
		if returned[i] == nil {
			final[i] = want
			continue
		}
		got := *returned[i]
		if _, ok := feeModified[i]; ok {
			if got.Fee <= want.Fee {
				return fmt.Errorf("reported fee mutation at original position %d did not increase the fee", i+1)
			}
			delta := uint64(got.Fee - want.Fee)
			if ^uint64(0)-totalFeeDelta < delta {
				return fmt.Errorf("observed fee delta overflows uint64")
			}
			totalFeeDelta += delta
			want.Fee = got.Fee
		}
		if !bytes.Equal(encodeTxn(want), encodeTxn(got)) {
			return fmt.Errorf("signer changed unreported fields at original position %d", i+1)
		}
		final[i] = got
	}
	if uint64(report.TotalFeesDelta) != totalFeeDelta {
		return fmt.Errorf("mutation total_fees_delta %d does not match observed delta %d", report.TotalFeesDelta, totalFeeDelta)
	}
	for i := len(slots); i < len(returned); i++ {
		if returned[i] == nil {
			return fmt.Errorf("signer returned no transaction at appended position %d", i+1)
		}
		final[i] = *returned[i]
	}

	groupID, err := validateCanonicalGroupID(final)
	if err != nil {
		return err
	}
	if appended == 0 {
		return nil
	}
	return validateCanonicalDummies(slots[0].txn, groupID, final[len(slots):])
}

// validateCanonicalGroupID checks that every transaction of a
// multi-transaction group carries the group ID computed over the group
// itself, and returns it. A single transaction needs no group ID.
func validateCanonicalGroupID(txns []types.Transaction) (types.Digest, error) {
	if len(txns) < 2 {
		return types.Digest{}, nil
	}
	ungrouped := append([]types.Transaction(nil), txns...)
	for i := range ungrouped {
		ungrouped[i].Group = types.Digest{}
	}
	want, err := crypto.ComputeGroupID(ungrouped)
	if err != nil {
		return types.Digest{}, fmt.Errorf("compute canonical returned group ID: %w", err)
	}
	for i := range txns {
		if txns[i].Group != want {
			return types.Digest{}, fmt.Errorf("returned transaction %d does not carry the canonical group ID", i+1)
		}
	}
	return want, nil
}

// canonicalDummyTxn rebuilds the index'th resource dummy the signer's planner
// appends to a group: a zero-fee, zero-amount self-payment from the dummy
// address with the index as its one-byte note, on the first original
// transaction's validity window and genesis, in the group.
func canonicalDummyTxn(firstOriginal types.Transaction, groupID types.Digest, index int) (types.Transaction, error) {
	dummyAcct := crypto.LogicSigAccount{Lsig: types.LogicSig{Logic: cosignedDummyProgram}}
	dummyAddr, err := dummyAcct.Address()
	if err != nil {
		return types.Transaction{}, fmt.Errorf("failed to compute dummy address: %w", err)
	}
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      dummyAddr,
			FirstValid:  firstOriginal.FirstValid,
			LastValid:   firstOriginal.LastValid,
			Note:        []byte{byte(index)},
			GenesisID:   firstOriginal.GenesisID,
			GenesisHash: firstOriginal.GenesisHash,
			Group:       groupID,
		},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: dummyAddr},
	}, nil
}

// validateCanonicalDummies requires every appended transaction to be exactly
// the canonical resource dummy for its position.
func validateCanonicalDummies(firstOriginal types.Transaction, groupID types.Digest, appended []types.Transaction) error {
	for i := range appended {
		want, err := canonicalDummyTxn(firstOriginal, groupID, i)
		if err != nil {
			return err
		}
		if !bytes.Equal(encodeTxn(want), encodeTxn(appended[i])) {
			return fmt.Errorf("appended transaction %d is not the canonical resource dummy", i+1)
		}
	}
	return nil
}

// signCanonicalDummy returns the signed bytes of a resource dummy: the dummy
// LogicSig with no arguments, which is its only valid authorization.
func signCanonicalDummy(txn types.Transaction) ([]byte, error) {
	_, signedBytes, err := crypto.SignLogicSigTransaction(types.LogicSig{Logic: cosignedDummyProgram}, txn)
	if err != nil {
		return nil, err
	}
	return signedBytes, nil
}

// validateSignResponse checks a /sign response against the request before any
// caller can submit or simulate it. Sign positions must carry the requested
// transaction, changed only as the mutation report states. Passthrough
// positions must come back byte for byte, foreign positions stay empty, and
// every appended position must be the canonical signed resource dummy.
func validateSignResponse(slots []requestSlot, signed []string, mutations *MutationReport) error {
	if len(signed) < len(slots) {
		return fmt.Errorf("signer returned %d signed transaction(s), want at least %d", len(signed), len(slots))
	}
	returned := make([]*types.Transaction, len(signed))
	signedBytes := make([][]byte, len(signed))
	for i, signedHex := range signed {
		if i < len(slots) && slots[i].mode == RequestModeForeign {
			if signedHex != "" {
				return fmt.Errorf("signer returned a signed transaction for foreign position %d", i+1)
			}
			continue
		}
		if signedHex == "" {
			if i >= len(slots) {
				return fmt.Errorf("signer returned empty dummy transaction at position %d", i+1)
			}
			return fmt.Errorf("signer returned no signature for position %d", i+1)
		}
		raw, err := hex.DecodeString(signedHex)
		if err != nil {
			return fmt.Errorf("signed transaction %d is invalid hex: %w", i+1, err)
		}
		signedBytes[i] = raw
		if i < len(slots) && slots[i].mode == RequestModePassthrough {
			if !bytes.Equal(raw, slots[i].signedBytes) {
				return fmt.Errorf("signer changed passthrough transaction %d", i+1)
			}
			txn := slots[i].txn
			returned[i] = &txn
			continue
		}
		stxn, err := decodeCanonicalSignedTxn(raw)
		if err != nil {
			return fmt.Errorf("signed transaction %d: %w", i+1, err)
		}
		returned[i] = &stxn.Txn
	}
	if err := validateGroupMutations(slots, returned, mutations); err != nil {
		return err
	}
	for i := len(slots); i < len(signed); i++ {
		want, err := signCanonicalDummy(*returned[i])
		if err != nil {
			return fmt.Errorf("recreate canonical resource dummy signature %d: %w", i-len(slots)+1, err)
		}
		if !bytes.Equal(want, signedBytes[i]) {
			return fmt.Errorf("appended transaction %d does not carry the canonical resource dummy authorization", i-len(slots)+1)
		}
	}
	return nil
}

// validatePlanResponse checks a /plan response against the request. A plan
// result is the final group as unsigned transactions, so every position is
// observed, foreign ones included.
func validatePlanResponse(slots []requestSlot, transactions []string, mutations *MutationReport) error {
	if len(transactions) < len(slots) {
		return fmt.Errorf("signer returned %d planned transaction(s), want at least %d", len(transactions), len(slots))
	}
	returned := make([]*types.Transaction, len(transactions))
	for i, txnHex := range transactions {
		raw, err := hex.DecodeString(txnHex)
		if err != nil {
			return fmt.Errorf("planned transaction %d is invalid hex: %w", i+1, err)
		}
		txn, err := decodeCanonicalTxn(raw)
		if err != nil {
			return fmt.Errorf("planned transaction %d: %w", i+1, err)
		}
		returned[i] = &txn
	}
	return validateGroupMutations(slots, returned, mutations)
}
