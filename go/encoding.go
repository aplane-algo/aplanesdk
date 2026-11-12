// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// encodeTxn encodes a transaction to msgpack bytes with "TX" prefix.
func encodeTxn(txn types.Transaction) []byte {
	// Encode to msgpack
	encoded := msgpack.Encode(txn)

	// Prepend "TX" prefix (what gets signed)
	result := make([]byte, len(encoded)+2)
	result[0] = 'T'
	result[1] = 'X'
	copy(result[2:], encoded)

	return result
}

// signedGroupFromHex decodes the signer's hex entries into raw bytes, one per
// transaction, in order. An empty entry stays empty.
func signedGroupFromHex(signed []string) ([][]byte, error) {
	group := make([][]byte, len(signed))
	for i, entry := range signed {
		raw, err := hex.DecodeString(entry)
		if err != nil {
			return nil, fmt.Errorf("signed transaction %d is invalid hex: %w", i+1, err)
		}
		group[i] = raw
	}
	return group, nil
}

// cloneSignedGroup copies every entry, so the copy shares no bytes with
// group.
func cloneSignedGroup(group [][]byte) [][]byte {
	if group == nil {
		return nil
	}
	cloned := make([][]byte, len(group))
	for i, entry := range group {
		cloned[i] = append([]byte(nil), entry...)
	}
	return cloned
}

// HexToBytes converts a hex string to bytes.
func HexToBytes(h string) ([]byte, error) {
	return hex.DecodeString(h)
}

// BytesToHex converts bytes to hex string.
func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}
