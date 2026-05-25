// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/base64"
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

// hexArrayToBase64 concatenates hex strings and returns base64.
func hexArrayToBase64(hexStrings []string) (string, error) {
	var combined []byte
	for _, h := range hexStrings {
		decoded, err := hex.DecodeString(h)
		if err != nil {
			return "", err
		}
		combined = append(combined, decoded...)
	}
	return base64.StdEncoding.EncodeToString(combined), nil
}

// AssembleGroup merges multiple signers' outputs into a single signed group.
// Each input is a []string from SignTransactionsListWithOptions, where empty
// strings represent slots that signer didn't sign. Exactly one signer must
// provide a non-empty value for each slot.
// Returns concatenated base64-encoded signed transactions.
func AssembleGroup(signedLists [][]string) (string, error) {
	if len(signedLists) == 0 {
		return "", fmt.Errorf("signedLists must not be empty")
	}

	groupLen := len(signedLists[0])
	for i, sl := range signedLists {
		if len(sl) != groupLen {
			return "", fmt.Errorf("signedLists[%d] has %d entries, expected %d", i, len(sl), groupLen)
		}
	}

	var combined []byte
	for idx := 0; idx < groupLen; idx++ {
		var found string
		for _, sl := range signedLists {
			if sl[idx] != "" {
				if found != "" {
					return "", fmt.Errorf("slot %d: multiple signers provided a signed transaction", idx)
				}
				found = sl[idx]
			}
		}
		if found == "" {
			return "", fmt.Errorf("slot %d: no signer provided a signed transaction", idx)
		}
		decoded, err := base64.StdEncoding.DecodeString(found)
		if err != nil {
			return "", fmt.Errorf("slot %d: invalid base64: %w", idx, err)
		}
		combined = append(combined, decoded...)
	}

	return base64.StdEncoding.EncodeToString(combined), nil
}

// HexToBytes converts a hex string to bytes.
func HexToBytes(h string) ([]byte, error) {
	return hex.DecodeString(h)
}

// BytesToHex converts bytes to hex string.
func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// Base64ToBytes converts a base64 string to bytes.
func Base64ToBytes(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// BytesToBase64 converts bytes to base64 string.
func BytesToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
