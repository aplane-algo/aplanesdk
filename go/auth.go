// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"fmt"
)

// AccountAuthLookup returns the current auth address for an Algorand account.
// It should return an empty string when the account signs for itself.
type AccountAuthLookup func(ctx context.Context, address string) (string, error)

// ResolvedAuthAddress describes the effective signer for one account.
type ResolvedAuthAddress struct {
	Address string
	// AuthAddress is the account whose key signs: the address itself, the
	// address it is rekeyed to, or, for a rotating account, the account
	// itself at every stage.
	AuthAddress string
	IsRekeyed   bool
	// ChainAuthAddress is the auth address the chain reports, empty when the
	// account signs for itself. For a rotating account that has rotated it
	// is the current stage's address, which the signer does not list as a
	// key; AuthAddress stays the account.
	ChainAuthAddress string
	KeyInfo          KeyInfo
}

// ListKeysIfKeysetChanged returns cached keys when /status reports the same
// keyset_revision as the local cache, otherwise it refreshes /keys.
func (c *SignerClient) ListKeysIfKeysetChanged() ([]KeyInfo, error) {
	return c.ListKeysIfKeysetChangedWithContext(context.Background())
}

// ListKeysIfKeysetChangedWithContext is the context-aware form of
// ListKeysIfKeysetChanged.
func (c *SignerClient) ListKeysIfKeysetChangedWithContext(ctx context.Context) ([]KeyInfo, error) {
	status, err := c.GetStatusWithContext(ctx)
	if err != nil {
		return nil, err
	}
	if status.SignerLocked {
		return nil, ErrSignerLocked
	}

	if keys, ok := c.cachedKeysForRevision(status.KeysetRevision); ok {
		return keys, nil
	}

	keysResp, err := c.GetKeysResponseWithContext(ctx)
	if err != nil {
		if err == ErrSignerLocked || err == ErrAuthentication {
			return nil, err
		}
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	if keysResp.Locked {
		return nil, ErrSignerLocked
	}
	c.cacheKeysRevision(status.KeysetRevision)
	return keysResp.Keys, nil
}

// ResolveAuthAddress resolves sender -> effective signer and verifies that
// the signer owns a spendable key for that effective signer.
func (c *SignerClient) ResolveAuthAddress(ctx context.Context, address string, lookup AccountAuthLookup) (*ResolvedAuthAddress, error) {
	if lookup == nil {
		return nil, fmt.Errorf("account auth lookup is required")
	}

	authAddr, err := lookup(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("failed to query account info: %w", err)
	}

	keys, err := c.ListKeysIfKeysetChangedWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return resolveAuthAddressWithKeys(address, authAddr, keys)
}

// resolveAuthAddressWithKeys is ResolveAuthAddress for an address whose
// on-chain auth address (empty when it is not rekeyed) and the signer's key
// list have already been read.
func resolveAuthAddressWithKeys(address, authAddr string, keys []KeyInfo) (*ResolvedAuthAddress, error) {
	signingAddr := address
	if authAddr != "" && authAddr != address {
		signingAddr = authAddr
	}

	// A rotating account is authorized by its current stage, which the
	// signer derives from the account's key and never lists. The signer holds
	// the account itself and signs for it at any stage.
	// One exception: a rotating account rekeyed to an ordinary key the signer
	// holds has left rotation, and that key signs for it like any rekey.
	own, isOwn := findSpendableKey(keys, address)
	_, authHeld := findSpendableKey(keys, signingAddr)
	leftRotation := signingAddr != address && authHeld
	if isOwn && own.SigningFlow == SigningFlowRotating1 && !leftRotation {
		chainAuth := ""
		if authAddr != address {
			chainAuth = authAddr
		}
		return &ResolvedAuthAddress{Address: address, AuthAddress: address, ChainAuthAddress: chainAuth, KeyInfo: own}, nil
	}

	key, ok := findSpendableKey(keys, signingAddr)
	if !ok {
		if signingAddr == address {
			return nil, fmt.Errorf("%w: %s is not available for signing", ErrKeyNotFound, address)
		}
		return nil, fmt.Errorf("%w: account is rekeyed to %s but that address is not signable", ErrKeyNotFound, authAddr)
	}

	chainAuth := ""
	if signingAddr != address {
		chainAuth = signingAddr
	}
	return &ResolvedAuthAddress{
		Address:          address,
		AuthAddress:      signingAddr,
		IsRekeyed:        signingAddr != address,
		ChainAuthAddress: chainAuth,
		KeyInfo:          key,
	}, nil
}

// isSpendableKey reports whether a key record is one that signs for its
// address. A witness or cosigner record is listed with is_spending_account
// false and does not.
func isSpendableKey(key KeyInfo) bool {
	return key.IsSpendingAccount == nil || *key.IsSpendingAccount
}

func findSpendableKey(keys []KeyInfo, address string) (KeyInfo, bool) {
	for _, key := range keys {
		if key.Address == address && isSpendableKey(key) {
			return key, true
		}
	}
	return KeyInfo{}, false
}
