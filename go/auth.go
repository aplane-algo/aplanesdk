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
	Address     string
	AuthAddress string
	IsRekeyed   bool
	KeyInfo     KeyInfo
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

	signingAddr := address
	if authAddr != "" && authAddr != address {
		signingAddr = authAddr
	}

	keys, err := c.ListKeysIfKeysetChangedWithContext(ctx)
	if err != nil {
		return nil, err
	}

	key, ok := findSpendableKey(keys, signingAddr)
	if !ok {
		if signingAddr == address {
			return nil, fmt.Errorf("%w: %s is not available for signing", ErrKeyNotFound, address)
		}
		return nil, fmt.Errorf("%w: account is rekeyed to %s but that address is not signable", ErrKeyNotFound, authAddr)
	}

	return &ResolvedAuthAddress{
		Address:     address,
		AuthAddress: signingAddr,
		IsRekeyed:   signingAddr != address,
		KeyInfo:     key,
	}, nil
}

func findSpendableKey(keys []KeyInfo, address string) (KeyInfo, bool) {
	for _, key := range keys {
		if key.Address != address {
			continue
		}
		if key.IsSpendingAccount != nil && !*key.IsSpendingAccount {
			continue
		}
		return key, true
	}
	return KeyInfo{}, false
}
