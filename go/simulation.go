// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SimulationResult contains the executable signed group released through the
// ordinary signing flow and the response returned by the caller's algod.
type SimulationResult struct {
	TxIDs        []string
	Transactions []string
	SignedGroup  []string
	Mutations    *MutationReport
	Response     *models.SimulateResponse
	Failed       bool
}

// GuardedSimulationResult contains both the complete guarded signing result
// and the client-side algod simulation result.
type GuardedSimulationResult struct {
	Signing    *GuardedSignResult
	Simulation *SimulationResult
}

// SimulateGroup obtains ordinary executable signatures and sends the exact
// signed group to the caller-provided algod simulation endpoint.
func (c *SignerClient) SimulateGroup(
	algodClient *algod.Client,
	txns []types.Transaction,
	authAddresses []string,
	lsigArgsMap LsigArgsMap,
	opts *SignOptions,
) (*SimulationResult, error) {
	return c.SimulateGroupWithContext(context.Background(), algodClient, txns, authAddresses, lsigArgsMap, opts)
}

// SimulateGroupWithContext is the context-aware form of SimulateGroup.
func (c *SignerClient) SimulateGroupWithContext(
	ctx context.Context,
	algodClient *algod.Client,
	txns []types.Transaction,
	authAddresses []string,
	lsigArgsMap LsigArgsMap,
	opts *SignOptions,
) (*SimulationResult, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	requests, err := buildSignRequestsWithOptions(txns, authAddresses, lsigArgsMap, opts)
	if err != nil {
		return nil, err
	}
	return c.simulateRequestsWithContext(ctx, algodClient, requests)
}

// SimulatePreparedTransaction signs and simulates one prepared transaction.
func (c *SignerClient) SimulatePreparedTransaction(
	ctx context.Context,
	algodClient *algod.Client,
	prepared PreparedTransaction,
) (*SimulationResult, error) {
	return c.SimulatePreparedGroup(ctx, algodClient, NewPreparedGroup(prepared))
}

// SimulatePreparedGroup signs a prepared group through the ordinary signer
// path, then simulates the exact released group through the caller's algod.
func (c *SignerClient) SimulatePreparedGroup(
	ctx context.Context,
	algodClient *algod.Client,
	group PreparedGroup,
) (*SimulationResult, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	requests, err := group.SignRequests()
	if err != nil {
		return nil, err
	}
	return c.simulateRequestsWithContext(ctx, algodClient, requests)
}

func (c *SignerClient) simulateRequestsWithContext(
	ctx context.Context,
	algodClient *algod.Client,
	requests []SignRequest,
) (*SimulationResult, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	response, err := c.SignRequestsWithContext(ctx, requests)
	if err != nil {
		return nil, err
	}
	if response.Mutations != nil && response.Mutations.ForeignCount > 0 {
		return nil, fmt.Errorf("signed simulation requires a complete group; signer returned %d foreign transaction(s)", response.Mutations.ForeignCount)
	}
	return simulateSignedGroupWithContext(ctx, algodClient, response.Signed, response.Mutations)
}

// SimulateGuardedGroup performs the complete guarded signing and approval flow
// before routing the assembled executable group to the caller's algod.
func SimulateGuardedGroup(algodClient *algod.Client, opts GuardedSignOptions) (*GuardedSimulationResult, error) {
	return SimulateGuardedGroupWithContext(context.Background(), algodClient, opts)
}

// SimulateGuardedGroupWithContext is the context-aware form of
// SimulateGuardedGroup.
func SimulateGuardedGroupWithContext(
	ctx context.Context,
	algodClient *algod.Client,
	opts GuardedSignOptions,
) (*GuardedSimulationResult, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	signing, err := SignGuardedGroupWithContext(ctx, opts)
	if err != nil {
		return nil, err
	}
	simulation, err := simulateSignedGroupWithContext(ctx, algodClient, signing.SignedGroup, nil)
	if err != nil {
		return nil, err
	}
	return &GuardedSimulationResult{Signing: signing, Simulation: simulation}, nil
}

// SimulatePreparedGuardedGroup signs and simulates a prepared guarded group.
func SimulatePreparedGuardedGroup(
	algodClient *algod.Client,
	opts PreparedGuardedGroupOptions,
) (*GuardedSimulationResult, error) {
	return SimulatePreparedGuardedGroupWithContext(context.Background(), algodClient, opts)
}

// SimulatePreparedGuardedGroupWithContext is the context-aware form of
// SimulatePreparedGuardedGroup.
func SimulatePreparedGuardedGroupWithContext(
	ctx context.Context,
	algodClient *algod.Client,
	opts PreparedGuardedGroupOptions,
) (*GuardedSimulationResult, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	signing, err := SignPreparedGuardedGroupWithContext(ctx, opts)
	if err != nil {
		return nil, err
	}
	simulation, err := simulateSignedGroupWithContext(ctx, algodClient, signing.SignedGroup, nil)
	if err != nil {
		return nil, err
	}
	return &GuardedSimulationResult{Signing: signing, Simulation: simulation}, nil
}

func simulateSignedGroupWithContext(
	ctx context.Context,
	algodClient *algod.Client,
	signedGroup []string,
	mutations *MutationReport,
) (*SimulationResult, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	decoded, txIDs, transactions, err := decodeExecutableSignedGroup(signedGroup)
	if err != nil {
		return nil, err
	}

	request := models.SimulateRequest{
		TxnGroups:            []models.SimulateRequestTransactionGroup{{Txns: decoded}},
		AllowEmptySignatures: false,
		FixSigners:           false,
		AllowMoreLogging:     true,
		ExecTraceConfig: models.SimulateTraceConfig{
			Enable:      true,
			StateChange: true,
		},
	}
	response, err := algodClient.SimulateTransaction(request).Do(ctx)
	if err != nil {
		request.ExecTraceConfig = models.SimulateTraceConfig{}
		request.AllowMoreLogging = false
		response, err = algodClient.SimulateTransaction(request).Do(ctx)
		if err != nil {
			return nil, fmt.Errorf("simulation API call failed: %w", err)
		}
	}

	failed := len(response.TxnGroups) > 0 && response.TxnGroups[0].FailureMessage != ""
	return &SimulationResult{
		TxIDs:        txIDs,
		Transactions: transactions,
		SignedGroup:  append([]string(nil), signedGroup...),
		Mutations:    mutations,
		Response:     &response,
		Failed:       failed,
	}, nil
}

func decodeExecutableSignedGroup(signedGroup []string) ([]types.SignedTxn, []string, []string, error) {
	if len(signedGroup) == 0 {
		return nil, nil, nil, fmt.Errorf("signed group is empty")
	}
	decoded := make([]types.SignedTxn, len(signedGroup))
	txIDs := make([]string, len(signedGroup))
	transactions := make([]string, len(signedGroup))
	for i, signedHex := range signedGroup {
		if signedHex == "" {
			return nil, nil, nil, fmt.Errorf("signed group position %d is empty", i+1)
		}
		raw, err := hex.DecodeString(signedHex)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("signed group position %d is invalid hex: %w", i+1, err)
		}
		if err := msgpack.Decode(raw, &decoded[i]); err != nil {
			return nil, nil, nil, fmt.Errorf("signed group position %d is invalid msgpack: %w", i+1, err)
		}
		txIDs[i] = crypto.GetTxID(decoded[i].Txn)
		transactions[i] = hex.EncodeToString(encodeTxn(decoded[i].Txn))
	}
	return decoded, txIDs, transactions, nil
}
