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
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SimulationResult contains the executable signed group released through the
// ordinary signing flow and the response returned by the caller's algod.
//
// Failed is true unless the node returned exactly one group result, that
// result reports no failure (no failure-message and no failed-at), and it
// holds one transaction result per transaction simulated: any other answer
// checked less than the group. FailureMessage says why, and is empty when
// Failed is false: the node's own failure-message, or which of those it was.
type SimulationResult struct {
	TxIDs          []string
	Transactions   []string
	SignedGroup    []string
	Mutations      *MutationReport
	Response       *models.SimulateResponse
	Failed         bool
	FailureMessage string
}

// CosignedSimulationResult contains both the complete cosigned signing result
// and the client-side algod simulation result.
type CosignedSimulationResult struct {
	Signing    *CosignedSignResult
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

// SimulatePreparedCosignedGroup signs and simulates a prepared cosigned group.
func SimulatePreparedCosignedGroup(
	algodClient *algod.Client,
	opts PreparedCosignedGroupOptions,
) (*CosignedSimulationResult, error) {
	return SimulatePreparedCosignedGroupWithContext(context.Background(), algodClient, opts)
}

// SimulatePreparedCosignedGroupWithContext is the context-aware form of
// SimulatePreparedCosignedGroup.
func SimulatePreparedCosignedGroupWithContext(
	ctx context.Context,
	algodClient *algod.Client,
	opts PreparedCosignedGroupOptions,
) (*CosignedSimulationResult, error) {
	if algodClient == nil {
		return nil, fmt.Errorf("algod client is required")
	}
	signing, err := SignPreparedCosignedGroupWithContext(ctx, opts)
	if err != nil {
		return nil, err
	}
	simulation, err := simulateSignedGroupWithContext(ctx, algodClient, signing.SignedGroup, nil)
	if err != nil {
		return nil, err
	}
	return &CosignedSimulationResult{Signing: signing, Simulation: simulation}, nil
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

	response, err := runSimulation(ctx, algodClient, decoded, false)
	if err != nil {
		return nil, err
	}

	failure := simulationFailure(response, len(decoded))
	return &SimulationResult{
		TxIDs:          txIDs,
		Transactions:   transactions,
		SignedGroup:    append([]string(nil), signedGroup...),
		Mutations:      mutations,
		Response:       response,
		Failed:         failure != "",
		FailureMessage: failure,
	}, nil
}

// simulationFailure says why a simulation of one group of submitted
// transactions did anything but pass, or is empty when it passed. It passes
// only when the node returned exactly one group result, with no failure
// message and no failed-at, holding one transaction result per transaction
// submitted: anything else checked less than the group, so it is a failure.
// The reason is the node's own failure message, or which of those it was.
//
// The node's answer is decoded before it is seen here, and the decoder reads
// a null group result as an empty one, so a result that is not an object
// fails on its count of transaction results.
func simulationFailure(response *models.SimulateResponse, submitted int) string {
	if response == nil || len(response.TxnGroups) == 0 {
		return "the node returned no result for the group"
	}
	if len(response.TxnGroups) != 1 {
		return fmt.Sprintf("the node returned %d results for one group", len(response.TxnGroups))
	}
	group := response.TxnGroups[0]
	if group.FailureMessage != "" {
		return group.FailureMessage
	}
	if len(group.FailedAt) > 0 {
		return "the node reported a failure without a message"
	}
	if len(group.TxnResults) != submitted {
		return fmt.Sprintf("the node returned %d transaction results for %d transactions", len(group.TxnResults), submitted)
	}
	return ""
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
		// The raw hex is what gets submitted and the decoded value is what
		// gets simulated, so the two must be the same transaction exactly.
		decoded[i], err = decodeCanonicalSignedTxn(raw)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("signed group position %d: %w", i+1, err)
		}
		txIDs[i] = crypto.GetTxID(decoded[i].Txn)
		transactions[i] = hex.EncodeToString(encodeTxn(decoded[i].Txn))
	}
	return decoded, txIDs, transactions, nil
}

// runSimulation sends one group to the node's simulate endpoint, with
// execution traces when the node allows them. allowEmptySignatures simulates
// an unsigned group; signed simulation leaves it off so the node checks every
// signature.
func runSimulation(ctx context.Context, algodClient *algod.Client, group []types.SignedTxn, allowEmptySignatures bool) (*models.SimulateResponse, error) {
	request := models.SimulateRequest{
		TxnGroups:            []models.SimulateRequestTransactionGroup{{Txns: group}},
		AllowEmptySignatures: allowEmptySignatures,
		// An unsigned transaction names no signer. FixSigners has the node
		// take each sender's authorizer from the chain, which a rekeyed
		// sender, such as a rotating account after its first spend, needs.
		FixSigners:       allowEmptySignatures,
		AllowMoreLogging: true,
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
	return &response, nil
}
