// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// RequestBoundedComponent sends a bounded base-component request to the user
// signer.
func (c *SignerClient) RequestBoundedComponent(req BoundedComponentRequest) (*BoundedComponentResponse, error) {
	return c.RequestBoundedComponentWithContext(context.Background(), req)
}

// RequestBoundedComponentWithContext sends a bounded base-component request
// to the user signer. This endpoint can wait on operator approval.
func (c *SignerClient) RequestBoundedComponentWithContext(ctx context.Context, reqBody BoundedComponentRequest) (*BoundedComponentResponse, error) {
	if err := reqBody.Validate(); err != nil {
		return nil, fmt.Errorf("invalid bounded component request: %w", err)
	}
	response, err := c.RequestComponentsWithContext(ctx, reqBody.ComponentRequest())
	if err != nil {
		return nil, err
	}
	result := &BoundedComponentResponse{RequestID: response.RequestID, Transactions: append([]string(nil), reqBody.GroupBytesHex...)}
	for _, component := range response.Components {
		result.Components = append(result.Components, BoundedBaseComponent{
			TargetIndex: component.TargetIndex, BoundedAccount: component.AuthAddress,
			BaseSignatures: component.BaseSignatures, RuntimeArgs: component.RuntimeArgs,
			AssemblyReceipt: component.AssemblyReceipt, SignatureScheme: component.SignatureScheme,
		})
	}
	return result, nil
}

func (c *SignerClient) RequestComponents(req ComponentRequest) (*ComponentResponse, error) {
	return c.RequestComponentsWithContext(context.Background(), req)
}

func (c *SignerClient) RequestComponentsWithContext(ctx context.Context, reqBody ComponentRequest) (*ComponentResponse, error) {
	if reqBody.RequestID == "" {
		requestID, err := newSignRequestID()
		if err != nil {
			return nil, fmt.Errorf("failed to create component request ID: %w", err)
		}
		reqBody.RequestID = requestID
	}
	if err := reqBody.Validate(); err != nil {
		return nil, fmt.Errorf("invalid component request: %w", err)
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal component request: %w", err)
	}
	timeout := componentSignTimeout
	approvalBearing := reqBody.TargetKind() != ComponentTargetKindSentry
	if approvalBearing {
		c.discoverApprovalWait(ctx)
		timeout = c.signRequestTimeout()
	}
	reqCtx, cancel := c.requestContext(ctx, timeout)
	defer cancel()

	var cancelOnce sync.Once
	sendCancel := func() {
		if !approvalBearing {
			return
		}
		cancelOnce.Do(func() {
			cancelCtx, cancel := context.WithTimeout(context.Background(), signCancelTimeout)
			defer cancel()
			_, _ = c.CancelSignRequestWithContext(cancelCtx, reqBody.RequestID)
		})
	}
	done := make(chan struct{})
	if approvalBearing {
		go func() {
			select {
			case <-done:
				return
			case <-reqCtx.Done():
			}
			select {
			case <-done:
			default:
				sendCancel()
			}
		}()
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.baseURL+"/sign/component", bytes.NewReader(body))
	if err != nil {
		close(done)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+c.token)
	resp, err := c.client.Do(req)
	close(done)
	if err != nil {
		if reqCtx.Err() != nil {
			sendCancel()
		}
		return nil, fmt.Errorf("failed to make request to Signer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrAuthentication
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, rejectedForbiddenError(resp)
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, ErrSignerUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		return nil, signerHTTPError(resp)
	}
	var result ComponentResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode component response: %w", err)
	}
	if err := result.Validate(); err != nil {
		return nil, fmt.Errorf("invalid component response: %w", err)
	}
	if result.RequestID != reqBody.RequestID {
		return nil, fmt.Errorf("component response request_id does not match request")
	}
	return &result, nil
}

// RequestBoundedAssemble sends a source-bound bounded assembly request to the
// user signer.
func (c *SignerClient) RequestBoundedAssemble(req BoundedAssemblyRequest) (*BoundedAssemblyResponse, error) {
	return c.RequestBoundedAssembleWithContext(context.Background(), req)
}

// RequestBoundedAssembleWithContext sends a source-bound bounded assembly
// request to the user signer.
func (c *SignerClient) RequestBoundedAssembleWithContext(ctx context.Context, reqBody BoundedAssemblyRequest) (*BoundedAssemblyResponse, error) {
	result, err := c.RequestAssembleWithContext(ctx, reqBody.AssemblyRequest())
	if err != nil {
		return nil, err
	}
	return &BoundedAssemblyResponse{RequestID: result.RequestID, SignedGroup: result.SignedGroup}, nil
}
