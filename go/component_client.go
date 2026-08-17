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
	expected := make(map[int]ComponentTargetKind, len(reqBody.Targets))
	for _, target := range reqBody.Targets {
		expected[target.TargetIndex] = target.Kind
	}
	if len(result.Components) != len(expected) {
		return nil, fmt.Errorf("component response target indices or kinds do not match request")
	}
	for _, component := range result.Components {
		if expected[component.TargetIndex] != component.Kind {
			return nil, fmt.Errorf("component response target indices or kinds do not match request")
		}
	}
	return &result, nil
}
