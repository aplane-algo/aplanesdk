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
	"time"
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
	if ctx == nil {
		ctx = context.Background()
	}
	// A context that has already ended sends nothing, as in postApproval.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	approvalBearing := reqBody.TargetKind() != ComponentTargetKindCosigner
	timeout := c.componentRequestTimeout(ctx, approvalBearing)
	reqCtx, cancel := c.requestContext(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.baseURL+"/sign/component", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Checked again before the cancel watcher starts: a watcher started on an
	// ended context could cancel a request that was never posted.
	if err := reqCtx.Err(); err != nil {
		return nil, err
	}

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
	resp, err := c.client.Do(req)
	close(done)
	if err != nil {
		if reqCtx.Err() != nil {
			sendCancel()
		}
		return nil, fmt.Errorf("failed to make request to Signer: %w", &lostAnswer{requestID: reqBody.RequestID, err: err})
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
	if err := readAnswer(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode component response: %w", &lostAnswer{requestID: reqBody.RequestID, err: err})
	}
	if result.Error != "" {
		return nil, fmt.Errorf("component signing failed: %s", result.Error)
	}
	if err := result.ValidateForRequest(reqBody); err != nil {
		return nil, fmt.Errorf("invalid component response: %w", err)
	}
	if result.RequestID != reqBody.RequestID {
		return nil, fmt.Errorf("component response request_id does not match request")
	}
	return &result, nil
}

func (c *SignerClient) componentRequestTimeout(ctx context.Context, approvalBearing bool) time.Duration {
	timeout := componentSignTimeout
	if !approvalBearing {
		return timeout
	}
	c.discoverApprovalWait(ctx)
	if approvalTimeout := c.signRequestTimeout(); approvalTimeout > timeout {
		return approvalTimeout
	}
	return timeout
}
