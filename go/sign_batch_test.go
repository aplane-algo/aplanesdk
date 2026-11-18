// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"strings"
	"testing"
)

// A batch label is a request's place among several sent one at a time. Each
// request that takes one refuses a label that names no place in a batch, and
// accepts the request without one.
func TestSignBatchLabelsAPlaceInABatch(t *testing.T) {
	group := GroupSignRequest{Requests: []SignRequest{{AuthAddress: "A", TxnBytesHex: "545801"}}}
	var component ComponentRequest
	readContractMetadata(t, "component_request.json", &component)

	for _, tc := range []struct {
		batch *SignBatch
		want  string
	}{
		{nil, ""},
		{&SignBatch{Position: 1, Count: 1}, ""},
		{&SignBatch{Position: 3, Count: 3}, ""},
		{&SignBatch{Position: 1, Count: maxSignBatchCount}, ""},
		{&SignBatch{Position: 0, Count: 3}, "batch position"},
		{&SignBatch{Position: 4, Count: 3}, "batch position"},
		{&SignBatch{Position: 1, Count: 0}, "batch count"},
		{&SignBatch{Position: 1, Count: maxSignBatchCount + 1}, "batch count"},
	} {
		group.Batch, component.Batch = tc.batch, tc.batch
		for name, err := range map[string]error{"group": group.Validate(), "component": component.Validate()} {
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("%s %+v: unexpected error %v", name, tc.batch, err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("%s %+v: error = %v, want %q", name, tc.batch, err, tc.want)
			}
		}
	}
}
