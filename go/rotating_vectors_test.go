// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// The rotating vectors are what a live signer returned for a rotating spend,
// and copies of those answers altered in each way a signer may not alter
// them. Every SDK must accept the captured answers and refuse every altered
// one. See contracts/signerapi_vectors/README.md.

type rotatingVectorCase struct {
	KeyType     string                  `json:"key_type"`
	OriginalTxn string                  `json:"original_txn_hex"`
	Prepare     RotatingPrepareResponse `json:"prepare"`
	Sign        RotatingSignResponse    `json:"sign"`
}

type rotatingTamperedPrepare struct {
	Name    string                  `json:"name"`
	Case    string                  `json:"case"`
	Prepare RotatingPrepareResponse `json:"prepare"`
}

type rotatingTamperedSign struct {
	Name string               `json:"name"`
	Case string               `json:"case"`
	Sign RotatingSignResponse `json:"sign"`
}

// rotatingAnswerBody is a raw 200 body for /sign/rotating/sign and how a
// client must class it: "accepted", "refused" (the answer was read and failed
// its checks) or "unknown" (the answer could not be read, so a signature may
// have been released).
type rotatingAnswerBody struct {
	Name   string `json:"name"`
	Case   string `json:"case"`
	Body   string `json:"body"`
	Expect string `json:"expect"`
}

type rotatingVectors struct {
	Cases            map[string]rotatingVectorCase `json:"cases"`
	PrepareTampered  []rotatingTamperedPrepare     `json:"prepare_tampered"`
	SignTampered     []rotatingTamperedSign        `json:"sign_tampered"`
	SignAnswerBodies []rotatingAnswerBody          `json:"sign_answer_bodies"`
}

func rotatingVectorsPath() string {
	return filepath.Join("..", "contracts", "signerapi_vectors", "rotating_vectors.json")
}

func loadRotatingVectors(t *testing.T) rotatingVectors {
	t.Helper()
	raw, err := os.ReadFile(rotatingVectorsPath())
	if err != nil {
		t.Fatalf("read rotating vectors: %v", err)
	}
	var vectors rotatingVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse rotating vectors: %v", err)
	}
	return vectors
}

func cloneJSON[T any](t *testing.T, value T) T {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func sameJSON(t *testing.T, a, b any) bool {
	t.Helper()
	left, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	right, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(left, right)
}

func preparedFromVector(c rotatingVectorCase, prepare RotatingPrepareResponse) (*PreparedRotating, error) {
	original, err := hex.DecodeString(c.OriginalTxn)
	if err != nil {
		return nil, err
	}
	return newPreparedRotating(original, &prepare, feeCeiling{}, nil)
}

// tamperedRotatingVectors derives the altered answers from the captured ones
// with the same tables the Go tests use. An alteration is kept for a case
// only when it changes the answer: some do nothing to a given capture, such
// as un-naming the signer of a stage 0 spend, which names none.
func tamperedRotatingVectors(t *testing.T, cases map[string]rotatingVectorCase) ([]rotatingTamperedPrepare, []rotatingTamperedSign) {
	t.Helper()
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	sort.Strings(names)
	var prepares []rotatingTamperedPrepare
	var signs []rotatingTamperedSign
	for _, name := range names {
		c := cases[name]
		for _, tamper := range rotatingPrepareTampers {
			response := cloneJSON(t, c.Prepare)
			txns := make([]types.Transaction, len(response.Transactions))
			for i, h := range response.Transactions {
				raw, err := hex.DecodeString(h)
				if err != nil {
					t.Fatal(err)
				}
				if txns[i], err = decodeCanonicalTxn(raw); err != nil {
					t.Fatalf("case %s transaction %d: %v", name, i, err)
				}
			}
			if response.Mutations == nil {
				// A capture with nothing reported has nothing to misreport.
				response.Mutations = &MutationReport{}
				tamper.alter(t, &response, txns)
				if sameJSON(t, *response.Mutations, MutationReport{}) {
					response.Mutations = nil
				}
			} else {
				tamper.alter(t, &response, txns)
			}
			if sameJSON(t, response, c.Prepare) {
				continue
			}
			prepares = append(prepares, rotatingTamperedPrepare{Name: tamper.name, Case: name, Prepare: response})
		}
		for _, tamper := range rotatingSignTampers {
			response := cloneJSON(t, c.Sign)
			signed := make([]types.SignedTxn, len(response.Signed))
			for i, h := range response.Signed {
				raw, err := hex.DecodeString(h)
				if err != nil {
					t.Fatal(err)
				}
				if signed[i], err = decodeCanonicalSignedTxn(raw); err != nil {
					t.Fatalf("case %s signed transaction %d: %v", name, i, err)
				}
			}
			if len(signed) < 2 && (strings.Contains(tamper.name, "dummy") || strings.Contains(tamper.name, "reordered") || strings.Contains(tamper.name, "extra transaction")) {
				continue // needs an appended dummy
			}
			tamper.alter(t, nil, &response, signed)
			if sameJSON(t, response, c.Sign) {
				continue
			}
			signs = append(signs, rotatingTamperedSign{Name: tamper.name, Case: name, Sign: response})
		}
		// At stage 0 the account signs as itself, so a spend signed by any
		// other program is refused even when it names that program as its
		// signer. At a later stage the SDK cannot tell one stage's program
		// from another's; the signer and the network do.
		if c.Sign.Stage == 0 {
			response := cloneJSON(t, c.Sign)
			raw, err := hex.DecodeString(response.Signed[0])
			if err != nil {
				t.Fatal(err)
			}
			spend, err := decodeCanonicalSignedTxn(raw)
			if err != nil {
				t.Fatal(err)
			}
			spend.Lsig = types.LogicSig{Logic: rotatingNextProgram, Args: spend.Lsig.Args}
			spend.AuthAddr = rotatingStageAddress(rotatingNextProgram)
			response.Signed[0] = hex.EncodeToString(msgpack.Encode(spend))
			signs = append(signs, rotatingTamperedSign{Name: "stage 0 spend signed by another program that it names as its signer", Case: name, Sign: response})
		}
	}
	return prepares, signs
}

// rotatingAnswerBodies builds raw sign answers from each captured one: how a
// client reads a 200 body is where three JSON libraries differ, and the
// altered answers above cannot show it, because they are written from typed
// values. A field left out or null takes its zero value; a field of the wrong
// type, a null or non-object body, and anything after the answer make it
// unreadable.
func rotatingAnswerBodies(t *testing.T, cases map[string]rotatingVectorCase) []rotatingAnswerBody {
	t.Helper()
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	sort.Strings(names)
	var bodies []rotatingAnswerBody
	for _, name := range names {
		c := cases[name]
		base, err := json.Marshal(c.Sign)
		if err != nil {
			t.Fatal(err)
		}
		with := func(change func(fields map[string]json.RawMessage)) string {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(base, &fields); err != nil {
				t.Fatal(err)
			}
			change(fields)
			out, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			return string(out)
		}
		set := func(key, value string) string {
			return with(func(fields map[string]json.RawMessage) { fields[key] = json.RawMessage(value) })
		}
		var signed []json.RawMessage
		if err := json.Unmarshal(mustField(t, base, "signed"), &signed); err != nil {
			t.Fatal(err)
		}
		signed[0] = json.RawMessage("null")
		nullEntry, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		for _, body := range []rotatingAnswerBody{
			{Name: "the captured answer", Body: string(base), Expect: "accepted"},
			{Name: "an extra field the client does not know", Body: set("extra", `{"a":1}`), Expect: "accepted"},
			{Name: "a null body", Body: "null", Expect: "unknown"},
			{Name: "an array body", Body: "[]", Expect: "unknown"},
			{Name: "a string body", Body: `"ok"`, Expect: "unknown"},
			{Name: "a number body", Body: "123", Expect: "unknown"},
			{Name: "an empty body", Body: "", Expect: "unknown"},
			{Name: "text after the answer", Body: string(base) + " x", Expect: "unknown"},
			{Name: "the answer twice", Body: string(base) + string(base), Expect: "unknown"},
			{Name: "the answer cut short", Body: string(base[:len(base)/2]), Expect: "unknown"},
			{Name: "signed is a string", Body: set("signed", `"x"`), Expect: "unknown"},
			{Name: "signed holds a number", Body: set("signed", "[1]"), Expect: "unknown"},
			{Name: "stage is a string", Body: set("stage", `"3"`), Expect: "unknown"},
			{Name: "stage is negative", Body: set("stage", "-1"), Expect: "unknown"},
			{Name: "stage is beyond 64 bits", Body: set("stage", "18446744073709551616"), Expect: "unknown"},
			{Name: "txid is a number", Body: set("txid", "5"), Expect: "unknown"},
			{Name: "a null entry in signed", Body: set("signed", string(nullEntry)), Expect: "refused"},
			{Name: "signed left out", Body: with(func(fields map[string]json.RawMessage) { delete(fields, "signed") }), Expect: "refused"},
			{Name: "signed is null", Body: set("signed", "null"), Expect: "refused"},
			{Name: "txid left out", Body: with(func(fields map[string]json.RawMessage) { delete(fields, "txid") }), Expect: "refused"},
		} {
			body.Case = name
			bodies = append(bodies, body)
		}
	}
	return bodies
}

func mustField(t *testing.T, object []byte, key string) json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(object, &fields); err != nil {
		t.Fatal(err)
	}
	return fields[key]
}

// TestRotatingAnswerBodies answers a real sign request with each raw body and
// requires the outcome class the vectors name.
func TestRotatingAnswerBodies(t *testing.T) {
	vectors := loadRotatingVectors(t)
	if len(vectors.SignAnswerBodies) == 0 {
		t.Fatal("no raw sign answers in the vectors")
	}
	for _, body := range vectors.SignAnswerBodies {
		t.Run(body.Case+"/"+body.Name, func(t *testing.T) {
			c := vectors.Cases[body.Case]
			prepared, err := preparedFromVector(c, c.Prepare)
			if err != nil {
				t.Fatalf("captured prepare answer refused: %v", err)
			}
			client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/status":
					json.NewEncoder(w).Encode(StatusResponse{State: "unlocked"})
				case "/sign/rotating/sign":
					w.Write([]byte(body.Body))
				}
			})
			defer server.Close()
			_, err = client.SignPreparedRotating(context.Background(), prepared, nil)
			got := "accepted"
			var unknown *SignOutcomeUnknownError
			switch {
			case errors.As(err, &unknown):
				got = "unknown"
			case err != nil:
				got = "refused"
			}
			if got != body.Expect {
				t.Fatalf("outcome %s (%v), want %s", got, err, body.Expect)
			}
		})
	}
}

func TestRotatingVectors(t *testing.T) {
	vectors := loadRotatingVectors(t)
	if len(vectors.Cases) == 0 {
		t.Fatal("no captured rotating cases")
	}
	wantPrepares, wantSigns := tamperedRotatingVectors(t, vectors.Cases)

	if os.Getenv("APLANE_UPDATE_ROTATING_VECTORS") == "1" {
		vectors.PrepareTampered, vectors.SignTampered = wantPrepares, wantSigns
		vectors.SignAnswerBodies = rotatingAnswerBodies(t, vectors.Cases)
		raw, err := json.MarshalIndent(vectors, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rotatingVectorsPath(), append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d prepare and %d sign alterations", len(wantPrepares), len(wantSigns))
	}
	// The file's altered answers are the ones the tables produce, so a check
	// added to the tables reaches the other SDKs through the file.
	if !sameJSON(t, vectors.PrepareTampered, wantPrepares) || !sameJSON(t, vectors.SignTampered, wantSigns) ||
		!sameJSON(t, vectors.SignAnswerBodies, rotatingAnswerBodies(t, vectors.Cases)) {
		t.Fatalf("rotating_vectors.json is out of date with the tamper tables; run with APLANE_UPDATE_ROTATING_VECTORS=1")
	}
	if len(vectors.PrepareTampered) < len(rotatingPrepareTampers) || len(vectors.SignTampered) < len(rotatingSignTampers) {
		t.Fatalf("only %d prepare and %d sign alterations; every table entry must apply to some case", len(vectors.PrepareTampered), len(vectors.SignTampered))
	}

	for name, c := range vectors.Cases {
		prepared, err := preparedFromVector(c, c.Prepare)
		if err != nil {
			t.Errorf("case %s: the captured prepare answer was refused: %v", name, err)
			continue
		}
		sign := c.Sign
		if _, err := prepared.verifySigned(&sign); err != nil {
			t.Errorf("case %s: the captured sign answer was refused: %v", name, err)
		}
	}
	for _, altered := range vectors.PrepareTampered {
		if _, err := preparedFromVector(vectors.Cases[altered.Case], altered.Prepare); err == nil {
			t.Errorf("case %s, %s: an altered prepare answer was accepted", altered.Case, altered.Name)
		}
	}
	for _, altered := range vectors.SignTampered {
		c := vectors.Cases[altered.Case]
		prepared, err := preparedFromVector(c, c.Prepare)
		if err != nil {
			continue // reported above
		}
		sign := altered.Sign
		if _, err := prepared.verifySigned(&sign); err == nil {
			t.Errorf("case %s, %s: an altered sign answer was accepted", altered.Case, altered.Name)
		}
	}

	// Every table entry must be exercised by at least one captured case.
	used := map[string]bool{}
	for _, altered := range vectors.PrepareTampered {
		used["prepare: "+altered.Name] = true
	}
	for _, altered := range vectors.SignTampered {
		used["sign: "+altered.Name] = true
	}
	for _, tamper := range rotatingPrepareTampers {
		if !used["prepare: "+tamper.name] {
			t.Errorf("no captured case exercises the prepare alteration %q", tamper.name)
		}
	}
	for _, tamper := range rotatingSignTampers {
		if !used["sign: "+tamper.name] {
			t.Errorf("no captured case exercises the sign alteration %q", tamper.name)
		}
	}
}
