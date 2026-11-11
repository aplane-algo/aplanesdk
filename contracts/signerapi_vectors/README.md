# Captured signer responses

`real_sign_responses.json` holds `/sign` requests and the responses a live
apsigner returned for them. The three SDKs feed each pair through their
response verification, so the checks are tested against what the signer really
produces, not against responses the SDKs' own test helpers build.

Each case is keyed by name and holds `key_type`, `request` (the `/sign` body's
`requests`) and `response` (`signed` and `mutations`):

- `logicsig_falcon_single`: one payment from a LogicSig Falcon account. The
  signer raised its fee, appended one resource dummy and grouped the two.
- `logicsig_falcon_pair`: two payments from a LogicSig Falcon account, plus
  one dummy.
- `native_falcon_single`: one payment from a native Falcon account. The fee
  was raised; there is no group.
- `ed25519_pair`: two payments from an Ed25519 account, grouped and otherwise
  unchanged.

The bytes were captured from a live signer on a local test network, through
aplane's SDK integration harness. The keys were throwaway; nothing here is
secret. Unlike `contracts/signerapi`, these are not wire-shape fixtures and
are not mirrored from the aplane repository.

## Rotating account answers

`rotating_vectors.json` holds what a live apsigner returned for spends from a
rotating account (`rotating1`), and copies of those answers altered in each
way a signer may not alter them. Every SDK must accept each captured answer
and refuse every altered one.

- `cases`: keyed by name. Each has `key_type`, `original_txn_hex` (the
  TX-prefixed transaction the client sent to `/sign/rotating/prepare`),
  `prepare` (the prepare response) and `sign` (the sign response for that
  prepared group).
  - `wotsc_stage0`: a first spend. The account signs as itself, so the signed
    spend names no signer.
  - `wotsc_stage2`: a spend after two rotations. The signed spend names the
    stage's address as its signer.
- `prepare_tampered`: entries of `name`, `case` and an altered `prepare`.
  Checked against the case's `original_txn_hex`, each must be refused.
- `sign_tampered`: entries of `name`, `case` and an altered `sign`. Checked
  against the case's own, unaltered `prepare`, each must be refused.

- `sign_answer_bodies`: entries of `name`, `case`, `body` and `expect`. `body`
  is a raw 200 body for `/sign/rotating/sign`, answered to a sign request for
  the case's own `prepare`. `expect` is the class the client must report:
  - `accepted`: the signed group is returned.
  - `refused`: the answer was read and failed its checks. A plain error.
  - `unknown`: the answer could not be read, so a signature may have been
    released. The client's "sign outcome unknown" error.

  The reading rule they pin: the body is exactly one JSON object; a field left
  out or null takes its zero value (so a null entry in `signed` is an empty
  string, which is then refused, and a null `stage` is stage 0, accepted only
  for a stage 0 spend); an unknown field is ignored; a field of the
  wrong type, a number outside the field's range, a null or non-object body,
  an empty or cut-off body, and anything after the object make the answer
  unreadable. Feed each body through the real transport with a fake server,
  not through the verifier alone.

The altered answers are generated, not written by hand: the Go SDK's tamper
tables (`go/rotating_test.go`) are applied to each captured case, and
`TestRotatingVectors` fails when the file and the tables disagree. To add a
check to every SDK, add an entry to a table and regenerate:

```bash
cd go && APLANE_UPDATE_ROTATING_VECTORS=1 go test -run TestRotatingVectors .
```

To capture fresh answers, run aplane's SDK integration bridge on LocalNet with
`APLANE_SDK_CAPTURE_ROTATING=1`, then regenerate as above.

Two rules have no vector, because they depend on the client's own settings or
on a pair of answers, and each SDK tests them directly: a fee raise above the
client's max fee increase (use a case's `mutations.total_fees_delta`), and a
spend signed by the program whose address is its own rekey target.
