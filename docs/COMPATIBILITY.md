# SDK and APlane compatibility

The native-Falcon SDK release line requires an APlane signer release after
`v0.35.0` that includes the native-Falcon signer API contract. It is not
wire-compatible with APlane `v0.35.0` or earlier.

This boundary is intentionally fail-closed:

- `lsig_size` was replaced by the structured `lsig_resources` declaration;
- passthrough LogicSig slots must declare their selected-path resources;
- native Falcon foreign slots declare `pq_scheme: "f1"`; and
- signer-owned `/plan` output determines dummy transactions and authorization
  fee adjustments.

The same release removes the obsolete client-side minimum-fee option from the
prepared guarded APIs and requires `GuardedSignTarget` callers to provide the
selected LogicSig resource declaration. Upgrade the signer and SDK together.

APlane's policy implementation stores one `aplane.policy.v1` document per
file, each with a `.hmac` sidecar in the active store generation: a node
default, `default.json`, plus `policies/<selector>.json` for every key given a
policy of its own (the address on a signer node, the Witness Key ID on a
cosigner node). A key with no file of its own follows the node default; a key
with one is governed by that file alone. It does not read or migrate earlier
layouts. Operators prepare and apply documents through `apadmin policy check`
and `apadmin policy apply`; see the
[APlane policy guide](https://github.com/aplane-algo/aplane/blob/main/docs/USER_POLICY.md)
and [v1 format specification](https://github.com/aplane-algo/aplane/blob/main/docs/ARCH_POLICY.md#the-boundary).

The shipped cosigner default rejects every transaction type, so a held
cosigner key with no document of its own rejects `/sign/component` with HTTP
403, `code: "forbidden"`, and a `transaction_type:<type>` rule ID in the error
message until the operator applies a document for it. A key the node does not
hold returns HTTP 400 with `code: "bad_request"`. This applies to the
`cosigned1` flow. The existing Go, Python, and TypeScript SDKs handle these
responses without client API or signer wire-contract changes. Policy
provisioning remains an operator workflow outside the SDKs.

The SDKs read only the current signer wire and client file formats:

- Error classification relies on the wire `code` that every apsigner error
  response carries. A 403 maps to the locked error only for `code: "locked"`
  and to the signing-rejected error only for `code: "forbidden"`, and an
  error maps to key-not-found only for `code: "not_found"`. Any other code,
  including an empty one, surfaces as the generic signer API error with its
  status, code, and message. Message text is never inspected.
- `/keys` template provenance is read only from `template_provenance_status`
  and `template_provenance_note`; the `template_status` and
  `template_warning` aliases are gone.
- `endpoints.yaml` must declare `schema_version: 2`.
- `bounded_authorization.contract` is `bounded2` or `plain1`, and `max_fee` is
  optional: required on `bounded2`, absent on `plain1` (a plain host, which has
  no fee ceiling). The cosigned helpers refuse an account with any other
  contract, or with a ceiling that contradicts its contract, before any request.
- The `cosigner1` signing flow, the `user` component target kind, the
  `guarded` assembly target kind and the explicit-group signing API are gone.
  `cosigner1` is an unknown flow, so an SDK refuses such a key before sending
  anything; the string survives only as the cosigner contract label in
  `bounded_authorization.cosigner.contract`.
- The prepared cosigned API is renamed, with no aliases: `SignPreparedGuardedGroup`
  and `SimulatePreparedGuardedGroup` (and their context forms) are
  `SignPreparedCosignedGroup` and `SimulatePreparedCosignedGroup`; Python's
  `sign_prepared_guarded_group` and `simulate_prepared_guarded_group` are
  `sign_prepared_cosigned_group` and `simulate_prepared_cosigned_group`;
  TypeScript's `signPreparedGuardedGroup` and `simulatePreparedGuardedGroup` are
  `signPreparedCosignedGroup` and `simulatePreparedCosignedGroup`; and every
  `Guarded*` type is `Cosigned*`. No wire value changes.
- Bounded accounts are plain hosts: `aplane.falcon1024-b.v1` is retired, and a bounded
  account in `/keys` is `aplane.falcon1024.v1` or `aplane.ed25519.v1` with
  `bounded_authorization.contract` `bounded2`. The SDKs route on the contract and the
  signing flow, never the key type name, so no code changes; an Ed25519 bounded account
  may now have a cosigner and signs through `cosigned1` like a Falcon one.
- Key types may carry `boundary_schema`, the boundary file grammar a per-key
  type's requests take; it is absent on a plain host.

Package source files retain placeholder versions. The publish workflow derives
the released Python and TypeScript package versions from the requested `vX.Y.Z`
tag, so the Git tag and package metadata in published artifacts remain the
version authority.

Sparse rotating recovery requires the matching signer change: status uses
`cached_entries` for the number of sparse records and `preparation` for readiness
at the last observation (`locating`, `preparing_successor`, `ready`, or
`unresolved`). Neither the observed stage nor the entry count measures complete
rotation history. No legacy `cached_stages` field is provided. The Python SDK
ignores fields it does not declare inside `/status` rotating entries, their
recovery state and `protocol_version`, and leaves `preparation` empty when the
signer does not report it.

The one-call send (`SendPrepared`/`SendPayment` in Go, `sendPrepared`/
`sendPayment` in TypeScript, `send_prepared`/`send_payment` in Python) is new.
When upgrading to the release that adds it, know what it needs from the
signer and what changed for callers of the existing calls:

- Rotating sends need a signer that refuses a spend whose validity window is
  not current at signing with the `rotating_window_not_current` code (HTTP
  409), added in aplane PR #250 after APlane `v0.49.0`. The SDK rebuilds the
  rounds and prepares again only on that code. An older signer refuses with
  `bad_request`, and the send returns that refusal without retrying.
- Every 200 answer is read strictly, in all three SDKs: exactly one JSON
  value (one object in TypeScript and Python), so a `null` body, an empty or
  cut-off body, or anything after the value is an error, never an empty
  answer. A field left out or `null`, at any depth, reads as its zero value;
  a field of the wrong type or out of range makes the answer unreadable. An
  answer whose `error` field is set is a refusal: component, assembly, key
  generation and key deletion answers as well as `/sign` and `/plan`. A key
  generation answer without an address is refused, and a key deletion answer
  is read as `{success, error}`. A `/keys` answer that spells an Algorand
  address non-canonically is refused whole. In TypeScript and Python an
  unreadable answer to a request that releases no signature is a plain
  `SignerError`, never a raw parse, type or attribute error, and in Python an
  unreadable `/status` no longer stops a sign request: the default approval
  wait is used. Each SDK's README says how its reader differs from the
  others'.
- The cosigned flow resolves the cosigner before asking for approval. A
  caller's `CosignerResolver`/`cosignerResolver`/`cosigner_resolver` is now
  called before the group is planned and before the user signer's base
  component, for every target that cannot take the listed-rekey path, so a
  resolver that fails leaves nothing signed. A rekey that may take the listed
  path is resolved after the base component, and only when it needs the
  cosigner. A resolver's own error is passed on as it is, never as an
  unknown outcome.
- A client created from a data directory (`FromEnv`, `fromEnv`, `from_env`)
  now finds a cosigned account's cosigner among the `role: cosigner`
  endpoints of its `endpoints.yaml` when no cosigner client or resolver is
  given, and opens SSH connections to them, closed with the client. Before,
  such a call failed with "cosigner client or resolver is required"; a client
  made any other way still does.
- `SimulationResult` gained a failure message: `FailureMessage` (Go),
  `failureMessage` (TypeScript), `failure_message` (Python). A simulation now
  fails unless the node returned exactly one group result, that result
  reports no failure, and it holds one transaction result per transaction
  simulated. Before, an answer with no group result read as a pass.
- `ResolveAuthAddress`/`resolveAuthAddress`/`resolve_auth_address` returns a
  rotating account itself as its auth address at every stage, with the stage
  address the chain reports in `ChainAuthAddress`/`chainAuthAddress`/
  `chain_auth_address`. Before, a rotating account that had rotated failed to
  resolve, since the signer does not list stage addresses. The prepare
  helpers also cap a rotating sender's validity window at 100 rounds.
- TypeScript and Python refuse, before any request is sent, an address that
  is not spelled canonically (another spelling that decodes to the same
  bytes, which the Go SDK's decoder already refused): a prepare helper's
  sender, receiver, close-to and rekey-to, a sign request's auth address, and
  an app call's account references and ABI account arguments. TypeScript's
  prepare helpers also refuse an address argument that is not a string.
- An approval-bearing request that is not posted, because its context had
  ended (Go), its signal was already aborted (TypeScript) or its body cannot
  be encoded as JSON (Python), is a plain error, and no `/sign/cancel` is
  sent for it.
- In Go, an error body's `code` is now kept only beside a message that is
  not blank, as TypeScript and Python keep it. In Python, a non-200 body that
  is JSON but not an object now carries no code, where it raised
  `AttributeError`.
- In Python, a `KeyboardInterrupt` while an approval-bearing request is
  pending now sends the best-effort `/sign/cancel` first, as a timeout does,
  and still propagates. It carries the request's ID as `aplane_request_id`;
  during a send it may also carry the prepared rotating group as
  `aplane_rotating`, or the signed group as `aplane_signed_group` and
  `aplane_tx_ids`.
- In TypeScript, an SSH identity file that cannot be parsed, holds no private
  key or needs a passphrase fails at once with a `SignerError`, instead of
  hanging.
