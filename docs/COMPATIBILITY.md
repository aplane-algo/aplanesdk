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
