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

Package source files retain placeholder versions. The publish workflow derives
the released Python and TypeScript package versions from the requested `vX.Y.Z`
tag, so the Git tag and package metadata in published artifacts remain the
version authority.
