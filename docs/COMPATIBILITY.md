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

APlane's v1 policy implementation uses `policy.json` on signer nodes and
`policies/<WitnessKeyID>.json` on cosigner nodes, with a `.hmac` sidecar for
each document in the active store generation. It does not read or migrate
the former `policy.yaml` format. Operators must prepare and apply v1 JSON
documents through `apadmin policy check` and `apadmin policy apply`; see the
[APlane policy guide](https://github.com/aplane-algo/aplane/blob/main/docs/USER_POLICY.md)
and [v1 format specification](https://github.com/aplane-algo/aplane/blob/main/docs/ARCH_POLICY_FORMAT.md).

Each cosigner Witness Key ID requires its own policy; there is no node-wide
fallback. A held key without a policy rejects `/sign/component` with HTTP 403,
`code: "forbidden"`, and rule ID `cosigner_policy:key_has_no_policy` in the
error message. A key the node does not hold returns HTTP 400 with
`code: "bad_request"`. This applies to both `cosigner1` and
`bounded-cosigner1` flows. The existing Go, Python, and TypeScript SDKs handle
these responses without client API or signer wire-contract changes. Policy
provisioning remains an operator workflow outside the SDKs.

Package source files retain placeholder versions. The publish workflow derives
the released Python and TypeScript package versions from the requested `vX.Y.Z`
tag, so the Git tag and package metadata in published artifacts remain the
version authority.
