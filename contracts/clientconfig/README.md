# Client endpoint fixtures

These fixtures pin the `endpoints.yaml` routing contract shared by the Go,
Python, and TypeScript SDKs. The canonical implementation remains APlane's
`internal/config.ClientEndpointRegistry`.

Files prefixed with `valid` must load successfully in every SDK. Files
prefixed with `invalid_` must be rejected. Keep edge-case fixtures shared so
strictness remains aligned across the SDK languages. The SDK loaders
deliberately reject ambiguous YAML scalar coercions, including forms that a
plain `yaml.v3` decode may coerce, rather than repairing them to defaults.

Every loader requires `schema_version: 2` exactly. The
`invalid_schema_version_*` and `invalid_v1_published_cosigners.yaml` fixtures
pin the rejection of a missing, null, zero, float, or `1` version; there is no
v1 adapter.

Endpoint records require an explicit `ssh://`, `https://`, or loopback
`http://` URL; `self` is invalid for both roles. Cosigner records reject a
nonzero `local_port`, while signer records may use it. The 12- and 13-cosigner
fixtures use distinct URLs for readability; URL uniqueness is not a loader
rule.
