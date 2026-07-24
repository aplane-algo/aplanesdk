# Client endpoint fixtures

These fixtures pin the `endpoints.yaml` routing contract shared by the Go,
Python, and TypeScript SDKs. The canonical implementation remains APlane's
`internal/config.ClientEndpointRegistry`.

Files prefixed with `valid` must load successfully in every SDK. Files
prefixed with `invalid_` must be rejected. Keep edge-case fixtures shared so
strictness remains aligned across the SDK languages. The SDK loaders
deliberately reject ambiguous YAML scalar coercions, including forms that a
plain `yaml.v3` decode may coerce, rather than repairing them to defaults.
