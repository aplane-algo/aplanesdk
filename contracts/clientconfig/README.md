# Client endpoint fixtures

These fixtures pin the `endpoints.yaml` routing contract shared by the Go,
Python, and TypeScript SDKs. The canonical implementation remains APlane's
`internal/config.ClientEndpointRegistry`.

`valid.yaml` must load successfully in every SDK. Files prefixed with
`invalid_` must be rejected.
