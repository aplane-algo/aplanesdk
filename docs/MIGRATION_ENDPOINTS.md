# Migrating SDK client routing to `endpoints.yaml`

The SDK data-directory helpers now use the same routing registry as APlane:
`$APCLIENT_DATA/endpoints.yaml`.

The former SDK-only nested routing block is no longer accepted:

```yaml
# Removed from config.yaml
endpoint:
  signer_port: 11270
  ssh:
    host: signer.example.com
```

Move that routing into an endpoint profile:

```yaml
schema_version: 1
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://signer.example.com:1127
    signer_port: 11270
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
```

Relative paths resolve against `APCLIENT_DATA`. The alias `primary` defaults
to `aplane.token`; every other alias defaults to `tokens/<alias>.token`.
`token_file` may override either location.

Go `FromEnv`, Python `SignerClient.from_env`, and TypeScript
`SignerClient.fromEnv` select the default signer unless given an endpoint
alias. SSH URLs create a managed tunnel. HTTPS and loopback HTTP URLs connect
directly. The client-local `self` URL is not supported by external SDKs.

Python `request_token_to_file` and TypeScript `requestTokenToFile` also select
an endpoint alias and require that endpoint to use `ssh://`. Their former
`host` and `ssh_port`/`sshPort` overrides were removed. The raw
`request_token(host, ...)` and `requestToken(host, ...)` functions remain for
caller-owned, ad-hoc provisioning flows.

Trust-on-first-use is no longer persisted in routing configuration. Pass
`trust_on_first_use=True`, `trustOnFirstUse: true`, or the Go
`FromEnvOptions.TrustOnFirstUse` explicitly for the call that may enroll an
unknown host key.

The routing projections formerly exposed through the SDK `ClientConfig`
types (`SSHConfig`, `ssh`, and `signerPort`/`signer_port`) were removed.
Endpoint routing types are now exposed separately from non-routing
`config.yaml` values.
