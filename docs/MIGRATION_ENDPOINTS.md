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
schema_version: 2
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

For registries shared with APlane tooling, prefer paths relative to
`APCLIENT_DATA` or absolute paths. SDK helpers expand `~`, while APlane
currently treats it as a literal path segment. Use lowercase SSH hostnames so
URL normalization and `known_hosts` lookup remain consistent across runtimes.
Schema v2 contains connection profiles only. Loaders accept schema v1 as a
bounded migration input, discard its retired `published_sentries` inventory,
and return the v2 runtime shape. Schema v2 rejects that field. Configure no
more than 12 `sentry` profiles; all SDK loaders reject larger registries.

The former sentry-reference synchronization client methods and wire types are
removed. APlane now keeps generation trust inputs and transaction routing
separate: operators explicitly export/import public sentry references for
guarded-account generation, while the APlane engine discovers routes from live
authenticated `/keys` responses for each signing operation. SDK applications
continue to choose or resolve their sentry client explicitly; loading
`endpoints.yaml` never creates a durable sentry-key inventory.

Go `FromEnv`, Python `SignerClient.from_env`, and TypeScript
`SignerClient.fromEnv` select the default signer unless given an endpoint
alias. SSH URLs create a managed tunnel. HTTPS and loopback HTTP URLs connect
directly. The client-local `self` URL is not supported by external SDKs.

Python `request_token_to_file` and TypeScript `requestTokenToFile` also select
an endpoint alias and require that endpoint to use `ssh://`. Their former
`host` and `ssh_port`/`sshPort` overrides were removed. The raw
`request_token(host, ...)` and `requestToken(host, ...)` functions remain for
caller-owned, ad-hoc provisioning flows. They do not fall back to the
operating-system user's personal SSH directory; callers must provide explicit
application-owned key and host-trust paths.

Trust-on-first-use is no longer persisted in routing configuration. Pass
`trust_on_first_use=True`, `trustOnFirstUse: true`, or the Go
`FromEnvOptions.TrustOnFirstUse` explicitly for the call that may enroll an
unknown host key.

The routing projections formerly exposed through the SDK `ClientConfig`
types (`SSHConfig`, `ssh`, and `signerPort`/`signer_port`) were removed.
Endpoint routing types are now exposed separately from non-routing
`config.yaml` values.
