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
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
```

Relative paths resolve against `APCLIENT_DATA`. `identity_file` defaults to
`.ssh/id_ed25519` and `known_hosts_path` to `.ssh/known_hosts`. The client's
enrolled SSH key is its only credential: there is no token file, and the
retired `token_file` key is accepted and ignored.

For registries shared with APlane tooling, prefer paths relative to
`APCLIENT_DATA` or absolute paths. SDK helpers expand `~`, while APlane
currently treats it as a literal path segment. Use lowercase SSH hostnames so
URL normalization and `known_hosts` lookup remain consistent across runtimes.
Schema v2 contains connection profiles only. Every loader requires
`schema_version: 2` exactly and rejects a missing, null, zero, or `1` value
(for example `endpoints.yaml schema_version = 1, want 2`); there is no v1
adapter. Schema v2 rejects the retired `published_cosigners` inventory.
Configure no more than 12 `cosigner` profiles; all SDK loaders reject larger
registries.

The former cosigner-reference synchronization client methods and wire types are
removed. APlane now keeps generation trust inputs and transaction routing
separate: operators explicitly export/import public cosigner references for
guarded-account generation, while the APlane engine discovers routes from live
authenticated `/keys` responses for each signing operation. SDK applications
continue to choose or resolve their cosigner client explicitly; loading
`endpoints.yaml` never creates a durable cosigner-key inventory.

Go `FromEnv`, Python `SignerClient.from_env`, and TypeScript
`SignerClient.fromEnv` select the default signer unless given an endpoint
alias. Every URL is `ssh://`: a node is reached only through its SSH server,
which authenticates the client's enrolled key and hands the API channel to its
REST listener with that identity. `https://` and `http://` URLs are rejected,
as is `url: self` for both signer and cosigner roles, including when the two
processes run on one host. Replace it with an explicit client-reachable URL
such as `ssh://host:1127` for each process, using its actual SSH port. An
endpoint record names no port beyond the one in its URL. The former
`signer_port` (the node's REST port behind SSH), `local_port`, and
`token_file` keys are accepted and ignored, as APlane ignores them: the node's
SSH server forwards every channel to its own REST listener, so the client never
chose the remote port, the local tunnel port is chosen at connect time, and
the key is the credential. Existing files keep working; the keys can be
removed at leisure, and new files should omit them. The explicit SSH
connection APIs keep their local-port option and no longer take a signer-port
or token argument; `DefaultSignerPort` / `DEFAULT_SIGNER_PORT`,
`LoadToken`/`loadToken`/`load_token`, and `NewSignerClientWithToken` (now
`NewSignerClient(baseURL)`) are gone.

Token provisioning is replaced by enrollment. Go `RequestEnrollmentFromEnv`,
Python `request_enrollment_from_env`, and TypeScript `requestEnrollmentFromEnv`
select an endpoint alias and ask that node to enroll the endpoint's client key.
The node answers at once with a result carrying the key's SHA256 fingerprint
and whether the request is pending: it is queued for the operator to approve
later in `apadmin` (the normal outcome), or the key was already enrolled.
Nothing waits for the operator and nothing is stored on the client; connect
once the operator has approved. The raw
`RequestEnrollment(host, ...)`, `request_enrollment(host, ...)`, and
`requestEnrollment(host, ...)` functions take explicit application-owned key
and host-trust paths; they do not fall back to the operating-system user's
personal SSH directory. The former `request_token*`/`requestToken*` helpers and
`TokenProvisioningError` are gone (`EnrollmentError` / `aplane.ErrEnrollment`
replace the latter).

Trust-on-first-use is no longer persisted in routing configuration. Pass
`trust_on_first_use=True`, `trustOnFirstUse: true`, or the Go
`FromEnvOptions.TrustOnFirstUse` explicitly for the call that may enroll an
unknown host key.

The routing projections formerly exposed through the SDK `ClientConfig`
types (`SSHConfig`, `ssh`, and `signerPort`/`signer_port`) were removed.
Endpoint routing types are now exposed separately from non-routing
`config.yaml` values.
