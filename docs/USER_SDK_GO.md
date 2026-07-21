# Go SDK Guide

Use the APlane Go SDK to sign Algorand transactions through `apsigner`
from Go applications and services.

The Go module path is `github.com/aplane-algo/aplanesdk/go`. It uses
the same client data directory and SSH-backed connection model as `apshell`,
but it also supports a caller-owned transport mode for advanced integrations.

## Overview

The Go SDK is a user-facing integration surface for:

- loading client config and token state from `APCLIENT_DATA`
- connecting to `apsigner` over the standard SSH-backed product path
- listing signer keys and available key types
- planning and signing single transactions and groups
- assembling multi-party group results
- building an `algod` client from the same client config
- constructing a signer client from a caller-owned base URL and HTTP client

Package versions are tracked independently across languages. Do not assume the
Go, Python, and TypeScript SDK package versions will always match.

## Requirements

- Go `1.25` or newer for this module as currently declared
- an APlane signer you can reach over the standard SSH-backed client path
- either:
  - an existing client data directory with config, token, SSH key, and
    `known_hosts`, or
  - explicit signer host, token, SSH key, and `known_hosts` paths, or
  - a caller-owned tunnel / HTTP transport for the signer API

The Go SDK depends on:

- `github.com/algorand/go-algorand-sdk/v2`
- `golang.org/x/crypto`
- `gopkg.in/yaml.v3`

Those are resolved automatically by the Go module system.

## Installation

Install the module with `go get`:

```bash
go get github.com/aplane-algo/aplanesdk/go
```

Import path:

```go
import "github.com/aplane-algo/aplanesdk/go"
```

## Configuration And Credentials

The Go SDK follows the same client data directory convention as `apshell`.

Resolution order (the SDK has no implicit default — `ResolveDataDir` returns an
error if neither is set):

1. explicit `DataDir`
2. `APCLIENT_DATA`

Typical client layout (installer default: `~/aplane/apclient`):

```text
<data_dir>/
  config.yaml
  aplane.token
  .ssh/
    id_ed25519
    known_hosts
```

The SDK reads:

- `config.yaml` for SSH host/port, signer REST port, and optional algod config
- `aplane.token` for HTTP bearer authentication and the SSH mutual proof
- `.ssh/id_ed25519` for client SSH auth
- `.ssh/known_hosts` for SSH host key verification

Example `config.yaml`:

```yaml
network: testnet
networks_allowed: [testnet]
endpoint:
  signer_port: 11270
  ssh:
    host: signer.example.com
    port: 1127
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    trust_on_first_use: false
algod:
  testnet:
    server: https://testnet-api.4160.nodely.dev
    token: ""
```

If `endpoint.ssh.trust_on_first_use: true` is set, the SDK can auto-trust an unknown
host key on first connection and save it to `known_hosts`. Otherwise, unknown
hosts are rejected until the host key is already trusted.

## First-Time Setup

If you already installed APlane locally or in client-only mode, the easiest
path is:

1. install APlane and create or obtain an `apclient` data directory
2. generate or provide the client SSH key under `.ssh/id_ed25519`
3. provision a token by using the normal product path (`apshell`, `apadmin`,
   or another SDK helper)
4. connect with `aplane.FromEnv(...)`

Unlike the Python and TypeScript SDKs, the Go SDK does **not** currently ship
its own token-provisioning helper. The token file must already exist at
`<dataDir>/aplane.token`, or you must provide the token directly to
`ConnectSSH(...)` or `NewSignerClientWithToken(...)`.

The simplest way to provision the token file is to run `apshell` and execute
the `request-token` command; an operator approves the request in `apadmin`
and `apshell` writes the token to `<dataDir>/aplane.token`.

## Connection Methods

### Recommended: Load From Client Data Dir

```go
client, err := aplane.FromEnv(nil)
if err != nil {
	return err
}
defer client.Close()

healthy, _ := client.Health()
```

This path:

- resolves the client data dir
- loads `config.yaml`
- loads `aplane.token`
- resolves SSH paths relative to the client data dir
- establishes the SSH tunnel automatically

`FromEnv(...)` requires:

- a token file at `<dataDir>/aplane.token`
- an `endpoint.ssh` block in `config.yaml`
- a readable SSH private key at the configured `identity_file`

You can override the defaults:

```go
client, err := aplane.FromEnv(&aplane.FromEnvOptions{
	DataDir: "/custom/path",
	Timeout: 30,
})
```

### Explicit SSH Connection

```go
client, err := aplane.ConnectSSH(
	"signer.example.com",
	"your-token",
	"~/.ssh/id_ed25519",
	&aplane.SSHConnectOptions{
		SSHPort:         1127,
		SignerPort:      11270,
		Timeout:         30, // optional explicit shorter request timeout
		KnownHostsPath:  "~/.ssh/known_hosts",
		TrustOnFirstUse: false,
	},
)
if err != nil {
	return err
}
defer client.Close()
```

The SSH username is the non-secret identity ID. Authentication verifies the
enrolled public key first, then performs a programmatic mutual proof of the
token bound to the accepted host key and fresh client/server nonces. The
server proves token possession before the client returns its proof, and the
bearer token is never sent as SSH metadata.

This is useful when:

- you do not want to depend on `APCLIENT_DATA`
- you manage the token out-of-band
- your app needs to choose the signer target dynamically

### Caller-Owned Transport

The Go SDK also supports a lower-level mode where your application already owns
the tunnel or HTTP path to `apsigner`.

```go
client := aplane.NewSignerClientWithToken("http://127.0.0.1:11270", token)
client.SetHTTPClient(&http.Client{Timeout: 30 * time.Second})
defer client.Close()
```

Use this when:

- your process already created the SSH tunnel
- you proxy signer traffic through another transport
- you need custom HTTP behavior such as retry or tracing middleware

## Common Tasks

### Health Check

```go
healthy, err := client.Health()
```

### Identity Status

```go
identity, err := client.GetStatus()
if err != nil {
	return err
}
fmt.Println(identity.State, identity.KeysetRevision, identity.ApprovalWaitSeconds)
```

`GetStatus(...)` calls authenticated `/status`. It does not require the
signer to be unlocked; a locked signer is returned as status data. Use
`KeysetRevision` as a process-local signal to refresh `/keys` only when the
loaded keyset changes. Do not treat it as a durable version across apsigner
restarts.

The SDK also uses `ApprovalWaitSeconds` to size `/sign` deadlines. If discovery
fails or an older signer omits the field, signing falls back to a 6-minute
deadline.

### List Keys

```go
keys, err := client.ListKeys(true)
if err != nil {
	return err
}
for _, key := range keys {
	fmt.Println(key.Address, key.KeyType, key.LsigSize)
}
```

`ListKeys(...)` returns `[]aplane.KeyInfo` with fields such as:

- `Address`
- `PublicKeyHex`
- `KeyType`
- `LsigSize`
- `IsGenericLsig`
- `SigningArgs`
- `TemplateProvenanceStatus`
- `TemplateProvenanceNote`
- `TemplateStatus`
- `TemplateWarning`

`LsigSize` is the spend-path LogicSig budget. For `bounded1`, it excludes the
external contract-admin signature slot;
`BoundedAuthorization.PostSigningLogicSigSize` is admin-inclusive.

The Go SDK exposes bounded inventory and ordinary spend signing only. It does
not expose `/sign/bounded-admin` or build and complete contract-admin rekeys;
use the APlane `aprekey` workflow for those operations.

`TemplateStatus` and `TemplateWarning` are legacy aliases for
`TemplateProvenanceStatus` and `TemplateProvenanceNote`.

### Get One Key

```go
keyInfo, err := client.GetKeyInfo(address)
```

### List Key Types

```go
keyTypes, err := client.ListKeyTypes()
if err != nil {
	return err
}
for _, keyType := range keyTypes {
	fmt.Println(keyType.KeyType, keyType.Family, keyType.DisplayName)
}
```

This is the easiest way to discover:

- available key families
- creation parameters for generated keys
- runtime args required by generic LogicSigs
- explicit mnemonic import support through `MnemonicImport`

### Generate And Delete A Key

```go
generated, err := client.GenerateKey("ed25519", nil)
if err != nil {
	return err
}
fmt.Println(generated.Address, generated.KeyType)

if err := client.DeleteKey(generated.Address); err != nil {
	return err
}
```

### Sign One Transaction

```go
params, err := algodClient.SuggestedParams().Do(ctx)
if err != nil {
	return err
}

txn, err := transaction.MakePaymentTxn(
	fromAddress,
	toAddress,
	1000,
	nil,
	"",
	params,
)
if err != nil {
	return err
}

signed, err := client.SignTransaction(txn, "", nil)
if err != nil {
	return err
}

signedBytes, err := aplane.Base64ToBytes(signed)
if err != nil {
	return err
}

txid, err := algodClient.SendRawTransaction(signedBytes).Do(ctx)
```

For rekeyed accounts, pass the signing key explicitly:

```go
signed, err := client.SignTransaction(txn, authAddress, nil)
```

For generic LogicSigs, pass runtime args as `aplane.LsigArgs`:

```go
signed, err := client.SignTransaction(
	txn,
	hashlockAddress,
	aplane.LsigArgs{
		"preimage": secretBytes,
	},
)
```

### Sign A Transaction Group

```go
signed, err := client.SignTransactions(
	[]types.Transaction{txn1, txn2},
	[]string{authAddr1, authAddr2},
	nil,
)
```

Important:

- do not pre-assign a group ID
- the signer computes the group after dummy insertion and fee pooling
- the returned base64 string is ready for algod submission after decoding

### Plan Without Signing

```go
plan, err := client.PlanGroup(
	[]types.Transaction{txn1, txn2},
	[]string{authAddr1, authAddr2},
	nil,
	nil,
)
if err != nil {
	return err
}
fmt.Println(plan.Transactions)
fmt.Printf("%+v\n", plan.Mutations)
```

Use `/plan` when you need:

- fee and dummy visibility before approval
- simulation inputs
- foreign-slot planning for multi-party workflows

### Passthrough And Foreign Planning

The Go SDK exposes passthrough and foreign-slot support through
`SignOptions`:

```go
opts := &aplane.SignOptions{
	Passthrough: map[int]string{
		1: otherSignerBase64,
	},
	LsigSizes: map[int]int{
		2: 3035,
	},
}

plan, err := client.PlanGroup(txns, authAddresses, lsigArgsMap, opts)
```

`SignOptions.Passthrough` values are base64-encoded signed transaction msgpack
from another signer and must already carry the intended group ID. The SDK
decodes them and sends them as passthrough slots. `SignOptions.LsigSizes`
marks unsigned foreign slots for `/plan` only so the signer can reserve dummy
and fee budget for another participant's LogicSig.

For actual signing with passthrough slots, use:

- `SignTransactionsWithOptions(...)`
- `SignTransactionsListWithOptions(...)`

Foreign slots are only supported on `/plan`; they must be resubmitted as
passthrough for final signing.

### Multi-Party Group Assembly

Use `AssembleGroup(...)` on the results of
`SignTransactionsListWithOptions(...)`:

```go
combined, err := aplane.AssembleGroup([][]string{
	aliceSigned,
	bobSigned,
})
if err != nil {
	return err
}

combinedBytes, err := aplane.Base64ToBytes(combined)
if err != nil {
	return err
}

txid, err := algodClient.SendRawTransaction(combinedBytes).Do(ctx)
```

### Guarded Sentry Signing

Guarded accounts use component signatures from both the user signer and a
sentry signer. Sentry component selectors are public policy keys, not Algorand
spending accounts, and must not be used as senders, receivers, auth addresses,
or rekey targets.

Use explicit clients; the SDK does not parse or mutate endpoint enrollment
files:

```go
result, err := aplane.SignGuardedGroup(aplane.GuardedSignOptions{
	UserClient:         userClient,
	SentryClient:       sentryClient,
	SentryComponentKey: "SENTRY_COMPONENT_SELECTOR",
	GroupBytesHex:      []string{"5458..."},
	Targets: []aplane.GuardedSignTarget{{
		TargetIndex:    0,
		GuardedAccount: "GUARDED_ACCOUNT_ADDRESS",
	}},
})
signedGroup := result.SignedGroup
```

For manual orchestration, use `RequestComponentSign` on the user and sentry
clients, then `RequestGuardedAssemble` on the user client. `AssembleGroup`
remains only the local multi-party concatenation helper.

User-role component signing runs the signer-domain approval gates and can
block on a manual operator decision. The SDK automatically discovers the
signer's `approval_wait_seconds` and sizes the request deadline accordingly,
exactly like `/sign`; sentry-role component requests stay on the short
deterministic deadline.

Guarded simulation is contained inside the user signer: call
`RequestGuardedSimulate` with the frozen group, sentry component signatures,
and signed passthrough entries. The signer produces the user component
signatures internally, assembles, simulates against its own algod, and returns
only transaction IDs, final unsigned transactions, and the simulation report.
Do not implement guarded simulation by requesting real user components and
simulating client-side: that triggers a real operator approval for a
transaction the caller only wants to preview, and leaves fully submittable
signed bytes in the client's hands.

## Transaction Semantics

- `SignTransaction(...)` returns one base64 string containing the full signed
  output, including any dummies the server added.
- `SignTransactions(...)` returns one concatenated base64 string for the full
  signed group.
- `SignTransactionsList(...)` returns per-slot base64 strings.
- `PlanGroup(...)` returns unsigned `TX`-prefixed hex transactions plus a
  mutation report.
- passthrough entries are supplied through `SignOptions.Passthrough`
- foreign planning uses empty auth-address slots plus optional
  `SignOptions.LsigSizes`

The Go SDK does not provide a `SendRawTransaction(...)` helper. Decode the
returned base64 string and submit it with the standard Algorand Go SDK.

## Error Handling

Main sentinel errors:

- `aplane.ErrAuthentication`
- `aplane.ErrSigningRejected`
- `aplane.ErrSignerUnavailable`
- `aplane.ErrSignerLocked`
- `aplane.ErrKeyNotFound`
- `aplane.ErrKeyDeletion`
- `aplane.ErrTokenNotFound`

Transaction submission helpers in your own code may also choose to wrap:

- `aplane.ErrLogicSigRejected`
- `aplane.ErrInsufficientFunds`
- `aplane.ErrInvalidTransaction`
- `aplane.ErrTransactionRejected`

Example:

```go
signed, err := client.SignTransaction(txn, "", nil)
if err != nil {
	switch {
	case errors.Is(err, aplane.ErrAuthentication):
		return fmt.Errorf("bad or missing token: %w", err)
	case errors.Is(err, aplane.ErrSignerLocked):
		return fmt.Errorf("signer is locked: %w", err)
	case errors.Is(err, aplane.ErrSigningRejected):
		return fmt.Errorf("operator rejected the signing request: %w", err)
	default:
		return err
	}
}
```

## Advanced Notes

- `LoadConfig(...)` also understands client-side `algod` configuration and can
  build an `algod` client with `Config.NewAlgodClient(...)`.
- `LoadToken(...)`, `LoadTokenFromDir(...)`, `ResolveDataDir(...)`,
  `ResolvePath(...)`, `Base64ToBytes(...)`, `BytesToBase64(...)`,
  `HexToBytes(...)`, and `BytesToHex(...)` are exported for integration code.
- `SignRequestsWithContext(...)` and `PlanRequestsWithContext(...)` let you
  bypass the transaction-to-request builder when you need raw request control.
- Signing request deadlines are approval-wait-aware. A shorter caller context
  deadline still wins; SDK `/sign` calls include a `request_id` and send a
  best-effort `/sign/cancel` when the caller context is canceled before the
  signer responds.
- `CancelSignRequestWithContext(...)` exposes explicit synchronous sign-request
  cancellation for advanced callers that already know a request ID.
- Go is the reference SDK shape for caller-initiated cancellation: pass a
  cancelable context to the signing call and the SDK will best-effort cancel the
  live signer request if that context ends before apsigner responds.
- If you call `SetHTTPClient(...)` with a client-level timeout, that timeout is
  a hard cap and the SDK cannot extend it for long approval waits.
- `known_hosts` verification is required for SSH unless you deliberately enable
  trust-on-first-use behavior.

## Compatibility Notes

This SDK follows the signer API contract documented in
the signer API contract documented by the main APlane repository.

For compatibility-sensitive changes, check:

- signer API request/response fixtures under `contracts/signerapi/`
- Go contract tests under `go/types_contract_test.go`
- broader testing guidance in the main APlane repository's `docs/DEV_TESTING.md`

## Related Docs

- main APlane repository `docs/USER_INSTALL.md`
- main APlane repository `docs/USER_CONFIG.md`
- main APlane repository `docs/DEV_TESTING.md`
- main APlane repository `docs/ARCH_CONTRACTS.md`
- `go/README.md`
