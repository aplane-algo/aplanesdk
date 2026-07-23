# APlane Go SDK

Go SDK for signing Algorand transactions via apsigner.

SDK package versions are tracked independently across languages. Use the compatibility notes in each release rather than assuming Go, Python, and TypeScript package versions will match exactly.

## Installation

```bash
go get github.com/aplane-algo/aplanesdk/go
```

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/aplane-algo/aplanesdk/go"
)

func main() {
	dataDir, err := aplane.ResolveDataDir("")
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := aplane.LoadConfig(dataDir)
	if err != nil {
		log.Fatal(err)
	}

	// Connect to signer
	client, err := aplane.FromEnv(&aplane.FromEnvOptions{DataDir: dataDir})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Build transaction with go-algorand-sdk
	algodClient, err := cfg.NewAlgodClient(cfg.Network)
	if err != nil {
		log.Fatal(err)
	}
	params, _ := algodClient.SuggestedParams().Do(context.Background())

	txn, _ := transaction.MakePaymentTxn(
		"SENDER_ADDRESS",
		"RECEIVER_ADDRESS",
		1000000, // 1 ALGO
		nil, "", params,
	)

	// Sign via apsigner (waits for operator approval)
	signed, err := client.SignTransaction(txn, "", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Submit using standard go-algorand-sdk (signed is base64)
	signedBytes, _ := aplane.Base64ToBytes(signed)
	txid, _ := algodClient.SendRawTransaction(signedBytes).Do(context.Background())
	fmt.Printf("Submitted: %s\n", txid)
}
```

## Connection Methods

The Go SDK supports two connection styles:

- managed signer connections through `ConnectSSH(...)` or `FromEnv(...)`
- caller-owned transport via `NewSignerClientWithToken(...)`, optionally combined with `SetHTTPClient(...)`

### Remote Connection via SSH

Connect to apsigner on a remote machine through an SSH tunnel with 2FA:

```go
client, err := aplane.ConnectSSH(
	"signer.example.com",
	"your-token",           // used for both SSH auth and HTTP API
	"~/.ssh/id_ed25519",
	&aplane.SSHConnectOptions{
		SSHPort:    1127,   // default
		SignerPort: 11270,  // default
		Timeout:    30,     // optional explicit shorter request timeout
	},
)
if err != nil {
	log.Fatal(err)
}
defer client.Close()
```

**Note**: SSH verifies the enrolled public key, then performs a programmatic
mutual proof of the token bound to the accepted host key and fresh nonces. The
SSH username is the non-secret identity ID; the bearer token is never sent as
SSH metadata.

### Environment-Based Connection

Load configuration from a data directory:

```go
// Reads APCLIENT_DATA from the environment (errors if unset)
client, err := aplane.FromEnv(nil)

// Or specify the data directory explicitly
client, err := aplane.FromEnv(&aplane.FromEnvOptions{
	DataDir: "~/aplane/apclient",
})
```

Data directory structure (installer default: `~/aplane/apclient`):
```
<data_dir>/
  config.yaml          # Connection settings
  aplane.token         # Authentication token
  .ssh/
    id_ed25519         # SSH key
    known_hosts        # Trusted signer host keys
```

Example `config.yaml`:
```yaml
network: testnet
networks_allowed: [testnet]
theme: auto
endpoint:
  signer_port: 11270
  ssh:
    host: signer.example.com
    port: 1127
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    trust_on_first_use: false
networks:
  testnet:
    algod:
      server: https://testnet-api.4160.nodely.dev
      token: ""
```

If you want Trust-On-First-Use host enrollment, set:

```yaml
endpoint:
  ssh:
    trust_on_first_use: true
```

That allows the SDK to trust and save the signer's SSH host key into `known_hosts` on first connection.

### Caller-Owned Transport

If your application already owns the tunnel or HTTP transport, build the signer
client directly from a base URL and token:

```go
client := aplane.NewSignerClientWithToken("http://localhost:11270", token)
client.SetHTTPClient(&http.Client{Timeout: 30 * time.Second})
defer client.Close()
```

This mode is intended for advanced callers that already control the connection
path to `apsigner`. If you set `http.Client.Timeout`, it is a hard cap on
every request, including approval-backed signing; the SDK cannot extend a
caller-owned transport timeout.

## API Reference

### SignerClient

#### `Health() (bool, error)`

Check if signer is reachable.

```go
healthy, err := client.Health()
```

#### `GetStatus() (*StatusResponse, error)`

Fetch authenticated signer status. This endpoint works while the signer is
locked and exposes `KeysetRevision` plus `ApprovalWaitSeconds`.

```go
identity, err := client.GetStatus()
if err != nil {
	log.Fatal(err)
}
fmt.Println(identity.State, identity.KeysetRevision)
```

`KeysetRevision` is process-local and useful for deciding when to refresh
`/keys`; it is not a durable storage version. `ApprovalWaitSeconds` is used by
the SDK to size `/sign` deadlines.

#### `ListKeys(refresh bool) ([]KeyInfo, error)`

List available signing keys.

`KeyInfo.LsigSize` is the spend-path LogicSig budget. For `bounded1`, it
excludes the external contract-admin signature slot; the admin-inclusive size
is available as `KeyInfo.BoundedAuthorization.PostSigningLogicSigSize`.

The SDK exposes bounded inventory and ordinary spend signing only. It does not
build, partially sign, or complete contract-admin rekey transactions; use the
APlane `aprekey` workflow for those operations.

```go
keys, err := client.ListKeys(false)
for _, key := range keys {
	fmt.Printf("%s [%s]\n", key.Address, key.KeyType)
}
```

#### `SignTransaction(txn, authAddress, lsigArgs) (string, error)`

Sign a single transaction. Returns base64-encoded signed transaction.

```go
// Basic signing
signed, err := client.SignTransaction(txn, "", nil)

// Rekeyed account
signed, err := client.SignTransaction(txn, "AUTH_KEY_ADDRESS", nil)

// Generic LogicSig with runtime args
signed, err := client.SignTransaction(
	txn,
	hashlockAddress,
	aplane.LsigArgs{"preimage": preimageBytes},
)
```

#### `SignTransactions(txns, authAddresses, lsigArgsMap) (string, error)`

Sign multiple transactions as a group. Returns concatenated base64.

**Important**: Do NOT pre-assign group IDs. The server computes the group ID.

```go
signed, err := client.SignTransactions(
	[]types.Transaction{txn1, txn2},
	[]string{authAddr1, authAddr2},
	nil,
)
```

#### `GetKeysResponseWithContext(ctx) (*KeysResult, error)`

Fetch the raw `/keys` response plus local locked-state reporting. `Locked` is
derived from a locked-signer HTTP response and is not part of the `/keys` JSON
payload.

```go
keysResp, err := client.GetKeysResponseWithContext(ctx)
if err != nil {
	log.Fatal(err)
}
if keysResp.Locked {
	log.Fatal("signer is locked")
}
```

#### `PlanRequestsWithContext(ctx, requests) (*PlanGroupResponse, error)`

Post raw `/plan` requests directly without rebuilding them from
`types.Transaction`.

```go
planResp, err := client.PlanRequestsWithContext(ctx, []aplane.SignRequest{
	{TxnBytesHex: txnHex, LsigSize: 3035},
})
```

#### `SignRequestsWithContext(ctx, requests) (*GroupSignResponse, error)`

Post raw `/sign` requests directly and receive the server-shaped response.

```go
signResp, err := client.SignRequestsWithContext(ctx, []aplane.SignRequest{
	{AuthAddress: authAddr, TxnSender: sender, TxnBytesHex: txnHex},
})
```

Signing requests discover `/status.approval_wait_seconds` and use that value
plus 30 seconds of slack for the HTTP deadline. If discovery fails or an older
signer omits the field, the SDK falls back to 6 minutes. A shorter caller
context deadline still wins; SDK `/sign` calls include a `request_id` and send
a best-effort `/sign/cancel` when the caller context is canceled before the
signer responds.

#### `CancelSignRequestWithContext(ctx, requestID) (*CancelSignResponse, error)`

Ask apsigner to cancel a live synchronous `/sign` request by request ID.
Successful responses are idempotent for client behavior and return state
`"canceled"` or `"not_found"`.

Go is the reference SDK shape for caller-initiated synchronous cancellation:
pass a cancelable `context.Context` to `SignRequestsWithContext` or
`SignGroupWithContext`. If that context is canceled before apsigner responds,
the SDK sends best-effort `/sign/cancel` for the generated or supplied
`request_id`.

### Config Helpers

#### `LoadConfig(dataDir) (*Config, error)`

Load client configuration from `config.yaml`, applying SDK defaults where the
file omits values.

#### `(*Config).NewAlgodClient(network) (*algod.Client, error)`

Construct an algod client from the configured network entry.

```go
dataDir, err := aplane.ResolveDataDir("")
if err != nil {
	log.Fatal(err)
}
cfg, err := aplane.LoadConfig(dataDir)
if err != nil {
	log.Fatal(err)
}

algodClient, err := cfg.NewAlgodClient(cfg.Network)
if err != nil {
	log.Fatal(err)
}
```

### Type Compatibility

The SDK uses `PlanGroupResponse` and `RuntimeArg` as its primary names. For
callers migrating from older contract names, `GroupPlanResponse` and
`RuntimeArgInfo` remain available as compatibility aliases.

## Supported Key Types

| Key Type | Description | Notes |
|----------|-------------|-------|
| `ed25519` | Native Algorand keys | Standard signing |
| `aplane.falcon1024.v1` | Post-quantum LogicSig | Large signature (~3KB) |
| `aplane.ed25519.v1` | Ed25519 DSA LogicSig | Library-visible plain DSA account |
| `aplane.witness-falcon1024.v1` | Witness key | Sentry-custodied policy signature key; not a spending account |
| `aplane.falcon1024-sentry1024.v1` | Guarded account | Requires user and sentry component signatures |
| `aplane.corridor.v1` | Bounded Corridor account | `bounded1` contract; `bounded-sentry1` spend flow |
| `aplane.falcon1024-allowlist.v1` | Bounded allowlist | Inline allowlist; `bounded1` signing flow |
| `aplane.falcon1024-allowlist.v2` | Bounded allowlist | Merkle allowlist; `bounded1` signing flow |
| `aplane.falcon1024-timelock.v1` | Bounded timelock | Round-gated `bounded1` signing flow |
| `aplane.falcon1024-allowlist-alock.v1` | Rekey-locked bounded allowlist | Ordinary spending uses `bounded1`; admin rekey is outside SDK scope |
| `aplane.htlc.v1` | Hash-locked funds | Requires `preimage` arg |

## Sentry And Guarded Accounts

Witness keys enrolled as sentries use 52-character public selectors for policy-signature
keys. They are not Algorand spending accounts and must not be used as senders,
receivers, auth addresses, or rekey targets. Guarded account keys embed the
sentry public key and are assembled through `/sign/assemble`; ordinary `/sign`
is not sufficient for guarded slots.

Use the low-level methods when your application owns the orchestration:

```go
userPart, err := userClient.RequestComponentSign(aplane.ComponentSignRequest{
	Role:          aplane.ComponentSignRoleUser,
	ComponentKey:  "GUARDED_ACCOUNT_ADDRESS",
	GroupBytesHex: []string{"5458..."},
	TargetIndices: []int{0},
})

sentryPart, err := sentryClient.RequestComponentSign(aplane.ComponentSignRequest{
	Role:          aplane.ComponentSignRoleSentry,
	ComponentKey:  "SENTRY_COMPONENT_SELECTOR",
	GroupBytesHex: []string{"5458..."},
	TargetIndices: []int{0},
})

assembled, err := userClient.RequestGuardedAssemble(aplane.GuardedAssemblyRequest{
	GroupBytesHex: []string{"5458..."},
	Targets: []aplane.GuardedAssemblyTarget{{
		TargetIndex:     0,
		GuardedAccount:  "GUARDED_ACCOUNT_ADDRESS",
		UserSignature:   userPart.Signatures[0].Signature,
		SentrySignature: sentryPart.Signatures[0].Signature,
	}},
})
```

For the common explicit two-client flow, use `SignGuardedGroup`:

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

`AssembleGroup` is still the local multi-party concatenation helper. It is not
the same operation as server-side guarded `RequestGuardedAssemble`.

### Bounded Sentry Accounts

Corridor uses the bounded contract `bounded1` with the distinct
`bounded-sentry1` online signing flow. The contract identifies the LogicSig
rules; the flow identifies the user-first multi-endpoint choreography. The
prepared helper detects that flow from signer inventory and routes it
automatically:

```go
result, err := aplane.SignPreparedGuardedGroup(aplane.PreparedGuardedGroupOptions{
	UserClient:     userClient,
	SentryResolver: sentryResolver,
	PreparedGroup:  preparedGroup,
})
signedGroup := result.SignedGroup
```

The user signer first approves and freezes the complete canonical group through
`RequestBoundedComponent`. Only then does the SDK request sentry signatures
over those exact bytes, sign any ordinary positions, and call
`RequestBoundedAssemble`. Before signing anything, the SDK compares the
signer-produced plan with the caller's prepared group: only reported fee
pooling and group-ID assignment are accepted, and appended positions must be
canonical budget dummies. It also verifies ordinary signed positions and every
assembled transaction against the frozen transaction bytes.

`PreparedGuardedGroupOptions.MinFee` applies to the legacy `sentry1` path. The
`bounded-sentry1` signer planner owns fee selection and reports its mutations,
so that path ignores `MinFee`.

Applications that own orchestration can call `RequestBoundedComponent` and
`RequestBoundedAssemble` directly. Sentry authorization is spend-only in this
contract; bounded contract-admin rekeys remain an external `aprekey` ceremony
and are not completed by the SDK.

## Error Handling

```go
import "errors"

signed, err := client.SignTransaction(txn, "", nil)
if err != nil {
	if errors.Is(err, aplane.ErrAuthentication) {
		log.Println("Invalid token")
	} else if errors.Is(err, aplane.ErrSigningRejected) {
		log.Println("Operator rejected")
	} else if errors.Is(err, aplane.ErrSignerUnavailable) {
		log.Println("Signer not reachable")
	} else if errors.Is(err, aplane.ErrKeyNotFound) {
		log.Println("Key not in signer")
	} else {
		log.Printf("Error: %v", err)
	}
}
```

## Fee Pooling (Large LogicSigs)

Algorand limits LogicSig size to 1000 bytes per transaction. Large signatures like Falcon-1024 (~3000 bytes) exceed this limit.

The server automatically creates dummy transactions to expand the LogicSig budget pool:

```go
// Falcon-1024 has lsigSize ~3035 bytes, needs 3 dummies
// Server automatically handles this - just sign and submit
signed, err := client.SignTransaction(txn, "", nil)
signedBytes, _ := aplane.Base64ToBytes(signed)
txid, _ := algodClient.SendRawTransaction(signedBytes).Do(ctx)
```

| Key Type | LogicSig Size | Dummies Needed | Extra Fee |
|----------|---------------|----------------|-----------|
| Ed25519 | 0 | 0 | 0 |
| Falcon-1024 | ~3035 | 3 | ~3000 uA |

## License

MIT

## Project

This SDK is part of the APlane project:

- Repository: https://github.com/aplane-algo/aplanesdk
- SDK path: `go`

APlane is an open-source project stewarded by the APlane Project.

See the repository [README](https://github.com/aplane-algo/aplanesdk/blob/main/README.md) for project overview and alpha-status guidance, and [DISCLAIMER.md](https://github.com/aplane-algo/aplanesdk/blob/main/DISCLAIMER.md) for risk, liability, and usage information.
