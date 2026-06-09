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

**Note**: SSH uses 2FA (token + public key). The token is passed as the SSH username.

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
| `aplane.timed-whitelist.v1` | Time-locked allow-list | No signature, TEAL-only |
| `aplane.htlc.v1` | Hash-locked funds | Requires `preimage` arg |

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
