# APlane Go SDK

Go SDK for signing Algorand transactions via apsigner.

SDK package versions are tracked independently across languages. Use the compatibility notes in each release rather than assuming Go, Python, and TypeScript package versions will match exactly.

The native-Falcon SDK release line requires an APlane signer release after
`v0.35.0`; see [`docs/COMPATIBILITY.md`](../docs/COMPATIBILITY.md).

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
- caller-owned transport via `NewSignerClient(...)`, optionally combined with `SetHTTPClient(...)`

The client's enrolled SSH key is its only credential. There is no API token:
the signer authenticates the SSH connection and attributes every request on
it to that key.

### Remote Connection via SSH

Connect to apsigner on a remote machine through an SSH tunnel:

```go
client, err := aplane.ConnectSSH(
	"signer.example.com",
	"~/aplane/apclient/.ssh/id_ed25519",
	&aplane.SSHConnectOptions{
		SSHPort:         1127,   // default
		Timeout:         30,     // optional explicit shorter request timeout
		SSHSetupTimeout: 60 * time.Second,
		KnownHostsPath:  "~/aplane/apclient/.ssh/known_hosts",
	},
)
if err != nil {
	log.Fatal(err)
}
defer client.Close()
```

TCP dialing and SSH authentication share a separate 60-second setup deadline.
Override it with `SSHSetupTimeout`; use `ConnectSSHWithContext` or
`FromEnvWithContext` for caller cancellation. Established tunnels detach from
the setup deadline and remain active until `Close`.

**Note**: SSH uses the fixed non-secret username `aplane` and public-key
authentication only. A key the signer has not enrolled (or has revoked) fails
the handshake with `aplane.ErrNotEnrolled`.

### Enrolling the Client Key

A new client key must be enrolled once. `RequestEnrollment` opens a
`enroll` SSH session and returns at once with an
`EnrollmentResult`: `Pending` is true when the request was queued for the
operator to approve later in `apadmin` (the normal outcome), false when the
key was already enrolled. `Fingerprint` is the key's SHA256 fingerprint, which
the operator sees. Nothing is stored on the client; connect once the operator
has approved (until then the handshake fails with `aplane.ErrNotEnrolled`):

```go
result, err := aplane.RequestEnrollment(
	"signer.example.com",
	"~/aplane/apclient/.ssh/id_ed25519",
	"ci-runner", // optional display label shown to the operator
	&aplane.EnrollmentOptions{KnownHostsPath: "~/aplane/apclient/.ssh/known_hosts"},
)
if err == nil && result.Pending {
	fmt.Printf("key %s queued; have the operator approve it in apadmin\n", result.Fingerprint)
}
```

`RequestEnrollmentFromEnv` does the same for an endpoint selected from
`endpoints.yaml` (the default signer, or `FromEnvOptions.Endpoint`). A refused
request (for example, a full enrollment queue) returns an error wrapping
`aplane.ErrEnrollment`. The same enrollment can be done from `apshell` with
`enroll`.

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
  config.yaml          # Network and algod settings
  endpoints.yaml       # Signer and cosigner routing
  .ssh/
    id_ed25519         # SSH key: the client's credential
    known_hosts        # Trusted signer host keys
```

Example `endpoints.yaml`:
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

Select a named endpoint or explicitly allow first-use trust for one call:

```go
client, err := aplane.FromEnv(&aplane.FromEnvOptions{
	Endpoint:        "cosigner.qa",
	TrustOnFirstUse: true,
})
```

### Caller-Owned Transport

If your application already owns the SSH tunnel to the signer, build the
signer client directly from its local base URL. The signer attributes the
requests to the key that opened the tunnel; the loopback REST port of a
signer answers only `/health`:

```go
client := aplane.NewSignerClient("http://localhost:11270")
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
locked and exposes `KeysetRevision`, `ApprovalWaitSeconds`, and persistent
operator-facing `Warnings`.

```go
status, err := client.GetStatus()
if err != nil {
	log.Fatal(err)
}
fmt.Println(status.State, status.KeysetRevision, status.Warnings)
```

`KeysetRevision` is process-local and useful for deciding when to refresh
`/keys`; it is not a durable storage version. `ApprovalWaitSeconds` is used by
the SDK to size `/sign` deadlines. Display non-empty `Warnings` to operators;
they report persistent health conditions that require attention.

#### `ListKeys(refresh bool) ([]KeyInfo, error)`

List available signing keys.

`KeyInfo.LogicSigResources` publishes independent program-byte,
argument-byte, and maximum-opcode-cost demand by authorization path.

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
	{TxnBytesHex: txnHex, LsigResources: &aplane.LogicSigResourceUsage{
		ProgramBytes: 1612, ArgumentBytes: 1423, MaxOpcodeCost: 20000,
	}},
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

#### `SendPrepared(ctx, algodClient, group, opts) (*SendResult, error)`

Sign a prepared transaction or group, check the signed result against what was
prepared, submit exactly those bytes, and wait for confirmation. The SDK picks
the signing flow from the signer's record of each key, so the same call works
for Ed25519, native Falcon, LogicSig, bounded, cosigned and rotating accounts,
and for a rekeyed sender.

```go
prepared, err := client.PreparePayment(ctx, algodClient, aplane.PaymentPrepParams{
	Sender: sender, Receiver: receiver, Amount: 1_000_000, // microAlgos
})
result, err := client.SendPrepared(ctx, algodClient, aplane.NewPreparedGroup(*prepared), nil)
fmt.Println(result.TxIDs[0], result.Outcome, result.ConfirmedRound)
```

`SendPayment(ctx, algodClient, params, opts)` does both steps for an ALGO
payment.

- **Result.** `SignedGroup` is the group as submitted; the first
  `OriginalCount` entries are yours and the rest are resource dummies the
  signer appended. `TxIDs`, `Fees` and `GroupID` are computed from the signed
  bytes. A signer may raise a fee or assign a group, so `TxIDs` can differ from
  the IDs of the transactions you prepared.
- **Options.** `NoWait` returns once the node accepts the group, with outcome
  `submitted`. `WaitRounds` is how many further rounds to wait for
  confirmation (default 10). A cosigned account needs `CosignerClient` with `CosignerComponentKey`, or a
  `CosignerResolver`; the SDK does not close a cosigner client you pass.
- **Refused before signing:** an unknown signing flow
  (`ErrUnsupportedSigningFlow`), and a pre-signed or foreign position
  (`ErrUnsupportedGroup`). Use the lower-level signing calls for those groups.
- **No replacement spends.** The call never builds a second transaction for
  one whose outcome is unknown. A rotating send may prepare and seek approval
  again when the signer says an attempt released no signature.

Failures:

| Error | Meaning | What to do |
|---|---|---|
| The signing call's own error | The signer refused (policy, operator, locked), or the SDK refused the signer's answer (`verify signer response: ...`, `ErrMaxFeeIncreaseExceeded`). Nothing was submitted. | Read the reason. If the SDK refused a sign answer, the signer did sign and the SDK discarded the result. |
| `*SignOutcomeUnknownError` | A signing exchange ended with no answer, or with a 200 answer that could not be read (not one JSON object of the expected shape). A signature may have been released; nothing was submitted. | Check with the operator or the audit log before signing again. For the ordinary flow the error carries the request ID; for a rotating account it carries the prepared group (see below). |
| `*SubmissionRejectedError` | The node refused the group or dropped it from its pool. | Read the reason. The signed bytes and IDs are in the error. |
| `*SubmissionUncertainError` | `Stage` says where it stopped: `unsent` (signed, never sent: your context ended), `submit` (the submission's answer never arrived), or `confirm` (not confirmed within the wait). Except for `unsent`, it may still confirm. | Look up `TxIDs`, or submit the same `SignedGroup` again. Do not sign a replacement until the outcome is known: both could execute. |

A node that answers "already in ledger" has a transaction with the same ID
from an earlier submission of the group. The SDK treats that as submitted and
looks for the outcome; it is not a rejection. A committed transaction that
carries a lease is the exception: the node refuses it for its lease, and the
SDK reports a rejection.

The existing `Sign*` and `Simulate*` calls are unchanged.

#### Rotating accounts

A rotating account (`signing_flow` `rotating1`) hands itself to a fresh stage
on every spend, so the signer adds a rekey to the transaction. `SendPrepared`
and `SendPayment` run the whole sequence:

1. **Prepare.** The signer returns the exact group it will sign: your
   transaction with the rekey to the next stage, its fee raised, and any
   resource dummies.
2. **Check.** The SDK refuses the group unless the only changes are that
   rekey, a reported fee raise within your max fee increase, the group ID and
   canonical dummies.
3. **Simulate, unsigned,** through your algod. A group that fails returns
   `*RotatingPreflightError`, as does an answer with no result for the
   group; a simulation that cannot be run returns a plain error. Either way
   no one-time key has been used.
4. **Sign,** with operator approval, then check the signed group is exactly
   the prepared one.
5. **Submit at once** and wait for confirmation. `SendResult.Rotating` reports
   the stage that signed and the stage that now controls the account.

What to know:

- **One transaction, alone.** A rotating account's transaction must be
  ungrouped, set no `RekeyTo`, not close the account, and take no LogicSig
  arguments. It cannot share a group with other transactions.
- **Short validity window.** The window is at most 100 rounds, and the signer
  signs only while `FirstValid` is at most 2 rounds ahead and at least 10
  rounds remain. Every `Prepare*` helper builds such a window when the sender
  is a rotating account. A transaction whose rounds are not current is
  refused before the operator is asked, and that includes one a helper built
  that has since gone stale: only `SendPayment` rebuilds rounds without the
  option. For a transaction you built yourself,
  set `SendOptions.RefreshValidity` to let the SDK rebuild the rounds; that
  changes the transaction ID, so leave it off if anything outside the
  transaction binds its rounds.
- **App calls carry the rekey.** A contract that requires a zero `RekeyTo`
  fails the simulation in step 3.
- **Bounded retries.** When the signer says an attempt released no signature
  (`rotating_stage_unproven`, `rotating_stage_changed`,
  `rotating_window_not_current`), the send prepares again, up to three
  attempts. Each attempt needs approval again. A timing refusal is retried
  only when the rounds may be rebuilt, and the retry uses the longest window
  to give the operator time.
- **`ResolveAuthAddress` returns the account itself** as the `AuthAddress` of
  a rotating account at every stage; the stage address the chain reports is
  in `ChainAuthAddress`. The `Prepare*` helpers use it.
- **The SDK cannot derive stage addresses.** It binds the next stage's
  address the signer reports to the prepared transaction; the signer derives
  it again from the seed before it signs.
- **Unsigned simulation checks effects, not signatures.** The node runs the
  stage program only on the signed group.
- **Two sends in a row** work once the first has confirmed, which the default
  wait ensures. Two spends prepared from the same stage cannot both land; the
  SDK does not serialize other clients or processes.

The steps are also available one at a time. None of them submits:

```go
prepared, err := client.PrepareRotating(ctx, txn, nil)              // nothing signed
simulation, err := client.SimulatePreparedRotating(ctx, algodClient, prepared) // never signs
signed, err := client.SignPreparedRotating(ctx, prepared, nil)       // waits for approval
result, err := client.SubmitSignedGroup(ctx, algodClient, signed.SignedGroup, nil)
```

Submit a signed rotating group promptly: the stage's one-time keys are
revealed until that transaction or a later rotation confirms.

**If a sign answer is lost** (`*SignOutcomeUnknownError`, whose `Rotating`
field holds the prepared group), call `SignPreparedRotating` again with that
same prepared group. It asks for the same transaction with the same IDs and
builds no second spend. It needs approval again and succeeds only while the
stage is still live and the window still acceptable. If the retry is refused,
do not prepare a replacement until the first attempt's outcome is known:
`rotating_stage_changed` means a transaction from that stage has confirmed.

`SubmitSignedGroup` also submits again the `SignedGroup` kept by a
`*SubmissionUncertainError`; the same bytes can execute only once.

A rotating account that was rekeyed to an ordinary key the signer holds has
left rotation. The `Prepare*` helpers name that key as its `AuthAddress`, and
it is then signed like any rekeyed account. `SendPrepared` confirms the rekey
on the chain first, so an ordinary key is never asked to sign for an account
that is still rotating. Recovery of an unknown stage is an
operator action (`rotate recover` in apshell).

### Config Helpers

#### `LoadConfig(dataDir) (*Config, error)`

Load client configuration from `config.yaml`, applying SDK defaults where the
file omits network or algod values. Routing is loaded separately with
`LoadClientEndpointRegistry`.

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

## Supported Key Types

| Key Type | Description | Notes |
|----------|-------------|-------|
| `ed25519` | Native Algorand keys | Standard signing |
| `falcon1024` | Native post-quantum keys | Protocol-native Falcon-1024 signature (`PQsig`) |
| `aplane.falcon1024.v1` | Post-quantum plain host | Enabled by default. With bounds (transfer kinds, a recipient list, or limits only) a `bounded2` account; without, `plain1`, with no host rules or fee ceiling. `cosigned1` signing flow with a cosigner, `bounded1` without one |
| `aplane.ed25519.v1` | Ed25519 plain host | Library-visible; the same bounds and overlays as `aplane.falcon1024.v1`, and the spending key is classical |
| `aplane.witness-falcon1024.v1` | Witness key | Cosigner-custodied policy signature key; not a spending account |
| `aplane.htlc.v1` | Hash-locked funds | Requires `preimage` arg |

Only the protocol-native types, `ed25519` and `falcon1024`, and the Falcon plain
host, `aplane.falcon1024.v1`, are enabled by default. The operator must enable any other type on the node (`apadmin keytype
enable <type>` or the apadmin KeyType Library) before key generation accepts
it; until then generation fails with "key type ... is not enabled on this
node". Enablement gates only creating keys: existing keys of a disabled type
keep signing.

## Cosigner And Cosigned Accounts

Witness keys enrolled as cosigners use 52-character public selectors for policy-signature
keys. They are not Algorand spending accounts and must not be used as senders,
receivers, auth addresses, or rekey targets. A cosigned account (signing flow
`cosigned1`) embeds the cosigner public key and is assembled through
`/sign/assemble`; ordinary `/sign` is not sufficient for its slots. Sign it with
`SignPreparedCosignedGroup`, below. `RequestComponents` and `RequestAssemble` are
the low-level calls that helper makes, for applications that own the
orchestration.

### Bounded Cosigner Accounts

Corridor uses the bounded contract `bounded2`, and a cosigned plain host
`plain1`, with the distinct `cosigned1` online signing flow, which carries spends and rekeys. A rekey to
an address on the account's rekey-to list needs no cosigner: the signer's base
component names its `path`, and the helper skips the cosigner for it. The contract identifies the LogicSig
rules; the flow identifies the user-first multi-endpoint choreography. The
prepared helper detects that flow from signer inventory and routes it
automatically:

```go
result, err := aplane.SignPreparedCosignedGroup(aplane.PreparedCosignedGroupOptions{
	UserClient:     userClient,
	CosignerResolver: cosignerResolver,
	PreparedGroup:  preparedGroup,
})
signedGroup := result.SignedGroup
```

The SDK first freezes the complete canonical group through `/plan`; the user
signer then approves those bytes through `RequestComponents` with
`kind: "bounded-base"`. It then signs ordinary positions, and only after
the user side is complete does it request cosigner signatures over the same
bytes and call `RequestAssemble`. Before
signing anything, the SDK compares the
signer-produced plan with the caller's prepared group: only reported fee
pooling and group-ID assignment are accepted, and appended positions must be
canonical budget dummies. The returned group must use canonical transaction
encoding and a group ID recomputed from the presented membership. The SDK also
verifies ordinary signed positions and every assembled transaction against the
frozen transaction bytes.

`RequestComponentsWithContext` sends best-effort `/sign/cancel` when its
approval-bearing request is canceled or times out. `RequestAssemble`
does not open an approval request and is not a cancellation handle.

The signer planner owns fee selection, authorization-resource sizing, and any
reported group mutations for the cosigned flow.

Applications that own orchestration can call `RequestComponents` and
`RequestAssemble` directly. The cosigner signs spends and
cosigned rekeys, never a rekey to a listed address.

## Error Handling

```go
import "errors"

signed, err := client.SignTransaction(txn, "", nil)
if err != nil {
	if errors.Is(err, aplane.ErrAuthentication) {
		log.Println("Connection is not authenticated by an enrolled SSH key")
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

## LogicSig Resource Planning

The signer plans LogicSig program bytes, argument bytes, and opcode cost as
independent consensus resources. Under v42, excess program bytes are paid by
the group fee; dummies are added only when argument or opcode capacity
requires them. The SDK submits transactions and lets the signer finalize fees,
membership, and the group ID before signing:

```go
signed, err := client.SignTransaction(txn, "", nil)
signedBytes, _ := aplane.Base64ToBytes(signed)
txid, _ := algodClient.SendRawTransaction(signedBytes).Do(ctx)
```

### Fee Impact

| Key Type | Dummies Added | Signer's Charge |
|----------|---------------|-----------------|
| `ed25519` | 0 | 0 |
| `falcon1024` (native) | 0 | 2,000 µAlgo native-PQ contribution |
| `aplane.falcon1024.v1` (LogicSig) | 1 | 1,000 µAlgo (the dummy's base fee) |

Figures assume a 1,000 µAlgo minimum fee. The LogicSig row is a program of
about 1,800 bytes with a signature argument of at most 1,423 bytes: the
argument exceeds the 1,000-byte per-transaction allowance, so the signer adds
one dummy, and the two-transaction group's 2,000 free program bytes cover the
program.

Build transactions with ordinary suggested fees, plus whatever your own
execution needs (for example, fee credit for an app's inner transactions). The
signer adds its charge on top and never counts a fee surplus toward it, because
it cannot tell a spare fee from one reserved for inner transactions, so
prepaying the charge pays it twice. Pre-grouped groups are immutable: their
fees must already include the charge, as `/plan` output does.

## License

MIT

## Project

This SDK is part of the APlane project:

- Repository: https://github.com/aplane-algo/aplanesdk
- SDK path: `go`

APlane is an open-source project stewarded by the APlane Project.

See the repository [README](https://github.com/aplane-algo/aplanesdk/blob/main/README.md) for project overview and alpha-status guidance, and [DISCLAIMER.md](https://github.com/aplane-algo/aplanesdk/blob/main/DISCLAIMER.md) for risk, liability, and usage information.
