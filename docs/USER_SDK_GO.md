# Go SDK Guide

Use the APlane Go SDK to sign Algorand transactions through `apsigner`
from Go applications and services.

The Go module path is `github.com/aplane-algo/aplanesdk/go`. It uses
the same client data directory and SSH-backed connection model as `apshell`,
but it also supports a caller-owned transport mode for advanced integrations.

## Overview

The Go SDK is a user-facing integration surface for:

- loading client config and the client SSH identity from `APCLIENT_DATA`
- enrolling the client SSH key at a signer (operator-approved)
- connecting to `apsigner` over the standard SSH-backed product path
- listing signer keys and available key types
- sending a transaction or group in one call (sign, check, submit and wait
  for confirmation) for every account type the signer holds
- finding a cosigned account's cosigner from `endpoints.yaml`
- planning and signing single transactions and groups without submitting them
- assembling multi-party group results
- building an `algod` client from the same client config
- constructing a signer client from a caller-owned base URL and HTTP client

Package versions are tracked independently across languages. Do not assume the
Go, Python, and TypeScript SDK package versions will always match.

## Requirements

- Go `1.26` or newer for this module as currently declared
- an APlane signer you can reach over the standard SSH-backed client path
- either:
  - an existing client data directory with config, an enrolled SSH key, and
    `known_hosts`, or
  - explicit signer host, enrolled SSH key, and `known_hosts` paths, or
  - a caller-owned SSH tunnel to the signer API

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

APlane never reads or writes the operating-system user's personal SSH
directory. Managed SSH keys and host trust live under `<data_dir>/.ssh/`.

Resolution order (the SDK has no implicit default — `ResolveDataDir` returns an
error if neither is set):

1. explicit `DataDir`
2. `APCLIENT_DATA`

Typical client layout (installer default: `~/aplane/apclient`):

```text
<data_dir>/
  config.yaml
  endpoints.yaml
  .ssh/
    id_ed25519
    known_hosts
```

The SDK reads:

- `config.yaml` for network and optional algod config
- `endpoints.yaml` for signer/cosigner `ssh://` URLs and SSH paths
- `.ssh/id_ed25519` for client SSH auth; the enrolled key is the client's only
  credential, and the signer attributes every request on the tunnel to it. The signer accepts Ed25519, ECDSA (P-256/384/521), or hardware-backed `sk-` Ed25519/ECDSA client keys; RSA and DSA keys fail authentication.
- `.ssh/known_hosts` for SSH host key verification

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

First-use trust is a runtime option:
`FromEnvOptions{TrustOnFirstUse: true}`. It is not stored in
`endpoints.yaml`.

## First-Time Setup

If you already installed APlane locally or in client-only mode, the easiest
path is:

1. install APlane and create or obtain an `apclient` data directory
2. generate or provide the client SSH key under `.ssh/id_ed25519`
3. enroll that key at the signer
4. connect with `aplane.FromEnv(...)`

Ask for enrollment with the Go helper. The signer answers at once with an
`EnrollmentResult`: `Pending` is true when the request was queued for the
operator to approve later in `apadmin` (the normal outcome), false when the
key was already enrolled; `Fingerprint` is the key's SHA256 fingerprint:

```go
result, err := aplane.RequestEnrollmentFromEnv(
	&aplane.FromEnvOptions{Endpoint: "cosigner.qa"},
	"ci-runner", // optional display label shown to the operator
)
if err == nil && result.Pending {
	fmt.Printf("key %s queued; have the operator approve it in apadmin\n", result.Fingerprint)
}
```

`RequestEnrollmentFromEnv(...)` uses the same data-dir resolution as
`FromEnv(...)`, selects the default signer or named endpoint, and uses that
endpoint's SSH host, port, key, and `known_hosts` path. Nothing waits for the
operator and nothing is stored on the client: the key is its credential, and
you connect once the operator has approved. The same enrollment can be done
from `apshell` with `enroll`. A key the signer has not enrolled
yet (or has revoked) fails `FromEnv`/`ConnectSSH` with
`aplane.ErrNotEnrolled`.

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
- validates `config.yaml` contains no obsolete routing
- loads and selects an endpoint from `endpoints.yaml`
- resolves SSH paths relative to the client data dir
- establishes the SSH tunnel automatically

`FromEnv(...)` requires:

- a default signer endpoint, or an explicit endpoint alias
- a readable, enrolled private key at that endpoint's `identity_file`

You can override the defaults:

```go
client, err := aplane.FromEnv(&aplane.FromEnvOptions{
	DataDir: "/custom/path",
	Endpoint: "cosigner.qa",
	Timeout: 30,
})
```

### Explicit SSH Connection

```go
client, err := aplane.ConnectSSH(
	"signer.example.com",
	"~/aplane/apclient/.ssh/id_ed25519",
	&aplane.SSHConnectOptions{
		SSHPort:         1127,
		Timeout:         30, // optional explicit shorter request timeout
		SSHSetupTimeout: 60 * time.Second,
		KnownHostsPath:  "~/aplane/apclient/.ssh/known_hosts",
		TrustOnFirstUse: false,
	},
)
if err != nil {
	return err
}
defer client.Close()
```

SSH setup has a separate 60-second default covering TCP dialing and
authentication. `SSHSetupTimeout` overrides that setup deadline without
shortening approval-bearing HTTP requests. Use `ConnectSSHWithContext` or
`FromEnvWithContext` when the caller must cancel setup; a successful connection
detaches from the setup context and remains active until `Close`.

The SSH username is the fixed non-secret value `aplane`, and public-key
authentication with the enrolled key is the only credential. The explicit form
of enrollment is `aplane.RequestEnrollment(host, keyPath, label,
&aplane.EnrollmentOptions{KnownHostsPath: ...})`.

This is useful when:

- you do not want to depend on `APCLIENT_DATA`
- you manage the SSH identity out-of-band
- your app needs to choose the signer target dynamically

### Caller-Owned Transport

The Go SDK also supports a lower-level mode where your application already owns
the SSH tunnel to `apsigner`. The signer attributes the requests to the key
that opened the tunnel; a signer's loopback REST port answers only `/health`.

```go
client := aplane.NewSignerClient("http://127.0.0.1:11270")
client.SetHTTPClient(&http.Client{Timeout: 30 * time.Second})
defer client.Close()
```

Use this when:

- your process already created the SSH tunnel
- you proxy signer traffic through another transport
- you need custom HTTP behavior such as retry or tracing middleware

## Sending Transactions

### Send A Payment Or A Prepared Group

`SendPayment` and `SendPrepared` are the recommended way to send. One call
signs a transaction or group, checks the signed result, submits exactly those
bytes and waits for confirmation:

```go
result, err := client.SendPayment(ctx, algodClient, aplane.PaymentPrepParams{
	Sender:   sender,
	Receiver: receiver,
	Amount:   1_000_000, // microAlgos
}, nil)
if err != nil {
	return err // see Send Failures below
}
fmt.Println(result.TxIDs[0], result.Outcome, result.ConfirmedRound)
```

`SendPayment` builds the payment with `PreparePayment` and sends it.
`SendPrepared` sends what a `Prepare*` helper built, one transaction or a
group:

```go
group, err := client.PreparePaymentGroup(ctx, algodClient, []aplane.PaymentPrepParams{
	{Sender: sender, Receiver: receiverA, Amount: 1_000_000},
	{Sender: sender, Receiver: receiverB, Amount: 2_000_000},
})
if err != nil {
	return err
}
result, err := client.SendPrepared(ctx, algodClient, *group, nil)
```

Wrap one prepared transaction with `aplane.NewPreparedGroup(*prepared)`.

The same call works for every account type: Ed25519, native Falcon, LogicSig,
bounded, cosigned and rotating accounts, and a rekeyed sender. You do not
look up the auth address or choose the signing flow:

- the `Prepare*` helpers read each sender's auth address from the chain and
  name the key that signs in `AuthAddress`;
- the send reads the signer's own record of that key and picks the flow from
  it: ordinary `/sign` for Ed25519, native Falcon, LogicSig and bounded
  accounts, the cosigned sequence for an account with a cosigner, and the
  rotating sequence for a rotating account;
- it signs, with operator approval where the signer asks for it, and checks
  the signed group against what was prepared, with the checks in
  [What The SDK Checks Before Returning](#what-the-sdk-checks-before-returning);
- it submits exactly those bytes and waits for confirmation.

Every position must name, in `AuthAddress`, a key this signer holds, as the
`Prepare*` helpers do.

`SendResult` carries:

- `SignedGroup`: the group as submitted, hex msgpack. The first
  `OriginalCount` entries are your transactions, in order; the rest are
  resource dummies the signer appended.
- `TxIDs`, `Fees` (microAlgos) and `GroupID`, computed from the signed bytes.
  The signer may raise a fee or assign a group ID, so `TxIDs` can differ from
  the IDs of the transactions you prepared.
- `Mutations`: the signer's report of what it changed, checked against the
  signed bytes; nil when it changed nothing.
- `Outcome` (`SendOutcomeConfirmed`, or `SendOutcomeSubmitted` with `NoWait`)
  and `ConfirmedRound`, zero unless confirmed.
- `Confirmation`: what go-algorand-sdk's `transaction.WaitForConfirmation`
  returned for the first transaction of the signed group, unchanged; nil
  unless confirmed. Read inner transactions, logs and created IDs from it as
  in any go-algorand-sdk program.
- `Flow`: empty for the ordinary flow, `SigningFlowCosigned1` or
  `SigningFlowRotating1`. `Cosigned` holds a cosigned send's component
  responses and `Rotating` a rotating send's stages.

`SendOptions` (nil for the defaults):

- `NoWait`: return once go-algorand-sdk's submit call returns success, with
  outcome `submitted`.
- `WaitRounds`: the round count given to go-algorand-sdk's
  `transaction.WaitForConfirmation`; zero means 10.
- `RefreshValidity`: let a rotating account's send rebuild the transaction's
  validity rounds; see [Rotating Accounts](#rotating-accounts).
- `CosignerClient` with `CosignerComponentKey`, or `CosignerResolver`: a
  cosigned account's cosigner, when it is not found from `endpoints.yaml`;
  see [Finding The Cosigner](#finding-the-cosigner). The send does not close
  a cosigner client you pass.

What go-algorand-sdk's wait does: `transaction.WaitForConfirmation` reads
the current round L and looks the transaction up. Then, until it has looked
`WaitRounds` times, it waits for the block after round L+1, then L+2, and so
on, and looks again. A wait of N rounds is N lookups: one now, and one after
each of rounds L+2 to L+N. It then waits for the block after round L+N
without looking and times out, so a wait of 1 can miss a confirmation in the
next round. A pool error or a failed status read ends the wait at once; a
failed lookup does not. Your context is passed to every request, so ending
it ends the wait. A `WaitRounds` near the largest `uint64` overflows inside
go-algorand-sdk (L plus `WaitRounds` wraps around) and the wait times out at
once. An algod client built by this SDK's `Config.NewAlgodClient` gives each request 30 seconds for the node to start answering; a wait-for-block request held longer than that fails and ends the wait.

Refused before anything is signed:

- `ErrUnsupportedSigningFlow`: a key needs a signing flow this SDK version
  cannot run. Upgrade the SDK.
- `ErrUnsupportedGroup`: a group the send does not cover, such as a
  pre-signed or foreign position, or a rotating account's transaction in a
  group.
- `ErrKeyNotFound`: a position names a key the signer does not hold.

The `Sign*` and `Plan*` calls under [Common Tasks](#common-tasks) remain for
callers who want signed bytes without the SDK submitting them: to submit
through their own node or pipeline, to hold a signed group, or to sign a
group the send does not take, such as a multi-party group with passthrough
positions. They do not submit and do not wait.

### Rotating Accounts

A rotating account (signing flow `rotating1`) hands itself to a fresh stage
on every spend, so the signer adds a rekey to the next stage to your
transaction. Inside `SendPrepared` and `SendPayment` the SDK:

1. asks the signer to prepare the exact group it will sign: your transaction
   with the rekey, its fee raised, and any resource dummies;
2. refuses that group unless the only changes are the rekey, a reported fee
   raise within your max fee increase, the group ID and canonical dummies;
3. simulates it, unsigned, through your algod. A failure returns
   `*RotatingPreflightError`, whose `Message` says why, before any one-time
   key is used;
4. asks the signer to sign, with operator approval, and checks that the
   signed group is exactly the prepared one;
5. submits at once and waits for confirmation. `SendResult.Rotating` reports
   the stage that signed (`Stage`), the stage that now controls the account
   (`Target`), its address (`RekeyTo`) and how many times the spend was
   prepared (`Attempts`).

Limits:

- **One transaction, alone.** It must be ungrouped, set no `RekeyTo`, not
  close the account, and take no LogicSig arguments. The send refuses
  anything else with `ErrUnsupportedGroup` before it asks the signer.
- **Short validity window.** At most `RotatingMaxValidityWindow` (100)
  rounds, and the signer signs only while `FirstValid` is at most
  `RotatingMaxLead` (2) rounds ahead of the current round and at least
  `RotatingMinRemaining` (10) rounds remain. The `Prepare*` helpers build such
  a window for a rotating sender. A transaction whose rounds are not current
  is refused before the operator is asked.
- **When the send rebuilds the rounds.** `SendPayment` builds its own
  transaction, so it may rebuild stale rounds. For a transaction you prepared
  or built, set `SendOptions.RefreshValidity` to allow it. That changes the
  transaction ID, so leave it off when anything outside the transaction, such
  as an app argument or a proof, binds its rounds.
- **Bounded retries.** When the signer says an attempt released no signature
  (`ErrCodeRotatingStageUnproven`, `ErrCodeRotatingStageChanged`,
  `ErrCodeRotatingWindowNotCurrent`), the send prepares again, up to three
  attempts, and each attempt needs approval again. A window refusal is
  retried only when the rounds may be rebuilt, with the longest window. This
  needs a signer that reports `rotating_window_not_current`; see the
  [compatibility note](COMPATIBILITY.md).
- **App calls carry the rekey**, so a contract that requires a zero
  `RekeyTo` fails the simulation.
- **Two sends in a row** work once the first has confirmed, which the default
  wait ensures.

The steps are also available one at a time, for callers who need them. None
of them submits:

```go
prepared, err := client.PrepareRotating(ctx, txn, nil)                         // nothing signed
simulation, err := client.SimulatePreparedRotating(ctx, algodClient, prepared) // never signs
signed, err := client.SignPreparedRotating(ctx, prepared, nil)                 // waits for approval
result, err := client.SubmitSignedGroup(ctx, algodClient, signed.SignedGroup, nil)
```

Submit a signed rotating group promptly: the stage's one-time keys are
revealed until that transaction or a later rotation confirms.

If a sign answer is lost (a `*SignOutcomeUnknownError` whose `Rotating` field
holds the prepared group), call `SignPreparedRotating` again with that same
prepared group. It asks for the same transaction with the same IDs and builds
no second spend. Do not call `SendPayment` or `SendPrepared` again until the
first attempt's outcome is known: that prepares a new spend from the same
stage.

For a rotating account, `ResolveAuthAddress` returns the account itself as
`AuthAddress` at every stage; the stage address the chain reports is in
`ChainAuthAddress`. A rotating account rekeyed to an ordinary key the signer
holds has left rotation, and is sent like any rekeyed account once the chain
confirms the rekey.

### Send Failures

| Error | What it means | What to do |
|---|---|---|
| `*SignOutcomeUnknownError` | A signing request ended with no answer, or with a 200 answer that could not be read. A signature may have been released. Nothing was submitted. | Do not send again. See [After An Unknown Outcome](#after-an-unknown-outcome), or check `RequestID` with the operator or the signer's audit log. |
| `*SubmissionError` | The group was signed, and go-algorand-sdk's submit or confirmation wait returned an error, or your context ended before one of them. `Err` is that error, unchanged. `Submitted` is true when the submit call returned success and the failure came later. When it is false, a cause that is go-algorand-sdk's `common.BadRequest` is algod's HTTP 400: the node refused the group. Any other cause leaves it open whether the node has the group, because the answer may have been lost. `SignedGroup`, `TxIDs` and `LastValid` are kept. | Do not sign a replacement. See [After An Unknown Outcome](#after-an-unknown-outcome). |
| `*RotatingPreflightError` | A rotating spend failed its unsigned simulation. Nothing was signed. | Read `Message`. |
| `ErrUnsupportedSigningFlow`, `ErrUnsupportedGroup`, `ErrKeyNotFound`, `ErrCosignerDiscovery` | Refused before anything that can execute was signed. | Read the reason. |
| Any other error | The signer refused (policy, operator, locked), or the SDK refused its answer (`verify signer response: ...`, `*MaxFeeIncreaseError`). Nothing was submitted. | Read the reason. When the SDK refused a sign answer, the signer did sign and the SDK discarded the result. |

Two of these must not be answered by sending again:

- `*SignOutcomeUnknownError`: the signer may have released a signature that
  never reached you. A replacement you build and sign, and that signature,
  could both execute. Find out what happened, or wait until the error's
  `LastValid` round has passed, first.
- `*SubmissionError`: the signed group may already be in a block or in the
  node's pool, and a replacement could execute beside it. Submitting the
  same `SignedGroup` again cannot pay twice: the same bytes execute at most
  once.

Any other error means nothing that was signed can execute: the send was
refused before signing, the signer refused, or the SDK refused the signer's
answer and discarded it. It is safe to fix the cause and send again.

### After An Unknown Outcome

The SDK does not look an unknown outcome up for you. A node can show that a
transaction confirmed, but not that it never did. What to do depends on the
error:

- A signed group whose submit or wait failed (`*SubmissionError`). The
  error carries `SignedGroup`, `TxIDs` and `LastValid`, and go-algorand-sdk's
  error as its cause in `Err` (also reached through `errors.As` and
  `errors.Unwrap`). Read the cause as you would in any go-algorand-sdk
  program.
  - `Submitted` true: follow the group with `transaction.WaitForConfirmation`
    on `TxIDs[0]` (a group confirms as a whole), waiting `LastValid` minus
    the current round, at least 1. A timeout from the wait means only that
    the wait ended.
  - `Submitted` false, and the cause is algod's HTTP 400, which
    go-algorand-sdk returns as a `common.BadRequest` (package
    `client/v2/common`): the node answered and refused the group. Read the
    reason; submitting the same bytes again gets the same answer.
  - `Submitted` false with any other cause (no answer, a lost connection, a
    5xx, your context ended): the node may or may not have the group. First
    follow `TxIDs[0]` with `transaction.WaitForConfirmation` for a few
    rounds. If it does not confirm, submit the same `SignedGroup` again with
    `SubmitSignedGroup`. If that comes back as a 400 whose text says the
    transaction is already in the ledger, the node has it: follow the ID.

  Submitting the same signed group again cannot pay twice. After `LastValid`
  the node refuses the group as dead whether or not it confirmed. Once
  `LastValid` has passed, neither a node's "not found" nor a refusal proves
  the group never confirmed: a node only looks back about 1000 rounds from
  its current round. Check an indexer before building a replacement.
- Nothing was submitted (`*SignOutcomeUnknownError`, any account that is not
  rotating). A signature may exist that the SDK never received. Once
  `LastValid` has passed, nothing signed by that request can execute, and a
  replacement is safe. No lookup is needed. Before that, do not build a
  replacement with different transaction IDs.
- Rotating accounts (`*SignOutcomeUnknownError` whose `Rotating` field holds
  the prepared group). Sign the same prepared group again with
  `SignPreparedRotating`, and submit the result with `SubmitSignedGroup`. It
  produces the same transaction IDs, so it cannot pay twice. See
  [Rotating Accounts](#rotating-accounts).

```go
result, err := client.SendPayment(ctx, algodClient, params, nil)
var failure *aplane.SubmissionError
if errors.As(err, &failure) {
	var refused common.BadRequest
	if !failure.Submitted && errors.As(err, &refused) {
		// algod answered 400 and refused the group: read the reason.
		return err
	}
	if !failure.Submitted {
		// The node may or may not have the group.
		return fmt.Errorf("%w: follow %s for a few rounds; if it does not confirm, submit the same SignedGroup again with SubmitSignedGroup", err, failure.TxIDs[0])
	}
	status, statusErr := algodClient.Status().Do(ctx)
	if statusErr != nil {
		return fmt.Errorf("%w (read current round: %v)", err, statusErr)
	}
	rounds := uint64(1)
	if failure.LastValid > status.LastRound {
		rounds = failure.LastValid - status.LastRound
	}
	info, waitErr := transaction.WaitForConfirmation(algodClient, failure.TxIDs[0], rounds, ctx)
	if waitErr != nil {
		// Only the wait ended. Do not build a replacement on the strength of it.
		return fmt.Errorf("%w (wait: %v)", err, waitErr)
	}
	fmt.Println(failure.TxIDs[0], info.ConfirmedRound)
	return nil
}
if err != nil {
	return err
}
fmt.Println(result.TxIDs[0], result.ConfirmedRound)
```

### Cancellation And Time Limits

The send and the step calls take a `context.Context`. The send sets no
deadline of its own: each signing request waits as long as the signer's
approval wait allows, unless the client was given a shorter `Timeout`, and a
shorter context deadline wins. Where the context ends decides what you get:

- before an approval-bearing request is posted (while keys, rounds or the
  plan are read, or between steps): a plain error, not an unknown outcome.
  Nothing more is sent, not even a `/sign/cancel`.
- while an approval-bearing request (`/sign`, `/sign/component`,
  `/sign/assemble`, `/sign/rotating/sign`) is waiting: a best-effort
  `/sign/cancel`, then `*SignOutcomeUnknownError`.
- after signing, before the submit call: `*SubmissionError` with
  `Submitted` false and the context's error as `Err`. The group was not
  posted; `SubmitSignedGroup` submits it.
- during the submit call: the context is passed to go-algorand-sdk's
  `SendRawTransaction`, and its error comes back in `*SubmissionError` with
  `Submitted` false. The node may still have the group.
- after the submit call returned success, when the send waits:
  `*SubmissionError` with `Submitted` true, whether the context ended before
  the wait or during it. The context is passed to
  `transaction.WaitForConfirmation` too.

## Common Tasks

### Health Check

```go
healthy, err := client.Health()
```

### Signer Status

```go
status, err := client.GetStatus()
if err != nil {
	return err
}
fmt.Println(status.State, status.KeysetRevision, status.ApprovalWaitSeconds)
```

`GetStatus(...)` calls authenticated `/status`. It does not require the
signer to be unlocked; a locked signer is returned as status data. Use
`KeysetRevision` as a process-local signal to refresh `/keys` only when the
loaded keyset changes. Do not treat it as a durable version across apsigner
restarts.

The SDK also uses `ApprovalWaitSeconds` to size `/sign` deadlines. If discovery
fails or the field is missing or out of range, signing falls back to a
6-minute deadline.

`Warnings` and `Notes` are operator-facing lines. `Rotating` lists each
rotating account's view from the signer's last background pass
(`RotatingAccountStatus`: observed authorizer, classification, cached stages
and `Recovery`); it is empty while locked or without rotating accounts. Stage
recovery itself (`/admin/rotating/recover`) is an operator action run from
apshell, so the SDK carries only its wire shapes (`RotatingRecoverRequest`,
`RotatingRecoverResponse`).

### List Keys

```go
keys, err := client.ListKeys(true)
if err != nil {
	return err
}
for _, key := range keys {
	fmt.Println(key.Address, key.KeyType, key.LogicSigResources)
}
```

`ListKeys(...)` returns `[]aplane.KeyInfo` with fields such as:

- `Address`
- `PublicKeyHex`
- `KeyType`
- `LogicSigResources`
- `IsGenericLsig`
- `SigningArgs`
- `TemplateProvenanceStatus`
- `TemplateProvenanceNote`

`LogicSigResources` publishes independent program-byte, argument-byte, and
maximum-opcode-cost demand by authorization path. Non-bounded LogicSig keys
publish a `Default` profile. Bounded keys publish exactly two paths, `Spend`
and `SpendingRekey`, which may differ: a rekey selects `SpendingRekey` and
every other transaction selects `Spend`.

`KeyTypeInfo.AuthorizationKind` distinguishes `ed25519`, `native_pq`, and
`logic_sig`. Do not infer Ed25519 from `RequiresLogicSig == false`: native
Falcon-1024 also has a false compatibility boolean.

`KeyInfo.AuthorizationKind` reports the same closed values for a key instance
and is authoritative for choosing its transaction authorization envelope. It
is empty for witness keys, which are not spending accounts, and whenever the
signer does not report it; never read an empty value as Ed25519.
Prefer it over `LogicSigResources != nil`, because a native Falcon-1024
spending key publishes no LogicSig profile and is otherwise indistinguishable
from an Ed25519 key. `SignPreparedCosignedGroup` sends no size hint for a
position the signer holds: it names the position's `AuthAddress`, and the
signer sizes the position from its own records and can put the group's
authorization charge on it. Setting `PQScheme` or `LsigResources` on such a
position is an error.

`BoundedAuthorization.Rekey` is a bounded account's rekey setting:
`spending_key` lets the spending key rekey the account, and `refused` means the
account refuses rekeys, except to an address on its rekey-to list when it has
one. The SDK fails a rekey on a bounded key that has neither. `BoundedAuthorization.Contract`
is `bounded2` on a bounded host, or `plain1` on a plain host such as
`aplane.falcon1024.v1`, which has no host rules: every transaction that doesn't
rekey is a spend, closes included. `BoundedAuthorization.MaxFee` is the bounded host's fee
ceiling and is optional: a plain host has none, so it is `nil`. Never read
its absence as zero.

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
- explicit mnemonic import support through `MnemonicImport` (native types only)
- per-key types through `PerKeyContract`, and whether one takes a boundary file
  through `BoundarySchema`: `aplane.boundary.v1` on the general bounded type,
  empty on a plain host, whose parameters are given directly

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

The `Sign*` calls in this and the following sections return signed bytes and
submit nothing. Use them when you want the signed transactions yourself; to
send, use `SendPayment` or `SendPrepared` (see
[Sending Transactions](#sending-transactions)).

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

For a rekeyed account, these calls take the signing key explicitly. (The
`Prepare*` helpers read it from the chain for you, so `SendPayment` and
`SendPrepared` need nothing extra; `ResolveAuthAddress` does that lookup on
its own.)

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

An empty auth address means the sender signs for itself, and the args then
apply to the sender. `LsigArgsMap` is keyed by auth address. A key that is no position's
authorizer is an error. A position's authorizer is its auth address, not its
sender when the account is rekeyed: for a passthrough position it is the
signer its signed bytes name, and for a foreign position, where nothing names
one, the sender. A key whose only positions in the request are passthrough or
foreign is accepted, and its args are not sent, because the request does not
sign for that address; this lets one map serve the plan and the final signing
of the same group. An entry with no args is
ignored.

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
	LsigResources: map[int]aplane.LogicSigResourceUsage{
		2: {ProgramBytes: 1612, ArgumentBytes: 1423, MaxOpcodeCost: 20000},
	},
}

plan, err := client.PlanGroup(txns, authAddresses, lsigArgsMap, opts)
```

`SignOptions.Passthrough` values are base64-encoded signed transaction msgpack
from another signer and must already carry the intended group ID. The SDK
decodes them and sends them as passthrough slots. They must be standard base64
with padding: a string that is not (a line break or other whitespace, URL-safe
characters, missing padding, data after the padding) is refused, as the Python
and TypeScript SDKs refuse it. `Base64ToBytes(...)` is that decoder and
refuses the same strings. `SignOptions.LsigResources`
describes unsigned foreign slots for `/plan` and must also accompany a final
passthrough LogicSig slot on `/sign`. Reuse the same selected
authorization-path values; the signer verifies the declared program and
argument byte counts against the signed envelope before accepting the
immutable group.

For a foreign native Falcon-1024 slot, use raw `SignRequest.PQScheme` or
`PreparedTransaction.PQScheme` with value `"f1"`. It is mutually exclusive
with `LsigResources` and declares native-PQ fee usage rather than LogicSig
resources.

`PlanRequestsWithContext(...)` is the per-slot planning API. Prefer it over
the address-keyed `PlanGroup(...)` convenience form when two transactions use
the same authorization address with different LogicSig arguments or app-call
metadata.

For actual signing with passthrough slots, use:

- `SignTransactionsWithOptions(...)`
- `SignTransactionsListWithOptions(...)`

Foreign slots are only supported on `/plan`; they must be resubmitted as
passthrough for final signing.

### Multi-Party Groups

A group that another party also signs goes through the signer in two steps:

1. Plan it with `PlanGroup(...)`, leaving the other party's positions foreign
   (an empty auth address) and declaring `SignOptions.LsigResources` for any
   that are LogicSigs. The plan is the final group: its group ID, and any fees
   and dummies the signer adds.
2. The other party signs its transaction from the planned group. Sign the
   planned group with `SignTransactionsWithOptions(...)`, passing that signed
   transaction as a passthrough position in `SignOptions.Passthrough` and
   repeating the same `LsigResources`.

The result is the complete signed group, ready to submit. `SendPrepared`
does not take passthrough positions, so a multi-party group is signed with
these calls and you submit it:

```go
signed, err := client.SignTransactionsWithOptions(plannedTxns, authAddresses, nil, &aplane.SignOptions{
	Passthrough: map[int]string{1: otherPartySignedBase64},
})
if err != nil {
	return err
}

signedBytes, err := aplane.Base64ToBytes(signed)
if err != nil {
	return err
}

txid, err := algodClient.SendRawTransaction(signedBytes).Do(ctx)
```

### Cosigned Accounts

Cosigned accounts (signing flow `cosigned1`) need component signatures from both
the user signer and a cosigner signer. A cosigned account is a plain host such
as `aplane.falcon1024.v1` created with a cosigner, or a bounded account with
one, such as Corridor. Either kind without a cosigner advertises `bounded1` and
signs through ordinary `/sign`. Cosigner component selectors are public policy keys, not
Algorand spending accounts, and must not be used as senders, receivers, auth
addresses, or rekey targets.

`SendPrepared` and `SendPayment` run the whole cosigned sequence and submit
the result. `SignPreparedCosignedGroup` runs the same sequence and returns
the signed group without submitting it.

#### Finding The Cosigner

A client created from a data directory (`FromEnv` or `FromEnvWithContext`)
finds a cosigned account's cosigner in its own `endpoints.yaml`. List the
cosigner node as an endpoint with role `cosigner`:

```yaml
schema_version: 2
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://signer.example.com:1127
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
  cosigner:
    role: cosigner
    url: ssh://cosigner.example.com:1127
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
```

The key in `identity_file` must be enrolled at the cosigner too
(`RequestEnrollmentFromEnv` with `Endpoint: "cosigner"`). When a send, or
`SignPreparedCosignedGroup`, is given no `CosignerClient` and no
`CosignerResolver`, the client then:

- connects, on first use, to every `role: cosigner` endpoint (at most 12),
  each with its own identity file and known hosts file and with the client's
  trust-on-first-use, SSH setup timeout and request timeout, and reads its
  `/keys`;
- signs with the one endpoint that lists the account's witness key, under its
  Witness Key ID;
- keeps those connections, and closes them when you `Close` the client.

An explicit `CosignerClient` (with `CosignerComponentKey`) or
`CosignerResolver` always wins. A client made with `ConnectSSH` or
`NewSignerClient` has no endpoint registry, so it needs one of them; without
one, a cosigned send is refused with "cosigner client or resolver is
required". `NewEndpointCosignerResolver(dataDir, opts)` builds the same
resolver for you to pass as `CosignerResolver`; it owns the connections it
opens, so `Close` it when done.

Every cosigner a position is sure to need is found before anything is asked
to sign, so a cosigner that cannot be found fails the send with nothing
signed. The error matches `aplane.ErrCosignerDiscovery` and is never an
unknown outcome. Its message says why:

- no endpoint lists the witness key: the message names every cosigner
  endpoint with its state (`ok`, `unreachable`, `locked`,
  `authentication failed`, `invalid cosigner metadata` or
  `configuration invalid`);
- more than one endpoint lists it;
- `endpoints.yaml` lists no cosigner endpoint;
- a cosigner endpoint's SSH host key differs from the pinned one.

A rekey to an address on the account's rekey-to list needs no cosigner. For
such a rekey the cosigner is looked up only after the user signer's base
component, and only if that component says the rekey needs one, so a listed
rekey works with no cosigner endpoint configured and with the cosigner down.

#### Cosigner Policy

Before signing, an operator must apply a policy document for the selected
cosigner Witness Key ID using `apadmin policy check` and `apadmin policy apply`.
The cosigner stores it as `policies/<WitnessKeyID>.json` with a `.hmac`
sidecar in the active generation. A key with no document of its own follows
the cosigner's node default, which as shipped rejects every transaction type,
so a newly generated key rejects every request until its document is applied.
This requirement also applies to bounded cosigner accounts such as Corridor.

If the cosigner holds the key but it is still on the deny-all default,
`/sign/component` returns HTTP 403 with `code: "forbidden"` and a
`transaction_type:<type>` rule ID in the error message. `RequestComponents`
returns `ErrSigningRejected`, and the cosigned signing helper propagates that
error. Apply the key's document before retrying. See the
[compatibility note](COMPATIBILITY.md) for policy format and provisioning details.

#### The Cosigned Sequence

The helper reads each position's key (its signing flow, LogicSig resources
and fee ceiling) from the user signer's `/keys` record, by the position's
auth address. A prepared transaction carries no key of its own. It is the
lookup the prepare helpers make: the spendable key for the address (a witness
key is never chosen), from a key list the client caches. Each call checks the
signer's keyset revision with one `/status` request and fetches `/keys` again
only when the revision has changed, so a key added or replaced on the signer
is picked up by the next call. An address with no spendable key is
refused with `ErrKeyNotFound`.

For manual orchestration, use `RequestComponents` on the user client with a
bounded-base target and on the cosigner client, then `RequestAssemble` on the
user client. Finish the user side (the base components and any ordinary-position
signing) before requesting cosigner components, so a cosigner never sees a group
the user signer rejects.

A cosigned account's LogicSig contract is `plain1` on a plain host, or
`bounded2` on a bounded account such as Corridor, and its online signing flow is
`cosigned1`. These are separate compatibility dimensions. A cosigned account's
spends and declared rekeys need the cosigner; a rekey to an address on its
rekey-to list does not, and the signer's base component says which (`path`), so
the helper asks the cosigner only for the targets that need it.
It checks a planned fee against the account's ceiling only on `bounded2`: a
`plain1` account has none. Before any request it refuses an account whose
contract it doesn't know, a `bounded2` account without a ceiling, and a `plain1`
account that advertises one.
`SignPreparedCosignedGroup` discovers the flow from signer inventory and performs
the user-first sequence. With a client from `FromEnv` the cosigner comes from
`endpoints.yaml`:

```go
result, err := aplane.SignPreparedCosignedGroup(aplane.PreparedCosignedGroupOptions{
	UserClient:    userClient,
	PreparedGroup: preparedGroup,
})
if err != nil {
	return err
}
signedGroup := result.SignedGroup
```

Set `CosignerClient` and `CosignerComponentKey`, or `CosignerResolver`, in
the options to name the cosigner yourself.

The sequence is `/plan`, user approval and base-component release through
`RequestComponents` with a bounded-base target, signing of ordinary group
positions, cosigner signing over the frozen group, and final `RequestAssemble`
on the user signer. Before requesting any additional signature, the SDK accepts only
mutation-report-declared fee pooling and group-ID assignment to the caller's
prepared positions, and requires every appended position to be a canonical
budget dummy. It verifies ordinary signed positions and every assembled
transaction against the frozen canonical bytes. Those two bounded methods are
also public for applications that own the orchestration.

The signer planner owns fee selection, authorization-resource sizing, and any
reported group mutations for the cosigned flow.

Base-component signing (the user signer's bounded-base request) runs the
signer-domain approval gates and can block on a manual operator decision. The
SDK automatically discovers the signer's `approval_wait_seconds` and sizes the
request deadline accordingly, exactly like `/sign`; cosigner-role component
requests stay on the short deterministic deadline.

Full simulation uses ordinary executable signing and the caller's algod. The
signer does not have a simulation endpoint and does not know whether the caller
will simulate or submit the released group. Policy, review, approval, assembly,
and audit behavior are therefore identical to submission.

```go
simulation, err := userClient.SimulatePreparedGroup(
	ctx,
	algodClient,
	preparedGroup,
)
if err != nil {
	return err
}
if simulation.Failed {
	// simulation.FailureMessage says why; simulation.Response has the
	// algod diagnostics.
}

cosigned, err := aplane.SimulatePreparedCosignedGroup(algodClient, cosignedOptions)
```

`SimulationResult.SignedGroup` contains fully executable signed transactions
that remain submittable until expiry. Keep them confidential. The helper sends
the exact signed group to the supplied algod with empty-signature overrides
disabled. A missing algod client fails before any signing request. A
simulation is `Failed` unless the node returned exactly one group result,
that result reports no failure, and it holds one transaction result per
transaction simulated. `FailureMessage` says why: the node's own failure
message, or which of the other cases it was. Transport or decoding failures
return an error and never trigger another signing request automatically.

## Transaction Semantics

- `SignTransaction(...)` returns one base64 string containing the full signed
  output, including any dummies the server added.
- `SignTransactions(...)` returns one concatenated base64 string for the full
  signed group.
- `SignTransactionsList(...)` returns per-slot base64 strings.
- These simple sign calls return only the signed transactions. To read what
  the signer changed (the fee it added, the group ID, appended dummies), call
  `SignRequestsWithContext(...)`, whose `GroupSignResponse.Mutations` is the
  mutation report, already checked against the request.
- Amounts and fees in the `*PrepParams` types are in microAlgos; an asset
  amount is in the asset's base units, not adjusted for its decimals.
- A foreign app or asset reference, and an ABI `application` or `asset`
  argument, must not be zero. A box's app index may be zero (the called app).
- Group helpers check every sender against everything it pays across the
  group: the ALGO it sends plus the fee of every position it sends, asset
  transfers included. The check is named `group_algo_balance`. It reads each
  sender's spendable ALGO from the `spendable_algo` check that the payment and
  asset-transfer helpers record on every position (the lowest value, when a
  sender has several positions), and refuses a position
  that lacks that check or whose `available` value is not a `uint64`
- `PrepareAsaTransfer(...)` checks the transfer's fee against the sender's spendable ALGO
  itself, so one transfer is refused alone exactly as it is in a group. Its
  `asa_transfer` check records the fee.
- `PlanGroup(...)` returns unsigned `TX`-prefixed hex transactions plus a
  mutation report.
- `SimulateGroup(...)` and `SimulatePreparedGroup(...)` perform ordinary
  signing, then use the caller-provided algod simulation endpoint.
- passthrough entries are supplied through `SignOptions.Passthrough`
- foreign planning uses empty auth-address slots plus optional
  `SignOptions.LsigResources`
- `SendPrepared(...)` and `SendPayment(...)` sign, submit and wait; their
  `SendResult.SignedGroup` is hex msgpack, one entry per transaction.
- `SubmitSignedGroup(...)` submits a signed hex group exactly as given (a
  rotating group from `SignPreparedRotating`, or the `SignedGroup` a
  `*SubmissionError` kept) and waits for confirmation. It signs
  nothing.

`SendPrepared` and `SendPayment` submit for you. There is no
`SendRawTransaction(...)` helper for the base64 the `Sign*` calls return:
decode it and submit it with the standard Algorand Go SDK.

### What The SDK Checks Before Returning

Every `/sign` and `/plan` result is checked against the request before
`SignTransaction(...)`, `SignTransactions*(...)`, `SignRequestsWithContext(...)`/`SignGroupWithContext(...)`, `PlanGroup(...)`/`PlanRequestsWithContext(...)` or the simulation helpers returns it, and before `SendPrepared(...)` submits anything. The
signer may change a request in three ways, and must report each in
`mutations`:

- raise the fee of a position it signs, listed in `fees_modified`, with the
  sum of the raises equal to `total_fees_delta`
- assign the group ID, which must be the ID computed over the returned group
- append resource dummies, counted in `dummies_added`

Anything else fails with an error whose message starts with
`verify signer response:` or `verify signer plan:`, and nothing is returned:

- a signed or planned position that differs from the requested transaction in
  any field the report does not cover
- a signed position that carries no authorization, more than one, or a
  multisig
- an authorization that is not the requested auth address's (the auth address
  you passed, or the sender when you passed none): an Ed25519 signature that
  does not verify over the transaction under that address; a LogicSig whose
  program address is not that address, or one delegated by a signature; a
  native Falcon proof whose scheme is not `f1`, whose public key or signature
  is missing, or whose account address is not that address. The Falcon
  signature itself is not verified.
- a signer field (`sgnr`) that does not name the auth address when it differs
  from the sender, or that is present when the sender signs for itself
- a fee change that is unreported, is not an increase, or does not add up to
  the reported total
- any reported change (a fee raise, a group ID, an appended dummy) to a
  request whose transactions already carried a group ID. The signer never
  changes such a group, and positions it does not return would stay bound to
  the original one.
- report counts (`original_count`, `final_count`, `dummies_added`,
  `passthrough_count`, `foreign_count`) that disagree with the request and
  the returned group
- an appended position that is not exactly the signer's resource dummy for
  that group, or that carries any authorization but the dummy LogicSig
- a passthrough position that does not come back byte for byte, or a foreign
  position that comes back signed
- signed transaction bytes that are not canonical msgpack, including bytes
  after the signed transaction

#### Limiting The Fee Increase

The checks above confirm that a fee raise is reported, not that it is
reasonable: the signer writes the report, so by default a reported raise of
any size is accepted. Set `SetMaxFeeIncrease(...)` on the client to put your own ceiling on it.
The value is in microAlgos and bounds the total the signer adds across all
positions of one request. Zero means the signer may not raise any fee. When
the raises add up to more than the ceiling, every sign, plan and simulate call
through that client fails with an error and returns nothing, so nothing can be
submitted or simulated.
The per-account `max_fee` check in the cosigned flow still applies as well.
The refusal is a `*aplane.MaxFeeIncreaseError` carrying `Raised` and `Limit`;
match it with `errors.As`, or with `errors.Is(err, aplane.ErrMaxFeeIncreaseExceeded)`.

```go
client.SetMaxFeeIncrease(200_000) // microAlgos, summed over the request
signed, err := client.SignTransaction(txn, "", nil)
var refused *aplane.MaxFeeIncreaseError
if errors.As(err, &refused) {
	// verify signer response: signer raised fees by 5000000 microAlgos,
	// more than the max fee increase 200000 set on this client
	log.Printf("signer asked for %d, ceiling is %d", refused.Raised, refused.Limit)
}
```

`ClearMaxFeeIncrease()` removes the ceiling and `MaxFeeIncrease()` reports it.
To have it in place before the client is returned, set the `MaxFeeIncrease`
field (a `*uint64`) of `SSHConnectOptions` or `FromEnvOptions`.

What counts toward the ceiling is everything the signer adds to the fees of
your transactions. A resource dummy carries a zero fee of its own, but the
signer charges each dummy's base fee to one of your transactions, and that
raise counts. So for a LogicSig account the raise includes the dummies' base
fees and the charge for the program's size; for a native Falcon account it is
the post-quantum signature charge. Measured against a live signer on a local
test network:

| Request | Dummies appended | Fee raise (microAlgos) |
|---|---|---|
| two payments, Ed25519 account | 0 | 0 |
| one payment, LogicSig Falcon account | 1 | 1000 |
| two payments, LogicSig Falcon account | 1 | 1074 |
| one payment, native Falcon account | 0 | 2000 |

These figures depend on the account type, the group's size and the network's
fee rules, which is why there is no default: any built-in number would be a
guess. Choose a ceiling that fits the accounts you sign for. To see the
charge, call `PlanGroup(...)` with your transactions and read
`Mutations.TotalFeesDelta` in the result.

Two limits to know:

- The ceiling is checked on each request by itself. If you plan and then send
  the planned transactions to sign, the sign request is measured from the
  already-raised fees, so the signer could raise them by up to the ceiling a
  second time. Send your original transactions to sign, not the planned ones.
  A plan is for looking at what the signer will do. The multi-party flow is
  not affected: a group sent with passthrough positions is already grouped,
  and the signer cannot change the fees of a group that is.
- Each request is held to the ceiling in force when that request starts. A
  single sign or plan call is one request. The cosigned helpers make several
  (a plan, then one or more sign requests), and each of those reads the
  ceiling when it starts, so a change made part-way applies to the requests
  that follow. On a plan call a refusal
  comes before the signer asks anyone for approval. On a sign or simulate
  call the check runs after the signer has answered: by then the signer has
  already asked for approval and produced a signature. The SDK discards that
  signature and returns nothing, but the approval was spent. To refuse before
  any approval is asked for, plan the same transactions first on a client
  with the same ceiling, then sign the originals.

The SDK decodes request entries before sending them. Unsigned transaction
bytes must be `TX`-prefixed canonical msgpack and passthrough entries must be
canonical signed transactions, and the auth address of a position to sign
must be a valid Algorand address, or the call fails before any request is made.
A passthrough transaction must round-trip through the SDK's Algorand
library (`go-algorand-sdk`), so one that uses a field newer than that library is refused
locally.

#### How Signer Answers Are Read

Every 200 answer from the signer, the key list included, is read strictly:
it must be exactly one JSON value, so a `null` body or anything after the
value is an error, never an empty answer, and a field left out or `null`
reads as its zero value. An answer whose `error` field is set is a refusal,
and at an approval-bearing request an answer that cannot be read counts as a
lost answer, which a send reports as `*SignOutcomeUnknownError`. The full
rule, and how the three SDKs' readers differ, is in
[`go/README.md`](../go/README.md) under `SendPrepared`.

## Error Handling

A send's failures are described in [Send Failures](#send-failures). Every
call returns the signer's refusals as errors you match with `errors.Is` or
`errors.As`.

Main sentinel errors:

- `aplane.ErrAuthentication`
- `aplane.ErrSigningRejected`
- `aplane.ErrSignerUnavailable`
- `aplane.ErrSignerLocked`
- `aplane.ErrKeyNotFound`
- `aplane.ErrKeyDeletion`
- `aplane.ErrNotEnrolled`
- `aplane.ErrEnrollment`
- `aplane.ErrMaxFeeIncreaseExceeded`, with `*aplane.MaxFeeIncreaseError` for
  the amounts: the signer raised fees by more than the client's max fee
  increase
- `aplane.ErrUnsupportedSigningFlow` and `aplane.ErrUnsupportedGroup`: a send
  refused the group before signing
- `aplane.ErrCosignerDiscovery`: a cosigned account's cosigner was not found
  in `endpoints.yaml`

Typed errors, matched with `errors.As`:

- `*aplane.SignOutcomeUnknownError`, `*aplane.SubmissionError` and
  `*aplane.RotatingPreflightError`: see [Send Failures](#send-failures)
- `*aplane.APIError`: any other signer refusal, with its HTTP `StatusCode`,
  its stable `Code` (such as `aplane.ErrCodeRotatingStageChanged`) and its
  `Message`

Example:

```go
result, err := client.SendPayment(ctx, algodClient, params, nil)
if err != nil {
	var unknown *aplane.SignOutcomeUnknownError
	var failure *aplane.SubmissionError
	switch {
	case errors.As(err, &unknown), errors.As(err, &failure):
		// Do not send again: see After An Unknown Outcome.
		return err
	case errors.Is(err, aplane.ErrAuthentication):
		return fmt.Errorf("connection is not authenticated by an enrolled SSH key: %w", err)
	case errors.Is(err, aplane.ErrSignerLocked):
		return fmt.Errorf("signer is locked: %w", err)
	case errors.Is(err, aplane.ErrSigningRejected):
		return fmt.Errorf("operator rejected the signing request: %w", err)
	default:
		return err
	}
}
fmt.Println(result.TxIDs[0])
```

## Advanced Notes

- `LoadConfig(...)` also understands client-side `algod` configuration and can
  build an `algod` client with `Config.NewAlgodClient(...)`. When
  `networks_allowed` is set in `config.yaml`, `NewAlgodClient` refuses a network
  that is not on it, and loading the config refuses a default network that is
  not on it. The list must hold network IDs written as text: a bare
  number, `true`/`false` or an empty entry is refused, so quote a name such as
  `"1"`. Quote a network name that YAML could read as a boolean, such as `"on"`, `"yes"` or `"no"`. The `network` value follows the same rule: it must be text and a network ID, and a bare number or `true`/`false` is refused.
- `ResolveDataDir(...)`,
  `ResolvePath(...)`, `Base64ToBytes(...)`, `BytesToBase64(...)`,
  `HexToBytes(...)`, and `BytesToHex(...)` are exported for integration code.
- `SignRequestsWithContext(...)` and `PlanRequestsWithContext(...)` let you
  bypass the transaction-to-request builder when you need raw request control.
- Signing request deadlines are approval-wait-aware. A shorter caller context
  deadline still wins; SDK `/sign` calls include a `request_id` and send a
  best-effort `/sign/cancel` when the caller context is canceled before the
  signer responds. A context that has already ended before a request is
  posted sends nothing, not even the cancel.
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

This SDK follows the signer API contract documented by the main APlane
repository. Before upgrading the SDK or the signer, read the
[compatibility note](COMPATIBILITY.md).

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
