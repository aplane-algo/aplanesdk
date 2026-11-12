# TypeScript SDK Guide

Use the APlane TypeScript SDK to sign Algorand transactions through
`apsigner` from Node.js applications and scripts.

The published package is `aplanesdk`. It uses the same client data directory and
SSH-backed connection model as `apshell`.

## Overview

The TypeScript SDK is a user-facing integration surface for:

- loading client config and the client SSH identity from `APCLIENT_DATA`
- enrolling the client SSH key at a signer over the `enroll` flow
- connecting to `apsigner` over the standard SSH-backed product path
- listing signer keys and available key types
- sending a transaction or group in one call (sign, check, submit and wait
  for confirmation) for every account type the signer holds
- finding a cosigned account's cosigner from `endpoints.yaml`
- planning and signing single transactions and groups without submitting them
- assembling multi-party group results
- submitting signed transactions with cleaner algod error mapping

Package versions are tracked independently across languages. Do not assume the
Go, Python, and TypeScript SDK package versions will always match.

## Requirements

- Node.js `>=22`, the floor `algosdk` 3.9 sets
- npm, pnpm, or yarn
- an APlane signer you can reach over the standard SSH-backed client path
- either:
  - an existing client data directory with config, an enrolled SSH key, and
    `known_hosts`, or
  - explicit signer host, enrolled SSH key, and `known_hosts` paths

The SDK expects:

- `algosdk` 3.9.0 or later as a peer dependency. Releases before 3.7.0 drop a
  native post-quantum signature (`pqsig`) when they decode a signed transaction,
  which breaks simulation for native Falcon keys; 3.9.0 is the release the SDK
  is tested against, and it requires Node.js 22
- `ssh2` for the SSH-backed runtime path

In a normal package-manager install, `ssh2` is brought in via `aplanesdk`'s
optional dependency. If your environment omits optional dependencies, install
`ssh2` explicitly.

## Installation

The published package name is `aplanesdk` on npm.

### Install From npm

```bash
npm install aplanesdk algosdk
```

Install a specific published version:

```bash
npm install aplanesdk@<version> algosdk
```

If your install omits optional dependencies or the runtime cannot resolve
`ssh2`, add it explicitly:

```bash
npm install aplanesdk algosdk ssh2
```

With pnpm or yarn:

```bash
pnpm add aplanesdk algosdk
yarn add aplanesdk algosdk
```

### Install From A Repo Checkout

For local development against this repository:

```bash
cd typescript
npm install
npm run build
```

You can also pack and install the local tarball into another project:

```bash
cd typescript
npm pack

# In your consuming project
npm install ../path/to/aplanesdk-<version>.tgz algosdk
```

### Verify The Install

Basic import check:

```bash
node --input-type=module -e 'import("aplanesdk").then(m => console.log(typeof m.SignerClient))'
```

## Configuration And Credentials

The TypeScript SDK follows the same client data directory convention as
`apshell`.

APlane never reads or writes the operating-system user's personal SSH
directory. Managed SSH keys and host trust live under `<data_dir>/.ssh/`.

Resolution order (the SDK has no implicit default — `resolveDataDir` throws
`SignerError` if neither is set):

1. explicit `dataDir`
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
`SignerClient.fromEnv({ trustOnFirstUse: true })`.

## First-Time Setup

If you already installed APlane locally or in client-only mode, the easiest
path is:

1. install APlane and create or obtain an `apclient` data directory
2. generate or provide the client SSH key under `.ssh/id_ed25519`
3. enroll that key at the signer
4. connect with `SignerClient.fromEnv()`

Ask for enrollment with the TypeScript helper:

```ts
import { requestEnrollmentFromEnv } from "aplanesdk";

const { fingerprint, pending } = await requestEnrollmentFromEnv({ endpoint: "cosigner.qa", label: "ci-runner" });
if (pending) console.log(`key ${fingerprint} queued; have the operator approve it in apadmin`);
```

`requestEnrollmentFromEnv()`:

- uses the same data-dir resolution as `SignerClient.fromEnv()`
- selects the default signer or named endpoint from `endpoints.yaml`
- uses that endpoint's SSH host, port, key, and `known_hosts` path
- opens an `enroll` SSH session, which answers at once
- resolves to an `EnrollmentResult`: `pending: true` when the request was
  queued for the operator (the normal outcome), `false` when the key was
  already enrolled; `fingerprint` is the key's SHA256 fingerprint. Nothing
  is stored.

Enrollment targets the signer's product store. The operator approves the
request later in `apadmin`; connect after that. The same enrollment can be
done from `apshell` with `enroll`. A key the signer has not
enrolled yet (or has revoked) fails `fromEnv`/`connectSsh` with a
`SignerUnavailableError` whose message says the key is not enrolled.

## Connection Methods

### Recommended: Load From Client Data Dir

```ts
import { SignerClient } from "aplanesdk";

const client = await SignerClient.fromEnv();
try {
  console.log(await client.health());
} finally {
  await client.close();
}
```

This path:

- resolves the client data dir
- refuses a `config.yaml` whose `network` is not in its `networks_allowed`,
  when that list is set, and one whose `networks_allowed` is not a list of
  network IDs written as text (a malformed list is an error, never an empty
  one; a bare number, `true`/`false` or an empty entry is refused, so quote a
  name such as `"1"`). Quote a network name that YAML could read as a boolean, such as `"on"`, `"yes"` or `"no"`. The `network` value follows the same rule: it must be text and a network ID, and a bare number or `true`/`false` is refused.
- validates `config.yaml` contains no obsolete routing
- loads and selects an endpoint from `endpoints.yaml`
- resolves SSH paths relative to the client data dir
- establishes the SSH tunnel automatically
- verifies that the signer answers on the forwarded REST port

`SignerClient.fromEnv()` requires:

- a default signer endpoint, or an explicit `endpoint` alias
- a readable, enrolled private key at that endpoint's `identity_file`

### Explicit SSH Connection

```ts
import { SignerClient, expandPath } from "aplanesdk";

const client = await SignerClient.connectSsh(
  "signer.example.com",
  "~/aplane/apclient/.ssh/id_ed25519",
  {
    sshPort: 1127,
    sshSetupTimeout: 60_000,
    knownHostsPath: expandPath("~/aplane/apclient/.ssh/known_hosts"),
    trustOnFirstUse: false,
  }
);

try {
  console.log(await client.health());
} finally {
  await client.close();
}
```

`sshSetupTimeout` separately bounds TCP dialing and SSH authentication and
defaults to 60 seconds. An optional `signal` cancels setup. Both controls detach
after authentication and do not shorten the established tunnel or operator
approval waits. Enrollment exposes equivalent `setupTimeout` and `signal`
options.

The SSH username is the fixed non-secret value `aplane`, and public-key
authentication with the enrolled key is the only credential. The explicit form
of enrollment is `requestEnrollment(host, sshKeyPath, { knownHostsPath, label })`.

This is useful when:

- you do not want to depend on `APCLIENT_DATA`
- you manage the SSH identity out-of-band
- your app needs to choose the signer target dynamically

Prefer the SSH-backed paths above. For advanced integrations that already own
the SSH tunnel to the signer, the public `SignerClient(baseUrl, timeout)`
constructor can be used directly; the signer attributes the requests to the
key that opened the tunnel, and a signer's loopback REST port answers only
`/health`. An explicit timeout shorter than the signer
approval wait will cancel queued/pending manual approval; SDK `/sign` calls
include a `request_id` and send a best-effort `/sign/cancel` when the HTTP
request times out or disconnects.
High-level signing methods accept `requestId` and `signal` options for
applications that need user-initiated cancellation.

`cancelSignRequest(requestId)` exposes explicit synchronous sign-request
cancellation for advanced callers that already know a request ID.

TypeScript high-level signing generates a request ID by default. Interactive
applications can pass an application-owned ID and an `AbortSignal`; aborting the
signal aborts the HTTP request and sends best-effort `/sign/cancel` with the
same ID:

```ts
const controller = new AbortController();
const requestId = "wallet-ui-approval-123";
const signed = await client.signTransaction(txn, undefined, undefined, {
  requestId,
  signal: controller.signal,
});

// elsewhere, if the user aborts while approval is pending:
controller.abort();
```

## Sending Transactions

### Send A Payment Or A Prepared Group

`sendPayment()` and `sendPrepared()` are the recommended way to send. One
call signs a transaction or group, checks the signed result, submits exactly
those bytes and waits for confirmation:

```ts
const result = await client.sendPayment(algodClient, {
  sender,
  receiver,
  amount: 1_000_000, // microAlgos
});
console.log(result.txIds[0], result.outcome, result.confirmedRound);
```

`sendPayment()` builds the payment with `preparePayment()` and sends it.
`sendPrepared()` sends what a `prepare*` helper built, one transaction or a
group:

```ts
const group = await client.preparePaymentGroup(algodClient, [
  { sender, receiver: receiverA, amount: 1_000_000 },
  { sender, receiver: receiverB, amount: 2_000_000 },
]);
const result = await client.sendPrepared(algodClient, group);
```

Pass one prepared transaction as `{ transactions: [prepared] }`.

The same call works for every account type: Ed25519, native Falcon, LogicSig,
bounded, cosigned and rotating accounts, and a rekeyed sender. You do not
look up the auth address or choose the signing flow:

- the `prepare*` helpers read each sender's auth address from the chain and
  name the key that signs in `authAddress`;
- the send reads the signer's own record of that key and picks the flow from
  it: ordinary `/sign` for Ed25519, native Falcon, LogicSig and bounded
  accounts, the cosigned sequence for an account with a cosigner, and the
  rotating sequence for a rotating account;
- it signs, with operator approval where the signer asks for it, and checks
  the signed group against what was prepared, with the checks in
  [What The SDK Checks Before Returning](#what-the-sdk-checks-before-returning);
- it submits exactly those bytes with algosdk's `sendRawTransaction` and
  waits with algosdk's `waitForConfirmation` on the first transaction ID. It
  reads nothing into either call's answer or error: a failure of either is a
  `SubmissionError` whose `cause` is algosdk's error.

Every position must name, in `authAddress`, a key this signer holds, as the
`prepare*` helpers do.

`SendResult` carries:

- `signedGroup`: the group as submitted, hex msgpack. The first
  `originalCount` entries are your transactions, in order; the rest are
  resource dummies the signer appended.
- `txIds`, `fees` (bigint microAlgos) and `groupId`, computed from the signed
  bytes. The signer may raise a fee or assign a group ID, so `txIds` can
  differ from the IDs of the transactions you prepared.
- `mutations`: the signer's report of what it changed, checked against the
  signed bytes; undefined when it changed nothing.
- `outcome` (`"confirmed"`, or `"submitted"` with `noWait`) and
  `confirmedRound`, a bigint, `0n` unless confirmed.
- `confirmation`: what algosdk's `waitForConfirmation()` returned for the
  first transaction of the signed group, unchanged (algosdk's
  `PendingTransactionResponse`); undefined unless confirmed. Read inner
  transactions, logs and created IDs from it as in any algosdk program.
- `flow`: `""` for the ordinary flow, `"cosigned1"` or `"rotating1"`.
  `cosigned` holds a cosigned send's component responses and `rotating` a
  rotating send's stages.

`SendOptions` (all optional):

- `noWait`: return once algosdk's submit call returns success, with outcome
  `"submitted"`.
- `waitRounds`: how many rounds algosdk's `waitForConfirmation()` waits for
  confirmation; unset or zero means 10 (algosdk's wait given 0 fails without
  looking). The wait takes no signal, so this is what bounds it.
- `refreshValidity`: let a rotating account's send rebuild the transaction's
  validity rounds; see [Rotating Accounts](#rotating-accounts).
- `cosignerClient` with `cosignerComponentKey`, or `cosignerResolver`: a
  cosigned account's cosigner, when it is not found from `endpoints.yaml`;
  see [Finding The Cosigner](#finding-the-cosigner). The send does not close
  a cosigner client you pass.
- `signal`: an `AbortSignal`; see
  [Cancellation And Time Limits](#cancellation-and-time-limits).

Refused before anything is signed:

- `UnsupportedSigningFlowError`: a key needs a signing flow this SDK version
  cannot run. Upgrade the SDK.
- `UnsupportedGroupError`: a group the send does not cover, such as a
  pre-signed or foreign position, or a rotating account's transaction in a
  group.
- `KeyNotFoundError`: a position names a key the signer does not hold.

The `sign*` and `plan*` calls under [Common Tasks](#common-tasks) remain for
callers who want signed bytes without the SDK submitting them: to submit
through their own node or pipeline, to hold a signed group, or to sign a
group the send does not take, such as a multi-party group with passthrough
positions. They do not submit and do not wait.

### Rotating Accounts

A rotating account (signing flow `rotating1`) hands itself to a fresh stage
on every spend, so the signer adds a rekey to the next stage to your
transaction. Inside `sendPrepared()` and `sendPayment()` the SDK:

1. asks the signer to prepare the exact group it will sign: your transaction
   with the rekey, its fee raised, and any resource dummies;
2. refuses that group unless the only changes are the rekey, a reported fee
   raise within your max fee increase, the group ID and canonical dummies;
3. simulates it, unsigned, through your algod. A failure throws
   `RotatingPreflightError`, whose `failureMessage` says why, before any
   one-time key is used;
4. asks the signer to sign, with operator approval, and checks that the
   signed group is exactly the prepared one;
5. submits at once and waits for confirmation. `result.rotating` reports the
   stage that signed (`stage`), the stage that now controls the account
   (`target`), its address (`rekeyTo`) and how many times the spend was
   prepared (`attempts`).

Limits:

- **One transaction, alone.** It must be ungrouped, set no `rekeyTo`, not
  close the account, and take no LogicSig arguments. The send refuses
  anything else with `UnsupportedGroupError` before it asks the signer.
- **Short validity window.** At most `ROTATING_MAX_VALIDITY_WINDOW` (100)
  rounds, and the signer signs only while `firstValid` is at most
  `ROTATING_MAX_LEAD` (2) rounds ahead of the current round and at least
  `ROTATING_MIN_REMAINING` (10) rounds remain. The `prepare*` helpers build
  such a window for a rotating sender. A transaction whose rounds are not
  current is refused before the operator is asked.
- **When the send rebuilds the rounds.** `sendPayment()` builds its own
  transaction, so it may rebuild stale rounds. For a transaction you prepared
  or built, set `refreshValidity: true` to allow it. That changes the
  transaction ID, so leave it off when anything outside the transaction, such
  as an app argument or a proof, binds its rounds.
- **Bounded retries.** When the signer says an attempt released no signature
  (`ErrorCodes.RotatingStageUnproven`, `ErrorCodes.RotatingStageChanged`,
  `ErrorCodes.RotatingWindowNotCurrent`, read from `SignerError.code`), the
  send prepares again, up to three attempts, and each attempt needs approval
  again. A window refusal is retried only when the rounds may be rebuilt,
  with the longest window. This needs a signer that reports
  `rotating_window_not_current`; see the
  [compatibility note](COMPATIBILITY.md).
- **App calls carry the rekey**, so a contract that requires a zero
  `rekeyTo` fails the simulation.
- **Two sends in a row** work once the first has confirmed, which the default
  wait ensures.

The steps are also available one at a time, for callers who need them. None
of them submits:

```ts
const prepared = await client.prepareRotating(txn);                             // nothing signed
const simulation = await client.simulatePreparedRotating(algodClient, prepared); // never signs
const signed = await client.signPreparedRotating(prepared);                     // waits for approval
const result = await client.submitSignedGroup(algodClient, signed.signedGroup);
```

Submit a signed rotating group promptly: the stage's one-time keys are
revealed until that transaction or a later rotation confirms.

If a sign answer is lost (a `SignOutcomeUnknownError` whose `rotating` field
holds the prepared group), call `signPreparedRotating()` again with that same
prepared group. It asks for the same transaction with the same IDs and builds
no second spend. Do not call `sendPayment()` or `sendPrepared()` again until
the first attempt's outcome is known: that prepares a new spend from the same
stage.

For a rotating account, `resolveAuthAddress()` returns the account itself as
`authAddress` at every stage; the stage address the chain reports is in
`chainAuthAddress`. A rotating account rekeyed to an ordinary key the signer
holds has left rotation, and is sent like any rekeyed account once the chain
confirms the rekey.

### Send Failures

| Error | What it means | What to do |
|---|---|---|
| `SignOutcomeUnknownError` | A signing request ended with no answer, or with a 200 answer that could not be read, or the SDK failed while checking one. A signature may have been released. Nothing was submitted. | Do not send again. See [After An Unknown Outcome](#after-an-unknown-outcome), or check `requestId` with the operator or the signer's audit log. |
| `SubmissionError` | The group was signed, and algosdk's submit call or its confirmation wait then failed. It carries the signed group (`signedGroup`), its IDs (`txIds`), its earliest last valid round (`lastValid`) and algosdk's error as `cause`, unchanged. `submitted` is true when the submit call returned success and the failure came later, and false when it did not return success; false does not mean the node lacks the group, because the answer may have been lost. | Read `cause` as you would in any algosdk program. Do not sign a replacement. See [After An Unknown Outcome](#after-an-unknown-outcome). |
| `RotatingPreflightError` | A rotating spend failed its unsigned simulation. Nothing was signed. | Read `failureMessage`. |
| `UnsupportedSigningFlowError`, `UnsupportedGroupError`, `KeyNotFoundError`, `CosignerDiscoveryError` | Refused before anything that can execute was signed. | Read the reason. |
| Any other error | The signer refused (policy, operator, locked), or the SDK refused its answer (`verify signer response: ...`, `MaxFeeIncreaseError`). Nothing was submitted. | Read the reason. When the SDK refused a sign answer, the signer did sign and the SDK discarded the result. |

Two of these must not be answered by sending again:

- `SignOutcomeUnknownError`: the signer may have released a signature that
  never reached you. A replacement you build and sign, and that signature,
  could both execute. Find out what happened, or wait until the error's
  `lastValid` round has passed, first.
- `SubmissionError`: the signed group may already be in a block or in the
  node's pool, and a replacement could execute beside it. Submitting the same
  `signedGroup` again cannot pay twice: the same bytes execute at most once.

Any other error means nothing that was signed can execute: the send was
refused before signing, the signer refused, or the SDK refused the signer's
answer and discarded it. It is safe to fix the cause and send again.

### After An Unknown Outcome

Both errors carry `lastValid`, the earliest last valid round of the
transactions involved. The signer never changes a validity round and never
submits.

**A group was signed** (`SubmissionError`). The error carries the signed
group (`signedGroup`), the transaction IDs (`txIds`), the last valid round
(`lastValid`), and algosdk's error as its `cause`; read the cause as you would
in any algosdk program.

- `submitted` true: algosdk's submit call returned success. Follow the group
  with algosdk's own wait: `waitForConfirmation()` on the first transaction
  ID (a group confirms as a whole), waiting `lastValid` minus the current
  round, at least 1. Given 0 rounds, algosdk's wait throws without looking
  the transaction up. A timeout from the wait means only that the wait ended.
- `submitted` false: submit the same signed group again with
  `submitSignedGroup()`; the node may already have it.

Submitting the same signed group again cannot pay twice. If the node already
has it, algosdk reports a 400 whose text says the transaction is already in
the ledger; that is good news, not a refusal. After the last valid round the
node refuses the group as dead whether or not it confirmed.

Once `lastValid` has passed, neither a node's "not found" nor a refusal
proves the group never confirmed (a node only looks back about 1000 rounds
from its current round): check an indexer before building a replacement.

```ts
try {
  await client.sendPayment(algodClient, { sender, receiver, amount: 1_000_000 });
} catch (error) {
  if (!(error instanceof SubmissionError)) throw error;
  // Submit the same signedGroup again with submitSignedGroup(); the node may
  // already have it.
  if (!error.submitted) throw error;
  try {
    const { lastRound } = await algodClient.status().do();
    const rounds = error.lastValid > lastRound ? error.lastValid - lastRound : 1n;
    const info = await algosdk.waitForConfirmation(algodClient, error.txIds[0], Number(rounds));
    console.log(`confirmed in round ${info.confirmedRound}`);
  } catch {
    // Only the wait ended. Keep the original error: it holds the signed
    // group, the IDs and the last valid round.
    throw error;
  }
}
```

**Nothing was submitted** (`SignOutcomeUnknownError`, any account that is not
rotating). A signature may exist that never reached you. Once `lastValid` has
passed, nothing signed by that request can execute, and a replacement is
safe. No lookup is needed. Before that, do not build a replacement with
different transaction IDs.

**Rotating accounts** (`SignOutcomeUnknownError` whose `rotating` field holds
the prepared group). Sign the same prepared group again with
`signPreparedRotating(error.rotating)`; see
[Rotating Accounts](#rotating-accounts). It produces the same transaction
IDs, so it cannot pay twice.

### Cancellation And Time Limits

The send takes an `AbortSignal` as `signal` in its options. It sets no time
limit of its own: each signing request waits as long as the signer's
approval wait allows, unless the client was given a shorter `timeout`. To
bound signing and submission, abort the signal from a timer; `waitRounds`
bounds the confirmation wait. Where the abort lands decides what you get:

- before an approval-bearing request is posted (while keys, rounds or the
  plan are read, or between steps): a plain error, such as
  `SignerUnavailableError` ("Request aborted by caller"), not an unknown
  outcome. No `/sign/cancel` is sent.
- while an approval-bearing request (`/sign`, `/sign/component`,
  `/sign/assemble`, `/sign/rotating/sign`) is in flight: the request is
  aborted, a best-effort `/sign/cancel` is sent, and the send throws
  `SignOutcomeUnknownError`.
- after signing, before the submit call: `SubmissionError` with `submitted`
  false and the signal's `reason` as `cause`. Nothing was posted;
  `submitSignedGroup()` submits the group.
- during the submit call: algosdk's request is aborted, and the send throws
  `SubmissionError` with `submitted` false and algosdk's error as `cause`.
  The node may have the group.
- after a successful submit, before the confirmation wait starts:
  `SubmissionError` with `submitted` true and the signal's `reason` as
  `cause`. With `noWait` there is no wait to start, and the send returns its
  result with outcome `"submitted"`.
- during the confirmation wait: nothing. algosdk's `waitForConfirmation()`
  takes no signal, so the wait cannot be interrupted; `waitRounds` bounds
  it. The signal covers signing and submission.

A few requests do not take the signal and run to completion or their own
timeout: the prepare step inside `sendPayment()`, the key listing that picks
the flow, and the `/status` call that discovers the approval wait. None of
them signs anything. [`typescript/README.md`](../typescript/README.md), under
`sendPrepared`, lists every request the signal reaches.

## Common Tasks

### Health Check

```ts
const healthy = await client.health();
```

### Signer Status

```ts
const status = await client.getStatus();
console.log(status.state, status.keysetRevision, status.approvalWaitSeconds);
```

`getStatus()` calls authenticated `/status`. It does not require unlock; a
locked signer is returned as status data. Use `keysetRevision` as a
process-local signal to refresh `listKeys(true)` only when the loaded keyset
changes. Do not treat it as durable across apsigner restarts.

The SDK also uses `approvalWaitSeconds` to size `/sign` deadlines. If discovery
fails or the field is missing or out of range, signing falls back to 6
minutes.

`warnings` and `notes` are operator-facing lines. `rotating` lists each
rotating account's view from the signer's last background pass
(`RotatingAccountStatus`, wire field names: observed authorizer,
classification, cached stages and `recovery`); it is absent while locked or
without rotating accounts. Stage recovery itself (`/admin/rotating/recover`)
is an operator action run from apshell, so the SDK carries only its wire
shapes (`RotatingRecoverRequest`, `RotatingRecoverResponse`).

### List Keys

```ts
const keys = await client.listKeys(true);
for (const key of keys) {
  console.log(key.address, key.keyType, key.logicSigResources);
}
```

`listKeys()` returns public SDK objects with camelCase fields such as:

- `address`
- `publicKeyHex`
- `keyType`
- `logicSigResources`
- `isGenericLsig`
- `signingArgs`
- `templateProvenanceStatus`
- `templateProvenanceNote`

`logicSigResources` publishes independent program-byte, argument-byte, and
maximum-opcode-cost demand by authorization path. Non-bounded LogicSig keys
publish a `default` profile. Bounded keys publish exactly two paths, `spend`
and `spendingRekey`, which may differ: a rekey selects `spendingRekey` and
every other transaction selects `spend`.

`KeyTypeInfo.authorizationKind` distinguishes `ed25519`, `native_pq`, and
`logic_sig`. `requiresLogicsig === false` alone does not imply Ed25519.

`KeyInfo.authorizationKind` reports the same closed values for a key instance
and is authoritative for choosing its transaction authorization envelope. It
is absent for witness keys, which are not spending accounts, and whenever
the signer does not report it; never read an absent value as Ed25519. Prefer it over checking `logicSigResources`, because a native
Falcon-1024 spending key publishes no LogicSig profile and is otherwise
indistinguishable from an Ed25519 key. `signPreparedCosignedGroup` sends no
size hint for a position the signer holds: it names the position's
`authAddress`, and the signer sizes the position from its own records and can
put the group's authorization charge on it. Setting `pqScheme` or
`lsigResources` on such a position is an error.

`boundedAuthorization.rekey` is a bounded account's rekey setting:
`spending_key` lets the spending key rekey the account, and `refused` means the
account refuses rekeys, except to an address on its rekey-to list when it has
one. The SDK fails a rekey on a bounded key that has neither. `boundedAuthorization.contract`
is `bounded2` on a bounded host, or `plain1` on a plain host such as
`aplane.falcon1024.v1`, which has no host rules: every transaction that doesn't
rekey is a spend, closes included. `boundedAuthorization.maxFee` is the bounded host's fee
ceiling and is optional: a plain host has none, so it is `undefined`. Never read
its absence as zero.

### List Key Types

```ts
const keyTypes = await client.listKeyTypes();
for (const keyType of keyTypes) {
  console.log(keyType.keyType, keyType.family, keyType.displayName);
}
```

This is the easiest way to discover:

- available key families
- creation parameters for generated keys
- runtime args required by generic LogicSigs
- explicit mnemonic import support through `mnemonicImport` (native types only)
- per-key types through `perKeyContract`, and whether one takes a boundary file
  through `boundarySchema`: `aplane.boundary.v1` on the general bounded type,
  absent on a plain host, whose parameters are given directly

### Generate And Delete A Key

```ts
const generated = await client.generateKey("ed25519");
console.log(generated.address, generated.keyType);

await client.deleteKey(generated.address);
```

### Sign One Transaction

The `sign*` calls in this and the following sections return signed bytes and
submit nothing. Use them when you want the signed transactions yourself; to
send, use `sendPayment()` or `sendPrepared()` (see
[Sending Transactions](#sending-transactions)).

```ts
import algosdk from "algosdk";
import { SignerClient } from "aplanesdk";

const algodClient = new algosdk.Algodv2("", "https://testnet-api.4160.nodely.dev", "");
const suggestedParams = await algodClient.getTransactionParams().do();

const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
  sender: fromAddress,
  receiver: toAddress,
  amount: 1000,
  suggestedParams,
});

const signed = await client.signTransaction(txn);
const { txid } = await algodClient.sendRawTransaction(Buffer.from(signed, "base64")).do();
```

For a rekeyed account, these calls take the signing key explicitly. (The
`prepare*` helpers read it from the chain for you, so `sendPayment()` and
`sendPrepared()` need nothing extra; `resolveAuthAddress()` does that lookup
on its own.)

```ts
const signed = await client.signTransaction(txn, authAddress);
```

For generic LogicSigs, pass runtime args as `Uint8Array` values:

```ts
const signed = await client.signTransaction(txn, hashlockAddress, {
  preimage: secretBytes,
});
```

Without `authAddress` the sender signs for itself, and the args apply to the
sender. `lsigArgsMap` is keyed by auth address. A key that is no position's
authorizer throws `SignerError`. A position's authorizer is its auth address, not its
sender when the account is rekeyed: for a passthrough position it is the
signer its signed bytes name, and for a foreign position, where nothing names
one, the sender. A key whose only positions in the request are passthrough or
foreign is accepted, and its args are not sent, because the request does not
sign for that address; this lets one map serve the plan and the final signing
of the same group. An entry with no args is
ignored.

### Sign A Transaction Group

```ts
const signedGroup = await client.signTransactions(
  [txn1, txn2],
  [authAddr1, authAddr2],
);
```

For ordinary signer-managed groups without passthrough:

- do not pre-assign a group ID
- the signer computes the group after dummy insertion and fee pooling
- the returned base64 string is ready for algod submission

### Plan Without Signing

```ts
const plan = await client.planGroup([txn1, txn2], [authAddr1, authAddr2]);
console.log(plan.transactions);
console.log(plan.mutations);
```

Use `/plan` when you need:

- fee and dummy visibility before approval
- simulation inputs
- foreign-slot planning for multi-party workflows

### Multi-Party Group Assembly

For multi-party workflows, the standard high-level flow is:

1. use `planGroup()` with foreign slots and `lsigResources`
2. collect the finalized foreign signatures from the other party
3. resubmit those signed slots as `passthrough` for final signing, repeating
   the same `lsigResources` for every passthrough LogicSig slot

Do not mix foreign entries and `passthrough` entries in the same request.
The signer checks the declared program and argument byte counts against each
signed passthrough envelope; omitting the declaration is a client error.

For a foreign native Falcon-1024 slot, set `pq_scheme: "f1"` on a raw
`SignRequest`, or `pqScheme: "f1"` on a `PreparedTransaction`. Do not combine
it with `lsig_resources`/`lsigResources`; it declares native-PQ fee usage
rather than LogicSig resources.

`planRequests()` is the per-slot planning API. Prefer it over the
address-keyed `planGroup()` convenience form when two transactions use the
same authorization address with different LogicSig arguments or app-call
metadata.

A group that another party also signs goes through the signer in two steps:

1. Plan it with `planGroup()`, leaving the other party's positions foreign (a
   `null` auth address) and declaring `lsigResources` for any that are
   LogicSigs. The plan is the final group: its group ID, and any fees and
   dummies the signer adds.
2. The other party signs its transaction from the planned group. Sign the
   planned group with `signTransactions()`, passing that signed transaction as
   a passthrough position and repeating the same `lsigResources`.

`sendPrepared()` does not take passthrough positions, so a multi-party group
is signed with these calls and you submit it:

```ts
const signedGroup = await client.signTransactions(
  plannedTxns,
  authAddresses,
  undefined,
  { 1: otherPartySignedBase64 },
);
```

Passthrough values are standard base64 with padding. A string that is not
(URL-safe characters, a line break or other whitespace, missing padding, data
after the padding) is refused, as the Go and Python SDKs refuse it.

The high-level final-signing helpers reject foreign slots for `/sign`; foreign
slots are accepted by `planGroup()` only.

### Cosigned Accounts

Cosigned accounts (signing flow `cosigned1`) need component signatures from both
the user signer and a cosigner signer. A cosigned account is a plain host such
as `aplane.falcon1024.v1` created with a cosigner, or a bounded account with
one, such as Corridor. Either kind without a cosigner advertises `bounded1` and
signs through ordinary `/sign`. Cosigner component selectors are public policy keys, not
Algorand spending accounts, and must not be used as senders, receivers, auth
addresses, or rekey targets.

`sendPrepared()` and `sendPayment()` run the whole cosigned sequence and
submit the result. `signPreparedCosignedGroup()` runs the same sequence and
returns the signed group without submitting it.

#### Finding The Cosigner

A client made with `SignerClient.fromEnv()` finds a cosigned account's
cosigner in its own `endpoints.yaml`. List the cosigner node as an endpoint
with role `cosigner`:

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
(`requestEnrollmentFromEnv({ endpoint: "cosigner" })`). When a send, or
`signPreparedCosignedGroup()`, is given no `cosignerClient` and no
`cosignerResolver`, the client then:

- connects, on first use, to every `role: cosigner` endpoint (at most 12),
  each with its own identity file and known_hosts path and with the client's
  `trustOnFirstUse`, `sshSetupTimeout` and `timeout`, and reads its `/keys`;
- signs with the one endpoint that lists the account's witness key, under its
  Witness Key ID;
- keeps those connections, and closes them when you `close()` the client.

An explicit `cosignerClient` (with `cosignerComponentKey`) or
`cosignerResolver` always wins. A client made with `SignerClient.connectSsh()`
or the constructor has no endpoint registry, so it needs one of them; without
one, a cosigned send is refused with "cosignerClient or cosignerResolver is
required". `EndpointCosignerResolver.fromDataDir(dataDir, options)` builds the
same resolver for you to pass as `cosignerResolver`; it owns the connections
it opens, so `close()` it when done.

Every cosigner a position is sure to need is found before anything is asked
to sign, so a cosigner that cannot be found fails the send with nothing
signed. The error is a `CosignerDiscoveryError`, never an unknown outcome.
Its message says why:

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
`transaction_type:<type>` rule ID in the error message. `requestComponents()`
throws `SigningRejectedError`, preserving the code and message, and the cosigned
signing helper propagates that error. Apply the key's document before retrying.
See the [compatibility note](COMPATIBILITY.md) for policy format and provisioning details.

#### The Cosigned Sequence

The helper reads each position's key (its signing flow, LogicSig resources
and fee ceiling) from the user signer's `/keys` record, by the position's
auth address. A prepared transaction carries no key of its own. It is the
lookup the prepare helpers make: the spendable key for the address (a witness
key is never chosen), from a key list the client caches. Each call checks the
signer's keyset revision with one `/status` request and fetches `/keys` again
only when the revision has changed, so a key added or replaced on the signer
is picked up by the next call. An address with no spendable key is
refused with `KeyNotFoundError`.

For manual orchestration, use `requestComponents()` on the user client with a
bounded-base target and on the cosigner client, then `requestAssemble()` on the
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
`signPreparedCosignedGroup()` discovers the flow from signer inventory and
performs the user-first sequence. With a client from `fromEnv()` the cosigner
comes from `endpoints.yaml`:

```ts
const result = await signPreparedCosignedGroup({
  userClient,
  preparedGroup,
});
const signedGroup = result.signedGroup;
```

Set `cosignerClient` and `cosignerComponentKey`, or `cosignerResolver`, in
the options to name the cosigner yourself.

The sequence is `/plan`, user approval and base-component release through
`requestComponents()` with a bounded-base target, signing of ordinary group
positions, cosigner signing over the frozen group, and final
`requestAssemble()` on the user signer. Before requesting any additional signature, the SDK accepts only
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

```ts
const simulation = await userClient.simulatePreparedGroup(
  algodClient,
  preparedGroup,
);
if (simulation.failed) {
  // simulation.failureMessage says why; simulation.response has the
  // algod diagnostics.
}

const cosigned = await simulatePreparedCosignedGroup(algodClient, cosignedOptions);
```

`SimulationResult.signedGroup` contains fully executable signed transactions
that remain submittable until expiry. Keep them confidential. The helper sends
the exact signed group to the supplied algod with empty-signature overrides
disabled. A missing algod client fails before any signing request. A
simulation is `failed` unless the node returned exactly one group result, an
object that reports no failure and holds one transaction result per
transaction simulated. `failureMessage` says why: the node's own failure
message, or which of the other cases it was. Transport or decoding failures
throw and never trigger another signing request automatically.

## Transaction Semantics

- `signTransaction()` returns one base64 string containing the full signed
  output, including any dummies the server added.
- `signTransactions()` returns one concatenated base64 string for the full
  signed group.
- `signTransactionsList()` returns per-slot base64 strings; it also rejects
  foreign slots for `/sign`.
- These simple sign calls return only the signed transactions. To read what
  the signer changed (the fee it added, the group ID, appended dummies), call
  `signRequests()`, whose `mutations` is the mutation report, already checked
  against the request.
- Amounts and fees in the `*PrepParams` types are in microAlgos; an asset
  amount is in the asset's base units, not adjusted for its decimals. IDs,
  amounts and fees must be whole numbers (a safe integer or a bigint): a
  fraction, a numeric string or a boolean is refused. That holds for every
  ID, count and index a prepare helper takes: app and asset IDs, foreign
  references, ABI `application` and `asset` arguments, box app indexes, extra
  pages, the state schema counts (`numLocalInts`, `numLocalByteSlices`,
  `numGlobalInts`, `numGlobalByteSlices`), and the key-registration rounds and
  dilution.
- Group helpers check every sender against everything it pays across the
  group: the ALGO it sends plus the fee of every position it sends, asset
  transfers included. The check is named `group_algo_balance`. It reads each
  sender's spendable ALGO from the `spendable_algo` check that the payment and
  asset-transfer helpers record on every position (the lowest value, when a
  sender has several positions), and refuses a position
  that lacks that check or whose `available` value is not a whole number
- `prepareAsaTransfer()` checks the transfer's fee against the sender's spendable ALGO
  itself, so one transfer is refused alone exactly as it is in a group. Its
  `asa_transfer` check records the fee.
- `signRequests()` accepts one or more raw `/sign` request entries and returns the
  `/sign` response, with its mutation report in the typed camelCase
  `MutationReport` form.
- `planGroup()` returns unsigned `TX`-prefixed hex transactions plus a mutation
  report.
- `simulatePreparedGroup()` performs ordinary signing, then uses the
  caller-provided algod simulation endpoint.
- passthrough entries are base64-encoded signed transaction msgpack slots that
  already carry the intended group ID
- foreign planning can include `lsigResources` for LogicSig resource planning
- `sendPrepared()` and `sendPayment()` sign, submit and wait; their
  `SendResult.signedGroup` is hex msgpack, one entry per transaction.
- `submitSignedGroup()` submits a signed hex group exactly as given (a
  rotating group from `signPreparedRotating()`, or the `signedGroup` a
  `SubmissionError` kept) and waits for confirmation, on the same path as
  every send. It signs nothing.

`sendPrepared()` and `sendPayment()` submit for you. Submit the base64 string
the `sign*` calls return with algosdk's own
`algodClient.sendRawTransaction(Buffer.from(signed, "base64")).do()`, and wait
with `algosdk.waitForConfirmation()`.

### What The SDK Checks Before Returning

Every `/sign` and `/plan` result is checked against the request before
`signTransaction()`, `signTransactions()`/`signTransactionsList()`, `signRequests()`, `planGroup()`/`planRequests()` or `simulatePreparedGroup()` returns it, and before `sendPrepared()` submits anything. The
signer may change a request in three ways, and must report each in
`mutations`:

- raise the fee of a position it signs, listed in `fees_modified`, with the
  sum of the raises equal to `total_fees_delta`
- assign the group ID, which must be the ID computed over the returned group
- append resource dummies, counted in `dummies_added`

Anything else fails with `SignerError` whose message starts with
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
any size is accepted. Set `maxFeeIncrease` on the client to put your own ceiling on it.
The value is in microAlgos and bounds the total the signer adds across all
positions of one request. Zero means the signer may not raise any fee. When
the raises add up to more than the ceiling, every sign, plan and simulate call
through that client fails with `SignerError` and returns nothing, so nothing can be
submitted or simulated.
The per-account `max_fee` check in the cosigned flow still applies as well.
The refusal is a `MaxFeeIncreaseError`, a `SignerError` subclass carrying
`raised` and `limit` as bigints.

```ts
// microAlgos, summed over the request
const client = await SignerClient.fromEnv({ maxFeeIncrease: 200_000 });
try {
  const signed = await client.signTransaction(txn);
} catch (err) {
  if (err instanceof MaxFeeIncreaseError) {
    // verify signer response: signer raised fees by 5000000 microAlgos,
    // more than the max fee increase 200000 set on this client
    console.error(`signer asked for ${err.raised}, ceiling is ${err.limit}`);
  }
}
```

`connectSsh()` and the constructor's options take the same field as a `number`
or `bigint`. Assigning `client.maxFeeIncrease` changes it, and assigning `undefined`
removes it.
Reading `client.maxFeeIncrease` returns the value as it was set.

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
charge, call `planGroup()` with your transactions and read
`mutations.totalFeesDelta` in the result.

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
must be a valid Algorand address, or the call throws `SignerError` before any request is made.
A passthrough transaction must round-trip through the SDK's Algorand
library (`algosdk`), so one that uses a field newer than that library is refused
locally.

#### How Signer Answers Are Read

Every 200 answer from the signer is read strictly, as the Go SDK reads it: it
must be exactly one JSON object of the answer's declared shape, a field left
out or `null` takes its zero value, and a field of the wrong type, a `null`
body or anything after the object makes the answer unreadable. An answer
whose `error` field is set is a refusal; an unreadable answer is a plain
`SignerError` at a request that releases no signature, and at an
approval-bearing request a lost answer, which a send reports as
`SignOutcomeUnknownError`. The full rule and the reader's known limits are in
[`typescript/README.md`](../typescript/README.md) under `sendPrepared`.

### Rekeyed Senders In Prep Helpers

The `prepare*` helpers and `resolveAuthAddress()` read the sender's auth
address from algod account information. algosdk v3 returns it as an `Address`
object and raw algod JSON as a string; both are accepted, and
`ResolvedAuthAddress.authAddress` and `PreparedTransaction.authAddress` are
always strings. For a rotating account, `authAddress` is the account itself
at every stage, and `chainAuthAddress` is the stage address the chain
reports.

## Error Handling

A send's failures are described in [Send Failures](#send-failures). Every
call throws the signer's refusals as `SignerError` subclasses.

Main SDK error classes:

- `SignerError`, whose `code` is the signer's stable error code when it sent
  one (such as `ErrorCodes.RotatingStageChanged`)
- `AuthenticationError`
- `SigningRejectedError`
- `SignerUnavailableError`
- `KeyNotFoundError`
- `KeyDeletionError`
- `EnrollmentError`
- `MaxFeeIncreaseError`: the signer raised fees by more than the client's
  `maxFeeIncrease`; carries `raised` and `limit` as bigints, and serializes
  them to JSON as decimal strings
- `UnsupportedSigningFlowError` and `UnsupportedGroupError`: a send refused
  the group before signing
- `CosignerDiscoveryError`: a cosigned account's cosigner was not found in
  `endpoints.yaml`
- `SignOutcomeUnknownError`, `SubmissionError` and `RotatingPreflightError`:
  see [Send Failures](#send-failures)

Example:

```ts
import {
  AuthenticationError,
  SignOutcomeUnknownError,
  SignerUnavailableError,
  SigningRejectedError,
  SubmissionError,
} from "aplanesdk";

try {
  const result = await client.sendPayment(algodClient, { sender, receiver, amount: 1_000_000 });
  console.log(result.txIds[0]);
} catch (err) {
  if (err instanceof SignOutcomeUnknownError || err instanceof SubmissionError) {
    // Do not send again: see "After An Unknown Outcome".
    console.error(`${err.message} (last valid round ${err.lastValid})`);
    throw err;
  } else if (err instanceof AuthenticationError) {
    console.error("connection is not authenticated by an enrolled SSH key");
  } else if (err instanceof SignerUnavailableError) {
    console.error("signer unavailable or locked");
  } else if (err instanceof SigningRejectedError) {
    console.error("operator rejected the signing request");
  } else {
    throw err;
  }
}
```

## Advanced Notes

- `knownHostsPath` is required for explicit SSH connections and enrollment.
  When trust-on-first-use is enabled, that path is where the SDK saves the
  newly trusted host key.
- If optional dependencies are omitted and `ssh2` is unavailable, the SSH
  connection and enrollment paths will fail at runtime until `ssh2` is
  installed.
- The SDK exports both runtime helpers and lower-level utilities such as
  `loadConfig`, `resolveDataDir`, `encodeTransaction`, and
  `encodeLsigArgs`.

## Compatibility Notes

This SDK follows the signer API contract documented by the main APlane
repository. Before upgrading the SDK or the signer, read the
[compatibility note](COMPATIBILITY.md).

For compatibility-sensitive changes, check:

- signer API request/response fixtures under `contracts/signerapi/`
- TypeScript contract tests under `typescript/tests/contracts.test.ts`
- broader testing guidance in the main APlane repository's `docs/DEV_TESTING.md`

## Related Docs

- main APlane repository `docs/USER_INSTALL.md`
- main APlane repository `docs/USER_CONFIG.md`
- main APlane repository `docs/DEV_TESTING.md`
- main APlane repository `docs/ARCH_CONTRACTS.md`
- `typescript/README.md`
