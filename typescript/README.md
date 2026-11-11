# APlane TypeScript SDK

TypeScript SDK for signing Algorand transactions via apsigner.

## Versioning

SDK packages are published only when the SDK changes. SDK versions track
compatible APlane release tags and may skip product release numbers.

The native-Falcon SDK release line requires an APlane signer release after
`v0.35.0`; see [`docs/COMPATIBILITY.md`](../docs/COMPATIBILITY.md).

## Installation

```bash
npm install aplanesdk algosdk
```

Or with yarn/pnpm:

```bash
yarn add aplanesdk algosdk
pnpm add aplanesdk algosdk
```

### Installing from Local Tarball

When installing from a local `.tgz` file, build and pack the SDK first, then install the generated tarball into your project:

```bash
# From typescript/
npm install
npm pack

# In your consuming project
npm init -y   # if needed
npm install ../path/to/aplanesdk-<version>.tgz algosdk
```

### Troubleshooting

**Peer dependency conflicts**: If you see peer dependency errors, try:

```bash
npm install aplanesdk algosdk --legacy-peer-deps
```

## Quick Start

```typescript
import { SignerClient, sendRawTransaction } from "aplanesdk";
import algosdk from "algosdk";

// Connect to signer
const client = await SignerClient.fromEnv();

// Build transaction with algosdk
const algodClient = new algosdk.Algodv2("", "https://testnet-api.4160.nodely.dev", "");
const params = await algodClient.getTransactionParams().do();

const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
  sender: "SENDER_ADDRESS",
  receiver: "RECEIVER_ADDRESS",
  amount: 1000000, // 1 ALGO
  suggestedParams: params,
});

// Sign via apsigner (waits for operator approval)
const signed = await client.signTransaction(txn);

// Submit to network (signed is ready to use, no processing needed)
const txid = await sendRawTransaction(algodClient, signed);
console.log(`Submitted: ${txid}`);
```

## Connection Methods

All SDK connections use the configured SSH-backed signer path. Direct local HTTP connection is not a supported SDK mode.

### Remote Connection via SSH

Connect to apsigner on a remote machine through an SSH tunnel, authenticated
by the enrolled client key:

```typescript
const client = await SignerClient.connectSsh(
  "signer.example.com",
  "~/aplane/apclient/.ssh/id_ed25519",
  {
    sshPort: 1127,           // default: 1127
    timeout: 30000,          // optional explicit shorter request timeout
    sshSetupTimeout: 60000,  // TCP dial + SSH authentication only
    knownHostsPath: "~/aplane/apclient/.ssh/known_hosts",
  }
);
```

SSH setup uses its own 60-second deadline, independent of HTTP request and
operator approval timeouts. Pass `signal` to cancel setup. Enrollment offers
the same controls as `setupTimeout` and `signal`.

**Note**: SSH uses the fixed non-secret username `aplane` and public-key
authentication only; the enrolled key is the client's only credential. A key
the signer has not enrolled fails the handshake. Remember to close when done:

```typescript
await client.close();
```

### Environment-Based Connection

Load configuration from a data directory. The directory is required — pass
`dataDir` or set the `APCLIENT_DATA` environment variable:

```typescript
// Set environment variable
// export APCLIENT_DATA=~/aplane/apclient

const client = await SignerClient.fromEnv();

// Or pass directly
const client = await SignerClient.fromEnv({ dataDir: "~/aplane/apclient" });
```

Data directory structure (installer default: `~/aplane/apclient`):
```
<data_dir>/
  config.yaml          # Non-routing client settings
  endpoints.yaml       # Signer and cosigner routing
  .ssh/
    id_ed25519         # SSH key: the client's credential
    known_hosts        # Trusted signer host keys
```

Example `endpoints.yaml` (remote via SSH):
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

Pass `trustOnFirstUse: true` to `SignerClient.fromEnv` only when the call may
trust and save an unknown host key. Use `endpoint: "cosigner.qa"` to select a
named endpoint.

A client made with `fromEnv` also finds a cosigned account's cosigner here:
list the cosigner as an endpoint with `role: cosigner`, and a cosigned send
needs nothing more (see [Cosigner discovery](#cosigner-discovery)).

```yaml
  cosigner:
    role: cosigner
    url: ssh://cosigner.example.com:1127
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
```

## Authentication

The client's SSH key is its credential. A new key is enrolled once: the
request is queued for the operator to approve later in `apadmin` (`pending:
true`, the normal outcome) or the key is already enrolled, and nothing is
stored on the client. Connect once the operator has approved:

```typescript
import { requestEnrollmentFromEnv } from "aplanesdk";

const { fingerprint, pending } = await requestEnrollmentFromEnv({ label: "ci-runner" });
if (pending) console.log(`key ${fingerprint} queued; have the operator approve it in apadmin`);
```

`requestEnrollment(host, sshKeyPath, { knownHostsPath, label })` is the
explicit form. The same enrollment can be done from `apshell` with
`enroll`.

## API Reference

### SignerClient

#### `health(): Promise<boolean>`

Check if signer is reachable.

```typescript
if (await client.health()) {
  console.log("Signer is online");
}
```

#### `getStatus(): Promise<StatusResponse>`

Fetch authenticated signer status. This works while the signer is locked.

```typescript
const status = await client.getStatus();
console.log(status.state, status.keysetRevision, status.warnings);
```

`keysetRevision` is process-local and useful for deciding when to refresh
`listKeys(true)`; it is not durable across apsigner restarts.
`approvalWaitSeconds` is used by the SDK to size `/sign` deadlines. Display
non-empty `warnings` to operators; they report persistent health conditions
that require attention.

#### `listKeys(refresh?: boolean): Promise<KeyInfo[]>`

List available signing keys.

```typescript
const keys = await client.listKeys();
for (const key of keys) {
  console.log(`${key.address} [${key.keyType}]`);
}
```

Returns list of `KeyInfo`:
- `address`: Algorand address
- `keyType`: "ed25519", "aplane.falcon1024.v1", "aplane.htlc.v1", etc.
- `logicSigResources`: independent program-byte, argument-byte, and
  maximum-opcode-cost demand by authorization path.
- `isGenericLsig`: True if no cryptographic signature needed
- `signingArgs`: List of `SigningArg` for LogicSigs

**Discovering required arguments for generic LogicSigs:**

```typescript
const keyInfo = await client.getKeyInfo(hashlockAddress);
if (keyInfo?.signingArgs) {
  for (const arg of keyInfo.signingArgs) {
    console.log(`${arg.name}: ${arg.type} - ${arg.description}`);
  }
}
```

#### `signTransaction(txn, authAddress?, lsigArgs?): Promise<string>`

Sign a single transaction. Returns a base64-encoded string ready for submission.

The server automatically handles fee pooling for large LogicSigs (e.g., Falcon-1024) by adding dummy transactions as needed.

```typescript
// Basic signing (uses txn.sender as authAddress)
const signed = await client.signTransaction(txn);

// Rekeyed account (different auth key)
const signed = await client.signTransaction(txn, "SIGNER_KEY_ADDRESS");

// Generic LogicSig with runtime args (e.g., HTLC)
const signed = await client.signTransaction(
  txn,
  "HASHLOCK_ADDRESS",
  { preimage: new Uint8Array([/* secret value */]) }
);

// Submit directly (no processing needed)
const txid = await sendRawTransaction(algodClient, signed);
```

#### `signTransactions(txns, authAddresses?, lsigArgsMap?): Promise<string>`

Sign multiple transactions as a group. Returns a base64-encoded string of concatenated signed transactions, ready for submission.

**Important**: Do NOT pre-assign group IDs. The server computes the group ID after adding any required dummy transactions for large LogicSigs.

```typescript
// Build transactions (do NOT call assignGroupId)
const txn1 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({...});
const txn2 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({...});

// Sign group (server handles grouping and dummies)
const signed = await client.signTransactions([txn1, txn2]);

// Submit directly (no processing needed)
const response = await algodClient.sendRawTransaction(Buffer.from(signed, "base64")).do();
```

#### `signTransactionsList(txns, authAddresses?, lsigArgsMap?): Promise<string[]>`

Like `signTransactions()` but returns individual base64-encoded transactions instead of concatenated. Useful when you need to inspect transactions individually.

```typescript
const signedList = await client.signTransactionsList([txn1, txn2]);
// signedList is string[], each element is a base64-encoded signed transaction
```

#### `signRequests(requests, options?): Promise<GroupSignResponse>`

Send one or more raw `/sign` request entries. Use this when an integration
already owns transaction encoding and wants APlane's native response shape. The
mutation report comes back in the typed camelCase `MutationReport` form.

```typescript
const response = await client.signRequests(
  [{
    txn_bytes_hex: "5458...",
    auth_address: "SIGNER_KEY_ADDRESS",
    txn_sender: "SENDER_ADDRESS", // advisory display hint only
  }],
  { requestId: "app-owned-request-id" },
);
```

Signing calls discover `/status.approval_wait_seconds` and use that value
plus 30 seconds of slack for the request timeout. If discovery fails or an older
signer omits the field, signing falls back to 6 minutes. An explicit shorter
timeout still wins; SDK `/sign` calls include a `request_id` and send a
best-effort `/sign/cancel` when the HTTP request times out or disconnects.
High-level signing methods accept `requestId` and `signal` options for
applications that need user-initiated cancellation.

#### `cancelSignRequest(requestId): Promise<CancelSignResponse>`

Ask apsigner to cancel a live synchronous `/sign` request by request ID.
Successful responses are idempotent for client behavior and return state
`"canceled"` or `"not_found"`.

TypeScript high-level signing generates a request ID by default. Interactive
applications can pass an application-owned ID and an `AbortSignal`; aborting the
signal aborts the HTTP request and sends best-effort `/sign/cancel` with the
same ID:

```typescript
const controller = new AbortController();
const requestId = "wallet-ui-approval-123";
const signed = await client.signTransaction(txn, undefined, undefined, {
  requestId,
  signal: controller.signal,
});

// elsewhere, if the user aborts while approval is pending:
controller.abort();
```

#### `sendPrepared(algodClient, group, options?): Promise<SendResult>`

Sign a prepared transaction or group, check the signed result against what was
prepared, submit exactly those bytes, and wait for confirmation. The SDK picks
the signing flow from the signer's record of each key, so the same call works
for Ed25519, native Falcon, LogicSig, bounded, cosigned and rotating accounts,
and for a rekeyed sender.

```typescript
const prepared = await client.preparePayment(algodClient, {
  sender,
  receiver,
  amount: 1_000_000, // microAlgos
});
const result = await client.sendPrepared(algodClient, { transactions: [prepared] });
console.log(result.txIds[0], result.outcome, result.confirmedRound);
```

`sendPayment(algodClient, params, options?)` does both steps for an ALGO
payment.

- **Result.** `signedGroup` is the group as submitted, hex msgpack; the first
  `originalCount` entries are yours and the rest are resource dummies the
  signer appended. `txIds`, `fees` (bigint microAlgos) and `groupId` are
  computed from the signed bytes. A signer may raise a fee or assign a group,
  so `txIds` can differ from the IDs of the transactions you prepared.
  `confirmedRound` is a bigint, `0n` unless `outcome` is `"confirmed"`.
- **Options.** `noWait` returns once the node accepts the group, with outcome
  `"submitted"`. `waitRounds` is how many further rounds to wait for
  confirmation (default 10). A cosigned account needs nothing extra when the
  client was made with `fromEnv` and `endpoints.yaml` lists its cosigner: the
  SDK finds it there (see [Cosigner discovery](#cosigner-discovery)).
  Otherwise pass `cosignerClient` with `cosignerComponentKey`, or a
  `cosignerResolver`; either wins over discovery, and the SDK does not close
  a cosigner client you pass. `signal` is an `AbortSignal`; see
  **Cancellation** below.
- **Cancellation.** The send checks `signal` before it asks the signer
  anything, before the ordinary `/sign` and before the rotating sign, and an
  abort found there is a plain stop: a `SignerUnavailableError` ("Request
  aborted by caller"), not an unknown outcome. Every approval-bearing request
  (`/sign`, `/sign/component`, yours and the cosigner's, `/sign/assemble` and
  `/sign/rotating/sign`) checks the signal again just before it is posted, after
  the approval-wait discovery: one that was never posted, because the signal
  had already been aborted or its body could not be encoded, is a plain error,
  and no `/sign/cancel` is sent for it. An abort while such a request is in
  flight ends it, which counts as a lost answer (`SignOutcomeUnknownError`),
  as in the Go SDK. Once the group is signed, an abort before it is sent is a
  `SubmissionUncertainError` at stage `"unsent"`. These requests take the
  signal and are aborted with it: `/sign` (including the cosigned sequence's
  other positions), the cosigned sequence's key listing (`/status` and
  `/keys`), its `/plan`, its `/sign/component` requests and `/sign/assemble`,
  the rotating `/sign/rotating/prepare` and `/sign/rotating/sign`, and every
  algod request the send makes (the account lookup for an account that left
  rotation, round reads, the suggested parameters for rebuilt rounds, the
  simulation, the submission and the confirmation wait). These do not, and run
  to completion or their own timeout: the prepare step inside `sendPayment`
  (its algod and key lookups), the key listing that picks the flow, and the
  `/status` call that discovers the approval wait. None of them signs
  anything. The best-effort `/sign/cancel` sent after an aborted or lost
  signing request uses its own short timeout, and a cancel that fails or
  whose answer cannot be read never fails the send or replaces its error.
- **Refused before signing:** an unknown signing flow
  (`UnsupportedSigningFlowError`), and a pre-signed or foreign position
  (`UnsupportedGroupError`). Use the lower-level signing calls for those
  groups.
- **No replacement spends.** The call never builds a second transaction for
  one whose outcome is unknown. A rotating send may prepare and seek approval
  again when the signer says an attempt released no signature.

Failures:

| Error | Meaning | What to do |
|---|---|---|
| The signing call's own error | The signer refused (policy, operator, locked), or the SDK refused the signer's answer (`verify signer response: ...`, `MaxFeeIncreaseError`). Nothing was submitted. | Read the reason. If the SDK refused a sign answer, the signer did sign and the SDK discarded the result. |
| `SignOutcomeUnknownError` | A signing exchange ended with no answer, or with a 200 answer that could not be read (not one JSON object of the expected shape), or the SDK failed while checking or describing a 200 answer (a fault in the SDK: anything thrown that is not a `SignerError`). A signature may have been released; nothing was submitted. | Call `resolveOutcome` with it (see [After an uncertain outcome](#after-an-uncertain-outcome)), or check with the operator or the audit log, before signing again. `requestId` names the request whose answer was lost: the `/sign` request of the ordinary flow, the rotating sign request, or the cosigned sequence's `/sign/component`, `/sign/assemble` or `/sign` request. `lastValid` is the earliest last valid round of the transactions sent to be signed. For the ordinary flow the error also carries `requests`; for a rotating account it carries the prepared group in `rotating` (see below). |
| `SubmissionRejectedError` | The node refused the group or dropped it from its pool. | Read the reason. The signed bytes and IDs are in `signedGroup` and `txIds`. |
| `SubmissionUncertainError` | `stage` says where it stopped: `"unsent"` (signed, never sent: your signal was aborted), `"submit"` (the submission's answer never arrived), or `"confirm"` (not confirmed within the wait). Except for `"unsent"`, it may still confirm. | Call `resolveOutcome` with it, look up `txIds`, or submit the same `signedGroup` again. Do not sign a replacement until the outcome is known: both could execute. `lastValid` is the signed group's earliest last valid round. |
| `CosignerDiscoveryError` | The SDK could not route a cosigned account's witness key to exactly one cosigner endpoint of `endpoints.yaml`. Nothing was signed that needed the cosigner. | Read the reason: it names every cosigner endpoint and its state. |

#### After an uncertain outcome

`resolveOutcome(algodClient, error, options?)` takes a
`SignOutcomeUnknownError` or a `SubmissionUncertainError` and says where
things stand. It asks the node only: it never signs, never submits and never
calls the signer. It rests on two facts: the signer never submits, so a
signature it released reaches the chain only if someone holding the signed
bytes submits them; and a transaction cannot execute after its last valid
round, which the signer never changes. The report's `state` is one of
`confirmed`, `pending`, `not_seen`, `signable`, `expired` and `too_old`;
`safeToReplace` says whether building a replacement is safe now, `advice`
says what to do in one sentence, and `confirmedRound`, `txIds`, `lastValid`,
`currentRound`, `signedGroup` and `rotating` carry the details.

```typescript
try {
  await client.sendPayment(algodClient, { sender, receiver, amount: 1_000_000 });
} catch (error) {
  if (error instanceof SignOutcomeUnknownError || error instanceof SubmissionUncertainError) {
    const report = await client.resolveOutcome(algodClient, error);
    console.log(report.state, report.advice);
  }
  throw error;
}
```

After a `SubmissionUncertainError` the signed group and its IDs are known.
The node's last round is read first, then the first transaction ID is looked
up (a group is atomic, so one is enough):

- found in a block: `confirmed`; do not send it again;
- in the node's pool: `pending`; wait;
- not found, or dropped from the pool, while the last round is at most
  `lastValid`: `not_seen`; submit the same signed group again
  (`submitSignedGroup`), or wait until `lastValid` has passed;
- not found or dropped, and the last round is past `lastValid` by at most
  500 rounds: `expired`, and safe to replace;
- not found or dropped, more than 500 rounds past `lastValid`: `too_old`. A
  node answers only for recent rounds, so past that margin a confirmed
  transaction can look "not found": look the ID up on an indexer.

After a `SignOutcomeUnknownError` nothing was submitted by the call. For a
rotating account the prepared group's IDs are known, so the spend is looked
up first: `confirmed` or `pending` as above, and otherwise the rounds decide.
For any other account the signer may have changed the transactions, so there
are no IDs and no lookup (`txIds` is empty):

- the last round is at most `lastValid`: `signable`. A released signature can
  still execute: for a rotating account sign the same prepared group again,
  otherwise wait until `lastValid` has passed before building a replacement;
- the last round is past `lastValid`: `expired`, and safe to replace. There is
  no `too_old` here: expiry alone settles it.

Any other node failure is thrown, never turned into a state. Before the node
is asked anything, these are refused, in this order: any other error, `null`
included ("not an uncertain outcome"); an error with no last valid round; a
`SubmissionUncertainError` with no transaction IDs (or an empty first one);
a missing algod client.

`waitForOutcome(algodClient, error, { signal?, timeoutMs? })` calls
`resolveOutcome` once per round (it waits for each next round with the node's
status-after-block call) until the state is `confirmed`, `expired` or
`too_old`. If the signal is aborted, `timeoutMs` passes or the node fails
first, it throws a `WaitForOutcomeError` whose `report` is the last report
(none if the wait ended before the first check) and whose `cause` says why.
It never signs or submits anything.

A node that answers "already in ledger" has a transaction with the same ID
from an earlier submission of the group. The SDK treats that as submitted and
looks for the outcome; it is not a rejection. A committed transaction that
carries a lease is the exception: the node refuses it for its lease, and the
SDK reports a rejection.

Every 200 answer from the signer is read as the Go SDK reads it, against the
answer's declared shape: `/status`, `/keys`, `/keytypes`, `/plan`,
`/admin/generate`, `/sign/cancel` and `DELETE /admin/keys` as much as the
signing answers. It is exactly one JSON object; null means zero at every
depth, so a field left out or null, in the answer or in any object nested in
it, takes its zero value (a field the Go SDK keeps as a pointer, such as a
rotating account's `stage`, is left out instead), as does a null entry in a
list; an unknown field is ignored. A field of the wrong type, a number outside
the field's range, a null or non-object body, an empty or cut-off body, or
anything after the object makes the answer unreadable. At a request that
releases no signature an unreadable answer is a plain `SignerError`, never a
`TypeError` or `SyntaxError`, and no field is coerced. `generateKey` refuses
an answer without an address; `deleteKey` reads the signer's
`{"success": true}` answer and refuses an empty one or one with an `error`.
A `/keys` answer listing an address in an alternate spelling (an Algorand
address algosdk reads, but not its canonical form) is refused as a whole; any
other address string, such as a witness key's Witness Key ID, is kept exactly
as sent. The addresses you pass in are held to the same spelling: a sign
request's `auth_address`, the prepare helpers' address parameters, an app
call's `accounts` and its ABI account arguments (which also take an algosdk
`Address`, from this or any other copy of algosdk, or a 32-byte public key)
must be canonically spelled address strings, and anything else is refused
before a request is sent.

Known limits of the reader, beside the Go and Python SDKs:

- Numbers. `JSON.parse` cannot hold a number above 2^53 exactly, so it is
  unreadable, where the Go SDK reads numbers up to 2^64 - 1 and then refuses
  them. The exception is a bound the SDK only reports and never computes on:
  a `/keytypes` creation parameter's `min` and `max`, which a generic LogicSig
  template may declare up to 2^64 - 1, are read as the number `JSON.parse`
  gives, rounded above 2^53, so that they cannot make the key type list
  unreadable (a negative, fractional or non-number value still does). A
  number written as `3.0` is read as `3`, because `JSON.parse` does not keep
  how a number was written. The Python SDK cannot read an integer of more
  than 4300 digits.
- Duplicate keys. Of two copies of a key the later one wins. The Go SDK keeps
  the earlier value when the later one is null.
- A UTF-8 byte order mark before the answer is read (fetch's `json()` strips
  it); the Go and Python SDKs cannot read such an answer.

The existing `sign*` and `simulate*` calls are unchanged. A `simulate*`
result is `failed` unless the node returned exactly one group result, an
object holding one transaction result per transaction, that reports no
failure; `failureMessage` says why: the node's own failure message, "the node
reported a failure without a message" for a failed-at alone, or "the node
returned no result for the group", "the node returned N results for one
group", "the node's result for the group is not an object" or "the node
returned M transaction results for N transactions".

#### Rotating accounts

A rotating account (`signingFlow` `rotating1`) hands itself to a fresh stage
on every spend, so the signer adds a rekey to the transaction. `sendPrepared`
and `sendPayment` run the whole sequence:

1. **Prepare.** The signer returns the exact group it will sign: your
   transaction with the rekey to the next stage, its fee raised, and any
   resource dummies.
2. **Check.** The SDK refuses the group unless the only changes are that
   rekey, a reported fee raise within your max fee increase, the group ID and
   canonical dummies.
3. **Simulate, unsigned,** through your algod. A group that fails throws
   `RotatingPreflightError`, as does an answer without exactly one result for
   the group, or with the wrong number of transaction results;
   `failureMessage` is the node's failure message, or which of those it was.
   A simulation that cannot be run throws a plain error. Either way no
   one-time key has been used.
4. **Sign,** with operator approval, then check the signed group is exactly
   the prepared one.
5. **Submit at once** and wait for confirmation. `result.rotating` reports the
   stage that signed and the stage that now controls the account.

What to know:

- **One transaction, alone.** A rotating account's transaction must be
  ungrouped, set no `rekeyTo`, not close the account, and take no LogicSig
  arguments. It cannot share a group with other transactions.
- **Short validity window.** The window is at most 100 rounds
  (`ROTATING_MAX_VALIDITY_WINDOW`), and the signer signs only while
  `firstValid` is at most 2 rounds ahead (`ROTATING_MAX_LEAD`) and at least 10
  rounds remain (`ROTATING_MIN_REMAINING`). Every `prepare*` helper builds such
  a window when the sender is a rotating account. A transaction whose rounds
  are not current is refused before the operator is asked, and that includes
  one a helper built that has since gone stale: only `sendPayment` rebuilds
  rounds without the option. For any other transaction, set
  `refreshValidity: true` to let the SDK rebuild the rounds; that changes the
  transaction ID, so leave it off if anything outside the transaction binds
  its rounds.
- **App calls carry the rekey.** A contract that requires a zero `rekeyTo`
  fails the simulation in step 3.
- **Bounded retries.** When the signer says an attempt released no signature
  (`rotating_stage_unproven`, `rotating_stage_changed`,
  `rotating_window_not_current`), the send prepares again, up to three
  attempts. Each attempt needs approval again. A timing refusal is retried
  only when the rounds may be rebuilt, and the retry uses the longest window
  to give the operator time. The codes are `ErrorCodes.RotatingStageUnproven`,
  `ErrorCodes.RotatingStageChanged` and
  `ErrorCodes.RotatingWindowNotCurrent`, read from `SignerError.code`.
- **The SDK cannot derive stage addresses.** It binds the next stage's
  address the signer reports to the prepared transaction; the signer derives
  it again from the seed before it signs.
- **Unsigned simulation checks effects, not signatures.** The node runs the
  stage program only on the signed group.
- **Two sends in a row** work once the first has confirmed, which the default
  wait ensures. Two spends prepared from the same stage cannot both land; the
  SDK does not serialize other clients or processes.
- **Stage numbers** are safe integers, never rounded. A sign answer with a
  stage beyond `Number.MAX_SAFE_INTEGER` cannot be read, so it is a
  `SignOutcomeUnknownError`; a prepare answer with one is a plain error.

The steps are also available one at a time. None of them submits:

```typescript
const prepared = await client.prepareRotating(txn);                           // nothing signed
const simulation = await client.simulatePreparedRotating(algodClient, prepared); // never signs
const signed = await client.signPreparedRotating(prepared);                  // waits for approval
const result = await client.submitSignedGroup(algodClient, signed.signedGroup);
```

A `PreparedRotating` cannot be changed after it is made: its state is in
private fields, every value it hands out is a copy, and it is checked again
when it is simulated or signed. Only one that `prepareRotating` made is
accepted; an object built on its prototype is refused before any request is
made. Submit a signed rotating group promptly: the stage's one-time keys are
revealed until that transaction or a later rotation confirms.

**If a sign answer is lost** (`SignOutcomeUnknownError`, whose `rotating`
field holds the prepared group), call `signPreparedRotating` again with that
same prepared group. It asks for the same transaction with the same IDs and
builds no second spend. It needs approval again and succeeds only while the
stage is still live and the window still acceptable. If the retry is refused,
do not prepare a replacement until the first attempt's outcome is known:
`rotating_stage_changed` means a transaction from that stage has confirmed.

```typescript
try {
  await client.sendPayment(algodClient, { sender, receiver, amount: 1_000_000 });
} catch (error) {
  if (error instanceof SignOutcomeUnknownError && error.rotating) {
    const signed = await client.signPreparedRotating(error.rotating);
    await client.submitSignedGroup(algodClient, signed.signedGroup);
  } else {
    throw error;
  }
}
```

`submitSignedGroup` also submits again the `signedGroup` kept by a
`SubmissionUncertainError`; the same bytes can execute only once.

A rotating account that was rekeyed to an ordinary key the signer holds has
left rotation. The `prepare*` helpers name that key as its `authAddress`, and
it is then signed like any rekeyed account. `sendPrepared` confirms the rekey
on the chain first, so an ordinary key is never asked to sign for an account
that is still rotating. `resolveAuthAddress` reports a rotating account's
`authAddress` as the account itself and the chain's authorizer, the current
stage, in `chainAuthAddress`. Recovery of an unknown stage is an operator
action (`rotate recover` in apshell).

## Supported Key Types

| Key Type | Description | Notes |
|----------|-------------|-------|
| `ed25519` | Native Algorand keys | Standard signing |
| `falcon1024` | Native post-quantum keys | Protocol-native Falcon-1024 signature (`PQsig`) |
| `aplane.falcon1024.v1` | Post-quantum plain host | Enabled by default. With bounds (transfer kinds, a recipient list, or limits only) a `bounded2` account; without, `plain1`, with no host rules or fee ceiling. `cosigned1` signing flow with a cosigner, `bounded1` without one |
| `aplane.ed25519.v1` | Ed25519 plain host | Library-visible; the same bounds and overlays as `aplane.falcon1024.v1`, and the spending key is classical |
| `aplane.witness-falcon1024.v1` | Witness key | Cosigner-custodied policy signature key; not a spending account |
| `aplane.htlc.v1` | Hash-locked funds | Requires `preimage` arg (check `signingArgs`) |

Only the protocol-native types, `ed25519` and `falcon1024`, and the Falcon plain
host, `aplane.falcon1024.v1`, are enabled by default. The operator must enable any other type on the node (`apadmin keytype
enable <type>` or the apadmin KeyType Library) before key generation accepts
it; until then generation fails with "key type ... is not enabled on this
node". Enablement gates only creating keys: existing keys of a disabled type
keep signing.

The server assembles the complete signed transaction - the SDK returns a base64 string ready for submission.

## Cosigner And Cosigned Accounts

Witness keys enrolled as cosigners are public policy-signature selectors, not Algorand
spending accounts. Do not use them as senders, receivers, auth addresses, or
rekey targets. A cosigned account (signing flow `cosigned1`) embeds the cosigner
public key and is assembled through `/sign/assemble`; ordinary `/sign` is not
sufficient for its slots. Send it with `sendPrepared`, or sign it with
`signPreparedCosignedGroup`, below. `requestComponents` and `requestAssemble` are
the low-level calls that helper makes, for applications that own the
orchestration.

### Cosigner discovery

A cosigned account needs nothing extra when `endpoints.yaml` lists its
cosigner (an endpoint with `role: cosigner`) and the client was made with
`SignerClient.fromEnv`: when a send, or `signPreparedCosignedGroup`, names no
`cosignerClient` and no `cosignerResolver`, the client uses an
`EndpointCosignerResolver` over its own `endpoints.yaml`, made on first use,
kept, and closed when the client is closed. It connects to the cosigner
endpoints with the client's own `trustOnFirstUse`, `sshSetupTimeout` and
`timeout`. An explicit client or resolver always wins. A client made any other
way asks for a cosigner as before.

You can also build one yourself and pass it as `cosignerResolver`:

```typescript
const resolver = EndpointCosignerResolver.fromDataDir("~/aplane/apclient");
// or: new EndpointCosignerResolver(loadClientEndpointRegistry(dataDir), options)
try {
  await client.sendPrepared(algodClient, group, { cosignerResolver: resolver });
} finally {
  await resolver.close(); // it owns the connections it opened
}
```

On first use it connects to every `role: cosigner` endpoint (at most 12),
each with its own identity file and known_hosts path exactly as a signer
endpoint is connected, and reads its `/keys`: 10 seconds per endpoint, 30
seconds for the whole sweep, at most 4 endpoints at once. A record counts when
it is a witness key with a key type; its `public_key_hex` must be non-empty hex
(compared without regard to case) and its `address` must be the Witness Key ID
derived from its key type and public key (base32 of SHA-512/256 over the
length-prefixed domain `APLANE_WITNESS_KEY_ID_V1`, key type and public key).
One record that fails either check makes that endpoint's whole listing
invalid. A witness key listed by exactly one live endpoint is routed there,
under its Witness Key ID; a key listed by more than one, or by none, is a
`CosignerDiscoveryError`. The "none" message names every cosigner endpoint
with its state: `ok`, `unreachable` (connection, transport or 5xx failure,
or out of time), `locked`, `authentication failed` (401, a 403 that is not
locked, or a key that is not enrolled), `invalid cosigner metadata` (an
unreadable `/keys` answer or a bad record), or `configuration invalid` (a bad
URL, an unreadable identity or known_hosts file, an unknown host key without
trust-on-first-use, or any other 4xx). An SSH host key that differs from the
pinned one at any cosigner endpoint aborts the whole discovery, needed or not.
The sweep's result is kept; a witness key it does not route triggers one fresh
sweep per resolve, which reads `/keys` again on the connections it kept and
connects afresh to the endpoints that had failed. Nothing is kept from a sweep
that a host key mismatch or your signal ended. `witnessKeyId(keyType,
publicKey)` derives a Witness Key ID.

The cosigned sequence asks the resolver, whichever it is, for every target
that cannot take the listed-rekey path (no rekey, or no rekey list on the
account) before it plans the group and before any approval-bearing request,
so a resolver that fails leaves nothing signed. Several targets are resolved
in the order of the witness key each needs (key type, then public key), and
the cosigner component requests go out in the order of their first target
position. A rekey that may take the listed path is resolved only
once the base component says it needs the cosigner: a listed rekey needs
none, and works with no cosigner configured or reachable. A resolver's own
error is passed on as it is, never as an unknown outcome.

### Bounded Cosigner Accounts

Corridor uses the bounded contract `bounded2`, and a cosigned plain host
`plain1`, with the distinct `cosigned1` online signing flow, which carries spends and rekeys. A rekey to
an address on the account's rekey-to list needs no cosigner: the signer's base
component names its `path`, and the helper skips the cosigner for it. The contract identifies the LogicSig
rules; the flow identifies the user-first multi-endpoint choreography. The
prepared helper detects that flow from signer inventory and routes it
automatically:

```typescript
const result = await signPreparedCosignedGroup({
  userClient,
  cosignerResolver,
  preparedGroup,
});
const signedGroup = result.signedGroup;
```

The SDK first freezes the complete canonical group through `/plan`; the user
signer then approves those bytes through `requestComponents()` with
`kind: "bounded-base"`. It then signs ordinary positions, and only after
the user side is complete does it request cosigner signatures over the same
bytes and call `requestAssemble()`. Before
signing anything, the SDK compares the
signer-produced plan with the caller's prepared group: only reported fee
pooling and group-ID assignment are accepted, and appended positions must be
canonical budget dummies. The returned group must use canonical transaction
encoding and a group ID recomputed from the presented membership. The SDK also
verifies ordinary signed positions and every assembled transaction against the
frozen transaction bytes.

`requestComponents()` sends best-effort `/sign/cancel` when its
approval-bearing request is aborted, times out, or disconnects.
`requestAssemble()` does not open an approval request and is not a
cancellation handle.

The signer planner owns fee selection, authorization-resource sizing, and any
reported group mutations for the cosigned flow.

Applications that own orchestration can call `requestComponents()` and
`requestAssemble()` directly. The cosigner signs spends and
cosigned rekeys, never a rekey to a listed address.

## Error Handling

### Signing Exceptions

```typescript
import {
  SignerError,

## Project

This SDK is part of the APlane project:

- Repository: https://github.com/aplane-algo/aplanesdk
- SDK path: `typescript`

APlane is an open-source project stewarded by the APlane Project.

See the repository [README](https://github.com/aplane-algo/aplanesdk/blob/main/README.md) for project overview and alpha-status guidance, and [DISCLAIMER.md](https://github.com/aplane-algo/aplanesdk/blob/main/DISCLAIMER.md) for risk, liability, and usage information.
  AuthenticationError,
  SigningRejectedError,
  SignerUnavailableError,
  KeyNotFoundError,
} from "aplanesdk";

try {
  const signed = await client.signTransaction(txn);
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.log("Connection is not authenticated by an enrolled SSH key");
  } else if (error instanceof SigningRejectedError) {
    console.log("Operator rejected the request");
  } else if (error instanceof SignerUnavailableError) {
    console.log("Signer not reachable or locked");
  } else if (error instanceof KeyNotFoundError) {
    console.log("Key not found in signer");
  } else if (error instanceof SignerError) {
    console.log(`Signing failed: ${error.message}`);
  }
}
```

### Submission Exceptions

`sendRawTransaction()` wraps verbose algod errors into clean exceptions:

```typescript
import {
  sendRawTransaction,
  TransactionRejectedError,
  LogicSigRejectedError,
  InsufficientFundsError,
  InvalidTransactionError,
} from "aplanesdk";

try {
  const txid = await sendRawTransaction(algodClient, signed);
} catch (error) {
  if (error instanceof LogicSigRejectedError) {
    console.log(`LogicSig failed: ${error.reason}`); // error.txid also available
  } else if (error instanceof InsufficientFundsError) {
    console.log(`Not enough funds: ${error.reason}`);
  } else if (error instanceof InvalidTransactionError) {
    console.log(`Invalid transaction: ${error.reason}`);
  } else if (error instanceof TransactionRejectedError) {
    console.log(`Rejected: ${error.reason}`);
  }
}
```

## Example: Complete Workflow

```typescript
import { SignerClient, SignerError, sendRawTransaction } from "aplanesdk";
import algosdk from "algosdk";

async function main() {
  // Connect to the signer with the enrolled client key
  const client = await SignerClient.fromEnv();

  // List keys
  const keys = await client.listKeys();
  const sender = keys[0].address;
  console.log(`Using: ${sender}`);

  // Build transaction
  const algodClient = new algosdk.Algodv2("", "https://testnet-api.4160.nodely.dev", "");
  const params = await algodClient.getTransactionParams().do();

  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: sender,
    receiver: sender,
    amount: 0,
    suggestedParams: params,
  });

  // Sign (will wait for operator approval)
  try {
    const signed = await client.signTransaction(txn);
    console.log("Signed!");

    // Submit directly (no processing needed)
    const txid = await sendRawTransaction(algodClient, signed);
    console.log(`TxID: ${txid}`);

    // Wait for confirmation
    const result = await algosdk.waitForConfirmation(algodClient, txid, 4);
    console.log(`Confirmed in round ${result.confirmedRound}`);
  } catch (error) {
    if (error instanceof SignerError) {
      console.log(`Failed: ${error.message}`);
    } else {
      throw error;
    }
  }
}

main().catch(console.error);
```

## LogicSig Resource Planning

The signer plans LogicSig program bytes, argument bytes, and opcode cost as
independent consensus resources. Under v42, excess program bytes are paid by
the group fee; dummies are added only when argument or opcode capacity
requires them.

### How It Works (Server-Side)

1. Server selects the authorization-path resource profile.
2. Server solves argument and opcode capacity, adding canonical dummies only
   when required.
3. Server adds the v42 program-byte fee contribution.
4. Server computes the final group ID and signs all transactions.
5. SDK returns the complete signed group ready for submission.

### Example: Falcon-1024 Key

```typescript
const params = await algodClient.getTransactionParams().do();
const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
  sender: falconAddr,
  receiver: receiverAddr,
  amount: 1000000,
  suggestedParams: params,
});

// Server automatically adds dummies - just sign and submit
const signed = await client.signTransaction(txn);
const txid = await sendRawTransaction(algodClient, signed);
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
- SDK path: `typescript`

APlane is an open-source project stewarded by the APlane Project.

See the repository [README](https://github.com/aplane-algo/aplanesdk/blob/main/README.md) for project overview and alpha-status guidance, and [DISCLAIMER.md](https://github.com/aplane-algo/aplanesdk/blob/main/DISCLAIMER.md) for risk, liability, and usage information.
