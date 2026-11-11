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
- planning and signing single transactions and groups
- assembling multi-party group results
- submitting signed transactions with cleaner algod error mapping

Package versions are tracked independently across languages. Do not assume the
Go, Python, and TypeScript SDK package versions will always match.

## Requirements

- Node.js `>=18`
- npm, pnpm, or yarn
- an APlane signer you can reach over the standard SSH-backed client path
- either:
  - an existing client data directory with config, an enrolled SSH key, and
    `known_hosts`, or
  - explicit signer host, enrolled SSH key, and `known_hosts` paths

The SDK expects:

- `algosdk` 3.7.0 or later as a peer dependency. Earlier releases drop a native
  post-quantum signature (`pqsig`) when they decode a signed transaction, which breaks
  simulation for native Falcon keys
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

```ts
import algosdk from "algosdk";
import { SignerClient, sendRawTransaction } from "aplanesdk";

const algodClient = new algosdk.Algodv2("", "https://testnet-api.4160.nodely.dev", "");
const suggestedParams = await algodClient.getTransactionParams().do();

const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
  sender: fromAddress,
  receiver: toAddress,
  amount: 1000,
  suggestedParams,
});

const signed = await client.signTransaction(txn);
const txid = await sendRawTransaction(algodClient, signed);
```

For rekeyed accounts, pass the signing key explicitly:

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
sender. `lsigArgsMap` is keyed by auth address. A key that matches no
position's auth address throws `SignerError`. A key whose only positions in the
request are passthrough or foreign is accepted, and its args are not sent,
because the request does not sign for that address; this lets one map serve
the plan and the final signing of the same group. An entry with no args is
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

`assembleGroup()` is a lower-level utility for workflows that already have
partial list-per-slot outputs where unsigned slots are represented by empty
strings:

```ts
import { assembleGroup } from "aplanesdk";

const aliceSigned = await aliceClient.signTransactionsList(...);
const bobSigned = await bobClient.signTransactionsList(...);
const combined = assembleGroup([aliceSigned, bobSigned]);
```

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

For manual orchestration, use `requestComponents()` on the user client with a
bounded-base target and on the cosigner client, then `requestAssemble()` on the
user client. Finish the user side (the base components and any ordinary-position
signing) before requesting cosigner components, so a cosigner never sees a group
the user signer rejects. `assembleGroup()` remains only the local multi-party
concatenation helper.

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
performs the user-first sequence:

```ts
const result = await signPreparedCosignedGroup({
  userClient,
  cosignerResolver,
  preparedGroup,
});
const signedGroup = result.signedGroup;
```

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
  // Inspect simulation.response for algod diagnostics.
}

const cosigned = await simulatePreparedCosignedGroup(algodClient, cosignedOptions);
```

`SimulationResult.signedGroup` contains fully executable signed transactions
that remain submittable until expiry. Keep them confidential. The helper sends
the exact signed group to the supplied algod with empty-signature overrides
disabled. A missing algod client fails before any signing request. Algod
execution failure sets `failed`; transport or decoding failures throw and
never trigger another signing request automatically.

## Transaction Semantics

- `signTransaction()` returns one base64 string containing the full signed
  output, including any dummies the server added.
- `signTransactions()` returns one concatenated base64 string for the full
  signed group.
- `signTransactionsList()` returns per-slot base64 strings; it also rejects
  foreign slots for `/sign`.
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

The helper `sendRawTransaction()` accepts the base64 string returned by the SDK
and handles common algod rejection cases with cleaner APlane error types.

### What The SDK Checks Before Returning

Every `/sign` and `/plan` result is checked against the request before
`signTransaction()`, `signTransactions()`/`signTransactionsList()`, `signRequests()`, `planGroup()`/`planRequests()` or `simulatePreparedGroup()` returns it. The
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

The SDK decodes request entries before sending them. Unsigned transaction
bytes must be `TX`-prefixed canonical msgpack and passthrough entries must be
canonical signed transactions, and the auth address of a position to sign
must be a valid Algorand address, or the call throws `SignerError` before any request is made.
A passthrough transaction must round-trip through the SDK's Algorand
library (`algosdk`), so one that uses a field newer than that library is refused
locally.

### Rekeyed Senders In Prep Helpers

The `prepare*` helpers and `resolveAuthAddress()` read the sender's auth
address from algod account information. algosdk v3 returns it as an `Address`
object and raw algod JSON as a string; both are accepted, and
`ResolvedAuthAddress.authAddress` and `PreparedTransaction.authAddress` are
always strings.

## Error Handling

Main SDK error classes:

- `SignerError`
- `AuthenticationError`
- `SigningRejectedError`
- `SignerUnavailableError`
- `KeyNotFoundError`
- `KeyDeletionError`
- `EnrollmentError`

Network submission helper errors:

- `TransactionRejectedError`
- `LogicSigRejectedError`
- `InsufficientFundsError`
- `InvalidTransactionError`

Example:

```ts
import {
  AuthenticationError,
  SignerUnavailableError,
  SigningRejectedError,
} from "aplanesdk";

try {
  const signed = await client.signTransaction(txn);
  const txid = await sendRawTransaction(algodClient, signed);
  console.log(txid);
} catch (err) {
  if (err instanceof AuthenticationError) {
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
- `sendRawTransaction()` is optional. You can still call
  `algodClient.sendRawTransaction(...)` directly if you prefer raw algod errors.
- The SDK exports both runtime helpers and lower-level utilities such as
  `loadConfig`, `resolveDataDir`, `encodeTransaction`, and
  `encodeLsigArgs`.

## Compatibility Notes

This SDK follows the signer API contract documented in
the signer API contract documented by the main APlane repository.

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
