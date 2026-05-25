# TypeScript SDK Guide

Use the APlane TypeScript SDK to sign Algorand transactions through
`apsigner` from Node.js applications and scripts.

The published package is `aplanesdk`. It uses the same client data directory and
SSH-backed connection model as `apshell`.

## Overview

The TypeScript SDK is a user-facing integration surface for:

- loading client config and token state from `APCLIENT_DATA`
- provisioning a token over the SSH `request-token` flow
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
  - an existing client data directory with config, token, SSH key, and
    `known_hosts`, or
  - explicit signer host, token, SSH key, and `known_hosts` paths

The SDK expects:

- `algosdk` as a peer dependency
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

Install AlgoKit Utils 4 in the same project when using the optional AlgoKit
adapter example/client helpers:

```bash
npm install "@algorandfoundation/algokit-utils@^10.0.0-beta.2"
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

Resolution order (the SDK has no implicit default — `resolveDataDir` throws
`SignerError` if neither is set):

1. explicit `dataDir`
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

- `config.yaml` for SSH host/port and signer REST port
- `aplane.token` for HTTP and SSH token auth
- `.ssh/id_ed25519` for client SSH auth
- `.ssh/known_hosts` for SSH host key verification

Example `config.yaml`:

```yaml
signer_port: 11270
ssh:
  host: signer.example.com
  port: 1127
  identity_file: .ssh/id_ed25519
  known_hosts_path: .ssh/known_hosts
  trust_on_first_use: false
```

If `trust_on_first_use: true` is set, the SDK will auto-trust an unknown host
key on first connection and save it to `known_hosts`. Otherwise, unknown hosts
are rejected until the host key is already trusted.

## First-Time Setup

If you already installed APlane locally or in client-only mode, the easiest
path is:

1. install APlane and create or obtain an `apclient` data directory
2. generate or provide the client SSH key under `.ssh/id_ed25519`
3. provision a token
4. connect with `SignerClient.fromEnv()`

Provision and save a token with the TypeScript helper:

```ts
import { requestTokenToFile } from "aplanesdk";

const tokenPath = await requestTokenToFile();
console.log(`Saved token to ${tokenPath}`);
```

`requestTokenToFile()`:

- uses the same data-dir resolution as `SignerClient.fromEnv()`
- loads SSH host, port, key path, and `known_hosts` path from `config.yaml`
- requests a token over SSH as `request-token:default`
- saves the token to `<dataDir>/aplane.token`

The provisioning helper only supports the current product identity `default`.
An operator must approve the request in `apadmin`.

Alternatively, you can obtain the token by running `apshell` and executing
the `request-token` command; `apshell` writes the approved token to
`<dataDir>/aplane.token` using the same client data directory.

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
- loads `config.yaml`
- loads `aplane.token`
- resolves SSH paths relative to the client data dir
- establishes the SSH tunnel automatically
- verifies that the signer answers on the forwarded REST port

`SignerClient.fromEnv()` requires:

- a token file at `<dataDir>/aplane.token`
- an `ssh` block in `config.yaml`
- a readable SSH private key at the configured `identity_file`

### Explicit SSH Connection

```ts
import { SignerClient, expandPath } from "aplanesdk";

const client = await SignerClient.connectSsh(
  "signer.example.com",
  "your-token",
  "~/.ssh/id_ed25519",
  {
    sshPort: 1127,
    signerPort: 11270,
    knownHostsPath: expandPath("~/.ssh/known_hosts"),
    trustOnFirstUse: false,
  }
);

try {
  console.log(await client.health());
} finally {
  await client.close();
}
```

This is useful when:

- you do not want to depend on `APCLIENT_DATA`
- you manage the token out-of-band
- your app needs to choose the signer target dynamically

Prefer the SSH-backed paths above. For advanced integrations that already own
the HTTP transport path, the public `SignerClient(baseUrl, token, timeout)`
constructor can be used directly. An explicit timeout shorter than the signer
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

### Identity Status

```ts
const identity = await client.getStatus();
console.log(identity.state, identity.keysetRevision, identity.approvalWaitSeconds);
```

`getStatus()` calls authenticated `/status`. It does not require unlock; a
locked signer is returned as status data. Use `keysetRevision` as a
process-local signal to refresh `listKeys(true)` only when the loaded keyset
changes. Do not treat it as durable across apsigner restarts.

The SDK also uses `approvalWaitSeconds` to size `/sign` deadlines. If discovery
fails or an older signer omits the field, signing falls back to 6 minutes.

### List Keys

```ts
const keys = await client.listKeys(true);
for (const key of keys) {
  console.log(key.address, key.keyType, key.lsigSize);
}
```

`listKeys()` returns public SDK objects with camelCase fields such as:

- `address`
- `publicKeyHex`
- `keyType`
- `lsigSize`
- `isGenericLsig`
- `signingArgs`
- `templateProvenanceStatus`
- `templateProvenanceNote`
- `templateStatus`
- `templateWarning`

`templateStatus` and `templateWarning` are legacy aliases for
`templateProvenanceStatus` and `templateProvenanceNote`.

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
- explicit mnemonic import support through `mnemonicImport`

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

1. use `planGroup()` with foreign slots and `lsigSizes`
2. collect the finalized foreign signatures from the other party
3. resubmit those signed slots as `passthrough` for final signing

Do not mix foreign entries and `passthrough` entries in the same request.

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

### AlgoKit Utils Adapter

The TypeScript SDK also exposes an optional AlgoKit Utils 4 (utils-ts v10)
adapter for AlgoKit transaction signing.

The minimal repository example is `typescript/examples/algokit_self_send.ts`.
From a checkout with dependencies installed and the SDK built:

```bash
cd ~/aplanesdk/typescript
npm install
npm install --no-save "@algorandfoundation/algokit-utils@^10.0.0-beta.2"
npm run build
export APCLIENT_DATA=~/aplane/apclient
export APLANE_ADDRESS=SENDER_ADDRESS
node --import tsx examples/algokit_self_send.ts
```

The core flow is:

1. Build the transaction with `algorand.createTransaction.*`.
2. Sign it with `createApsignerAccount(...).signer`.
3. Submit the returned signed blobs with `algorand.client.algod.sendRawTransaction(...)`.

```ts
import { AlgorandClient, microAlgo } from "@algorandfoundation/algokit-utils";
import { SignerClient, createApsignerAccount } from "aplanesdk";

const sender = "SENDER_ADDRESS";
const algorand = AlgorandClient.testNet();
const signer = await SignerClient.fromEnv();

const info = await algorand.account.getInformation(sender);
const account = createApsignerAccount({
  client: signer,
  address: sender,
  authAddress: info.authAddr?.toString() ?? sender,
});
const txn = await algorand.createTransaction.payment({
  sender,
  signer: account,
  receiver: sender,
  amount: microAlgo(0),
  validityWindow: 1000,
});
const signed = await account.signer([txn], [0]);
const txId = (await algorand.client.algod.sendRawTransaction(signed)).txId;
```

You can also register the account with AlgoKit for call sites that resolve
signers from the client:

```ts
algorand.setSignerFromAccount(account);
```

The adapter connects AlgoKit clients to APlane's transaction signing functions
and presents the AlgoKit `addr` plus `signer(txnGroup, indexesToSign)` account
shape.

Use `createTransaction.*` when APlane must own final signing and any
APlane-managed group expansion. `algorand.send.*` owns the composer send path
and signs inside that path.

## Transaction Semantics

- `signTransaction()` returns one base64 string containing the full signed
  output, including any dummies the server added.
- `signTransactions()` returns one concatenated base64 string for the full
  signed group.
- `signTransactionsList()` returns per-slot base64 strings; it also rejects
  foreign slots for `/sign`.
- `signRequests()` accepts one or more raw `/sign` request entries and returns the raw
  `/sign` response.
- `planGroup()` returns unsigned `TX`-prefixed hex transactions plus a mutation
  report.
- passthrough entries are base64-encoded signed transaction msgpack slots that
  already carry the intended group ID
- foreign planning can include `lsigSizes` hints for LogicSig budget planning

The helper `sendRawTransaction()` accepts the base64 string returned by the SDK
and handles common algod rejection cases with cleaner APlane error types.

## Error Handling

Main SDK error classes:

- `SignerError`
- `AuthenticationError`
- `SigningRejectedError`
- `SignerUnavailableError`
- `KeyNotFoundError`
- `KeyDeletionError`
- `TokenProvisioningError`

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
    console.error("bad or missing token");
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

- `knownHostsPath` is required for explicit SSH connections and token
  provisioning. When trust-on-first-use is enabled, that path is where the SDK
  saves the newly trusted host key.
- If optional dependencies are omitted and `ssh2` is unavailable, the SSH
  connection and token provisioning paths will fail at runtime until `ssh2` is
  installed.
- `sendRawTransaction()` is optional. You can still call
  `algodClient.sendRawTransaction(...)` directly if you prefer raw algod errors.
- The SDK exports both runtime helpers and lower-level utilities such as
  `loadConfig`, `loadToken`, `resolveDataDir`, `encodeTransaction`, and
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
