# APlane TypeScript SDK

TypeScript SDK for signing Algorand transactions via apsigner.

## Versioning

SDK packages are published only when the SDK changes. SDK versions track
compatible APlane release tags and may skip product release numbers.

## Installation

```bash
npm install aplanesdk algosdk
```

For the AlgoKit adapter example/client helpers, install AlgoKit Utils 4 in the
same project:

```bash
npm install "@algorandfoundation/algokit-utils@^10.0.0-beta.2"
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
npm install ../path/to/aplanesdk-0.20.0.tgz algosdk
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

Connect to apsigner on a remote machine through an SSH tunnel with 2FA:

```typescript
const client = await SignerClient.connectSsh(
  "signer.example.com",
  "your-token",              // used for both SSH auth and HTTP API
  "~/.ssh/id_ed25519",
  {
    sshPort: 1127,           // default: 1127
    signerPort: 11270,       // default: 11270
    timeout: 30000,          // optional explicit shorter request timeout
  }
);
```

**Note**: SSH uses 2FA (token + public key). The token is passed as the SSH
username. Remember to close when done:

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
  config.yaml          # Connection settings
  aplane.token         # Authentication token
  .ssh/
    id_ed25519         # SSH key
    known_hosts        # Trusted signer host keys
```

Example `config.yaml` (remote via SSH):
```yaml
endpoint:
  signer_port: 11270
  ssh:
    host: signer.example.com
    port: 1127
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    trust_on_first_use: false
```

If you want Trust-On-First-Use host enrollment, set `endpoint.ssh.trust_on_first_use: true`. On first connection, the SDK will trust and save the signer's SSH host key into `known_hosts`.

## Authentication

The token is the contents of the `aplane.token` file from your apsigner data directory.

```typescript
import { loadToken } from "aplanesdk";

// Load from file
const token = loadToken("~/aplane/apclient/aplane.token");

// Or from environment
const token = process.env.APSIGNER_TOKEN;
```

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
const identity = await client.getStatus();
console.log(identity.state, identity.keysetRevision);
```

`keysetRevision` is process-local and useful for deciding when to refresh
`listKeys(true)`; it is not durable across apsigner restarts.
`approvalWaitSeconds` is used by the SDK to size `/sign` deadlines.

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
- `keyType`: "ed25519", "aplane.falcon1024.v1", "aplane.timed-whitelist.v1", etc.
- `lsigSize`: LogicSig size (for budget calculation)
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
already owns transaction encoding and wants APlane's native response shape.

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

### AlgoKit Utils Adapter

For AlgoKit Utils 4 (utils-ts v10) transaction signing, use the adapter
account. It connects AlgoKit clients to APlane's transaction signing functions
and presents the `addr` + `signer(txnGroup, indexesToSign)` shape.

The minimal repository example is `examples/algokit_self_send.ts`. From a
checkout with dependencies installed and the SDK built:

```bash
cd ~/aplanesdk/typescript
npm install
npm install --no-save "@algorandfoundation/algokit-utils@^10.0.0-beta.2"
npm run build
export APCLIENT_DATA=~/aplane/apclient
export APLANE_ADDRESS=SENDER_ADDRESS
node --import tsx examples/algokit_self_send.ts
```

The example builds a transaction with AlgoKit, signs it through the APlane
adapter, then submits the signed blobs with AlgoKit's algod client:

```typescript
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

Use `createTransaction.*` when APlane must own final signing and any
APlane-managed group expansion. `algorand.send.*` owns the composer send path
and signs inside that path.

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

## Supported Key Types

| Key Type | Description | Notes |
|----------|-------------|-------|
| `ed25519` | Native Algorand keys | Standard signing |
| `aplane.falcon1024.v1` | Post-quantum LogicSig | Signature in LogicSig.Args[0] |
| `aplane.sentry-ed25519.v1` | Sentry component key | Policy signature only; not a spending account |
| `aplane.falcon1024-sentry-ed25519.v1` | Guarded account | Requires user and sentry component signatures |
| `aplane.timed-whitelist.v1` | Time-locked allow-list | No signature, TEAL-only |
| `aplane.htlc.v*` | Hash-locked funds | Requires `preimage` arg (check `signingArgs`) |

The server assembles the complete signed transaction - the SDK returns a base64 string ready for submission.

## Sentry And Guarded Accounts

Sentry component keys are public policy-signature selectors, not Algorand
spending accounts. Do not use them as senders, receivers, auth addresses, or
rekey targets. Guarded account keys must be signed through the guarded flow.

Low-level endpoint wrappers are available:

```typescript
const userPart = await userClient.requestComponentSign({
  role: COMPONENT_SIGN_ROLE_USER,
  component_key: "GUARDED_ACCOUNT_ADDRESS",
  group_bytes_hex: ["5458..."],
  target_indices: [0],
});

const sentryPart = await sentryClient.requestComponentSign({
  role: COMPONENT_SIGN_ROLE_SENTRY,
  component_key: "SENTRY_COMPONENT_SELECTOR",
  group_bytes_hex: ["5458..."],
  target_indices: [0],
});

const assembled = await userClient.requestGuardedAssemble({
  group_bytes_hex: ["5458..."],
  targets: [{
    target_index: 0,
    guarded_account: "GUARDED_ACCOUNT_ADDRESS",
    user_signature: userPart.signatures[0].signature,
    sentry_signature: sentryPart.signatures[0].signature,
  }],
});
```

For the common explicit two-client flow, use `signGuardedGroup`:

```typescript
const result = await signGuardedGroup({
  userClient,
  sentryClient,
  sentryComponentKey: "SENTRY_COMPONENT_SELECTOR",
  groupBytesHex: ["5458..."],
  guardedTargets: [
    { targetIndex: 0, guardedAccount: "GUARDED_ACCOUNT_ADDRESS" },
  ],
});
const signedGroup = result.signedGroup;
```

`assembleGroup()` remains the local multi-party concatenation helper; it is not
the same operation as server-side guarded assembly.

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
    console.log("Invalid token");
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
import { SignerClient, loadToken, SignerError, sendRawTransaction } from "aplanesdk";
import algosdk from "algosdk";

async function main() {
  // Load token
  const token = loadToken("~/aplane/apclient/aplane.token");

  // Connect to local signer
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

## Fee Pooling (Large LogicSigs)

Algorand limits LogicSig size to 1000 bytes per transaction. Large signatures like Falcon-1024 (~3000 bytes) exceed this limit.

**Solution**: The server automatically creates dummy transactions to expand the LogicSig budget pool. Each transaction in a group contributes 1000 bytes to the shared pool.

### How It Works (Server-Side)

1. Server detects key's `lsigSize` exceeds available budget
2. Server calculates dummies needed: `ceil(total_lsig_bytes / 1000) - num_txns`
3. Server creates dummy self-payment transactions (0 amount, min fee)
4. Server distributes dummy fees across LogicSig transactions in the group
5. Server computes group ID and signs all transactions
6. SDK returns concatenated signed group ready for submission

### Example: Falcon-1024 Key

```typescript
// Falcon-1024 has lsigSize ~3035 bytes, needs 3 dummies
// Total group: 1 main + 3 dummies = 4 transactions
// Pool budget: 4 x 1000 = 4000 bytes (enough for 3035)

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

| Key Type | LogicSig Size | Dummies Needed | Extra Fee |
|----------|---------------|----------------|-----------|
| Ed25519 | 0 | 0 | 0 |
| Falcon-1024 | ~3035 | 3 | ~3000 uA |

The extra fee covers the dummy transactions required for post-quantum security.

## License

MIT

## Project

This SDK is part of the APlane project:

- Repository: https://github.com/aplane-algo/aplanesdk
- SDK path: `typescript`

APlane is an open-source project stewarded by the APlane Project.

See the repository [README](https://github.com/aplane-algo/aplanesdk/blob/main/README.md) for project overview and alpha-status guidance, and [DISCLAIMER.md](https://github.com/aplane-algo/aplanesdk/blob/main/DISCLAIMER.md) for risk, liability, and usage information.
