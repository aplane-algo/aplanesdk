# APlane Python SDK

Python SDK for signing Algorand transactions via apsigner.

## Versioning

SDK packages are published only when the SDK changes. SDK versions track
compatible APlane release tags and may skip product release numbers.

## Installation

```bash
pip install aplanesdk
```

The published package is `aplanesdk` on PyPI.

For the AlgoKit adapter, install AlgoKit Utils in the same environment:

```bash
pip install 'algokit-utils>=5.0.0b1'
```

Or install from source:

```bash
cd python
pip install -e .
```

## Quick Start

```python
from aplanesdk import SignerClient, send_raw_transaction
from algosdk import transaction
from algosdk.v2client import algod

# Connect to signer (reads config.yaml and token from data dir)
client = SignerClient.from_env()

# Build transaction with algosdk
algod_client = algod.AlgodClient("", "https://testnet-api.4160.nodely.dev")
params = algod_client.suggested_params()

txn = transaction.PaymentTxn(
    sender="SENDER_ADDRESS",
    sp=params,
    receiver="RECEIVER_ADDRESS",
    amt=1000000  # 1 ALGO
)

# Sign via apsigner (waits for operator approval)
signed = client.sign_transaction(txn)

# Submit to network (signed is ready to use, no processing needed)
txid = send_raw_transaction(algod_client, signed)
print(f"Submitted: {txid}")
```

## Connection Methods

All SDK connections use the configured SSH-backed signer path. Direct local HTTP connection is not a supported SDK mode.

### Environment-Based Connection (Recommended)

Load configuration from a data directory. The directory is required — pass
`data_dir` or set the `APCLIENT_DATA` environment variable:

```python
# Set environment variable
# export APCLIENT_DATA=~/aplane/apclient

client = SignerClient.from_env()

# Or pass directly
client = SignerClient.from_env(data_dir="~/aplane/apclient")
```

Data directory structure (installer default: `~/aplane/apclient`):
```
<data_dir>/
  config.yaml          # Connection settings
  aplane.token         # Authentication token
  .ssh/
    id_ed25519         # SSH private key for authentication
    known_hosts        # Trusted server host keys
```

Example `config.yaml`:
```yaml
endpoint:
  signer_port: 11270
  ssh:
    host: localhost            # Change to remote host if signer is on another machine
    port: 1127
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
```

### Direct SSH Connection

Connect explicitly via SSH tunnel with 2FA:

```python
client = SignerClient.connect_ssh(
    host="signer.example.com",
    token="your-token",           # used for both SSH auth and HTTP API
    ssh_key_path="~/.ssh/id_ed25519",
    ssh_port=1127,                # default: 1127
    signer_port=11270,            # default: 11270
    timeout=30                    # optional explicit shorter request timeout
)
```

**Note**: SSH verifies the enrolled public key, then performs a programmatic
mutual proof of the token bound to the accepted host key and fresh nonces. The
SSH username is the non-secret identity ID; the bearer token is never sent as
SSH metadata. Keys are enrolled via the `request-token` operator-approved flow.

The SSH tunnel is established automatically. Remember to close when done:

```python
client.close()
```

Or use as a context manager:

```python
with SignerClient.connect_ssh(host="...", token="...", ssh_key_path="...") as client:
    signed = client.sign_transaction(txn)
# Tunnel closed automatically
```

## Authentication

The recommended way to obtain a token is via the `request-token` flow, which enrolls your SSH key and provisions a token in a single operator-approved step. The token is saved automatically to `$APCLIENT_DATA/aplane.token`.

If your token was provisioned separately (e.g. copied by the operator), you can load it explicitly:

```python
from aplanesdk import load_token

token = load_token("/path/to/apclient/aplane.token")
```

## API Reference

### SignerClient

#### `health() -> bool`

Check if signer is reachable.

```python
if client.health():
    print("Signer is online")
```

#### `get_status() -> StatusResponse`

Fetch authenticated signer status. This works while the signer is locked.

```python
identity = client.get_status()
print(identity.state, identity.keyset_revision)
```

`keyset_revision` is process-local and useful for deciding when to refresh
`list_keys(refresh=True)`; it is not durable across apsigner restarts.
`approval_wait_seconds` is used by the SDK to size `/sign` deadlines.

#### `list_keys() -> List[KeyInfo]`

List available signing keys.

```python
keys = client.list_keys()
for key in keys:
    print(f"{key.address} [{key.key_type}]")
```

Returns list of `KeyInfo`:
- `address`: Algorand address
- `key_type`: "ed25519", "aplane.falcon1024.v1", "aplane.htlc.v1", etc.
- `lsig_size`: spend-path LogicSig size used for budget calculation. For
  `bounded1`, this excludes the external contract-admin signature slot;
  `bounded_authorization.post_signing_lsig_size` is admin-inclusive.
- `is_generic_lsig`: True if no cryptographic signature needed
- `signing_args`: List of `SigningArg` for LogicSigs (name, arg_type, description)

The SDK exposes bounded inventory and ordinary spend signing only. It does not
build, partially sign, or complete contract-admin rekey transactions; use the
APlane `apbounded-admin` workflow for those operations.

**Discovering required arguments for generic LogicSigs:**

```python
key_info = client.get_key_info(hashlock_address)
if key_info.signing_args:
    for arg in key_info.signing_args:
        print(f"{arg.name}: {arg.arg_type} - {arg.description}")
```

#### `sign_transaction(txn, auth_address=None, lsig_args=None) -> str`

Sign a single transaction. Returns a base64-encoded string ready for submission.

The server automatically handles fee pooling for large LogicSigs (e.g., Falcon-1024) by adding dummy transactions as needed.

```python
# Basic signing (uses txn.sender as auth_address)
signed = client.sign_transaction(txn)

# Rekeyed account (different auth key)
signed = client.sign_transaction(txn, auth_address="SIGNER_KEY_ADDRESS")

# Generic LogicSig with runtime args (e.g., HTLC)
signed = client.sign_transaction(
    txn,
    auth_address="HASHLOCK_ADDRESS",
    lsig_args={"preimage": b"secret_value"}
)

# Submit directly (no processing needed)
txid = send_raw_transaction(algod_client, signed)
```

#### `sign_transactions(txns, auth_addresses=None, lsig_args_map=None) -> str`

Sign multiple transactions as a group. Returns a base64-encoded string of concatenated signed transactions, ready for submission.

**Important**: Do NOT pre-assign group IDs. The server computes the group ID after adding any required dummy transactions for large LogicSigs.

```python
# Build transactions (do NOT call assign_group_id)
txn1 = transaction.PaymentTxn(sender=addr1, sp=params, receiver=addr2, amt=100000)
txn2 = transaction.PaymentTxn(sender=addr2, sp=params, receiver=addr1, amt=100000)

# Sign group (server handles grouping and dummies)
signed = client.sign_transactions([txn1, txn2])

# Submit directly (no processing needed)
txid = algod_client.send_raw_transaction(signed)
```

#### `sign_transactions_list(txns, auth_addresses=None, lsig_args_map=None) -> List[str]`

Like `sign_transactions()` but returns individual base64-encoded transactions instead of concatenated. Useful when you need to inspect transactions individually.

```python
signed_list = client.sign_transactions_list([txn1, txn2])
# signed_list is List[str], each element is a base64-encoded signed transaction
```

#### `sign_requests(sign_entries, request_id=None) -> GroupSignResponse`

Send one or more raw `/sign` request entries. Use this when an integration
already owns transaction encoding and wants APlane's native response shape.

```python
response = client.sign_requests(
    [{
        "txn_bytes_hex": "5458...",
        "auth_address": "SIGNER_KEY_ADDRESS",
        "txn_sender": "SENDER_ADDRESS",  # advisory display hint only
    }],
    request_id="app-owned-request-id",
)
```

### AlgoKit Utils Adapter

For AlgoKit Utils 4 (utils-py v5) transaction composers, use the adapter
account. It connects AlgoKit clients to APlane's transaction signing functions
and presents the `addr` + `signer(txn_group, indexes_to_sign)` shape.

The minimal repository example is `examples/algokit_self_send.py`. From a
checkout, run it as a module so it imports the local SDK source:

```bash
cd ~/aplanesdk/python
export APCLIENT_DATA=~/aplane/apclient
export APLANE_ADDRESS=SENDER_ADDRESS
python -m examples.algokit_self_send
```

The example builds a transaction with AlgoKit, signs it through the APlane
adapter, then submits the signed blobs with AlgoKit's algod client:

```python
from algokit_utils import AlgoAmount, AlgorandClient, PaymentParams
from aplanesdk import SignerClient
from aplanesdk.algokit import create_apsigner_account

sender = "SENDER_ADDRESS"
algorand = AlgorandClient.testnet()

with SignerClient.from_env() as signer:
    auth = algorand.client.algod.account_information(sender).auth_addr or sender
    account = create_apsigner_account(signer, sender, auth_address=auth)
    txn = algorand.create_transaction.payment(
        PaymentParams(
            sender=sender,
            signer=account,
            receiver=sender,
            amount=AlgoAmount(micro_algo=0),
            validity_window=1000,
        )
    )
    signed = account.signer([txn], [0])
    tx_id = algorand.client.algod.send_raw_transaction(signed).tx_id
```

Use `create_transaction.*` when APlane must own final signing and any
APlane-managed group expansion. `algorand.send.*` owns the composer send path
and signs inside that path.

The Python AlgoKit signer is synchronous. `ApsignerAccount` tracks one active
signing request at a time; overlapping calls on the same account raise
`RuntimeError`. Use separate account objects for concurrent signing. For
asyncio applications, run the AlgoKit call site in a worker thread, for example
with `asyncio.to_thread(...)`. If an application needs to own request IDs, pass
`new_request_id`, a callable that returns a fresh ID for each sign call.

Signing calls discover `/status.approval_wait_seconds` and use that value
plus 30 seconds of slack for the request timeout. If discovery fails or an older
signer omits the field, signing falls back to 6 minutes. An explicit shorter
timeout still wins; SDK `/sign` calls include a `request_id` and send a
best-effort `/sign/cancel` when the HTTP request times out or disconnects.
High-level signing methods accept an optional keyword-only `request_id`.
AlgoKit adapter callers can call `account.cancel()` from another thread to
cancel the in-flight adapter request.

#### `cancel_sign_request(request_id) -> CancelSignResponse`

Ask apsigner to cancel a live synchronous `/sign` request by request ID.
Successful responses are idempotent for client behavior and return state
`"canceled"` or `"not_found"`.

Python high-level signing generates a request ID by default. Interactive
applications can pass an application-owned ID, then call
`cancel_sign_request()` with the same value from another thread:

```python
request_id = "wallet-ui-approval-123"
signed = client.sign_transaction(txn, request_id=request_id)
# elsewhere, if the user aborts while approval is pending:
client.cancel_sign_request(request_id)
```

For AlgoKit adapter signing, call `cancel()` on the account:

```python
account.cancel()
```

#### `close()`

Close the client and SSH tunnel (if any).

```python
client.close()
```

## Supported Key Types

| Key Type | Description | Notes |
|----------|-------------|-------|
| `ed25519` | Native Algorand keys | Standard signing |
| `aplane.falcon1024.v1` | Post-quantum LogicSig | Signature in LogicSig.Args[0] |
| `aplane.ed25519.v1` | Ed25519 DSA LogicSig | Library-visible plain DSA account |
| `aplane.sentry-falcon1024.v1` | Sentry component key | Policy signature only; not a spending account |
| `aplane.falcon1024-sentry1024.v1` | Guarded account | Requires user and sentry component signatures |
| `aplane.corridor.v1` | Corridor account | Falcon user and sentry signatures with corridor policy |
| `aplane.falcon1024-allowlist.v1` | Bounded allowlist | Inline allowlist; `bounded1` signing flow |
| `aplane.falcon1024-allowlist.v2` | Bounded allowlist | Merkle allowlist; `bounded1` signing flow |
| `aplane.falcon1024-timelock.v1` | Bounded timelock | Round-gated `bounded1` signing flow |
| `aplane.falcon1024-allowlist-alock.v1` | Rekey-locked bounded allowlist | Ordinary spending uses `bounded1`; admin rekey is outside SDK scope |
| `aplane.htlc.v1` | Hash-locked funds | Requires `preimage` arg (check `signing_args`) |

The server assembles the complete signed transaction - the SDK returns a base64 string ready for submission.

## Sentry And Guarded Accounts

Sentry component keys are public policy-signature selectors, not Algorand
spending accounts. Do not use them as senders, receivers, auth addresses, or
rekey targets. Guarded account keys must be signed through the guarded flow.

Low-level endpoint wrappers are available:

```python
user_part = user_client.request_component_sign(ComponentSignRequest(
    role=COMPONENT_SIGN_ROLE_USER,
    component_key="GUARDED_ACCOUNT_ADDRESS",
    group_bytes_hex=["5458..."],
    target_indices=[0],
))

sentry_part = sentry_client.request_component_sign(ComponentSignRequest(
    role=COMPONENT_SIGN_ROLE_SENTRY,
    component_key="SENTRY_COMPONENT_SELECTOR",
    group_bytes_hex=["5458..."],
    target_indices=[0],
))

assembled = user_client.request_guarded_assemble(GuardedAssemblyRequest(
    group_bytes_hex=["5458..."],
    targets=[GuardedAssemblyTarget(
        target_index=0,
        guarded_account="GUARDED_ACCOUNT_ADDRESS",
        user_signature=user_part.signatures[0].signature,
        sentry_signature=sentry_part.signatures[0].signature,
    )],
))
```

For the common explicit two-client flow, use `sign_guarded_group`:

```python
result = sign_guarded_group(
    user_client=user_client,
    sentry_client=sentry_client,
    sentry_component_key="SENTRY_COMPONENT_SELECTOR",
    group_bytes_hex=["5458..."],
    guarded_targets=[
        GuardedSignTarget(target_index=0, guarded_account="GUARDED_ACCOUNT_ADDRESS"),
    ],
)
signed_group = result.signed_group
```

`assemble_group()` remains the local multi-party concatenation helper; it is
not the same operation as server-side guarded assembly.

## Error Handling

### Signing Exceptions

```python
from aplanesdk import (
    SignerError,
    AuthenticationError,
    SigningRejectedError,
    SignerUnavailableError,
    KeyNotFoundError
)

try:
    signed = client.sign_transaction(txn)
except AuthenticationError:
    print("Invalid token")
except SigningRejectedError:
    print("Operator rejected the request")
except SignerUnavailableError:
    print("Signer not reachable or locked")
except KeyNotFoundError:
    print("Key not found in signer")
except SignerError as e:
    print(f"Signing failed: {e}")
```

### Submission Exceptions

`send_raw_transaction()` wraps verbose algod errors into clean exceptions:

```python
from aplanesdk import (
    send_raw_transaction,
    TransactionRejectedError,
    LogicSigRejectedError,
    InsufficientFundsError,
    InvalidTransactionError
)

try:
    txid = send_raw_transaction(algod_client, signed)
except LogicSigRejectedError as e:
    print(f"LogicSig failed: {e.reason}")  # e.txid also available
except InsufficientFundsError as e:
    print(f"Not enough funds: {e.reason}")
except InvalidTransactionError as e:
    print(f"Invalid transaction: {e.reason}")
except TransactionRejectedError as e:
    print(f"Rejected: {e.reason}")
```

## Example: Complete Workflow

```python
#!/usr/bin/env python3
from aplanesdk import SignerClient, load_token, SignerError, send_raw_transaction
from algosdk import transaction
from algosdk.v2client import algod

def main():
    # Load token
    token = load_token("~/aplane/apclient/aplane.token")

    # Connect via SSH (public key plus host-key-bound token proof)
    with SignerClient.connect_ssh(
        host="signer.example.com",
        token=token,
        ssh_key_path="~/.ssh/id_ed25519"
    ) as client:

        # List keys
        keys = client.list_keys()
        sender = keys[0].address
        print(f"Using: {sender}")

        # Build transaction
        algod_client = algod.AlgodClient("", "https://testnet-api.4160.nodely.dev")
        params = algod_client.suggested_params()

        txn = transaction.PaymentTxn(
            sender=sender,
            sp=params,
            receiver=sender,
            amt=0
        )

        # Sign (will wait for operator approval)
        try:
            signed = client.sign_transaction(txn)
            print("Signed!")

            # Submit directly (no processing needed)
            txid = send_raw_transaction(algod_client, signed)
            print(f"TxID: {txid}")

            # Wait for confirmation
            result = transaction.wait_for_confirmation(algod_client, txid, 4)
            print(f"Confirmed in round {result['confirmed-round']}")

        except SignerError as e:
            print(f"Failed: {e}")

if __name__ == "__main__":
    main()
```

## Fee Pooling (Large LogicSigs)

Algorand limits LogicSig size to 1000 bytes per transaction. Large signatures like Falcon-1024 (~3000 bytes) exceed this limit.

**Solution**: The server automatically creates dummy transactions to expand the LogicSig budget pool. Each transaction in a group contributes 1000 bytes to the shared pool.

### How It Works (Server-Side)

1. Server detects key's `lsig_size` exceeds available budget
2. Server calculates dummies needed: `ceil(total_lsig_bytes / 1000) - num_txns`
3. Server creates dummy self-payment transactions (0 amount, min fee)
4. Server distributes dummy fees across LogicSig transactions in the group
5. Server computes group ID and signs all transactions
6. SDK returns concatenated signed group ready for submission

### Example: Falcon-1024 Key

```python
# Falcon-1024 has lsig_size ~3035 bytes, needs 3 dummies
# Total group: 1 main + 3 dummies = 4 transactions
# Pool budget: 4 x 1000 = 4000 bytes (enough for 3035)

params = algod_client.suggested_params()
txn = transaction.PaymentTxn(sender=falcon_addr, sp=params, receiver=receiver, amt=1000000)

# Server automatically adds dummies - just sign and submit
signed = client.sign_transaction(txn)
txid = send_raw_transaction(algod_client, signed)
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
- SDK path: `python`

APlane is an open-source project stewarded by the APlane Project.

See the repository [README](https://github.com/aplane-algo/aplanesdk/blob/main/README.md) for project overview and alpha-status guidance, and [DISCLAIMER.md](https://github.com/aplane-algo/aplanesdk/blob/main/DISCLAIMER.md) for risk, liability, and usage information.
