# Python SDK Guide

Use the APlane Python SDK to sign Algorand transactions through `apsigner`
from Python applications and scripts.

The published package is `aplanesdk`. It uses the same client data directory and
SSH-backed connection model as `apshell`, so it fits naturally into an
existing APlane client install.

## Overview

The Python SDK is a user-facing integration surface for:

- loading client config and token state from `APCLIENT_DATA`,
- provisioning a token over the SSH `request-token` flow,
- connecting to `apsigner` over the standard SSH-backed product path,
- listing signer keys and available key types,
- planning and signing single transactions and groups,
- assembling multi-party group results,
- submitting signed transactions with cleaner algod error mapping.

Package versions are tracked independently across languages. Do not assume the
Python, Go, and TypeScript SDK package versions will always match.

## Requirements

- Python `>=3.10`
- `pip`
- an APlane signer you can reach over the standard SSH-backed client path
- either:
  - an existing client data directory with config, token, SSH key, and
    `known_hosts`, or
  - explicit signer host, token, SSH key, and `known_hosts` paths

When you install `aplanesdk`, its runtime dependencies are installed with it,
including `py-algorand-sdk`, `paramiko`, `requests`, and `pyyaml`.

## Installation

The published package name is `aplanesdk` on PyPI.

### Recommended: Install In A Virtual Environment

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

Install the SDK from PyPI:

```bash
python -m pip install aplanesdk
```

Install a specific published version:

```bash
python -m pip install 'aplanesdk==<version>'
```

Install AlgoKit Utils in the same environment when using the optional AlgoKit
adapter:

```bash
python -m pip install 'algokit-utils>=5.0.0b1'
```

Verify that the package imports and reports the installed version:

```bash
python -c 'import aplanesdk; print(aplanesdk.__version__)'
```

### Install From A Repo Checkout

For local development against this repository:

```bash
python -m pip install -e ./python
```

Install with development/test extras:

```bash
python -m pip install -e './python[dev]'
```

### What Gets Installed

Installing `aplanesdk` also installs its runtime dependencies, including:

- `py-algorand-sdk`
- `paramiko`
- `requests`
- `pyyaml`

You do not need to install those separately unless you are managing them
yourself in a larger application environment.

## Configuration And Credentials

The Python SDK follows the same client data directory convention as
`apshell`.

Resolution order (the SDK has no implicit default — `SignerClient.from_env`
raises `SignerError` if neither is set):

1. explicit `data_dir=...`
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

If `ssh.trust_on_first_use: true` is set, the SDK will auto-trust an unknown
host key on first connection and save it to `known_hosts`. Otherwise, unknown
hosts are rejected until the host key is already trusted.

## First-Time Setup

If you already installed APlane locally or in client-only mode, the easiest
path is:

1. install APlane and create or obtain an `apclient` data directory
2. generate or provide the client SSH key under `.ssh/id_ed25519`
3. provision a token
4. connect with `SignerClient.from_env()`

Provision and save a token with the Python helper:

```python
from aplanesdk import request_token_to_file

token_path = request_token_to_file()
print(f"Saved token to {token_path}")
```

`request_token_to_file()`:

- uses the same data-dir resolution as `SignerClient.from_env()`
- loads SSH host, port, key path, and `known_hosts` path from `config.yaml`
- requests a token over SSH as `request-token:default`
- saves the token to `<data_dir>/aplane.token` with mode `0600`

The provisioning helper only supports the current product identity
`default`. An operator must approve the request in `apadmin`.

Alternatively, you can obtain the token by running `apshell` and executing
the `request-token` command; `apshell` writes the approved token to
`<data_dir>/aplane.token` using the same client data directory.

## Connection Methods

### Recommended: Load From Client Data Dir

```python
from aplanesdk import SignerClient

client = SignerClient.from_env()
try:
    print(client.health())
finally:
    client.close()
```

This path:

- resolves the client data dir,
- loads `config.yaml`,
- loads `aplane.token`,
- resolves SSH paths relative to the client data dir,
- establishes the SSH tunnel automatically,
- verifies that the signer answers on the forwarded REST port.

`SignerClient.from_env()` requires:

- a token file at `<data_dir>/aplane.token`
- an `ssh` block in `config.yaml`
- a readable SSH private key at the configured `identity_file`

### Explicit SSH Connection

```python
from aplanesdk import SignerClient

with SignerClient.connect_ssh(
    host="signer.example.com",
    token="your-token",
    ssh_key_path="~/.ssh/id_ed25519",
    known_hosts_path="~/.ssh/known_hosts",
    ssh_port=1127,
    signer_port=11270,
) as client:
    print(client.health())
```

This is useful when:

- you do not want to depend on `APCLIENT_DATA`
- you manage the token out-of-band
- your app needs to choose the signer target dynamically

The SDK uses token-as-SSH-username plus public-key auth, matching the normal
product SSH flow.

### Advanced: Caller-Managed HTTP

The low-level constructor `SignerClient(base_url, token, timeout=...)` exists
and can be used if you already own the HTTP transport path. The normal product
and convenience flow remains the SSH-backed path shown above. An explicit
timeout shorter than the signer approval wait will cancel queued/pending manual
approval; SDK `/sign` calls include a `request_id` and send a best-effort
`/sign/cancel` when the HTTP request times out or disconnects.
High-level signing methods accept an optional keyword-only `request_id` for
applications that need user-initiated cancellation from another thread.

`cancel_sign_request(request_id)` exposes explicit synchronous sign-request
cancellation for advanced callers that already know a request ID.

Python high-level signing generates a request ID by default. Interactive
applications can pass an application-owned ID, then call
`cancel_sign_request()` with the same value from another thread:

```python
request_id = "wallet-ui-approval-123"
signed = client.sign_transaction(txn, request_id=request_id)
# elsewhere, if the user aborts while approval is pending:
client.cancel_sign_request(request_id)
```

## Common Tasks

### Health Check

```python
if client.health():
    print("Signer is reachable")
```

`health()` returns `True` on HTTP 200 and `False` on unreachable or unhealthy
responses.

### Identity Status

```python
identity = client.get_status()
print(identity.state, identity.keyset_revision, identity.approval_wait_seconds)
```

`get_status()` calls authenticated `/status`. It does not require unlock; a
locked signer is returned as status data. Use `keyset_revision` as a
process-local signal to refresh `list_keys(refresh=True)` only when the loaded
keyset changes. Do not treat it as durable across apsigner restarts.

The SDK also uses `approval_wait_seconds` to size `/sign` deadlines. If
discovery fails or an older signer omits the field, signing falls back to 6
minutes.

### List Keys

```python
keys = client.list_keys()
for key in keys:
    print(key.address, key.key_type, key.lsig_size)
```

Useful `KeyInfo` fields include:

- `address`
- `key_type`
- `public_key_hex`
- `lsig_size`
- `is_generic_lsig`
- `signing_args`
- `template_provenance_status`
- `template_provenance_note`
- `template_status`
- `template_warning`

`template_status` and `template_warning` are legacy aliases for
`template_provenance_status` and `template_provenance_note`.

If you need one cached entry by address:

```python
info = client.get_key_info("YOUR_ADDRESS")
```

### List Key Types

```python
key_types = client.list_key_types()
for kt in key_types:
    print(kt.key_type, kt.display_name, kt.requires_logicsig)
```

Use this to discover signer-supported key types rather than hard-coding them.
Creation and runtime metadata are surfaced through `creation_params` and
`runtime_args`. Explicit mnemonic import support is surfaced through
`mnemonic_import`.

### Generate A Key

```python
result = client.generate_key("ed25519")
print(result.address)
```

This is an authenticated admin operation and requires an unlocked signer.

Key types with creation parameters take a string map:

```python
result = client.generate_key(
    "aplane.timelock.v1",
    {
        "recipient": "ADDR1",
        "unlock_round": "123456",
    },
)
```

### Delete A Key

```python
client.delete_key("ADDRESS_TO_DELETE")
```

This is also an authenticated admin operation and requires an unlocked signer.

### Sign One Transaction

```python
from aplanesdk import SignerClient, send_raw_transaction
from algosdk import transaction
from algosdk.v2client import algod

client = SignerClient.from_env()
algod_client = algod.AlgodClient("", "https://testnet-api.4160.nodely.dev")
params = algod_client.suggested_params()

txn = transaction.PaymentTxn(
    sender="SENDER_ADDRESS",
    sp=params,
    receiver="RECEIVER_ADDRESS",
    amt=1000000,
)

signed = client.sign_transaction(txn)
txid = send_raw_transaction(algod_client, signed)
print(txid)
```

If you are signing for a rekeyed account, pass the auth address explicitly:

```python
signed = client.sign_transaction(txn, auth_address="AUTH_ADDRESS")
```

Generic LogicSig runtime args are passed as raw bytes:

```python
signed = client.sign_transaction(
    txn,
    auth_address="LOGICSIG_ADDRESS",
    lsig_args={"preimage": b"secret"},
)
```

### Sign A Group

```python
signed_group = client.sign_transactions([txn1, txn2])
```

Without passthrough entries:

- do not pre-assign a group ID
- do not pre-insert dummy transactions
- let the signer compute grouping, dummy insertion, and fee pooling

If you want per-slot outputs instead of one concatenated base64 blob:

```python
signed_list = client.sign_transactions_list([txn1, txn2])
```

### Plan A Group Without Signing

```python
plan = client.plan_group([txn1, txn2])
print(plan["transactions"])
print(plan["mutations"])
```

Use `plan_group()` when you need:

- dry-run visibility into dummy insertion and fee changes
- unsigned post-mutation transactions for simulation
- a first pass for multi-party coordination

### AlgoKit Utils Adapter

The Python SDK also exposes an optional AlgoKit Utils 4 (utils-py v5) adapter
for AlgoKit transaction signing.

The minimal repository example is `python/examples/algokit_self_send.py`. From
a checkout, run it as a module so Python imports the local SDK source instead
of any installed `aplanesdk` package:

```bash
cd ~/aplanesdk/python
export APCLIENT_DATA=~/aplane/apclient
export APLANE_ADDRESS=SENDER_ADDRESS
python -m examples.algokit_self_send
```

The core flow is:

1. Build the transaction with `algorand.create_transaction.*`.
2. Sign it with `create_apsigner_account(...).signer`.
3. Submit the returned signed blobs with `algorand.client.algod.send_raw_transaction(...)`.

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

You can also register the account with AlgoKit for call sites that resolve
signers from the client:

```python
algorand.set_signer_from_account(account)
```

The adapter connects AlgoKit clients to APlane's transaction signing functions
and presents the AlgoKit `addr` plus `signer(txn_group, indexes_to_sign)`
account shape.

Use `create_transaction.*` when APlane must own final signing and any
APlane-managed group expansion. `algorand.send.*` owns the composer send path
and signs inside that path.

The Python AlgoKit signer callback is synchronous. `ApsignerAccount` exposes
`cancel()` as the cancellation side channel and rejects overlapping sign calls
on the same account with `RuntimeError`. Use separate account objects for
concurrent signing. In asyncio applications, wrap the AlgoKit call site with
`asyncio.to_thread(...)` so the event loop is not blocked while the operator
approves the request. If an application needs to own request IDs, pass
`new_request_id`, a callable that returns a fresh ID for each sign call.

## Transaction Semantics

The Python SDK uses `py-algorand-sdk` transaction objects as input and returns
base64-encoded signed payloads for submission.

Important behavior:

- `sign_transaction()` returns a single base64 string
- `sign_transactions()` returns one base64 string containing the concatenated
  signed group
- `sign_transactions_list()` returns one base64 string per slot
- `sign_requests()` accepts one or more raw `/sign` request entries and returns the raw
  `/sign` response
- for large LogicSigs, the signer may add dummy transactions for fee pooling
- the high-level signing helpers convert the server’s hex response to base64

### Foreign Entries

Python follows the cross-SDK contract here:

- foreign entries are allowed in `plan_group()`
- foreign entries are rejected client-side for `/sign`

In practice, that means:

- use `plan_group()` first when some slots are signed by another party
- do not mix foreign entries and `passthrough` entries in the same request
- then resubmit the finalized foreign slots as `passthrough`

### Passthrough And Multi-Party Assembly

`passthrough` lets you include base64-encoded signed transaction msgpack slots
in a final signing request.
When passthrough entries are present:

- the caller must pre-assign group IDs on all transactions
- the signer will not insert dummies for the whole group
- the signer treats passthrough transactions as immutable

For multi-party workflows, the standard high-level flow is:

1. use `plan_group()` with foreign slots and `lsig_sizes`
2. collect the finalized foreign signatures from the other party
3. resubmit those signed slots as `passthrough` for final signing

`assemble_group()` is a lower-level utility for workflows that already have
partial list-per-slot outputs where unsigned slots are represented by empty
strings:

```python
from aplanesdk import assemble_group

combined = assemble_group([alice_signed_list, bob_signed_list])
```

Each slot must have exactly one non-empty signed entry across the input lists.

## Error Handling

The SDK raises typed exceptions for the common signer-side failure cases:

- `AuthenticationError`
- `SigningRejectedError`
- `SignerUnavailableError`
- `KeyNotFoundError`
- `KeyDeletionError`
- `TokenProvisioningError`
- `TransactionRejectedError`
- `LogicSigRejectedError`
- `InsufficientFundsError`
- `InvalidTransactionError`

Typical pattern:

```python
from aplanesdk import (
    AuthenticationError,
    SignerUnavailableError,
    SigningRejectedError,
    SignerError,
)

try:
    signed = client.sign_transaction(txn)
except AuthenticationError:
    print("Token invalid or missing")
except SigningRejectedError:
    print("Operator rejected the request")
except SignerUnavailableError:
    print("Signer unreachable, locked, or unavailable")
except SignerError as err:
    print(f"Signing failed: {err}")
```

`send_raw_transaction()` adds cleaner algod error mapping for common rejection
cases such as LogicSig rejection, insufficient funds, and malformed groups.

## Related Docs

- main APlane repository `docs/USER_INSTALL.md`
- main APlane repository `docs/USER_CONFIG.md`
- main APlane repository `docs/USER_QUICKSTART.md`
- main APlane repository `docs/ARCH_CONTRACTS.md`
- [`python/README.md`](../python/README.md)
