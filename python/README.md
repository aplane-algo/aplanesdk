# APlane Python SDK

Python SDK for signing Algorand transactions via apsigner.

## Versioning

SDK packages are published only when the SDK changes. SDK versions track
compatible APlane release tags and may skip product release numbers.

The native-Falcon SDK release line requires an APlane signer release after
`v0.35.0`; see [`docs/COMPATIBILITY.md`](../docs/COMPATIBILITY.md).

## Installation

```bash
pip install aplanesdk
```

The published package is `aplanesdk` on PyPI.

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

# Connect to signer (reads endpoints.yaml and the enrolled SSH key from data dir)
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

Data-directory connections use `endpoints.yaml`. SSH endpoints create a
managed tunnel; HTTPS and loopback HTTP endpoints connect directly.
Managed SSH keys and host trust live under the APlane client data directory;
the SDK does not use the operating-system user's personal SSH directory.

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
  config.yaml          # Non-routing client settings
  endpoints.yaml       # Signer and cosigner routing
  .ssh/
    id_ed25519         # SSH private key: the client's credential
    known_hosts        # Trusted server host keys
```

Example `endpoints.yaml`:
```yaml
schema_version: 2
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://localhost:1127
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
```

### Direct SSH Connection

Connect explicitly via SSH tunnel, authenticated by the enrolled client key:

```python
client = SignerClient.connect_ssh(
    host="signer.example.com",
    ssh_key_path="~/aplane/apclient/.ssh/id_ed25519",
    known_hosts_path="~/aplane/apclient/.ssh/known_hosts",
    ssh_port=1127,                # default: 1127
    timeout=30,                   # optional explicit shorter request timeout
    ssh_setup_timeout=60,         # TCP dial + SSH authentication only
)
```

SSH setup uses its own 60-second deadline, independent of HTTP request and
operator approval timeouts. The deadline is cleared after authentication.
`request_enrollment()` and `request_enrollment_from_env()` expose the same
setup-only deadline as `setup_timeout`.

**Note**: SSH uses the fixed non-secret username `aplane` and public-key
authentication only; the enrolled key is the client's only credential. Keys
are enrolled via the `enroll` operator-approved flow.

The SSH tunnel is established automatically. Remember to close when done:

```python
client.close()
```

Or use as a context manager:

```python
with SignerClient.connect_ssh(
    host="...",
    ssh_key_path="~/aplane/apclient/.ssh/id_ed25519",
    known_hosts_path="~/aplane/apclient/.ssh/known_hosts",
) as client:
    signed = client.sign_transaction(txn)
# Tunnel closed automatically
```

## Authentication

The client's SSH key is its credential. A new key is enrolled once: the
request is queued for the operator to approve later in `apadmin`
(`pending=True`, the normal outcome) or the key is already enrolled, and
nothing is stored on the client. Connect once the operator has approved.
`request_enrollment_from_env(endpoint="cosigner.qa", label="ci-runner")`
selects a named endpoint; without an alias it selects the default signer:

```python
from aplanesdk import request_enrollment_from_env

result = request_enrollment_from_env(label="ci-runner")
if result.pending:
    print(f"key {result.fingerprint} queued; have the operator approve it in apadmin")
```

`request_enrollment(host, ssh_key_path, known_hosts_path=..., label=...)` is
the explicit form. The same enrollment can be done from `apshell` with
`enroll`.

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
status = client.get_status()
print(status.state, status.keyset_revision, status.warnings)
```

`keyset_revision` is process-local and useful for deciding when to refresh
`list_keys(refresh=True)`; it is not durable across apsigner restarts.
`approval_wait_seconds` is used by the SDK to size `/sign` deadlines. Display
non-empty `warnings` to operators; they report persistent health conditions
that require attention.

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
- `logic_sig_resources`: independent program-byte, argument-byte, and
  maximum-opcode-cost demand by authorization path.
- `is_generic_lsig`: True if no cryptographic signature needed
- `signing_args`: List of `SigningArg` for LogicSigs (name, arg_type, description)

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

Signing calls discover `/status.approval_wait_seconds` and use that value
plus 30 seconds of slack for the request timeout. If discovery fails or an older
signer omits the field, signing falls back to 6 minutes. An explicit shorter
timeout still wins; SDK `/sign` calls include a `request_id` and send a
best-effort `/sign/cancel` when the HTTP request times out or disconnects.
High-level signing methods accept an optional keyword-only `request_id`.

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

#### `send_prepared(algod_client, group, *, no_wait=False, wait_rounds=0, ...) -> SendResult`

Sign a prepared transaction or group, check the signed result against what was
prepared, submit exactly those bytes, and wait for confirmation. The SDK picks
the signing flow from the signer's record of each key, so the same call works
for Ed25519, native Falcon, LogicSig, bounded, cosigned and rotating accounts,
and for a rekeyed sender.

```python
prepared = client.prepare_payment(
    algod_client, sender=sender, receiver=receiver, amount=1_000_000  # microAlgos
)
result = client.send_prepared(algod_client, prepared)
print(result.tx_ids[0], result.outcome, result.confirmed_round)
```

`group` is a `PreparedGroup`, or one `PreparedTransaction`.
`send_payment(algod_client, sender=..., receiver=..., amount=...)` does both
steps for an ALGO payment.

- **Result.** `signed_group` is the group as submitted; the first
  `original_count` entries are yours and the rest are resource dummies the
  signer appended. `tx_ids`, `fees` and `group_id` are computed from the
  signed bytes. A signer may raise a fee or assign a group, so `tx_ids` can
  differ from the IDs of the transactions you prepared.
- **Options.** `no_wait=True` returns once the node accepts the group, with
  outcome `"submitted"`. `wait_rounds` is how many further rounds to wait for
  confirmation (0 means the default, 10). A cosigned account needs
  `cosigner_client` with `cosigner_component_key`, or a `cosigner_resolver`;
  the SDK does not close a cosigner client you pass.
- **Refused before signing:** an unknown signing flow
  (`UnsupportedSigningFlowError`), and a pre-signed or foreign position
  (`UnsupportedGroupError`). Use the lower-level signing calls for those
  groups.
- **No replacement spends.** The call never builds a second transaction for
  one whose outcome is unknown. A rotating send may prepare and seek approval
  again when the signer says an attempt released no signature.

Failures:

| Exception | Meaning | What to do |
|---|---|---|
| The signing call's own `SignerError` | The signer refused (policy, operator, locked), or the SDK refused the signer's answer (`verify signer response: ...`, `MaxFeeIncreaseError`). Nothing was submitted. | Read the reason. If the SDK refused a sign answer, the signer did sign and the SDK discarded the result. |
| `SignOutcomeUnknownError` | A signing exchange ended with no usable answer: none arrived, or the signer's 200 answer could not be read (not exactly one JSON object of the expected shape: empty, cut off, `null`, not an object, text after it, or a field of the wrong type or out of range). A signature may have been released; nothing was submitted. | Check with the operator or the audit log before signing again. For the ordinary flow the error carries `request_id` and `requests`; for a rotating account it carries the prepared group in `rotating` (see below). |
| `SubmissionRejectedError` | The node refused the group or dropped it from its pool. | Read the reason. The signed bytes and IDs are in `signed_group` and `tx_ids`. |
| `SubmissionUncertainError` | `stage` says where it stopped: `"submit"` (the submission's answer never arrived) or `"confirm"` (not confirmed within the wait). It may still confirm. | Look up `tx_ids`, or submit the same `signed_group` again with `submit_signed_group`. Do not sign a replacement until the outcome is known: both could execute. |

A node that answers "already in ledger" has a transaction with the same ID
from an earlier submission of the group. The SDK treats that as submitted and
looks for the outcome; it is not a rejection. A committed transaction that
carries a lease is the exception: the node refuses it for its lease, and the
SDK reports a rejection.

The call has no deadline of its own. Each signer request keeps its usual
timeout, and a request that times out or disconnects while approval is
pending is canceled with a best-effort `/sign/cancel`, as for the other
signing calls; such an ending is a `SignOutcomeUnknownError`.

A `KeyboardInterrupt`, or any other exception that is not an `Exception`, is
not turned into an SDK error: it still stops the program. What it carries
says what was in flight (on Python 3.11 and later it also gets a note):

- **While a sign, component or assembly request was pending**, the
  exception carries the request's ID as `aplane_request_id`; for a request
  awaiting approval the SDK first sends the best-effort `/sign/cancel`. A
  signature may have been released: treat it like a
  `SignOutcomeUnknownError`. For a rotating account it also carries the
  prepared group as `aplane_rotating`, whenever the interrupt came after the
  group was prepared, and the same recovery applies: sign that same prepared
  group again (below); do not call `send_payment` or `send_prepared` again
  until the first attempt's outcome is known, because that prepares a new
  spend from the same stage.
- **While the signed group was submitted or its confirmation awaited**, the
  group may have reached the node: the exception carries the signed bytes as
  `aplane_signed_group` and their IDs as `aplane_tx_ids`. Treat it like a
  `SubmissionUncertainError`.

```python
try:
    result = client.send_prepared(algod_client, prepared)
except KeyboardInterrupt as e:
    if hasattr(e, "aplane_tx_ids"):
        print("signed group may be on the network:", e.aplane_tx_ids)
    elif hasattr(e, "aplane_request_id"):
        print("a signature may have been released:", e.aplane_request_id)
    raise
```

The existing `sign_*` and `simulate_*` calls are unchanged.

#### Rotating accounts

A rotating account (`signing_flow` `rotating1`) hands itself to a fresh stage
on every spend, so the signer adds a rekey to the transaction. `send_prepared`
and `send_payment` run the whole sequence:

1. **Prepare.** The signer returns the exact group it will sign: your
   transaction with the rekey to the next stage, its fee raised, and any
   resource dummies.
2. **Check.** The SDK refuses the group unless the only changes are that
   rekey, a reported fee raise within your max fee increase, the group ID and
   canonical dummies.
3. **Simulate, unsigned,** through your algod. A group that fails raises
   `RotatingPreflightError`, as does an answer with no result for the group;
   a simulation that cannot be run raises a plain `SignerError`. Either way no
   one-time key has been used.
4. **Sign,** with operator approval, then check the signed group is exactly
   the prepared one.
5. **Submit at once** and wait for confirmation. `SendResult.rotating`
   reports the stage that signed and the stage that now controls the account.

What to know:

- **One transaction, alone.** A rotating account's transaction must be
  ungrouped, set no `rekey_to`, not close the account, and take no LogicSig
  arguments. It cannot share a group with other transactions.
- **Short validity window.** The window is at most 100 rounds, and the signer
  signs only while `first_valid_round` is at most 2 rounds ahead and at least
  10 rounds remain. Every `prepare_*` helper builds such a window when the
  sender is a rotating account. A transaction whose rounds are not current is
  refused before the operator is asked, and that includes one a helper built
  that has since gone stale: only `send_payment` rebuilds rounds without
  `refresh_validity`. For any other transaction, pass
  `refresh_validity=True` to let the SDK rebuild the rounds; that changes the
  transaction ID, so leave it off if anything outside the transaction binds
  its rounds.
- **App calls carry the rekey.** A contract that requires a zero `rekey_to`
  fails the simulation in step 3.
- **Bounded retries.** When the signer says an attempt released no signature
  (`rotating_stage_unproven`, `rotating_stage_changed`,
  `rotating_window_not_current`), the send prepares again, up to three
  attempts. Each attempt needs approval again. A timing refusal is retried
  only when the rounds may be rebuilt, and the retry uses the longest window
  to give the operator time.
- **The SDK cannot derive stage addresses.** It binds the next stage's
  address the signer reports to the prepared transaction; the signer derives
  it again from the seed before it signs.
- **Unsigned simulation checks effects, not signatures.** The node runs the
  stage program only on the signed group.
- **Two sends in a row** work once the first has confirmed, which the default
  wait ensures. Two spends prepared from the same stage cannot both land; the
  SDK does not serialize other clients or processes.

The steps are also available one at a time. None of them submits:

```python
prepared = client.prepare_rotating(txn)                                 # nothing signed
simulation = client.simulate_prepared_rotating(algod_client, prepared)  # never signs
signed = client.sign_prepared_rotating(prepared)                        # waits for approval
result = client.submit_signed_group(algod_client, signed.signed_group)
```

`prepare_rotating` returns a `PreparedRotating`. Its fields are read-only by
convention, and everything it hands out (`account`, `stage`, `target`,
`rekey_to`, `transactions`, `mutations`, `original`, `tx_ids`) is a copy. It
is verified again whenever it is simulated or signed, which catches a change
that breaks its binding to the original transaction. `sign_prepared_rotating(prepared, request_id=...)`
takes an application-owned request ID for `cancel_sign_request`.

Submit a signed rotating group promptly: the stage's one-time keys are
revealed until that transaction or a later rotation confirms.

**If a sign answer is lost** (`SignOutcomeUnknownError`, whose `rotating`
attribute holds the prepared group, or an interrupt while approval was
pending, whose `aplane_rotating` attribute holds it), call
`sign_prepared_rotating` again with that same prepared group. Do not call
`send_payment` or `send_prepared` again until the first attempt's outcome is
known. It asks for the same transaction with the same IDs
and builds no second spend. It needs approval again and succeeds only while
the stage is still live and the window still acceptable. If the retry is
refused, do not prepare a replacement until the first attempt's outcome is
known: `rotating_stage_changed` means a transaction from that stage has
confirmed.

```python
from aplanesdk import SignOutcomeUnknownError

try:
    result = client.send_payment(algod_client, sender=account, receiver=receiver, amount=5000)
except SignOutcomeUnknownError as e:
    if e.rotating is None:
        raise
    signed = client.sign_prepared_rotating(e.rotating)  # the same transaction again
    result = client.submit_signed_group(algod_client, signed.signed_group)
# After a KeyboardInterrupt with e.aplane_rotating set, the same recovery:
# client.sign_prepared_rotating(e.aplane_rotating)
```

`submit_signed_group` also submits again the `signed_group` kept by a
`SubmissionUncertainError`; the same bytes can execute only once.

A rotating account that was rekeyed to an ordinary key the signer holds has
left rotation. The `prepare_*` helpers name that key as its `auth_address`,
and it is then signed like any rekeyed account. `send_prepared` confirms the
rekey on the chain first, so an ordinary key is never asked to sign for an
account that is still rotating. `resolve_auth_address` returns the rotating
account itself as the `auth_address` of an account that has rotated, and the
stage address the chain reports as `chain_auth_address`. Recovery of an
unknown stage is an operator action (`rotate recover` in apshell).

#### `close()`

Close the client and SSH tunnel (if any).

```python
client.close()
```

## Supported Key Types

| Key Type | Description | Notes |
|----------|-------------|-------|
| `ed25519` | Native Algorand keys | Standard signing |
| `falcon1024` | Native post-quantum keys | Protocol-native Falcon-1024 signature (`PQsig`) |
| `aplane.falcon1024.v1` | Post-quantum plain host | Enabled by default. With bounds (transfer kinds, a recipient list, or limits only) a `bounded2` account; without, `plain1`, with no host rules or fee ceiling. `cosigned1` signing flow with a cosigner, `bounded1` without one |
| `aplane.ed25519.v1` | Ed25519 plain host | Library-visible; the same bounds and overlays as `aplane.falcon1024.v1`, and the spending key is classical |
| `aplane.witness-falcon1024.v1` | Witness key | Cosigner-custodied policy signature key; not a spending account |
| `aplane.htlc.v1` | Hash-locked funds | Requires `preimage` arg (check `signing_args`) |

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
sufficient for its slots. Sign it with `sign_prepared_cosigned_group`, below. `request_components` and `request_assemble` are
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

```python
result = sign_prepared_cosigned_group(
    user_client=user_client,
    cosigner_resolver=cosigner_resolver,
    prepared_group=prepared_group,
)
signed_group = result.signed_group
```

The SDK first freezes the complete canonical group through `/plan`; the user
signer then approves those bytes through `request_components()` with
`kind="bounded-base"`. It then signs ordinary positions, and only after
the user side is complete does it request cosigner signatures over the same
bytes and call `request_assemble()`. Before
signing anything, the SDK compares the
signer-produced plan with the caller's prepared group: only reported fee
pooling and group-ID assignment are accepted, and appended positions must be
canonical budget dummies. The returned group must use canonical transaction
encoding and a group ID recomputed from the presented membership. The SDK also
verifies ordinary signed positions and every assembled transaction against the
frozen transaction bytes.

`request_components()` sends best-effort `/sign/cancel` when its
approval-bearing HTTP request times out or disconnects.
`request_assemble()` does not open an approval request and is not a
cancellation handle.

The signer planner owns fee selection, authorization-resource sizing, and any
reported group mutations for the cosigned flow.

Applications that own orchestration can call `request_components()` and
`request_assemble()` directly. The cosigner signs spends and
cosigned rekeys, never a rekey to a listed address.

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
    print("Connection is not authenticated by an enrolled SSH key")
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
from aplanesdk import SignerClient, SignerError, send_raw_transaction
from algosdk import transaction
from algosdk.v2client import algod

def main():
    # Connect via SSH, authenticated by the enrolled client key
    with SignerClient.connect_ssh(
        host="signer.example.com",
        ssh_key_path="~/aplane/apclient/.ssh/id_ed25519",
        known_hosts_path="~/aplane/apclient/.ssh/known_hosts",
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

```python
params = algod_client.suggested_params()
txn = transaction.PaymentTxn(sender=falcon_addr, sp=params, receiver=receiver, amt=1000000)

# Server automatically adds dummies - just sign and submit
signed = client.sign_transaction(txn)
txid = send_raw_transaction(algod_client, signed)
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
- SDK path: `python`

APlane is an open-source project stewarded by the APlane Project.

See the repository [README](https://github.com/aplane-algo/aplanesdk/blob/main/README.md) for project overview and alpha-status guidance, and [DISCLAIMER.md](https://github.com/aplane-algo/aplanesdk/blob/main/DISCLAIMER.md) for risk, liability, and usage information.
