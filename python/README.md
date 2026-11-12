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
from aplanesdk import SignerClient, signed_group_base64
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

# Sign via apsigner (waits for operator approval). signed is the signed
# group: a list of bytes, one signed transaction per entry, yours first.
signed = client.sign_transaction(txn)

# Submit the whole list, one of two ways. submit_signed_group submits and
# waits for confirmation, and reports a failure as SubmissionError:
result = client.submit_signed_group(algod_client, signed)
print(f"Confirmed {result.tx_ids[0]} in round {result.confirmed_round}")

# Or submit with algosdk and wait with algosdk:
# txid = algod_client.send_raw_transaction(signed_group_base64(signed))
# transaction.wait_for_confirmation(algod_client, txid, 4)
```

`signed_group_base64(signed)` is the base64 text of the entries joined in
order, which is what algosdk's `send_raw_transaction` takes. It reads no
node and does not check the entries: they come from the SDK's verified
output, and the node checks what it is sent.

To sign, submit and wait for confirmation in one call, pass the same
transaction to `send_transactions` (see below):

```python
result = client.send_transactions(algod_client, [txn])
print(result.tx_ids[0], result.confirmed_round)
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
- `address`: the account's Algorand address, kept exactly as the signer sent
  it and matched by its exact text. A witness key's record carries its
  Witness Key ID here, which is not an Algorand address. A key list that
  spells an Algorand address non-canonically (the same 32 bytes and checksum,
  other text) is refused whole with a `SignerError`, as the Go and TypeScript
  SDKs refuse it, since a lookup by the canonical address would never find
  that key.
- `key_type`: "ed25519", "aplane.falcon1024.v1", "aplane.htlc.v1", etc.
- `logic_sig_resources`: independent program-byte, argument-byte, and
  maximum-opcode-cost demand by authorization path.
- `is_generic_lsig`: True if no cryptographic signature needed
- `signing_args`: List of `SigningArg` for LogicSigs (name, arg_type, description)
- `valid_rekey_target`: whether an account of another key type may be rekeyed
  to an account of this type; the signer refuses a rekey to a held aplane key
  whose type is not one.

**Discovering required arguments for generic LogicSigs:**

```python
key_info = client.get_key_info(hashlock_address)
if key_info.signing_args:
    for arg in key_info.signing_args:
        print(f"{arg.name}: {arg.arg_type} - {arg.description}")
```

#### `sign_transaction(txn, auth_address=None, lsig_args=None) -> List[bytes]`

Sign a single transaction. Returns the signed group: a list with one entry
per transaction, each the raw msgpack bytes of one signed transaction. The
first entry is your transaction. The server pools the fees of large LogicSigs
(e.g., Falcon-1024) and adds dummy transactions as needed; they follow your
transaction in the list, and the whole list is what must be submitted.

```python
from aplanesdk import signed_group_base64

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

# Submit and wait with the SDK (SendResult, or SubmissionError)
result = client.submit_signed_group(algod_client, signed)

# Or submit and wait with algosdk
txid = algod_client.send_raw_transaction(signed_group_base64(signed))
transaction.wait_for_confirmation(algod_client, txid, 4)
```

#### `sign_transactions(txns, auth_addresses=None, lsig_args_map=None, passthrough=None, ...) -> List[bytes]`

Sign multiple transactions as a group. Returns the signed group, one entry per
transaction in group order: the transactions given, then any dummies the
server appended. Each entry is the raw msgpack bytes of one signed
transaction.

**Important**: Do NOT pre-assign group IDs. The server computes the group ID after adding any required dummy transactions for large LogicSigs.

```python
# Build transactions (do NOT call assign_group_id)
txn1 = transaction.PaymentTxn(sender=addr1, sp=params, receiver=addr2, amt=100000)
txn2 = transaction.PaymentTxn(sender=addr2, sp=params, receiver=addr1, amt=100000)

# Sign group (server handles grouping and dummies)
signed = client.sign_transactions([txn1, txn2])

# Submit and wait with the SDK, or with algosdk
result = client.submit_signed_group(algod_client, signed)
# txid = algod_client.send_raw_transaction(signed_group_base64(signed))
# transaction.wait_for_confirmation(algod_client, txid, 4)

# Or keep each entry as text, as hex, and read it back with bytes.fromhex
for entry in signed:
    print(entry.hex())
```

`passthrough` maps a group index to a transaction someone else already
signed, as its raw msgpack bytes (a `bytearray` or `memoryview` is copied).
A value that is not bytes, such as a base64 or hex string, is refused with a
`ValueError` naming the position before anything is sent, and so is one that
is not exactly one canonically encoded signed transaction. A
`PreparedTransaction` takes a pre-signed slot the same way, as
`signed_transaction` bytes.

py-algorand-sdk's signers return `SignedTransaction` objects; turn one into
the bytes the SDK takes with `encoding.msgpack_encode`, which gives base64:

```python
import base64
from algosdk import encoding

signed_bytes = base64.b64decode(encoding.msgpack_encode(signed_txn))
```

#### `sign_requests(sign_entries, request_id=None) -> GroupSignResponse`

Send one or more raw `/sign` request entries. Use this when an integration
already owns transaction encoding and wants APlane's native response shape:
the answer's `signed` list is the signer's wire answer, hex, as the signer
sends it.

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

The cancel a signing call sends itself, when its request times out or
disconnects, is best effort: its failure, or an answer to it the SDK cannot
read, never fails the call or replaces its error. Only
`cancel_sign_request()` reports a cancel's outcome. A request whose body
cannot be encoded as JSON (one holding `NaN`, say) is never sent: it is a
plain `ValueError`, with no cancel and no unknown outcome.

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
steps for an ALGO payment, and `send_transactions` (below) sends transactions
you built with algosdk.

- **Result.** `signed_group` is the group as submitted, a list with one
  entry per transaction, each the raw msgpack bytes of one signed
  transaction; the first `original_count` entries are yours and the rest are
  resource dummies the signer appended. `tx_ids`, `fees` and `group_id` are computed from the
  signed bytes. A signer may raise a fee or assign a group, so `tx_ids` can
  differ from the IDs of the transactions you prepared. Once confirmed,
  `confirmation` holds what algosdk's wait returned for the first
  transaction, unchanged; its inner transactions, logs and created IDs are
  read from it as in any algosdk program.
- **Submission.** The signed group is posted with algosdk's
  `send_raw_transaction` and followed with algosdk's
  `transaction.wait_for_confirmation` on `tx_ids[0]`, both as they are. The
  SDK does not read their answers or their errors.
- **Options.** `no_wait=True` returns once algosdk's submit call returns
  success, with outcome `"submitted"`. `wait_rounds` is how many rounds
  algosdk's wait looks for the group (0 means the default, 10; the SDK never
  passes algosdk 0, which it reads as 1000). A cosigned account needs nothing
  extra when the client came from `SignerClient.from_env` and its
  `endpoints.yaml` lists the account's cosigner: the SDK finds it there (see
  "Finding the cosigner" below). Otherwise pass `cosigner_client` with
  `cosigner_component_key`, or a `cosigner_resolver`; either one wins over
  the registry. The SDK does not close a cosigner client you pass.
- **What algosdk's wait does.** With `wait_rounds` N, algosdk reads the
  current round r, looks the first transaction up at once, and then, for k
  from 1 to N-1, waits for the block after round r+k and looks again. It
  then waits for the block after round r+N and gives up without looking, so
  a wait of 1 looks only once and can miss a confirmation in the next round.
  A lookup that fails with algod's HTTP error (`AlgodHTTPError`) is skipped;
  any other failed lookup, and any failed status read or wait for a block,
  ends the wait. The call's `timeout` cannot interrupt it: each request it
  makes has algosdk's own 30-second socket timeout, and one that times out
  ends the wait.
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
| `SignOutcomeUnknownError` | A signing exchange ended with no usable answer: none arrived, the signer's 200 answer could not be read (not exactly one JSON object of the expected shape: empty, cut off, `null`, not an object, text after it, or a field of the wrong type or out of range), or checking, decoding or describing it raised an exception that is not one of the SDK's own refusals (a fault in the SDK's checks, not a verdict on the answer). A signature may have been released; nothing was submitted. | Do not send again; see "After an unknown outcome" below. The error's `request_id` names the request whose answer was lost: the `/sign` of the ordinary flow (which also carries `requests`), the `/sign/component`, `/sign/assemble` or primary `/sign` of the cosigned sequence (for a fault between its requests, the last of them that answered), or the rotating sign request, whose error carries the prepared group in `rotating` (see below). |
| `SubmissionError` | The group was signed, and algosdk's submit call or its confirmation wait failed. `submitted` is `True` when the submit call returned success and the failure came later, and `False` when it did not return success. `error`, also the `__cause__`, is algosdk's error, unchanged. The message says which step failed and quotes it. | Read `error` as you would in any algosdk program. With `submitted` `False`, an algod HTTP 400 means the node answered: read its reason; anything else leaves it open whether the node has the group. The signed group (a list of bytes, one signed transaction per entry), the IDs and the last valid round are in `signed_group`, `tx_ids` and `last_valid`; see "After an unknown outcome" below. Do not sign a replacement until the outcome is known: both could execute. |

By default the call has no deadline of its own. Each signer request keeps
its usual timeout, and a request that times out or disconnects while
approval is pending is canceled with a best-effort `/sign/cancel`, as for the
other signing calls; such an ending is a `SignOutcomeUnknownError`.

`timeout=` (seconds) sets one, on `send_prepared`, `send_payment`,
`send_transactions`, `prepare_rotating` and `sign_prepared_rotating`. It covers signing and
submission. Every HTTP request to a signer, a cosigner or the node up to the
submission is held to what remains, and the steps check it in between; it
does not interrupt a call already blocked outside HTTP. It does not cover the
confirmation wait: algosdk's `wait_for_confirmation` cannot be interrupted,
so `wait_rounds` bounds the wait. Where it passes decides what you get:

- before any approval-bearing request is posted: `SendTimeoutError` (a
  `SignerError`), nothing signed, nothing canceled;
- while an approval-bearing request is waiting: a best-effort `/sign/cancel`,
  then `SignOutcomeUnknownError` with the request ID (the prepared group for
  a rotating account, and `last_valid`), whose `error` is the
  `SendTimeoutError`;
- after signing, before the submission: `SubmissionError` with `submitted`
  `False`, whose `error` is the `SendTimeoutError`; nothing was posted, and
  `signed_group` holds the group;
- during the submission: `SubmissionError` with `submitted` `False`, whose
  `error` is what algosdk raised for the request the limit cut short;
- after the submission, before the wait: `SubmissionError` with `submitted`
  `True`, whose `error` is the `SendTimeoutError`. With `no_wait=True` there
  is no wait to start, so the send returns with outcome `"submitted"`.

`timeout=None` (the default) behaves exactly as before.

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
  group may have reached the node: the exception carries the signed group as
  `aplane_signed_group` (a list of bytes, one signed transaction per entry)
  and their IDs as `aplane_tx_ids`. Treat it like a `SubmissionError`.

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

The `sign_*` and `simulate_*` calls do not submit. A `simulate_*` result's
`signed_group` is the signed group that was simulated, a list of bytes with
one signed transaction per entry (empty for an unsigned rotating simulation),
and its `transactions` are the simulated transactions unsigned, as hex. A
`simulate_*` result is `failed` unless the node returned exactly one group result, that
result reports no failure (no `failure-message` and no `failed-at`), and it
holds one transaction result per transaction simulated: an answer without
exactly one result, or with the wrong count of transaction results, checked
less than the group. `failure_message` says why: the node's `failure-message`
when it gave one, otherwise one of "the node returned no result for the
group", "the node returned N results for one group", "the node's result for
the group is not an object", "the node reported a failure without a message"
or "the node returned M transaction results for N transactions". Each field
is chosen by presence: `txn-groups` is read when present, even empty, and
`txn_groups` only when it is not, and so for the failure message.

#### `send_transactions(algod_client, txns, *, no_wait=False, wait_rounds=0, ...) -> SendResult`

Send transactions you built with algosdk's own constructors. For each
distinct sender, the SDK reads its account from the node and finds the
signing address as the `prepare_*` helpers do (`resolve_auth_address`: the
sender, or the address the chain says it is rekeyed to). It wraps each
transaction, in the order given, in a `PreparedTransaction` naming its
sender's signing address, and sends the group with `send_prepared`. It runs
none of the `prepare_*` preflight checks, such as balances and opt-ins.

```python
payment = transaction.PaymentTxn(
    sender=sender, sp=algod_client.suggested_params(), receiver=receiver, amt=1_000_000
)
result = client.send_transactions(algod_client, [payment])
print(result.tx_ids[0], result.outcome, result.confirmed_round)
```

The call does not modify the transaction objects you pass in. It validates
and submits the signer's returned group using the existing prepared-send
flow. Use the transaction IDs in the result.

Two rules on what you pass:

- A rotating account accepts a validity window of at most
  `ROTATING_MAX_VALIDITY_WINDOW` (100) rounds, and algosdk's
  `suggested_params()` gives 1000, so a rotating sender's transaction built
  with the defaults is refused unless you pass `refresh_validity=True` or
  build it with a window of 100 rounds or less.
- A group ID you set is kept, and the SDK then refuses an answer in which
  the signer raised a fee, appended a transaction or changed the group ID (a
  rotating account's transaction that carries one is refused before anything
  is signed), so transactions whose accounts need a fee raise or resource
  dummies cannot be sent with one: leave the group ID unset and let the
  signer group them.

The options, the result and the failures are those of `send_prepared`,
described above. An empty list is refused with a `ValueError`.
`send_transactions` itself reads each distinct sender's account once, and
the signer's keys once, before it hands the group to `send_prepared`, which
makes its own reads as documented there. A failed account lookup is a plain
`SignerError` (`SendTimeoutError` when the call's `timeout` ended it) naming
the transaction's position and sender. A failed resolution of a sender is
raised as it is, the same exception object (`KeyNotFoundError`, say), with a
note naming the position and sender (`__notes__`, which Python 3.11 and later
print with the traceback). A failed read of the signer's keys, such as a
locked or unreachable signer, is raised as it is and names no transaction.
All are raised before anything is signed.
`examples/send_built.py` is a complete program.

#### After an unknown outcome

Which case applies depends on the error.

**The group was signed** (`SubmissionError`). The error carries the signed
group (`signed_group`), the transaction IDs (`tx_ids`), the last valid round
(`last_valid`, the earliest in the group), and algosdk's error as its cause
(`error`, also `__cause__`). Read the cause as you would in any algosdk
program.

- `submitted` is `True`: algosdk's submit call returned success. Follow the
  group with algosdk's `transaction.wait_for_confirmation` on `tx_ids[0]` (a
  group confirms as a whole) for up to `last_valid` minus the current round,
  at least 1 (algosdk reads 0 as 1000 rounds). The examples wait at most 10
  more rounds. A timeout from the wait (`ConfirmationTimeoutError`) means
  only that the wait ended.
- `submitted` is `False`: the submit call did not return success. There
  are two cases.
  - The cause is algod's own HTTP 400: the node answered. Read its reason,
    as in any algosdk program; the reason decides what to do. algosdk
    raises it as an `AlgodHTTPError` whose `code` is the HTTP status:

    ```python
    from algosdk.error import AlgodHTTPError

    # The node answered with a 400: read the reason in str(error.error).
    answered_400 = isinstance(error.error, AlgodHTTPError) and error.error.code == 400
    ```

    The reason is one of three kinds. The node says the transaction is
    already in the ledger or its pool: it has the group, so follow
    `tx_ids[0]`. A refusal the same bytes will always get, such as an
    overspend or a failed signature or program; after the last valid round,
    "dead" is such an answer too, and it proves nothing about whether the
    group confirmed earlier. A refusal that depends on the moment, such as a
    fee below what the pool currently asks or a node that is behind:
    submitting the same group later may work. The SDK itself does not look.
  - Anything else (no answer, a lost connection, a 5xx, the call's
    `timeout`): the node may or may not have the group. First look
    `tx_ids[0]` up with algosdk's wait for a few rounds. If it does not
    confirm, submit the same `signed_group` again with
    `submit_signed_group`. If that comes back as a 400 saying the transaction is
    already in the ledger, the node has it: follow `tx_ids[0]`.
- Submitting the same signed group again cannot pay twice. A 400 saying the
  transaction is already in the ledger is good news, not a refusal. After
  the last valid round the node refuses the group as dead whether or not it
  confirmed, so a refusal then proves nothing.
- Once the last valid round has passed, neither a node's "not found" nor a
  refusal proves the group never confirmed (a node looks back only about
  1000 rounds from the current round): check an indexer before building a
  replacement.

**Nothing was submitted** (`SignOutcomeUnknownError`, any account that is not
rotating). A signature may exist that the SDK never received. Once
`last_valid` has passed, nothing signed by that request can execute, and a
replacement is safe. No lookup is needed. Before that, do not build a
replacement with different transaction IDs.

**Rotating accounts** (`SignOutcomeUnknownError` whose `rotating` holds the
prepared group). Sign the same prepared group again with
`sign_prepared_rotating` and submit the result with `submit_signed_group` (see
"If a sign answer is lost" below). It produces the same transaction IDs, so it
cannot pay twice.

A `SendTimeoutError` raised on its own means nothing that can execute was
signed. When the time limit ends the call later, the call raises one of the
two errors above, and that error's case applies.

```python
from algosdk import transaction
from aplanesdk import SubmissionError

try:
    result = client.send_prepared(algod_client, prepared)
except SubmissionError as error:
    if not error.submitted:
        # The two cases above: with algod's 400 the node answered, so read
        # the reason; otherwise look tx_ids[0] up, then submit the same
        # signed_group again with submit_signed_group.
        raise
    try:
        current = algod_client.status()["last-round"]
        info = transaction.wait_for_confirmation(
            algod_client, error.tx_ids[0], max(error.last_valid - current, 1)
        )
    except Exception:
        # Only the wait ended. Keep the original error: it holds the signed
        # group, the IDs and the last valid round.
        raise error
    print("confirmed in round", info["confirmed-round"])
```

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
   `RotatingPreflightError`, as does an answer without exactly one result
   for the group, or with the wrong count of transaction results; a
   simulation that cannot be run raises a plain `SignerError`. Either way no
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
`SubmissionError`; the same bytes can execute only once. It takes the signed
group as a list with one entry per transaction, in group order, each the raw
msgpack bytes of exactly one canonically encoded signed transaction (a
`bytearray` or `memoryview` is copied to bytes when the call starts). An
entry that is not bytes, such as a hex or base64 string, is refused with a
`ValueError` naming its position, and one that is not exactly one canonical
signed transaction with a `SignerError`, both before anything is posted.

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

The server assembles the complete signed transaction; the SDK returns the signed group as a list of bytes, one signed transaction per entry, ready for submission.

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
signed_group = result.signed_group  # a list of bytes, one signed transaction per entry
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

### Finding the cosigner

A cosigned account needs nothing extra when `endpoints.yaml` lists its
cosigner. A `SignerClient` made by `from_env` (or `from_env(data_dir=...)`),
given no `cosigner_client` and no `cosigner_resolver`, finds the cosigner
with an `EndpointCosignerResolver` over the same registry, connecting with the
same `timeout`, `trust_on_first_use` and `ssh_setup_timeout`. It makes the
resolver on first use, keeps it, and closes it, with its connections, when
the client is closed; a closed client makes none again, so a later cosigned
call fails as with no cosigner and opens no connection. A client not made
from a data directory still needs a cosigner passed to it.

```yaml
schema_version: 2
endpoints:
  primary:  {role: signer,   url: "ssh://signer.example.com:1127"}
  cosign-a: {role: cosigner, url: "ssh://cosigner-a.example.com:1127"}
```

On first use the resolver connects to every endpoint with role `cosigner` (at
most 12), each with its own `identity_file` and `known_hosts_path`, and reads
its `/keys`: at most 4 endpoints at once, 10 seconds per endpoint, 30 seconds
for the whole sweep. A record counts when `is_witness_key` is true and it has
a `key_type`; its `public_key_hex` must be hex (compared in either case) and
its `address` must be the Witness Key ID derived from its key type and public
key, or the whole endpoint's listing is invalid. The witness key an account
names must be listed by exactly one endpoint; the resolver then uses that
endpoint's client, with the listed Witness Key ID as the component key. The
sweep is kept, and a key it does not hold makes one fresh sweep, which reads
`/keys` again through the connections still live and reconnects the endpoints
that had failed. A kept connection that has been closed, or whose SSH link is
down, counts as not holding its keys (a local check, with no request), so it
too makes one fresh sweep, which connects that endpoint again.
`witness_key_id(key_type, public_key)` derives the ID: the unpadded base32 of
SHA-512/256 over `APLANE_WITNESS_KEY_ID_V1`, the key type and the public key,
each prefixed by its length as 4 bytes big-endian.

Otherwise it raises `CosignerDiscoveryError` (a `SignerError`):

- more than one endpoint lists the key: `cosigner discovery: Witness Key ID
  <id> (<key type>) is listed by endpoints "a", "b"; each witness key needs
  exactly one endpoint`;
- none does: `cosigner discovery: no endpoint lists Witness Key ID <id> (<key
  type>); endpoints: "a" ok, "b" unreachable`, every cosigner endpoint by
  alias, each `ok`, `unreachable`, `locked`, `authentication failed`,
  `invalid cosigner metadata` or `configuration invalid`;
- no cosigner endpoint is configured: `cosigner discovery: endpoints.yaml
  lists no cosigner endpoint`;
- any cosigner endpoint's SSH host key differs from the pinned one, needed or
  not: `cosigner discovery: endpoint "<alias>": <the mismatch error>`, and
  nothing from that sweep is kept;
- the account's cosigner public key is not hex, or it names no cosigner key
  type, or the resolver is closed, or a hand-built registry lists more than 12
  cosigner endpoints, each with its own message;
- the call's `timeout` passed during discovery: an error that is both a
  `CosignerDiscoveryError` and a `SendTimeoutError`.

The public key in the not-hex message, and the aliases in the list of
endpoints and in the host key message, are quoted as Go's `%q` quotes them
(`\"`, `\\`, `\n`, `\t`, `\xNN` for other control characters, and so on), so
the three SDKs word the same failure alike.

The cosigned sequence resolves the cosigner of every target that cannot take
the listed path (a spend, or a rekey of an account without a rekey list)
before anything is asked to sign, with any resolver, so a failure is a plain
error with nothing signed. A rekey of an account with a rekey list may take
the listed path, which needs no cosigner, so its cosigner is resolved only
after the base component, and only when the signer's path needs one: the
rekey-list escape hatch keeps working with the cosigner down or not
configured. A resolver's own exception is passed on as it is, never as an
unknown outcome, even when it was raised from an SDK error that is one.

To use the resolver yourself, build it from a data directory or a loaded
registry and close it when done:

```python
from aplanesdk import EndpointCosignerResolver

with EndpointCosignerResolver(data_dir="~/aplane/apclient") as resolver:
    result = client.send_prepared(algod_client, prepared, cosigner_resolver=resolver)
```

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

### How Signer Answers Are Read

Every 200 answer from the signer is read as exactly one JSON object of the
shape the Go SDK declares for it. A field left out or `null`, at any depth,
reads as its zero value; an unknown field is ignored. A body that is not one
object (empty, cut off, `null`, a list, text after it, `NaN`) or a field of
the wrong type or out of range is an answer that could not be read:

- at a request that releases no signature (`/status`, `/keys`, `/keytypes`,
  `/plan`, `/admin/generate`, `/sign/cancel`, `DELETE /admin/keys`) it is a
  plain `SignerError` beginning "failed to decode ... response". A `/status`
  that cannot be read never stops a sign request: the SDK then uses its
  default approval wait;
- at an approval-bearing request (`/sign`, `/sign/component`,
  `/sign/assemble`, `/sign/rotating/sign`) a signature may be out, so a send
  reports it as `SignOutcomeUnknownError`.

An answer whose `error` field is set is a refusal, and a key generation
answer that names no address is refused too ("missing address"). A non-200
body that is JSON but not an object carries no error code; its text is the
message.

The three SDKs' JSON readers differ in known ways that a real signer never
reaches:

- Go matches keys case-insensitively, so of two keys that differ only in case
  (`signed` and `Signed`) the later one wins where TypeScript and Python read
  only the exact name.
- Go refuses `-0` for an unsigned field where the others read it as 0.
- Of a key given twice, the later value is read, except that a later `null`
  leaves Go's earlier string, number or boolean in place (a list, object or
  pointer it does empty); Python and TypeScript read that `null` as zero.
- A body that starts with a UTF-8 byte order mark is readable in TypeScript
  only.
- An integer of more than 4300 digits is unreadable in Python only (Python's
  integer conversion limit).

## Example: Complete Workflow

```python
#!/usr/bin/env python3
from aplanesdk import SignerClient, SignerError, signed_group_base64
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

            # Submit the whole signed group with algosdk, and wait with
            # algosdk. client.submit_signed_group(algod_client, signed) does
            # both in one call instead.
            txid = algod_client.send_raw_transaction(signed_group_base64(signed))
            print(f"TxID: {txid}")
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

# The server adds the dummies; they follow the payment in the signed group
signed = client.sign_transaction(txn)
result = client.submit_signed_group(algod_client, signed)
# or: txid = algod_client.send_raw_transaction(signed_group_base64(signed))
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
