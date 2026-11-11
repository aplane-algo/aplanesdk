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
steps for an ALGO payment.

- **Result.** `signed_group` is the group as submitted; the first
  `original_count` entries are yours and the rest are resource dummies the
  signer appended. `tx_ids`, `fees` and `group_id` are computed from the
  signed bytes. A signer may raise a fee or assign a group, so `tx_ids` can
  differ from the IDs of the transactions you prepared.
- **Options.** `no_wait=True` returns once the node accepts the group, with
  outcome `"submitted"`. `wait_rounds` is how many further rounds to wait for
  confirmation (0 means the default, 10). A cosigned account needs nothing
  extra when the client came from `SignerClient.from_env` and its
  `endpoints.yaml` lists the account's cosigner: the SDK finds it there (see
  "Finding the cosigner" below). Otherwise pass `cosigner_client` with
  `cosigner_component_key`, or a `cosigner_resolver`; either one wins over
  the registry. The SDK does not close a cosigner client you pass.
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
| `SignOutcomeUnknownError` | A signing exchange ended with no usable answer: none arrived, the signer's 200 answer could not be read (not exactly one JSON object of the expected shape: empty, cut off, `null`, not an object, text after it, or a field of the wrong type or out of range), or checking, decoding or describing it raised an exception that is not one of the SDK's own refusals (a fault in the SDK's checks, not a verdict on the answer). A signature may have been released; nothing was submitted. | Check with the operator or the audit log before signing again. The error's `request_id` names the request whose answer was lost: the `/sign` of the ordinary flow (which also carries `requests`), the `/sign/component`, `/sign/assemble` or primary `/sign` of the cosigned sequence (for a fault between its requests, the last of them that answered), or the rotating sign request, whose error carries the prepared group in `rotating` (see below). |
| `SubmissionRejectedError` | The node refused the group or dropped it from its pool. | Read the reason. The signed bytes and IDs are in `signed_group` and `tx_ids`. |
| `SubmissionUncertainError` | `stage` says where it stopped: `"submit"` (the submission's answer never arrived), `"confirm"` (not confirmed within the wait), or `"unsent"` (the call's `timeout` passed after signing, before submission; the node does not have it). Unless unsent, it may still confirm. | Look up `tx_ids`, or submit the same `signed_group` again with `submit_signed_group`. Do not sign a replacement until the outcome is known: both could execute. |

A node that answers "already in ledger" has a transaction with the same ID
from an earlier submission of the group. The SDK treats that as submitted and
looks for the outcome; it is not a rejection. A committed transaction that
carries a lease is the exception: the node refuses it for its lease, and the
SDK reports a rejection.

By default the call has no deadline of its own. Each signer request keeps
its usual timeout, and a request that times out or disconnects while
approval is pending is canceled with a best-effort `/sign/cancel`, as for the
other signing calls; such an ending is a `SignOutcomeUnknownError`.

`timeout=` (seconds, the whole call) sets one, on `send_prepared`,
`send_payment`, `prepare_rotating`, `sign_prepared_rotating` and
`wait_for_outcome`. Every HTTP request to a signer, a cosigner or the node is
held to what remains, and the steps check it in between; it does not
interrupt a call already blocked outside HTTP. Where it passes decides what
you get, as in the Go SDK when its context deadline passes:

- before any approval-bearing request is posted: `SendTimeoutError` (a
  `SignerError`), nothing signed, nothing canceled;
- while an approval-bearing request is waiting: a best-effort `/sign/cancel`,
  then `SignOutcomeUnknownError` with the request ID (the prepared group for
  a rotating account, and `last_valid`), whose `error` is the
  `SendTimeoutError`;
- after signing, before submission: `SubmissionUncertainError` with stage
  `"unsent"` (`SEND_STAGE_UNSENT`): the node does not have the group, and
  `signed_group` holds it;
- during submission or the confirmation wait: `SubmissionUncertainError` with
  stage `"submit"` or `"confirm"`.

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

The existing `sign_*` and `simulate_*` calls are unchanged. A `simulate_*`
result is `failed` unless the node returned exactly one group result, that
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

#### After an uncertain outcome

`client.resolve_outcome(algod_client, error)` takes a
`SignOutcomeUnknownError` or a `SubmissionUncertainError` and says where
things stand, from the node alone: it never signs, never submits and never
calls the signer. Both errors carry `last_valid`, the earliest last valid
round of what was sent to be signed (the signer never changes validity
rounds, so it is the signed group's too); after it nothing that request
released can execute. The helper reads the node's current round, then looks
up the first transaction ID when the IDs are known (a group is atomic). The
`OutcomeReport` it returns has `state`, `confirmed_round` (0 unless
confirmed), `tx_ids`, `last_valid`, `current_round`, `safe_to_replace`,
`signed_group` and `rotating` (when the error carried them) and `advice`, one
sentence on what to do.

For a `SubmissionUncertainError`, whose signed bytes and IDs are known:

- the node has it in a block: `confirmed`;
- it is in the node's pool: `pending`;
- the node does not have it (or dropped it with a pool error) and the current
  round is at most `last_valid`: `not_seen`, it can still execute; submit the
  same signed group again, or wait until `last_valid` has passed;
- not found, or a pool error, and the current round is past `last_valid` by
  at most 500 rounds: `expired`, and `safe_to_replace` is true;
- past `last_valid` by more than 500 rounds: `too_old`; a node answers only
  for recent rounds, so a confirmed transaction can look not found. Look the
  ID up on an indexer before sending again.

For a `SignOutcomeUnknownError`, where this call submitted nothing:

- a rotating account's prepared group is looked up first: `confirmed` or
  `pending` as above; not found, or a pool error, falls through to the rounds;
- the current round is at most `last_valid`: `signable`, a signature may have
  been released and can still execute (for a rotating account, sign the same
  prepared group again; otherwise wait until `last_valid` has passed before
  building a replacement);
- for a rotating account, the current round is past `last_valid` by at most
  500 rounds: `expired`, `safe_to_replace`; past it by more than 500 rounds:
  `too_old`. Signing the same prepared group again gives the same IDs, which
  may then have been submitted, so the group can have confirmed, and the node
  may no longer remember it. Look the ID up on an indexer before sending
  again;
- for an account that is not rotating, the current round is past
  `last_valid`: `expired`, `safe_to_replace`. There is no `too_old` here: this
  call never submitted, and the signed bytes never left the SDK, so expiry
  alone settles it. There are no IDs to look up (the signer may have changed
  the transactions), so `tx_ids` is empty.

The state names are the constants `OUTCOME_CONFIRMED`, `OUTCOME_PENDING`,
`OUTCOME_NOT_SEEN`, `OUTCOME_SIGNABLE`, `OUTCOME_EXPIRED` and
`OUTCOME_TOO_OLD`. Any other error, or `None`, is refused with `SignerError`
"not an uncertain outcome"; so is an error with no last valid round, or a
submission error with no transaction IDs. A node failure other than the
lookup's "not found" is raised, never turned into a state.

`client.wait_for_outcome(algod_client, error, timeout=None)` resolves once a
round, waiting for each next round with the node's status-after-block call,
until the state is `confirmed`, `expired` or `too_old`. `timeout` is in
seconds, for the whole call: `None` (the default) sets no limit; 0, a
negative or a non-finite number is refused with `ValueError`, but only after
the refusals of the error above, which come first. The limit is checked
before each check of the node: when it passes, `SendTimeoutError` is raised
with the last report as its `report`, or `None`, with nothing asked of the
node, when it passed before the first.

```python
try:
    result = client.send_prepared(algod_client, prepared)
except (SignOutcomeUnknownError, SubmissionUncertainError) as error:
    report = client.resolve_outcome(algod_client, error)
    print(report.state, report.advice)
    if not report.safe_to_replace:
        raise
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
