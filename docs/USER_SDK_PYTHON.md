# Python SDK Guide

Use the APlane Python SDK to sign Algorand transactions through `apsigner`
from Python applications and scripts.

The published package is `aplanesdk`. It uses the same client data directory and
SSH-backed connection model as `apshell`, so it fits naturally into an
existing APlane client install.

## Overview

The Python SDK is a user-facing integration surface for:

- loading client config and the client SSH identity from `APCLIENT_DATA`,
- enrolling the client SSH key at a signer over the `enroll` flow,
- connecting to `apsigner` over the standard SSH-backed product path,
- listing signer keys and available key types,
- sending a transaction or group in one call (sign, check, submit and wait
  for confirmation) for every account type the signer holds,
- finding a cosigned account's cosigner from `endpoints.yaml`,
- planning and signing single transactions and groups without submitting
  them,
- assembling multi-party group results,
- submitting signed transactions with cleaner algod error mapping.

Package versions are tracked independently across languages. Do not assume the
Python, Go, and TypeScript SDK package versions will always match.

## Requirements

- Python `>=3.10`
- `pip`
- an APlane signer you can reach over the standard SSH-backed client path
- either:
  - an existing client data directory with config, an enrolled SSH key, and
    `known_hosts`, or
  - explicit signer host, enrolled SSH key, and `known_hosts` paths

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

- `py-algorand-sdk` 2.12.0 or later. Earlier releases read a transaction with a native
  post-quantum signature (`pqsig`) as unsigned
- `paramiko`
- `requests`
- `pyyaml`

You do not need to install those separately unless you are managing them
yourself in a larger application environment.

## Configuration And Credentials

The Python SDK follows the same client data directory convention as
`apshell`.

APlane never reads or writes the operating-system user's personal `~/.ssh`
directory. Managed SSH keys and host trust live under `<data_dir>/.ssh/`.

Resolution order (the SDK has no implicit default — `SignerClient.from_env`
raises `SignerError` if neither is set):

1. explicit `data_dir=...`
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
  credential, and the signer attributes every request on the tunnel to it. The Python SDK loads Ed25519 or ECDSA (P-256/384/521) key files; the signer refuses RSA and DSA keys, and hardware-backed `sk-` keys are not supported from a key file.
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
`SignerClient.from_env(trust_on_first_use=True)`.

## First-Time Setup

If you already installed APlane locally or in client-only mode, the easiest
path is:

1. install APlane and create or obtain an `apclient` data directory
2. generate or provide the client SSH key under `.ssh/id_ed25519`
3. enroll that key at the signer
4. connect with `SignerClient.from_env()`

Ask for enrollment with the Python helper:

```python
from aplanesdk import request_enrollment_from_env

result = request_enrollment_from_env(endpoint="cosigner.qa", label="ci-runner")
if result.pending:
    print(f"key {result.fingerprint} queued; have the operator approve it in apadmin")
```

`request_enrollment_from_env()`:

- uses the same data-dir resolution as `SignerClient.from_env()`
- selects the default signer or named endpoint from `endpoints.yaml`
- uses that endpoint's SSH host, port, key, and `known_hosts` path
- opens an `enroll` SSH session, which answers at once
- returns an `EnrollmentResult`: `pending=True` when the request was queued
  for the operator (the normal outcome), `False` when the key was already
  enrolled; `fingerprint` is the key's SHA256 fingerprint. Nothing is stored.

Enrollment targets the signer's product store. The operator approves the
request later in `apadmin`; connect after that. The same enrollment can be
done from `apshell` with `enroll`. A key the signer has not
enrolled yet (or has revoked) fails `from_env`/`connect_ssh` with
`AuthenticationError`.

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
- refuses a `config.yaml` whose `network` is not in its `networks_allowed`,
  when that list is set, and one whose `networks_allowed` is not a list of
  network IDs written as text (a malformed list is an error, never an empty
  one; a bare number, `true`/`false` or an empty entry is refused, so quote a
  name such as `"1"`). Quote a network name that YAML could read as a boolean, such as `"on"`, `"yes"` or `"no"`. The `network` value follows the same rule: it must be text and a network ID, and a bare number or `true`/`false` is refused.
- validates `config.yaml` contains no obsolete routing,
- loads and selects an endpoint from `endpoints.yaml`,
- resolves SSH paths relative to the client data dir,
- establishes the SSH tunnel automatically,
- verifies that the signer answers on the forwarded REST port.

`SignerClient.from_env()` requires:

- a default signer endpoint, or an explicit `endpoint=...` alias
- a readable, enrolled private key at that endpoint's `identity_file`

### Explicit SSH Connection

```python
from aplanesdk import SignerClient

with SignerClient.connect_ssh(
    host="signer.example.com",
    ssh_key_path="~/aplane/apclient/.ssh/id_ed25519",
    known_hosts_path="~/aplane/apclient/.ssh/known_hosts",
    ssh_port=1127,
    ssh_setup_timeout=60,
) as client:
    print(client.health())
```

`ssh_setup_timeout` separately bounds TCP dialing and SSH authentication and
defaults to 60 seconds. The deadline is cleared after authentication, so it
does not shorten the established tunnel or an operator approval wait.
Enrollment exposes the same setup-only control as `setup_timeout`.

This is useful when:

- you do not want to depend on `APCLIENT_DATA`
- you manage the SSH identity out-of-band
- your app needs to choose the signer target dynamically

The SSH username is the fixed non-secret value `aplane`, and public-key
authentication with the enrolled key is the only credential. The explicit form
of enrollment is `request_enrollment(host, ssh_key_path,
known_hosts_path=..., label=...)`.

### Advanced: Caller-Managed Tunnel

The low-level constructor `SignerClient(base_url, timeout=...)` exists and can
be used if you already own the SSH tunnel to the signer; the signer attributes
the requests to the key that opened it, and a signer's loopback REST port
answers only `/health`. The normal product
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

## Sending Transactions

### Send A Payment Or A Prepared Group

`send_payment()` and `send_prepared()` are the recommended way to send. One
call signs a transaction or group, checks the signed result, submits exactly
those bytes and waits for confirmation:

```python
result = client.send_payment(
    algod_client, sender=sender, receiver=receiver, amount=1_000_000  # microAlgos
)
print(result.tx_ids[0], result.outcome, result.confirmed_round)
```

`send_payment()` builds the payment with `prepare_payment()` and sends it.
`send_prepared()` sends what a `prepare_*` helper built: a `PreparedGroup`,
or one `PreparedTransaction`:

```python
group = client.prepare_payment_group(
    algod_client,
    [
        {"sender": sender, "receiver": receiver_a, "amount": 1_000_000},
        {"sender": sender, "receiver": receiver_b, "amount": 2_000_000},
    ],
)
result = client.send_prepared(algod_client, group)
```

The same call works for every account type: Ed25519, native Falcon, LogicSig,
bounded, cosigned and rotating accounts, and a rekeyed sender. You do not
look up the auth address or choose the signing flow:

- the `prepare_*` helpers read each sender's auth address from the chain and
  name the key that signs in `auth_address`;
- the send reads the signer's own record of that key and picks the flow from
  it: ordinary `/sign` for Ed25519, native Falcon, LogicSig and bounded
  accounts, the cosigned sequence for an account with a cosigner, and the
  rotating sequence for a rotating account;
- it signs, with operator approval where the signer asks for it, and checks
  the signed group against what was prepared, with the checks in
  [What The SDK Checks Before Returning](#what-the-sdk-checks-before-returning);
- it submits exactly those bytes and waits for confirmation.

Every position must name, in `auth_address`, a key this signer holds, as the
`prepare_*` helpers do.

`SendResult` carries:

- `signed_group`: the group as submitted, a list with one entry per
  transaction, each the raw msgpack bytes of one signed transaction. The
  first `original_count` entries are your transactions, in order; the rest
  are resource dummies the signer appended.
- `tx_ids`, `fees` (microAlgos) and `group_id`, computed from the signed
  bytes. The signer may raise a fee or assign a group ID, so `tx_ids` can
  differ from the IDs of the transactions you prepared.
- `mutations`: the signer's report of what it changed (snake_case keys),
  checked against the signed bytes; `None` when it changed nothing.
- `outcome` (`SEND_OUTCOME_CONFIRMED`, or `SEND_OUTCOME_SUBMITTED` with
  `no_wait=True`) and `confirmed_round`, 0 unless confirmed.
- `confirmation`: what algosdk's wait returned for the first transaction of
  the signed group, the one it followed, unchanged; `None` unless confirmed.
  Its inner transactions, logs and created IDs are read from it as in any
  algosdk program.
- `flow`: `""` for the ordinary flow, `SIGNING_FLOW_COSIGNED1` or
  `SIGNING_FLOW_ROTATING1`. `cosigned` holds a cosigned send's component
  responses and `rotating` a rotating send's stages.

Keyword arguments (all optional):

- `no_wait=True`: return once algosdk's submit call returns success, with
  outcome `"submitted"`.
- `wait_rounds`: how many rounds algosdk's `wait_for_confirmation` looks for
  the group; 0 means 10. The SDK never passes algosdk 0, which it reads as
  1000.
- `refresh_validity=True` (`send_prepared()` and `send_transactions()`): let
  a rotating account's send rebuild the transaction's validity rounds; see
  [Rotating Accounts](#rotating-accounts).
- `cosigner_client` with `cosigner_component_key`, or `cosigner_resolver`: a
  cosigned account's cosigner, when it is not found from `endpoints.yaml`;
  see [Finding The Cosigner](#finding-the-cosigner). The send does not close
  a cosigner client you pass.
- `timeout`: a limit in seconds on signing and submission, not on the
  confirmation wait; see
  [Cancellation And Time Limits](#cancellation-and-time-limits).

What algosdk's wait does: with `wait_rounds` N, algosdk reads the current
round r, looks the first transaction up at once, and then, for k from 1 to
N-1, waits for the block after round r+k and looks again. It then waits for
the block after round r+N and gives up without looking, so a wait of 1
looks only once and can miss a confirmation in the next round. A lookup
that fails with algod's HTTP error (`AlgodHTTPError`) is skipped; any other
failed lookup, and any failed status read or wait for a block, ends the
wait. The call's `timeout` cannot interrupt it: each request it makes has
algosdk's own 30-second socket timeout, and one that times out ends the
wait.

Refused before anything is signed:

- `UnsupportedSigningFlowError`: a key needs a signing flow this SDK version
  cannot run. Upgrade the SDK.
- `UnsupportedGroupError`: a group the send does not cover, such as a
  pre-signed or foreign position, or a rotating account's transaction in a
  group.
- `KeyNotFoundError`: a position names a key the signer does not hold.

The `sign_*` and `plan_*` calls under [Common Tasks](#common-tasks) are for
callers who want signed bytes without the SDK submitting them: to submit
through their own node or pipeline, to hold a signed group, or to sign a
group the send does not take, such as a multi-party group with passthrough
positions. They do not submit and do not wait.

### Send Transactions Built With algosdk

`send_transactions()` sends transactions you built with algosdk's own
constructors. For each distinct sender, it reads the sender's account from
the node and finds the signing address as the `prepare_*` helpers do
(`resolve_auth_address()`: the sender, or the address the chain says it is
rekeyed to). It wraps each transaction, in the order given, in a
`PreparedTransaction` naming its sender's signing address, and sends the
group with `send_prepared()`. It runs none of the `prepare_*`
preflight checks, such as balances and opt-ins.

```python
from algosdk import transaction

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

The keyword arguments, the result and the failures are those of
`send_prepared()`, described in
[Send A Payment Or A Prepared Group](#send-a-payment-or-a-prepared-group)
and [Send Failures](#send-failures). An empty list is refused with a
`ValueError`. The signer's keys are read once for the call. A failed
account lookup is a plain `SignerError` (`SendTimeoutError` when the call's
`timeout` ended it), and a failed resolution keeps its class
(`KeyNotFoundError`, say); both name the transaction's position and sender
and are raised before anything is signed.
`python/examples/send_built.py` is a complete program.

### Rotating Accounts

A rotating account (signing flow `rotating1`) hands itself to a fresh stage
on every spend, so the signer adds a rekey to the next stage to your
transaction. Inside `send_prepared()` and `send_payment()` the SDK:

1. asks the signer to prepare the exact group it will sign: your transaction
   with the rekey, its fee raised, and any resource dummies;
2. refuses that group unless the only changes are the rekey, a reported fee
   raise within your max fee increase, the group ID and canonical dummies;
3. simulates it, unsigned, through your algod. A failure raises
   `RotatingPreflightError`, whose `message` says why, before any one-time
   key is used;
4. asks the signer to sign, with operator approval, and checks that the
   signed group is exactly the prepared one;
5. submits at once and waits for confirmation. `result.rotating` reports the
   stage that signed (`stage`), the stage that now controls the account
   (`target`), its address (`rekey_to`) and how many times the spend was
   prepared (`attempts`).

Limits:

- **One transaction, alone.** It must be ungrouped, set no `rekey_to`, not
  close the account, and take no LogicSig arguments. The send refuses
  anything else with `UnsupportedGroupError` before it asks the signer.
- **Short validity window.** At most `ROTATING_MAX_VALIDITY_WINDOW` (100)
  rounds, and the signer signs only while `first_valid_round` is at most
  `ROTATING_MAX_LEAD` (2) rounds ahead of the current round and at least
  `ROTATING_MIN_REMAINING` (10) rounds remain. The `prepare_*` helpers build
  such a window for a rotating sender. A transaction whose rounds are not
  current is refused before the operator is asked.
- **When the send rebuilds the rounds.** `send_payment()` builds its own
  transaction, so it may rebuild stale rounds. For a transaction you prepared
  or built, pass `refresh_validity=True` to allow it. That changes the
  transaction ID, so leave it off when anything outside the transaction, such
  as an app argument or a proof, binds its rounds.
- **Bounded retries.** When the signer says an attempt released no signature
  (`ERR_CODE_ROTATING_STAGE_UNPROVEN`, `ERR_CODE_ROTATING_STAGE_CHANGED`,
  `ERR_CODE_ROTATING_WINDOW_NOT_CURRENT`, read from `SignerError.code`), the
  send prepares again, up to three attempts, and each attempt needs approval
  again. A window refusal is retried only when the rounds may be rebuilt,
  with the longest window. This needs a signer that reports
  `rotating_window_not_current`; see the
  [compatibility note](COMPATIBILITY.md).
- **App calls carry the rekey**, so a contract that requires a zero
  `rekey_to` fails the simulation.
- **Two sends in a row** work once the first has confirmed, which the default
  wait ensures.

The steps are also available one at a time, for callers who need them. None
of them submits:

```python
prepared = client.prepare_rotating(txn)                                 # nothing signed
simulation = client.simulate_prepared_rotating(algod_client, prepared)  # never signs
signed = client.sign_prepared_rotating(prepared)                        # waits for approval
result = client.submit_signed_group(algod_client, signed.signed_group)
```

`signed.signed_group` is a list of bytes, one signed transaction per entry, in
prepared order. `prepared.transactions` are the unsigned prepared
transactions, hex msgpack with the `TX` prefix.

Submit a signed rotating group promptly: the stage's one-time keys are
revealed until that transaction or a later rotation confirms.

If a sign answer is lost (a `SignOutcomeUnknownError` whose `rotating`
attribute holds the prepared group), call `sign_prepared_rotating()` again
with that same prepared group. It asks for the same transaction with the same
IDs and builds no second spend. Do not call `send_payment()` or
`send_prepared()` again until the first attempt's outcome is known: that
prepares a new spend from the same stage.

For a rotating account, `resolve_auth_address()` returns the account itself
as `auth_address` at every stage; the stage address the chain reports is in
`chain_auth_address`. A rotating account rekeyed to an ordinary key the
signer holds has left rotation, and is sent like any rekeyed account once the
chain confirms the rekey.

### Send Failures

| Exception | What it means | What to do |
|---|---|---|
| `SignOutcomeUnknownError` | A signing request ended with no answer, or with a 200 answer that could not be read, or the SDK failed while checking one. A signature may have been released. Nothing was submitted. | Do not send again. See [After An Unknown Outcome](#after-an-unknown-outcome). `request_id` names the request in the signer's audit log. |
| `SubmissionError` | The group was signed, and algosdk's submit call or its confirmation wait failed. `submitted` is `True` when the submit call returned success and the failure came later, and `False` when it did not return success. `error`, also the `__cause__`, is algosdk's error, unchanged. | Read `error` as you would in any algosdk program. With `submitted` `False`, an algod HTTP 400 means the node answered: read its reason; anything else leaves it open whether the node has the group. Do not sign a replacement. See [After An Unknown Outcome](#after-an-unknown-outcome). |
| `RotatingPreflightError` | A rotating spend failed its unsigned simulation. Nothing was signed. | Read `message`. |
| `UnsupportedSigningFlowError`, `UnsupportedGroupError`, `KeyNotFoundError`, `CosignerDiscoveryError`, `SendTimeoutError` | Refused, or out of time, before anything that can execute was signed. | Read the reason. |
| Any other `SignerError` | The signer refused (policy, operator, locked), or the SDK refused its answer (`verify signer response: ...`, `MaxFeeIncreaseError`). Nothing was submitted. | Read the reason. When the SDK refused a sign answer, the signer did sign and the SDK discarded the result. |

Two of these must not be answered by sending again:

- `SignOutcomeUnknownError`: the signer may have released a signature that
  never reached you. A replacement you build and sign, and that signature,
  could both execute. Find out what happened, or wait until the error's
  `last_valid` round has passed, first.
- `SubmissionError`: the signed group may already be in a block or in the
  node's pool, whatever `submitted` says, and a replacement could execute
  beside it. Submitting the same `signed_group` again cannot pay twice: the
  same bytes execute at most once.

Any other error means nothing that was signed can execute: the send was refused before signing, the signer refused,
or the SDK refused the signer's answer and discarded it. It is safe to fix
the cause and send again.

### After An Unknown Outcome

Which case applies depends on the error.

**The group was signed** (`SubmissionError`). The error carries the signed
group (`signed_group`, a list of bytes with one signed transaction per
entry), the transaction IDs (`tx_ids`), the last valid round
(`last_valid`, the earliest in the group), and algosdk's error as its cause
(`error`, also `__cause__`). Read the cause as you would in any algosdk
program.

- `submitted` is `True`: algosdk's submit call returned success. Follow the
  group with algosdk's `transaction.wait_for_confirmation()` on `tx_ids[0]`
  (a group confirms as a whole) for up to `last_valid` minus the current
  round, at least 1 (algosdk reads 0 as 1000 rounds). The examples wait at
  most 10 more rounds. A timeout from the wait (`ConfirmationTimeoutError`)
  means only that the wait ended.
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
    `submit_signed_group()`. If that comes back as a 400 saying the transaction is
    already in the ledger, the node has it: follow `tx_ids[0]`.
- Submitting the same signed group again cannot pay twice. A 400 saying the
  transaction is already in the ledger is good news, not a refusal. After
  the last valid round the node refuses the group as dead whether or not it
  confirmed, so a refusal then proves nothing.
- Once the last valid round has passed, neither a node's "not found" nor a
  refusal proves the group never confirmed (a node looks back only about
  1000 rounds from the current round): check an indexer before building a
  replacement.

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

**Nothing was submitted** (`SignOutcomeUnknownError`, any account that is not
rotating). A signature may exist that the SDK never received. Once
`last_valid` has passed, nothing signed by that request can execute, and a
replacement is safe. No lookup is needed. Before that, do not build a
replacement with different transaction IDs.

**Rotating accounts** (`SignOutcomeUnknownError` whose `rotating` holds the
prepared group). Sign the same prepared group again with
`client.sign_prepared_rotating(error.rotating)` and submit the result with
`submit_signed_group()`. It produces the same transaction IDs, so it cannot pay
twice. See [Rotating Accounts](#rotating-accounts).

A `SendTimeoutError` raised on its own means nothing that can execute was
signed. When the time limit ends the call later, the call raises one of the
two errors above, and that error's case applies.

### Cancellation And Time Limits

`send_prepared()`, `send_payment()` and `send_transactions()` take
`timeout=` (seconds, for signing and submission). `None`, the default, sets no limit of its own: each signing
request waits as long as the signer's approval wait allows, unless the
client was created with a shorter request `timeout`. Every HTTP request to a
signer, a cosigner or the node up to the submission is held to what
remains, and the steps check it in between; it does not interrupt a call
already blocked outside HTTP. It does not cover the confirmation wait:
algosdk's `wait_for_confirmation()` cannot be interrupted, so `wait_rounds`
bounds the wait. Where it passes decides what you get:

- before an approval-bearing request is posted (while keys, rounds or the
  plan are read, or between steps): `SendTimeoutError` (a `SignerError`), not
  an unknown outcome. Nothing more is sent, not even a `/sign/cancel`. During
  cosigner discovery the error is both a `CosignerDiscoveryError` and a
  `SendTimeoutError`.
- while an approval-bearing request (`/sign`, `/sign/component`,
  `/sign/assemble`, `/sign/rotating/sign`) is waiting: a best-effort
  `/sign/cancel`, then `SignOutcomeUnknownError` whose `error` is the
  `SendTimeoutError`.
- after signing, before the submission: `SubmissionError` with `submitted`
  `False`, whose `error` is the `SendTimeoutError`. Nothing was posted;
  `submit_signed_group()` submits `signed_group`.
- during the submission: `SubmissionError` with `submitted` `False`, whose
  `error` is what algosdk raised for the request the limit cut short.
- after the submission, before the wait: `SubmissionError` with `submitted`
  `True`, whose `error` is the `SendTimeoutError`. With `no_wait=True` there
  is no wait to start, so the send returns with outcome `"submitted"`.

`prepare_rotating()` and `sign_prepared_rotating()` take the same `timeout`.

A `KeyboardInterrupt` is not turned into an SDK error: it still stops the
program, and it says what was in flight. Raised while a sign, component or
assembly request was pending, it carries the request's ID as
`aplane_request_id` (after the best-effort `/sign/cancel` for a request
awaiting approval), and for a rotating account the prepared group as
`aplane_rotating`: treat it like a `SignOutcomeUnknownError`. Raised while the
signed group was submitted or its confirmation awaited, it carries
`aplane_signed_group` (a list of bytes, one signed transaction per entry) and
`aplane_tx_ids`: treat it like a `SubmissionError`.

## Common Tasks

### Health Check

```python
if client.health():
    print("Signer is reachable")
```

`health()` returns `True` on HTTP 200 and `False` on unreachable or unhealthy
responses.

### Signer Status

```python
status = client.get_status()
print(status.state, status.keyset_revision, status.approval_wait_seconds)
```

`get_status()` calls authenticated `/status`. It does not require unlock; a
locked signer is returned as status data. Use `keyset_revision` as a
process-local signal to refresh `list_keys(refresh=True)` only when the loaded
keyset changes. Do not treat it as durable across apsigner restarts.

The SDK also uses `approval_wait_seconds` to size `/sign` deadlines. If
discovery fails or the field is missing or out of range, signing falls back
to 6 minutes.

`warnings` and `notes` are operator-facing lines. `rotating` lists each
rotating account's view from the signer's last background pass
(`RotatingAccountStatus`: observed authorizer, classification, cached stages
and `RotatingRecoveryStatus`); it is empty while locked or without rotating
accounts. Stage recovery itself (`/admin/rotating/recover`) is an operator
action run from apshell, so the SDK carries only its wire shapes
(`RotatingRecoverRequest`, `RotatingRecoverResponse`).

### List Keys

```python
keys = client.list_keys()
for key in keys:
    print(key.address, key.key_type, key.logic_sig_resources)
```

Useful `KeyInfo` fields include:

- `address`
- `key_type`
- `public_key_hex`
- `logic_sig_resources`
- `is_generic_lsig`
- `signing_args`
- `template_provenance_status`
- `template_provenance_note`

`logic_sig_resources` publishes independent program-byte, argument-byte, and
maximum-opcode-cost demand by authorization path. Non-bounded LogicSig keys
publish a `default` profile. Bounded keys publish exactly two paths, `spend`
and `spending_rekey`, which may differ: a rekey selects `spending_rekey` and
every other transaction selects `spend`.

`KeyTypeInfo.authorization_kind` distinguishes `ed25519`, `native_pq`, and
`logic_sig`. A false `requires_logicsig` value may mean either native Ed25519
or native Falcon-1024.

`KeyInfo.authorization_kind` reports the same closed values for a key instance
and is authoritative for choosing its transaction authorization envelope. It
is empty for witness keys, which are not spending accounts, and whenever the
signer does not report it; never read an empty value as Ed25519.
Prefer it over `logic_sig_resources is not None`, because a native
Falcon-1024 spending key publishes no LogicSig profile and is otherwise
indistinguishable from an Ed25519 key. `sign_prepared_cosigned_group` sends no
size hint for a position the signer holds: it names the position's
`auth_address`, and the signer sizes the position from its own records and can
put the group's authorization charge on it. Setting `pq_scheme` or
`lsig_resources` on such a position is an error.

`bounded_authorization.rekey` is a bounded account's rekey setting:
`spending_key` lets the spending key rekey the account, and `refused` means the
account refuses rekeys, except to an address on its rekey-to list when it has
one. The SDK fails a rekey on a bounded key that has neither. `bounded_authorization.contract`
is `bounded2` on a bounded host, or `plain1` on a plain host such as
`aplane.falcon1024.v1`, which has no host rules: every transaction that doesn't
rekey is a spend, closes included. `bounded_authorization.max_fee` is the bounded host's fee
ceiling and is optional: a plain host has none, so it is `None`. Never read
its absence as zero.

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
`mnemonic_import`, which only native types report. `per_key_contract` marks a
type whose accounts each select their contract at generation, and
`boundary_schema` says whether its requests take a boundary file:
`aplane.boundary.v1` on the general bounded type, empty on a plain host, whose
parameters are given directly.

### Generate A Key

```python
result = client.generate_key("ed25519")
print(result.address)
```

This is an authenticated admin operation and requires an unlocked signer.

Key types with creation parameters take a string map:

```python
result = client.generate_key(
    "aplane.htlc.v1",
    {
        "hash": "SHA256_HEX",
        "recipient": "ADDR1",
        "refund_address": "ADDR2",
        "timeout_round": "123456",
    },
)
```

### Delete A Key

```python
client.delete_key("ADDRESS_TO_DELETE")
```

This is also an authenticated admin operation and requires an unlocked signer.

### Sign One Transaction

The `sign_*` calls in this and the following sections return signed bytes
and submit nothing. Use them when you want the signed transactions yourself;
to send, use `send_payment()`, `send_prepared()` or `send_transactions()`
(see [Sending Transactions](#sending-transactions)).

`sign_transaction()` returns the signed group: a list with one entry per
transaction, each the raw msgpack bytes of one signed transaction. The first
entry is your transaction; any after it are resource dummies the signer
appended, and the whole list is what must be submitted. Submit it one of two
ways:

- `submit_signed_group()` submits it and waits for confirmation, returning a
  `SendResult` or raising `SubmissionError`, as a send does;
- or algosdk submits it and you wait with algosdk: `signed_group_base64()`
  gives the base64 text of the entries joined in order, which is what
  algosdk's `send_raw_transaction()` takes. It reads no node and does not
  check the entries: they come from the SDK's verified output, and the node
  checks what it is sent.

```python
from aplanesdk import SignerClient, signed_group_base64
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

# Submit and wait with the SDK
result = client.submit_signed_group(algod_client, signed)
print(result.tx_ids[0], result.confirmed_round)

# Or submit and wait with algosdk
# txid = algod_client.send_raw_transaction(signed_group_base64(signed))
# transaction.wait_for_confirmation(algod_client, txid, 4)
```

For a rekeyed account, these calls take the auth address explicitly. (The
`prepare_*` helpers read it from the chain for you, so `send_payment()` and
`send_prepared()` need nothing extra; `resolve_auth_address()` does that
lookup on its own.)

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

Without `auth_address` the sender signs for itself, and the args apply to the
sender. `lsig_args_map` is keyed by auth address. A key that is no position's
authorizer raises `ValueError`. A position's authorizer is its auth address, not its
sender when the account is rekeyed: for a passthrough position it is the
signer its signed bytes name, and for a foreign position, where nothing names
one, the sender. A key whose only positions in the request are passthrough or
foreign is accepted, and its args are not sent, because the request does not
sign for that address; this lets one map serve the plan and the final signing
of the same group. An entry with no args is
ignored.

### Sign A Group

```python
signed_group = client.sign_transactions([txn1, txn2])
result = client.submit_signed_group(algod_client, signed_group)
# or: txid = algod_client.send_raw_transaction(signed_group_base64(signed_group))
```

`sign_transactions()` returns the signed group as `sign_transaction()` does:
one entry per transaction in group order, the transactions given and then
any dummies the signer appended, each the raw msgpack bytes of one signed
transaction. To keep a signed group as text, write each entry as hex and
read it back with `bytes.fromhex()`:

```python
lines = [entry.hex() for entry in signed_group]
signed_group = [bytes.fromhex(line) for line in lines]
```

Without passthrough entries:

- do not pre-assign a group ID
- do not pre-insert dummy transactions
- let the signer compute grouping, dummy insertion, and fee pooling

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

## Transaction Semantics

The Python SDK uses `py-algorand-sdk` transaction objects as input. A signed
transaction, wherever the SDK returns or takes one, is `bytes`: the raw
canonical msgpack of one signed transaction, and a signed group is a
`List[bytes]`, one entry per transaction, in group order. The `sign_*` calls
return them for you to submit; `send_prepared()`, `send_payment()` and
`send_transactions()` submit for you. The signer's wire shapes hold hex, as
the signer sends it: `sign_requests()`, `request_assemble()` and the plan
answers return what the signer sent.

Important behavior:

- `sign_transaction()` and `sign_transactions()` return the signed group, a
  list of bytes; the first entries are the transactions given, and any
  resource dummies the signer appended follow them. Submit it with
  `submit_signed_group()`, or with algosdk's `send_raw_transaction()` given
  `signed_group_base64(signed_group)`
- a signed transaction the caller supplies (a `passthrough` value, a
  `PreparedTransaction.signed_transaction`, an entry given to
  `submit_signed_group()`) must be bytes; a `bytearray` or `memoryview` is
  copied to bytes when it is taken, so a later change to the buffer reaches
  nothing the SDK holds. Anything else, such as a hex or base64 string, is
  refused with a `ValueError` naming its position before anything is sent.
  Each must be exactly one canonically encoded signed transaction: two
  transactions in one entry, trailing bytes and a non-canonical encoding are
  refused before anything is sent
- these simple sign calls return only the signed transactions; to read what
  the signer changed (the fee it added, the group ID, appended dummies), call
  `sign_requests()`, whose `mutations` is the mutation report, already checked
  against the request
- amounts and fees given to the `prepare_*` helpers are in microAlgos; an
  asset amount is in the asset's base units, not adjusted for its decimals.
  IDs, amounts and fees must be integers: a float, a numeric string or a
  bool raises `ValueError`. Any integral type is accepted (one that defines
  `__index__`, such as a NumPy integer) and is converted to a plain `int`.
  That holds for every ID, count and index a prepare helper takes: app and
  asset IDs, foreign references, ABI `application` and `asset` arguments, box
  app indexes, extra pages, the counts of a `StateSchema`, `on_complete`, and
  the key-registration rounds and dilution. A bool is also refused where an
  ABI method takes an integer. `None` still means "not set" for an optional
  parameter, `extra_pages` and the schemas included
- Group helpers check every sender against everything it pays across the
  group: the ALGO it sends plus the fee of every position it sends, asset
  transfers included. The check is named `group_algo_balance`. It reads each
  sender's spendable ALGO from the `spendable_algo` check that the payment and
  asset-transfer helpers record on every position (the lowest value, when a
  sender has several positions), and refuses a position
  that lacks that check or whose `available` value is not a non-negative integer
- `prepare_asa_transfer()` checks the transfer's fee against the sender's spendable ALGO
  itself, so one transfer is refused alone exactly as it is in a group. Its
  `asa_transfer` check records the fee
- `sign_requests()` accepts one or more raw `/sign` request entries and returns the raw
  `/sign` response
- for large LogicSigs, the signer may add dummy transactions for fee pooling
- `send_prepared()`, `send_payment()` and `send_transactions()` sign, submit
  and wait; their `SendResult.signed_group` is a list of bytes, one signed
  transaction per entry
- `submit_signed_group()` submits a signed group exactly as given, a list of
  bytes (a rotating group from `sign_prepared_rotating()`, or the
  `signed_group` a `SubmissionError` kept), and waits for confirmation, as a
  send does. It signs nothing

### What The SDK Checks Before Returning

Every `/sign` and `/plan` result is checked against the request before
`sign_transaction()`, `sign_transactions()`, `sign_requests()`, `plan_group()`/`plan_requests()` or `simulate_prepared_group()` returns it, and before `send_prepared()` submits anything. The
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
any size is accepted. Set `max_fee_increase` on the client to put your own ceiling on it.
The value is in microAlgos and bounds the total the signer adds across all
positions of one request. Zero means the signer may not raise any fee. When
the raises add up to more than the ceiling, every sign, plan and simulate call
through that client fails with `SignerError` and returns nothing, so nothing can be
submitted or simulated.
The per-account `max_fee` check in the cosigned flow still applies as well.
The refusal is a `MaxFeeIncreaseError`, a `SignerError` subclass carrying
`raised` and `limit`.

```python
client = SignerClient.from_env(max_fee_increase=200_000)  # microAlgos, summed over the request
try:
    signed = client.sign_transaction(txn)
except MaxFeeIncreaseError as refused:
    # verify signer response: signer raised fees by 5000000 microAlgos,
    # more than the max fee increase 200000 set on this client
    print(f"signer asked for {refused.raised}, ceiling is {refused.limit}")
```

`connect_ssh()` and the constructor take the same argument, and
`client.max_fee_increase` can be set or returned to `None` at any time. A value
that is not a non-negative integer raises `SignerError`.

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
charge, call `plan_group()` with your transactions and read
`mutations["total_fees_delta"]` in the result.

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
must be a valid Algorand address, or the call fails before any request is made:
`sign_requests()` and `plan_requests()` raise `SignerError` for malformed
request entries, and the helpers that build entries from transactions raise
`ValueError` for a bad argument.
A passthrough transaction must round-trip through the SDK's Algorand
library (`py-algorand-sdk`), so one that uses a field newer than that library is refused
locally.

#### How Signer Answers Are Read

Every 200 answer from the signer is read strictly, as the Go SDK reads it: it
must be exactly one JSON object of the answer's declared shape, a field left
out or `null` reads as its zero value, and a field of the wrong type, a
`null` body or anything after the object makes the answer unreadable. An
answer whose `error` field is set is a refusal; an unreadable answer is a
plain `SignerError` at a request that releases no signature, and at an
approval-bearing request a lost answer, which a send reports as
`SignOutcomeUnknownError`. The full rule and how the three SDKs' readers
differ are in
[`python/README.md`](../python/README.md#how-signer-answers-are-read).

### Foreign Entries

Python follows the cross-SDK contract here:

- foreign entries are allowed in `plan_group()`
- foreign entries are rejected client-side for `/sign`

In practice, that means:

- use `plan_group()` first when some slots are signed by another party
- do not mix foreign entries and `passthrough` entries in the same request
- then resubmit the finalized foreign slots as `passthrough`

For a foreign native Falcon-1024 slot, set
`pq_scheme=PQ_SCHEME_FALCON1024` on `PreparedTransaction` (or use the same
exported constant in a raw request). It is
mutually exclusive with `lsig_resources` and declares native-PQ fee usage
rather than LogicSig resources.

`plan_requests()` is the per-slot planning API. Prefer it over the
address-keyed `plan_group()` convenience form when two transactions use the
same authorization address with different LogicSig arguments or app-call
metadata.

### Passthrough And Multi-Party Assembly

`passthrough` maps a group index to a transaction another party already
signed, included in a final signing request as it is. Each value is the raw
msgpack bytes of one signed transaction, as `sign_transactions()` returns
them; a `bytearray` or `memoryview` is copied to bytes. A value that is not
bytes, such as a hex or base64 string, raises `ValueError` naming its
position, and so does one that is not exactly one canonically encoded signed
transaction, before any request is made. A `PreparedTransaction` takes a
pre-signed slot the same way, as `signed_transaction` bytes.

py-algorand-sdk's signers return `SignedTransaction` objects; turn one into
the bytes the SDK takes with `encoding.msgpack_encode`, which gives base64:

```python
import base64
from algosdk import encoding

signed_bytes = base64.b64decode(encoding.msgpack_encode(signed_txn))
```

When passthrough entries are present:

- the caller must pre-assign group IDs on all transactions
- the signer will not insert dummies for the whole group
- the signer treats passthrough transactions as immutable

For multi-party workflows, the standard high-level flow is:

1. use `plan_group()` with foreign slots and `lsig_resources`
2. collect the finalized foreign signatures from the other party
3. resubmit those signed slots as `passthrough` for final signing, repeating
   the same `lsig_resources` for every passthrough LogicSig slot

The signer checks the declared program and argument byte counts against each
signed passthrough envelope. Omitting the declaration for a LogicSig
passthrough is a client error.

`send_prepared()` does not take passthrough positions, so a multi-party group
is signed with these calls and you submit it.

### Cosigned Accounts

Cosigned accounts (signing flow `cosigned1`) need component signatures from both
the user signer and a cosigner signer. A cosigned account is a plain host such
as `aplane.falcon1024.v1` created with a cosigner, or a bounded account with
one, such as Corridor. Either kind without a cosigner advertises `bounded1` and
signs through ordinary `/sign`. Cosigner component selectors are public policy keys, not
Algorand spending accounts, and must not be used as senders, receivers, auth
addresses, or rekey targets.

`send_prepared()` and `send_payment()` run the whole cosigned sequence and
submit the result. `sign_prepared_cosigned_group()` runs the same sequence
and returns the signed group without submitting it.

#### Finding The Cosigner

A client made with `SignerClient.from_env()` (or
`from_env(data_dir=...)`) finds a cosigned account's cosigner in its own
`endpoints.yaml`. List the cosigner node as an endpoint with role
`cosigner`:

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
(`request_enrollment_from_env(endpoint="cosigner")`). When a send, or
`sign_prepared_cosigned_group()`, is given no `cosigner_client` and no
`cosigner_resolver`, the client then:

- connects, on first use, to every `role: cosigner` endpoint (at most 12),
  each with its own `identity_file` and `known_hosts_path` and with the
  client's `timeout`, `trust_on_first_use` and `ssh_setup_timeout`, and reads
  its `/keys`;
- signs with the one endpoint that lists the account's witness key, under its
  Witness Key ID;
- keeps those connections, and closes them when you `close()` the client.

An explicit `cosigner_client` (with `cosigner_component_key`) or
`cosigner_resolver` always wins. A client made with
`SignerClient.connect_ssh()` or the constructor has no endpoint registry, so
it needs one of them; without one, a cosigned send is refused with
"cosigner_client or cosigner_resolver is required".
`EndpointCosignerResolver(data_dir=...)` builds the same resolver for you to
pass as `cosigner_resolver`; it owns the connections it opens, so close it
when done (it is a context manager).

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
`transaction_type:<type>` rule ID in the error message. `request_components()`
raises `SigningRejectedError`, preserving the code and message, and the cosigned
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

For manual orchestration, use `request_components()` on the user client with a
bounded-base target and on the cosigner client, then `request_assemble()` on the
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
`sign_prepared_cosigned_group()` discovers the flow from signer inventory and
performs the user-first sequence. With a client from `from_env()` the
cosigner comes from `endpoints.yaml`:

```python
result = sign_prepared_cosigned_group(
    user_client=user_client,
    prepared_group=prepared_group,
)
signed_group = result.signed_group  # a list of bytes, one signed transaction per entry
```

Pass `cosigner_client` and `cosigner_component_key`, or `cosigner_resolver`,
to name the cosigner yourself.

The sequence is `/plan`, user approval and base-component release through
`request_components()` with a bounded-base target, signing of ordinary group
positions, cosigner signing over the frozen group, and final
`request_assemble()` on the user signer. Before requesting any additional
signature, the SDK accepts only
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

```python
simulation = user_client.simulate_prepared_group(
    algod_client,
    prepared_group,
)
if simulation.failed:
    # simulation.failure_message says why; simulation.response has the
    # algod diagnostics.
    pass

cosigned = simulate_prepared_cosigned_group(algod_client, **cosigned_options)
```

`SimulationResult.signed_group` contains fully executable signed transactions,
a list of bytes with one signed transaction per entry, that remain
submittable until expiry; its `transactions` are the same transactions
unsigned, as hex. Keep them confidential. The helper sends
the exact signed group to the supplied algod with empty-signature overrides
disabled. A missing algod client fails before any signing request. A
simulation is `failed` unless the node returned exactly one group result, an
object that reports no failure and holds one transaction result per
transaction simulated. `failure_message` says why: the node's own failure
message, or which of the other cases it was. Transport or decoding failures
raise an error and never trigger another signing request automatically.

## Error Handling

A send's failures are described in [Send Failures](#send-failures). Every
call raises the signer's refusals as `SignerError` subclasses; a
`SignerError`'s `code` is the signer's stable error code when it sent one
(such as `ERR_CODE_ROTATING_STAGE_CHANGED`).

The SDK raises typed exceptions for the common signer-side failure cases:

- `AuthenticationError`
- `SigningRejectedError`
- `SignerUnavailableError`
- `KeyNotFoundError`
- `KeyDeletionError`
- `EnrollmentError`
- `MaxFeeIncreaseError`: the signer raised fees by more than the client's
  `max_fee_increase`; carries `raised` and `limit`
- `UnsupportedSigningFlowError` and `UnsupportedGroupError`: a send refused
  the group before signing
- `CosignerDiscoveryError`: a cosigned account's cosigner was not found in
  `endpoints.yaml`
- `SendTimeoutError`: a call's `timeout` passed
- `SignOutcomeUnknownError`, `SubmissionError` and `RotatingPreflightError`:
  see [Send Failures](#send-failures)

A submission you make yourself with algosdk raises algosdk's own errors.

Typical pattern:

```python
from aplanesdk import (
    AuthenticationError,
    SignerError,
    SignerUnavailableError,
    SigningRejectedError,
    SignOutcomeUnknownError,
    SubmissionError,
)

try:
    result = client.send_payment(algod_client, sender=sender, receiver=receiver, amount=1_000_000)
    print(result.tx_ids[0])
except (SignOutcomeUnknownError, SubmissionError):
    # Do not send again: see "After An Unknown Outcome".
    raise
except AuthenticationError:
    print("Connection is not authenticated by an enrolled SSH key")
except SigningRejectedError:
    print("Operator rejected the request")
except SignerUnavailableError:
    print("Signer unreachable, locked, or unavailable")
except SignerError as err:
    print(f"Sending failed: {err}")
```

## Related Docs

- main APlane repository `docs/USER_INSTALL.md`
- main APlane repository `docs/USER_CONFIG.md`
- main APlane repository `docs/USER_QUICKSTART.md`
- main APlane repository `docs/ARCH_CONTRACTS.md`
- [`python/README.md`](../python/README.md)
- [compatibility note](COMPATIBILITY.md): read it before upgrading the SDK or
  the signer
