# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""The client checks every /sign and /plan result against what it asked for."""

import base64
import copy
import inspect
import json
import pathlib
import pickle
import re
from unittest.mock import MagicMock, patch

import msgpack
import pytest
from algosdk import encoding, transaction

from aplanesdk import (
    InsufficientFundsError,
    MaxFeeIncreaseError,
    PreparedGroup,
    PreparedTransaction,
    SignerClient,
    SignerError,
)
from aplanesdk.signer import (
    _decode_request_slots,
    _simulate_signed_group,
    _validate_plan_response,
    _validate_sign_response,
    _verify_bounded_assembled_group,
    _verify_signed_transaction_matches_canonical,
    encode_transaction,
)
from tests import fake_signer


def make_client():
    return SignerClient("http://localhost:11270", timeout=10)


def pregrouped_pair():
    pair = [fake_signer.payment(41, 42, 1_000_000), fake_signer.payment(43, 44, 5)]
    transaction.assign_group_id(pair)
    return pair


def single_entries():
    return fake_signer.sign_entries(fake_signer.payment(41, 42, 1_000_000))


def pair_entries():
    return fake_signer.sign_entries(
        fake_signer.payment(41, 42, 1_000_000), fake_signer.payment(43, 44, 5)
    )


def passthrough_entries():
    pair = pregrouped_pair()
    entries = fake_signer.sign_entries(*pair)
    entries[1] = {"signed_txn_hex": fake_signer.signed_hex(pair[1])}
    return entries


def foreign_entries():
    entries = fake_signer.sign_entries(*pregrouped_pair())
    entries[1] = {"txn_bytes_hex": entries[1]["txn_bytes_hex"]}
    return entries


def resign(body, index, edit):
    """Replace the transaction inside a signed slot."""
    signed = fake_signer.decode_signed(body["signed"][index])
    edit(signed.transaction)
    body["signed"][index] = fake_signer.signed_hex(signed.transaction)


def set_fields(**fields):
    def edit(txn):
        for name, value in fields.items():
            setattr(txn, name, value)

    return edit


def add_fee(amount):
    def edit(txn):
        txn.fee += amount

    return edit


RAISED = {"fee_raise": {0: 2000}}
WITH_DUMMIES = {"fee_raise": {0: 2000}, "dummies": 2}


@pytest.mark.parametrize(
    ("entries", "signer", "want"),
    [
        (single_entries, {}, 1),
        # A native Falcon or LogicSig account: the signer raises the fee of an
        # ungrouped transaction and leaves it ungrouped.
        (single_entries, RAISED, 1),
        (pair_entries, {}, 2),
        (single_entries, WITH_DUMMIES, 3),
        (lambda: fake_signer.sign_entries(*pregrouped_pair()), {}, 2),
        (passthrough_entries, {}, 2),
        (foreign_entries, {}, 2),
    ],
    ids=[
        "single",
        "single-fee-raised",
        "ungrouped-pair-grouped",
        "fee-raised-with-dummies",
        "pregrouped-pair",
        "passthrough",
        "foreign",
    ],
)
def test_sign_response_accepts_reported_mutations(entries, signer, want):
    requests = entries()
    body = fake_signer.sign_response(requests, **signer)
    assert len(body["signed"]) == want
    _validate_sign_response(
        _decode_request_slots(requests), body["signed"], body.get("mutations"), None
    )


def replace_dummy_with_payment(body):
    # A 50 ALGO payment in the dummy's place, regrouped so the group ID is
    # still canonical.
    txns = [fake_signer.decode_signed(item).transaction for item in body["signed"]]
    txns[1] = fake_signer.payment(41, 45, 50_000_000)
    for txn in txns:
        txn.group = None
    transaction.assign_group_id(txns)
    body["signed"] = [fake_signer.signed_hex(txn) for txn in txns]


def regroup_with_wrong_id(body):
    for index in range(len(body["signed"])):
        resign(body, index, set_fields(group=bytes([0x99]) * 32))


def alter_passthrough(body):
    signed = fake_signer.decode_signed(body["signed"][1])
    signed.signature = base64.b64encode(bytes([9]) * 64).decode()
    body["signed"][1] = base64.b64decode(encoding.msgpack_encode(signed)).hex()


def reauthorize_dummy(body):
    body["signed"][2] = fake_signer.signed_hex(
        fake_signer.decode_signed(body["signed"][2]).transaction
    )


def mutate(**fields):
    return lambda body: body["mutations"].update(fields)


TAMPER_CASES = [
    (
        "substituted receiver and amount",
        single_entries,
        {},
        lambda body: resign(
            body, 0, set_fields(receiver=fake_signer.test_address(45), amt=100_000_000)
        ),
        "unreported fields at original position 1",
    ),
    (
        "unreported fee raise",
        single_entries,
        {},
        lambda body: resign(body, 0, add_fee(5000)),
        "unreported fields at original position 1",
    ),
    (
        "fee raise larger than reported total",
        single_entries,
        RAISED,
        lambda body: resign(body, 0, add_fee(1)),
        "total_fees_delta 2000 does not match observed delta 2001",
    ),
    (
        "reported fee index did not increase",
        single_entries,
        RAISED,
        lambda body: resign(body, 0, set_fields(fee=1000)),
        "did not increase the fee",
    ),
    (
        "reported fee index decreased the fee",
        single_entries,
        RAISED,
        lambda body: resign(body, 0, set_fields(fee=999)),
        "did not increase the fee",
    ),
    (
        "negative total fee delta",
        single_entries,
        RAISED,
        mutate(total_fees_delta=-2000),
        "total_fees_delta must not be negative",
    ),
    (
        "duplicated fee index",
        single_entries,
        RAISED,
        mutate(fees_modified=[0, 0]),
        "fee index 0 is duplicated",
    ),
    (
        "fee index outside the request",
        single_entries,
        WITH_DUMMIES,
        mutate(fees_modified=[0, 1]),
        "fee index 1 is outside original positions",
    ),
    (
        "fee index on a passthrough position",
        passthrough_entries,
        {},
        mutate(fees_modified=[1]),
        "fee index 1 is a passthrough position",
    ),
    (
        "group ID that does not bind the group",
        pair_entries,
        {},
        regroup_with_wrong_id,
        "does not carry the canonical group ID",
    ),
    (
        "group ID changed without a report",
        lambda: fake_signer.sign_entries(*pregrouped_pair()),
        {},
        lambda body: resign(body, 0, set_fields(group=bytes([0x99]) * 32)),
        "unreported fields at original position 1",
    ),
    (
        "group ID change reported for one transaction",
        single_entries,
        RAISED,
        mutate(group_id_changed=True),
        "group ID change for a single transaction",
    ),
    (
        "appended payment that is not a dummy",
        single_entries,
        WITH_DUMMIES,
        replace_dummy_with_payment,
        "appended transaction 1 is not the canonical resource dummy",
    ),
    (
        "dummy with a different authorization",
        single_entries,
        WITH_DUMMIES,
        reauthorize_dummy,
        "appended transaction 2 does not carry the canonical resource dummy authorization",
    ),
    (
        "dummies_added does not match appended count",
        single_entries,
        WITH_DUMMIES,
        mutate(dummies_added=1),
        "dummies_added 1 does not match appended count 2",
    ),
    (
        "final_count does not match returned count",
        single_entries,
        WITH_DUMMIES,
        mutate(final_count=2),
        "final_count 2 does not match returned count 3",
    ),
    (
        "original_count does not match request",
        single_entries,
        RAISED,
        mutate(original_count=2),
        "original_count 2 does not match request count 1",
    ),
    (
        "appended without a mutation report",
        single_entries,
        WITH_DUMMIES,
        lambda body: body.pop("mutations"),
        r"appended 2 transaction\(s\) without a mutation report",
    ),
    (
        "appended without a group ID change",
        single_entries,
        WITH_DUMMIES,
        mutate(group_id_changed=False),
        "appended dummies without reporting a group ID change",
    ),
    (
        "trailing bytes after a signed transaction",
        single_entries,
        {},
        lambda body: body["signed"].__setitem__(0, body["signed"][0] * 2),
        "signed transaction 1: ",
    ),
    (
        "truncated response",
        pair_entries,
        {},
        lambda body: body.update(signed=body["signed"][:1]),
        r"returned 1 signed transaction\(s\), want at least 2",
    ),
    (
        "empty signed position",
        pair_entries,
        {},
        lambda body: body["signed"].__setitem__(1, ""),
        "no signature for position 2",
    ),
    (
        "empty dummy position",
        single_entries,
        WITH_DUMMIES,
        lambda body: body["signed"].__setitem__(2, ""),
        "empty dummy transaction at position 3",
    ),
    (
        "empty passthrough position",
        passthrough_entries,
        {},
        lambda body: body["signed"].__setitem__(1, ""),
        "no signature for position 2",
    ),
    (
        "altered passthrough",
        passthrough_entries,
        {},
        alter_passthrough,
        "signer changed passthrough transaction 2",
    ),
    (
        "passthrough not reported",
        passthrough_entries,
        {},
        lambda body: body.pop("mutations"),
        r"passthrough_count 0 does not match the 1 passthrough transaction\(s\) requested",
    ),
    (
        "signed foreign position",
        foreign_entries,
        {},
        lambda body: body["signed"].__setitem__(1, fake_signer.signed_hex(pregrouped_pair()[1])),
        "signed transaction for foreign position 2",
    ),
    (
        "foreign count does not match",
        foreign_entries,
        {},
        mutate(foreign_count=0),
        r"foreign_count 0 does not match the 1 foreign transaction\(s\) requested",
    ),
]


@pytest.mark.parametrize(
    ("entries", "signer", "tamper", "error"),
    [case[1:] for case in TAMPER_CASES],
    ids=[case[0] for case in TAMPER_CASES],
)
def test_sign_response_rejects_tampering(entries, signer, tamper, error):
    requests = entries()
    slots = _decode_request_slots(requests)
    body = fake_signer.sign_response(requests, **signer)
    _validate_sign_response(slots, body["signed"], body.get("mutations"), None)
    tamper(body)
    with pytest.raises(SignerError, match=error):
        _validate_sign_response(slots, body["signed"], body.get("mutations"), None)


def test_plan_response_checks_foreign_positions_and_dummies():
    requests = pair_entries()
    requests[1] = {"txn_bytes_hex": requests[1]["txn_bytes_hex"]}
    slots = _decode_request_slots(requests)
    signer = {"fee_raise": {0: 1000}, "dummies": 1}

    def replan(body, edit):
        txns = [
            encoding.msgpack_decode(base64.b64encode(bytes.fromhex(item)[2:]).decode())
            for item in body["transactions"]
        ]
        for txn in txns:
            txn.group = None
        edit(txns)
        transaction.assign_group_id(txns)
        body["transactions"] = [encode_transaction(txn)[0] for txn in txns]

    body = fake_signer.plan_response(requests, **signer)
    assert len(body["transactions"]) == 3
    _validate_plan_response(slots, body["transactions"], body["mutations"], None)

    cases = [
        (lambda txns: setattr(txns[0], "amt", 999_999), "unreported fields at original position 1"),
        (lambda txns: setattr(txns[1], "fee", 2000), "unreported fields at original position 2"),
        (lambda txns: setattr(txns[2], "amt", 1), "appended transaction 1 is not the canonical"),
        (
            lambda txns: setattr(txns[2], "last_valid_round", txns[2].last_valid_round + 1),
            "appended transaction 1 is not the canonical",
        ),
    ]
    for edit, error in cases:
        body = fake_signer.plan_response(requests, **signer)
        replan(body, edit)
        with pytest.raises(SignerError, match=error):
            _validate_plan_response(slots, body["transactions"], body["mutations"], None)

    body = fake_signer.plan_response(requests, **signer)
    body["mutations"]["fees_modified"] = [0, 1]
    with pytest.raises(SignerError, match="fee index 1 is a foreign position"):
        _validate_plan_response(slots, body["transactions"], body["mutations"], None)


def test_public_calls_reject_a_substituted_transaction():
    """The checks run inside the public sign, plan and simulate calls."""
    client = make_client()
    txn = fake_signer.payment(41, 42, 1_000_000)
    other = fake_signer.payment(41, 45, 100_000_000)

    def substitute(body):
        if "signed" in body:
            body["signed"] = [fake_signer.signed_hex(other)]
        else:
            body["transactions"] = [encode_transaction(other)[0]]

    error = "unreported fields at original position 1"
    algod_client = MagicMock()
    with (
        patch.object(client, "_discover_approval_wait"),
        patch.object(
            client.session, "post", side_effect=fake_signer.signer_post(tamper=substitute)
        ),
    ):
        with pytest.raises(SignerError, match=error):
            client.sign_transaction(txn)
        with pytest.raises(SignerError, match=error):
            client.sign_transactions([txn])
        with pytest.raises(SignerError, match=error):
            client.sign_transactions_list([txn])
        with pytest.raises(SignerError, match=error):
            client.sign_requests(fake_signer.sign_entries(txn))
        with pytest.raises(SignerError, match=error):
            client.plan_group([txn])
        with pytest.raises(SignerError, match=error):
            client.simulate_prepared_group(
                algod_client,
                PreparedGroup([PreparedTransaction(transaction=txn, auth_address=txn.sender)]),
            )
    algod_client.simulate_transactions.assert_not_called()


def test_sign_transaction_accepts_a_raised_fee_and_dummies():
    client = make_client()
    txn = fake_signer.payment(41, 42, 1_000_000)
    post = fake_signer.signer_post(fee_raise={0: 2000}, dummies=1)
    with (
        patch.object(client, "_discover_approval_wait"),
        patch.object(client.session, "post", side_effect=post),
    ):
        signed = client.sign_transactions_list([txn])
        plan = client.plan_group([txn])

    assert len(signed) == 2
    assert encoding.msgpack_decode(signed[0]).transaction.fee == txn.fee + 2000
    assert len(plan["transactions"]) == 2
    assert plan["mutations"]["dummies_added"] == 1


def test_signed_transaction_identity_checks_reject_noncanonical_bytes():
    txn = fake_signer.payment(41, 42, 1)
    other = fake_signer.payment(41, 45, 2)
    canonical_hex = encode_transaction(txn)[0]
    signed_hex = fake_signer.signed_hex(txn)

    _verify_signed_transaction_matches_canonical("slot", 0, signed_hex, canonical_hex)
    _verify_bounded_assembled_group([canonical_hex], [signed_hex])

    # A second signed transaction after the first.
    concatenated = signed_hex + fake_signer.signed_hex(other)
    # The same signed transaction with its keys out of canonical order.
    fields = msgpack.unpackb(bytes.fromhex(signed_hex), raw=False, strict_map_key=False)
    reordered = msgpack.packb({key: fields[key] for key in sorted(fields, reverse=True)}).hex()
    assert reordered != signed_hex
    # The same signed transaction with a field the SDK does not know.
    extended = msgpack.packb({**fields, "zz": 1}).hex()

    for bad in (concatenated, reordered, extended):
        with pytest.raises(SignerError, match="slot 0: "):
            _verify_signed_transaction_matches_canonical("slot", 0, bad, canonical_hex)
        with pytest.raises(SignerError, match="assembled transaction 0: "):
            _verify_bounded_assembled_group([canonical_hex], [bad])
        algod_client = MagicMock()
        with pytest.raises(SignerError, match="signed group position 1: "):
            _simulate_signed_group(algod_client, [bad])
        algod_client.simulate_transactions.assert_not_called()

    with pytest.raises(SignerError, match="does not match the submitted canonical bytes"):
        _verify_signed_transaction_matches_canonical(
            "slot", 0, fake_signer.signed_hex(other), canonical_hex
        )


def test_request_bytes_must_be_canonical():
    txn = fake_signer.payment(41, 42, 1)
    canonical = encode_transaction(txn)[0]
    signed = fake_signer.signed_hex(txn)
    for entry in (
        {"auth_address": "A", "txn_bytes_hex": canonical[4:]},
        {"auth_address": "A", "txn_bytes_hex": canonical + "00"},
        {"signed_txn_hex": signed + signed},
    ):
        with pytest.raises(SignerError, match="transaction 1: "):
            _decode_request_slots([entry])
    assert copy.deepcopy(_decode_request_slots(fake_signer.sign_entries(txn))[0].txn) == txn


def test_any_failure_while_verifying_is_a_signer_error():
    """A response the checks cannot even read is reported like any other bad response."""
    client = make_client()
    txn = fake_signer.payment(41, 42, 1)
    boom = RuntimeError("decoder blew up")
    with (
        patch.object(client, "_discover_approval_wait"),
        patch.object(client.session, "post", side_effect=fake_signer.signer_post()),
    ):
        with patch("aplanesdk.signer._validate_group_mutations", side_effect=boom):
            with pytest.raises(
                SignerError,
                match="verify signer response: the check itself failed with RuntimeError: decoder blew up",
            ) as sign:
                client.sign_transaction(txn)
            with pytest.raises(
                SignerError,
                match="verify signer plan: the check itself failed with RuntimeError: decoder blew up",
            ) as plan:
                client.plan_group([txn])
    assert sign.value.__cause__ is boom
    assert plan.value.__cause__ is boom

    # A report whose fields are the wrong shape fails inside the checks too.
    def break_report(body):
        body["mutations"] = {"original_count": 1, "final_count": 1, "fees_modified": [[0]]}

    with (
        patch.object(client, "_discover_approval_wait"),
        patch.object(
            client.session, "post", side_effect=fake_signer.signer_post(tamper=break_report)
        ),
    ):
        with pytest.raises(SignerError, match="verify signer response: "):
            client.sign_transaction(txn)


FIVE_ALGO = 5_000_000


def _fee_ceiling_txns(count):
    return [fake_signer.payment(41, 42, 1_000_000), fake_signer.payment(43, 44, 5)][:count]


@pytest.mark.parametrize(
    ("limit", "fee_raise", "count", "refused"),
    [
        # Unset is unbounded: a reported raise of any size is accepted.
        (None, {0: FIVE_ALGO}, 1, None),
        (200_000, {0: 3000}, 1, None),
        (3000, {0: 3000}, 1, None),
        (2999, {0: 3000}, 1, (3000, 2999)),
        (0, {0: 1}, 1, (1, 0)),
        (0, {}, 2, None),
        (4999, {0: 2000, 1: 3000}, 2, (5000, 4999)),
        (5000, {0: 2000, 1: 3000}, 2, None),
    ],
    ids=[
        "unset-large-raise",
        "above-the-raise",
        "equal-to-the-raise",
        "one-below-the-raise",
        "zero-with-a-raise",
        "zero-with-no-raise",
        "two-positions-summed",
        "two-positions-at-the-sum",
    ],
)
def test_max_fee_increase(limit, fee_raise, count, refused):
    client = SignerClient("http://localhost:11270", timeout=10, max_fee_increase=limit)
    txns = _fee_ceiling_txns(count)
    prepared = PreparedGroup(
        [PreparedTransaction(transaction=txn, auth_address=txn.sender) for txn in txns]
    )
    algod_client = MagicMock()
    algod_client.simulate_transactions.return_value = {
        "txn-groups": [{"txn-results": [{}] * count}]
    }
    calls = [
        ("response", lambda: client.sign_transactions(txns)),
        ("response", lambda: client.sign_transactions_list(txns)),
        ("response", lambda: client.sign_requests(fake_signer.sign_entries(*txns))),
        ("plan", lambda: client.plan_group(txns)),
        ("response", lambda: client.simulate_prepared_group(algod_client, prepared)),
    ]
    with (
        patch.object(client, "_discover_approval_wait"),
        patch.object(
            client.session, "post", side_effect=fake_signer.signer_post(fee_raise=fee_raise)
        ),
    ):
        for kind, call in calls:
            if refused is None:
                call()
                continue
            raised, ceiling = refused
            error = (
                f"verify signer {kind}: signer raised fees by {raised} microAlgos, "
                f"more than the max fee increase {ceiling} set on this client"
            )
            with pytest.raises(SignerError, match=error):
                call()
    if refused is None:
        assert algod_client.simulate_transactions.call_count == 1
    else:
        algod_client.simulate_transactions.assert_not_called()


def test_max_fee_increase_ignores_zero_fee_dummies():
    client = SignerClient("http://localhost:11270", max_fee_increase=2000)
    post = fake_signer.signer_post(fee_raise={0: 2000}, dummies=2)
    with (
        patch.object(client, "_discover_approval_wait"),
        patch.object(client.session, "post", side_effect=post),
    ):
        assert len(client.sign_transactions_list([fake_signer.payment()])) == 3


class _Integral:
    """An integer that is not an int, as numpy.int64 is."""

    def __init__(self, value):
        self._value = value

    def __index__(self):
        return self._value


def test_max_fee_increase_setting():
    client = make_client()
    assert client.max_fee_increase is None, "there must be no default"
    client.max_fee_increase = 0
    assert client.max_fee_increase == 0
    client.max_fee_increase = None
    assert client.max_fee_increase is None

    # Any integral type is accepted and stored as a plain int.
    client.max_fee_increase = _Integral(250_000)
    assert client.max_fee_increase == 250_000
    assert type(client.max_fee_increase) is int
    assert (
        SignerClient("http://localhost:11270", max_fee_increase=_Integral(0)).max_fee_increase == 0
    )

    # The same error type as the constructor's other argument errors.
    error = "max_fee_increase must be a non-negative integer"
    for bad in (-1, _Integral(-1), 1.5, 1000.0, "1000", True, False):
        with pytest.raises(SignerError, match=error):
            client.max_fee_increase = bad
        with pytest.raises(SignerError, match=error):
            SignerClient("http://localhost:11270", max_fee_increase=bad)
        # Refused before any connection is attempted.
        with pytest.raises(SignerError, match=error):
            SignerClient.connect_ssh("signer.invalid", "/nonexistent/key", max_fee_increase=bad)
    assert client.max_fee_increase == 250_000, "a refused value must not replace the setting"


def test_max_fee_increase_is_snapshotted_when_the_call_starts():
    """Clearing the ceiling while the signer waits for approval lets nothing through."""
    txn = fake_signer.payment(41, 42, 1)
    client = SignerClient("http://localhost:11270", max_fee_increase=1000)
    answer = fake_signer.signer_post(fee_raise={0: 3000})

    def delayed_post(url, json=None, **kwargs):
        # The response arrives after the ceiling has been removed.
        client.max_fee_increase = None
        return answer(url, json=json, **kwargs)

    error = "more than the max fee increase 1000 set on this client"
    with patch.object(client, "_discover_approval_wait"):
        with patch.object(client.session, "post", side_effect=delayed_post):
            with pytest.raises(SignerError, match="verify signer response: .*" + error):
                client.sign_transaction(txn)
        assert client.max_fee_increase is None

        client.max_fee_increase = 1000
        with patch.object(client.session, "post", side_effect=delayed_post):
            with pytest.raises(SignerError, match="verify signer plan: .*" + error):
                client.plan_group([txn])

        # A call started with no ceiling is not held to one.
        with patch.object(client.session, "post", side_effect=answer):
            client.sign_transaction(txn)


def test_connection_helpers_forward_max_fee_increase(tmp_path):
    (tmp_path / "endpoints.yaml").write_text(
        "schema_version: 2\nendpoints:\n  primary:\n    role: signer\n"
        "    url: ssh://signer.example.com\n"
    )
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "id_ed25519").write_text("dummy-private-key")
    with patch.object(SignerClient, "connect_ssh", return_value="client") as connect:
        SignerClient.from_env(data_dir=str(tmp_path), max_fee_increase=250_000)
    assert connect.call_args.kwargs["max_fee_increase"] == 250_000

    tunnel = MagicMock()
    tunnel.local_bind_port = 12345
    with (
        patch("aplanesdk.signer._SSHTunnel", return_value=tunnel),
        patch.object(SignerClient, "health", return_value=True),
    ):
        client = SignerClient.connect_ssh(
            "signer.example.com", "/key", known_hosts_path="/kh", max_fee_increase=250_000
        )
    assert client.max_fee_increase == 250_000


# A signed position must carry exactly one authorization, and it must be the
# requested auth address's. The Go and TypeScript suites run the same list.

ED = fake_signer.account(41)
OTHER = fake_signer.account(45)
LSIG = fake_signer.lsig_account(1)
OTHER_LSIG = fake_signer.lsig_account(2)
PQ = fake_signer.pq_account(3)
OTHER_PQ = fake_signer.pq_account(4)
DUMMY = fake_signer.hold_program(bytes.fromhex("033120320312"))


def _check_authorization(txn, auth, signed_hex):
    entry = {
        "auth_address": auth,
        "txn_sender": txn.sender,
        "txn_bytes_hex": encode_transaction(txn)[0],
    }
    _validate_sign_response(_decode_request_slots([entry]), [signed_hex], None, None)


@pytest.mark.parametrize(
    ("sender", "auth"),
    [(ED, ED), (OTHER, ED), (LSIG, LSIG), (ED, LSIG), (PQ, PQ), (ED, PQ), (DUMMY, DUMMY)],
    ids=[
        "ed25519, sender signs",
        "ed25519, rekeyed sender",
        "LogicSig account",
        "LogicSig account, rekeyed sender",
        "native Falcon account",
        "native Falcon account, rekeyed sender",
        "the dummy program, when it is the auth address",
    ],
)
def test_authorization_accepted(sender, auth):
    txn = fake_signer.payment(sender=sender)
    _check_authorization(txn, auth, fake_signer.encode_signed(fake_signer.authorize(txn, auth)))


def _raw(signed):
    return msgpack.unpackb(bytes.fromhex(fake_signer.encode_signed(signed)), raw=False)


def _pack(fields) -> str:
    # Canonical msgpack: keys in sorted order, as the Algorand libraries write it.
    def canonical(value):
        if isinstance(value, dict):
            return {key: canonical(value[key]) for key in sorted(value)}
        if isinstance(value, list):
            return [canonical(item) for item in value]
        return value

    return msgpack.packb(canonical(fields), use_bin_type=True).hex()


def _edit(**changes):
    """Edit the signed transaction's top-level wire fields; None removes one."""

    def apply(signed):
        fields = _raw(signed)
        for name, value in changes.items():
            if value is None:
                fields.pop(name, None)
            else:
                fields[name] = value(fields) if callable(value) else value
        return _pack(fields)

    return apply


def _resign(auth, strip_signer=False):
    def apply(signed):
        replaced = fake_signer.authorize(signed.transaction, auth)
        fields = _raw(replaced)
        if strip_signer:
            fields.pop("sgnr", None)
        return _pack(fields)

    return apply


_OTHER_BYTES = encoding.decode_address(OTHER)
# Refused by the decoder, before the authorization check.
_SIG_ONLY = "signed transaction 1: "

AUTHORIZATION_REFUSALS = [
    ("an unsigned wrapper", ED, ED, _edit(sig=None), _SIG_ONLY),
    (
        "a signature by another key",
        ED,
        ED,
        _resign(OTHER, strip_signer=True),
        "signature does not verify under the requested auth address",
    ),
    (
        "a signature over another transaction",
        ED,
        ED,
        _edit(sig=lambda _: _raw(fake_signer.authorize(fake_signer.payment(41, 45, 5), ED))["sig"]),
        "signature does not verify under the requested auth address",
    ),
    (
        "the dummy LogicSig on an original position",
        ED,
        ED,
        _edit(sig=None, lsig={"l": bytes.fromhex("033120320312")}),
        f"LogicSig program address {DUMMY} is not the requested auth address",
    ),
    (
        "the dummy LogicSig naming itself as signer",
        ED,
        ED,
        _resign(DUMMY),
        f"names signer {DUMMY}, but the sender signs for itself",
    ),
    (
        "another LogicSig program",
        LSIG,
        LSIG,
        _edit(lsig=lambda fields: {**fields["lsig"], "l": bytes([0x06, 0x81, 2])}),
        "is not the requested auth address",
    ),
    (
        "a LogicSig delegated by a signature",
        LSIG,
        LSIG,
        _edit(lsig=lambda fields: {**fields["lsig"], "sig": bytes([1]) * 64}),
        "LogicSig is delegated by a signature",
    ),
    (
        "a wrong signer field",
        OTHER,
        ED,
        _edit(sgnr=_OTHER_BYTES),
        "not the requested auth address",
    ),
    (
        "a missing signer field for a rekeyed sender",
        OTHER,
        ED,
        _edit(sgnr=None),
        "does not name its signer",
    ),
    (
        "a signer field when the sender signs",
        ED,
        ED,
        _edit(sgnr=_OTHER_BYTES),
        "but the sender signs for itself",
    ),
    (
        "a multisig",
        ED,
        ED,
        _edit(sig=None, msig={"subsig": [{"pk": bytes(32)}], "thr": 1, "v": 1}),
        "carries a multisig",
    ),
    (
        "two authorizations",
        ED,
        ED,
        _edit(lsig={"l": bytes([0x06, 0x81, 1])}),
        _SIG_ONLY,
    ),
    (
        "a post-quantum proof with no signature",
        PQ,
        PQ,
        _edit(pqsig=lambda fields: {**fields["pqsig"], "sig": b""}),
        _SIG_ONLY,  # an empty field is not canonical, so the decoder refuses it
    ),
    (
        "a post-quantum proof with another scheme",
        PQ,
        PQ,
        _edit(pqsig=lambda fields: {**fields["pqsig"], "sch": b"x9"}),
        "post-quantum scheme",
    ),
    (
        "another post-quantum key",
        PQ,
        PQ,
        _edit(
            pqsig=lambda fields: _raw(
                fake_signer.authorize(fake_signer.payment(sender=OTHER_PQ), OTHER_PQ)
            )["pqsig"]
        ),
        "post-quantum key's address",
    ),
]


@pytest.mark.parametrize(
    ("sender", "auth", "tamper", "error"),
    [case[1:] for case in AUTHORIZATION_REFUSALS],
    ids=[case[0] for case in AUTHORIZATION_REFUSALS],
)
def test_authorization_refused(sender, auth, tamper, error):
    txn = fake_signer.payment(sender=sender)
    signed = fake_signer.authorize(txn, auth)
    _check_authorization(txn, auth, fake_signer.encode_signed(signed))
    with pytest.raises(SignerError, match=re.escape(error)) as refused:
        _check_authorization(txn, auth, tamper(signed))
    assert str(refused.value).startswith("signed transaction 1")


def test_request_auth_address_must_be_an_address():
    txn = fake_signer.payment()
    entry = {"auth_address": "AUTH", "txn_bytes_hex": encode_transaction(txn)[0]}
    with pytest.raises(SignerError, match="auth_address 'AUTH' is not a valid address"):
        _decode_request_slots([entry])
    client = make_client()
    with patch.object(client.session, "post") as post:
        with pytest.raises(ValueError, match="is not a valid address"):
            client.sign_transaction(txn, auth_address="AUTH")
    post.assert_not_called()


def test_max_fee_increase_refusal_is_typed():
    client = SignerClient("http://localhost:11270", max_fee_increase=4999)
    txns = _fee_ceiling_txns(2)
    text = "signer raised fees by 5000 microAlgos, more than the max fee increase 4999 set on this client"
    with (
        patch.object(client, "_discover_approval_wait"),
        patch.object(
            client.session,
            "post",
            side_effect=fake_signer.signer_post(fee_raise={0: 2000, 1: 3000}),
        ),
    ):
        for prefix, call in (
            ("verify signer response: ", lambda: client.sign_transactions(txns)),
            ("verify signer plan: ", lambda: client.plan_group(txns)),
        ):
            with pytest.raises(MaxFeeIncreaseError) as refused:
                call()
            assert isinstance(refused.value, SignerError)
            assert (refused.value.raised, refused.value.limit) == (5000, 4999)
            assert str(refused.value) == prefix + text
            assert isinstance(refused.value.__cause__, MaxFeeIncreaseError)

    # Any other verification failure is a plain SignerError.
    def blank(body):
        body["signed"][0] = ""

    with (
        patch.object(client, "_discover_approval_wait"),
        patch.object(client.session, "post", side_effect=fake_signer.signer_post(tamper=blank)),
    ):
        with pytest.raises(SignerError) as other:
            client.sign_transactions(txns)
    assert type(other.value) is SignerError


def test_connect_ssh_refuses_a_bad_ceiling_before_connecting_and_applies_a_good_one():
    tunnel = MagicMock()
    tunnel.local_bind_port = 12345
    with (
        patch("aplanesdk.signer._SSHTunnel", return_value=tunnel) as open_tunnel,
        patch.object(SignerClient, "health", return_value=True),
    ):
        for bad in (-1, 1.5, True, "1000"):
            with pytest.raises(SignerError, match="max_fee_increase must be a non-negative"):
                SignerClient.connect_ssh(
                    "signer.example.com", "/key", known_hosts_path="/kh", max_fee_increase=bad
                )
        open_tunnel.assert_not_called()

        client = SignerClient.connect_ssh(
            "signer.example.com",
            "/key",
            known_hosts_path="/kh",
            max_fee_increase=_Integral(1000),
        )
    open_tunnel.assert_called_once()
    assert client.max_fee_increase == 1000
    assert type(client.max_fee_increase) is int

    # The ceiling is in force on the returned client.
    with (
        patch.object(client, "_discover_approval_wait"),
        patch.object(
            client.session, "post", side_effect=fake_signer.signer_post(fee_raise={0: 3000})
        ),
    ):
        with pytest.raises(MaxFeeIncreaseError):
            client.sign_transaction(fake_signer.payment())


def test_max_fee_increase_error_pickles_and_copies():
    error = MaxFeeIncreaseError(5000, 4999, "verify signer response: ")
    for clone in (pickle.loads(pickle.dumps(error)), copy.copy(error), copy.deepcopy(error)):
        assert type(clone) is MaxFeeIncreaseError
        assert (clone.raised, clone.limit) == (5000, 4999)
        assert str(clone) == str(error)
        assert str(clone).startswith("verify signer response: signer raised fees by 5000")

    # The same flaw, fixed the same way: an error built from more than its message.
    rejected = InsufficientFundsError("TXID", "overspend")
    for clone in (pickle.loads(pickle.dumps(rejected)), copy.copy(rejected)):
        assert type(clone) is InsufficientFundsError
        assert (clone.txid, clone.reason) == ("TXID", "overspend")
        assert str(clone) == str(rejected)


def test_validators_require_the_ceiling_argument():
    """Leaving the ceiling out is an error, not a silent "no ceiling"."""
    entries = fake_signer.sign_entries(fake_signer.payment())
    slots = _decode_request_slots(entries)
    body = fake_signer.sign_response(entries)
    plan = fake_signer.plan_response(entries)
    with pytest.raises(TypeError):
        _validate_sign_response(slots, body["signed"], None)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        _validate_plan_response(slots, plan["transactions"], None)  # type: ignore[call-arg]
    _validate_sign_response(slots, body["signed"], None, None)
    _validate_plan_response(slots, plan["transactions"], None, None)


# A request that already carries a group ID is immutable to the signer, so a
# response that regroups it, raises a fee on it or appends to it is refused:
# the positions the signer did not return stay bound to the original group.


def _grouped_with_foreign():
    return foreign_entries()


def _grouped_all_signed():
    return fake_signer.sign_entries(*pregrouped_pair())


def _grouped_single():
    return fake_signer.sign_entries(pregrouped_pair()[0])


def _ungrouped_with_foreign():
    entries = pair_entries()
    entries[1] = {"txn_bytes_hex": entries[1]["txn_bytes_hex"]}
    return entries


_REGROUPED = "group ID change for a request that was already grouped"


@pytest.mark.parametrize(
    ("entries", "signer", "error"),
    [
        (_grouped_with_foreign, {"fee_raise": {0: 2000}}, _REGROUPED),
        (_grouped_with_foreign, {"dummies": 1}, _REGROUPED),
        (_grouped_all_signed, {"fee_raise": {0: 2000}}, _REGROUPED),
        (
            _grouped_single,
            {"fee_raise": {0: 2000}},
            "fee change for a request that was already grouped",
        ),
    ],
    ids=[
        "fee raised and regrouped, with a foreign position",
        "a dummy appended, with a foreign position",
        "fee raised and regrouped, every position signed",
        "fee raised on a single grouped transaction",
    ],
)
def test_mutating_a_grouped_request_is_refused(entries, signer, error):
    requests = entries()
    slots = _decode_request_slots(requests)
    body = fake_signer.sign_response(requests, **signer)
    with pytest.raises(SignerError, match=error):
        _validate_sign_response(slots, body["signed"], body.get("mutations"), None)
    plan = fake_signer.plan_response(requests, **signer)
    with pytest.raises(SignerError, match=error):
        _validate_plan_response(slots, plan["transactions"], plan.get("mutations"), None)


@pytest.mark.parametrize(
    ("entries", "signer"),
    [
        (_grouped_with_foreign, {}),
        (_grouped_all_signed, {}),
        # The signer does group an ungrouped request that has a foreign
        # position, and may raise the fee of a position it signs in it.
        (_ungrouped_with_foreign, {}),
        (_ungrouped_with_foreign, {"fee_raise": {0: 2000}, "dummies": 1}),
    ],
    ids=[
        "a grouped request returned as sent, with a foreign position",
        "a grouped request returned as sent, every position signed",
        "an ungrouped request with a foreign position, grouped",
        "an ungrouped request with a foreign position, fee raised and a dummy",
    ],
)
def test_unmutated_grouped_and_mutated_ungrouped_requests_are_accepted(entries, signer):
    requests = entries()
    body = fake_signer.sign_response(requests, **signer)
    _validate_sign_response(
        _decode_request_slots(requests), body["signed"], body.get("mutations"), None
    )


# Requests and the responses a live signer returned for them. The fake signer
# builds its dummies with the helpers under test, so these are what show the
# SDK's idea of a canonical dummy is the signer's.

_VECTORS = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[2]
        / "contracts"
        / "signerapi_vectors"
        / "real_sign_responses.json"
    ).read_text()
)
# The slot whose last byte is flipped: the appended dummy where there is one,
# otherwise the first signed transaction.
_VECTOR_TAMPER_SLOT = {
    "logicsig_falcon_single": 1,
    "logicsig_falcon_pair": 2,
    "native_falcon_single": 0,
    "ed25519_pair": 0,
}


def test_the_captured_vectors_are_the_expected_cases():
    assert set(_VECTORS) == set(_VECTOR_TAMPER_SLOT)


@pytest.mark.parametrize("name", sorted(_VECTOR_TAMPER_SLOT))
def test_captured_signer_responses_are_accepted(name):
    vector = _VECTORS[name]
    slots = _decode_request_slots(vector["request"]["requests"])
    signed = vector["response"]["signed"]
    mutations = vector["response"].get("mutations")
    _validate_sign_response(slots, signed, mutations, None)

    tampered = list(signed)
    raw = bytearray(bytes.fromhex(tampered[_VECTOR_TAMPER_SLOT[name]]))
    raw[-1] ^= 0x01
    tampered[_VECTOR_TAMPER_SLOT[name]] = raw.hex()
    with pytest.raises(SignerError):
        _validate_sign_response(slots, tampered, mutations, None)


def _rewrite(signed_hex, edit):
    fields = msgpack.unpackb(bytes.fromhex(signed_hex), raw=False)
    edit(fields)
    return _pack(fields)


def test_captured_responses_refuse_a_changed_signature_or_dummy_authorization():
    ed = _VECTORS["ed25519_pair"]
    signed = list(ed["response"]["signed"])

    def flip_signature(fields):
        fields["sig"] = bytes([fields["sig"][0] ^ 0x01]) + fields["sig"][1:]

    signed[0] = _rewrite(signed[0], flip_signature)
    with pytest.raises(
        SignerError, match="signature does not verify under the requested auth address"
    ):
        _validate_sign_response(
            _decode_request_slots(ed["request"]["requests"]),
            signed,
            ed["response"]["mutations"],
            None,
        )

    lsig = _VECTORS["logicsig_falcon_single"]
    signed = list(lsig["response"]["signed"])

    def add_argument(fields):
        fields["lsig"]["arg"] = [b"\x01"]

    signed[1] = _rewrite(signed[1], add_argument)
    with pytest.raises(
        SignerError,
        match="appended transaction 1 does not carry the canonical resource dummy authorization",
    ):
        _validate_sign_response(
            _decode_request_slots(lsig["request"]["requests"]),
            signed,
            lsig["response"]["mutations"],
            None,
        )


def test_hex_with_whitespace_is_refused():
    """bytes.fromhex skips whitespace; the Go and TypeScript SDKs do not."""
    txn = fake_signer.payment()
    entries = fake_signer.sign_entries(txn)
    slots = _decode_request_slots(entries)
    body = fake_signer.sign_response(entries)
    plan = fake_signer.plan_response(entries)
    for spaced in (lambda h: h[:10] + " " + h[10:], lambda h: h + "\n", lambda h: " " + h):
        with pytest.raises(SignerError, match="signed transaction 1 is invalid hex"):
            _validate_sign_response(slots, [spaced(body["signed"][0])], None, None)
        with pytest.raises(SignerError, match="planned transaction 1 is invalid hex"):
            _validate_plan_response(slots, [spaced(plan["transactions"][0])], None, None)
        with pytest.raises(SignerError, match="txn_bytes_hex is invalid hex"):
            _decode_request_slots(
                [{**entries[0], "txn_bytes_hex": spaced(entries[0]["txn_bytes_hex"])}]
            )
    _validate_sign_response(slots, body["signed"], None, None)


def test_sign_and_plan_requests_keep_their_public_signatures():
    """A subclass overriding the documented signatures still works with the helpers."""
    seen = []

    class Recording(SignerClient):
        def sign_requests(self, sign_entries, *, request_id=None):
            seen.append("sign")
            return super().sign_requests(sign_entries, request_id=request_id)

        def plan_requests(self, sign_entries):
            seen.append("plan")
            return super().plan_requests(sign_entries)

    client = Recording("http://localhost:11270")
    txn = fake_signer.payment()
    with (
        patch.object(client, "_discover_approval_wait"),
        patch.object(client.session, "post", side_effect=fake_signer.signer_post()),
    ):
        client.sign_transaction(txn)
        client.plan_group([txn])
    assert seen == ["sign", "plan"]
    assert list(inspect.signature(SignerClient.sign_requests).parameters) == [
        "self",
        "sign_entries",
        "request_id",
    ]
    assert list(inspect.signature(SignerClient.plan_requests).parameters) == [
        "self",
        "sign_entries",
    ]


def test_malformed_request_bytes_are_a_signer_error():
    """An adapter catching SignerError sees a bad request as it did when the signer refused it."""
    client = make_client()
    canonical = encode_transaction(fake_signer.payment())[0]
    bad = [{"txn_bytes_hex": canonical + "00", "auth_address": fake_signer.account(41)}]
    with patch.object(client.session, "post") as post:
        with pytest.raises(SignerError, match="invalid sign request: transaction 1: txn_bytes_hex"):
            client.sign_requests(bad)
        with pytest.raises(SignerError, match="invalid plan request: transaction 1: txn_bytes_hex"):
            client.plan_requests(bad)
        with pytest.raises(SignerError, match="invalid sign request: transaction 1: auth_address"):
            client.sign_requests([{"txn_bytes_hex": canonical, "auth_address": "AUTH"}])
        # Plain argument misuse stays a ValueError.
        with pytest.raises(ValueError, match="sign_entries must not be empty"):
            client.sign_requests([])
    post.assert_not_called()


def test_an_internal_error_while_verifying_is_not_reported_as_a_bad_signature():
    client = make_client()
    txn = fake_signer.payment()
    boom = RuntimeError("verifier blew up")

    class BrokenKey:
        def __init__(self, *_):
            pass

        def verify(self, *_):
            raise boom

    with (
        patch.object(client, "_discover_approval_wait"),
        patch.object(client.session, "post", side_effect=fake_signer.signer_post()),
        patch("aplanesdk.signer.VerifyKey", BrokenKey),
    ):
        with pytest.raises(SignerError) as failed:
            client.sign_transaction(txn)
    message = str(failed.value)
    assert message.startswith("verify signer response: ")
    assert "RuntimeError" in message and "verifier blew up" in message
    assert "does not verify" not in message
    assert failed.value.__cause__ is boom

    # A real bad signature still reads as one, with the library's verdict chained.
    def break_signature(body):
        fields = msgpack.unpackb(bytes.fromhex(body["signed"][0]), raw=False)
        fields["sig"] = bytes([fields["sig"][0] ^ 0x01]) + fields["sig"][1:]
        body["signed"][0] = _pack(fields)

    with (
        patch.object(client, "_discover_approval_wait"),
        patch.object(
            client.session, "post", side_effect=fake_signer.signer_post(tamper=break_signature)
        ),
    ):
        with pytest.raises(SignerError, match="signature does not verify") as refused:
            client.sign_transaction(txn)
    assert type(refused.value.__cause__.__cause__.__cause__).__name__ == "BadSignatureError"
