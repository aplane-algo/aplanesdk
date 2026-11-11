# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Rotating accounts: prepare_rotating, simulate_prepared_rotating,
sign_prepared_rotating and the rotating send.

A port of the Go SDK's rotating_test.go. The signer and algod are local HTTP
fakes (tests/send_fakes.py). The tamper tables below are the Go tables, and
the shared vectors (test_rotating_vectors.py) are generated from those.
"""

import base64
import copy
import json

import pytest
from algosdk import encoding, transaction

import aplanesdk.signer as signer_module
from aplanesdk import (
    ERR_CODE_BAD_REQUEST,
    ERR_CODE_FORBIDDEN,
    ERR_CODE_ROTATING_STAGE_CHANGED,
    ERR_CODE_ROTATING_STAGE_UNPROVEN,
    ERR_CODE_ROTATING_WINDOW_NOT_CURRENT,
    ERR_CODE_UNAUTHORIZED,
    ROTATING_MAX_LEAD,
    ROTATING_MAX_VALIDITY_WINDOW,
    ROTATING_MIN_REMAINING,
    SEND_OUTCOME_CONFIRMED,
    SIGNING_FLOW_ROTATING1,
    AuthenticationError,
    MaxFeeIncreaseError,
    PreparedGroup,
    PreparedRotating,
    PreparedTransaction,
    RotatingPreflightError,
    SignerError,
    SignerUnavailableError,
    SigningRejectedError,
    SignOutcomeUnknownError,
    UnsupportedGroupError,
)
from aplanesdk.signer import (
    _canonical_dummy_txn,
    _check_rotating_window,
    _rotating_window_current,
)
from tests import fake_signer
from tests.send_fakes import (
    DROP,
    ELSEWHERE,
    ROTATING_KEY_TYPE,
    ROTATING_NEXT_PROGRAM,
    ROTATING_TEST_PROGRAM,
    FakeNode,
    HTTPFake,
    RotatingSigner,
    SendSigner,
    alternate_spelling,
    decode_map,
    key,
    program_address,
    refusal,
    regroup,
    reply,
    rotating_payment,
    set_prepared,
    set_signed,
    signer_client,
    truncated,
)


@pytest.fixture
def fakes():
    made = []

    def track(fake):
        made.append(fake)
        return fake

    yield track
    for fake in made:
        fake.http.close()


@pytest.fixture
def quick_backoff(monkeypatch):
    monkeypatch.setattr(signer_module, "_ROTATING_UNPROVEN_BACKOFF", 0.001)


class Fixture:
    """A rotating account at stage 3 whose spends need one dummy and a 1,000
    microAlgo charge, and a node at round 10."""

    def __init__(self, fakes, signer=None, node=None):
        self.signer = fakes(signer or RotatingSigner(fake_signer.account(41)))
        self.node = fakes(node or FakeNode())
        self.client = signer_client(self.signer.http.url)
        self.txn = rotating_payment(self.signer.account, 10, 110)

    def send(self, txn=None, **options):
        return self.client.send_prepared(
            self.node.client, rotating_group(txn or self.txn), **options
        )


def rotating_group(txn):
    return PreparedGroup([PreparedTransaction(transaction=txn, auth_address=txn.sender)])


def decode_txn_hex(txn_hex):
    return encoding.msgpack_decode(base64.b64encode(bytes.fromhex(txn_hex)[2:]).decode())


def decode_signed(blob):
    import msgpack

    unpacker = msgpack.Unpacker(raw=False)
    unpacker.feed(blob)
    return encoding.msgpack_decode(next(unpacker))


def test_send_prepared_rotating_prepares_simulates_signs_submits(fakes):
    f = Fixture(fakes)

    result = f.send()

    assert f.signer.count("/sign/rotating/prepare") == 1
    assert f.signer.count("/sign/rotating/sign") == 1
    assert f.signer.count("/sign") == 0
    # The group was simulated once, unsigned, exactly as prepared, with the
    # node taking the sender's authorizer from the chain; without that an
    # account that has rotated fails its own simulation.
    simulations = f.node.simulations()
    assert len(simulations) == 1
    assert simulations[0]["allow-empty-signatures"] is True
    assert simulations[0]["fix-signers"] is True
    prepared = f.signer.sign_requests[0]["transactions"]
    simulated = simulations[0]["txn-groups"][0]["txns"]
    assert len(simulated) == 2 and len(prepared) == 2
    for index, entry in enumerate(simulated):
        assert set(entry) == {"txn"}, f"simulated transaction {index} carries a signature"
        canonical = base64.b64decode(encoding.msgpack_encode(entry["txn"]))
        assert (b"TX" + canonical).hex() == prepared[index]

    assert result.flow == SIGNING_FLOW_ROTATING1 and result.original_count == 1
    assert len(result.signed_group) == 2 and result.group_id
    assert [blob.hex() for blob in f.node.submissions()] == ["".join(result.signed_group)]
    spend = decode_signed(f.node.submissions()[0])
    assert spend.transaction.rekey_to == f.signer.next_target()
    assert spend.transaction.fee == 2000
    assert spend.auth_addr == program_address(ROTATING_TEST_PROGRAM)
    # The ID is the signed spend's, not the draft's.
    assert result.tx_ids[0] == spend.transaction.get_txid() != f.txn.get_txid()
    assert result.fees == [2000, 0]
    details = result.rotating
    assert details.stage == 3 and details.target == 4
    assert details.rekey_to == f.signer.next_target()
    assert details.attempts == 1 and details.request_id
    assert result.outcome == SEND_OUTCOME_CONFIRMED


def test_send_prepared_rotating_stage_zero_without_dummies(fakes):
    account = program_address(ROTATING_TEST_PROGRAM)
    f = Fixture(fakes, RotatingSigner(account, stage=0, dummies=0, charge=0))

    result = f.send(rotating_payment(account, 10, 110))

    spend = decode_signed(f.node.submissions()[0])
    assert spend.auth_addr is None
    assert len(result.signed_group) == 1 and result.group_id == "" and result.mutations is None


# -----------------------------------------------------------------------------
# The prepared group: the client's authority boundary
# -----------------------------------------------------------------------------


def _respend(response, txns, change):
    """Change the prepared spend, regroup, and write the group back, as a
    signer that altered the spend would have to."""
    change(txns[0])
    regroup(txns)
    set_prepared(response, txns)


def _set(name, value):
    return lambda txn: setattr(txn, name, value)


def _flip_genesis(txn):
    genesis = bytearray(base64.b64decode(txn.genesis_hash))
    genesis[1] ^= 1
    txn.genesis_hash = base64.b64encode(bytes(genesis)).decode()


def _alter_group_id(response, txns):
    for txn in txns:
        group = bytearray(txn.group)
        group[0] ^= 1
        txn.group = bytes(group)
    set_prepared(response, txns)


def _dummy(change):
    def alter(response, txns):
        change(txns[1])
        regroup(txns)
        set_prepared(response, txns)

    return alter


def _extra_transaction(response, txns):
    txns.append(_canonical_dummy_txn(txns[0], None, len(txns) - 1))
    regroup(txns)
    set_prepared(response, txns)


def _no_fee_report(response, txns):
    response["mutations"]["fees_modified"] = None
    response["mutations"]["total_fees_delta"] = 0


def _field(name, value):
    def alter(response, txns):
        response[name] = value(response) if callable(value) else value

    return alter


def _overflow(response, txns):
    response["stage"], response["target"] = (1 << 64) - 1, 0


def _transaction_text(change):
    def alter(response, txns):
        response["transactions"][0] = change(response["transactions"][0])

    return alter


# The things a signer may not do to a prepared group. Each alters a correct
# prepare answer; the text is what this SDK's check says. They are the Go
# tables, which generate the shared vectors.
PREPARE_TAMPERS = [
    (
        "receiver changed",
        lambda r, t: _respend(r, t, _set("receiver", ELSEWHERE)),
        "changed unreported fields",
    ),
    (
        "amount changed",
        lambda r, t: _respend(r, t, lambda s: setattr(s, "amt", s.amt + 1)),
        "changed unreported fields",
    ),
    ("note added", lambda r, t: _respend(r, t, _set("note", b"x")), "changed unreported fields"),
    (
        "close-out added",
        lambda r, t: _respend(r, t, _set("close_remainder_to", ELSEWHERE)),
        "changed unreported fields",
    ),
    (
        "validity rounds changed",
        lambda r, t: _respend(
            r, t, lambda s: setattr(s, "last_valid_round", s.last_valid_round - 1)
        ),
        "changed unreported fields",
    ),
    ("network changed", lambda r, t: _respend(r, t, _flip_genesis), "changed unreported fields"),
    (
        "rekey to an address other than the one reported",
        lambda r, t: _respend(r, t, _set("rekey_to", ELSEWHERE)),
        "changed unreported fields",
    ),
    (
        "rekey left out",
        lambda r, t: _respend(r, t, _set("rekey_to", None)),
        "changed unreported fields",
    ),
    (
        "reported rekey target is the zero address",
        _field("rekey_to", encoding.encode_address(bytes(32))),
        "rekey_to must be another, non-zero address",
    ),
    (
        "reported rekey target is the account",
        _field("rekey_to", lambda r: r["account"]),
        "rekey_to must be another, non-zero address",
    ),
    (
        "reported rekey target in another spelling of its address",
        _field("rekey_to", lambda r: alternate_spelling(r["rekey_to"])),
        "invalid rekey_to",
    ),
    (
        "account in another spelling of the sender",
        _field("account", lambda r: alternate_spelling(r["account"])),
        "is not the sender",
    ),
    ("reported rekey target is not an address", _field("rekey_to", "nonsense"), "invalid rekey_to"),
    (
        "fee raised more than reported",
        lambda r, t: _respend(r, t, lambda s: setattr(s, "fee", s.fee + 500)),
        "total_fees_delta",
    ),
    ("fee raised with no fee report", _no_fee_report, "changed unreported fields"),
    ("fee lowered", lambda r, t: _respend(r, t, _set("fee", 500)), "did not increase the fee"),
    ("group ID not the group's", _alter_group_id, "canonical group ID"),
    ("dummy pays the account's money", _dummy(_set("amt", 1)), "not the canonical resource dummy"),
    (
        "dummy on other rounds",
        _dummy(lambda d: setattr(d, "last_valid_round", d.last_valid_round + 1)),
        "not the canonical resource dummy",
    ),
    ("extra transaction beyond the report", _extra_transaction, "final_count"),
    ("dummies with no report", _field("mutations", None), "without a mutation report"),
    ("no transactions", _field("transactions", None), "prepared group is empty"),
    ("another account", _field("account", fake_signer.test_address(9)), "is not the sender"),
    (
        "target is not the next stage",
        _field("target", lambda r: r["stage"] + 2),
        "not the stage after",
    ),
    ("target equals the stage", _field("target", lambda r: r["stage"]), "not the stage after"),
    ("stage number overflows", _overflow, "not the stage after"),
    # Go says "not canonical": its decoder reads the spend and finds bytes
    # left over. This decoder refuses the extra data while reading.
    (
        "trailing bytes after the spend",
        _transaction_text(lambda h: h + "00"),
        "prepared transaction 1: invalid msgpack",
    ),
    ("spend without the TX prefix", _transaction_text(lambda h: h[4:]), "missing TX prefix"),
    ("spend is not hex", _transaction_text(lambda h: "zz"), "invalid hex"),
]


@pytest.mark.parametrize(
    "alter,text", [case[1:] for case in PREPARE_TAMPERS], ids=[case[0] for case in PREPARE_TAMPERS]
)
def test_prepare_rotating_refuses_altered_group(fakes, alter, text):
    # None reaches simulation or signing.
    f = Fixture(fakes)
    f.signer.alter_prepare = alter

    with pytest.raises(SignerError, match="verify prepared rotating group") as excinfo:
        f.send()

    assert text in str(excinfo.value)
    assert f.node.simulations() == []
    assert f.signer.count("/sign/rotating/sign") == 0
    assert f.node.submissions() == []


def test_prepare_rotating_holds_the_fee_ceiling(fakes):
    f = Fixture(fakes)
    f.client.max_fee_increase = 999

    with pytest.raises(MaxFeeIncreaseError) as excinfo:
        f.send()

    assert excinfo.value.raised == 1000 and excinfo.value.limit == 999
    assert f.node.simulations() == [] and f.signer.count("/sign/rotating/sign") == 0

    f.client.max_fee_increase = 1000
    f.send()


@pytest.mark.parametrize(
    "stage,target",
    [
        (3.0, 4),
        (True, 2),
        ("3", 4),
        (-1, 0),
        ((1 << 64) - 1, 1 << 64),
        ((1 << 64) - 1, 0),
    ],
    ids=[
        "float stage",
        "bool stage",
        "text stage",
        "negative stage",
        "target past uint64",
        "last stage wraps",
    ],
)
def test_prepare_rotating_refuses_a_stage_that_is_not_a_uint64(fakes, stage, target):
    # Python integers do not wrap, so the overflow rule is a range check: a
    # stage or target outside uint64, or anything but an integer, is refused.
    f = Fixture(fakes)

    def alter(response, txns):
        response["stage"], response["target"] = stage, target

    f.signer.alter_prepare = alter
    # Refused where the answer is read, or by the check after: a plain
    # failure either way, since preparing releases nothing.
    with pytest.raises(SignerError, match="failed to decode response|verify prepared") as e:
        f.client.prepare_rotating(f.txn)
    assert not isinstance(e.value, SignOutcomeUnknownError)
    assert f.signer.count("/sign/rotating/sign") == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("group_id_changed", 0),
        ("group_id_changed", "true"),
        ("fees_modified", 0),
        ("fees_modified", ""),
        ("fees_modified", {}),
        ("fees_modified", [0.0]),
        ("reason", 5),
        ("total_fees_delta", "1000"),
        ("dummies_added", 1 << 63),
    ],
)
def test_prepare_answers_mutation_report_is_typed_as_go_decodes_it(fakes, field, value):
    # A plain failure: preparing releases nothing.
    f = Fixture(fakes)

    def alter(response, txns):
        response["mutations"][field] = value

    f.signer.alter_prepare = alter
    with pytest.raises(SignerError, match="failed to decode response") as excinfo:
        f.client.prepare_rotating(f.txn)
    assert not isinstance(excinfo.value, SignOutcomeUnknownError)


@pytest.mark.parametrize("body", [b"null", b"[]", b"", b"{} {}", b'{"stage": NaN}'])
def test_an_unreadable_prepare_answer_is_a_plain_failure(fakes, body):
    f = Fixture(fakes)

    def app(method, path, request):
        if path == "/sign/rotating/prepare":
            return (200, body, "application/json")
        return f.signer.app(method, path, request)

    other = fakes(_Fake(app))
    with pytest.raises(SignerError) as excinfo:
        signer_client(other.http.url).prepare_rotating(f.txn)
    assert not isinstance(excinfo.value, SignOutcomeUnknownError)


def test_a_prepare_answer_field_left_out_takes_its_zero_value(fakes):
    # As in Go's typed decoding: a stage left out is stage 0.
    account = program_address(ROTATING_TEST_PROGRAM)
    f = Fixture(fakes, RotatingSigner(account, stage=0, dummies=0, charge=0))

    def alter(response, txns):
        del response["stage"]
        response["mutations"] = None

    f.signer.alter_prepare = alter
    prepared = f.client.prepare_rotating(rotating_payment(account, 10, 110))
    assert prepared.stage == 0 and prepared.target == 1


@pytest.mark.parametrize(
    "field,value", [("group_id_changed", 0), ("fees_modified", 0), ("reason", 5)]
)
def test_a_plan_report_is_typed_as_go_decodes_it(field, value):
    # The /plan answer is read by its declared shape, the mutation report's
    # fields typed as Go decodes them.
    from unittest.mock import patch

    client = signer_client("http://127.0.0.1:9")
    txn = fake_signer.payment(41, 42)

    def tamper(body):
        body.setdefault("mutations", {"original_count": 1, "final_count": 1})[field] = value

    with patch.object(client.session, "post", side_effect=fake_signer.signer_post(tamper=tamper)):
        with pytest.raises(
            SignerError, match=f"failed to decode plan response: answer field mutations field {field}"
        ):
            client.plan_group([txn])


# -----------------------------------------------------------------------------
# The signed group
# -----------------------------------------------------------------------------


def _resign(change):
    def alter(signer, response, signed):
        change(signed)
        set_signed(response, signed)

    return alter


def _hex_list(change):
    def alter(signer, response, signed):
        response["signed"] = change(response["signed"])

    return alter


def _swap(items):
    return [items[1], items[0]] + items[2:]


def _set_in(index, *path_and_value):
    *path, value = path_and_value

    def change(signed):
        target = signed[index]
        for name in path[:-1]:
            target = target[name]
        if value is _DELETE:
            target.pop(path[-1], None)
        else:
            target[path[-1]] = value

    return change


_DELETE = object()
_SIGNATURE = bytes([1]) + bytes(63)


def _plain_key(signed):
    signed[0].pop("lsig")
    signed[0]["sig"] = _SIGNATURE


def _field_of_answer(name, value):
    def alter(signer, response, signed):
        response[name] = value(response)

    return alter


def _another_stage(signer, response, signed):
    response["stage"], response["target"] = response["stage"] + 1, response["target"] + 1


def _another_txid(signer, response, signed):
    response["txid"] = encoding.msgpack_decode(signed[1]).transaction.get_txid()


def _another_group_id(signer, response, signed):
    response["group_id"] = base64.b64encode(bytes(32)).decode()


def _amount_up(signed):
    signed[0]["txn"]["amt"] += 1


# Signed answers that are not exactly the prepared group, properly
# authorized. Each alters a correct sign answer. Where this decoder refuses
# an envelope before the Go check would, the text says so.
SIGN_TAMPERS = [
    (
        "spend changed after preparation",
        _resign(_amount_up),
        "differs from the prepared transaction",
    ),
    (
        "dummy changed after preparation",
        _resign(_set_in(1, "txn", "note", b"\x09")),
        "differs from the prepared transaction",
    ),
    ("transactions reordered", _hex_list(_swap), "differs from the prepared transaction"),
    (
        "transaction missing",
        _hex_list(lambda items: items[:1]),
        "signed group has 1 transaction(s), prepared 2",
    ),
    (
        "extra transaction",
        _hex_list(lambda items: items + [items[1]]),
        "signed group has 3 transaction(s), prepared 2",
    ),
    # Go: "not a canonical signed transaction", found after decoding.
    (
        "trailing bytes",
        _hex_list(lambda items: [items[0] + "00"] + items[1:]),
        "signed transaction 1: invalid msgpack",
    ),
    # Go: "not authorized by a stage program". An envelope with no
    # authorization does not decode as a signed transaction here.
    (
        "spend not signed",
        _resign(_set_in(0, "lsig", _DELETE)),
        "signed transaction 1: did not decode as a signed transaction",
    ),
    (
        "spend signed by a plain key instead",
        _resign(_plain_key),
        "not authorized by a stage program",
    ),
    # Go: "more than one authorization". This decoder keeps one of the two,
    # so the bytes are not the canonical encoding of what it read.
    (
        "spend carries two authorizations",
        _resign(_set_in(0, "sig", _SIGNATURE)),
        "not a canonical signed transaction",
    ),
    (
        "stage program delegated by a signature",
        _resign(_set_in(0, "lsig", "sig", _SIGNATURE)),
        "delegated by a signature",
    ),
    (
        "signer of the spend not named",
        _resign(_set_in(0, "sgnr", _DELETE)),
        "does not name its signer",
    ),
    (
        "named signer is not the program's address",
        _resign(
            _set_in(0, "sgnr", encoding.decode_address(program_address(ROTATING_NEXT_PROGRAM)))
        ),
        "not the requested auth address",
    ),
    # Go: "not the canonical signed resource dummy".
    (
        "dummy not signed",
        _resign(_set_in(1, "lsig", _DELETE)),
        "signed transaction 2: did not decode as a signed transaction",
    ),
    (
        "dummy signed by another program",
        _resign(_set_in(1, "lsig", {"l": ROTATING_NEXT_PROGRAM})),
        "not the canonical signed resource dummy",
    ),
    (
        "another stage reported, target unchanged",
        _field_of_answer("stage", lambda r: r["stage"] + 1),
        "signer reports stage 4 to 4, prepared 3 to 4",
    ),
    (
        "another target reported, stage unchanged",
        _field_of_answer("target", lambda r: r["target"] + 1),
        "signer reports stage 3 to 5, prepared 3 to 4",
    ),
    ("another stage reported", _another_stage, "signer reports stage 4 to 5, prepared 3 to 4"),
    ("another transaction ID reported", _another_txid, "signer reports transaction ID"),
    ("another group ID reported", _another_group_id, "signer reports group ID"),
]


@pytest.mark.parametrize(
    "alter,text", [case[1:] for case in SIGN_TAMPERS], ids=[case[0] for case in SIGN_TAMPERS]
)
def test_sign_prepared_rotating_refuses_altered_response(fakes, alter, text):
    # None is submitted.
    f = Fixture(fakes)
    f.signer.alter_sign = lambda response, signed: alter(f.signer, response, signed)

    with pytest.raises(SignerError, match="verify signer response") as excinfo:
        f.send()

    # A well-typed answer that fails a check is a refusal, not a lost answer.
    assert not isinstance(excinfo.value, SignOutcomeUnknownError)
    assert text in str(excinfo.value)
    assert f.node.submissions() == []
    assert f.signer.count("/sign/rotating/sign") == 1


@pytest.mark.parametrize(
    "stage,target", [(3, 5), (3, None), (None, 4)], ids=["another target", "no target", "no stage"]
)
def test_sign_prepared_rotating_refuses_a_reported_stage_that_is_not_the_prepared_one(
    fakes, stage, target
):
    # A field left out, or null, decodes at its zero value, as in Go: it is
    # well typed, and refused as another stage.
    f = Fixture(fakes)

    def alter(response, signed):
        response["stage"], response["target"] = stage, target

    f.signer.alter_sign = alter
    with pytest.raises(SignerError, match="signer reports stage") as excinfo:
        f.send()
    assert not isinstance(excinfo.value, SignOutcomeUnknownError)
    assert f.node.submissions() == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("stage", "3"),
        ("stage", 3.0),
        ("stage", True),
        ("stage", -1),
        ("stage", 1 << 64),
        ("target", 4.0),
        ("target", "4"),
        ("signed", "ab"),
        ("signed", [1]),
        ("txid", 5),
        ("group_id", ["x"]),
    ],
)
def test_a_sign_answer_with_a_field_of_the_wrong_type_is_an_unknown_outcome(fakes, field, value):
    # Go decodes the answer into a typed struct, which fails for these: the
    # answer could not be read, and a signature may have been released.
    f = Fixture(fakes)

    def alter(response, signed):
        response[field] = value

    f.signer.alter_sign = alter
    with pytest.raises(SignOutcomeUnknownError) as excinfo:
        f.send()
    assert isinstance(excinfo.value.rotating, PreparedRotating)
    assert excinfo.value.request_id
    assert f.node.submissions() == []
    assert f.signer.count("/sign/rotating/sign") == 1


@pytest.mark.parametrize("body", [b"123", b'"ok"', b"[]", b"[1, 2]"])
def test_a_sign_answer_that_is_not_an_object_is_an_unknown_outcome(fakes, body):
    f = Fixture(fakes)
    prepared = f.client.prepare_rotating(f.txn)

    def app(method, path, request):
        if path == "/sign/rotating/sign":
            return (200, body, "application/json")
        return f.signer.app(method, path, request)

    other = fakes(_Fake(app))
    with pytest.raises(SignOutcomeUnknownError) as excinfo:
        signer_client(other.http.url).sign_prepared_rotating(prepared)
    assert excinfo.value.rotating is prepared


class TestStageProgramMustFitTheStage:
    def test_stage_0_signs_as_the_account_itself(self, fakes):
        # The signer claims stage 0, but the program is not the account's.
        f = Fixture(fakes)
        f.signer.stage = 0
        with pytest.raises(SignerError, match="does not fit stage 0"):
            f.send()
        assert f.node.submissions() == []

    def test_a_later_stage_does_not_sign_as_the_account(self, fakes):
        account = program_address(ROTATING_TEST_PROGRAM)
        f = Fixture(fakes, RotatingSigner(account, stage=2, dummies=0, charge=0))
        with pytest.raises(SignerError, match="does not fit stage 2"):
            f.send(rotating_payment(account, 10, 110))

    def test_the_next_stages_program_does_not_sign(self, fakes):
        f = Fixture(fakes)

        def alter(response, txns):
            # The reported target is the address of the program that signs.
            target = program_address(ROTATING_TEST_PROGRAM)
            response["rekey_to"] = target
            txns[0].rekey_to = target
            regroup(txns)
            set_prepared(response, txns)

        f.signer.alter_prepare = alter
        with pytest.raises(SignerError, match="authorized by the next stage's program"):
            f.send()
        assert f.node.submissions() == []


# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------


class TestFailedPreflightSignsNothing:
    def test_simulation_fails(self, fakes):
        f = Fixture(fakes)
        f.node.simulate = lambda: reply(
            200,
            {
                "last-round": 10,
                "version": 2,
                "txn-groups": [{"failure-message": "logic eval error: rekey not allowed"}],
            },
        )
        with pytest.raises(RotatingPreflightError) as excinfo:
            f.send()
        assert "rekey not allowed" in excinfo.value.message
        assert isinstance(excinfo.value.prepared, PreparedRotating)
        assert f.signer.count("/sign/rotating/sign") == 0 and f.node.submissions() == []

    def test_simulation_cannot_be_run(self, fakes):
        f = Fixture(fakes)
        f.node.simulate = lambda: reply(500, {"message": "down"})
        with pytest.raises(SignerError, match="nothing was signed"):
            f.send()
        assert f.signer.count("/sign/rotating/sign") == 0

    def test_simulate_only_never_signs(self, fakes):
        f = Fixture(fakes)
        prepared = f.client.prepare_rotating(f.txn)
        simulation = f.client.simulate_prepared_rotating(f.node.client, prepared)
        assert not simulation.failed and len(simulation.tx_ids) == 2
        assert simulation.tx_ids == prepared.tx_ids
        assert simulation.signed_group == []
        assert f.signer.count("/sign/rotating/sign") == 0 and f.node.submissions() == []


class TestStopsBeforeSigning:
    def test_simulation_reports_no_group(self, fakes):
        f = Fixture(fakes)
        f.node.simulate = lambda: reply(200, {"last-round": 10, "version": 2})
        with pytest.raises(RotatingPreflightError, match="no result for the group"):
            f.send()
        assert f.signer.count("/sign/rotating/sign") == 0

    def test_the_steps_report_an_empty_simulation_answer_as_failed(self, fakes):
        f = Fixture(fakes)
        f.node.simulate = lambda: reply(200, {"last-round": 10, "version": 2})
        prepared = f.client.prepare_rotating(f.txn)
        assert f.client.simulate_prepared_rotating(f.node.client, prepared).failed


# -----------------------------------------------------------------------------
# Retries
# -----------------------------------------------------------------------------

STAGE_CHANGED = refusal(ERR_CODE_ROTATING_STAGE_CHANGED, "the account's authorizer changed")
NOT_CURRENT = refusal(
    ERR_CODE_ROTATING_WINDOW_NOT_CURRENT, "fewer than 10 rounds remain before last valid round"
)
UNPROVEN = refusal(
    ERR_CODE_ROTATING_STAGE_UNPROVEN, "the account's live stage has not been found yet"
)


@pytest.mark.usefixtures("quick_backoff")
class TestRetries:
    def test_stage_not_found_yet_then_found(self, fakes):
        f = Fixture(fakes)
        f.signer.prepare_errors = [UNPROVEN]
        result = f.send()
        assert result.rotating.attempts == 2
        assert f.signer.count("/sign/rotating/prepare") == 2
        assert f.signer.count("/sign/rotating/sign") == 1

    def test_authorizer_moved_before_signing_then_signed(self, fakes):
        f = Fixture(fakes)
        f.signer.sign_errors = [STAGE_CHANGED]
        result = f.send()
        assert result.rotating.attempts == 2
        # Every attempt is prepared, simulated and presented for approval again.
        assert f.signer.count("/sign/rotating/prepare") == 2
        assert f.signer.count("/sign/rotating/sign") == 2
        assert len(f.node.simulations()) == 2 and len(f.node.submissions()) == 1
        # The supplied transaction was not rebuilt.
        sent = result.rotating.transaction
        assert (sent.first_valid_round, sent.last_valid_round) == (10, 110)

    def test_gives_up_after_three_attempts(self, fakes):
        f = Fixture(fakes)
        f.signer.sign_errors = [STAGE_CHANGED] * 4
        with pytest.raises(SignerError) as excinfo:
            f.send()
        assert excinfo.value.code == ERR_CODE_ROTATING_STAGE_CHANGED
        assert f.signer.count("/sign/rotating/sign") == 3 and f.node.submissions() == []

    def test_window_not_current_supplied_input_is_returned_not_rebuilt(self, fakes):
        f = Fixture(fakes)
        f.signer.sign_errors = [NOT_CURRENT]
        with pytest.raises(SignerError) as excinfo:
            f.send()
        assert excinfo.value.code == ERR_CODE_ROTATING_WINDOW_NOT_CURRENT
        assert f.signer.count("/sign/rotating/prepare") == 1
        assert f.signer.count("/sign/rotating/sign") == 1 and f.node.submissions() == []

    def test_window_not_current_rebuilt_when_refresh_is_allowed(self, fakes):
        f = Fixture(fakes, node=FakeNode(round=50))
        f.signer.sign_errors = [NOT_CURRENT]
        result = f.send(rotating_payment(f.signer.account, 50, 150), refresh_validity=True)
        assert result.rotating.attempts == 2
        assert f.signer.count("/sign/rotating/sign") == 2 and len(f.signer.prepare_seen) == 2

    def test_an_uncoded_bad_request_is_not_retried(self, fakes):
        f = Fixture(fakes)
        # The old wording of a timing refusal, without the code.
        f.signer.sign_errors = [
            refusal(ERR_CODE_BAD_REQUEST, "fewer than 10 rounds remain before last valid round 110")
        ]
        with pytest.raises(SignerError) as excinfo:
            f.send(refresh_validity=True)
        assert excinfo.value.code == ERR_CODE_BAD_REQUEST
        assert f.signer.count("/sign/rotating/sign") == 1
        assert f.signer.count("/sign/rotating/prepare") == 1

    def test_a_policy_refusal_is_not_retried(self, fakes):
        f = Fixture(fakes)
        f.signer.error_status = 403
        f.signer.sign_errors = [refusal(ERR_CODE_FORBIDDEN, "rejected")]
        with pytest.raises(SigningRejectedError):
            f.send()
        assert f.signer.count("/sign/rotating/sign") == 1
        assert f.signer.count("/sign/rotating/prepare") == 1


@pytest.mark.usefixtures("quick_backoff")
class TestRetryBounds:
    def test_a_stage_that_is_never_found_ends_after_three_prepares(self, fakes):
        f = Fixture(fakes)
        f.signer.prepare_errors = [refusal(ERR_CODE_ROTATING_STAGE_UNPROVEN, "not found yet")] * 6
        with pytest.raises(SignerError) as excinfo:
            f.send()
        assert excinfo.value.code == ERR_CODE_ROTATING_STAGE_UNPROVEN
        assert f.signer.count("/sign/rotating/prepare") == 3
        assert f.signer.count("/sign/rotating/sign") == 0

    def test_a_window_that_is_never_current_ends_after_three_signs(self, fakes):
        f = Fixture(fakes)
        f.signer.sign_errors = [refusal(ERR_CODE_ROTATING_WINDOW_NOT_CURRENT, "too few")] * 6
        with pytest.raises(SignerError) as excinfo:
            f.send(refresh_validity=True)
        assert excinfo.value.code == ERR_CODE_ROTATING_WINDOW_NOT_CURRENT
        assert f.signer.count("/sign/rotating/sign") == 3 and f.node.submissions() == []

    def test_the_wait_before_preparing_again_grows_with_each_attempt(self, fakes, monkeypatch):
        waits = []
        monkeypatch.setattr(signer_module.time, "sleep", waits.append)
        f = Fixture(fakes)
        f.signer.prepare_errors = [UNPROVEN, UNPROVEN]
        f.send()
        assert waits == [0.001, 0.002]


# -----------------------------------------------------------------------------
# Validity rounds
# -----------------------------------------------------------------------------


class TestValidityRounds:
    def test_a_supplied_window_over_the_limit_is_refused_before_the_signer(self, fakes):
        f = Fixture(fakes)
        with pytest.raises(SignerError, match="validity window is 1000 rounds"):
            f.send(rotating_payment(f.signer.account, 10, 1010))
        assert f.signer.count("/sign/rotating/prepare") == 0

    @pytest.mark.parametrize("rounds", [(10, 1010), (1, 12)], ids=["overlong", "stale"])
    def test_refresh_rebuilds_an_overlong_or_stale_window(self, fakes, rounds):
        f = Fixture(fakes, node=FakeNode(round=40))
        result = f.send(rotating_payment(f.signer.account, *rounds), refresh_validity=True)
        sent = f.signer.prepare_seen[0]
        assert sent.first_valid_round == 40 and sent.last_valid_round >= 50
        assert sent.last_valid_round - sent.first_valid_round <= ROTATING_MAX_VALIDITY_WINDOW
        assert result.rotating.transaction.first_valid_round == sent.first_valid_round

    def test_refresh_keeps_a_stale_windows_length_between_10_and_100_rounds(self, fakes):
        f = Fixture(fakes, node=FakeNode(round=40))
        f.send(rotating_payment(f.signer.account, 1, 31), refresh_validity=True)
        sent = f.signer.prepare_seen[0]
        assert (sent.first_valid_round, sent.last_valid_round) == (40, 70)

    def test_a_current_window_is_left_alone_even_when_refresh_is_allowed(self, fakes):
        f = Fixture(fakes)
        f.send(refresh_validity=True)
        sent = f.signer.prepare_seen[0]
        assert (sent.first_valid_round, sent.last_valid_round) == (10, 110)

    def test_the_callers_transaction_is_not_changed(self, fakes):
        f = Fixture(fakes, node=FakeNode(round=40))
        txn = rotating_payment(f.signer.account, 10, 1010)
        f.send(txn, refresh_validity=True)
        assert (txn.first_valid_round, txn.last_valid_round) == (10, 1010)


class TestChecksTheRoundBeforeTheOperatorIsAsked:
    def test_stale_rounds_are_refused_when_they_may_not_be_rebuilt(self, fakes):
        f = Fixture(fakes, node=FakeNode(round=105))  # fewer than 10 rounds left of 10-110
        with pytest.raises(SignerError, match="are not current at round 105"):
            f.send()
        assert f.signer.count("/sign/rotating/prepare") == 0

    def test_a_window_too_short_to_sign_is_not_kept_when_rebuilding(self, fakes):
        f = Fixture(fakes, node=FakeNode(round=40))
        f.send(rotating_payment(f.signer.account, 40, 45), refresh_validity=True)
        sent = f.signer.prepare_seen[0]
        assert (sent.first_valid_round, sent.last_valid_round) == (
            40,
            40 + ROTATING_MAX_VALIDITY_WINDOW,
        )


def test_send_prepared_rotating_widens_the_window_after_a_timing_refusal(fakes):
    f = Fixture(fakes, node=FakeNode(round=40))
    f.signer.sign_errors = [refusal(ERR_CODE_ROTATING_WINDOW_NOT_CURRENT, "too few rounds remain")]
    # A 12-round window is current, and leaves the operator two rounds.
    result = f.send(rotating_payment(f.signer.account, 40, 52), refresh_validity=True)
    assert result.rotating.attempts == 2
    first, second = f.signer.prepare_seen
    assert first.last_valid_round - first.first_valid_round == 12
    assert second.last_valid_round - second.first_valid_round == ROTATING_MAX_VALIDITY_WINDOW


def test_rotating_timing_constants_match_the_contract():
    # docs/ARCH_SIGNING.md, "Rotating accounts": a window of at most 100
    # rounds, first valid at most 2 rounds ahead, at least 10 rounds left.
    assert (ROTATING_MAX_VALIDITY_WINDOW, ROTATING_MAX_LEAD, ROTATING_MIN_REMAINING) == (
        100,
        2,
        10,
    )
    txn = rotating_payment(fake_signer.account(41), 12, 112)
    for current, want in {9: False, 10: True, 102: True, 103: False}.items():
        assert _rotating_window_current(txn, current) is want, current
    txn.last_valid_round = 113
    assert not _rotating_window_current(txn, 10)


@pytest.mark.parametrize(
    "first,last", [(-1, 10), (10, 1 << 64), (10.0, 20)], ids=["negative", "past uint64", "float"]
)
def test_rounds_that_are_not_uint64_are_refused(first, last):
    txn = rotating_payment(fake_signer.account(41), 1, 2)
    txn.first_valid_round, txn.last_valid_round = first, last
    with pytest.raises(ValueError):
        _check_rotating_window(txn)


class TestUnsupportedShapes:
    @pytest.mark.parametrize(
        "change,text",
        [
            (
                lambda item: setattr(item.transaction, "group", bytes([1]) + bytes(31)),
                "must be ungrouped",
            ),
            (
                lambda item: setattr(item.transaction, "rekey_to", ELSEWHERE),
                "must not set rekey_to",
            ),
            (
                lambda item: setattr(item.transaction, "close_remainder_to", ELSEWHERE),
                "cannot close out",
            ),
            (
                lambda item: setattr(item, "lsig_args", {"x": b"\x01"}),
                "takes no LogicSig arguments",
            ),
        ],
        ids=["already grouped", "sets its own rekey", "closes the account", "LogicSig arguments"],
    )
    def test_refused_before_the_signer(self, fakes, change, text):
        f = Fixture(fakes)
        group = rotating_group(f.txn)
        change(group.transactions[0])
        with pytest.raises(UnsupportedGroupError, match=text):
            f.client.send_prepared(f.node.client, group, refresh_validity=True)
        assert f.signer.count("/sign/rotating/prepare") == 0


# -----------------------------------------------------------------------------
# A lost answer, and the prepared object
# -----------------------------------------------------------------------------


def test_sign_prepared_rotating_lost_answer_then_identical_retry(fakes):
    f = Fixture(fakes)
    f.signer.sign_errors = [None]  # the first sign gets no answer

    with pytest.raises(SignOutcomeUnknownError) as excinfo:
        f.send(refresh_validity=True)

    unknown = excinfo.value
    assert isinstance(unknown.rotating, PreparedRotating) and unknown.request_id
    # The send stops: no second prepare, no second sign, nothing submitted.
    assert f.signer.count("/sign/rotating/prepare") == 1
    assert f.signer.count("/sign/rotating/sign") == 1 and f.node.submissions() == []

    # The caller's recovery: the same prepared group, signed again.
    signed = f.client.sign_prepared_rotating(unknown.rotating)
    first, second = f.signer.sign_requests
    assert first["transactions"] == second["transactions"]
    assert first["account"] == second["account"]
    assert first["request_id"] != second["request_id"]
    assert f.signer.count("/sign/rotating/prepare") == 1
    result = f.client.submit_signed_group(f.node.client, signed.signed_group)
    assert result.outcome == SEND_OUTCOME_CONFIRMED
    assert result.tx_ids[0] == signed.txid == unknown.rotating.tx_ids[0]


def test_sign_prepared_rotating_refused_retry_makes_no_further_call(fakes):
    f = Fixture(fakes)
    prepared = f.client.prepare_rotating(f.txn)
    f.signer.sign_errors = [STAGE_CHANGED]
    with pytest.raises(SignerError) as excinfo:
        f.client.sign_prepared_rotating(prepared)
    assert excinfo.value.code == ERR_CODE_ROTATING_STAGE_CHANGED
    assert f.signer.count("/sign/rotating/prepare") == 1
    assert f.signer.count("/sign/rotating/sign") == 1 and f.node.submissions() == []


def test_prepared_rotating_cannot_be_changed_by_its_holder(fakes):
    f = Fixture(fakes)
    prepared = f.client.prepare_rotating(f.txn)
    want = list(prepared.transactions)
    # Everything handed out is a copy.
    prepared.transactions[0] = "00"
    prepared.mutations["fees_modified"][0] = 7
    original = prepared.original
    original.amt = 999999
    f.txn.amt = 999999
    with pytest.raises(AttributeError):
        prepared.stage = 9
    with pytest.raises(AttributeError):
        prepared.extra = 1

    f.client.sign_prepared_rotating(prepared, request_id="client-chosen-id")

    request = f.signer.sign_requests[0]
    assert request["transactions"] == want and request["request_id"] == "client-chosen-id"
    assert prepared.original.amt == 5000
    assert prepared.mutations["fees_modified"] == [0]


def test_sign_prepared_rotating_checks_the_binding_again(fakes):
    f = Fixture(fakes)
    prepared = f.client.prepare_rotating(f.txn)
    # Nothing outside the SDK should change a prepared group. If one were
    # changed all the same, neither simulation nor signing may use it.
    altered = copy.deepcopy(f.txn)
    altered.amt = 999999
    prepared._original = bytes.fromhex(signer_module.encode_transaction(altered)[0])

    with pytest.raises(SignerError, match="verify prepared rotating group"):
        f.client.sign_prepared_rotating(prepared)
    with pytest.raises(SignerError, match="verify prepared rotating group"):
        f.client.simulate_prepared_rotating(f.node.client, prepared)
    assert f.signer.count("/sign/rotating/sign") == 0 and f.node.simulations() == []


class TestAnswerClassification:
    def test_an_unreadable_answer_is_an_unknown_outcome(self, fakes):
        f = Fixture(fakes)
        prepared = f.client.prepare_rotating(f.txn)

        def app(method, path, body):
            if path == "/sign/rotating/sign":
                return truncated(b'{"signed": ["ab')
            return f.signer.app(method, path, body)

        truncating = fakes(_Fake(app))
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            signer_client(truncating.http.url).sign_prepared_rotating(prepared)
        assert excinfo.value.rotating is prepared

    def test_a_dropped_answer_is_an_unknown_outcome_and_cancels(self, fakes):
        f = Fixture(fakes)
        prepared = f.client.prepare_rotating(f.txn)
        f.signer.sign_errors = [None]
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            f.client.sign_prepared_rotating(prepared, request_id="app-id-1")
        assert excinfo.value.request_id == "app-id-1"
        assert f.signer.count("/sign/cancel") == 1

    def test_an_unauthenticated_connection_is_an_authentication_error(self, fakes):
        f = Fixture(fakes)
        f.signer.error_status = 401
        f.signer.prepare_errors = [refusal(ERR_CODE_UNAUTHORIZED, "no")]
        with pytest.raises(AuthenticationError):
            f.client.prepare_rotating(f.txn)

    def test_a_failed_prepare_exchange_is_a_plain_failure(self, fakes):
        # Preparing releases nothing, so its lost answer is not an unknown
        # sign outcome.
        f = Fixture(fakes)
        f.signer.prepare_errors = [None]
        with pytest.raises(SignerUnavailableError) as excinfo:
            f.client.prepare_rotating(f.txn)
        assert not isinstance(excinfo.value, SignOutcomeUnknownError)

        # In a send it ends the send, as a plain failure, without a retry.
        f.signer.prepare_errors = [None]
        with pytest.raises(SignerUnavailableError) as excinfo:
            f.send()
        assert not isinstance(excinfo.value, SignOutcomeUnknownError)
        assert f.signer.count("/sign/rotating/prepare") == 2
        assert f.signer.count("/sign/rotating/sign") == 0


def test_an_interrupt_while_approval_is_pending_cancels_it_and_propagates(fakes):
    # A Ctrl-C still stops the program; the pending approval is canceled
    # first, as on a timeout.
    f = Fixture(fakes)
    prepared = f.client.prepare_rotating(f.txn)
    real_post = f.client.session.post
    cancels = []

    def post(url, **kwargs):
        if url.endswith("/sign/rotating/sign"):
            raise KeyboardInterrupt
        if url.endswith("/sign/cancel"):
            cancels.append(kwargs["json"]["request_id"])
        return real_post(url, **kwargs)

    f.client.session.post = post
    with pytest.raises(KeyboardInterrupt) as excinfo:
        f.client.sign_prepared_rotating(prepared, request_id="app-id-2")
    assert cancels == ["app-id-2"]
    # It carries what a lost answer carries: the request and the prepared
    # group, whose identical re-sign is the recovery.
    assert excinfo.value.aplane_request_id == "app-id-2"
    assert excinfo.value.aplane_rotating is prepared
    if hasattr(excinfo.value, "add_note"):
        assert any("aplane_rotating" in note for note in excinfo.value.__notes__)


def test_an_interrupt_during_a_rotating_send_carries_the_prepared_group(fakes):
    f = Fixture(fakes)
    real_post = f.client.session.post
    interrupted = []

    def post(url, **kwargs):
        if url.endswith("/sign/rotating/sign") and not interrupted:
            interrupted.append(kwargs["json"]["request_id"])
            raise KeyboardInterrupt
        return real_post(url, **kwargs)

    f.client.session.post = post
    with pytest.raises(KeyboardInterrupt) as excinfo:
        f.send()
    prepared = excinfo.value.aplane_rotating
    assert isinstance(prepared, PreparedRotating)
    assert excinfo.value.aplane_request_id == interrupted[0]
    assert f.signer.count("/sign/rotating/prepare") == 1 and f.node.submissions() == []

    # The recovery: the same prepared group signed again, never a new spend.
    signed = f.client.sign_prepared_rotating(prepared)
    f.client.submit_signed_group(f.node.client, signed.signed_group)
    assert f.signer.count("/sign/rotating/prepare") == 1
    assert signed.txid == prepared.tx_ids[0]


@pytest.mark.parametrize("method", ["simulate_transactions", "send_raw_transaction"])
def test_an_interrupt_around_the_rotating_sign_carries_the_prepared_group(fakes, method):
    f = Fixture(fakes)

    class Interrupting:
        def __getattr__(self, name):
            if name == method:

                def interrupt(*args, **kwargs):
                    raise KeyboardInterrupt

                return interrupt
            return getattr(f.node.client, name)

    with pytest.raises(KeyboardInterrupt) as excinfo:
        f.client.send_prepared(Interrupting(), rotating_group(f.txn))
    assert isinstance(excinfo.value.aplane_rotating, PreparedRotating)
    if method == "send_raw_transaction":
        assert excinfo.value.aplane_tx_ids == excinfo.value.aplane_rotating.tx_ids


def test_a_fault_in_the_checks_is_not_reported_as_a_refusal(fakes, monkeypatch):
    # Only the checks' own refusals are refusals. A fault inside them is an
    # SDK defect and, before anything is signed, surfaces as what it is.
    f = Fixture(fakes)
    prepared = f.client.prepare_rotating(f.txn)

    def fault(*args, **kwargs):
        raise TypeError("a defect in the checks")

    monkeypatch.setattr(signer_module, "_validate_group_mutations", fault)
    with pytest.raises(TypeError, match="a defect"):
        f.client.prepare_rotating(f.txn)
    with pytest.raises(TypeError, match="a defect"):
        f.client.simulate_prepared_rotating(f.node.client, prepared)
    with pytest.raises(TypeError, match="a defect"):
        f.client.sign_prepared_rotating(prepared)
    with pytest.raises(TypeError, match="a defect"):
        f.send()
    assert f.signer.count("/sign/rotating/sign") == 0


def _assert_unknown_after_a_fault(error, request_id, prepared):
    assert isinstance(error, SignOutcomeUnknownError)
    assert error.request_id == request_id
    assert error.rotating is prepared
    assert isinstance(error.__cause__, TypeError)
    assert "the check itself failed with TypeError" in str(error)


def test_a_fault_in_checking_the_signed_group_is_an_unknown_outcome(fakes, monkeypatch):
    # The signer answered 200, so the stage has signed. A fault in checking
    # the answer is not a refusal, and does not escape bare: it is an unknown
    # outcome that names the request and holds the prepared group, whose
    # identical re-sign is the recovery.
    f = Fixture(fakes)
    prepared = f.client.prepare_rotating(f.txn)

    def fault(*args, **kwargs):
        raise TypeError("a defect in the checks")

    monkeypatch.setattr(signer_module, "_sign_canonical_dummy", fault)
    with pytest.raises(SignerError) as excinfo:
        f.client.sign_prepared_rotating(prepared, request_id="app-id-3")
    _assert_unknown_after_a_fault(excinfo.value, "app-id-3", prepared)
    assert f.signer.count("/sign/rotating/sign") == 1

    # The rotating send reports it the same way, and submits nothing.
    with pytest.raises(SignerError) as excinfo:
        f.send()
    sent = f.signer.sign_requests[-1]
    _assert_unknown_after_a_fault(excinfo.value, sent["request_id"], excinfo.value.rotating)
    assert isinstance(excinfo.value.rotating, PreparedRotating)
    assert excinfo.value.rotating.transactions == sent["transactions"]
    assert f.signer.count("/sign/rotating/sign") == 2 and f.node.submissions() == []


def test_a_fault_in_describing_the_signed_group_is_an_unknown_outcome(fakes, monkeypatch):
    # After the signed group has been checked and before it is submitted.
    f = Fixture(fakes)

    def fault(*args, **kwargs):
        raise TypeError("a defect in the checks")

    monkeypatch.setattr(signer_module, "_decode_executable_signed_group", fault)
    with pytest.raises(SignerError) as excinfo:
        f.send()
    sent = f.signer.sign_requests[-1]
    _assert_unknown_after_a_fault(excinfo.value, sent["request_id"], excinfo.value.rotating)
    # The prepared group is the one that was sent to be signed.
    assert isinstance(excinfo.value.rotating, PreparedRotating)
    assert excinfo.value.rotating.transactions == sent["transactions"]
    assert f.signer.count("/sign/rotating/sign") == 1 and f.node.submissions() == []


class _Fake:
    def __init__(self, app):
        self.http = HTTPFake(app)


# -----------------------------------------------------------------------------
# Prepare helpers and auth-address resolution
# -----------------------------------------------------------------------------


STAGE = program_address(ROTATING_TEST_PROGRAM)


def _helper_cases(sender, other):
    """Each prepare_* helper that fetches suggested parameters, with the
    accounts its checks need."""
    holding = {"assets": [{"asset-id": 7, "amount": 5}]}
    return [
        ("payment", lambda c, a: c.prepare_payment(a, sender=sender, receiver=other, amount=1), {}),
        (
            "asa transfer",
            lambda c, a: c.prepare_asa_transfer(
                a, sender=sender, receiver=other, asset_id=7, amount=1
            ),
            {sender: holding, other: holding},
        ),
        ("asa opt-in", lambda c, a: c.prepare_asa_opt_in(a, sender=sender, asset_id=8), {}),
        (
            "asa opt-out",
            lambda c, a: c.prepare_asa_opt_out(a, sender=sender, asset_id=7, close_to=other),
            {sender: holding, other: holding},
        ),
        (
            "account close",
            lambda c, a: c.prepare_account_close(a, sender=sender, close_to=other),
            {},
        ),
        ("rekey", lambda c, a: c.prepare_rekey(a, sender=sender, rekey_to=other), {}),
        ("keyreg", lambda c, a: c.prepare_keyreg(a, sender=sender, mode="offline"), {}),
        ("app call", lambda c, a: c.prepare_app_call(a, sender=sender, app_id=5), {}),
        (
            "app deploy",
            lambda c, a: c.prepare_app_deploy(
                a, sender=sender, approval_program=b"\x06\x81\x01", clear_program=b"\x06\x81\x01"
            ),
            {},
        ),
    ]


ROTATING_SENDER = fake_signer.account(41)
ORDINARY_SENDER = fake_signer.account(43)
HELPER_NAMES = [case[0] for case in _helper_cases(ROTATING_SENDER, ORDINARY_SENDER)]


def _helper_keys():
    return [
        key(ROTATING_SENDER, SIGNING_FLOW_ROTATING1, key_type=ROTATING_KEY_TYPE),
        key(ORDINARY_SENDER),
    ]


@pytest.mark.parametrize("index", range(len(HELPER_NAMES)), ids=HELPER_NAMES)
def test_every_prepare_helper_builds_a_rotating_window(fakes, index):
    _, helper, accounts = _helper_cases(ROTATING_SENDER, ORDINARY_SENDER)[index]
    signer = fakes(SendSigner(_helper_keys()))
    # The account has rotated: the chain names a stage address the signer
    # does not list.
    node = fakes(FakeNode(round=500, accounts=accounts, auth_addrs={ROTATING_SENDER: STAGE}))
    client = signer_client(signer.http.url)

    prepared = helper(client, node.client)

    txn = prepared.transaction
    assert prepared.auth_address == ROTATING_SENDER
    assert (txn.first_valid_round, txn.last_valid_round) == (
        500,
        500 + ROTATING_MAX_VALIDITY_WINDOW,
    )
    _check_rotating_window(txn)


@pytest.mark.parametrize("index", range(len(HELPER_NAMES)), ids=HELPER_NAMES)
def test_every_prepare_helper_keeps_an_ordinary_senders_window(fakes, index):
    _, helper, accounts = _helper_cases(ORDINARY_SENDER, ROTATING_SENDER)[index]
    signer = fakes(SendSigner(_helper_keys()))
    node = fakes(FakeNode(round=500, accounts=accounts))
    client = signer_client(signer.http.url)

    if HELPER_NAMES[index] == "rekey":
        # A rotating account is never a rekey target; rekey to the sender's
        # own address instead.
        prepared = client.prepare_rekey(
            node.client, sender=ORDINARY_SENDER, rekey_to=ORDINARY_SENDER
        )
    else:
        prepared = helper(client, node.client)

    txn = prepared.transaction
    assert txn.last_valid_round - txn.first_valid_round == 1000


def test_prepare_helpers_and_resolution_for_a_rotated_account(fakes):
    signer = fakes(SendSigner(_helper_keys()))
    node = fakes(FakeNode(round=500, auth_addrs={ROTATING_SENDER: STAGE}))
    client = signer_client(signer.http.url)

    resolved = client.resolve_auth_address(ROTATING_SENDER, lambda _: STAGE)
    assert resolved.auth_address == ROTATING_SENDER and not resolved.is_rekeyed
    assert resolved.chain_auth_address == STAGE
    assert resolved.key_info.signing_flow == SIGNING_FLOW_ROTATING1

    at_stage_0 = client.resolve_auth_address(ROTATING_SENDER, lambda _: "")
    assert at_stage_0.auth_address == ROTATING_SENDER and at_stage_0.chain_auth_address == ""


def test_the_window_fit_does_not_report_signer_failures(fakes):
    # The fit reads the inventory resolution just refreshed; it asks the
    # signer nothing, so a locked or unreachable signer is reported by the
    # helper's key resolution, in its usual form.
    client = signer_client("http://127.0.0.1:9")

    def refuse(*args, **kwargs):
        raise AssertionError("the window fit asked the signer")

    client.session.get = refuse
    client.session.post = refuse
    txn = rotating_payment(ROTATING_SENDER, 500, 1500)
    client._fit_rotating_window(txn, ROTATING_SENDER)
    assert txn.last_valid_round == 1500

    unavailable = fakes(_Fake(lambda method, path, body: reply(503, {"error": "locked"})))
    node = fakes(FakeNode())
    with pytest.raises(SignerUnavailableError, match="locked"):
        signer_client(unavailable.http.url).prepare_payment(
            node.client, sender=ROTATING_SENDER, receiver=ORDINARY_SENDER, amount=1
        )


def test_resolve_auth_address_reports_the_chain_authorizer(fakes):
    sender, holder = fake_signer.account(41), fake_signer.account(45)
    signer = fakes(SendSigner([key(sender), key(holder)]))
    client = signer_client(signer.http.url)

    rekeyed = client.resolve_auth_address(sender, lambda _: holder)
    assert rekeyed.chain_auth_address == holder and rekeyed.auth_address == holder
    assert rekeyed.is_rekeyed

    own = client.resolve_auth_address(sender, lambda _: "")
    assert own.chain_auth_address == "" and own.auth_address == sender and not own.is_rekeyed


@pytest.mark.usefixtures("quick_backoff")
def test_send_payment_may_rebuild_a_rotating_window(fakes):
    signer = RotatingSigner(fake_signer.account(41))
    f = Fixture(fakes, signer, FakeNode(auth_addrs={signer.account: STAGE}))
    f.signer.sign_errors = [refusal(ERR_CODE_ROTATING_WINDOW_NOT_CURRENT, "too few rounds remain")]

    # send_payment built the transaction, so it may rebuild its rounds with no
    # option set; and the helper gave a rotated account a window it can use.
    result = f.client.send_payment(
        f.node.client, sender=signer.account, receiver=fake_signer.test_address(42), amount=5000
    )

    assert result.rotating is not None and result.rotating.attempts == 2
    sent = f.signer.prepare_seen[0]
    assert sent.last_valid_round - sent.first_valid_round == ROTATING_MAX_VALIDITY_WINDOW


def test_sign_request_carries_app_call_info(fakes):
    f = Fixture(fakes)
    group = rotating_group(f.txn)
    group.transactions[0].app_call_info = {"mode": "raw"}
    f.client.send_prepared(f.node.client, group)
    assert f.signer.sign_requests[0]["app_call_info"] == {"mode": "raw"}
    # The prepare request carries the transaction only.
    assert json.dumps(f.signer.sign_requests[0]["transactions"])
