# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Prepare-helper argument checks, preflight fees, and the smaller client checks."""

import base64
import dataclasses
from unittest.mock import MagicMock, patch

import pytest
from algosdk import abi, transaction

import aplanesdk
from aplanesdk import PreparedGroup, PreparedTransaction, SignerClient, SignerError
from aplanesdk.signer import (
    KeyInfo,
    PreparedCheck,
    _validate_group_algo_balance,
    KeyNotFoundError,
    _parse_lsig_resource_usage,
    _encode_abi_method_args,
    _require_uint,
    _strict_base64,
    send_raw_transaction,
    load_config,
    sign_prepared_cosigned_group,
)
from tests import fake_signer
from tests.test_client import make_client, mock_response, sdk_test_address


class Algod:
    """An algod as a real network answers: a zero per-byte fee and a 1000 minimum."""

    def __init__(self, accounts):
        self.accounts = accounts

    def suggested_params(self):
        return transaction.SuggestedParams(
            0, 1, 100, base64.b64encode(bytes(32)).decode(), gen="testnet-v1", min_fee=1000
        )

    def account_info(self, address):
        return self.accounts[address]


def _status():
    return mock_response(
        200,
        {
            "state": "unlocked",
            "signer_locked": False,
            "ready_for_signing": True,
            "key_count": 1,
            "keyset_revision": 1,
        },
    )


def _keys(address):
    return mock_response(200, {"count": 1, "keys": [{"address": address, "key_type": "ed25519"}]})


def _signer(client, address):
    return patch.object(client.session, "get", side_effect=[_status(), _keys(address), _status()])


SENDER = sdk_test_address(1)
RECEIVER = sdk_test_address(2)
BAD_INTEGERS = [123.9, 123.0, "123", True, -1, 2**64]


@pytest.mark.parametrize("bad", BAD_INTEGERS + [0])
def test_app_id_must_be_a_positive_integer(bad):
    client = make_client()
    algod = MagicMock()
    with pytest.raises(ValueError, match="app_id must"):
        client.prepare_app_call(algod, sender=SENDER, app_id=bad)
    with pytest.raises(ValueError, match="app_id must"):
        client.prepare_abi_app_call(algod, sender=SENDER, app_id=bad, method_signature="do()void")
    algod.suggested_params.assert_not_called()


@pytest.mark.parametrize("bad", BAD_INTEGERS)
def test_foreign_references_must_be_integers(bad):
    client = make_client()
    with pytest.raises(ValueError, match=r"foreign_apps\[0\] must"):
        client.prepare_app_call(MagicMock(), sender=SENDER, app_id=7, foreign_apps=[bad])
    with pytest.raises(ValueError, match=r"foreign_assets\[1\] must"):
        client.prepare_app_call(MagicMock(), sender=SENDER, app_id=7, foreign_assets=[5, bad])


@pytest.mark.parametrize("bad", BAD_INTEGERS + [0])
def test_asset_id_must_be_a_positive_integer(bad):
    client = make_client()
    algod = MagicMock()
    with pytest.raises(ValueError, match="asset_id must"):
        client.prepare_asa_transfer(algod, sender=SENDER, receiver=RECEIVER, asset_id=bad, amount=1)
    with pytest.raises(ValueError, match="asset_id must"):
        client.prepare_asa_opt_in(algod, sender=SENDER, asset_id=bad)
    with pytest.raises(ValueError, match="asset_id must"):
        client.prepare_asa_opt_out(algod, sender=SENDER, asset_id=bad, close_to=RECEIVER)
    algod.suggested_params.assert_not_called()


@pytest.mark.parametrize("bad", BAD_INTEGERS)
def test_amounts_and_fees_must_be_integers(bad):
    client = make_client()
    algod = Algod({SENDER: {"amount": 2_000_000, "min-balance": 100_000}})
    with pytest.raises(ValueError, match="amount must"):
        client.prepare_payment(algod, sender=SENDER, receiver=RECEIVER, amount=bad)
    with pytest.raises(ValueError, match="amount must"):
        client.prepare_asa_transfer(algod, sender=SENDER, receiver=RECEIVER, asset_id=5, amount=bad)
    with pytest.raises(ValueError, match="fee must"):
        client.prepare_payment(algod, sender=SENDER, receiver=RECEIVER, amount=1, fee=bad)


def test_valid_integers_are_accepted():
    client = make_client()
    algod = Algod({SENDER: {"amount": 2_000_000, "min-balance": 100_000}})
    with _signer(client, SENDER):
        prepared = client.prepare_app_call(
            algod, sender=SENDER, app_id=123, foreign_apps=[7], foreign_assets=[9]
        )
    assert prepared.transaction.index == 123
    with _signer(client, SENDER):
        assert (
            client.prepare_payment(
                algod, sender=SENDER, receiver=RECEIVER, amount=0, fee=0
            ).transaction.fee
            == 0
        )


# The opt-in and close preflights compare the balance with the fee the built
# transaction pays. The suggested fee is per byte, zero on a real network, so
# comparing against it checked nothing.


def test_opt_in_preflight_uses_the_transaction_fee():
    client = make_client()
    with _signer(client, SENDER):
        prepared = client.prepare_asa_opt_in(
            Algod({SENDER: {"amount": 1000, "min-balance": 0}}), sender=SENDER, asset_id=1001
        )
    assert prepared.transaction.fee == 1000
    assert prepared.checks[0].data["fee"] == 1000

    with pytest.raises(
        SignerError, match="insufficient funds for opt-in fee: balance 999, fee 1000"
    ):
        client.prepare_asa_opt_in(
            Algod({SENDER: {"amount": 999, "min-balance": 0}}), sender=SENDER, asset_id=1001
        )
    # An explicit flat fee is the fee that is checked.
    with pytest.raises(SignerError, match="balance 4999, fee 5000"):
        client.prepare_asa_opt_in(
            Algod({SENDER: {"amount": 4999, "min-balance": 0}}),
            sender=SENDER,
            asset_id=1001,
            fee=5000,
        )
    # No minimum-balance rule was added: a balance that covers the fee passes.
    client = make_client()
    with _signer(client, SENDER):
        client.prepare_asa_opt_in(
            Algod({SENDER: {"amount": 1000, "min-balance": 100_000}}),
            sender=SENDER,
            asset_id=1001,
        )


def test_account_close_preflight_uses_the_transaction_fee():
    client = make_client()
    with _signer(client, SENDER):
        prepared = client.prepare_account_close(
            Algod({SENDER: {"amount": 1000, "min-balance": 0}}), sender=SENDER, close_to=RECEIVER
        )
    assert prepared.checks[0].data["fee"] == 1000
    with pytest.raises(
        SignerError, match="insufficient funds for close fee: balance 999, fee 1000"
    ):
        client.prepare_account_close(
            Algod({SENDER: {"amount": 999, "min-balance": 0}}), sender=SENDER, close_to=RECEIVER
        )


def _sweep_accounts(balance, other_balance=2_000_000):
    return {
        SENDER: {
            "amount": balance,
            "min-balance": 100_000,
            "assets": [{"asset-id": 1001, "amount": 25}],
        },
        RECEIVER: {
            "amount": other_balance,
            "min-balance": 100_000,
            "assets": [{"asset-id": 1001, "amount": 25}],
        },
    }


def _keys_for(*addresses):
    return mock_response(
        200,
        {
            "count": len(addresses),
            "keys": [{"address": address, "key_type": "ed25519"} for address in addresses],
        },
    )


def _signer_for_both(client):
    return patch.object(
        client.session,
        "get",
        side_effect=lambda url, **_: (
            _status() if url.endswith("/status") else _keys_for(SENDER, RECEIVER)
        ),
    )


def test_group_checks_every_sender_against_everything_it_pays():
    transfer = {"sender": SENDER, "receiver": RECEIVER, "asset_id": 1001, "amount": 5}
    payment = {"sender": SENDER, "receiver": RECEIVER, "amount": 10_000}

    def sweep(balance, *, asa_transfers, payments, other_balance=2_000_000):
        client = make_client()
        with _signer_for_both(client):
            return client.prepare_sweep_group(
                Algod(_sweep_accounts(balance, other_balance)),
                asa_transfers=asa_transfers,
                payments=payments,
            )

    # Available is the balance less the 100,000 minimum. The sender pays
    # 10,000 plus two 1000 fees: its own and the ASA transfer's.
    group = sweep(112_000, asa_transfers=[transfer], payments=[payment])
    assert group.checks[-1].name == "group_algo_balance"
    with pytest.raises(SignerError, match="available 11999, required 12000"):
        sweep(111_999, asa_transfers=[transfer], payments=[payment])

    # A sweep with no payments still checks the fees its sender pays.
    sweep(102_000, asa_transfers=[transfer, transfer], payments=[])
    with pytest.raises(SignerError, match="available 1999, required 2000"):
        sweep(101_999, asa_transfers=[transfer, transfer], payments=[])

    # A sender with only asset transfers is checked beside one that pays.
    other_transfer = {"sender": RECEIVER, "receiver": SENDER, "asset_id": 1001, "amount": 1}
    both = [other_transfer, other_transfer]
    sweep(2_000_000, asa_transfers=both, payments=[payment], other_balance=102_000)
    with pytest.raises(SignerError, match=f"group insufficient funds for {RECEIVER}"):
        sweep(2_000_000, asa_transfers=both, payments=[payment], other_balance=101_999)

    # The ASA transfer group helper makes the same check.
    client = make_client()
    with _signer_for_both(client):
        with pytest.raises(SignerError, match="available 1999, required 2000"):
            client.prepare_asa_transfer_group(Algod(_sweep_accounts(101_999)), [transfer, transfer])


def test_asa_transfer_checks_its_fee_against_spendable_algo():
    """An asset transfer's own check compares its fee with the sender's spendable ALGO.

    A single transfer and a group of one therefore agree.
    """
    transfer = {"sender": SENDER, "receiver": RECEIVER, "asset_id": 1001, "amount": 5}

    def single(balance):
        client = make_client()
        with _signer_for_both(client):
            return client.prepare_asa_transfer(Algod(_sweep_accounts(balance)), **transfer)

    prepared = single(2_000_000)
    # The two checks, and the data all three SDKs record.
    assert [check.name for check in prepared.checks] == ["asa_transfer", "spendable_algo"]
    assert prepared.checks[0].data == {"asset_id": 1001, "amount": 5, "balance": 25, "fee": 1000}
    assert prepared.checks[1].data == {"available": 1_900_000}

    # Exactly the fee above the 100,000 minimum is enough.
    single(101_000)
    client = make_client()
    with _signer_for_both(client):
        client.prepare_asa_transfer_group(Algod(_sweep_accounts(101_000)), [transfer])

    # One microAlgo short: the single helper and both group helpers refuse
    # with the transfer's own message.
    message = "insufficient funds for asset transfer fee: available 999, fee 1000"
    with pytest.raises(SignerError, match=message):
        single(100_999)
    client = make_client()
    with _signer_for_both(client):
        with pytest.raises(SignerError, match=message):
            client.prepare_asa_transfer_group(Algod(_sweep_accounts(100_999)), [transfer])
        with pytest.raises(SignerError, match=message):
            client.prepare_sweep_group(Algod(_sweep_accounts(100_999)), asa_transfers=[transfer])
    # An account below its minimum has nothing to spend, not a negative amount.
    with pytest.raises(SignerError, match="available 0, fee 1000"):
        single(50_000)


def test_group_reads_spendable_algo_from_its_own_check():
    """The group check's balance comes from the spendable_algo check and nowhere else.

    A position without it, or with a value that is not an integer, is refused,
    not passed, even beside a position of the same sender that has one.
    """

    def position(checks):
        return PreparedTransaction(
            transaction=fake_signer.payment(amount=1),
            checks=checks,
        )

    def spendable(data):
        return [PreparedCheck(name="spendable_algo", status="ok", data=data)]

    good = position(spendable({"available": 5000}))
    assert _validate_group_algo_balance([good, good]).data == {"sender_count": 1}
    for checks, message in (
        ([], "no ALGO balance on record"),
        (
            [PreparedCheck(name="payment_balance", status="ok", data={"available": 5000})],
            "no ALGO balance on record",
        ),
        (spendable({"balance": 5000}), "has no available amount"),
        (spendable(None), "has no available amount"),
        (spendable({"available": None}), "available amount must be an integer, not NoneType"),
        (spendable({"available": "5000"}), "available amount must be an integer, not str"),
        (spendable({"available": 5000.0}), "available amount must be an integer, not float"),
        (spendable({"available": True}), "available amount must be an integer, not bool"),
        (spendable({"available": -1}), "available amount must not be negative"),
    ):
        with pytest.raises(SignerError, match=f"group transaction 1, sender .*: .*{message}"):
            _validate_group_algo_balance([good, position(checks)])


def test_lsig_resource_numbers_are_not_coerced():
    usage = _parse_lsig_resource_usage(
        {"program_bytes": 512, "argument_bytes": 32, "max_opcode_cost": 20000}
    )
    assert (usage.program_bytes, usage.argument_bytes, usage.max_opcode_cost) == (512, 32, 20000)
    # A missing field keeps its default, and a key with no resources has none.
    assert _parse_lsig_resource_usage({"program_bytes": 512}).argument_bytes == 0
    assert _parse_lsig_resource_usage(None) is None
    name = "signer-reported LogicSig resources program_bytes"
    for bad in (512.9, 512.0, "512", True, None):
        with pytest.raises(SignerError, match=f"{name} must be an integer, not "):
            _parse_lsig_resource_usage({"program_bytes": bad})
    # A negative number is an integer, and is refused as what it is.
    with pytest.raises(SignerError, match=f"{name} must not be negative"):
        _parse_lsig_resource_usage({"program_bytes": -1})

    client = make_client()
    keys = {
        "count": 1,
        "keys": [
            {
                "address": SENDER,
                "key_type": "aplane.falcon1024.v1",
                "logic_sig_resources": {"default": {"program_bytes": "512"}},
            }
        ],
    }
    with patch.object(client.session, "get", return_value=mock_response(200, keys)):
        with pytest.raises(SignerError, match="program_bytes is not an unsigned 64-bit integer"):
            client.list_keys(refresh=True)


def test_one_integer_check_words_each_refusal():
    assert _require_uint(5, "x") == 5
    for bad, message in (
        (1.5, "x must be an integer, not float"),
        ("1", "x must be an integer, not str"),
        (True, "x must be an integer, not bool"),
        (-1, "x must not be negative"),
        (2**64, "x must be below 2\\*\\*64"),
    ):
        with pytest.raises(ValueError, match=message):
            _require_uint(bad, "x")
        with pytest.raises(SignerError, match=message):
            _require_uint(bad, "x", error=SignerError)
    with pytest.raises(ValueError, match="x must be greater than zero"):
        _require_uint(0, "x", positive=True)


# ABI reference arguments (application, asset) are IDs too, and go through
# the same check before anything is encoded.


@pytest.mark.parametrize("bad", [123.9, 123.0, "123", True, -1, 0, 2**64])
def test_abi_reference_arguments_must_be_integers(bad):
    client = make_client()
    algod = MagicMock()
    with pytest.raises(ValueError, match="asset argument must"):
        client.prepare_abi_app_call(
            algod, sender=SENDER, app_id=7, method_signature="f(asset)void", args=[bad]
        )
    with pytest.raises(ValueError, match="application argument must"):
        client.prepare_abi_app_call(
            algod, sender=SENDER, app_id=7, method_signature="f(application)void", args=[bad]
        )
    algod.suggested_params.assert_not_called()


def test_abi_reference_arguments_accept_integers_and_addresses():
    client = make_client()
    algod = Algod({SENDER: {"amount": 2_000_000, "min-balance": 100_000}})
    with _signer(client, SENDER):
        prepared = client.prepare_abi_app_call(
            algod,
            sender=SENDER,
            app_id=7,
            method_signature="f(asset,application,account)void",
            args=[1001, 9, RECEIVER],
        )
    assert prepared.transaction.foreign_assets == [1001]
    assert prepared.transaction.foreign_apps == [9]
    assert prepared.transaction.accounts == [RECEIVER]
    with pytest.raises(Exception):
        client.prepare_abi_app_call(
            MagicMock(), sender=SENDER, app_id=7, method_signature="f(account)void", args=[123]
        )


@pytest.mark.parametrize("bad", [123.9, "123", True, -1, 2**64])
def test_every_prepare_helper_checks_its_ids_counts_and_indexes(bad):
    client = make_client()
    algod = MagicMock()
    deploy = dict(sender=SENDER, approval_program=b"\x06\x81\x01", clear_program=b"\x06\x81\x01")
    with pytest.raises(ValueError, match="extra_pages must"):
        client.prepare_app_deploy(algod, extra_pages=bad, **deploy)
    with pytest.raises(ValueError, match=r"foreign_apps\[0\] must"):
        client.prepare_app_deploy(algod, foreign_apps=[bad], **deploy)
    with pytest.raises(ValueError, match=r"foreign_assets\[0\] must"):
        client.prepare_app_deploy(algod, foreign_assets=[bad], **deploy)
    for prepare, extra in (
        (client.prepare_app_deploy, deploy),
        (client.prepare_app_call, dict(sender=SENDER, app_id=7)),
        (
            client.prepare_abi_app_call,
            dict(sender=SENDER, app_id=7, method_signature="f()void"),
        ),
    ):
        with pytest.raises(ValueError, match=r"boxes\[0\] app index must"):
            prepare(algod, boxes=[(bad, b"name")], **extra)
    with pytest.raises(ValueError, match=r"boxes\[0\] must be an \(app index, name\) pair"):
        client.prepare_app_call(algod, sender=SENDER, app_id=7, boxes=[7])
    online = dict(
        sender=SENDER,
        mode="online",
        votekey="k",
        selkey="k",
        sprfkey="k",
        votefst=1,
        votelst=10,
        votekd=3,
    )
    for field in ("votefst", "votelst", "votekd"):
        with pytest.raises(ValueError, match=f"{field} must"):
            client.prepare_keyreg(algod, **{**online, field: bad})
    algod.suggested_params.assert_not_called()


PROGRAM = b"\x06\x81\x01"
DEPLOY = dict(sender=SENDER, approval_program=PROGRAM, clear_program=PROGRAM)


@pytest.mark.parametrize("bad", [123.9, "123", True, -1, 2**64])
def test_state_schema_counts_must_be_integers(bad):
    """A caller-built StateSchema is checked member by member before algod is asked."""
    client = make_client()
    algod = MagicMock()
    for prepare, extra in (
        (client.prepare_app_deploy, DEPLOY),
        (client.prepare_app_call, dict(sender=SENDER, app_id=7)),
    ):
        for name in ("global_schema", "local_schema"):
            with pytest.raises(ValueError, match=f"{name}.num_uints must"):
                prepare(algod, **{name: transaction.StateSchema(bad, 0)}, **extra)
            with pytest.raises(ValueError, match=f"{name}.num_byte_slices must"):
                prepare(algod, **{name: transaction.StateSchema(0, bad)}, **extra)
    with pytest.raises(ValueError, match="global_schema must be a StateSchema, not tuple"):
        client.prepare_app_deploy(algod, global_schema=(1, 1), **DEPLOY)
    algod.suggested_params.assert_not_called()


@pytest.mark.parametrize("bad", [1.9, 1.0, "1", True, -1, 6])
def test_on_complete_must_be_one_of_the_on_completion_values(bad):
    client = make_client()
    algod = MagicMock()
    with pytest.raises(ValueError, match="on_complete"):
        client.prepare_app_call(algod, sender=SENDER, app_id=7, on_complete=bad)
    algod.suggested_params.assert_not_called()


@pytest.mark.parametrize(
    "signature,args,message",
    [
        ("f(uint64)void", [True], "ABI argument 0 must be an integer, not bool"),
        ("f(byte)void", [False], "ABI argument 0 must be an integer, not bool"),
        ("f(bool,(uint8,uint16))void", [True, (1, True)], r"ABI argument 1\[1\] must"),
        ("f(uint64[])void", [[1, True]], r"ABI argument 0\[1\] must"),
    ],
)
def test_abi_integer_arguments_refuse_bools(signature, args, message):
    client = make_client()
    algod = MagicMock()
    with pytest.raises(ValueError, match=message):
        client.prepare_abi_app_call(
            algod, sender=SENDER, app_id=7, method_signature=signature, args=args
        )
    algod.suggested_params.assert_not_called()


class Whole:
    """An integral type that is not int: it only defines __index__."""

    def __init__(self, value):
        self.value = value

    def __index__(self):
        return self.value


def test_any_integral_type_is_an_integer():
    """operator.index decides: an __index__ type is taken and goes on as a plain int."""
    assert _require_uint(Whole(5), "x") == 5
    assert type(_require_uint(Whole(5), "x")) is int
    with pytest.raises(ValueError, match="x must not be negative"):
        _require_uint(Whole(-1), "x")
    with pytest.raises(ValueError, match="x must be below"):
        _require_uint(Whole(2**64), "x")
    with pytest.raises(ValueError, match="x must be greater than zero"):
        _require_uint(Whole(0), "x", positive=True)
    for bad in (True, False, 1.0, "1", b"1", None):
        with pytest.raises(ValueError, match="x must be an integer, not"):
            _require_uint(bad, "x")

    client = make_client()
    algod = Algod({SENDER: {"amount": 5_000_000, "min-balance": 100_000}})
    with _signer(client, SENDER):
        payment = client.prepare_payment(
            algod, sender=SENDER, receiver=RECEIVER, amount=Whole(7), fee=Whole(2000)
        ).transaction
    assert (payment.amt, payment.fee) == (7, 2000)
    assert type(payment.amt) is int and type(payment.fee) is int

    client = make_client()
    with _signer(client, SENDER):
        deployed = client.prepare_app_deploy(
            algod,
            extra_pages=Whole(1),
            global_schema=transaction.StateSchema(Whole(2), Whole(3)),
            foreign_apps=[Whole(9)],
            foreign_assets=[Whole(11)],
            boxes=[(Whole(0), b"a")],
            **DEPLOY,
        ).transaction
    assert deployed.extra_pages == 1 and type(deployed.extra_pages) is int
    assert (deployed.global_schema.num_uints, deployed.global_schema.num_byte_slices) == (2, 3)
    assert deployed.foreign_apps == [9] and type(deployed.foreign_apps[0]) is int
    assert deployed.foreign_assets == [11]
    # The transaction encodes: nothing but plain ints reached it.
    assert deployed.get_txid()

    client = make_client()
    with _signer(client, SENDER):
        call = client.prepare_abi_app_call(
            algod,
            sender=SENDER,
            app_id=Whole(7),
            method_signature="f(asset)void",
            args=[Whole(1001)],
            on_complete=Whole(0),
        ).transaction
    assert call.index == 7 and call.foreign_assets == [1001]
    assert call.on_complete == transaction.OnComplete.NoOpOC
    assert call.get_txid()


def test_none_keeps_meaning_the_default():
    """None is "not set" wherever a parameter took it before the integer checks."""
    client = make_client()
    algod = Algod({SENDER: {"amount": 5_000_000, "min-balance": 100_000}})
    with _signer(client, SENDER):
        deployed = client.prepare_app_deploy(
            algod,
            extra_pages=None,
            global_schema=None,
            local_schema=transaction.StateSchema(),
            foreign_apps=None,
            foreign_assets=None,
            boxes=None,
            fee=None,
            **DEPLOY,
        )
    assert deployed.transaction.extra_pages == 0
    assert deployed.checks[0].data["extra_pages"] == 0
    # An all-zero schema is left out of the transaction.
    assert deployed.transaction.global_schema is None
    assert deployed.transaction.local_schema is None

    client = make_client()
    with _signer(client, SENDER):
        call = client.prepare_app_call(
            algod,
            sender=SENDER,
            app_id=7,
            foreign_apps=None,
            foreign_assets=None,
            boxes=None,
            local_schema=None,
            global_schema=None,
            fee=None,
        ).transaction
    assert call.local_schema is None and call.global_schema is None
    assert call.fee == 1000


def test_box_references_with_integer_indexes_are_accepted():
    client = make_client()
    algod = Algod({SENDER: {"amount": 2_000_000, "min-balance": 100_000}})
    with _signer(client, SENDER):
        prepared = client.prepare_app_call(
            algod, sender=SENDER, app_id=7, foreign_apps=[9], boxes=[(0, b"a"), (9, b"b")]
        )
    assert len(prepared.transaction.boxes) == 2


class _KeysetSigner:
    """A signer whose key list and keyset revision a test sets.

    It counts /keys fetches and refuses any request past the key read.
    """

    def __init__(self, revision, keys):
        self.revision = revision
        self.keys = keys
        self.fetches = 0

    def get(self, url, **_kwargs):
        if url.endswith("/status"):
            return mock_response(json_data={"state": "unlocked", "keyset_revision": self.revision})
        if url.endswith("/keys"):
            self.fetches += 1
            return mock_response(json_data={"count": len(self.keys), "keys": self.keys})
        raise AssertionError(f"unexpected request {url}")


def test_cosigned_group_takes_the_spendable_key_from_the_signer():
    """The key's flow, resources and ceiling come from the signer's record.

    The flow takes the spendable key for the position's auth address from a
    key list refreshed when the signer's keyset revision changes: the lookup
    the prepare helpers make. A prepared transaction carries no key of its own.
    """
    assert "signer_key" not in {field.name for field in dataclasses.fields(PreparedTransaction)}
    txn = fake_signer.payment()
    sender = txn.sender
    # Two rows for one address, the non-spending one last. A second spendable
    # row follows as well: the first one is the one chosen, from the fresh
    # list and from the cache alike.
    signer = _KeysetSigner(
        1,
        [
            {
                "address": sender,
                "key_type": "aplane.witness-falcon1024.v1",
                "is_spending_account": False,
                "signing_flow": "witness8",
            },
            {"address": sender, "key_type": "ed25519", "signing_flow": "cosigner9"},
            {"address": sender, "key_type": "ed25519", "signing_flow": "cosigner11"},
            {
                "address": sender,
                "key_type": "aplane.witness-falcon1024.v1",
                "is_spending_account": False,
                "signing_flow": "witness9",
            },
        ],
    )
    user = make_client()
    user.session = MagicMock()
    user.session.get.side_effect = signer.get
    user.session.post.side_effect = AssertionError("the flow must stop at the key record")
    group = PreparedGroup([PreparedTransaction(transaction=txn, auth_address=sender)])

    def attempt():
        sign_prepared_cosigned_group(user_client=user, prepared_group=group)

    # The spendable row decides the flow, on the fresh read and from the cache.
    for _ in range(2):
        with pytest.raises(ValueError, match="signing flow 'cosigner9'"):
            attempt()
    # An unchanged keyset revision costs no further /keys request.
    assert signer.fetches == 1
    # The prepare helpers select the same row from the same list.
    resolved = user.resolve_auth_address(sender, lambda _address: {})
    assert resolved.key_info.signing_flow == "cosigner9"
    assert signer.fetches == 1

    # The operator changes the key: a new revision, and the next call reads
    # the new record.
    signer.revision = 2
    signer.keys = [{"address": sender, "key_type": "ed25519", "signing_flow": "cosigner10"}]
    with pytest.raises(ValueError, match="signing flow 'cosigner10'"):
        attempt()
    assert signer.fetches == 2

    # Only a non-spending row for the address: there is no key to sign with.
    signer.revision = 3
    signer.keys = [
        {
            "address": sender,
            "key_type": "aplane.witness-falcon1024.v1",
            "is_spending_account": False,
        }
    ]
    with pytest.raises(KeyNotFoundError, match="is not available for signing"):
        attempt()
    # A position with no auth address has nothing to look a key up by.
    with pytest.raises(ValueError, match="auth address is required"):
        sign_prepared_cosigned_group(
            user_client=user, prepared_group=PreparedGroup([PreparedTransaction(transaction=txn)])
        )


def test_config_enforces_networks_allowed(tmp_path):
    (tmp_path / "config.yaml").write_text("network: mainnet\nnetworks_allowed: [testnet]\n")
    with pytest.raises(SignerError, match="network 'mainnet' is not in networks_allowed"):
        load_config(str(tmp_path))
    (tmp_path / "config.yaml").write_text("network: testnet\nnetworks_allowed: [testnet]\n")
    config = load_config(str(tmp_path))
    assert config.is_network_allowed("testnet")
    assert not config.is_network_allowed("mainnet")
    (tmp_path / "config.yaml").write_text("network: testnet\n")
    assert load_config(str(tmp_path)).is_network_allowed("mainnet")


# A networks_allowed that cannot be read must not become an empty list, which
# permits every network, and an entry that is not text is not a network name.
# The Go and TypeScript suites run the same cases.


@pytest.mark.parametrize(
    "value",
    [
        "mainnet",
        "{a: b}",
        "[testnet, [a]]",
        "[testnet, Mainnet]",
        "[testnet, 1.5]",
        "[testnet, -x]",
        "[testnet, 1]",
        "[testnet, true]",
        "[testnet, null]",
        "[testnet, ~]",
    ],
)
def test_config_refuses_a_malformed_networks_allowed(tmp_path, value):
    (tmp_path / "config.yaml").write_text(f"network: testnet\nnetworks_allowed: {value}\n")
    with pytest.raises(SignerError, match="networks_allowed"):
        load_config(str(tmp_path))


@pytest.mark.parametrize(
    ("value", "allowed"),
    [
        ("[]", []),
        ("", []),
        # A name made of digits, or spelled like a boolean, is fine once quoted.
        ('[testnet, "1"]', ["testnet", "1"]),
        ('[testnet, "true"]', ["testnet", "true"]),
        ("[testnet, my_net-2]", ["testnet", "my_net-2"]),
    ],
)
def test_config_reads_a_well_formed_networks_allowed(tmp_path, value, allowed):
    (tmp_path / "config.yaml").write_text(f"network: testnet\nnetworks_allowed: {value}\n")
    assert load_config(str(tmp_path)).networks_allowed == allowed


def test_assemble_group_is_gone():
    assert not hasattr(aplanesdk, "assemble_group")
    assert not hasattr(aplanesdk.signer, "assemble_group")
    assert SignerClient is aplanesdk.SignerClient


# The case list the Go and TypeScript suites run too: the three SDKs accept and
# refuse the same strings.
BASE64_ACCEPTED = ["", "QQ==", "QUI=", "QUJD", "QUJDRA==", "+/+/", "AAAA"]
BASE64_REFUSED = [
    "QUJD\n",  # a trailing line feed
    "QUJD\r\n",  # a trailing CRLF
    "QU\nJD",  # a line feed inside
    "QUJD\r\nQUJD",  # a wrapped line
    "\nQUJD",  # a leading line feed
    "QU JD",  # a space
    "QUJD ",  # a trailing space
    "\tQUJD",  # a tab
    "QU*D",  # a character outside the alphabet
    "-_-_",  # the URL-safe alphabet
    "QUI",  # missing padding
    "QQ=",  # short padding
    "QQ===",  # long padding
    "QUI=QUJD",  # data after the padding
    "=QUJ",  # padding first
    "Q",  # one character
]


@pytest.mark.parametrize("good", BASE64_ACCEPTED)
def test_strict_base64_accepts_standard_padded_base64(good):
    assert base64.b64encode(_strict_base64(good)).decode() == good


@pytest.mark.parametrize("bad", BASE64_REFUSED + [None, b"QUJD", 5])
def test_strict_base64_is_refused_at_every_site(bad):
    """One decoder at every site that takes a caller's base64, before any request."""
    with pytest.raises(ValueError, match="input is not valid base64"):
        _strict_base64(bad, "input")
    if not isinstance(bad, str):
        return
    with pytest.raises(ValueError, match="signed_transaction_base64 is not valid base64"):
        PreparedTransaction(signed_transaction_base64=bad).to_sign_request()

    client = make_client()
    client.session = MagicMock()
    with pytest.raises(ValueError, match=r"passthrough\[0\] is not valid base64"):
        client.sign_transactions([fake_signer.payment()], passthrough={0: bad})
    client.session.post.assert_not_called()

    # Never submitted: algod's client would decode it leniently and send it.
    algod = MagicMock()
    with pytest.raises(ValueError, match="signed transaction is not valid base64") as refusal:
        send_raw_transaction(algod, bad)
    assert not isinstance(refusal.value, SignerError)
    algod.send_raw_transaction.assert_not_called()


def test_send_raw_transaction_submits_valid_base64():
    algod = MagicMock()
    algod.send_raw_transaction.return_value = "TXID"
    assert send_raw_transaction(algod, "QUJD") == "TXID"
    algod.send_raw_transaction.assert_called_once_with("QUJD")


# Whole config files the Go and TypeScript suites load too. A YAML alias is
# read as the value it stands for, and the default network must be text like
# the allowlist's entries.


@pytest.mark.parametrize(
    ("content", "network", "allowed"),
    [
        ("nets: &nets [testnet]\nnetworks_allowed: *nets\n", "testnet", ["testnet"]),
        (
            "name: &name testnet\nnetworks_allowed: [*name, mainnet]\n",
            "testnet",
            ["testnet", "mainnet"],
        ),
        ("name: &name mainnet\nnetwork: *name\n", "mainnet", []),
        ("network: ~\n", "testnet", []),
        ('network: "1"\n', "1", []),
        ('network: "1"\nnetworks_allowed: ["1"]\n', "1", ["1"]),
    ],
)
def test_config_reads_aliases_and_a_text_network(tmp_path, content, network, allowed):
    (tmp_path / "config.yaml").write_text(content)
    config = load_config(str(tmp_path))
    assert (config.network, config.networks_allowed) == (network, allowed)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("n: &n 1\nnetworks_allowed: [*n]\n", "networks_allowed"),
        ("n: &n {a: b}\nnetworks_allowed: *n\n", "networks_allowed"),
        ("network: 1\n", "invalid network in config.yaml"),
        ("network: 1\nnetworks_allowed: [testnet]\n", "invalid network in config.yaml"),
        ("network: true\n", "invalid network in config.yaml"),
        ("network: 1.5\n", "invalid network in config.yaml"),
        ("network: [a]\n", "invalid network in config.yaml"),
        ("network: Mainnet\n", "invalid network in config.yaml"),
        ("n: &n 1\nnetwork: *n\n", "invalid network in config.yaml"),
    ],
)
def test_config_refuses_a_network_that_is_not_text(tmp_path, content, message):
    (tmp_path / "config.yaml").write_text(content)
    with pytest.raises(SignerError, match=message):
        load_config(str(tmp_path))


@pytest.mark.parametrize("recorded", [(5000, 1999), (1999, 5000)])
def test_group_balance_uses_the_lowest_recorded_spendable_algo(recorded):
    """Positions of one sender each read its balance; the lowest value is checked."""

    def position(available):
        return PreparedTransaction(
            transaction=fake_signer.payment(amount=0),
            checks=[
                PreparedCheck(name="spendable_algo", status="ok", data={"available": available})
            ],
        )

    with pytest.raises(SignerError, match="available 1999, required 2000"):
        _validate_group_algo_balance([position(value) for value in recorded])
    _validate_group_algo_balance([position(5000), position(2000)])
    _validate_group_algo_balance([position(2000), position(5000)])


def test_abi_bool_refusal_names_the_methods_own_argument():
    """The error gives the argument's index in the method, and its name if it has one.

    Past 15 arguments the tail is packed into one tuple, and a reference
    argument is encoded as an index; neither moves the label.
    """
    client = make_client()
    algod = MagicMock()
    # 17 arguments: the last three are packed into a tuple for encoding.
    many = "f(" + ",".join(["uint64"] * 17) + ")void"
    with pytest.raises(ValueError, match="ABI argument 16 must be an integer, not bool"):
        client.prepare_abi_app_call(
            algod, sender=SENDER, app_id=7, method_signature=many, args=[1] * 16 + [True]
        )
    with pytest.raises(ValueError, match=r"ABI argument 15\[1\] must be an integer, not bool"):
        client.prepare_abi_app_call(
            algod,
            sender=SENDER,
            app_id=7,
            method_signature="f(" + ",".join(["uint64"] * 15) + ",(uint8,uint8),uint64)void",
            args=[1] * 15 + [(1, False), 1],
        )
    # Reference arguments before the integer.
    with pytest.raises(ValueError, match="ABI argument 2 must be an integer, not bool"):
        client.prepare_abi_app_call(
            algod,
            sender=SENDER,
            app_id=7,
            method_signature="f(asset,account,uint64)void",
            args=[1001, RECEIVER, True],
        )
    # A transaction argument is refused outright, so it cannot shift a label.
    with pytest.raises(ValueError, match="ABI transaction arguments are not supported"):
        client.prepare_abi_app_call(
            algod, sender=SENDER, app_id=7, method_signature="f(pay,uint64)void", args=[None, True]
        )
    algod.suggested_params.assert_not_called()

    # A method that names its arguments has the name in the message.
    named = abi.Method(
        "f",
        [abi.Argument("asset", name="token"), abi.Argument("uint64", name="amount")],
        abi.Returns("void"),
    )
    with pytest.raises(ValueError, match=r"ABI argument 1 \(amount\) must be an integer, not bool"):
        _encode_abi_method_args(named, [1001, True], SENDER, 7, None, None, None)
