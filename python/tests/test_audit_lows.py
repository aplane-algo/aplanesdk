# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Prepare-helper argument checks, preflight fees, and the smaller client checks."""

import base64
import dataclasses
from unittest.mock import MagicMock, patch

import pytest
from algosdk import transaction

import aplanesdk
from aplanesdk import PreparedGroup, PreparedTransaction, SignerClient, SignerError
from aplanesdk.signer import (
    KeyInfo,
    KeyNotFoundError,
    _parse_lsig_resource_usage,
    _require_uint,
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

    # A sender with only an asset transfer is checked beside one that pays.
    other_transfer = {"sender": RECEIVER, "receiver": SENDER, "asset_id": 1001, "amount": 1}
    sweep(2_000_000, asa_transfers=[other_transfer], payments=[payment], other_balance=101_000)
    with pytest.raises(SignerError, match=f"group insufficient funds for {RECEIVER}"):
        sweep(2_000_000, asa_transfers=[other_transfer], payments=[payment], other_balance=100_999)

    # The ASA transfer group helper makes the same check.
    client = make_client()
    with _signer_for_both(client):
        with pytest.raises(SignerError, match="available 1999, required 2000"):
            client.prepare_asa_transfer_group(Algod(_sweep_accounts(101_999)), [transfer, transfer])


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
        with pytest.raises(SignerError, match="program_bytes must be an integer"):
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
    # Two rows for one address, the non-spending one last.
    signer = _KeysetSigner(
        1,
        [
            {"address": sender, "key_type": "ed25519", "signing_flow": "cosigner9"},
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
