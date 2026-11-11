# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Prepare-helper argument checks, preflight fees, and the smaller client checks."""

import base64
from unittest.mock import MagicMock, patch

import pytest
from algosdk import transaction

import aplanesdk
from aplanesdk import PreparedGroup, PreparedTransaction, SignerClient, SignerError
from aplanesdk.signer import (
    KeyInfo,
    _parse_lsig_resource_usage,
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
    with pytest.raises(ValueError, match="app_id must be"):
        client.prepare_app_call(algod, sender=SENDER, app_id=bad)
    with pytest.raises(ValueError, match="app_id must be"):
        client.prepare_abi_app_call(algod, sender=SENDER, app_id=bad, method_signature="do()void")
    algod.suggested_params.assert_not_called()


@pytest.mark.parametrize("bad", BAD_INTEGERS)
def test_foreign_references_must_be_integers(bad):
    client = make_client()
    with pytest.raises(ValueError, match=r"foreign_apps\[0\] must be"):
        client.prepare_app_call(MagicMock(), sender=SENDER, app_id=7, foreign_apps=[bad])
    with pytest.raises(ValueError, match=r"foreign_assets\[1\] must be"):
        client.prepare_app_call(MagicMock(), sender=SENDER, app_id=7, foreign_assets=[5, bad])


@pytest.mark.parametrize("bad", BAD_INTEGERS + [0])
def test_asset_id_must_be_a_positive_integer(bad):
    client = make_client()
    algod = MagicMock()
    with pytest.raises(ValueError, match="asset_id must be"):
        client.prepare_asa_transfer(algod, sender=SENDER, receiver=RECEIVER, asset_id=bad, amount=1)
    with pytest.raises(ValueError, match="asset_id must be"):
        client.prepare_asa_opt_in(algod, sender=SENDER, asset_id=bad)
    with pytest.raises(ValueError, match="asset_id must be"):
        client.prepare_asa_opt_out(algod, sender=SENDER, asset_id=bad, close_to=RECEIVER)
    algod.suggested_params.assert_not_called()


@pytest.mark.parametrize("bad", BAD_INTEGERS)
def test_amounts_and_fees_must_be_integers(bad):
    client = make_client()
    algod = Algod({SENDER: {"amount": 2_000_000, "min-balance": 100_000}})
    with pytest.raises(ValueError, match="amount must be"):
        client.prepare_payment(algod, sender=SENDER, receiver=RECEIVER, amount=bad)
    with pytest.raises(ValueError, match="amount must be"):
        client.prepare_asa_transfer(algod, sender=SENDER, receiver=RECEIVER, asset_id=5, amount=bad)
    with pytest.raises(ValueError, match="fee must be"):
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


def test_sweep_counts_asa_transfer_fees_against_the_paying_sender():
    def accounts(balance):
        return {
            SENDER: {
                "amount": balance,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 25}],
            },
            RECEIVER: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 0}],
            },
        }

    def sweep(balance):
        client = make_client()
        with _signer(client, SENDER):
            return client.prepare_sweep_group(
                Algod(accounts(balance)),
                asa_transfers=[
                    {"sender": SENDER, "receiver": RECEIVER, "asset_id": 1001, "amount": 5}
                ],
                payments=[{"sender": SENDER, "receiver": RECEIVER, "amount": 10_000}],
            )

    # Available is the balance less the 100,000 minimum. The sender pays
    # 10,000 plus two 1000 fees: its own and the ASA transfer's.
    assert len(sweep(112_000).transactions) == 2
    with pytest.raises(SignerError, match="available 11999, required 12000"):
        sweep(111_999)


def test_lsig_resource_numbers_are_not_coerced():
    usage = _parse_lsig_resource_usage(
        {"program_bytes": 512, "argument_bytes": 32, "max_opcode_cost": 20000}
    )
    assert (usage.program_bytes, usage.argument_bytes, usage.max_opcode_cost) == (512, 32, 20000)
    # A missing field keeps its default, and a key with no resources has none.
    assert _parse_lsig_resource_usage({"program_bytes": 512}).argument_bytes == 0
    assert _parse_lsig_resource_usage(None) is None
    for bad in (512.9, 512.0, "512", True, -1, None):
        with pytest.raises(SignerError, match="non-integer program_bytes"):
            _parse_lsig_resource_usage({"program_bytes": bad})

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
        with pytest.raises(SignerError, match="non-integer program_bytes"):
            client.list_keys(refresh=True)


def test_cosigned_group_refuses_a_signer_key_for_another_address():
    txn = fake_signer.payment()
    other_key = KeyInfo(address=sdk_test_address(9), key_type="ed25519")
    user = MagicMock()
    with pytest.raises(ValueError, match="signer key is for .* not the position's auth address"):
        sign_prepared_cosigned_group(
            user_client=user,
            prepared_group=PreparedGroup(
                [
                    PreparedTransaction(
                        transaction=txn, auth_address=txn.sender, signer_key=other_key
                    )
                ]
            ),
        )
    user.plan_requests.assert_not_called()


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


def test_assemble_group_is_gone():
    assert not hasattr(aplanesdk, "assemble_group")
    assert not hasattr(aplanesdk.signer, "assemble_group")
    assert SignerClient is aplanesdk.SignerClient
