# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Cross-SDK prepared transaction request-shape fixture tests."""

import base64
import json
from pathlib import Path

import pytest
from algosdk import transaction

from aplanesdk.signer import PreparedGroup, PreparedTransaction


FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "contracts"
    / "prep"
    / "sign_request_shapes.json"
)


def load_fixture() -> dict:
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def suggested_params() -> transaction.SuggestedParams:
    return transaction.SuggestedParams(
        1000,
        100,
        200,
        base64.b64encode(bytes([9]) * 32).decode(),
        "testnet-v1",
        flat_fee=True,
    )


def build_groups(addresses: dict) -> dict[str, PreparedGroup]:
    sender = addresses["sender"]
    receiver = addresses["receiver"]
    auth = addresses["auth"]
    close_to = addresses["close_to"]
    rekey_to = addresses["rekey_to"]
    foreign = addresses["foreign"]
    app_account = addresses["app_account"]
    passthrough = base64.b64encode(bytes.fromhex("82a3736967c440")).decode()

    payment = transaction.PaymentTxn(sender, suggested_params(), receiver, 12345, note=b"pay")
    asa = transaction.AssetTransferTxn(sender, suggested_params(), receiver, 5, 1001, note=b"asa")
    opt_in = transaction.AssetTransferTxn(sender, suggested_params(), sender, 0, 1001, note=b"optin")
    opt_out = transaction.AssetTransferTxn(
        sender,
        suggested_params(),
        sender,
        0,
        1001,
        close_assets_to=close_to,
        note=b"optout",
    )
    close = transaction.PaymentTxn(
        sender,
        suggested_params(),
        close_to,
        0,
        close_remainder_to=close_to,
        note=b"close",
    )
    rekey = transaction.PaymentTxn(
        sender,
        suggested_params(),
        sender,
        0,
        rekey_to=rekey_to,
        note=b"rekey",
    )
    keyreg = transaction.KeyregNonparticipatingTxn(
        sender,
        suggested_params(),
        note=b"keyreg",
    )
    raw_app = transaction.ApplicationCallTxn(
        sender,
        suggested_params(),
        7,
        transaction.OnComplete.NoOpOC,
        app_args=[b"raw"],
        accounts=[app_account],
        foreign_apps=[8],
        foreign_assets=[1001],
        note=b"rawapp",
    )
    abi_app = transaction.ApplicationCallTxn(
        sender,
        suggested_params(),
        7,
        transaction.OnComplete.NoOpOC,
        app_args=[bytes.fromhex("01020304"), (42).to_bytes(8, "big")],
        accounts=[app_account],
        foreign_apps=[8],
        foreign_assets=[1001],
        note=b"abiapp",
    )
    app_deploy = transaction.ApplicationCreateTxn(
        sender,
        suggested_params(),
        transaction.OnComplete.NoOpOC,
        approval_program=b"\x01\x20\x01\x01\x22",
        clear_program=b"\x01\x20\x01\x01\x22",
        global_schema=transaction.StateSchema(1, 0),
        local_schema=transaction.StateSchema(0, 1),
        extra_pages=1,
        app_args=[b"init"],
        note=b"deploy",
    )
    foreign_payment = transaction.PaymentTxn(
        foreign,
        suggested_params(),
        receiver,
        500,
        note=b"foreign",
    )
    second_payment = transaction.PaymentTxn(
        sender,
        suggested_params(),
        close_to,
        6789,
        note=b"pay2",
    )

    def signed(txn, **kwargs):
        return PreparedTransaction(transaction=txn, auth_address=auth, **kwargs)

    def foreign_slot(txn):
        return PreparedTransaction(transaction=txn, lsig_size=3035)

    passthrough_slot = PreparedTransaction(signed_transaction_base64=passthrough)

    return {
        "payment_sign_mode_lsig_args": PreparedGroup([
            signed(
                payment,
                lsig_args={
                    "preimage": b"secret",
                    "recipient": bytes.fromhex("aabbccdd"),
                },
            )
        ]),
        "asa_transfer": PreparedGroup([signed(asa)]),
        "asa_opt_in": PreparedGroup([signed(opt_in)]),
        "asa_opt_out": PreparedGroup([signed(opt_out)]),
        "account_close": PreparedGroup([signed(close)]),
        "rekey": PreparedGroup([signed(rekey)]),
        "keyreg_nonparticipation": PreparedGroup([signed(keyreg)]),
        "raw_app_call_info": PreparedGroup([
            signed(raw_app, app_call_info={"mode": "raw"})
        ]),
        "abi_app_call_info": PreparedGroup([
            signed(
                abi_app,
                app_call_info={"mode": "abi", "method": "do(uint64)void"},
            )
        ]),
        "app_deploy": PreparedGroup([
            signed(app_deploy, app_call_info={"mode": "raw"})
        ]),
        "payment_plus_app_group": PreparedGroup([
            signed(payment),
            signed(raw_app, app_call_info={"mode": "raw"}),
        ]),
        "grouped_payments": PreparedGroup([signed(payment), signed(second_payment)]),
        "foreign_lsig_context": PreparedGroup([foreign_slot(foreign_payment)]),
        "passthrough_signed_slot": PreparedGroup([passthrough_slot]),
        "mixed_sign_foreign_passthrough": PreparedGroup([
            signed(payment),
            foreign_slot(foreign_payment),
            passthrough_slot,
        ]),
    }


@pytest.mark.parametrize("case", load_fixture()["cases"], ids=lambda case: case["name"])
def test_prepared_sign_request_parity_fixture(case):
    fixture = load_fixture()
    groups = build_groups(fixture["addresses"])
    assert case["name"] in groups
    assert groups[case["name"]].to_sign_requests() == case["expected_requests"]
