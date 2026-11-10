# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""A stand-in for apsigner's planner, for tests.

It does to a request group what the real signer does, so mocked responses are
ones a real signer could return: it raises the fees it is told to, appends
resource dummies, groups an ungrouped group, reports all of it, and signs.
"""

import base64
import copy
from unittest.mock import MagicMock

from algosdk import encoding, transaction

from aplanesdk.signer import (
    _canonical_dummy_txn,
    _decode_request_slots,
    _group_id_bytes,
    _sign_canonical_dummy,
    _txn_bytes,
)


def test_address(seed: int) -> str:
    raw = bytearray(32)
    raw[-1] = seed
    return encoding.encode_address(bytes(raw))


test_address.__test__ = False  # type: ignore[attr-defined]


def payment(sender_seed: int = 41, receiver_seed: int = 42, amount: int = 1_000_000, sender=None):
    genesis_hash = bytearray(32)
    genesis_hash[0] = 7
    params = transaction.SuggestedParams(
        1000,
        10,
        1010,
        base64.b64encode(bytes(genesis_hash)).decode(),
        "testnet-v1.0",
        flat_fee=True,
    )
    return transaction.PaymentTxn(
        sender or test_address(sender_seed), params, test_address(receiver_seed), amount
    )


def sign_entries(*txns):
    return [
        {
            "auth_address": txn.sender,
            "txn_sender": txn.sender,
            "txn_bytes_hex": _txn_bytes(txn).hex(),
        }
        for txn in txns
    ]


def signed_hex(txn) -> str:
    """A signed transaction as an Ed25519 signer would return it."""
    signed = transaction.SignedTransaction(txn, base64.b64encode(bytes([1]) * 64).decode())
    return base64.b64decode(encoding.msgpack_encode(signed)).hex()


def decode_signed(signed_hex_value: str):
    return encoding.msgpack_decode(base64.b64encode(bytes.fromhex(signed_hex_value)).decode())


def _finalize(entries, fee_raise=None, dummies=0):
    slots = _decode_request_slots(entries)
    fee_raise = fee_raise or {}
    final = []
    report = {"original_count": len(slots)}
    pre_grouped = _group_id_bytes(slots[0].txn) is not None
    total = 0
    for index, slot in enumerate(slots):
        txn = copy.deepcopy(slot.txn)
        if fee_raise.get(index):
            txn.fee += fee_raise[index]
            report.setdefault("fees_modified", []).append(index)
            total += fee_raise[index]
        if slot.mode == "passthrough":
            report["passthrough_count"] = report.get("passthrough_count", 0) + 1
        elif slot.mode == "foreign":
            report["foreign_count"] = report.get("foreign_count", 0) + 1
        final.append(txn)
    for index in range(dummies):
        final.append(_canonical_dummy_txn(slots[0].txn, None, index))
    report["final_count"] = len(final)
    if dummies:
        report["dummies_added"] = dummies
    if total:
        report["total_fees_delta"] = total
    if len(final) > 1 and (not pre_grouped or dummies or total):
        for txn in final:
            txn.group = None
        group_id = transaction.calculate_group_id(final)
        for txn in final:
            txn.group = group_id
        report["group_id_changed"] = True
    if set(report) == {"original_count", "final_count"}:
        return slots, final, None
    return slots, final, report


def sign_response(entries, fee_raise=None, dummies=0) -> dict:
    """The /sign response body a real signer would return for these entries."""
    slots, final, report = _finalize(entries, fee_raise, dummies)
    signed = []
    for index, txn in enumerate(final):
        if index >= len(slots):
            signed.append(_sign_canonical_dummy(txn).hex())
        elif slots[index].mode == "passthrough":
            signed.append(entries[index]["signed_txn_hex"])
        elif slots[index].mode == "foreign":
            signed.append("")
        else:
            signed.append(signed_hex(txn))
    body = {"signed": signed}
    if report is not None:
        body["mutations"] = report
    return body


def plan_response(entries, fee_raise=None, dummies=0) -> dict:
    """The /plan response body a real signer would return for these entries."""
    _, final, report = _finalize(entries, fee_raise, dummies)
    body = {"transactions": [_txn_bytes(txn).hex() for txn in final]}
    if report is not None:
        body["mutations"] = report
    return body


def _response(body):
    resp = MagicMock()
    resp.status_code = 200
    resp.text = ""
    resp.json.return_value = body
    return resp


def signer_post(fee_raise=None, dummies=0, tamper=None):
    """A session.post stand-in answering /sign and /plan as a real signer would.

    ``tamper`` may edit the response body before it is returned.
    """

    def post(url, json=None, **kwargs):
        del kwargs
        if url.endswith("/plan"):
            body = plan_response(json["requests"], fee_raise, dummies)
        elif url.endswith("/sign"):
            body = sign_response(json["requests"], fee_raise, dummies)
        else:
            raise AssertionError(f"unexpected POST {url}")
        if tamper is not None:
            tamper(body)
        return _response(body)

    return post
