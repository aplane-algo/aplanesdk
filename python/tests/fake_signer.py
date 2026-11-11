# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""A stand-in for apsigner's planner, for tests.

It does to a request group what the real signer does, so mocked responses are
ones a real signer could return: it raises the fees it is told to, appends
resource dummies, groups an ungrouped group, reports all of it, and signs.
"""

import base64
import copy
import json as json_module
from unittest.mock import MagicMock

from algosdk import encoding, transaction
from nacl.signing import SigningKey

from aplanesdk.signer import (
    _canonical_dummy_txn,
    _decode_request_slots,
    _group_id_bytes,
    _sign_canonical_dummy,
    encode_transaction,
)


def test_address(seed: int) -> str:
    raw = bytearray(32)
    raw[-1] = seed
    return encoding.encode_address(bytes(raw))


test_address.__test__ = False  # type: ignore[attr-defined]


# The fake signer's accounts, by address: Ed25519 keys, LogicSig programs and
# native Falcon public keys, as the real signer holds them.
_KEYS: dict = {}
_PROGRAMS: dict = {}
_PQ_KEYS: dict = {}


def account(seed: int) -> str:
    """The address of the fake signer's Ed25519 account for a seed."""
    key = SigningKey(bytes([seed]) * 32)
    address = encoding.encode_address(bytes(key.verify_key))
    _KEYS[address] = key
    return address


def lsig_account(seed: int) -> str:
    """A LogicSig account the fake signer holds: the hash of its program."""
    program = bytes([0x06, 0x81, seed])  # #pragma version 6; pushint seed
    address = transaction.LogicSigAccount(program).address()
    _PROGRAMS[address] = program
    return address


def pq_account(seed: int) -> str:
    """A native Falcon account the fake signer holds.

    The public key and signature are filler: nothing verifies them.
    """
    public_key = bytes([seed]) * 1793
    address, salt = encoding.address_from_pq_key(b"f1", public_key)
    _PQ_KEYS[address] = transaction.PQSig(b"f1", salt, public_key, bytes([9]) * 1232)
    return address


def hold_program(program: bytes) -> str:
    """Have the fake signer hold a LogicSig account for the given program."""
    address = transaction.LogicSigAccount(program).address()
    _PROGRAMS[address] = program
    return address


def authorize(txn, auth_address: str):
    """Sign as the fake signer's account at auth_address would.

    The account's kind of authorization, and the signer field when the account
    is not the sender. An address the fake signer does not hold gets a
    signature that verifies under nothing.
    """
    rekeyed = auth_address if auth_address != txn.sender else None
    if auth_address in _KEYS:
        message = bytes.fromhex(encode_transaction(txn)[0])
        signature = _KEYS[auth_address].sign(message).signature
        return transaction.SignedTransaction(txn, base64.b64encode(signature).decode(), rekeyed)
    if auth_address in _PROGRAMS:
        signed = transaction.LogicSigTransaction(
            txn, transaction.LogicSigAccount(_PROGRAMS[auth_address], [b"\x01\x02\x03"])
        )
        return signed
    if auth_address in _PQ_KEYS:
        return transaction.PQSignedTransaction(txn, _PQ_KEYS[auth_address], rekeyed)
    return transaction.SignedTransaction(txn, base64.b64encode(bytes([1]) * 64).decode(), rekeyed)


def encode_signed(signed) -> str:
    return base64.b64decode(encoding.msgpack_encode(signed)).hex()


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
        sender or account(sender_seed), params, test_address(receiver_seed), amount
    )


def sign_entries(*txns):
    return [
        {
            "auth_address": txn.sender,
            "txn_sender": txn.sender,
            "txn_bytes_hex": encode_transaction(txn)[0],
        }
        for txn in txns
    ]


def signed_hex(txn) -> str:
    """A transaction signed by its sender."""
    return encode_signed(authorize(txn, txn.sender))


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
            signed.append(encode_signed(authorize(txn, entries[index]["auth_address"])))
    body = {"signed": signed}
    if report is not None:
        body["mutations"] = report
    return body


def plan_response(entries, fee_raise=None, dummies=0) -> dict:
    """The /plan response body a real signer would return for these entries."""
    _, final, report = _finalize(entries, fee_raise, dummies)
    body = {"transactions": [encode_transaction(txn)[0] for txn in final]}
    if report is not None:
        body["mutations"] = report
    return body


def _response(body):
    resp = MagicMock()
    resp.status_code = 200
    resp.text = ""
    resp.json.return_value = body
    return resp


def posted_json(kwargs):
    """The JSON body a session.post call sent: approval-bearing requests are
    posted as bytes the SDK encoded itself, the others with json=."""
    if kwargs.get("data") is not None:
        return json_module.loads(kwargs["data"])
    return kwargs.get("json")


def signer_post(fee_raise=None, dummies=0, tamper=None):
    """A session.post stand-in answering /sign and /plan as a real signer would.

    ``tamper`` may edit the response body before it is returned.
    """

    def post(url, **kwargs):
        json = posted_json(kwargs)
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
