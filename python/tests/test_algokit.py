# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

import base64
from threading import Event, Thread

import pytest
from algosdk import account, encoding, transaction

from aplanesdk.algokit import ApsignerAccount, create_apsigner_account, list_apsigner_accounts
from aplanesdk.signer import GroupSignResponse, KeyInfo, SignerError, encode_transaction

_SIGNING_KEY, _ = account.generate_account()
# Real addresses: the zero address is left out of a canonical encoding.
_SENDER = account.generate_account()[1]
_RECEIVER = account.generate_account()[1]


def payment(note: int, fee: int = 1_000) -> transaction.PaymentTxn:
    """A distinct transaction; py-algosdk's has the sender the adapter reads."""
    params = transaction.SuggestedParams(
        fee=fee,
        first=1,
        last=1_000,
        gh=base64.b64encode(b"\x07" * 32).decode(),
        gen="testnet-v1.0",
        flat_fee=True,
    )
    return transaction.PaymentTxn(_SENDER, params, _RECEIVER, 0, note=bytes([note]))


def encode_for_test(txn) -> bytes:
    return bytes.fromhex(encode_transaction(txn)[0])


def signed_hex(txn) -> str:
    return base64.b64decode(encoding.msgpack_encode(txn.sign(_SIGNING_KEY))).hex()


def sign_honestly(requests) -> list[str]:
    """Signs exactly the transactions requested, as apsigner does when it
    changes nothing."""
    signed = []
    for request in requests:
        raw = bytes.fromhex(request["txn_bytes_hex"])[2:]
        signed.append(signed_hex(encoding.msgpack_decode(base64.b64encode(raw).decode())))
    return signed


class MockSignerClient:
    def __init__(self) -> None:
        self.sign_calls = []
        self.cancel_calls = []

    def sign_requests(self, requests, *, request_id=None):
        self.sign_calls.append((requests, request_id))
        return GroupSignResponse(signed=sign_honestly(requests))

    def cancel_sign_request(self, request_id):
        self.cancel_calls.append(request_id)

    def list_keys(self, refresh=False):
        return [
            KeyInfo(
                address="ADDR",
                key_type="ed25519",
            )
        ]


def test_account_signer_sends_requested_indexes() -> None:
    client = MockSignerClient()
    account = ApsignerAccount(
        client,
        "SENDER",
        auth_address="AUTH",
        new_request_id=lambda: "sdk-algokit-test",
        lsig_args={"preimage": b"\x01\x02"},
        encode_transaction=encode_for_test,
    )

    group = [payment(1), payment(2), payment(3)]
    signed = account.signer(group, [0, 2])

    assert account.addr == "SENDER"
    assert account.auth_address == "AUTH"
    assert signed == [bytes.fromhex(signed_hex(group[0])), bytes.fromhex(signed_hex(group[2]))]
    assert client.sign_calls == [
        (
            [
                {
                    "txn_bytes_hex": encode_transaction(group[0])[0],
                    "txn_sender": _SENDER,
                    "auth_address": "AUTH",
                    "lsig_args": {"preimage": "0102"},
                },
                {
                    "txn_bytes_hex": encode_transaction(group[2])[0],
                    "txn_sender": _SENDER,
                    "auth_address": "AUTH",
                    "lsig_args": {"preimage": "0102"},
                },
            ],
            "sdk-algokit-test",
        )
    ]


def test_list_apsigner_accounts() -> None:
    client = MockSignerClient()
    accounts = list_apsigner_accounts(client, refresh=True)

    assert len(accounts) == 1
    assert accounts[0].addr == "ADDR"
    assert accounts[0].auth_address == "ADDR"


def test_create_apsigner_account() -> None:
    client = MockSignerClient()
    account = create_apsigner_account(
        client,
        "ADDR",
        encode_transaction=lambda _txn: b"TX",
    )

    assert account.addr == "ADDR"
    assert callable(account.signer)


def test_default_encoder_supports_current_algokit_utils_v5() -> None:
    pytest.importorskip("algokit_transact.codec.transaction")
    from algokit_transact.models.transaction import (
        PaymentTransactionFields,
        Transaction,
        TransactionType,
    )
    from aplanesdk.algokit import _default_encode_transaction

    txn = Transaction(
        transaction_type=TransactionType.Payment,
        sender=_SENDER,
        first_valid=1,
        last_valid=1_000,
        fee=1_000,
        genesis_hash=b"\x07" * 32,
        genesis_id="testnet-v1.0",
        note=b"\x01",
        payment=PaymentTransactionFields(receiver=_RECEIVER, amount=5),
    )

    encoded = _default_encode_transaction(txn)

    assert isinstance(encoded, bytes)
    assert encoded

    # AlgoKit's encoder and py-algosdk's must agree on a transaction's bytes,
    # or the adapter would refuse a transaction apsigner signed unchanged.
    client = MockSignerClient()
    signed = create_apsigner_account(client, _SENDER).signer([txn], [0])
    requests = client.sign_calls[0][0]
    assert requests[0]["txn_bytes_hex"] == encoded.hex()
    assert signed == [bytes.fromhex(item) for item in sign_honestly(requests)]


def test_cancel_sends_current_request_id_best_effort() -> None:
    client = MockSignerClient()
    account = ApsignerAccount(
        client,
        "ADDR",
        new_request_id=lambda: "sdk-cancel-test",
        encode_transaction=encode_for_test,
    )

    def sign_requests(requests, *, request_id=None):
        client.sign_calls.append((requests, request_id))
        account.cancel()
        return GroupSignResponse(signed=sign_honestly(requests))

    client.sign_requests = sign_requests

    txn = payment(1)
    signed = account.signer([txn], [0])

    assert signed == [bytes.fromhex(signed_hex(txn))]
    assert client.cancel_calls == ["sdk-cancel-test"]


def test_cancel_without_in_flight_request_is_noop() -> None:
    client = MockSignerClient()
    account = ApsignerAccount(client, "ADDR", encode_transaction=lambda _txn: b"TX")

    account.cancel()

    assert client.cancel_calls == []


def test_concurrent_signing_is_rejected() -> None:
    started = Event()
    release = Event()
    errors: list[BaseException] = []

    class BlockingClient(MockSignerClient):
        def sign_requests(self, requests, *, request_id=None):
            self.sign_calls.append((requests, request_id))
            started.set()
            release.wait(2)
            return GroupSignResponse(signed=sign_honestly(requests))

    client = BlockingClient()
    account = ApsignerAccount(
        client,
        "ADDR",
        new_request_id=lambda: "sdk-concurrent-test",
        encode_transaction=encode_for_test,
    )

    def run_sign() -> None:
        try:
            account.signer([payment(1)], [0])
        except BaseException as exc:
            errors.append(exc)

    thread = Thread(target=run_sign)
    thread.start()
    assert started.wait(2)

    with pytest.raises(RuntimeError, match="in-flight signing request"):
        account.signer([payment(1)], [0])

    release.set()
    thread.join(2)
    assert not thread.is_alive()
    assert errors == []


def test_empty_indexes_returns_empty_without_calling_client() -> None:
    client = MockSignerClient()
    account = ApsignerAccount(client, "ADDR", encode_transaction=lambda _txn: b"TX")

    assert account.signer([payment(1)], []) == []
    assert client.sign_calls == []


def test_encoder_failure_clears_in_flight_slot() -> None:
    client = MockSignerClient()
    calls = {"n": 0}

    def flaky_encoder(txn) -> bytes:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("encoder boom")
        return encode_for_test(txn)

    account = ApsignerAccount(client, "ADDR", encode_transaction=flaky_encoder)

    with pytest.raises(RuntimeError, match="encoder boom"):
        account.signer([payment(1)], [0])

    # The previous failure must not leave a stuck in-flight request id;
    # a follow-up sign call should succeed normally.
    txn = payment(1)
    signed = account.signer([txn], [0])
    assert signed == [bytes.fromhex(signed_hex(txn))]


def test_rejects_regrouped_signer_response() -> None:
    # AlgoKit assigns its own group ID, so a signer that re-grouped (added
    # dummies or recomputed the group ID) produces signatures AlgoKit cannot
    # submit. The adapter must fail fast rather than return them.
    for mutations in ({"dummies_added": 2}, {"group_id_changed": True}):

        class RegroupedClient(MockSignerClient):
            def sign_requests(self, requests, *, request_id=None):
                self.sign_calls.append((requests, request_id))
                return GroupSignResponse(signed=sign_honestly(requests), mutations=mutations)

        account = ApsignerAccount(
            RegroupedClient(),
            "ADDR",
            encode_transaction=encode_for_test,
        )
        with pytest.raises(SignerError, match="re-grouped"):
            account.signer([payment(1)], [0])


def test_rejects_mismatched_signed_count() -> None:
    class ExpandingClient(MockSignerClient):
        def sign_requests(self, requests, *, request_id=None):
            self.sign_calls.append((requests, request_id))
            return GroupSignResponse(signed=sign_honestly(requests) * 2)  # 2 signed, 1 requested

    account = ApsignerAccount(
        ExpandingClient(),
        "ADDR",
        encode_transaction=encode_for_test,
    )

    with pytest.raises(SignerError, match="returned 2 signed transaction"):
        account.signer([payment(1)], [0])


def test_rejects_too_few_signer_responses() -> None:
    class ShortClient(MockSignerClient):
        def sign_requests(self, requests, *, request_id=None):
            self.sign_calls.append((requests, request_id))
            return GroupSignResponse(signed=sign_honestly(requests)[:1])

    account = ApsignerAccount(
        ShortClient(),
        "ADDR",
        encode_transaction=encode_for_test,
    )

    with pytest.raises(SignerError, match="returned 1 signed transaction"):
        account.signer([payment(1), payment(2)], [0, 1])


# Audit finding 4: for a lone transaction from a native Falcon or LogicSig
# account, apsigner adds the authorization charge to the fee without
# regrouping. AlgoKit would submit the raised transaction and wait on the ID of
# its own copy, report a failure for a payment that went through, and a retry
# would pay twice. The adapter refuses before AlgoKit submits.
def test_refuses_a_transaction_whose_fee_the_signer_raised() -> None:
    class FeeRaisingClient(MockSignerClient):
        def sign_requests(self, requests, *, request_id=None):
            self.sign_calls.append((requests, request_id))
            return GroupSignResponse(
                signed=[signed_hex(payment(1, fee=3_000))],
                mutations={"fees_modified": [0], "total_fees_delta": 2_000},
            )

    account = ApsignerAccount(FeeRaisingClient(), "ADDR", encode_transaction=encode_for_test)

    with pytest.raises(
        SignerError,
        match=r"raised the fee of AlgoKit transaction 0 by the account's authorization charge "
        r"\(2000 microAlgos in total\); AlgoKit's transaction ID would no longer match what is "
        r"submitted, so nothing was submitted",
    ):
        account.signer([payment(1)], [0])


def test_refuses_any_other_change_to_a_signed_transaction() -> None:
    class ChangingClient(MockSignerClient):
        def sign_requests(self, requests, *, request_id=None):
            self.sign_calls.append((requests, request_id))
            signed = sign_honestly(requests)
            signed[1] = signed_hex(payment(9))
            return GroupSignResponse(signed=signed)

    account = ApsignerAccount(ChangingClient(), "ADDR", encode_transaction=encode_for_test)

    with pytest.raises(SignerError, match="apsigner returned AlgoKit transaction 1 changed"):
        account.signer([payment(1), payment(2)], [0, 1])


def test_refuses_a_signed_transaction_it_cannot_read() -> None:
    class GarbageClient(MockSignerClient):
        def sign_requests(self, requests, *, request_id=None):
            self.sign_calls.append((requests, request_id))
            return GroupSignResponse(signed=["aabb"])

    account = ApsignerAccount(GarbageClient(), "ADDR", encode_transaction=encode_for_test)

    with pytest.raises(
        SignerError, match="unreadable signed transaction for AlgoKit transaction 0"
    ):
        account.signer([payment(1)], [0])
