# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

from threading import Event, Thread

import pytest

from aplanesdk.algokit import ApsignerAccount, create_apsigner_account, list_apsigner_accounts
from aplanesdk.signer import GroupSignResponse, KeyInfo, SignerError


class MockTxn:
    def __init__(self, sender: str) -> None:
        self.sender = sender


class MockSignerClient:
    def __init__(self) -> None:
        self.sign_calls = []
        self.cancel_calls = []

    def sign_requests(self, requests, *, request_id=None):
        self.sign_calls.append((requests, request_id))
        return GroupSignResponse(signed=["aabb", "ccdd"])

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
        encode_transaction=lambda txn: b"TX" + txn.sender.encode(),
    )

    signed = account.signer([MockTxn("1"), MockTxn("2"), MockTxn("3")], [0, 2])

    assert account.addr == "SENDER"
    assert account.auth_address == "AUTH"
    assert signed == [bytes.fromhex("aabb"), bytes.fromhex("ccdd")]
    assert client.sign_calls == [
        (
            [
                {
                    "txn_bytes_hex": "545831",
                    "txn_sender": "1",
                    "auth_address": "AUTH",
                    "lsig_args": {"preimage": "0102"},
                },
                {
                    "txn_bytes_hex": "545833",
                    "txn_sender": "3",
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


def test_cancel_sends_current_request_id_best_effort() -> None:
    client = MockSignerClient()
    account = ApsignerAccount(
        client,
        "ADDR",
        new_request_id=lambda: "sdk-cancel-test",
        encode_transaction=lambda _txn: b"TX",
    )

    def sign_requests(requests, *, request_id=None):
        client.sign_calls.append((requests, request_id))
        account.cancel()
        return GroupSignResponse(signed=["aabb"])

    client.sign_requests = sign_requests

    signed = account.signer([MockTxn("ADDR")], [0])

    assert signed == [bytes.fromhex("aabb")]
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
            return GroupSignResponse(signed=["aabb"])

    client = BlockingClient()
    account = ApsignerAccount(
        client,
        "ADDR",
        new_request_id=lambda: "sdk-concurrent-test",
        encode_transaction=lambda _txn: b"TX",
    )

    def run_sign() -> None:
        try:
            account.signer([MockTxn("ADDR")], [0])
        except BaseException as exc:
            errors.append(exc)

    thread = Thread(target=run_sign)
    thread.start()
    assert started.wait(2)

    with pytest.raises(RuntimeError, match="in-flight signing request"):
        account.signer([MockTxn("ADDR")], [0])

    release.set()
    thread.join(2)
    assert not thread.is_alive()
    assert errors == []


def test_empty_indexes_returns_empty_without_calling_client() -> None:
    client = MockSignerClient()
    account = ApsignerAccount(client, "ADDR", encode_transaction=lambda _txn: b"TX")

    assert account.signer([MockTxn("ADDR")], []) == []
    assert client.sign_calls == []


def test_encoder_failure_clears_in_flight_slot() -> None:
    client = MockSignerClient()
    calls = {"n": 0}

    def flaky_encoder(_txn: object) -> bytes:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("encoder boom")
        return b"TX"

    def sign_one(requests, *, request_id=None):
        client.sign_calls.append((requests, request_id))
        return GroupSignResponse(signed=["aabb"])

    client.sign_requests = sign_one
    account = ApsignerAccount(client, "ADDR", encode_transaction=flaky_encoder)

    with pytest.raises(RuntimeError, match="encoder boom"):
        account.signer([MockTxn("ADDR")], [0])

    # The previous failure must not leave a stuck in-flight request id;
    # a follow-up sign call should succeed normally.
    signed = account.signer([MockTxn("ADDR")], [0])
    assert signed == [bytes.fromhex("aabb")]


def test_allows_expanded_signer_response() -> None:
    class ExpandingClient(MockSignerClient):
        def sign_requests(self, requests, *, request_id=None):
            self.sign_calls.append((requests, request_id))
            return GroupSignResponse(signed=["aabb", "ccdd"])

    account = ApsignerAccount(
        ExpandingClient(),
        "ADDR",
        encode_transaction=lambda _txn: b"TX",
    )

    signed = account.signer([MockTxn("ADDR")], [0])

    assert signed == [bytes.fromhex("aabb"), bytes.fromhex("ccdd")]


def test_rejects_too_few_signer_responses() -> None:
    class ShortClient(MockSignerClient):
        def sign_requests(self, requests, *, request_id=None):
            self.sign_calls.append((requests, request_id))
            return GroupSignResponse(signed=["aabb"])

    account = ApsignerAccount(
        ShortClient(),
        "ADDR",
        encode_transaction=lambda _txn: b"TX",
    )

    with pytest.raises(SignerError, match="fewer signed transactions"):
        account.signer([MockTxn("1"), MockTxn("2")], [0, 1])
