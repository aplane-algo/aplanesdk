# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Local stand-ins for apsigner and algod, for the unified sending tests.

Both are real HTTP servers on the loopback interface, so a send goes through
the SDK's own transport and a real AlgodClient: a dropped connection, a body
cut short and an HTTP error reach the code under test as they would from a
real signer or node.
"""

import base64
import copy
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

import msgpack
from algosdk import encoding, transaction
from algosdk.v2client import algod

from aplanesdk.signer import (
    COSIGNED_DUMMY_PROGRAM,
    SignerClient,
    _canonical_dummy_txn,
    encode_transaction,
)
from tests import fake_signer

# An answer that closes the connection with nothing sent.
DROP = object()


def truncated(body: bytes) -> tuple:
    """A 200 answer whose body is cut short: complete as HTTP, unreadable as
    JSON."""
    return (200, body, "application/json")


def reply(status: int, body: Any) -> tuple:
    return (status, json.dumps(body).encode(), "application/json")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 (the stdlib's name)
        self._serve()

    def do_POST(self) -> None:  # noqa: N802
        self._serve()

    def _serve(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        answer = self.server.app(self.command, urlparse(self.path).path, body)  # type: ignore[attr-defined]
        if answer is DROP:
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return
        status, payload, content_type = answer
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    # A client's kept-alive connection holds its handler thread; closing the
    # server does not wait for it.
    block_on_close = False

    def handle_error(self, request: Any, client_address: Any) -> None:
        # A dropped connection is the point of some tests.
        pass


class HTTPFake:
    """A loopback HTTP server that answers with app(method, path, body)."""

    def __init__(self, app: Callable[[str, str, bytes], Any]):
        self.server = _Server(("127.0.0.1", 0), _Handler)
        self.server.app = app  # type: ignore[attr-defined]
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.url = f"http://{host}:{port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def key(address: str, signing_flow: str = "", **fields: Any) -> Dict[str, Any]:
    """A /keys entry."""
    entry: Dict[str, Any] = {"address": address, "key_type": "ed25519"}
    if signing_flow:
        entry["signing_flow"] = signing_flow
    entry.update(fields)
    return entry


def status_body(approval_wait_seconds: int = 0) -> Dict[str, Any]:
    return {
        "state": "unlocked",
        "signer_locked": False,
        "ready_for_signing": True,
        "key_count": 1,
        "keyset_revision": 1,
        "approval_wait_seconds": approval_wait_seconds,
    }


class SendSigner:
    """A fake signer for send tests. ``sign`` answers /sign; None signs every
    position as its auth address would, raising the fees in ``fee_raise`` and
    appending ``dummies`` resource dummies."""

    def __init__(
        self,
        keys: List[Dict[str, Any]],
        sign: Optional[Callable[[Dict[str, Any]], Any]] = None,
        fee_raise: Optional[Dict[int, int]] = None,
        dummies: int = 0,
    ):
        self.keys = keys
        self.sign = sign
        self.fee_raise = fee_raise
        self.dummies = dummies
        self.paths: List[str] = []
        self.lock = threading.Lock()
        self.http = HTTPFake(self.app)

    def count(self, path: str) -> int:
        with self.lock:
            return sum(1 for seen in self.paths if seen == path)

    def app(self, method: str, path: str, body: bytes) -> Any:
        with self.lock:
            self.paths.append(path)
        if path == "/status":
            return reply(200, status_body())
        if path == "/keys":
            return reply(200, {"count": len(self.keys), "keys": self.keys})
        if path == "/sign/cancel":
            return reply(200, {"success": True, "state": "canceled"})
        if path == "/sign":
            request = json.loads(body)
            if self.sign is not None:
                return self.sign(request)
            return reply(
                200, fake_signer.sign_response(request["requests"], self.fee_raise, self.dummies)
            )
        raise AssertionError(f"unexpected signer path {path}")


def _genesis_hash() -> bytes:
    genesis = bytearray(32)
    genesis[0] = 7
    return bytes(genesis)


class FakeNode:
    """A fake algod.

    ``submit`` answers a submission given its bytes; None accepts the group
    and reports its first transaction's ID. ``pending`` answers the pending
    transaction lookup; None confirms in round 12. ``simulate`` answers the
    simulate endpoint; None reports success, with one transaction result per
    transaction. ``auth_addrs`` is the chain's auth address per account.
    ``round`` is the node's current round, and ``wait_round`` the round a
    wait for the next block answers with, when it is not that.
    """

    def __init__(
        self,
        submit: Optional[Callable[[bytes], Any]] = None,
        pending: Optional[Callable[[], Any]] = None,
        simulate: Optional[Callable[[], Any]] = None,
        auth_addrs: Optional[Dict[str, str]] = None,
        round: int = 10,
        accounts: Optional[Dict[str, Dict[str, Any]]] = None,
        wait_round: Optional[int] = None,
    ):
        self.submit = submit
        self.pending = pending
        self.simulate = simulate
        self.auth_addrs = auth_addrs or {}
        self.round = round
        self.accounts = accounts or {}
        self.wait_round = wait_round
        self.lock = threading.Lock()
        self.submitted: List[bytes] = []
        self.simulated: List[Dict[str, Any]] = []
        self.lookups = 0
        # The rounds each wait-for-block call asked to follow.
        self.waits: List[str] = []
        self.http = HTTPFake(self.app)
        self.client = algod.AlgodClient("", self.http.url)

    def submissions(self) -> List[bytes]:
        with self.lock:
            return list(self.submitted)

    def simulations(self) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.simulated)

    def app(self, method: str, path: str, body: bytes) -> Any:
        if method == "POST" and path == "/v2/transactions":
            with self.lock:
                self.submitted.append(body)
            if self.submit is not None:
                return self.submit(body)
            unpacker = msgpack.Unpacker(raw=False)
            unpacker.feed(body)
            first = encoding.msgpack_decode(next(unpacker))
            return reply(200, {"txId": first.get_txid()})
        if path.startswith("/v2/status/wait-for-block-after/"):
            with self.lock:
                self.waits.append(path.rsplit("/", 1)[1])
            answer = self.round if self.wait_round is None else self.wait_round
            return reply(200, {"last-round": answer})
        if path == "/v2/status":
            return reply(200, {"last-round": self.round})
        if path.startswith("/v2/accounts/"):
            address = path.rsplit("/", 1)[1]
            account = {"address": address, "amount": 5_000_000, "min-balance": 100_000}
            account.update(self.accounts.get(address, {}))
            if self.auth_addrs.get(address):
                account["auth-addr"] = self.auth_addrs[address]
            return reply(200, account)
        if path == "/v2/transactions/params":
            return reply(
                200,
                {
                    "fee": 0,
                    "min-fee": 1000,
                    "last-round": self.round,
                    "genesis-id": "testnet-v1.0",
                    "genesis-hash": base64.b64encode(_genesis_hash()).decode(),
                    "consensus-version": "test",
                },
            )
        if method == "POST" and path == "/v2/transactions/simulate":
            request = msgpack.unpackb(body, raw=False, strict_map_key=False)
            with self.lock:
                self.simulated.append(request)
            if self.simulate is not None:
                return self.simulate()
            # A passing group: one result, with one transaction result per
            # transaction simulated.
            txns = request.get("txn-groups", [{}])[0].get("txns", [])
            group = {"txn-results": [{} for _ in txns]}
            return reply(200, {"last-round": self.round, "version": 2, "txn-groups": [group]})
        if path.startswith("/v2/transactions/pending/"):
            with self.lock:
                self.lookups += 1
            if self.pending is not None:
                return reply(200, self.pending())
            return reply(200, {"confirmed-round": 12, "pool-error": ""})
        raise AssertionError(f"unexpected algod request {method} {path}")


def signer_client(url: str) -> SignerClient:
    # A short timeout, so a test that goes wrong fails instead of waiting for
    # an approval that never comes.
    return SignerClient(url, timeout=10)


# -----------------------------------------------------------------------------
# Rotating accounts
# -----------------------------------------------------------------------------

# A stage program for tests. Its address stands for a stage's.
ROTATING_TEST_PROGRAM = bytes([0x0A, 0x81, 0x01])
# A program other than the stage that signs.
ROTATING_NEXT_PROGRAM = bytes([0x0A, 0x81, 0x02])
# An address no fixture uses.
ELSEWHERE = encoding.encode_address(bytes([0x55]) + bytes(31))
ROTATING_KEY_TYPE = "aplane.rotating-triple-wotsc.v1"


_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def alternate_spelling(address: str) -> str:
    """Another spelling of address: the unused low bits of its last base32
    character set. py-algorand-sdk decodes it to the same 32 bytes; the Go
    SDK refuses it."""
    value = _BASE32.index(address[-1])
    other = address[:-1] + _BASE32[value | 1]
    assert other != address and encoding.decode_address(other) == encoding.decode_address(address)
    return other


def program_address(program: bytes) -> str:
    return transaction.LogicSigAccount(program).address()


def rotating_payment(sender: str, first: int, last: int) -> transaction.PaymentTxn:
    """A payment from sender with the given validity rounds."""
    params = transaction.SuggestedParams(
        1000,
        first,
        last,
        base64.b64encode(_genesis_hash()).decode(),
        "testnet-v1.0",
        flat_fee=True,
    )
    return transaction.PaymentTxn(sender, params, fake_signer.test_address(42), 5000)


def encode_map(value: Dict[str, Any]) -> bytes:
    """Canonical msgpack of a decoded map."""
    return base64.b64decode(encoding.msgpack_encode(value))


def decode_map(raw: bytes) -> Dict[str, Any]:
    return msgpack.unpackb(raw, raw=False, strict_map_key=False)


def regroup(txns: List[transaction.Transaction]) -> None:
    """Recompute the group ID over txns, as a signer that changed a member
    would have to."""
    if len(txns) < 2:
        return
    for txn in txns:
        txn.group = None
    group_id = transaction.calculate_group_id(txns)
    for txn in txns:
        txn.group = group_id


def set_prepared(response: Dict[str, Any], txns: List[transaction.Transaction]) -> None:
    response["transactions"] = [encode_transaction(txn)[0] for txn in txns]


class RotatingSigner:
    """A fake signer holding one rotating account. It prepares and signs as
    the real one does, and lets a test alter either answer.

    ``prepare_errors`` and ``sign_errors`` are answered, in order, before any
    success; a None entry closes the connection with no answer.
    """

    def __init__(
        self,
        account: str,
        stage: int = 3,
        program: bytes = ROTATING_TEST_PROGRAM,
        dummies: int = 1,
        charge: int = 1000,
    ):
        self.account = account
        self.stage = stage
        self.program = program
        self.dummies = dummies
        self.charge = charge
        self.alter_prepare: Optional[Callable[[Dict[str, Any], List[Any]], None]] = None
        self.alter_sign: Optional[Callable[[Dict[str, Any], List[Dict[str, Any]]], None]] = None
        self.prepare_errors: List[Optional[Dict[str, str]]] = []
        self.sign_errors: List[Optional[Dict[str, str]]] = []
        self.error_status = 409
        self.extra_keys: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.paths: List[str] = []
        self.prepare_seen: List[transaction.Transaction] = []
        self.sign_requests: List[Dict[str, Any]] = []
        self.http = HTTPFake(self.app)

    def count(self, path: str) -> int:
        with self.lock:
            return sum(1 for seen in self.paths if seen == path)

    def next_target(self) -> str:
        raw = bytearray(32)
        raw[0], raw[31] = 0xAA, (self.stage + 1) % 256
        return encoding.encode_address(bytes(raw))

    def _fail(self, queue: List[Optional[Dict[str, str]]]) -> Any:
        with self.lock:
            if not queue:
                return None
            failure = queue.pop(0)
        if failure is None:
            return DROP
        status = 400 if failure.get("code") == "bad_request" else self.error_status
        return reply(status, failure)

    def app(self, method: str, path: str, body: bytes) -> Any:
        with self.lock:
            self.paths.append(path)
        if path == "/status":
            return reply(200, status_body())
        if path == "/keys":
            keys = [key(self.account, "rotating1", key_type=ROTATING_KEY_TYPE)] + self.extra_keys
            return reply(200, {"count": len(keys), "keys": keys})
        if path == "/sign/cancel":
            return reply(200, {"success": True, "state": "canceled"})
        if path == "/sign/rotating/prepare":
            request = json.loads(body)
            raw = bytes.fromhex(request["txn_bytes_hex"])
            txn = encoding.msgpack_decode(base64.b64encode(raw[2:]).decode())
            with self.lock:
                self.prepare_seen.append(txn)
            failure = self._fail(self.prepare_errors)
            if failure is not None:
                return failure
            response, txns = self.prepare(txn)
            if self.alter_prepare is not None:
                self.alter_prepare(response, txns)
            return reply(200, response)
        if path == "/sign/rotating/sign":
            request = json.loads(body)
            with self.lock:
                self.sign_requests.append(request)
            failure = self._fail(self.sign_errors)
            if failure is not None:
                return failure
            response, signed = self.sign_group(request)
            if self.alter_sign is not None:
                self.alter_sign(response, signed)
            return reply(200, response)
        raise AssertionError(f"unexpected signer path {path}")

    def prepare(self, original: transaction.Transaction) -> tuple:
        """The group the real signer would build: the spend with the
        rotation rekey and the authorization charge, then canonical dummies,
        grouped."""
        spend = copy.deepcopy(original)
        spend.rekey_to = self.next_target()
        spend.fee += self.charge
        txns = [spend] + [_canonical_dummy_txn(original, None, i) for i in range(self.dummies)]
        report: Optional[Dict[str, Any]] = None
        if self.dummies or self.charge:
            report = {
                "original_count": 1,
                "final_count": len(txns),
                "dummies_added": self.dummies,
            }
            if self.charge:
                report["fees_modified"] = [0]
                report["total_fees_delta"] = self.charge
        if len(txns) > 1:
            regroup(txns)
            assert report is not None  # dummies were added
            report["group_id_changed"] = True
        response: Dict[str, Any] = {
            "account": self.account,
            "stage": self.stage,
            "target": self.stage + 1,
            "rekey_to": self.next_target(),
            "mutations": report,
        }
        set_prepared(response, txns)
        return response, txns

    def sign_group(self, request: Dict[str, Any]) -> tuple:
        """Sign the prepared group: the spend by the stage program, naming it
        as the signer unless it is the account itself, and each dummy by the
        dummy program. ``signed`` is the decoded maps, for tests to alter."""
        signed = []
        for index, txn_hex in enumerate(request["transactions"]):
            raw = bytes.fromhex(txn_hex)
            txn = encoding.msgpack_decode(base64.b64encode(raw[2:]).decode())
            if index == 0:
                stxn = transaction.LogicSigTransaction(
                    txn, transaction.LogicSigAccount(self.program, [b"\x01\x02\x03"])
                )
            else:
                stxn = transaction.LogicSigTransaction(
                    txn, transaction.LogicSigAccount(COSIGNED_DUMMY_PROGRAM)
                )
            signed.append(decode_map(base64.b64decode(encoding.msgpack_encode(stxn))))
        spend = encoding.msgpack_decode(
            base64.b64encode(bytes.fromhex(request["transactions"][0])[2:]).decode()
        )
        response: Dict[str, Any] = {
            "stage": self.stage,
            "target": self.stage + 1,
            "txid": spend.get_txid(),
            "group_id": base64.b64encode(spend.group or bytes(32)).decode(),
        }
        set_signed(response, signed)
        return response, signed


def set_signed(response: Dict[str, Any], signed: List[Dict[str, Any]]) -> None:
    response["signed"] = [encode_map(item).hex() for item in signed]


def refusal(code: str, message: str) -> Dict[str, str]:
    return {"error": message, "code": code}
