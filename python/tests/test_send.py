# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Unified sending: send_prepared, send_payment and the submission layer.

A port of the Go SDK's send_test.go. The signer and algod are local HTTP
fakes (tests/send_fakes.py), so a send goes through the SDK's real transport
and a real AlgodClient.
"""

import base64
import copy
import json

import msgpack
import pytest
from algosdk import encoding, transaction

from aplanesdk import (
    KEY_TYPE_WITNESS_FALCON1024,
    SEND_OUTCOME_CONFIRMED,
    SEND_OUTCOME_SUBMITTED,
    SEND_STAGE_CONFIRM,
    SEND_STAGE_SUBMIT,
    SIGNING_FLOW_BOUNDED1,
    SIGNING_FLOW_COSIGNED1,
    SIGNING_FLOW_ROTATING1,
    KeyNotFoundError,
    PreparedGroup,
    PreparedTransaction,
    SignerError,
    SigningRejectedError,
    SignOutcomeUnknownError,
    SubmissionRejectedError,
    SubmissionUncertainError,
    UnsupportedGroupError,
    UnsupportedSigningFlowError,
)
from aplanesdk import signer as signer_module
from aplanesdk.signer import COSIGNED_DUMMY_PROGRAM, _UINT64_MAX
from tests import fake_signer
from tests.send_fakes import (
    DROP,
    FakeNode,
    HTTPFake,
    RotatingSigner,
    SendSigner,
    alternate_spelling,
    key,
    reply,
    rotating_payment,
    signer_client,
    status_body,
    truncated,
)


@pytest.fixture
def fakes():
    """Register fakes to be closed when the test ends."""
    made = []

    def track(fake):
        made.append(fake)
        return fake

    yield track
    for fake in made:
        fake.http.close()


def ordinary_key(txn):
    return key(txn.sender)


def prepared_for(txn):
    return PreparedGroup([PreparedTransaction(transaction=txn, auth_address=txn.sender)])


def make(fakes, signer, node=None):
    signer = fakes(signer)
    node = fakes(node or FakeNode())
    return signer, node, signer_client(signer.http.url)


def signed_hex(txn):
    return fake_signer.signed_hex(txn)


def decode_first(blob):
    unpacker = msgpack.Unpacker(raw=False)
    unpacker.feed(blob)
    return encoding.msgpack_decode(next(unpacker))


def test_send_prepared_signs_submits_and_confirms(fakes):
    txn = fake_signer.payment(41, 42)
    signer, node, client = make(fakes, SendSigner([ordinary_key(txn)]))

    result = client.send_prepared(node.client, prepared_for(txn))

    want_hex = signed_hex(txn)
    assert result.signed_group == [want_hex]
    assert [blob.hex() for blob in node.submissions()] == [want_hex]
    assert result.outcome == SEND_OUTCOME_CONFIRMED and result.confirmed_round == 12
    assert result.flow == "" and result.original_count == 1 and result.group_id == ""
    assert result.tx_ids == [txn.get_txid()]
    assert result.fees == [1000]
    assert signer.count("/sign") == 1


def test_send_prepared_accepts_one_prepared_transaction(fakes):
    txn = fake_signer.payment(41, 42)
    signer, node, client = make(fakes, SendSigner([ordinary_key(txn)]))
    result = client.send_prepared(
        node.client, PreparedTransaction(transaction=txn, auth_address=txn.sender)
    )
    assert result.tx_ids == [txn.get_txid()]


def test_send_prepared_group_reports_group_id(fakes):
    first = fake_signer.payment(41, 42)
    second = fake_signer.payment(43, 44, amount=2)
    signer, node, client = make(fakes, SendSigner([ordinary_key(first), ordinary_key(second)]))

    group = PreparedGroup(
        [
            PreparedTransaction(transaction=first, auth_address=first.sender),
            PreparedTransaction(transaction=second, auth_address=second.sender),
        ]
    )
    result = client.send_prepared(node.client, group)

    assert len(result.signed_group) == 2 and result.original_count == 2 and result.group_id
    # The signer assigned the group, so the signed IDs are not the drafts'.
    assert result.tx_ids[0] != first.get_txid()
    assert [blob.hex() for blob in node.submissions()] == ["".join(result.signed_group)]


def test_send_prepared_no_wait_returns_submitted(fakes):
    txn = fake_signer.payment(41, 42)
    signer, node, client = make(fakes, SendSigner([ordinary_key(txn)]))

    result = client.send_prepared(node.client, prepared_for(txn), no_wait=True)

    assert result.outcome == SEND_OUTCOME_SUBMITTED and result.confirmed_round == 0
    assert node.lookups == 0


def _refusal_cases():
    txn = fake_signer.payment(41, 42)
    other = fake_signer.payment(45, 46)
    sender, holder = txn.sender, other.sender
    signed_base64 = base64.b64encode(bytes.fromhex(signed_hex(txn))).decode()
    return [
        (
            "rotating sender in a group",
            [key(sender, SIGNING_FLOW_ROTATING1), key(holder)],
            PreparedGroup(
                [
                    PreparedTransaction(transaction=txn, auth_address=sender),
                    PreparedTransaction(transaction=other, auth_address=holder),
                ]
            ),
            UnsupportedGroupError,
            "sends one transaction alone",
        ),
        (
            # After a rotation the chain names a stage address, which the
            # signer does not hold; the sender's own record decides.
            "rotating sender bound to a key the signer does not hold",
            [key(sender, SIGNING_FLOW_ROTATING1)],
            PreparedGroup([PreparedTransaction(transaction=txn, auth_address=holder)]),
            UnsupportedGroupError,
            "signs as itself",
        ),
        (
            "rekeyed to a rotating account",
            [key(holder, SIGNING_FLOW_ROTATING1)],
            PreparedGroup([PreparedTransaction(transaction=txn, auth_address=holder)]),
            UnsupportedGroupError,
            "signs only its own transactions",
        ),
        (
            "unknown flow",
            [key(sender, "future9")],
            prepared_for(txn),
            UnsupportedSigningFlowError,
            "upgrade the SDK",
        ),
        (
            "unknown flow beside a cosigned account",
            [key(sender, SIGNING_FLOW_COSIGNED1), key(holder, "future9")],
            PreparedGroup(
                [
                    PreparedTransaction(transaction=txn, auth_address=sender),
                    PreparedTransaction(transaction=other, auth_address=holder),
                ]
            ),
            UnsupportedSigningFlowError,
            "upgrade the SDK",
        ),
        (
            "pre-signed position",
            [key(sender)],
            PreparedGroup([PreparedTransaction(signed_transaction_base64=signed_base64)]),
            UnsupportedGroupError,
            "already signed",
        ),
        (
            "foreign position",
            [key(sender)],
            PreparedGroup([PreparedTransaction(transaction=txn)]),
            UnsupportedGroupError,
            "no auth address",
        ),
        (
            "key not held",
            [key(holder)],
            prepared_for(txn),
            KeyNotFoundError,
            "not available for signing",
        ),
        (
            "witness record is not a spending key",
            [key(sender, is_spending_account=False)],
            prepared_for(txn),
            KeyNotFoundError,
            "not available for signing",
        ),
    ]


@pytest.mark.parametrize(
    "keys,group,want,text",
    [case[1:] for case in _refusal_cases()],
    ids=[case[0] for case in _refusal_cases()],
)
def test_send_prepared_refuses_before_signing(fakes, keys, group, want, text):
    signer, node, client = make(fakes, SendSigner(keys))

    with pytest.raises(want, match=text):
        client.send_prepared(node.client, group)

    assert signer.count("/sign") == 0
    assert node.submissions() == []


@pytest.mark.parametrize(
    "first_flow,second_flow,want",
    [
        ("", SIGNING_FLOW_BOUNDED1, ""),
        (SIGNING_FLOW_COSIGNED1, "", SIGNING_FLOW_COSIGNED1),
        (SIGNING_FLOW_BOUNDED1, SIGNING_FLOW_COSIGNED1, SIGNING_FLOW_COSIGNED1),
    ],
    ids=["ordinary and bounded", "cosigned first", "cosigned last"],
)
def test_classify_send_routes_whole_group(fakes, first_flow, second_flow, want):
    first = fake_signer.payment(41, 42)
    second = fake_signer.payment(43, 44, amount=2)
    group = PreparedGroup(
        [
            PreparedTransaction(transaction=first, auth_address=first.sender),
            PreparedTransaction(transaction=second, auth_address=second.sender),
        ]
    )
    signer, _, client = make(
        fakes, SendSigner([key(first.sender, first_flow), key(second.sender, second_flow)])
    )
    assert client._classify_send(group) == (want, [])


def test_send_prepared_requires_algod_before_signer(fakes):
    txn = fake_signer.payment(41, 42)
    signer, _, client = make(fakes, SendSigner([ordinary_key(txn)]))

    with pytest.raises(ValueError, match="algod_client is required"):
        client.send_prepared(None, prepared_for(txn))

    assert signer.paths == []


class _Recorder:
    """A signer that records the paths it is asked for and answers any of
    them, so a test can tell what was posted."""

    def __init__(self):
        self.paths = []
        self.http = HTTPFake(self.app)

    def app(self, method, path, body):
        self.paths.append(path)
        if path == "/status":
            return reply(200, status_body())
        return reply(200, {"success": True, "state": "canceled"})


class TestABodyThatCannotBeEncoded:
    """A request whose body cannot be encoded was provably never posted: it
    is a plain error, with no /sign/cancel and no unknown outcome."""

    def test_a_send(self, fakes):
        txn = fake_signer.payment(41, 42)
        signer, node, client = make(fakes, SendSigner([ordinary_key(txn)]))
        group = PreparedGroup(
            [
                PreparedTransaction(
                    transaction=txn, auth_address=txn.sender, app_call_info={"m": float("nan")}
                )
            ]
        )
        with pytest.raises(ValueError, match="failed to encode sign request") as excinfo:
            client.send_prepared(node.client, group)
        assert not isinstance(excinfo.value, SignerError)
        assert signer.count("/sign") == 0 and signer.count("/sign/cancel") == 0

    def test_a_sign_request(self, fakes):
        recorder = fakes(_Recorder())
        client = signer_client(recorder.http.url)
        entries = fake_signer.sign_entries(fake_signer.payment(41, 42))
        entries[0]["app_call_info"] = {"method": float("inf")}
        with pytest.raises(ValueError, match="failed to encode sign request"):
            client.sign_requests(entries)
        assert "/sign" not in recorder.paths and "/sign/cancel" not in recorder.paths

    def test_a_component_request(self, fakes):
        recorder = fakes(_Recorder())
        client = signer_client(recorder.http.url)
        target = {
            "target_index": 0,
            "kind": "bounded-base",
            "auth_address": fake_signer.account(41),
            "app_call_info": {"method": float("nan")},
        }
        with pytest.raises(ValueError, match="failed to encode component request"):
            client.request_components({"group_bytes_hex": ["5458aa"], "targets": [target]})
        assert "/sign/component" not in recorder.paths and "/sign/cancel" not in recorder.paths

    def test_an_assembly_request(self, fakes):
        recorder = fakes(_Recorder())
        client = signer_client(recorder.http.url)
        target = {
            "target_index": 0,
            "kind": "bounded-cosigner",
            "auth_address": fake_signer.account(41),
            "base_signatures": ["aa"],
            "assembly_receipt": "bb",
            "bounded_runtime_args": {"a": float("nan")},
        }
        with pytest.raises(ValueError, match="failed to encode assembly request"):
            client.request_assemble({"group_bytes_hex": ["5458aa"], "targets": [target]})
        assert recorder.paths == []


class TestSendPreparedSignFailures:
    def test_no_answer_is_an_unknown_outcome(self, fakes):
        txn = fake_signer.payment(41, 42)
        signer, node, client = make(fakes, SendSigner([ordinary_key(txn)], sign=lambda _: DROP))

        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            client.send_prepared(node.client, prepared_for(txn))

        unknown = excinfo.value
        assert unknown.request_id
        assert [entry["auth_address"] for entry in unknown.requests] == [txn.sender]
        assert signer.count("/sign") == 1 and node.submissions() == []

    @pytest.mark.parametrize(
        "cancel_answer",
        [truncated(b"not json"), truncated(b"null"), reply(200, {"success": "yes"}), DROP],
    )
    def test_a_failed_cancel_neither_fails_nor_masks_the_send(self, fakes, cancel_answer):
        # The cancel a lost answer sends is best effort: however it fails, the
        # send reports the lost answer.
        txn = fake_signer.payment(41, 42)

        class CancelFails(SendSigner):
            def app(self, method, path, body):
                if path == "/sign/cancel":
                    with self.lock:
                        self.paths.append(path)
                    return cancel_answer
                return super().app(method, path, body)

        signer, node, client = make(
            fakes, CancelFails([ordinary_key(txn)], sign=lambda _: DROP)
        )
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            client.send_prepared(node.client, prepared_for(txn))

        assert "Failed to connect" in str(excinfo.value)
        assert signer.count("/sign/cancel") == 1 and node.submissions() == []

    def test_an_unreadable_answer_is_an_unknown_outcome(self, fakes):
        txn = fake_signer.payment(41, 42)
        signer, node, client = make(
            fakes, SendSigner([ordinary_key(txn)], sign=lambda _: truncated(b'{"signed": ["ab'))
        )

        with pytest.raises(SignOutcomeUnknownError):
            client.send_prepared(node.client, prepared_for(txn))

        assert node.submissions() == []

    def test_a_refusal_is_the_signers_error(self, fakes):
        txn = fake_signer.payment(41, 42)
        signer, node, client = make(
            fakes,
            SendSigner(
                [ordinary_key(txn)],
                sign=lambda _: reply(403, {"error": "rejected", "code": "forbidden"}),
            ),
        )

        with pytest.raises(SigningRejectedError) as excinfo:
            client.send_prepared(node.client, prepared_for(txn))

        assert not isinstance(excinfo.value, SignOutcomeUnknownError)
        assert node.submissions() == []

    def test_a_response_that_fails_verification_is_never_submitted(self, fakes):
        txn = fake_signer.payment(41, 42)
        altered = fake_signer.payment(41, 42, amount=999)
        signer, node, client = make(
            fakes,
            SendSigner(
                [ordinary_key(txn)], sign=lambda _: reply(200, {"signed": [signed_hex(altered)]})
            ),
        )

        with pytest.raises(SignerError, match="verify signer response"):
            client.send_prepared(node.client, prepared_for(txn))

        assert node.submissions() == []


def _http_error(status, message):
    return lambda _blob: reply(status, {"message": message})


@pytest.mark.parametrize(
    "node_options,options,rejected,stage,text",
    [
        ({"submit": _http_error(400, "overspend")}, {}, True, "", "overspend"),
        ({"submit": _http_error(500, "boom")}, {}, False, SEND_STAGE_SUBMIT, "boom"),
        (
            {"submit": lambda _blob: reply(200, {"txId": "SOMEOTHERID"})},
            {},
            False,
            SEND_STAGE_SUBMIT,
            "SOMEOTHERID",
        ),
        ({"pending": lambda: {"pool-error": "fee too low"}}, {}, True, "", "fee too low"),
        (
            {"pending": lambda: {}},
            {"wait_rounds": 2},
            False,
            SEND_STAGE_CONFIRM,
            "not confirmed after 2 rounds",
        ),
    ],
    ids=[
        "node refuses the group",
        "node fails without an answer about the group",
        "node reports another transaction ID",
        "pool drops the group",
        "not confirmed within the wait",
    ],
)
def test_send_prepared_submission_failures_keep_signed_bytes(
    fakes, node_options, options, rejected, stage, text
):
    txn = fake_signer.payment(41, 42)
    signer, node, client = make(fakes, SendSigner([ordinary_key(txn)]), FakeNode(**node_options))

    with pytest.raises((SubmissionRejectedError, SubmissionUncertainError)) as excinfo:
        client.send_prepared(node.client, prepared_for(txn), **options)

    error = excinfo.value
    if rejected:
        assert isinstance(error, SubmissionRejectedError)
    else:
        assert isinstance(error, SubmissionUncertainError) and error.stage == stage
    assert text in str(error)
    assert error.signed_group == [signed_hex(txn)] and error.tx_ids == [txn.get_txid()]
    # Nothing is signed or submitted a second time.
    assert signer.count("/sign") == 1 and len(node.submissions()) == 1


def test_send_payment_prepares_then_sends(fakes):
    sender = fake_signer.account(41)
    receiver = fake_signer.test_address(42)
    signer, node, client = make(fakes, SendSigner([key(sender)]))

    result = client.send_payment(node.client, sender=sender, receiver=receiver, amount=1_000_000)

    assert result.outcome == SEND_OUTCOME_CONFIRMED and len(node.submissions()) == 1
    sent = decode_first(node.submissions()[0]).transaction
    assert sent.sender == sender and sent.receiver == receiver and sent.amt == 1_000_000


def test_send_prepared_reports_what_the_signer_added(fakes):
    txn = fake_signer.payment(41, 42)
    signer, node, client = make(
        fakes, SendSigner([ordinary_key(txn)], fee_raise={0: 500}, dummies=1)
    )

    result = client.send_prepared(node.client, prepared_for(txn))

    assert result.original_count == 1 and len(result.signed_group) == 2
    assert len(result.tx_ids) == 2 and result.group_id
    assert result.fees == [1500, 0]
    assert result.mutations["dummies_added"] == 1 and result.mutations["total_fees_delta"] == 500
    assert result.tx_ids[0] != txn.get_txid()
    assert [blob.hex() for blob in node.submissions()] == ["".join(result.signed_group)]


class TestSendPreparedConfirmationWait:
    @pytest.mark.parametrize("rounds,waits", [(1, ["10"]), (3, ["10", "11", "12"])])
    def test_looks_once_now_and_once_after_each_round_of_the_wait(self, fakes, rounds, waits):
        txn = fake_signer.payment(41, 42)
        signer, node, client = make(
            fakes, SendSigner([ordinary_key(txn)]), FakeNode(pending=lambda: {})
        )

        with pytest.raises(SubmissionUncertainError) as excinfo:
            client.send_prepared(node.client, prepared_for(txn), wait_rounds=rounds)

        assert excinfo.value.stage == SEND_STAGE_CONFIRM
        assert node.lookups == rounds + 1
        # At round 10 the first wait follows round 10, so it ends when round
        # 11 exists; the wait covers exactly the next rounds.
        assert node.waits == waits

    def test_the_largest_wait_does_not_wrap_around(self, fakes):
        txn = fake_signer.payment(41, 42)
        lookups = []

        def pending():
            lookups.append(1)
            return {} if len(lookups) < 4 else {"confirmed-round": 13}

        signer, node, client = make(
            fakes, SendSigner([ordinary_key(txn)]), FakeNode(pending=pending)
        )
        result = client.send_prepared(node.client, prepared_for(txn), wait_rounds=_UINT64_MAX)
        assert result.confirmed_round == 13

    def test_a_wait_beyond_uint64_is_refused_before_signing(self, fakes):
        txn = fake_signer.payment(41, 42)
        signer, node, client = make(fakes, SendSigner([ordinary_key(txn)]))
        with pytest.raises(ValueError, match="wait_rounds"):
            client.send_prepared(node.client, prepared_for(txn), wait_rounds=_UINT64_MAX + 1)
        assert signer.paths == []


def test_submit_treats_an_already_known_group_as_submitted(fakes):
    txn = fake_signer.payment(41, 42)
    message = f"TransactionPool.Remember: transaction already in ledger: {txn.get_txid()}"
    signer, node, client = make(
        fakes, SendSigner([ordinary_key(txn)]), FakeNode(submit=_http_error(400, message))
    )

    # The node has these bytes from an earlier submission. That is not a
    # refusal: a caller told "rejected" might sign a replacement.
    result = client.send_prepared(node.client, prepared_for(txn))
    assert result.outcome == SEND_OUTCOME_CONFIRMED


def test_submit_connection_dropped_is_not_an_answer(fakes):
    txn = fake_signer.payment(41, 42)
    signer, node, client = make(
        fakes, SendSigner([ordinary_key(txn)]), FakeNode(submit=lambda _blob: DROP)
    )

    with pytest.raises(SubmissionUncertainError) as excinfo:
        client.send_prepared(node.client, prepared_for(txn))

    assert excinfo.value.stage == SEND_STAGE_SUBMIT
    assert excinfo.value.signed_group == [signed_hex(txn)]


def test_submit_signed_group_refuses_bytes_it_cannot_verify(fakes):
    txn = fake_signer.payment(41, 42)
    signer, node, client = make(fakes, SendSigner([ordinary_key(txn)]))
    with pytest.raises(SignerError, match="verify signed group"):
        client.submit_signed_group(node.client, [signed_hex(txn) + "00"])
    assert node.submissions() == []


def test_typed_send_errors_pickle_with_their_fields():
    import pickle

    rejected = SubmissionRejectedError(["aa"], ["ID"], SignerError("no"))
    uncertain = SubmissionUncertainError(
        SEND_STAGE_CONFIRM, ["aa"], ["ID"], SignerError("no"), last_valid=1000
    )
    unknown = SignOutcomeUnknownError(
        SignerError("gone"), request_id="r1", requests=[{}], last_valid=1000
    )
    for error in (rejected, uncertain, unknown):
        clone = pickle.loads(pickle.dumps(error))
        assert type(clone) is type(error) and str(clone) == str(error)
    assert pickle.loads(pickle.dumps(uncertain)).stage == SEND_STAGE_CONFIRM
    assert pickle.loads(pickle.dumps(unknown)).request_id == "r1"
    for error in (uncertain, unknown):
        assert pickle.loads(pickle.dumps(error)).last_valid == 1000


# -----------------------------------------------------------------------------
# Cosigned accounts
# -----------------------------------------------------------------------------


def _signed_group_for(group_bytes_hex):
    """Each frozen transaction signed by the dummy program: bytes that carry
    exactly the frozen transactions, which is all the checks look at."""
    signed = []
    for txn_hex in group_bytes_hex:
        txn = encoding.msgpack_decode(base64.b64encode(bytes.fromhex(txn_hex)[2:]).decode())
        stxn = transaction.LogicSigTransaction(
            txn, transaction.LogicSigAccount(COSIGNED_DUMMY_PROGRAM)
        )
        signed.append(base64.b64decode(encoding.msgpack_encode(stxn)).hex())
    return signed


class CosignedFixture:
    """A signer holding one cosigned account, its cosigner, and a node.
    ``fault`` names a user-signer path and how it fails: "<path> drop"
    closes the connection with no answer, "<path> truncate" answers 200 with
    a body cut short."""

    def __init__(self, fakes, fault="", cosigner_fault="", rekey_path=""):
        """``rekey_path``, when set, makes the transaction a rekey of an
        account with a rekey list, which the signer's base component answers
        with that path ("spending_rekey" or "listed_rekey")."""
        self.bounded = fake_signer.test_address(21)
        self.fault = fault
        self.cosigner_fault = cosigner_fault
        self.cosigner_calls = 0
        self.path = rekey_path or "spend"
        usage = {"program_bytes": 5308, "argument_bytes": 3358, "max_opcode_cost": 20000}
        authorization = {
            "contract": "bounded2",
            "max_fee": 1000,
            "rekey": "refused",
            "cosigner": {
                "component_key_type": KEY_TYPE_WITNESS_FALCON1024,
                "public_key_hex": "aabb",
            },
        }
        if rekey_path:
            authorization["rekey"] = "spending_key"
            authorization["rekey_list"] = {"contract": "rekey_list1", "depth": 4}
        bounded_key = key(
            self.bounded,
            SIGNING_FLOW_COSIGNED1,
            key_type="aplane.falcon1024.v1",
            logic_sig_resources={"spend": usage, "spending_rekey": usage, "listed_rekey": usage},
            cosigner_component_key_type=KEY_TYPE_WITNESS_FALCON1024,
            bounded_authorization=authorization,
        )
        self.keys = [bounded_key]
        self.user = fakes(_Fake(self.user_app))
        self.cosigner = fakes(_Fake(self.cosigner_app))
        self.node = fakes(FakeNode())
        self.user_client = signer_client(self.user.http.url)
        self.cosigner_client = signer_client(self.cosigner.http.url)
        params = transaction.SuggestedParams(
            1000, 1, 100, base64.b64encode(bytes(32)).decode(), "testnet-v1.0", flat_fee=True
        )
        self.txn = transaction.PaymentTxn(
            self.bounded,
            params,
            fake_signer.test_address(22),
            1000,
            rekey_to=fake_signer.test_address(23) if rekey_path else None,
        )

    def user_app(self, method, path, body):
        if self.fault == f"{path} drop":
            return DROP
        if self.fault == f"{path} truncate":
            return truncated(b'{"request_id": "x", "signed_gr')
        if path == "/status":
            return reply(200, status_body(approval_wait_seconds=60))
        if path == "/keys":
            return reply(200, {"count": len(self.keys), "keys": self.keys})
        if path == "/sign/cancel":
            return reply(200, {"success": True, "state": "canceled"})
        request = json.loads(body)
        if path == "/plan":
            return reply(200, fake_signer.plan_response(request["requests"]))
        if path == "/sign":
            return reply(200, fake_signer.sign_response(request["requests"]))
        if path == "/sign/component":
            return reply(
                200,
                {
                    "request_id": request["request_id"],
                    "components": [
                        {
                            "target_index": 0,
                            "kind": "bounded-base",
                            "auth_address": self.bounded,
                            "base_signatures": ["base-sig"],
                            "runtime_args": {"proof": "aabb"},
                            "assembly_receipt": "receipt",
                            "signature_scheme": "aplane.falcon1024.v1",
                            "path": self.path,
                        }
                    ],
                },
            )
        if path == "/sign/assemble":
            return reply(
                200,
                {
                    "request_id": request["request_id"],
                    "signed_group": _signed_group_for(request["group_bytes_hex"]),
                },
            )
        raise AssertionError(f"unexpected user path {path}")

    def cosigner_app(self, method, path, body):
        self.cosigner_calls += 1
        if self.cosigner_fault == "drop":
            return DROP
        if self.cosigner_fault == "truncate":
            return truncated(b'{"request_id": "x", "compon')
        request = json.loads(body)
        assert request["targets"][0]["component_key"] == "COSIGNER_COMPONENT"
        return reply(
            200,
            {
                "request_id": request["request_id"],
                "components": [
                    {
                        "kind": "cosigner",
                        "target_index": 0,
                        "signature": "cosigner-sig",
                        "signature_scheme": KEY_TYPE_WITNESS_FALCON1024,
                    }
                ],
            },
        )

    def send(self, **options):
        return self.user_client.send_prepared(self.node.client, prepared_for(self.txn), **options)


class _Fake:
    """An HTTPFake with the .http attribute the fakes fixture closes, and the
    paths it was asked for."""

    def __init__(self, app):
        self.paths = []
        # The request ID each request named, by path, in order.
        self.request_ids = {}

        def record(method, path, body):
            self.paths.append(path)
            try:
                request_id = json.loads(body).get("request_id")
            except (ValueError, AttributeError):
                request_id = None
            if request_id:
                self.request_ids.setdefault(path, []).append(request_id)
            return app(method, path, body)

        self.http = HTTPFake(record)


def test_send_prepared_cosigned_group(fakes):
    fixture = CosignedFixture(fakes)

    result = fixture.send(
        cosigner_client=fixture.cosigner_client, cosigner_component_key="COSIGNER_COMPONENT"
    )

    assert result.flow == SIGNING_FLOW_COSIGNED1
    assert result.cosigned is not None and result.cosigned.bounded_assembly_response is not None
    assert fixture.cosigner_calls == 1
    assert [blob.hex() for blob in fixture.node.submissions()] == ["".join(result.signed_group)]
    assert result.outcome == SEND_OUTCOME_CONFIRMED
    assert result.tx_ids[0] == fixture.txn.get_txid() and result.fees[0] == 1000


def test_send_prepared_cosigned_without_a_cosigner_is_refused(fakes):
    fixture = CosignedFixture(fakes)

    with pytest.raises(SignerError, match="cosigner_client or cosigner_resolver is required") as e:
        fixture.send()

    assert not isinstance(e.value, SignOutcomeUnknownError)
    assert fixture.node.submissions() == []


@pytest.mark.parametrize(
    "fault,unknown",
    [
        # Approval-bearing steps: the signer may have acted.
        ("/sign/component drop", True),
        ("/sign/component truncate", True),
        ("/sign/assemble drop", True),
        ("/sign/assemble truncate", True),
        # Planning releases nothing, so its failure is a plain error.
        ("/plan drop", False),
        ("/plan truncate", False),
    ],
)
def test_send_prepared_cosigned_lost_answers(fakes, fault, unknown):
    fixture = CosignedFixture(fakes, fault)

    with pytest.raises(SignerError) as excinfo:
        fixture.send(
            cosigner_client=fixture.cosigner_client, cosigner_component_key="COSIGNER_COMPONENT"
        )

    assert isinstance(excinfo.value, SignOutcomeUnknownError) is unknown
    if unknown:
        # It names the request whose answer was lost, as the audit log does.
        path = fault.split()[0]
        assert excinfo.value.request_id == fixture.user.request_ids[path][-1]
        assert excinfo.value.request_id in str(excinfo.value)
    assert fixture.node.submissions() == []


@pytest.mark.parametrize("fault", ["drop", "truncate"])
def test_send_prepared_cosigned_lost_cosigner_answer_names_its_request(fakes, fault):
    fixture = CosignedFixture(fakes, cosigner_fault=fault)

    with pytest.raises(SignOutcomeUnknownError) as excinfo:
        fixture.send(
            cosigner_client=fixture.cosigner_client, cosigner_component_key="COSIGNER_COMPONENT"
        )

    assert excinfo.value.request_id == fixture.cosigner.request_ids["/sign/component"][0]
    assert fixture.node.submissions() == []


def test_send_prepared_cosigned_lost_primary_sign_is_an_unknown_outcome(fakes):
    """The /sign of the group's other positions is approval-bearing too."""
    fixture = CosignedFixture(fakes, "/sign drop")
    holder = fake_signer.account(45)
    fixture.keys.append(key(holder))
    params = transaction.SuggestedParams(
        1000, 1, 100, base64.b64encode(bytes(32)).decode(), "testnet-v1.0", flat_fee=True
    )
    other = transaction.PaymentTxn(holder, params, fake_signer.test_address(22), 1)
    group = PreparedGroup(
        [
            PreparedTransaction(transaction=fixture.txn, auth_address=fixture.bounded),
            PreparedTransaction(transaction=other, auth_address=holder),
        ]
    )

    with pytest.raises(SignOutcomeUnknownError) as excinfo:
        fixture.user_client.send_prepared(
            fixture.node.client,
            group,
            cosigner_client=fixture.cosigner_client,
            cosigner_component_key="COSIGNER_COMPONENT",
        )
    assert excinfo.value.request_id == fixture.user.request_ids["/sign"][0]
    assert fixture.user.paths.count("/sign") == 1
    assert fixture.cosigner_calls == 0
    assert fixture.node.submissions() == []


# -----------------------------------------------------------------------------
# A fault after a 200: the checks raised something that is not a refusal
# -----------------------------------------------------------------------------


class TestAFaultAfterTheSignerAnswered:
    """Once an approval-bearing request has answered 200, its signature is
    out. An exception in checking, decoding or describing what it answered
    with, one that is not the SDK's own refusal, leaves the outcome unknown:
    the send raises SignOutcomeUnknownError naming the request. A refusal by
    the checks stays a plain error."""

    BOOM = RuntimeError("checker blew up")

    def _cosigned_send(self, fixture):
        return fixture.send(
            cosigner_client=fixture.cosigner_client, cosigner_component_key="COSIGNER_COMPONENT"
        )

    def test_in_the_sign_checks(self, fakes, monkeypatch):
        txn = fake_signer.payment(41, 42)
        signer, node, client = make(fakes, _RecordingSendSigner([ordinary_key(txn)]))
        monkeypatch.setattr(
            "aplanesdk.signer._validate_group_mutations", _raises(self.BOOM)
        )
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            client.send_prepared(node.client, prepared_for(txn))
        unknown = excinfo.value
        assert unknown.request_id == signer.request_ids[0]
        assert [entry["auth_address"] for entry in unknown.requests] == [txn.sender]
        assert "the check itself failed with RuntimeError: checker blew up" in str(unknown)
        assert _caused_by(unknown, self.BOOM) and node.submissions() == []

    def test_in_describing_the_signed_group(self, fakes, monkeypatch):
        txn = fake_signer.payment(41, 42)
        signer, node, client = make(fakes, _RecordingSendSigner([ordinary_key(txn)]))
        monkeypatch.setattr(
            "aplanesdk.signer._decode_executable_signed_group", _raises(self.BOOM)
        )
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            client.send_prepared(node.client, prepared_for(txn))
        assert excinfo.value.request_id == signer.request_ids[0]
        assert excinfo.value.requests is not None
        assert _caused_by(excinfo.value, self.BOOM) and node.submissions() == []

    def test_a_refusal_in_describing_stays_a_refusal(self, fakes, monkeypatch):
        txn = fake_signer.payment(41, 42)
        signer, node, client = make(fakes, SendSigner([ordinary_key(txn)]))
        monkeypatch.setattr(
            "aplanesdk.signer._decode_executable_signed_group",
            _raises(SignerError("signed group position 1 is empty")),
        )
        with pytest.raises(SignerError, match="verify signed group") as excinfo:
            client.send_prepared(node.client, prepared_for(txn))
        assert not isinstance(excinfo.value, SignOutcomeUnknownError)

    @pytest.mark.parametrize(
        "patched,path",
        [
            ("_validate_component_response", "/sign/component"),
            ("_validate_assembly_response", "/sign/assemble"),
            ("_verify_bounded_assembled_group", "/sign/assemble"),
            ("_decode_executable_signed_group", "/sign/assemble"),
        ],
    )
    def test_in_the_cosigned_sequence(self, fakes, monkeypatch, patched, path):
        fixture = CosignedFixture(fakes)
        monkeypatch.setattr(f"aplanesdk.signer.{patched}", _raises(self.BOOM))
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            self._cosigned_send(fixture)
        assert excinfo.value.request_id == fixture.user.request_ids[path][-1]
        assert _caused_by(excinfo.value, self.BOOM)
        assert fixture.node.submissions() == []

    def test_in_checking_the_cosigned_primary_sign(self, fakes, monkeypatch):
        fixture = CosignedFixture(fakes)
        holder = fake_signer.account(45)
        fixture.keys.append(key(holder))
        params = transaction.SuggestedParams(
            1000, 1, 100, base64.b64encode(bytes(32)).decode(), "testnet-v1.0", flat_fee=True
        )
        other = transaction.PaymentTxn(holder, params, fake_signer.test_address(22), 1)
        group = PreparedGroup(
            [
                PreparedTransaction(transaction=fixture.txn, auth_address=fixture.bounded),
                PreparedTransaction(transaction=other, auth_address=holder),
            ]
        )
        monkeypatch.setattr(
            "aplanesdk.signer._verify_signed_transaction_matches_canonical", _raises(self.BOOM)
        )
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            fixture.user_client.send_prepared(
                fixture.node.client,
                group,
                cosigner_client=fixture.cosigner_client,
                cosigner_component_key="COSIGNER_COMPONENT",
            )
        assert excinfo.value.request_id == fixture.user.request_ids["/sign"][0]
        assert _caused_by(excinfo.value, self.BOOM) and fixture.cosigner_calls == 0

    def _with_primary(self, fixture):
        """The fixture's cosigned spend and an ordinary position the user
        signer signs with /sign."""
        holder = fake_signer.account(45)
        fixture.keys.append(key(holder))
        params = transaction.SuggestedParams(
            1000, 1, 100, base64.b64encode(bytes(32)).decode(), "testnet-v1.0", flat_fee=True
        )
        other = transaction.PaymentTxn(holder, params, fake_signer.test_address(22), 1)
        return PreparedGroup(
            [
                PreparedTransaction(transaction=fixture.txn, auth_address=fixture.bounded),
                PreparedTransaction(transaction=other, auth_address=holder),
            ]
        )

    @pytest.mark.parametrize(
        "patched,boom,answered",
        [
            # Between the base components' answer and the cosigner's request.
            ("_component_path_resources", TypeError("bad path table"), "user component"),
            ("_component_request_for_indices", KeyError("targets"), "user component"),
            # After the cosigner answered: the last answer is the cosigner's.
            ("_component_signatures_by_index", KeyError("signature"), "cosigner component"),
            ("_sign_cosigned_dummies", AttributeError("no fee"), "cosigner component"),
            ("AssemblyTarget", TypeError("bad target"), "cosigner component"),
        ],
    )
    def test_between_the_cosigned_requests(self, fakes, monkeypatch, patched, boom, answered):
        # A fault between the sequence's requests, once one has answered 200,
        # is the last answered request's lost answer.
        fixture = CosignedFixture(fakes)
        monkeypatch.setattr(f"aplanesdk.signer.{patched}", _raises(boom))
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            self._cosigned_send(fixture)
        source = fixture.user if answered == "user component" else fixture.cosigner
        assert excinfo.value.request_id == source.request_ids["/sign/component"][-1]
        assert excinfo.value.request_id in str(excinfo.value)
        assert f"the check itself failed with {type(boom).__name__}" in str(excinfo.value)
        assert _caused_by(excinfo.value, boom)
        assert "/sign/assemble" not in fixture.user.paths and fixture.node.submissions() == []

    def test_between_the_cosigned_requests_after_the_primary_sign(self, fakes, monkeypatch):
        # With an ordinary position, the primary /sign is the last answer
        # before the cosigner is asked.
        fixture = CosignedFixture(fakes)
        group = self._with_primary(fixture)
        monkeypatch.setattr(
            "aplanesdk.signer._component_request_for_indices", _raises(self.BOOM)
        )
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            fixture.user_client.send_prepared(
                fixture.node.client,
                group,
                cosigner_client=fixture.cosigner_client,
                cosigner_component_key="COSIGNER_COMPONENT",
            )
        assert excinfo.value.request_id == fixture.user.request_ids["/sign"][0]
        assert _caused_by(excinfo.value, self.BOOM) and fixture.cosigner_calls == 0

    def test_a_refusal_between_the_cosigned_requests_stays_a_refusal(self, fakes, monkeypatch):
        fixture = CosignedFixture(fakes)
        monkeypatch.setattr(
            "aplanesdk.signer._component_path_resources",
            _raises(SignerError("signer key publishes no LogicSig resources")),
        )
        with pytest.raises(SignerError, match="publishes no LogicSig resources") as excinfo:
            self._cosigned_send(fixture)
        assert not isinstance(excinfo.value, SignOutcomeUnknownError)
        assert type(excinfo.value) is SignerError

    def test_a_fault_before_any_cosigned_answer_is_raised_as_itself(self, fakes, monkeypatch):
        # Nothing approval-bearing has answered: nothing can be out.
        fixture = CosignedFixture(fakes)
        monkeypatch.setattr(
            "aplanesdk.signer._validate_bounded_target_fees", _raises(self.BOOM)
        )
        with pytest.raises(RuntimeError) as excinfo:
            self._cosigned_send(fixture)
        assert excinfo.value is self.BOOM
        assert "/sign/component" not in fixture.user.paths

    def test_a_cosigner_resolver_fault_is_raised_as_itself(self, fakes):
        # The caller's resolver raised it, not the SDK, so it is no fault of
        # the sequence's. A spend's cosigner is resolved before anything is
        # asked to sign.
        fixture = CosignedFixture(fakes)
        with pytest.raises(LookupError, match="no cosigner") as excinfo:
            fixture.send(cosigner_resolver=_raises(LookupError("no cosigner for this account")))
        assert not isinstance(excinfo.value, SignerError)
        assert "/sign/component" not in fixture.user.paths and fixture.cosigner_calls == 0

    def test_a_late_cosigner_resolver_fault_is_raised_as_itself(self, fakes):
        # A rekey that could have taken the listed path is resolved only
        # after its base component answered, and its resolver's fault is
        # still no fault of the sequence's.
        fixture = CosignedFixture(fakes, rekey_path="spending_rekey")
        with pytest.raises(LookupError, match="no cosigner") as excinfo:
            fixture.send(cosigner_resolver=_raises(LookupError("no cosigner for this account")))
        assert not isinstance(excinfo.value, SignerError)
        assert "/sign/component" in fixture.user.paths and fixture.cosigner_calls == 0

    @pytest.mark.parametrize("rekey_path", ["", "spending_rekey"], ids=["up front", "late"])
    def test_a_resolver_error_raised_from_a_lost_answer_is_its_own(self, fakes, rekey_path):
        # What the resolver raises is never an unknown outcome, even when it
        # was raised from one of the SDK's lost-answer marks; it comes back
        # unchanged.
        fixture = CosignedFixture(fakes, rekey_path=rekey_path)

        def resolver(_target):
            try:
                raise signer_module._AnswerLostError("lost", request_id="other-request")
            except signer_module._AnswerLostError as lost:
                raise SignerError("cosigner lookup failed") from lost

        with pytest.raises(SignerError, match="^cosigner lookup failed$") as excinfo:
            fixture.send(cosigner_resolver=resolver)
        assert type(excinfo.value) is SignerError
        assert isinstance(excinfo.value.__cause__, signer_module._AnswerLostError)
        assert fixture.cosigner_calls == 0
        assert ("/sign/component" in fixture.user.paths) == bool(rekey_path)

    def test_an_interrupt_between_the_cosigned_requests_is_not_caught(self, fakes, monkeypatch):
        fixture = CosignedFixture(fakes)
        monkeypatch.setattr("aplanesdk.signer._sign_cosigned_dummies", _raises(KeyboardInterrupt()))
        with pytest.raises(KeyboardInterrupt):
            self._cosigned_send(fixture)

    def test_a_cosigned_refusal_stays_a_refusal(self, fakes, monkeypatch):
        fixture = CosignedFixture(fakes)
        monkeypatch.setattr(
            "aplanesdk.signer._verify_bounded_assembled_group",
            _raises(SignerError("assembled transaction 0 does not match")),
        )
        with pytest.raises(SignerError, match="does not match") as excinfo:
            self._cosigned_send(fixture)
        assert not isinstance(excinfo.value, SignOutcomeUnknownError)

    def test_an_interrupt_is_not_caught(self, fakes, monkeypatch):
        txn = fake_signer.payment(41, 42)
        signer, node, client = make(fakes, SendSigner([ordinary_key(txn)]))
        monkeypatch.setattr(
            "aplanesdk.signer._decode_executable_signed_group", _raises(KeyboardInterrupt())
        )
        with pytest.raises(KeyboardInterrupt):
            client.send_prepared(node.client, prepared_for(txn))


def _raises(error):
    def fail(*_args, **_kwargs):
        raise error

    return fail


def _caused_by(error, cause):
    seen = error
    while seen is not None:
        if seen is cause:
            return True
        seen = seen.__cause__
    return False


class _RecordingSendSigner(SendSigner):
    """A SendSigner that records the request ID of each /sign."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.request_ids = []

    def app(self, method, path, body):
        if path == "/sign":
            self.request_ids.append(json.loads(body)["request_id"])
        return super().app(method, path, body)


# -----------------------------------------------------------------------------
# A rotating account that left rotation
# -----------------------------------------------------------------------------


class TestAccountThatLeftRotation:
    """A rotating account rekeyed to an ordinary key the signer holds has left
    rotation: that key signs for it through the ordinary flow, once the chain
    confirms the rekey."""

    def setup_method(self):
        self.txn = fake_signer.payment(41, 42)
        self.sender = self.txn.sender
        self.holder = fake_signer.account(45)
        self.keys = [key(self.sender, SIGNING_FLOW_ROTATING1), key(self.holder)]
        self.group = PreparedGroup(
            [PreparedTransaction(transaction=self.txn, auth_address=self.holder)]
        )

    def test_the_chain_confirms_the_rekey(self, fakes):
        signer, node, client = make(
            fakes, SendSigner(self.keys), FakeNode(auth_addrs={self.sender: self.holder})
        )
        result = client.send_prepared(node.client, self.group)
        assert result.flow == "" and signer.count("/sign") == 1
        sent = decode_first(node.submissions()[0])
        assert sent.authorizing_address == self.holder

    @pytest.mark.parametrize(
        "chain_auth", ["", fake_signer.test_address(77)], ids=["still at stage 0", "rotated"]
    )
    def test_refused_while_the_account_is_still_rotating(self, fakes, chain_auth):
        # A caller cannot have an ordinary key sign for an account that is
        # still rotating: nothing is asked of the signer.
        signer, node, client = make(
            fakes, SendSigner(self.keys), FakeNode(auth_addrs={self.sender: chain_auth})
        )
        with pytest.raises(UnsupportedGroupError, match="is not rekeyed to it"):
            client.send_prepared(node.client, self.group)
        assert signer.count("/sign") == 0 and node.submissions() == []

    def test_resolve_auth_address_names_the_held_key(self, fakes):
        signer, _, client = make(fakes, SendSigner(self.keys))
        resolved = client.resolve_auth_address(self.sender, lambda _: self.holder)
        assert resolved.auth_address == self.holder and resolved.is_rekeyed
        assert resolved.chain_auth_address == self.holder


# -----------------------------------------------------------------------------
# Addresses are compared in canonical form
# -----------------------------------------------------------------------------


def _respelled(txn, sender):
    """txn with its sender written as sender: the same 32 bytes on the wire."""
    txn = copy.deepcopy(txn)
    txn.sender = sender
    return txn


class TestAddressSpellings:
    """py-algorand-sdk accepts another spelling of an address, which decodes
    to the same 32 bytes; the Go SDK refuses it, and compares addresses in
    canonical form only."""

    def test_a_rotating_sender_spelled_otherwise_naming_a_held_key_is_refused(self, fakes):
        # Compared as written, the sender would not be found as a rotating
        # account: the chain check would be skipped and the ordinary key would
        # sign for an account that is still rotating.
        txn = fake_signer.payment(41, 42)
        holder = fake_signer.account(45)
        keys = [key(txn.sender, SIGNING_FLOW_ROTATING1), key(holder)]
        signer, node, client = make(fakes, SendSigner(keys))
        respelled = _respelled(txn, alternate_spelling(txn.sender))
        assert encoding.msgpack_encode(respelled) == encoding.msgpack_encode(txn)

        group = PreparedGroup([PreparedTransaction(transaction=respelled, auth_address=holder)])
        with pytest.raises(ValueError, match="not the canonical spelling"):
            client.send_prepared(node.client, group)

        assert signer.count("/sign") == 0 and node.submissions() == []

    def test_a_rotating_sender_and_auth_address_spelled_otherwise_are_refused(self, fakes):
        # The Go SDK cannot build a transaction from that spelling at all.
        signer = fakes(RotatingSigner(fake_signer.account(41)))
        node = fakes(FakeNode())
        client = signer_client(signer.http.url)
        other = alternate_spelling(signer.account)
        txn = _respelled(
            transaction.PaymentTxn(
                signer.account,
                transaction.SuggestedParams(
                    1000, 10, 110, base64.b64encode(bytes(32)).decode(), "t", flat_fee=True
                ),
                fake_signer.test_address(42),
                1,
            ),
            other,
        )
        group = PreparedGroup([PreparedTransaction(transaction=txn, auth_address=other)])

        with pytest.raises(ValueError, match="not the canonical spelling"):
            client.send_prepared(node.client, group)
        with pytest.raises(ValueError, match="not the canonical spelling"):
            client.prepare_rotating(txn)

        assert signer.count("/sign/rotating/prepare") == 0
        assert signer.count("/sign/rotating/sign") == 0 and node.submissions() == []

    def test_an_auth_address_spelled_otherwise_is_refused(self, fakes):
        # The Go SDK compares it with the signer's canonical records and
        # finds no key; its address decoding refuses it too.
        txn = fake_signer.payment(41, 42)
        signer, node, client = make(fakes, SendSigner([key(txn.sender)]))
        group = PreparedGroup(
            [PreparedTransaction(transaction=txn, auth_address=alternate_spelling(txn.sender))]
        )
        with pytest.raises(ValueError, match="not the canonical spelling"):
            client.send_prepared(node.client, group)
        assert signer.count("/sign") == 0

    def test_the_chain_check_compares_canonical_forms(self, fakes):
        # The account left rotation for the held key, and the node spells
        # that key otherwise: the same address, so the rekey is confirmed.
        txn = fake_signer.payment(41, 42)
        holder = fake_signer.account(45)
        keys = [key(txn.sender, SIGNING_FLOW_ROTATING1), key(holder)]
        signer, node, client = make(
            fakes, SendSigner(keys), FakeNode(auth_addrs={txn.sender: alternate_spelling(holder)})
        )
        group = PreparedGroup([PreparedTransaction(transaction=txn, auth_address=holder)])
        result = client.send_prepared(node.client, group)
        assert result.flow == "" and signer.count("/sign") == 1

    def test_resolve_auth_address(self, fakes):
        sender, holder = fake_signer.account(41), fake_signer.account(45)
        signer, _, client = make(
            fakes, SendSigner([key(sender, SIGNING_FLOW_ROTATING1), key(holder)])
        )
        with pytest.raises(ValueError, match="not the canonical spelling"):
            client.resolve_auth_address(alternate_spelling(sender), lambda _: "")
        # The chain's answer is compared in canonical form, and reported so.
        rekeyed = client.resolve_auth_address(sender, lambda _: alternate_spelling(holder))
        assert rekeyed.auth_address == holder and rekeyed.chain_auth_address == holder
        stage = fake_signer.test_address(77)
        rotated = client.resolve_auth_address(sender, lambda _: alternate_spelling(stage))
        assert rotated.auth_address == sender and rotated.chain_auth_address == stage

    def test_a_key_list_with_an_address_spelled_otherwise_is_refused(self, fakes):
        # Compared as written, a rotating record the signer spells otherwise
        # would not be found, and an ordinary key it names would sign for the
        # account without the chain check. The whole list is refused instead,
        # as the Go and TypeScript SDKs refuse it, and nothing is signed.
        txn = fake_signer.payment(41, 42)
        holder = fake_signer.account(45)
        respelled = alternate_spelling(txn.sender)
        keys = [key(holder), key(respelled, SIGNING_FLOW_ROTATING1)]
        signer, node, client = make(fakes, SendSigner(keys))
        with pytest.raises(SignerError) as refused:
            client.list_keys()
        assert str(refused.value) == (
            f'signer key list refused: key 1 address "{respelled}" is a non-canonical '
            f"spelling of address {txn.sender}"
        )

        group = PreparedGroup([PreparedTransaction(transaction=txn, auth_address=holder)])
        with pytest.raises(SignerError, match="signer key list refused") as excinfo:
            client.send_prepared(node.client, group)
        assert type(excinfo.value) is SignerError
        assert signer.count("/sign") == 0 and node.submissions() == []

    def test_a_key_address_that_is_not_an_address_is_kept_as_sent(self, fakes):
        # A witness key's record carries its 52-character Witness Key ID; any
        # string that is not an address is kept exactly, and matched only by
        # an exact lookup.
        txn = fake_signer.payment(41, 42)
        witness_id = "ROGAFDACF7ASC3EMZRWNKVM73NXHO4P6O4EB7ZXWER37SM63BMFQ"
        keys = [
            key(
                witness_id,
                key_type=KEY_TYPE_WITNESS_FALCON1024,
                is_witness_key=True,
                is_spending_account=False,
            ),
            key("PLACEHOLDER"),
            key(""),
            key(txn.sender.lower()),
            key(txn.sender),
        ]
        signer, node, client = make(fakes, SendSigner(keys))
        listed = [record.address for record in client.list_keys()]
        assert listed == [witness_id, "PLACEHOLDER", "", txn.sender.lower(), txn.sender]
        assert client.get_key_info(witness_id).is_witness_key is True

        result = client.send_prepared(node.client, prepared_for(txn))
        assert result.tx_ids == [txn.get_txid()]

    def test_a_sign_request_names_its_auth_address_canonically(self, fakes):
        txn = fake_signer.payment(41, 42)
        signer, _, client = make(fakes, SendSigner([key(txn.sender)]))
        with pytest.raises(ValueError, match="not the canonical spelling"):
            client.sign_transaction(txn, auth_address=alternate_spelling(txn.sender))
        assert signer.count("/sign") == 0


# -----------------------------------------------------------------------------
# A 200 answer of the wrong shape is an answer that could not be read
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        b"123",
        b'"ok"',
        b"[]",
        b'{"signed":"x"}',
        b'{"signed":[1]}',
        b'{"signed":[], "mutations":"x"}',
        b'{"signed":[], "mutations":{"dummies_added":"1"}}',
        b'{"signed":[], "mutations":{"fees_modified":[0.5]}}',
        b'{"signed":[], "error":5}',
    ],
)
def test_a_sign_answer_of_the_wrong_shape_is_an_unknown_outcome(fakes, body):
    # The Go SDK decodes the answer into typed structs, and this one does not
    # decode: it could not be read, and a signature may have been released.
    txn = fake_signer.payment(41, 42)
    signer, node, client = make(
        fakes, SendSigner([ordinary_key(txn)], sign=lambda _: (200, body, "application/json"))
    )
    with pytest.raises(SignOutcomeUnknownError) as excinfo:
        client.send_prepared(node.client, prepared_for(txn))
    assert excinfo.value.request_id and excinfo.value.requests
    assert node.submissions() == []


def test_a_well_typed_answer_that_fails_its_checks_is_a_refusal(fakes):
    txn = fake_signer.payment(41, 42)
    signer, node, client = make(
        fakes, SendSigner([ordinary_key(txn)], sign=lambda _: reply(200, {"signed": ["00"]}))
    )
    with pytest.raises(SignerError, match="verify signer response") as excinfo:
        client.send_prepared(node.client, prepared_for(txn))
    assert not isinstance(excinfo.value, SignOutcomeUnknownError)


@pytest.mark.parametrize(
    "path,body,unknown",
    [
        ("/sign/component", {"request_id": "x", "components": "none"}, True),
        ("/sign/component", {"request_id": "x", "components": [{"target_index": "0"}]}, True),
        ("/sign/assemble", {"request_id": 5, "signed_group": []}, True),
        ("/sign/assemble", {"request_id": "x", "signed_group": [7]}, True),
        # An error field that is not a string cannot be read either: it is
        # not taken as a refusal.
        ("/sign/component", {"request_id": "x", "components": [], "error": {"x": 1}}, True),
        ("/sign/component", {"request_id": "x", "components": [], "error": 5}, True),
        ("/sign/assemble", {"request_id": "x", "signed_group": [], "error": {"x": 1}}, True),
        ("/sign/assemble", {"request_id": "x", "signed_group": [], "error": 5}, True),
        # A string error is the signer's refusal.
        ("/sign/component", {"error": "refused"}, False),
        ("/sign/assemble", {"error": "refused"}, False),
        # Planning releases nothing: a malformed plan is a plain failure.
        ("/plan", {"transactions": "none"}, False),
    ],
)
def test_a_cosigned_step_answered_in_the_wrong_shape(fakes, path, body, unknown):
    fixture = CosignedFixture(fakes)
    app = fixture.user_app

    def user_app(method, request_path, request_body):
        if request_path == path:
            return reply(200, body)
        return app(method, request_path, request_body)

    fixture.user.http.server.app = user_app
    with pytest.raises(SignerError) as excinfo:
        fixture.send(
            cosigner_client=fixture.cosigner_client, cosigner_component_key="COSIGNER_COMPONENT"
        )
    assert isinstance(excinfo.value, SignOutcomeUnknownError) is unknown
    assert fixture.node.submissions() == []


# -----------------------------------------------------------------------------
# KeyboardInterrupt and other exceptions that are not Exceptions
# -----------------------------------------------------------------------------


def _interrupting_post(client, path, cancels):
    real_post = client.session.post

    def post(url, **kwargs):
        if url.endswith(path):
            raise KeyboardInterrupt
        if url.endswith("/sign/cancel"):
            cancels.append(kwargs["json"]["request_id"])
        return real_post(url, **kwargs)

    return post


def test_an_interrupt_while_a_sign_is_pending_cancels_it_and_propagates(fakes):
    txn = fake_signer.payment(41, 42)
    signer, node, client = make(fakes, SendSigner([ordinary_key(txn)]))
    cancels = []
    client.session.post = _interrupting_post(client, "/sign", cancels)

    with pytest.raises(KeyboardInterrupt) as excinfo:
        client.send_prepared(node.client, prepared_for(txn))

    assert len(cancels) == 1 and cancels[0].startswith("sdk-")
    assert excinfo.value.aplane_request_id == cancels[0]
    if hasattr(excinfo.value, "add_note"):
        assert any("aplane_request_id" in note for note in excinfo.value.__notes__)
    assert node.submissions() == []


def test_an_interrupt_while_a_component_is_pending_cancels_it_and_propagates(fakes):
    fixture = CosignedFixture(fakes)
    cancels = []
    fixture.user_client.session.post = _interrupting_post(
        fixture.user_client, "/sign/component", cancels
    )
    with pytest.raises(KeyboardInterrupt) as excinfo:
        fixture.send(
            cosigner_client=fixture.cosigner_client, cosigner_component_key="COSIGNER_COMPONENT"
        )
    assert len(cancels) == 1
    assert excinfo.value.aplane_request_id == cancels[0]


def test_an_interrupt_while_an_assembly_is_pending_names_it(fakes):
    # Assembly releases the whole group. It opens no approval, so nothing is
    # canceled, but the exception names the request.
    fixture = CosignedFixture(fakes)
    cancels = []
    real_post = fixture.user_client.session.post
    assembled = []

    def post(url, **kwargs):
        if url.endswith("/sign/assemble"):
            assembled.append(fake_signer.posted_json(kwargs)["request_id"])
            raise KeyboardInterrupt
        if url.endswith("/sign/cancel"):
            cancels.append(kwargs["json"]["request_id"])
        return real_post(url, **kwargs)

    fixture.user_client.session.post = post
    with pytest.raises(KeyboardInterrupt) as excinfo:
        fixture.send(
            cosigner_client=fixture.cosigner_client, cosigner_component_key="COSIGNER_COMPONENT"
        )
    assert excinfo.value.aplane_request_id == assembled[0] and cancels == []


class _Interrupting:
    """An algod client that raises KeyboardInterrupt from one method."""

    def __init__(self, client, method):
        self._client = client
        self._method = method

    def __getattr__(self, name):
        if name == self._method:

            def interrupt(*args, **kwargs):
                raise KeyboardInterrupt

            return interrupt
        return getattr(self._client, name)


@pytest.mark.parametrize("method", ["send_raw_transaction", "status", "pending_transaction_info"])
def test_an_interrupt_during_submission_carries_the_signed_group(fakes, method):
    # It still stops the program, but the group may be on the network, so the
    # exception keeps its bytes and IDs.
    txn = fake_signer.payment(41, 42)
    signer, node, client = make(fakes, SendSigner([ordinary_key(txn)]))

    with pytest.raises(KeyboardInterrupt) as excinfo:
        client.send_prepared(_Interrupting(node.client, method), prepared_for(txn))

    interrupt = excinfo.value
    assert interrupt.aplane_signed_group == [signed_hex(txn)]
    assert interrupt.aplane_tx_ids == [txn.get_txid()]
    if hasattr(interrupt, "add_note"):
        assert any("aplane_signed_group" in note for note in interrupt.__notes__)


# -----------------------------------------------------------------------------
# Checks the tests above would not notice missing
# -----------------------------------------------------------------------------


def test_signed_simulation_leaves_the_signers_to_the_signatures(fakes):
    # fix-signers and empty signatures are for the unsigned rotating
    # preflight only: a signed simulation has the node check every signature.
    txn = fake_signer.payment(41, 42)
    signer, node, client = make(fakes, SendSigner([ordinary_key(txn)]))
    client.simulate_prepared_group(node.client, prepared_for(txn))
    request = node.simulations()[0]
    assert "fix-signers" not in request and "allow-empty-signatures" not in request


ONE_RESULT = [{}]


@pytest.mark.parametrize(
    "answer,message",
    [
        ({}, "the node returned no result for the group"),
        ({"txn-groups": None}, "the node returned no result for the group"),
        ({"txn-groups": []}, "the node returned no result for the group"),
        ({"txn-groups": {}}, "the node returned no result for the group"),
        # The field is chosen by presence: an empty txn-groups is not
        # replaced by a txn_groups beside it.
        (
            {"txn-groups": [], "txn_groups": [{"txn-results": ONE_RESULT}]},
            "the node returned no result for the group",
        ),
        (
            {"txn-groups": [{"txn-results": ONE_RESULT}, {"txn-results": ONE_RESULT}]},
            "the node returned 2 results for one group",
        ),
        ({"txn-groups": [None]}, "the node's result for the group is not an object"),
        ({"txn-groups": [7]}, "the node's result for the group is not an object"),
        (
            {"txn-groups": [{"failure-message": "logic eval error", "txn-results": ONE_RESULT}]},
            "logic eval error",
        ),
        # A failure message is chosen by presence, and any value but empty
        # is a failure.
        (
            {"txn-groups": [{"failure-message": "", "failure_message": "x", "txn-results": ONE_RESULT}]},
            "",
        ),
        ({"txn-groups": [{"failure-message": 0, "txn-results": ONE_RESULT}]}, "0"),
        ({"txn-groups": [{"failure-message": False, "txn-results": ONE_RESULT}]}, "False"),
        (
            {"txn-groups": [{"failed-at": [0], "txn-results": ONE_RESULT}]},
            "the node reported a failure without a message",
        ),
        ({"txn-groups": [{}]}, "the node returned 0 transaction results for 1 transactions"),
        (
            {"txn-groups": [{"txn-results": [{}, {}]}]},
            "the node returned 2 transaction results for 1 transactions",
        ),
        ({"txn-groups": [{"txn-results": ONE_RESULT, "failed-at": []}]}, ""),
        ({"txn_groups": [{"txn_results": ONE_RESULT}]}, ""),
        ({"txn-groups": [{"txn-results": ONE_RESULT}]}, ""),
    ],
)
def test_a_signed_simulation_passes_only_with_one_full_group_result(fakes, answer, message):
    # An answer that checked less than the group is a failure, not a pass:
    # exactly one group result, an object, with no failure message and no
    # failed-at, holding one transaction result per transaction submitted.
    txn = fake_signer.payment(41, 42)
    answer = dict(answer, **{"last-round": 10, "version": 2})
    signer, node, client = make(
        fakes, SendSigner([ordinary_key(txn)]), FakeNode(simulate=lambda: reply(200, answer))
    )
    result = client.simulate_prepared_group(node.client, prepared_for(txn))
    assert result.failure_message == message
    assert result.failed is bool(message)


def test_the_confirmation_wait_follows_a_node_that_jumps_ahead(fakes):
    # The wait after round 10 answers round 20: three rounds of waiting are
    # used up, and the group is looked up once more, not once per round.
    txn = fake_signer.payment(41, 42)
    signer, node, client = make(
        fakes, SendSigner([ordinary_key(txn)]), FakeNode(pending=lambda: {}, wait_round=20)
    )
    with pytest.raises(SubmissionUncertainError) as excinfo:
        client.send_prepared(node.client, prepared_for(txn), wait_rounds=3)
    assert excinfo.value.stage == SEND_STAGE_CONFIRM
    assert node.lookups == 2 and node.waits == ["10"]


# -----------------------------------------------------------------------------
# The prepare helpers' address parameters
# -----------------------------------------------------------------------------


class _NoAlgod:
    def __getattr__(self, name):
        raise AssertionError(f"the helper asked algod for {name} before refusing")


_SENDER = fake_signer.account(41)
_OTHER = fake_signer.account(43)


@pytest.mark.parametrize(
    "helper,kwargs,field",
    [
        ("prepare_payment", {"sender": _SENDER, "receiver": _OTHER, "amount": 1}, "sender"),
        ("prepare_payment", {"sender": _SENDER, "receiver": _OTHER, "amount": 1}, "receiver"),
        (
            "prepare_asa_transfer",
            {"sender": _SENDER, "receiver": _OTHER, "asset_id": 7, "amount": 1},
            "receiver",
        ),
        ("prepare_asa_opt_in", {"sender": _SENDER, "asset_id": 7}, "sender"),
        ("prepare_asa_opt_out", {"sender": _SENDER, "asset_id": 7, "close_to": _OTHER}, "close_to"),
        ("prepare_account_close", {"sender": _SENDER, "close_to": _OTHER}, "close_to"),
        ("prepare_rekey", {"sender": _SENDER, "rekey_to": _OTHER}, "rekey_to"),
        ("prepare_keyreg", {"sender": _SENDER, "mode": "offline"}, "sender"),
        ("prepare_app_call", {"sender": _SENDER, "app_id": 5}, "sender"),
        (
            "prepare_app_deploy",
            {"sender": _SENDER, "approval_program": b"\x06", "clear_program": b"\x06"},
            "sender",
        ),
    ],
)
def test_a_prepare_helper_refuses_an_address_spelled_otherwise(helper, kwargs, field):
    # As the Go transaction builders do, before anything is asked of algod
    # or the signer.
    client = signer_client("http://127.0.0.1:9")
    kwargs = dict(kwargs, **{field: alternate_spelling(kwargs[field])})
    with pytest.raises(ValueError, match=f"{field} .* is not the canonical spelling"):
        getattr(client, helper)(_NoAlgod(), **kwargs)


_APP_CALLS = [
    ("prepare_app_call", {"sender": _SENDER, "app_id": 5}),
    ("prepare_abi_app_call", {"sender": _SENDER, "app_id": 5, "method_signature": "f()void"}),
    (
        "prepare_app_deploy",
        {"sender": _SENDER, "approval_program": b"\x06", "clear_program": b"\x06"},
    ),
]


@pytest.mark.parametrize("helper,kwargs", _APP_CALLS)
@pytest.mark.parametrize(
    "entry,error",
    [
        (alternate_spelling(_OTHER), "is not the canonical spelling"),
        (123, "is not a valid address"),
        (None, "is not a valid address"),
        (bytes(32), "is not a valid address"),
        ("NOT-AN-ADDRESS", "is not a valid address"),
    ],
)
def test_an_app_call_refuses_an_account_reference_that_is_not_a_canonical_address(
    helper, kwargs, entry, error
):
    # As the Go SDK's address decoding does, before anything is asked of
    # algod or the signer.
    client = signer_client("http://127.0.0.1:9")
    with pytest.raises(ValueError, match=rf"accounts\[1\] .*{error}"):
        getattr(client, helper)(_NoAlgod(), accounts=[_OTHER, entry], **kwargs)


@pytest.mark.parametrize("value", [alternate_spelling(_OTHER), alternate_spelling(_SENDER)])
def test_an_abi_account_argument_spelled_otherwise_is_refused(value):
    # Spelled otherwise, the sender would be listed as another account, and
    # an account already listed would be listed twice.
    client = signer_client("http://127.0.0.1:9")
    with pytest.raises(ValueError, match="account reference argument .* is not the canonical"):
        client.prepare_abi_app_call(
            _NoAlgod(), sender=_SENDER, app_id=5, method_signature="f(account)void", args=[value]
        )


@pytest.mark.parametrize(
    "sender,error",
    [("", "sender is required"), (alternate_spelling(_SENDER), "sender .* is not the canonical")],
)
def test_an_abi_app_call_checks_its_sender_before_its_arguments(sender, error):
    # The arguments are encoded against the sender, so it is checked first,
    # and its error is the one reported.
    client = signer_client("http://127.0.0.1:9")
    with pytest.raises(ValueError, match=error):
        client.prepare_abi_app_call(
            _NoAlgod(), sender=sender, app_id=5, method_signature="f(uint64)void", args=[True]
        )


def test_a_rekey_to_a_rotating_account_spelled_otherwise_is_refused(fakes):
    # Spelled otherwise, the target would not be found by its record, and the
    # check that refuses a rekey to a rotating account would be skipped.
    rotating = fake_signer.account(45)
    signer, node, client = make(
        fakes, SendSigner([key(_SENDER), key(rotating, SIGNING_FLOW_ROTATING1)])
    )
    with pytest.raises(SignerError, match="rotating account"):
        client.prepare_rekey(node.client, sender=_SENDER, rekey_to=rotating)
    with pytest.raises(ValueError, match="not the canonical spelling"):
        client.prepare_rekey(node.client, sender=_SENDER, rekey_to=alternate_spelling(rotating))


# -----------------------------------------------------------------------------
# last_valid on the two uncertain errors, in every flow
# -----------------------------------------------------------------------------


def _payment_valid_to(sender_seed, receiver_seed, last_valid):
    txn = fake_signer.payment(sender_seed, receiver_seed)
    txn.last_valid_round = last_valid
    return txn


class TestLastValidInEveryFlow:
    def test_an_ordinary_lost_answer(self, fakes):
        first = _payment_valid_to(41, 42, 1500)
        second = _payment_valid_to(43, 44, 1200)
        signer, node, client = make(
            fakes, SendSigner([key(first.sender), key(second.sender)], sign=lambda _: DROP)
        )
        group = PreparedGroup(
            [
                PreparedTransaction(transaction=first, auth_address=first.sender),
                PreparedTransaction(transaction=second, auth_address=second.sender),
            ]
        )
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            client.send_prepared(node.client, group)
        assert excinfo.value.last_valid == 1200

    def test_an_ordinary_fault_describing_the_signed_group(self, fakes, monkeypatch):
        txn = _payment_valid_to(41, 42, 1300)
        signer, node, client = make(fakes, SendSigner([key(txn.sender)]))

        def fault(result):
            raise RuntimeError("boom")

        monkeypatch.setattr(signer_module, "_describe_signed_group", fault)
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            client.send_prepared(
                node.client, PreparedTransaction(transaction=txn, auth_address=txn.sender)
            )
        assert excinfo.value.last_valid == 1300

    @pytest.mark.parametrize("fault", ["/sign/component drop", "/sign/assemble truncate"])
    def test_a_cosigned_lost_answer(self, fakes, fault):
        fixture = CosignedFixture(fakes, fault=fault)
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            fixture.send(
                cosigner_client=fixture.cosigner_client,
                cosigner_component_key="COSIGNER_COMPONENT",
            )
        assert excinfo.value.last_valid == fixture.txn.last_valid_round == 100

    def test_a_rotating_send(self, fakes):
        signer = fakes(RotatingSigner(fake_signer.account(41)))
        node = fakes(FakeNode())
        client = signer_client(signer.http.url)
        signer.sign_errors = [None]
        txn = rotating_payment(signer.account, 10, 110)
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            client.send_prepared(
                node.client, PreparedTransaction(transaction=txn, auth_address=txn.sender)
            )
        assert excinfo.value.rotating is not None
        assert excinfo.value.last_valid == 110

    def test_the_rotating_step_call(self, fakes):
        signer = fakes(RotatingSigner(fake_signer.account(41)))
        client = signer_client(signer.http.url)
        prepared = client.prepare_rotating(rotating_payment(signer.account, 10, 105))
        signer.sign_errors = [None]
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            client.sign_prepared_rotating(prepared)
        assert excinfo.value.rotating is prepared
        assert excinfo.value.last_valid == 105

    def test_a_rotating_fault_describing_the_signed_group(self, fakes, monkeypatch):
        signer = fakes(RotatingSigner(fake_signer.account(41)))
        node = fakes(FakeNode())
        client = signer_client(signer.http.url)
        txn = rotating_payment(signer.account, 10, 108)

        def fault(result):
            raise RuntimeError("boom")

        monkeypatch.setattr(signer_module, "_describe_signed_group", fault)
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            client.send_prepared(
                node.client, PreparedTransaction(transaction=txn, auth_address=txn.sender)
            )
        assert excinfo.value.last_valid == 108

    @pytest.mark.parametrize(
        "node_options,stage",
        [
            ({"submit": lambda _blob: reply(500, {"message": "boom"})}, SEND_STAGE_SUBMIT),
            ({"pending": lambda: {}}, SEND_STAGE_CONFIRM),
        ],
    )
    def test_a_submission(self, fakes, node_options, stage):
        txn = _payment_valid_to(41, 42, 1400)
        signer, node, client = make(fakes, SendSigner([key(txn.sender)]), FakeNode(**node_options))
        with pytest.raises(SubmissionUncertainError) as excinfo:
            client.send_prepared(
                node.client,
                PreparedTransaction(transaction=txn, auth_address=txn.sender),
                wait_rounds=1,
            )
        assert excinfo.value.stage == stage and excinfo.value.last_valid == 1400
