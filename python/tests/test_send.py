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
    uncertain = SubmissionUncertainError(SEND_STAGE_CONFIRM, ["aa"], ["ID"], SignerError("no"))
    unknown = SignOutcomeUnknownError(SignerError("gone"), request_id="r1", requests=[{}])
    for error in (rejected, uncertain, unknown):
        clone = pickle.loads(pickle.dumps(error))
        assert type(clone) is type(error) and str(clone) == str(error)
    assert pickle.loads(pickle.dumps(uncertain)).stage == SEND_STAGE_CONFIRM
    assert pickle.loads(pickle.dumps(unknown)).request_id == "r1"


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

    def __init__(self, fakes, fault=""):
        self.bounded = fake_signer.test_address(21)
        self.fault = fault
        self.cosigner_calls = 0
        bounded_key = key(
            self.bounded,
            SIGNING_FLOW_COSIGNED1,
            key_type="aplane.falcon1024.v1",
            logic_sig_resources={
                "spend": {"program_bytes": 5308, "argument_bytes": 3358, "max_opcode_cost": 20000}
            },
            cosigner_component_key_type=KEY_TYPE_WITNESS_FALCON1024,
            bounded_authorization={
                "contract": "bounded2",
                "max_fee": 1000,
                "rekey": "refused",
                "cosigner": {
                    "component_key_type": KEY_TYPE_WITNESS_FALCON1024,
                    "public_key_hex": "aabb",
                },
            },
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
        self.txn = transaction.PaymentTxn(self.bounded, params, fake_signer.test_address(22), 1000)

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
                            "path": "spend",
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

        def record(method, path, body):
            self.paths.append(path)
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

    with pytest.raises(SignOutcomeUnknownError):
        fixture.user_client.send_prepared(
            fixture.node.client,
            group,
            cosigner_client=fixture.cosigner_client,
            cosigner_component_key="COSIGNER_COMPONENT",
        )
    assert fixture.user.paths.count("/sign") == 1
    assert fixture.cosigner_calls == 0
    assert fixture.node.submissions() == []


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
        with pytest.raises(SignerError, match=f"key 1 address {respelled} is not the canonical"):
            client.list_keys()

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
            assembled.append(kwargs["json"]["request_id"])
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


@pytest.mark.parametrize(
    "groups,message",
    [
        (None, "returned no result for the group"),
        ([], "returned no result for the group"),
        ([{}, {}], "returned 2 group results for one group"),
        ([{"failure-message": "logic eval error"}], "logic eval error"),
        ([{}], ""),
    ],
    ids=["no groups field", "zero results", "two results", "failed", "passed"],
)
def test_a_signed_simulation_needs_exactly_one_group_result(fakes, groups, message):
    # As in the rotating preflight, an answer without exactly one group
    # result checked nothing: it is a failure, not a pass.
    txn = fake_signer.payment(41, 42)
    answer = {"last-round": 10, "version": 2}
    if groups is not None:
        answer["txn-groups"] = groups
    signer, node, client = make(
        fakes, SendSigner([ordinary_key(txn)]), FakeNode(simulate=lambda: reply(200, answer))
    )
    result = client.simulate_prepared_group(node.client, prepared_for(txn))
    assert result.failed is bool(message)
    if message:
        assert message in result.failure_message
    else:
        assert result.failure_message == ""


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
