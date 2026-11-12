# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""The time limit of a send and of the rotating steps (timeout=), stage by
stage, as Go behaves when its context deadline passes at the same point."""

import json
import time

import pytest

from aplanesdk import (
    ERR_CODE_ROTATING_STAGE_UNPROVEN,
    SEND_OUTCOME_CONFIRMED,
    SEND_STAGE_CONFIRM,
    SEND_STAGE_SUBMIT,
    SEND_STAGE_UNSENT,
    PreparedTransaction,
    SendTimeoutError,
    SignerError,
    SignOutcomeUnknownError,
    SubmissionUncertainError,
)
from aplanesdk import signer as signer_module
from tests import fake_signer
from tests.send_fakes import (
    FakeNode,
    HTTPFake,
    RotatingSigner,
    SendSigner,
    key,
    refusal,
    reply,
    rotating_payment,
    signer_client,
)
from tests.test_send import CosignedFixture, fakes  # noqa: F401 (fixture)

LIMIT = 0.4
SLOW = 1.5
APPROVAL_PATHS = ("/sign", "/sign/component", "/sign/assemble", "/sign/rotating/sign")


class Slowed:
    """A fake signer or node whose answer at one path comes late."""

    def __init__(self, inner, path, delay=SLOW, prefix=False):
        self.inner = inner
        self.path = path
        self.delay = delay
        self.prefix = prefix
        self.paths = []
        self.bodies = {}
        self.http = HTTPFake(self.app)

    def app(self, method, path, body):
        self.paths.append(path)
        self.bodies.setdefault(path, []).append(body)
        if path == self.path or (self.prefix and path.startswith(self.path)):
            time.sleep(self.delay)
        return self.inner(method, path, body)


def payment():
    return fake_signer.payment(41, 42)


def prepared(txn):
    return PreparedTransaction(transaction=txn, auth_address=txn.sender)


def ordinary(fakes, slow_path, node=None, **signer_options):
    txn = payment()
    signer = SendSigner([key(txn.sender)], **signer_options)
    slowed = fakes(Slowed(signer.app, slow_path))
    node = fakes(node or FakeNode())
    return txn, slowed, node, signer_client(slowed.http.url)


def _quick(started):
    return time.monotonic() - started < SLOW


class TestBeforeAnyApproval:
    @pytest.mark.parametrize("path", ["/status", "/keys"])
    def test_a_slow_signer_is_a_plain_timeout(self, fakes, path):
        txn, signer, node, client = ordinary(fakes, path)
        started = time.monotonic()
        with pytest.raises(SendTimeoutError) as excinfo:
            client.send_prepared(node.client, prepared(txn), timeout=LIMIT)
        assert _quick(started)
        assert not isinstance(excinfo.value, SignOutcomeUnknownError)
        assert isinstance(excinfo.value, SignerError)
        assert not any(seen in APPROVAL_PATHS for seen in signer.paths)
        assert "/sign/cancel" not in signer.paths

    def test_a_slow_node_while_preparing_is_a_plain_timeout(self, fakes):
        sender = fake_signer.account(41)
        signer = fakes(SendSigner([key(sender)]))
        node = FakeNode()
        slowed_node = fakes(Slowed(node.app, "/v2/transactions/params"))
        from algosdk.v2client import algod

        started = time.monotonic()
        with pytest.raises(SendTimeoutError):
            signer_client(signer.http.url).send_payment(
                algod.AlgodClient("", slowed_node.http.url),
                sender=sender,
                receiver=fake_signer.test_address(42),
                amount=1,
                timeout=LIMIT,
            )
        assert _quick(started)
        assert signer.count("/sign") == 0

    def test_a_slow_cosigned_plan_is_a_plain_timeout(self, fakes):
        fixture = CosignedFixture(fakes)
        slowed = fakes(Slowed(fixture.user_app, "/plan"))
        fixture.user_client = signer_client(slowed.http.url)
        with pytest.raises(SendTimeoutError):
            fixture.send(
                cosigner_client=fixture.cosigner_client,
                cosigner_component_key="COSIGNER_COMPONENT",
                timeout=LIMIT,
            )
        assert not any(seen in APPROVAL_PATHS for seen in slowed.paths)
        assert "/sign/cancel" not in slowed.paths

    def test_a_limit_spent_before_the_request_posts_nothing(self, fakes, monkeypatch):
        # The limit passes after the key list was read: nothing is posted.
        txn, signer, node, client = ordinary(fakes, "/none")
        real = client._classify_send

        def slow_classify(group):
            answer = real(group)
            time.sleep(LIMIT + 0.1)
            return answer

        monkeypatch.setattr(client, "_classify_send", slow_classify)
        with pytest.raises(SendTimeoutError):
            client.send_prepared(node.client, prepared(txn), timeout=LIMIT)
        assert "/sign" not in signer.paths and "/sign/cancel" not in signer.paths

    def test_the_rotating_wait_to_retry_ends_with_the_limit(self, fakes):
        rotating = RotatingSigner(fake_signer.account(41))
        rotating.prepare_errors = [refusal(ERR_CODE_ROTATING_STAGE_UNPROVEN, "not yet")] * 3
        signer = fakes(rotating)
        node = fakes(FakeNode())
        txn = rotating_payment(rotating.account, 10, 110)
        started = time.monotonic()
        with pytest.raises(SendTimeoutError) as excinfo:
            signer_client(signer.http.url).send_prepared(
                node.client, prepared(txn), timeout=1.0
            )
        # The first wait to retry is 2 seconds; the limit ends it early.
        assert time.monotonic() - started < 1.9
        assert excinfo.value.code == ERR_CODE_ROTATING_STAGE_UNPROVEN
        assert rotating.count("/sign/rotating/prepare") == 1
        assert rotating.count("/sign/rotating/sign") == 0

    def test_prepare_rotating_takes_a_limit(self, fakes):
        rotating = RotatingSigner(fake_signer.account(41))
        slowed = fakes(Slowed(rotating.app, "/sign/rotating/prepare"))
        rotating.http.close()
        with pytest.raises(SendTimeoutError):
            signer_client(slowed.http.url).prepare_rotating(
                rotating_payment(rotating.account, 10, 110), timeout=LIMIT
            )


class TestWhileApprovalWaits:
    def test_an_ordinary_sign(self, fakes):
        txn, signer, node, client = ordinary(fakes, "/sign")
        started = time.monotonic()
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            client.send_prepared(node.client, prepared(txn), timeout=LIMIT)
        assert _quick(started)
        error = excinfo.value
        assert isinstance(error.error, SendTimeoutError)
        assert error.__cause__ is error.error
        assert error.request_id and error.last_valid == txn.last_valid_round
        # The pending approval was canceled, by its ID.
        (cancel,) = signer.bodies["/sign/cancel"]
        assert json.loads(cancel)["request_id"] == error.request_id
        assert node.submissions() == []

    def test_a_cosigned_component_request(self, fakes):
        fixture = CosignedFixture(fakes)
        slowed = fakes(Slowed(fixture.user_app, "/sign/component"))
        fixture.user_client = signer_client(slowed.http.url)
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            fixture.send(
                cosigner_client=fixture.cosigner_client,
                cosigner_component_key="COSIGNER_COMPONENT",
                timeout=LIMIT,
            )
        error = excinfo.value
        assert isinstance(error.error, SendTimeoutError)
        assert error.last_valid == 100
        (component,) = slowed.bodies["/sign/component"]
        assert error.request_id == json.loads(component)["request_id"]
        assert "/sign/cancel" in slowed.paths

    def test_a_rotating_send(self, fakes):
        rotating = RotatingSigner(fake_signer.account(41))
        slowed = fakes(Slowed(rotating.app, "/sign/rotating/sign"))
        rotating.http.close()
        node = fakes(FakeNode())
        txn = rotating_payment(rotating.account, 10, 110)
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            signer_client(slowed.http.url).send_prepared(
                node.client, prepared(txn), timeout=LIMIT
            )
        error = excinfo.value
        assert isinstance(error.error, SendTimeoutError)
        assert error.rotating is not None and error.last_valid == 110
        assert "/sign/cancel" in slowed.paths
        assert node.submissions() == []

    def test_the_rotating_step_call(self, fakes):
        rotating = RotatingSigner(fake_signer.account(41))
        slowed = fakes(Slowed(rotating.app, "/sign/rotating/sign"))
        rotating.http.close()
        client = signer_client(slowed.http.url)
        group = client.prepare_rotating(rotating_payment(rotating.account, 10, 105))
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            client.sign_prepared_rotating(group, request_id="step-1", timeout=LIMIT)
        error = excinfo.value
        assert isinstance(error.error, SendTimeoutError)
        assert error.request_id == "step-1" and error.rotating is group
        assert error.last_valid == 105
        (cancel,) = slowed.bodies["/sign/cancel"]
        assert json.loads(cancel)["request_id"] == "step-1"


class TestAfterSigning:
    def test_before_submission_the_group_is_unsent(self, fakes, monkeypatch):
        txn, signer, node, client = ordinary(fakes, "/none")
        real = signer_module._describe_signed_group

        def slow_describe(result):
            raw = real(result)
            time.sleep(LIMIT + 0.1)
            return raw

        monkeypatch.setattr(signer_module, "_describe_signed_group", slow_describe)
        with pytest.raises(SubmissionUncertainError) as excinfo:
            client.send_prepared(node.client, prepared(txn), timeout=LIMIT)
        error = excinfo.value
        assert error.stage == SEND_STAGE_UNSENT
        assert isinstance(error.error, SendTimeoutError)
        assert error.signed_group and error.tx_ids and error.last_valid == txn.last_valid_round
        assert node.submissions() == []

    def test_a_slow_submission(self, fakes):
        node = FakeNode()
        slowed_node = fakes(Slowed(node.app, "/v2/transactions"))
        txn, signer, _, client = ordinary(fakes, "/none")
        from algosdk.v2client import algod

        with pytest.raises(SubmissionUncertainError) as excinfo:
            client.send_prepared(
                algod.AlgodClient("", slowed_node.http.url), prepared(txn), timeout=LIMIT
            )
        assert excinfo.value.stage == SEND_STAGE_SUBMIT
        assert isinstance(excinfo.value.error, SendTimeoutError)

    def test_a_slow_confirmation(self, fakes):
        node = FakeNode(pending=lambda: {})
        slowed_node = fakes(
            Slowed(node.app, "/v2/status/wait-for-block-after/", prefix=True)
        )
        txn, signer, _, client = ordinary(fakes, "/none")
        from algosdk.v2client import algod

        started = time.monotonic()
        with pytest.raises(SubmissionUncertainError) as excinfo:
            client.send_prepared(
                algod.AlgodClient("", slowed_node.http.url), prepared(txn), timeout=LIMIT
            )
        assert _quick(started)
        assert excinfo.value.stage == SEND_STAGE_CONFIRM
        assert isinstance(excinfo.value.error, SendTimeoutError)
        assert len(node.submissions()) == 1


class _StrictAlgod:
    """An algod whose methods take no timeout argument: a send without a
    limit calls it exactly as before."""

    def __init__(self, node):
        self.node = node

    def __getattr__(self, name):
        method = getattr(self.node.client, name)

        def call(*args):
            return method(*args)

        return call


class TestNoLimit:
    def test_none_calls_the_node_as_before(self, fakes):
        txn, signer, node, client = ordinary(fakes, "/none")
        result = client.send_prepared(_StrictAlgod(node), prepared(txn), timeout=None)
        assert result.outcome == SEND_OUTCOME_CONFIRMED

    def test_a_limit_long_enough_changes_nothing(self, fakes):
        txn, signer, node, client = ordinary(fakes, "/none")
        result = client.send_prepared(node.client, prepared(txn), timeout=30)
        assert result.outcome == SEND_OUTCOME_CONFIRMED

    @pytest.mark.parametrize("bad", [0, -1, float("inf"), "1", True])
    def test_a_bad_limit_is_refused_before_anything(self, fakes, bad):
        txn, signer, node, client = ordinary(fakes, "/none")
        with pytest.raises(ValueError):
            client.send_prepared(node.client, prepared(txn), timeout=bad)
        assert signer.paths == []

    def test_the_limit_is_the_whole_call(self, fakes):
        # Each request alone is quicker than the limit; together they are
        # not.
        txn = payment()
        signer = SendSigner([key(txn.sender)])

        def app(method, path, body):
            time.sleep(0.15)
            return signer.app(method, path, body)

        slowed = fakes(Slowed(app, "/none"))
        node = fakes(FakeNode())
        with pytest.raises((SendTimeoutError, SignOutcomeUnknownError)):
            signer_client(slowed.http.url).send_prepared(
                node.client, prepared(txn), timeout=0.35
            )
