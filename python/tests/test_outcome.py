# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""After an uncertain outcome: last_valid on the two errors in every flow,
resolve_outcome against a fake node for every row of the decision tables,
and wait_for_outcome."""

import pickle
import threading
import time

import pytest

from aplanesdk import (
    OUTCOME_CONFIRMED,
    OUTCOME_EXPIRED,
    OUTCOME_NOT_SEEN,
    OUTCOME_PENDING,
    OUTCOME_SIGNABLE,
    OUTCOME_TOO_OLD,
    PreparedGroup,
    PreparedTransaction,
    SEND_STAGE_CONFIRM,
    SEND_STAGE_SUBMIT,
    SignerClient,
    SignerError,
    SignOutcomeUnknownError,
    SubmissionUncertainError,
)
from aplanesdk import signer as signer_module
from aplanesdk.signer import SendTimeoutError
from tests import fake_signer
from tests.send_fakes import (
    DROP,
    FakeNode,
    HTTPFake,
    RotatingSigner,
    SendSigner,
    key,
    reply,
    rotating_payment,
    signer_client,
)
from tests.test_send import CosignedFixture, fakes  # noqa: F401 (fixture)

LAST_VALID = 1000
CONFIRMED_ADVICE = "The group was confirmed in round {}. Do not send it again."
PENDING_ADVICE = "The group is in the node's pool. Wait; do not send again."
NOT_SEEN_ADVICE = (
    "The node does not have the group and it can still execute until round 1000. Submit the "
    "same signed group again, or wait until round 1000 has passed."
)
SUBMISSION_EXPIRED_ADVICE = (
    "The group was not confirmed and can no longer execute. It is safe to build a new one."
)
TOO_OLD_ADVICE = (
    "The group's validity ended more than 500 rounds ago and this node may no longer remember "
    "it. Look the transaction ID up on an indexer before sending again."
)
ROTATING_TOO_OLD_ADVICE = (
    "The prepared group's validity ended more than 500 rounds ago and this node may no longer "
    "remember it. Look the transaction ID up on an indexer before sending again."
)
ROTATING_SIGNABLE_ADVICE = (
    "A signature may have been released and can execute until round 1000. Sign the same "
    "prepared group again, or wait until round 1000 has passed."
)
SIGNABLE_ADVICE = (
    "A signature may have been released and can execute until round 1000. Wait until round "
    "1000 has passed before building a replacement."
)
SIGN_EXPIRED_ADVICE = (
    "No signature released by that request can execute any more. It is safe to build a new one."
)

CONFIRMED = (200, {"confirmed-round": 990, "pool-error": ""})
IN_POOL = (200, {"confirmed-round": 0, "pool-error": ""})
POOL_ERROR = (200, {"pool-error": "transaction dead: round passed"})
NOT_FOUND = (404, {"message": "could not find the transaction in the transaction pool"})
NODE_FAILS = (500, {"message": "internal error"})


class Node:
    """A fake algod for outcome lookups: a round that the wait for the next
    block advances, and an answer for the pending-transaction lookup."""

    def __init__(self, round, lookup=NOT_FOUND, status=None, advance=1, wait=None):
        self.round = round
        self.lookup = lookup
        self.status = status
        self.advance = advance
        self.wait = wait
        self.calls = []
        self.lock = threading.Lock()
        self.http = HTTPFake(self.app)
        from algosdk.v2client import algod

        self.client = algod.AlgodClient("", self.http.url)

    def app(self, method, path, body):
        with self.lock:
            self.calls.append(path)
        if path == "/v2/status":
            if self.status is not None:
                return reply(*self.status)
            return reply(200, {"last-round": self.round})
        if path.startswith("/v2/status/wait-for-block-after/"):
            if self.wait is not None:
                return self.wait()
            with self.lock:
                self.round = int(path.rsplit("/", 1)[1]) + self.advance
            return reply(200, {"last-round": self.round})
        if path.startswith("/v2/transactions/pending/"):
            lookup = self.lookup(self.round) if callable(self.lookup) else self.lookup
            return reply(*lookup)
        raise AssertionError(f"unexpected node path {method} {path}")

    def lookups(self):
        return [path for path in self.calls if path.startswith("/v2/transactions/pending/")]


@pytest.fixture
def node():
    made = []

    def build(*args, **kwargs):
        made.append(Node(*args, **kwargs))
        return made[-1]

    yield build
    for item in made:
        item.http.close()


class _Prepared:
    """Stands in for a PreparedRotating: all the report needs is its IDs."""

    tx_ids = ["ROTATINGSPENDID", "ROTATINGDUMMYID"]


def submission_error(last_valid=LAST_VALID, tx_ids=("FIRSTID", "SECONDID")):
    return SubmissionUncertainError(
        SEND_STAGE_CONFIRM, ["aa", "bb"], list(tx_ids), SignerError("gone"), last_valid=last_valid
    )


def sign_error(rotating=False, last_valid=LAST_VALID):
    return SignOutcomeUnknownError(
        SignerError("gone"),
        request_id="r1",
        rotating=_Prepared() if rotating else None,
        last_valid=last_valid,
    )


def client():
    return SignerClient("http://127.0.0.1:9")


class TestSubmissionTable:
    @pytest.mark.parametrize(
        "lookup,current,state,safe,advice",
        [
            (CONFIRMED, 995, OUTCOME_CONFIRMED, False, CONFIRMED_ADVICE.format(990)),
            (CONFIRMED, 5000, OUTCOME_CONFIRMED, False, CONFIRMED_ADVICE.format(990)),
            (IN_POOL, 995, OUTCOME_PENDING, False, PENDING_ADVICE),
            (NOT_FOUND, 999, OUTCOME_NOT_SEEN, False, NOT_SEEN_ADVICE),
            (NOT_FOUND, 1000, OUTCOME_NOT_SEEN, False, NOT_SEEN_ADVICE),
            (POOL_ERROR, 1000, OUTCOME_NOT_SEEN, False, NOT_SEEN_ADVICE),
            (NOT_FOUND, 1001, OUTCOME_EXPIRED, True, SUBMISSION_EXPIRED_ADVICE),
            (POOL_ERROR, 1001, OUTCOME_EXPIRED, True, SUBMISSION_EXPIRED_ADVICE),
            (NOT_FOUND, 1500, OUTCOME_EXPIRED, True, SUBMISSION_EXPIRED_ADVICE),
            (POOL_ERROR, 1500, OUTCOME_EXPIRED, True, SUBMISSION_EXPIRED_ADVICE),
            (NOT_FOUND, 1501, OUTCOME_TOO_OLD, False, TOO_OLD_ADVICE),
            (POOL_ERROR, 1501, OUTCOME_TOO_OLD, False, TOO_OLD_ADVICE),
        ],
        ids=[
            "confirmed",
            "confirmed long ago",
            "in pool",
            "not found before the last valid round",
            "not found at the last valid round",
            "pool error at the last valid round",
            "not found one round after",
            "pool error one round after",
            "not found 500 rounds after",
            "pool error 500 rounds after",
            "not found 501 rounds after",
            "pool error 501 rounds after",
        ],
    )
    def test_rows(self, node, lookup, current, state, safe, advice):
        algod = node(current, lookup)
        error = submission_error()
        report = client().resolve_outcome(algod.client, error)
        assert report.state == state
        assert report.safe_to_replace is safe
        assert report.advice == advice
        assert report.confirmed_round == (990 if state == OUTCOME_CONFIRMED else 0)
        assert report.tx_ids == ["FIRSTID", "SECONDID"]
        assert report.last_valid == LAST_VALID and report.current_round == current
        assert report.signed_group == ["aa", "bb"] and report.rotating is None
        # One lookup, of the first transaction: a group is atomic.
        assert algod.lookups() == ["/v2/transactions/pending/FIRSTID"]

    def test_the_round_is_read_before_the_lookup(self, node):
        algod = node(1000, NOT_FOUND)
        client().resolve_outcome(algod.client, submission_error())
        assert algod.calls == ["/v2/status", "/v2/transactions/pending/FIRSTID"]


class TestSignTable:
    @pytest.mark.parametrize(
        "lookup,current,state,safe,advice",
        [
            (CONFIRMED, 995, OUTCOME_CONFIRMED, False, CONFIRMED_ADVICE.format(990)),
            (CONFIRMED, 1200, OUTCOME_CONFIRMED, False, CONFIRMED_ADVICE.format(990)),
            (IN_POOL, 995, OUTCOME_PENDING, False, PENDING_ADVICE),
            (NOT_FOUND, 1000, OUTCOME_SIGNABLE, False, ROTATING_SIGNABLE_ADVICE),
            (POOL_ERROR, 1000, OUTCOME_SIGNABLE, False, ROTATING_SIGNABLE_ADVICE),
            (NOT_FOUND, 1001, OUTCOME_EXPIRED, True, SIGN_EXPIRED_ADVICE),
            (POOL_ERROR, 1001, OUTCOME_EXPIRED, True, SIGN_EXPIRED_ADVICE),
            (NOT_FOUND, 1500, OUTCOME_EXPIRED, True, SIGN_EXPIRED_ADVICE),
            (POOL_ERROR, 1500, OUTCOME_EXPIRED, True, SIGN_EXPIRED_ADVICE),
            (NOT_FOUND, 1501, OUTCOME_TOO_OLD, False, ROTATING_TOO_OLD_ADVICE),
            (POOL_ERROR, 1501, OUTCOME_TOO_OLD, False, ROTATING_TOO_OLD_ADVICE),
            (NOT_FOUND, 9999, OUTCOME_TOO_OLD, False, ROTATING_TOO_OLD_ADVICE),
            (CONFIRMED, 9999, OUTCOME_CONFIRMED, False, CONFIRMED_ADVICE.format(990)),
        ],
        ids=[
            "confirmed",
            "confirmed, after the last valid round",
            "in pool",
            "not found at the last valid round",
            "pool error at the last valid round",
            "not found one round after",
            "pool error one round after",
            "not found 500 rounds after",
            "pool error 500 rounds after",
            "not found 501 rounds after",
            "pool error 501 rounds after",
            "not found long after",
            "confirmed long after",
        ],
    )
    def test_rotating_rows(self, node, lookup, current, state, safe, advice):
        algod = node(current, lookup)
        error = sign_error(rotating=True)
        report = client().resolve_outcome(algod.client, error)
        assert (report.state, report.safe_to_replace, report.advice) == (state, safe, advice)
        assert report.tx_ids == _Prepared.tx_ids
        assert report.rotating is error.rotating and report.signed_group is None
        assert report.current_round == current and report.last_valid == LAST_VALID
        assert algod.calls == ["/v2/status", "/v2/transactions/pending/ROTATINGSPENDID"]

    @pytest.mark.parametrize(
        "current,state,safe,advice",
        [
            (999, OUTCOME_SIGNABLE, False, SIGNABLE_ADVICE),
            (1000, OUTCOME_SIGNABLE, False, SIGNABLE_ADVICE),
            (1001, OUTCOME_EXPIRED, True, SIGN_EXPIRED_ADVICE),
            (1500, OUTCOME_EXPIRED, True, SIGN_EXPIRED_ADVICE),
            (1501, OUTCOME_EXPIRED, True, SIGN_EXPIRED_ADVICE),
            (9999, OUTCOME_EXPIRED, True, SIGN_EXPIRED_ADVICE),
        ],
    )
    def test_rows_without_ids(self, node, current, state, safe, advice):
        # The signer may have changed the transactions, so their IDs are not
        # known and nothing is looked up. Their signed bytes never left the
        # SDK, so expiry alone settles it: never too old.
        algod = node(current, CONFIRMED)
        report = client().resolve_outcome(algod.client, sign_error())
        assert (report.state, report.safe_to_replace, report.advice) == (state, safe, advice)
        assert report.tx_ids == [] and report.rotating is None and report.signed_group is None
        assert algod.lookups() == []


class TestRefusals:
    @pytest.mark.parametrize(
        "error", [ValueError("x"), SignerError("x"), None, "error"], ids=repr
    )
    def test_another_error_is_refused(self, node, error):
        algod = node(10)
        with pytest.raises(SignerError) as excinfo:
            client().resolve_outcome(algod.client, error)
        assert str(excinfo.value) == "not an uncertain outcome"
        with pytest.raises(SignerError, match="^not an uncertain outcome$"):
            client().wait_for_outcome(algod.client, error)
        assert algod.calls == []

    @pytest.mark.parametrize("error", [submission_error(last_valid=0), sign_error(last_valid=0)])
    def test_no_last_valid_round_is_refused(self, node, error):
        algod = node(10)
        with pytest.raises(SignerError) as excinfo:
            client().resolve_outcome(algod.client, error)
        assert str(excinfo.value) == "the error carries no last valid round"
        assert algod.calls == []

    @pytest.mark.parametrize("tx_ids", [(), ("",), ("", "SECOND")])
    def test_a_submission_without_ids_is_refused(self, node, tx_ids):
        algod = node(10)
        with pytest.raises(SignerError) as excinfo:
            client().resolve_outcome(algod.client, submission_error(tx_ids=tx_ids))
        assert str(excinfo.value) == "the error carries no transaction IDs"
        assert algod.calls == []

    def test_the_order_of_the_checks(self):
        # Type, then last valid round, then IDs, then the algod client.
        with pytest.raises(SignerError, match="^not an uncertain outcome$"):
            client().resolve_outcome(None, None)
        with pytest.raises(SignerError, match="no last valid round"):
            client().resolve_outcome(None, submission_error(last_valid=0, tx_ids=()))
        with pytest.raises(SignerError, match="no transaction IDs"):
            client().resolve_outcome(None, submission_error(tx_ids=()))
        for error in (submission_error(), sign_error()):
            with pytest.raises(ValueError, match="^algod client is required$"):
                client().resolve_outcome(None, error)

    def test_a_rotating_group_whose_first_id_is_empty_is_not_looked_up(self, node):
        algod = node(990, CONFIRMED)
        error = sign_error(rotating=True)
        error.rotating = type("Prepared", (), {"tx_ids": ["", "DUMMY"]})()
        report = client().resolve_outcome(algod.client, error)
        assert report.state == OUTCOME_SIGNABLE and report.tx_ids == ["", "DUMMY"]
        assert algod.lookups() == []

    @pytest.mark.parametrize(
        "options,error",
        [
            ({"status": NODE_FAILS}, sign_error()),
            ({"status": NODE_FAILS}, submission_error()),
            ({"lookup": NODE_FAILS}, submission_error()),
            ({"lookup": NODE_FAILS}, sign_error(rotating=True)),
            ({"lookup": (200, {"confirmed-round": "soon"})}, submission_error()),
        ],
        ids=["status, sign", "status, submission", "lookup", "lookup, rotating", "odd answer"],
    )
    def test_a_node_failure_is_an_error_not_a_state(self, node, options, error):
        algod = node(10, **options)
        with pytest.raises(SignerError):
            client().resolve_outcome(algod.client, error)


class TestWaitForOutcome:
    def test_waits_round_by_round_until_expired(self, node):
        algod = node(998)
        report = client().wait_for_outcome(algod.client, sign_error(), timeout=10)
        assert report.state == OUTCOME_EXPIRED and report.current_round == 1001
        waits = [path for path in algod.calls if "wait-for-block-after" in path]
        assert waits == [f"/v2/status/wait-for-block-after/{n}" for n in (998, 999, 1000)]

    def test_waits_until_a_pending_group_confirms(self, node):
        algod = node(500, lambda current: CONFIRMED if current >= 502 else IN_POOL)
        report = client().wait_for_outcome(algod.client, submission_error(), timeout=10)
        assert report.state == OUTCOME_CONFIRMED and report.confirmed_round == 990
        # It never submits or signs: the node has no other path, and the
        # client points at nothing.
        assert all(
            path == "/v2/status" or "wait-for-block-after" in path or "pending" in path
            for path in algod.calls
        )

    def test_a_final_state_returns_at_once(self, node):
        algod = node(2000)
        report = client().wait_for_outcome(algod.client, submission_error())
        assert report.state == OUTCOME_TOO_OLD
        assert not any("wait-for-block-after" in path for path in algod.calls)

    def test_the_time_limit_ends_the_wait_with_the_last_report(self, node):
        # The node's round never moves on.
        algod = node(900, advance=0)
        started = time.monotonic()
        with pytest.raises(SendTimeoutError) as excinfo:
            client().wait_for_outcome(algod.client, sign_error(), timeout=0.3)
        assert time.monotonic() - started < 2
        report = excinfo.value.report
        assert report is not None and report.state == OUTCOME_SIGNABLE
        assert report.current_round == 900

    def test_the_time_limit_bounds_a_wait_the_node_holds(self, node):
        def held():
            time.sleep(1.5)
            return reply(200, {"last-round": 901})

        algod = node(900, wait=held)
        started = time.monotonic()
        with pytest.raises(SendTimeoutError) as excinfo:
            client().wait_for_outcome(algod.client, sign_error(), timeout=0.4)
        assert time.monotonic() - started < 1.2
        assert excinfo.value.report.state == OUTCOME_SIGNABLE

    def test_a_failed_wait_is_an_error_with_the_last_report(self, node):
        algod = node(900, wait=lambda: reply(500, {"message": "down"}))
        with pytest.raises(SignerError, match="wait for round 901") as excinfo:
            client().wait_for_outcome(algod.client, sign_error())
        assert excinfo.value.report.state == OUTCOME_SIGNABLE
        assert excinfo.value.report.current_round == 900

    def test_a_node_failure_after_a_report_carries_it(self, node):
        algod = node(900)
        checks = []

        def lookup(current):
            checks.append(current)
            return IN_POOL if len(checks) == 1 else NODE_FAILS

        algod.lookup = lookup
        with pytest.raises(SignerError, match="look up transaction FIRSTID") as excinfo:
            client().wait_for_outcome(algod.client, submission_error(), timeout=10)
        assert excinfo.value.report.state == OUTCOME_PENDING
        assert excinfo.value.report.current_round == 900

    def test_a_first_failure_carries_no_report(self, node):
        algod = node(900, status=NODE_FAILS)
        with pytest.raises(SignerError, match="read the node's current round") as excinfo:
            client().wait_for_outcome(algod.client, sign_error())
        assert excinfo.value.report is None

    def test_a_bad_time_limit_is_refused(self, node):
        algod = node(900)
        for bad in (0, -1, float("nan"), float("inf"), "5", True):
            with pytest.raises(ValueError, match="^timeout must be a positive number"):
                client().wait_for_outcome(algod.client, sign_error(), timeout=bad)
        assert algod.calls == []

    @pytest.mark.parametrize("bad", [0, -1, float("nan")])
    def test_the_refusals_come_before_the_time_limit_is_checked(self, node, bad):
        algod = node(900)
        refusals = [
            (algod.client, None, SignerError, "^not an uncertain outcome$"),
            (algod.client, ValueError("x"), SignerError, "^not an uncertain outcome$"),
            (algod.client, sign_error(last_valid=0), SignerError, "no last valid round"),
            (algod.client, submission_error(tx_ids=()), SignerError, "no transaction IDs"),
            (None, sign_error(), ValueError, "^algod client is required$"),
        ]
        for algod_client, error, kind, message in refusals:
            with pytest.raises(kind, match=message):
                client().wait_for_outcome(algod_client, error, timeout=bad)
        assert algod.calls == []


# -----------------------------------------------------------------------------
# last_valid in every flow
# -----------------------------------------------------------------------------


def _payment(sender_seed, receiver_seed, last_valid):
    txn = fake_signer.payment(sender_seed, receiver_seed)
    txn.last_valid_round = last_valid
    return txn


def _make(fakes, signer, node=None):
    signer = fakes(signer)
    node = fakes(node or FakeNode())
    return signer, node, signer_client(signer.http.url)


class TestLastValidInEveryFlow:
    def test_an_ordinary_lost_answer(self, fakes):
        first = _payment(41, 42, 1500)
        second = _payment(43, 44, 1200)
        signer, node, signer_client_ = _make(
            fakes, SendSigner([key(first.sender), key(second.sender)], sign=lambda _: DROP)
        )
        group = PreparedGroup(
            [
                PreparedTransaction(transaction=first, auth_address=first.sender),
                PreparedTransaction(transaction=second, auth_address=second.sender),
            ]
        )
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            signer_client_.send_prepared(node.client, group)
        assert excinfo.value.last_valid == 1200

    def test_an_ordinary_fault_describing_the_signed_group(self, fakes, monkeypatch):
        txn = _payment(41, 42, 1300)
        signer, node, signer_client_ = _make(fakes, SendSigner([key(txn.sender)]))

        def fault(result):
            raise RuntimeError("boom")

        monkeypatch.setattr(signer_module, "_describe_signed_group", fault)
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            signer_client_.send_prepared(
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
        rotating_client = signer_client(signer.http.url)
        signer.sign_errors = [None]
        txn = rotating_payment(signer.account, 10, 110)
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            rotating_client.send_prepared(
                node.client, PreparedTransaction(transaction=txn, auth_address=txn.sender)
            )
        assert excinfo.value.rotating is not None
        assert excinfo.value.last_valid == 110

    def test_the_rotating_step_call(self, fakes):
        signer = fakes(RotatingSigner(fake_signer.account(41)))
        rotating_client = signer_client(signer.http.url)
        prepared = rotating_client.prepare_rotating(rotating_payment(signer.account, 10, 105))
        signer.sign_errors = [None]
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            rotating_client.sign_prepared_rotating(prepared)
        assert excinfo.value.last_valid == 105

    def test_a_rotating_fault_describing_the_signed_group(self, fakes, monkeypatch):
        signer = fakes(RotatingSigner(fake_signer.account(41)))
        node = fakes(FakeNode())
        rotating_client = signer_client(signer.http.url)
        txn = rotating_payment(signer.account, 10, 108)

        def fault(result):
            raise RuntimeError("boom")

        monkeypatch.setattr(signer_module, "_describe_signed_group", fault)
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            rotating_client.send_prepared(
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
        txn = _payment(41, 42, 1400)
        signer, node, signer_client_ = _make(
            fakes, SendSigner([key(txn.sender)]), FakeNode(**node_options)
        )
        with pytest.raises(SubmissionUncertainError) as excinfo:
            signer_client_.send_prepared(
                node.client,
                PreparedTransaction(transaction=txn, auth_address=txn.sender),
                wait_rounds=1,
            )
        assert excinfo.value.stage == stage and excinfo.value.last_valid == 1400

    def test_the_errors_pickle_with_it(self):
        for error in (submission_error(), sign_error()):
            assert pickle.loads(pickle.dumps(error)).last_valid == LAST_VALID


def test_a_rotating_lost_answer_resolves_against_its_prepared_group(fakes, node):
    signer = fakes(RotatingSigner(fake_signer.account(41)))
    rotating_client = signer_client(signer.http.url)
    prepared = rotating_client.prepare_rotating(rotating_payment(signer.account, 10, 105))
    signer.sign_errors = [None]
    with pytest.raises(SignOutcomeUnknownError) as excinfo:
        rotating_client.sign_prepared_rotating(prepared)
    algod = node(50, IN_POOL)
    report = rotating_client.resolve_outcome(algod.client, excinfo.value)
    assert report.state == OUTCOME_PENDING
    assert report.tx_ids == prepared.tx_ids
    assert algod.lookups() == [f"/v2/transactions/pending/{prepared.tx_ids[0]}"]
