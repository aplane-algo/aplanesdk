# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""The shared rotating vectors: what a live signer returned for rotating
spends, and copies of those answers altered in each way a signer may not alter
them. Every SDK must accept the captured answers and refuse every altered
one. See contracts/signerapi_vectors/README.md.

The altered answers are generated from the Go SDK's tamper tables; they are
read here as data, and none is special-cased by name.
"""

import base64
import copy
import json
from pathlib import Path

import pytest
from algosdk import encoding

from aplanesdk import (
    MaxFeeIncreaseError,
    RotatingSignResult,
    SignerError,
    SignOutcomeUnknownError,
)
from aplanesdk.signer import (
    _AnswerUnreadError,
    _new_prepared_rotating,
    _rotating_sign_answer,
    _sign_canonical_dummy,
    encode_transaction,
)
from tests.send_fakes import (
    HTTPFake,
    decode_map,
    encode_map,
    program_address,
    regroup,
    reply,
    set_prepared,
    signer_client,
    status_body,
)
from tests.test_rotating import PREPARE_TAMPERS, SIGN_TAMPERS

VECTORS_PATH = (
    Path(__file__).resolve().parents[2]
    / "contracts"
    / "signerapi_vectors"
    / "rotating_vectors.json"
)


def load_vectors():
    with open(VECTORS_PATH, encoding="utf-8") as f:
        return json.load(f)


VECTORS = load_vectors()
CASES = VECTORS["cases"]


def prepared_from(case, prepare, max_fee_increase=None):
    return _new_prepared_rotating(
        bytes.fromhex(case["original_txn_hex"]), copy.deepcopy(prepare), max_fee_increase, None
    )


def assert_verifier_refusal(error):
    """A refusal by the checks themselves: not an answer that could not be
    read, and not a fault inside the checking code, which would surface as
    some other exception and fail the test on its own."""
    assert isinstance(error, SignerError)
    assert not isinstance(error, _AnswerUnreadError)
    assert "the check itself failed" not in str(error)


def verify_signed(prepared, sign):
    """Check a sign answer the way sign_prepared_rotating does: read it as
    its wire types, then verify it against the prepared group."""
    return prepared._verify_signed(_rotating_sign_answer(copy.deepcopy(sign)))


def decode_txn_hex(txn_hex):
    return encoding.msgpack_decode(base64.b64encode(bytes.fromhex(txn_hex)[2:]).decode())


def test_the_vectors_have_cases_and_alterations():
    assert CASES
    assert VECTORS["prepare_tampered"] and VECTORS["sign_tampered"]


@pytest.mark.parametrize("name", sorted(CASES))
def test_every_captured_answer_is_accepted(name):
    case = CASES[name]
    prepared = prepared_from(case, case["prepare"])
    result = verify_signed(prepared, case["sign"])
    assert result.stage == case["sign"]["stage"] and result.target == case["sign"]["target"]
    assert result.txid == case["sign"]["txid"]
    assert result.signed_group == case["sign"]["signed"]
    assert prepared.tx_ids[0] == case["sign"]["txid"]


@pytest.mark.parametrize(
    "altered",
    VECTORS["prepare_tampered"],
    ids=[f"{entry['case']}: {entry['name']}" for entry in VECTORS["prepare_tampered"]],
)
def test_every_altered_prepare_answer_is_refused(altered):
    with pytest.raises(SignerError, match="verify prepared rotating group") as excinfo:
        prepared_from(CASES[altered["case"]], altered["prepare"])
    assert_verifier_refusal(excinfo.value)


@pytest.mark.parametrize(
    "altered",
    VECTORS["sign_tampered"],
    ids=[f"{entry['case']}: {entry['name']}" for entry in VECTORS["sign_tampered"]],
)
def test_every_altered_sign_answer_is_refused(altered):
    # Checked against the case's own, unaltered prepare answer.
    case = CASES[altered["case"]]
    prepared = prepared_from(case, case["prepare"])
    with pytest.raises(SignerError) as excinfo:
        verify_signed(prepared, altered["sign"])
    assert_verifier_refusal(excinfo.value)


def test_the_alterations_are_the_ones_this_sdk_tests_directly():
    # The vectors come from the Go tables; the direct tests in
    # test_rotating.py port the same tables. Each table entry applies to some
    # captured case, and nothing in the file is outside the tables, except
    # the one alteration only a stage 0 capture can carry.
    prepare_names = {entry["name"] for entry in VECTORS["prepare_tampered"]}
    sign_names = {entry["name"] for entry in VECTORS["sign_tampered"]}
    assert prepare_names == {case[0] for case in PREPARE_TAMPERS}
    assert sign_names - {case[0] for case in SIGN_TAMPERS} == {
        "stage 0 spend signed by another program that it names as its signer"
    }
    assert {case[0] for case in SIGN_TAMPERS} <= sign_names


@pytest.fixture(scope="module")
def raw_signer():
    """A signer that answers each sign request with the raw body it is set
    to, through the SDK's real transport."""

    class Signer:
        body = b""

        def app(self, method, path, request):
            if path == "/status":
                return reply(200, status_body())
            if path == "/sign/cancel":
                return reply(200, {"success": True, "state": "canceled"})
            if path == "/sign/rotating/sign":
                return (200, self.body, "application/json")
            raise AssertionError(f"unexpected signer path {path}")

    signer = Signer()
    signer.http = HTTPFake(signer.app)
    yield signer
    signer.http.close()


@pytest.mark.parametrize(
    "entry",
    VECTORS["sign_answer_bodies"],
    ids=[f"{entry['case']}: {entry['name']}" for entry in VECTORS["sign_answer_bodies"]],
)
def test_every_raw_sign_answer_is_read_as_the_vectors_say(raw_signer, entry):
    # The body answers a sign request for the case's own prepared group. The
    # class is decided by how the transport reads it and the checks after.
    case = CASES[entry["case"]]
    prepared = prepared_from(case, case["prepare"])
    raw_signer.body = entry["body"].encode()
    client = signer_client(raw_signer.http.url)

    if entry["expect"] == "accepted":
        result = client.sign_prepared_rotating(prepared)
        assert isinstance(result, RotatingSignResult)
        assert result.signed_group == case["sign"]["signed"]
    elif entry["expect"] == "refused":
        with pytest.raises(SignerError) as excinfo:
            client.sign_prepared_rotating(prepared)
        assert not isinstance(excinfo.value, SignOutcomeUnknownError)
        assert_verifier_refusal(excinfo.value)
    elif entry["expect"] == "unknown":
        with pytest.raises(SignOutcomeUnknownError) as excinfo:
            client.sign_prepared_rotating(prepared)
        assert excinfo.value.rotating is prepared
    else:
        raise AssertionError(f"unknown expectation {entry['expect']!r}")


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
@pytest.mark.parametrize("field", ["stage", "extra"])
def test_a_sign_answer_with_a_non_finite_number_is_unreadable(raw_signer, constant, field):
    # JSON has no such numbers, so the body is not JSON, even where the
    # number is in a field the client would otherwise ignore. Python's reader
    # would take them.
    case = CASES["wotsc_stage2"]
    prepared = prepared_from(case, case["prepare"])
    answer = dict(case["sign"], **{field: "PLACEHOLDER"})
    body = json.dumps(answer).replace('"PLACEHOLDER"', constant)
    raw_signer.body = body.encode()
    with pytest.raises(SignOutcomeUnknownError):
        signer_client(raw_signer.http.url).sign_prepared_rotating(prepared)


# The two rules the vectors cannot carry, because they depend on the client's
# own settings or on a pair of answers.


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_fee_ceiling_holds_a_captured_answer(name):
    case = CASES[name]
    raised = case["prepare"]["mutations"]["total_fees_delta"]
    assert raised > 0
    with pytest.raises(MaxFeeIncreaseError) as excinfo:
        prepared_from(case, case["prepare"], max_fee_increase=raised - 1)
    assert excinfo.value.raised == raised and excinfo.value.limit == raised - 1
    prepared_from(case, case["prepare"], max_fee_increase=raised)


def _rekeyed_to(case, rekey_to):
    """The case's prepare and sign answers with the spend rekeyed to
    rekey_to, signed with the same envelopes, and regrouped as a signer would
    have to."""
    prepare = copy.deepcopy(case["prepare"])
    sign = copy.deepcopy(case["sign"])
    txns = [decode_txn_hex(txn_hex) for txn_hex in prepare["transactions"]]
    txns[0].rekey_to = rekey_to
    regroup(txns)
    set_prepared(prepare, txns)
    prepare["rekey_to"] = rekey_to
    spend = decode_map(bytes.fromhex(sign["signed"][0]))
    spend["txn"] = decode_map(bytes.fromhex(encode_transaction(txns[0])[0])[2:])
    sign["signed"] = [encode_map(spend).hex()] + [
        _sign_canonical_dummy(txn).hex() for txn in txns[1:]
    ]
    sign["txid"] = txns[0].get_txid()
    sign["group_id"] = base64.b64encode(txns[0].group).decode()
    return prepare, sign


def test_a_spend_signed_by_the_program_whose_address_is_its_rekey_target_is_refused():
    case = CASES["wotsc_stage2"]
    stage_program = decode_map(bytes.fromhex(case["sign"]["signed"][0]))["lsig"]["l"]
    stage_address = program_address(stage_program)

    # Control: the same rebuilding with another target is accepted, so the
    # refusal below is the rule's.
    elsewhere = encoding.encode_address(bytes([0x55]) + bytes(31))
    prepare, sign = _rekeyed_to(case, elsewhere)
    verify_signed(prepared_from(case, prepare), sign)

    # The reported target is the address of the program that signs: each
    # answer is acceptable alone, and the pair is not.
    prepare, sign = _rekeyed_to(case, stage_address)
    prepared = prepared_from(case, prepare)
    with pytest.raises(SignerError, match="authorized by the next stage's program") as excinfo:
        verify_signed(prepared, sign)
    assert_verifier_refusal(excinfo.value)
