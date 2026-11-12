"""The examples are not run in CI (they need a signer and a node), so check
what can be checked without one: each compiles, every name it imports from
aplanesdk exists, every method it calls on the signer client exists, and an
unknown outcome is handled as the SDK docs say: a submitted group is waited
for with algosdk until its last valid round, a group whose submit call did not
return success is left to the caller to submit again, an unknown sign outcome
asks the node nothing, and an outcome the wait does not settle is raised as it
was."""

import ast
import importlib.util
import pathlib
import py_compile
from unittest import mock

import pytest

import aplanesdk
from aplanesdk import (
    SignerClient,
    SignerError,
    SignOutcomeUnknownError,
    SubmissionError,
)

EXAMPLES = sorted((pathlib.Path(__file__).resolve().parents[1] / "examples").glob("*.py"))

# Names an example binds to a SignerClient.
CLIENT_NAMES = {"signer", "client", "cosigner"}


def test_there_are_examples():
    assert EXAMPLES, "no examples found"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_compiles(path, tmp_path):
    py_compile.compile(str(path), cfile=str(tmp_path / "example.pyc"), doraise=True)


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_imports_names_that_exist(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "aplanesdk":
            for alias in node.names:
                assert hasattr(aplanesdk, alias.name), f"{path.name} imports aplanesdk.{alias.name}, which does not exist"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_calls_client_methods_that_exist(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in CLIENT_NAMES
        ):
            assert hasattr(SignerClient, node.func.attr), (
                f"{path.name} calls {node.func.value.id}.{node.func.attr}, which SignerClient does not have"
            )


def _load(path):
    spec = importlib.util.spec_from_file_location(f"example_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(path, monkeypatch, error, algod_client, signer=None):
    """Run the example's main against a signer whose send raises error and an
    algod client that is algod_client."""
    signer = signer or mock.MagicMock()
    signer.get_key_info.return_value = None
    signer.send_prepared.side_effect = error
    signer.send_payment.side_effect = error
    factory = mock.MagicMock()
    factory.from_env.return_value.__enter__.return_value = signer
    algod_module = mock.MagicMock()
    algod_module.AlgodClient.return_value = algod_client
    module = _load(path)
    monkeypatch.setattr(module, "SignerClient", factory)
    monkeypatch.setattr(module, "algod", algod_module)
    return module.main()


def _submission_error(last_valid=10, submitted=True, cause=None):
    return SubmissionError(
        ["aa", "bb"],
        ["TXONE", "TXTWO"],
        last_valid,
        submitted,
        cause or SignerError("gone"),
    )


def _assert_prints_what_acting_needs(out, last_valid=10):
    """Every entry of the signed group, as submit_signed_group takes it, the
    transaction IDs and the last valid round."""
    lines = [line.strip() for line in out.splitlines()]
    assert "aa" in lines and "bb" in lines
    assert "Transaction IDs: TXONE, TXTWO" in lines
    assert f"Last valid round: {last_valid}" in lines


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_a_submission_the_wait_cannot_settle_raises_the_original_error(path, monkeypatch, capsys):
    error = _submission_error()
    algod_client = mock.MagicMock()
    algod_client.status.side_effect = SignerError("node down")

    with pytest.raises(SubmissionError) as excinfo:
        _run(path, monkeypatch, error, algod_client)

    assert excinfo.value is error
    out = capsys.readouterr().out
    assert "Still unknown (node down)" in out
    _assert_prints_what_acting_needs(out)


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
@pytest.mark.parametrize(
    "current,waited",
    [(5, [6, 7, 8, 9, 10]), (10, [11]), (20, [21])],
    ids=["until last valid", "at last valid", "past last valid"],
)
def test_a_submitted_group_is_waited_for_until_its_last_valid_round(
    path, current, waited, monkeypatch, capsys
):
    # The wait follows the first transaction for last valid - current rounds,
    # at least one, then gives up without claiming anything.
    error = _submission_error(last_valid=10)
    signer = mock.MagicMock()
    algod_client = mock.MagicMock()
    algod_client.status.return_value = {"last-round": current}
    algod_client.pending_transaction_info.return_value = {"confirmed-round": 0, "pool-error": ""}

    with pytest.raises(SubmissionError) as excinfo:
        _run(path, monkeypatch, error, algod_client, signer)

    assert excinfo.value is error
    # The submit call returned success, so the group is not submitted again.
    signer.submit_signed_group.assert_not_called()
    assert {c.args[0] for c in algod_client.pending_transaction_info.call_args_list} == {"TXONE"}
    assert [c.args[0] for c in algod_client.status_after_block.call_args_list] == waited
    out = capsys.readouterr().out
    assert "after round 10, check an indexer before building a replacement" in out
    _assert_prints_what_acting_needs(out)


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_a_submitted_group_the_wait_sees_confirmed_is_reported(path, monkeypatch, capsys):
    algod_client = mock.MagicMock()
    algod_client.status.return_value = {"last-round": 5}
    algod_client.pending_transaction_info.return_value = {"confirmed-round": 7, "pool-error": ""}

    _run(path, monkeypatch, _submission_error(), algod_client)

    out = capsys.readouterr().out
    assert "Confirmed TXONE in round 7" in out
    assert "Last valid round" not in out


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_a_group_whose_submit_did_not_succeed_is_not_resubmitted_and_raises(
    path, monkeypatch, capsys
):
    # The example says what to do and raises the original error: it does not
    # submit again, wait, or read the cause.
    error = _submission_error(submitted=False)
    signer = mock.MagicMock()
    algod_client = mock.MagicMock()

    with pytest.raises(SubmissionError) as excinfo:
        _run(path, monkeypatch, error, algod_client, signer)

    assert excinfo.value is error
    signer.submit_signed_group.assert_not_called()
    assert algod_client.mock_calls == []
    out = capsys.readouterr().out
    assert "algod's HTTP 400, the node refused the group" in out
    assert "may or may not have the group" in out
    assert "submit the same signed_group again with submit_signed_group" in out
    _assert_prints_what_acting_needs(out)


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_an_unknown_sign_outcome_asks_the_node_nothing_and_raises(path, monkeypatch, capsys):
    error = SignOutcomeUnknownError(SignerError("gone"), request_id="req-7", last_valid=10)
    algod_client = mock.MagicMock()

    with pytest.raises(SignOutcomeUnknownError) as excinfo:
        _run(path, monkeypatch, error, algod_client)

    assert excinfo.value is error
    assert algod_client.mock_calls == []
    assert "request req-7" in capsys.readouterr().out
