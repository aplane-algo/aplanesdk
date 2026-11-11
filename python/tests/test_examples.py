"""The examples are not run in CI (they need a signer and a node), so check
what can be checked without one: each compiles, every name it imports from
aplanesdk exists, every method it calls on the signer client exists, and an
uncertain outcome the node cannot be asked about is printed and raised as it
was."""

import ast
import importlib.util
import pathlib
import py_compile
from unittest import mock

import pytest

import aplanesdk
from aplanesdk import (
    SEND_STAGE_CONFIRM,
    SignerClient,
    SignerError,
    SignOutcomeUnknownError,
    SubmissionUncertainError,
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


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
@pytest.mark.parametrize("kind", ["submission", "sign"])
def test_an_outcome_that_cannot_be_checked_raises_the_original_error(
    path, kind, monkeypatch, capsys
):
    if kind == "submission":
        error = SubmissionUncertainError(
            SEND_STAGE_CONFIRM, ["aa", "bb"], ["TXONE", "TXTWO"], SignerError("gone"), last_valid=10
        )
    else:
        error = SignOutcomeUnknownError(SignerError("gone"), request_id="req-7", last_valid=10)
    signer = mock.MagicMock()
    signer.get_key_info.return_value = None
    signer.send_prepared.side_effect = error
    signer.send_payment.side_effect = error
    signer.resolve_outcome.side_effect = SignerError("node down")
    factory = mock.MagicMock()
    factory.from_env.return_value.__enter__.return_value = signer
    module = _load(path)
    monkeypatch.setattr(module, "SignerClient", factory)

    with pytest.raises(type(error)) as excinfo:
        module.main()

    assert excinfo.value is error
    out = capsys.readouterr().out
    assert ("TXONE, TXTWO" if kind == "submission" else "request req-7") in out
    assert "Could not check the outcome (node down)" in out
