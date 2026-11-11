"""The examples are not run in CI (they need a signer and a node), so check
what can be checked without one: each compiles, every name it imports from
aplanesdk exists, and every method it calls on the signer client exists."""

import ast
import pathlib
import py_compile

import pytest

import aplanesdk
from aplanesdk import SignerClient

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
