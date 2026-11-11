# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Tests for aplane Python SDK client."""

import base64
import copy
import json
import os
import re
from unittest.mock import patch, MagicMock

import pytest
from algosdk import account, encoding as algo_encoding, transaction

import aplanesdk
from tests import fake_signer

from aplanesdk.signer import (
    SignerClient,
    AUTHORIZATION_KIND_LOGIC_SIG,
    AUTHORIZATION_KIND_NATIVE_PQ,
    PQ_SCHEME_FALCON1024,
    AuthenticationError,
    SigningRejectedError,
    SignerUnavailableError,
    SignerError,
    KeyNotFoundError,
    KeyDeletionError,
    sign_prepared_cosigned_group,
    simulate_prepared_cosigned_group,
    load_config,
    load_client_endpoint_registry,
    resolve_client_endpoint,
    ComponentRequest,
    ComponentResponse,
    AssemblyRequest,
    AssemblyTarget,
    AssemblyResponse,
    GroupSignResponse,
    KeyInfo,
    LogicSigResourceProfile,
    LogicSigResourceUsage,
    BoundedCosignerAuthorizationInfo,
    BoundedAuthorizationInfo,
    BoundedRekeyListInfo,
    BoundedSignatureArgLayout,
    PreparedTransaction,
    PreparedGroup,
    COMPONENT_TARGET_KIND_BOUNDED_BASE,
    COMPONENT_PATH_LISTED_REKEY,
    ASSEMBLY_TARGET_KIND_BOUNDED_COSIGNER,
    KEY_TYPE_WITNESS_FALCON1024,
    SIGNING_FLOW_COSIGNED1,
    EnrollmentError,
    EnrollmentResult,
    request_enrollment,
    request_enrollment_from_env,
    encode_transaction,
    _validate_sign_request_id,
    _request_bounded_primary_passthrough,
    _sign_cosigned_dummies,
    _validate_bounded_component_request,
    _validate_group_mutations,
    _decode_request_slots,
    _validate_bounded_target_fees,
    _decode_canonical_group,
    _selected_prepared_resources,
)

TEST_COMPONENT_KIND_COSIGNER = "cosigner"


def component_request(*, role, group_bytes_hex, target_indices, request_id="", component_key=""):
    target_set = set(target_indices)
    del role
    targets = []
    for index in target_indices:
        targets.append({"target_index": index, "kind": "cosigner", "component_key": component_key})
    return ComponentRequest(
        request_id=request_id,
        group_bytes_hex=group_bytes_hex,
        targets=targets,
        contextual_positions=[
            {"target_index": index}
            for index in range(len(group_bytes_hex))
            if index not in target_set
        ],
    )


def component_signature(target_index, signature, signature_scheme):
    return {
        "target_index": target_index,
        "kind": "cosigner",
        "signature": signature,
        "signature_scheme": signature_scheme,
    }


def component_response(*, request_id, signatures, component_key=""):
    del component_key
    return ComponentResponse(request_id=request_id, components=signatures)


def cosigned_assembly_target(*, target_index, account, cosigner_signature):
    return AssemblyTarget(
        target_index=target_index,
        kind="bounded-cosigner",
        auth_address=account,
        base_signatures=["aabb"],
        assembly_receipt="eeff",
        cosigner_signature=cosigner_signature,
    )


def cosigned_assembly_request(*, group_bytes_hex, request_id="", targets=None, passthrough=None):
    return AssemblyRequest(
        group_bytes_hex=group_bytes_hex,
        request_id=request_id,
        targets=targets,
        passthrough=passthrough,
    )


assembly_response = AssemblyResponse


def make_client(base_url="http://localhost:11270"):
    """Create a SignerClient with no SSH tunnel."""
    return SignerClient(base_url, timeout=10)


def mock_response(status_code=200, json_data=None, text=""):
    """Create a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = json.dumps(json_data).encode() if json_data else b""
    resp.json.return_value = json_data if json_data else {}
    return resp


def sdk_test_address(seed: int) -> str:
    raw = bytearray(32)
    raw[-1] = seed
    return algo_encoding.encode_address(bytes(raw))


def bounded_resource_test_key(rekey):
    return KeyInfo(
        address=sdk_test_address(1),
        key_type="aplane.falcon1024.v1",
        logic_sig_resources=LogicSigResourceProfile(
            spend=LogicSigResourceUsage(1001, 101, 10001),
            spending_rekey=LogicSigResourceUsage(2002, 202, 20002),
        ),
        bounded_authorization=BoundedAuthorizationInfo(
            contract="bounded2",
            base_signature_arg_layout=BoundedSignatureArgLayout(1, [1423]),
            spend_effects=["pay"],
            max_fee=1000,
            rekey=rekey,
            runtime_args=[],
            derived_args=[],
            argument_layout=[],
            layer3_policy="fixed_allowlist",
        ),
    )


@pytest.mark.parametrize(
    ("rekey_to", "rekey", "expected_program_bytes"),
    [
        (None, "refused", 1001),
        (None, "spending_key", 1001),
        (sdk_test_address(2), "spending_key", 2002),
    ],
)
def test_selected_prepared_resources_uses_bounded_authorization_path(
    rekey_to, rekey, expected_program_bytes
):
    key = bounded_resource_test_key(rekey)
    txn = MagicMock(rekey_to=rekey_to)

    selected = _selected_prepared_resources(key, txn)

    assert selected is not None
    assert selected.program_bytes == expected_program_bytes
    assert selected is not key.logic_sig_resources.spend
    assert selected is not key.logic_sig_resources.spending_rekey


# A rekey on an "only these" account is sized from the listed path: the signer
# checks the target against the account's list and adds the proof.
def test_selected_prepared_resources_uses_the_listed_path_for_only_these():
    key = bounded_resource_test_key("refused")
    key.logic_sig_resources.listed_rekey = LogicSigResourceUsage(1001, 1583, 20003)
    key.bounded_authorization.rekey_list = BoundedRekeyListInfo(contract="rekey_list1", depth=4)

    listed = _selected_prepared_resources(key, MagicMock(rekey_to=sdk_test_address(2)))
    assert listed == LogicSigResourceUsage(1001, 1583, 20003)
    assert listed is not key.logic_sig_resources.listed_rekey
    spend = _selected_prepared_resources(key, MagicMock(rekey_to=None))
    assert spend == LogicSigResourceUsage(1001, 101, 10001)


# Only spending_key authorizes a rekey without a list. refused says so; a
# missing setting and any other value (such as the removed admin_key
# authorization) are unavailable metadata.
@pytest.mark.parametrize("rekey,message", [
    ("refused", "the account refuses rekeys"),
    ("", "bounded rekey authorization metadata is unavailable"),
    ("admin_key", "bounded rekey authorization metadata is unavailable"),
])
def test_selected_prepared_resources_rejects_rekey_without_spending_key_authorization(rekey, message):
    key = bounded_resource_test_key(rekey)
    txn = MagicMock(rekey_to=sdk_test_address(2))

    with pytest.raises(ValueError, match=message):
        _selected_prepared_resources(key, txn)


def cosigned_test_resources():
    return LogicSigResourceUsage(
        program_bytes=1612,
        argument_bytes=1423,
        max_opcode_cost=20000,
    )


def create_cosigned_dummies(first_txn, count):
    dummy_account = transaction.LogicSigAccount(bytes.fromhex("033120320312"))
    dummy_address = dummy_account.address()
    params = transaction.SuggestedParams(
        int(first_txn.fee),
        int(first_txn.first_valid_round),
        int(first_txn.last_valid_round),
        first_txn.genesis_hash,
        first_txn.genesis_id,
        flat_fee=True,
    )
    dummies = []
    for index in range(count):
        txn = transaction.PaymentTxn(
            dummy_address,
            params,
            dummy_address,
            0,
            note=bytes([index]),
        )
        txn.fee = 0
        dummies.append(txn)
    return dummies


class MockAlgod:
    def __init__(self, accounts):
        self.accounts = accounts

    def suggested_params(self):
        return transaction.SuggestedParams(
            1000,
            1,
            100,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            gen="testnet-v1",
            flat_fee=False,
        )

    def account_info(self, address):
        return self.accounts[address]


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_healthy(self):
        client = make_client()
        with patch.object(client.session, "get", return_value=mock_response(200)):
            assert client.health() is True

    def test_unhealthy(self):
        client = make_client()
        with patch.object(client.session, "get", return_value=mock_response(503)):
            assert client.health() is False

    def test_network_error(self):
        import requests as req
        client = make_client()
        with patch.object(client.session, "get", side_effect=req.ConnectionError("refused")):
            assert client.health() is False

    def test_uses_client_timeout(self):
        client = make_client()
        with patch.object(client.session, "get", return_value=mock_response(200)) as mock_get:
            assert client.health() is True
        assert mock_get.call_args.kwargs["timeout"] == 3


# ---------------------------------------------------------------------------
# get_status
# ---------------------------------------------------------------------------

class TestGetStatus:
    def test_returns_signer_status(self):
        client = make_client()
        resp = mock_response(200, {
            "state": "unlocked",
            "signer_locked": False,
            "ready_for_signing": True,
            "key_count": 37,
            "keyset_revision": 4,
            "approval_wait_seconds": 60,
            "warnings": ["authenticated prune is required", 7],
        })

        with patch.object(client.session, "get", return_value=resp) as mock_get:
            status = client.get_status()

        assert status.keyset_revision == 4
        assert status.approval_wait_seconds == 60
        assert status.warnings == ["authenticated prune is required"]
        assert mock_get.call_args.args[0] == "http://localhost:11270/status"
        assert mock_get.call_args.kwargs["timeout"] == 5

    def test_locked_state_is_success(self):
        client = make_client()
        resp = mock_response(200, {
            "state": "locked",
            "signer_locked": True,
            "ready_for_signing": False,
            "key_count": 0,
            "keyset_revision": 2,
        })

        with patch.object(client.session, "get", return_value=resp):
            status = client.get_status()

        assert status.state == "locked"
        assert status.signer_locked is True
        assert status.ready_for_signing is False

    def test_null_approval_wait_defaults_to_zero(self):
        client = make_client()
        resp = mock_response(200, {
            "state": "unlocked",
            "approval_wait_seconds": None,
        })

        with patch.object(client.session, "get", return_value=resp):
            status = client.get_status()

        assert status.approval_wait_seconds == 0

    def test_invalid_warnings_default_to_empty(self):
        client = make_client()
        resp = mock_response(200, {
            "state": "unlocked",
            "warnings": None,
        })

        with patch.object(client.session, "get", return_value=resp):
            status = client.get_status()

        assert status.warnings == []

    def test_auth_error(self):
        client = make_client()
        with patch.object(client.session, "get", return_value=mock_response(401)):
            with pytest.raises(AuthenticationError):
                client.get_status()


# ---------------------------------------------------------------------------
# list_keys
# ---------------------------------------------------------------------------

class TestListKeys:
    def test_returns_keys(self):
        client = make_client()
        resp = mock_response(200, {
            "count": 2,
            "keys": [
                {"address": "ADDR1", "key_type": "ed25519", "public_key_hex": "abcd"},
                {
                    "address": "ADDR2",
                    "key_type": "aplane.falcon1024.v1",
                    "logic_sig_resources": {
                        "default": {
                            "program_bytes": 1612,
                            "argument_bytes": 1423,
                            "max_opcode_cost": 20000,
                        }
                    },
                    "template_provenance_status": "unavailable",
                    "template_provenance_note": "template fingerprint unavailable",
                },
            ],
        })
        with patch.object(client.session, "get", return_value=resp):
            keys = client.list_keys()

        assert len(keys) == 2
        assert keys[0].address == "ADDR1"
        assert keys[0].key_type == "ed25519"
        assert keys[0].public_key_hex == "abcd"
        assert keys[1].logic_sig_resources.default == LogicSigResourceUsage(
            program_bytes=1612,
            argument_bytes=1423,
            max_opcode_cost=20000,
        )
        assert keys[1].template_provenance_status == "unavailable"
        assert keys[1].template_provenance_note == "template fingerprint unavailable"

    def test_auth_error(self):
        client = make_client()
        with patch.object(client.session, "get", return_value=mock_response(401)):
            with pytest.raises(AuthenticationError):
                client.list_keys()

    def test_json_error_body(self):
        client = make_client()
        resp = mock_response(500, {"error": "inventory unavailable"})
        with patch.object(client.session, "get", return_value=resp):
            with pytest.raises(SignerError, match="inventory unavailable"):
                client.list_keys(refresh=True)

    def test_cache(self):
        client = make_client()
        resp = mock_response(200, {
            "count": 1,
            "keys": [{"address": "ADDR1", "key_type": "ed25519"}],
        })
        with patch.object(client.session, "get", return_value=resp) as mock_get:
            client.list_keys()
            client.list_keys()  # cached
            assert mock_get.call_count == 1

            client.list_keys(refresh=True)
            assert mock_get.call_count == 2

    def test_refresh_clears_stale_cache_entries(self):
        client = make_client()
        first = mock_response(200, {
            "count": 2,
            "keys": [
                {"address": "ADDR1", "key_type": "ed25519"},
                {"address": "ADDR2", "key_type": "ed25519"},
            ],
        })
        second = mock_response(200, {
            "count": 1,
            "keys": [
                {"address": "ADDR1", "key_type": "ed25519"},
            ],
        })

        with patch.object(client.session, "get", side_effect=[first, second]):
            client.list_keys()
            refreshed = client.list_keys(refresh=True)

        assert len(refreshed) == 1
        assert refreshed[0].address == "ADDR1"
        assert "ADDR2" not in client._key_cache

    def test_uses_client_timeout(self):
        client = make_client()
        with patch.object(client.session, "get", return_value=mock_response(200, {"count": 0, "keys": []})) as mock_get:
            client.list_keys(refresh=True)
        assert mock_get.call_args.kwargs["timeout"] == 10


class TestAuthResolution:
    def _status(self, revision=1):
        return mock_response(200, {
            "state": "unlocked",
            "signer_locked": False,
            "ready_for_signing": True,
            "key_count": 1,
            "keyset_revision": revision,
        })

    def _keys(self, *addresses):
        return mock_response(200, {
            "count": len(addresses),
            "keys": [
                {"address": address, "key_type": "ed25519"}
                for address in addresses
            ],
        })

    def test_list_keys_if_keyset_changed_uses_revision(self):
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(1),
            self._keys("ADDR1"),
            self._status(1),
            self._status(2),
            self._keys("ADDR2"),
        ]) as mock_get:
            first = client.list_keys_if_keyset_changed()
            second = client.list_keys_if_keyset_changed()
            third = client.list_keys_if_keyset_changed()

        assert [key.address for key in first] == ["ADDR1"]
        assert [key.address for key in second] == ["ADDR1"]
        assert [key.address for key in third] == ["ADDR2"]
        key_calls = [
            call.args[0] for call in mock_get.call_args_list
            if call.args[0].endswith("/keys")
        ]
        assert len(key_calls) == 2

    def test_resolve_auth_address_self_signing(self):
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(1),
            self._keys("SENDER"),
        ]):
            resolved = client.resolve_auth_address("SENDER", lambda _: {})

        assert resolved.address == "SENDER"
        assert resolved.auth_address == "SENDER"
        assert resolved.is_rekeyed is False
        assert resolved.key_info.address == "SENDER"

    def test_resolve_auth_address_rekeyed(self):
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(1),
            self._keys("AUTH"),
        ]):
            resolved = client.resolve_auth_address(
                "SENDER",
                lambda _: {"auth-addr": "AUTH"},
            )

        assert resolved.address == "SENDER"
        assert resolved.auth_address == "AUTH"
        assert resolved.is_rekeyed is True
        assert resolved.key_info.address == "AUTH"

    def test_resolve_auth_address_rejects_rekeyed_not_signable(self):
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(1),
            self._keys("SENDER"),
        ]):
            with pytest.raises(KeyNotFoundError, match="not signable"):
                client.resolve_auth_address(
                    "SENDER",
                    lambda _: {"auth-addr": "AUTH"},
                )


# ---------------------------------------------------------------------------
# list_key_types
# ---------------------------------------------------------------------------

class TestListKeyTypes:
    def test_returns_key_types(self):
        client = make_client()
        resp = mock_response(200, {
            "key_types": [
                {
                    "key_type": "ed25519",
                    "family": "ed25519",
                    "display_name": "Ed25519",
                    "requires_logicsig": False,
                    "mnemonic_import": True,
                },
                {
                    "key_type": "aplane.falcon1024.v1",
                    "family": "falcon",
                    "requires_logicsig": True,
                    "mnemonic_import": True,
                    "creation_params": [
                        {"name": "network", "label": "Network", "type": "string", "required": True},
                        {
                            "name": "recipients",
                            "label": "Recipients",
                            "type": "address[]",
                            "required": True,
                        },
                    ],
                },
            ],
        })
        with patch.object(client.session, "get", return_value=resp):
            types = client.list_key_types()

        assert len(types) == 2
        assert types[0].key_type == "ed25519"
        assert types[0].family == "ed25519"
        assert types[0].mnemonic_import is True
        assert types[1].key_type == "aplane.falcon1024.v1"
        assert types[1].mnemonic_import is True
        assert types[1].creation_params is not None
        assert len(types[1].creation_params) == 2
        assert types[1].creation_params[0].name == "network"
        assert types[1].creation_params[1].param_type == "address[]"

    def test_auth_error(self):
        client = make_client()
        with patch.object(client.session, "get", return_value=mock_response(401)):
            with pytest.raises(AuthenticationError):
                client.list_key_types()

    def test_uses_client_timeout(self):
        client = make_client()
        with patch.object(client.session, "get", return_value=mock_response(200, {"key_types": []})) as mock_get:
            client.list_key_types()
        assert mock_get.call_args.kwargs["timeout"] == 10


# ---------------------------------------------------------------------------
# generate_key
# ---------------------------------------------------------------------------

class TestGenerateKey:
    def test_generates_key(self):
        client = make_client()
        resp = mock_response(200, {
            "address": "NEWADDR123",
            "key_type": "ed25519",
        })
        with patch.object(client.session, "post", return_value=resp):
            result = client.generate_key("ed25519")

        assert result.address == "NEWADDR123"
        assert result.key_type == "ed25519"

    def test_with_parameters(self):
        client = make_client()
        resp = mock_response(200, {
            "address": "NEWADDR456",
            "key_type": "aplane.falcon1024.v1",
            "parameters": {"network": "testnet"},
        })
        with patch.object(client.session, "post", return_value=resp) as mock_post:
            result = client.generate_key("aplane.falcon1024.v1", {"network": "testnet"})

        assert result.address == "NEWADDR456"
        assert result.parameters == {"network": "testnet"}

        # Verify request body
        call_kwargs = mock_post.call_args
        body = call_kwargs[1]["json"] if "json" in call_kwargs[1] else json.loads(call_kwargs[1].get("data", "{}"))
        assert body["key_type"] == "aplane.falcon1024.v1"

    def test_auth_error(self):
        client = make_client()
        with patch.object(client.session, "post", return_value=mock_response(401)):
            with pytest.raises(AuthenticationError):
                client.generate_key("ed25519")

    def test_truncated_sign_response_rejected(self):
        client = make_client()
        entries = fake_signer.sign_entries(fake_signer.payment(41, 42), fake_signer.payment(43, 44))

        def truncate(body):
            body["signed"] = body["signed"][:1]

        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post(tamper=truncate)):
            with pytest.raises(SignerError, match="want at least 2"):
                client.sign_requests(entries)

    def test_foreign_slot_stays_empty(self):
        client = make_client()
        grouped = [fake_signer.payment(41, 42), fake_signer.payment(43, 44)]
        transaction.assign_group_id(grouped)
        entries = fake_signer.sign_entries(*grouped)
        entries[1] = {"txn_bytes_hex": entries[1]["txn_bytes_hex"]}
        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post()):
            result = client.sign_requests(entries)
        assert result.signed[1] == ""
        assert result.mutations["foreign_count"] == 1
        assert fake_signer.decode_signed(result.signed[0]).transaction == grouped[0]

    def test_locked_error(self):
        client = make_client()
        resp = mock_response(403, {"error": "signer is locked", "code": "locked"})
        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerUnavailableError):
                client.generate_key("ed25519")

    @pytest.mark.parametrize("body", [None, {"error": "forbidden"}])
    def test_forbidden_without_code_is_generic_error(self, body):
        client = make_client()
        with patch.object(client.session, "post", return_value=mock_response(403, body)):
            with pytest.raises(SignerError) as excinfo:
                client.generate_key("ed25519")
        assert type(excinfo.value) is SignerError
        assert excinfo.value.code == ""

    def test_locked_code_is_locked(self):
        client = make_client()
        resp = mock_response(403, {"error": "signer is locked", "code": "locked"})
        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerUnavailableError) as excinfo:
                client.generate_key("ed25519")
        assert excinfo.value.code == "locked"

    def test_forbidden_code_is_not_locked(self):
        client = make_client()
        resp = mock_response(
            403,
            {"error": "key generation not allowed for node role", "code": "forbidden"},
        )
        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerError) as excinfo:
                client.generate_key("ed25519")
        assert not isinstance(excinfo.value, SignerUnavailableError)
        assert excinfo.value.code == "forbidden"
        assert "node role" in str(excinfo.value)

    def test_missing_required_fields(self):
        client = make_client()
        resp = mock_response(200, {"key_type": "ed25519"})
        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerError, match="missing address"):
                client.generate_key("ed25519")

    def test_uses_client_timeout(self):
        client = make_client()
        resp = mock_response(200, {"address": "NEWADDR123", "key_type": "ed25519"})
        with patch.object(client.session, "post", return_value=resp) as mock_post:
            client.generate_key("ed25519")
        assert mock_post.call_args.kwargs["timeout"] == 10


# ---------------------------------------------------------------------------
# delete_key
# ---------------------------------------------------------------------------

class TestDeleteKey:
    def test_deletes_key(self):
        client = make_client()
        resp = mock_response(200, {})
        with patch.object(client.session, "delete", return_value=resp):
            client.delete_key("ADDR_TO_DELETE")  # should not raise

    def test_not_found(self):
        client = make_client()
        resp = mock_response(404, {"error": "Key not found: MISSING"})
        with patch.object(client.session, "delete", return_value=resp):
            with pytest.raises(KeyDeletionError):
                client.delete_key("MISSING")

    def test_auth_error(self):
        client = make_client()
        with patch.object(client.session, "delete", return_value=mock_response(401)):
            with pytest.raises(AuthenticationError):
                client.delete_key("ADDR")

    def test_uses_client_timeout(self):
        client = make_client()
        with patch.object(client.session, "delete", return_value=mock_response(200, {})) as mock_delete:
            client.delete_key("ADDR")
        assert mock_delete.call_args.kwargs["timeout"] == 10


# ---------------------------------------------------------------------------
# cosigner low-level endpoints
# ---------------------------------------------------------------------------

class TestSpecializedLowLevelEndpoints:
    def test_request_components_posts_to_component_endpoint(self):
        client = make_client()
        resp = mock_response(200, {
            "request_id": "sdk-generated",
            "components": [
                {
                    "target_index": 0,
                    "kind": "cosigner",
                    "signature": "aabb",
                    "signature_scheme": KEY_TYPE_WITNESS_FALCON1024,
                },
            ],
        })

        with patch.object(client.session, "post", return_value=resp) as mock_post:
            result = client.request_components(component_request(
                request_id="sdk-generated",
                role=TEST_COMPONENT_KIND_COSIGNER,
                component_key="COMPONENT",
                group_bytes_hex=["5458aa"],
                target_indices=[0],
            ))

        assert result.components[0]["signature"] == "aabb"
        assert mock_post.call_args.args[0] == "http://localhost:11270/sign/component"
        body = mock_post.call_args.kwargs["json"]
        assert body["request_id"].startswith("sdk-")
        assert body["targets"][0]["kind"] == "cosigner"
        assert body["targets"][0]["component_key"] == "COMPONENT"

    def test_request_components_rejects_cosigner_key_on_deny_all_default(self):
        client = make_client()
        witness_key_id = "A" * 52
        message = (
            "cosigner policy rejected request: txn 1: [transaction_type:pay] "
            "pay transactions are rejected by policy"
        )
        resp = mock_response(403, {"error": message, "code": "forbidden"})

        with patch.object(client.session, "post", return_value=resp) as mock_post:
            with pytest.raises(SigningRejectedError) as excinfo:
                client.request_components(component_request(
                    role=TEST_COMPONENT_KIND_COSIGNER,
                    component_key=witness_key_id,
                    group_bytes_hex=["5458aa"],
                    target_indices=[0],
                ))

        assert excinfo.value.code == "forbidden"
        assert str(excinfo.value) == message
        mock_post.assert_called_once()
        assert mock_post.call_args.args[0] == "http://localhost:11270/sign/component"

    def test_request_components_rejects_malformed_response(self):
        client = make_client()
        resp = mock_response(200, {"request_id": "sdk-test"})

        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerError, match="invalid component response"):
                client.request_components(component_request(
                    role=TEST_COMPONENT_KIND_COSIGNER,
                    group_bytes_hex=["5458aa"],
                    target_indices=[0],
                ))

    def test_request_components_rejects_foreign_target_index(self):
        client = make_client()
        resp = mock_response(200, {
            "request_id": "sdk-component",
            "components": [{
                "target_index": 1,
                "kind": "cosigner",
                "signature": "aabb",
                "signature_scheme": KEY_TYPE_WITNESS_FALCON1024,
            }],
        })

        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerError, match="indices or kinds do not match"):
                client.request_components(component_request(
                    request_id="sdk-component",
                    role=TEST_COMPONENT_KIND_COSIGNER,
                    group_bytes_hex=["5458aa", "5458bb"],
                    target_indices=[0],
                ))

    def test_request_components_rejects_out_of_group_target_index(self):
        client = make_client()
        resp = mock_response(200, {
            "request_id": "sdk-component",
            "components": [{
                "target_index": 1,
                "kind": "cosigner",
                "signature": "aabb",
                "signature_scheme": KEY_TYPE_WITNESS_FALCON1024,
            }],
        })

        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerError, match="outside the frozen group"):
                client.request_components(component_request(
                    request_id="sdk-component",
                    role=TEST_COMPONENT_KIND_COSIGNER,
                    group_bytes_hex=["5458aa"],
                    target_indices=[0],
                ))

    def test_request_assemble_posts_to_assemble_endpoint(self):
        client = make_client()
        resp = mock_response(200, {
            "request_id": "sdk-assembly",
            "signed_group": ["ccdd"],
        })

        with patch.object(client.session, "post", return_value=resp) as mock_post:
            result = client.request_assemble(cosigned_assembly_request(
                request_id="sdk-assembly",
                group_bytes_hex=["5458aa"],
                targets=[
                    cosigned_assembly_target(
                        target_index=0,
                        account="BOUNDED",
                        cosigner_signature="bbcc",
                    ),
                ],
            ))

        assert result.signed_group == ["ccdd"]
        assert mock_post.call_args.args[0] == "http://localhost:11270/sign/assemble"
        body = mock_post.call_args.kwargs["json"]
        assert body["request_id"].startswith("sdk-")
        assert body["targets"][0]["kind"] == "bounded-cosigner"
        assert body["targets"][0]["auth_address"] == "BOUNDED"

    def test_request_assemble_rejects_missing_coverage(self):
        client = make_client()
        with patch.object(client.session, "post") as mock_post:
            with pytest.raises(ValueError, match="not covered"):
                client.request_assemble(cosigned_assembly_request(
                    group_bytes_hex=["5458aa", "5458bb"],
                    targets=[
                        cosigned_assembly_target(
                            target_index=0,
                            account="BOUNDED",
                            cosigner_signature="bbcc",
                        ),
                    ],
                ))

        mock_post.assert_not_called()

    def test_bounded_component_and_assembly_endpoints(self):
        client = make_client()
        component_response = mock_response(
            200,
            {
                "request_id": "bounded-base-id",
                "components": [{
                    "target_index": 0,
                    "kind": "bounded-base",
                    "auth_address": "BOUNDED",
                    "base_signatures": ["base-sig"],
                    "assembly_receipt": "receipt",
                    "signature_scheme": "aplane.falcon1024.v1",
                    "path": "spend",
                }],
            },
        )
        assembly_response = mock_response(
            200,
            {"request_id": "bounded-assembly-id", "signed_group": ["signed"]},
        )
        with patch.object(
            client.session,
            "post",
            side_effect=[component_response, assembly_response],
        ) as mock_post, patch.object(client, "_discover_approval_wait"):
            component = client.request_components(ComponentRequest(
                request_id="bounded-base-id",
                group_bytes_hex=["5458aa"],
                targets=[{"target_index": 0, "kind": COMPONENT_TARGET_KIND_BOUNDED_BASE, "auth_address": "BOUNDED"}],
            ))
            assembly = client.request_assemble({
                "request_id": "bounded-assembly-id",
                "group_bytes_hex": ["5458aa"],
                "targets": [{
                    "target_index": 0,
                    "kind": ASSEMBLY_TARGET_KIND_BOUNDED_COSIGNER,
                    "auth_address": "BOUNDED",
                    "base_signatures": ["base-sig"],
                    "assembly_receipt": "receipt",
                    "cosigner_signature": "cosigner-sig",
                }],
            })

        assert component.components[0]["assembly_receipt"] == "receipt"
        assert assembly.signed_group == ["signed"]
        assert mock_post.call_args_list[0].args[0].endswith(
            "/sign/component"
        )
        assert mock_post.call_args_list[1].args[0].endswith(
            "/sign/assemble"
        )

    def test_bounded_component_timeout_sends_best_effort_cancel(self):
        import requests

        client = make_client()
        cancel_response = mock_response(
            200, {"success": True, "state": "canceled"}
        )
        with patch.object(
            client.session,
            "post",
            side_effect=[requests.Timeout("timed out"), cancel_response],
        ) as mock_post, patch.object(client, "_discover_approval_wait"):
            with pytest.raises(SignerUnavailableError):
                client.request_components(ComponentRequest(
                    request_id="bounded-cancel-id",
                    group_bytes_hex=["5458aa"],
                    targets=[{"target_index": 0, "kind": COMPONENT_TARGET_KIND_BOUNDED_BASE, "auth_address": "BOUNDED"}],
                ))

        assert mock_post.call_args_list[0].args[0].endswith(
            "/sign/component"
        )
        assert mock_post.call_args_list[1].args[0].endswith("/sign/cancel")
        assert mock_post.call_args_list[1].kwargs["json"] == {
            "request_id": "bounded-cancel-id"
        }

    def test_bounded_endpoints_classify_not_found(self):
        client = make_client()
        response = mock_response(
            400, {"error": "key not found", "code": "not_found"}
        )
        with patch.object(
            client.session, "post", return_value=response
        ), patch.object(client, "_discover_approval_wait"):
            with pytest.raises(KeyNotFoundError):
                client.request_components(ComponentRequest(
                    request_id="bounded-not-found",
                    group_bytes_hex=["5458aa"],
                    targets=[{"target_index": 0, "kind": COMPONENT_TARGET_KIND_BOUNDED_BASE, "auth_address": "BOUNDED"}],
                ))

    def test_bounded_endpoints_surface_200_error_bodies(self):
        client = make_client()
        error_response = mock_response(200, {"error": "bounded failed"})
        with patch.object(
            client.session, "post", return_value=error_response
        ), patch.object(client, "_discover_approval_wait"):
            with pytest.raises(SignerError, match="bounded failed"):
                client.request_components(ComponentRequest(
                    request_id="bounded-base-id",
                    group_bytes_hex=["5458aa"],
                    targets=[{"target_index": 0, "kind": COMPONENT_TARGET_KIND_BOUNDED_BASE, "auth_address": "BOUNDED"}],
                ))

        with patch.object(client.session, "post", return_value=error_response):
            with pytest.raises(SignerError, match="bounded failed"):
                client.request_assemble({
                    "request_id": "bounded-assembly-id",
                    "group_bytes_hex": ["5458aa"],
                    "targets": [{
                        "target_index": 0,
                        "kind": ASSEMBLY_TARGET_KIND_BOUNDED_COSIGNER,
                        "auth_address": "BOUNDED",
                        "base_signatures": ["base-sig"],
                        "assembly_receipt": "receipt",
                        "cosigner_signature": "cosigner-sig",
                    }],
                })

def record_call_order(events, **mocks):
    """Wrap MagicMocks so each call appends its name to events, in call order."""
    for name, mock in mocks.items():
        def side_effect(*args, _name=name, _original=mock.side_effect,
                        _return=mock.return_value, **kwargs):
            events.append(_name)
            if isinstance(_original, BaseException):
                raise _original
            if _original is not None:
                return _original(*args, **kwargs)
            return _return
        mock.side_effect = side_effect


class TestSignPreparedCosignedGroup:
    @pytest.fixture(autouse=True)
    def _signer_holds_the_groups_keys(self, monkeypatch):
        """The cosigned flow reads each key from the signer, not from the group.

        These tests describe the signer's keys on the prepared transactions, so
        the user client here answers key lookups with exactly those.
        """
        real = sign_prepared_cosigned_group

        def sign(*args, **kwargs):
            user = kwargs.get("user_client")
            group = kwargs.get("prepared_group")
            # A test that sets its own key lookup on a real client keeps it.
            own_lookup = not isinstance(user, MagicMock) and isinstance(
                getattr(user, "__dict__", {}).get("get_key_info"), MagicMock
            )
            if user is not None and group is not None and not own_lookup:
                held = {
                    item.signer_key.address: item.signer_key
                    for item in group.transactions
                    if item.signer_key is not None
                }
                user.get_key_info = held.get
            return real(*args, **kwargs)

        monkeypatch.setitem(globals(), "sign_prepared_cosigned_group", sign)

    def test_prepared_plan_preserves_per_slot_args_for_repeated_auth_address(self):
        cosigned = sdk_test_address(31)
        receiver = sdk_test_address(32)
        user = make_client()
        params = transaction.SuggestedParams(
            1000,
            1,
            100,
            base64.b64encode(bytes(32)).decode(),
            "testnet-v1.0",
            flat_fee=True,
        )
        signer_key = KeyInfo(
            address=cosigned,
            key_type="aplane.falcon1024.v1",
            signing_flow=SIGNING_FLOW_COSIGNED1,
            cosigner_component_key_type=KEY_TYPE_WITNESS_FALCON1024,
            logic_sig_resources=LogicSigResourceProfile(
                spend=LogicSigResourceUsage(1612, 1423, 20000)
            ),
            bounded_authorization=BoundedAuthorizationInfo(
                contract="plain1",
                base_signature_arg_layout=BoundedSignatureArgLayout(count=1, max_sizes=[1280]),
                spend_effects=[],
                max_fee=None,
                rekey="refused",
                runtime_args=[],
                derived_args=[],
                argument_layout=[],
                layer3_policy="none",
                cosigner=BoundedCosignerAuthorizationInfo(
                    contract="cosigner1",
                    component_key_type=KEY_TYPE_WITNESS_FALCON1024,
                    public_key_hex="aabbcc",
                    component_key_id="",
                    signature_max_size=1423,
                    required_on=["spend"],
                ),
            ),
        )

        def assert_per_slot_requests(requests):
            assert [request["lsig_args"] for request in requests] == [
                {"preimage": b"alpha".hex()},
                {"preimage": b"beta".hex()},
            ]
            assert [request["app_call_info"] for request in requests] == [
                {"mode": "raw", "method": "first"},
                {"mode": "abi", "method": "second"},
            ]
            raise RuntimeError("stop after per-slot plan assertion")

        user.plan_requests = MagicMock(side_effect=assert_per_slot_requests)
        prepared = PreparedGroup([
            PreparedTransaction(
                transaction=transaction.PaymentTxn(cosigned, params, receiver, 1),
                auth_address=cosigned,
                signer_key=signer_key,
                lsig_args={"preimage": b"alpha"},
                app_call_info={"mode": "raw", "method": "first"},
            ),
            PreparedTransaction(
                transaction=transaction.PaymentTxn(cosigned, params, receiver, 2),
                auth_address=cosigned,
                signer_key=signer_key,
                lsig_args={"preimage": b"beta"},
                app_call_info={"mode": "abi", "method": "second"},
            ),
        ])

        with pytest.raises(RuntimeError, match="stop after per-slot plan assertion"):
            sign_prepared_cosigned_group(user_client=user, prepared_group=prepared)

    def test_plan_validation_rejects_unreported_changes_and_bad_dummies(self):
        sender = sdk_test_address(21)
        receiver = sdk_test_address(22)
        params = transaction.SuggestedParams(
            1000,
            1,
            100,
            base64.b64encode(bytes(32)).decode(),
            "testnet-v1.0",
            flat_fee=True,
        )
        original = transaction.PaymentTxn(sender, params, receiver, 1000)
        planned_original = transaction.PaymentTxn(sender, params, receiver, 1000)
        planned_original.fee += 1000
        dummy = create_cosigned_dummies(original, 1)[0]
        planned = [planned_original, dummy]
        transaction.assign_group_id(planned)
        mutations = {
            "dummies_added": 1,
            "group_id_changed": True,
            "fees_modified": [0],
            "total_fees_delta": 1000,
            "original_count": 1,
            "final_count": 2,
        }
        slots = _decode_request_slots(fake_signer.sign_entries(original))

        def regroup(txns):
            for txn in txns:
                txn.group = None
            transaction.assign_group_id(txns)
            return txns

        _validate_group_mutations(slots, planned, mutations, None)

        changed = copy.deepcopy(planned)
        changed[0].receiver = sdk_test_address(23)
        with pytest.raises(SignerError, match="unreported fields"):
            _validate_group_mutations(slots, regroup(changed), mutations, None)

        changed = copy.deepcopy(planned)
        changed[1].amt = 1
        with pytest.raises(SignerError, match="not the canonical resource dummy"):
            _validate_group_mutations(slots, regroup(changed), mutations, None)
        with pytest.raises(SignerError, match="not the canonical resource dummy"):
            _sign_cosigned_dummies(original, changed[1].group, changed[1:], 1)

        # A dummy on another validity window is not the planner's dummy.
        changed = copy.deepcopy(planned)
        changed[1].last_valid_round += 1
        with pytest.raises(SignerError, match="not the canonical resource dummy"):
            _validate_group_mutations(slots, regroup(changed), mutations, None)

        grouped = copy.deepcopy(original)
        grouped.group = bytes([0x31]) * 32
        regrouped = copy.deepcopy(grouped)
        regrouped.group = bytes([0x32]) * 32
        with pytest.raises(SignerError, match="group ID change for a single transaction"):
            _validate_group_mutations(
                _decode_request_slots(fake_signer.sign_entries(grouped)),
                [regrouped],
                {
                    "group_id_changed": True,
                    "original_count": 1,
                    "final_count": 1,
                }, None)

        with pytest.raises(SignerError, match="exceeds advertised max_fee"):
            _validate_bounded_target_fees(planned, {0: planned[0].fee - 1})

    def test_bounded_canonical_group_recomputes_group_id(self):
        import msgpack

        sender = sdk_test_address(61)
        receiver = sdk_test_address(62)
        params = transaction.SuggestedParams(
            1000,
            1,
            100,
            base64.b64encode(bytes(32)).decode(),
            "testnet-v1.0",
            flat_fee=True,
        )
        first = transaction.PaymentTxn(sender, params, receiver, 1)
        second = transaction.PaymentTxn(sender, params, receiver, 2)

        def encode(txn):
            return (
                b"TX" + base64.b64decode(algo_encoding.msgpack_encode(txn))
            ).hex()

        assert len(_decode_canonical_group([encode(first)])) == 1

        grouped = [copy.deepcopy(first), copy.deepcopy(second)]
        transaction.assign_group_id(grouped)
        assert len(_decode_canonical_group([encode(txn) for txn in grouped])) == 2

        fabricated = [copy.deepcopy(first), copy.deepcopy(second)]
        for txn in fabricated:
            txn.group = bytes([0x44]) * 32
        with pytest.raises(SignerError, match="does not carry the canonical group ID"):
            _decode_canonical_group([encode(txn) for txn in fabricated])

        singleton = copy.deepcopy(first)
        singleton.group = bytes([0x44]) * 32
        with pytest.raises(SignerError, match="singleton"):
            _decode_canonical_group([encode(singleton)])

        canonical = base64.b64decode(algo_encoding.msgpack_encode(first))
        fields = msgpack.unpackb(canonical, raw=False)
        noncanonical = msgpack.packb(
            dict(reversed(list(fields.items()))), use_bin_type=True
        )
        assert noncanonical != canonical
        with pytest.raises(SignerError, match="bytes are not canonical"):
            _decode_canonical_group([(b"TX" + noncanonical).hex()])

    def test_bounded_component_rejects_incomplete_partition(self):
        with pytest.raises(ValueError, match="group_bytes_hex is empty"):
            _validate_bounded_component_request({
                "request_id": "bounded-request",
                "targets": [{"target_index": 0, "auth_address": "BOUNDED"}],
            })

        user = make_client()
        user.get_key_info = MagicMock(
            side_effect=AuthenticationError("Not authenticated: connect through an enrolled SSH key")
        )
        params = transaction.SuggestedParams(
            1000, 1, 100, base64.b64encode(bytes(32)).decode(), "testnet-v1.0", flat_fee=True
        )
        with pytest.raises(AuthenticationError):
            sign_prepared_cosigned_group(
                user_client=user,
                prepared_group=PreparedGroup([
                    PreparedTransaction(
                        transaction=transaction.PaymentTxn(
                            sdk_test_address(24), params, sdk_test_address(25), 1
                        ),
                        auth_address=sdk_test_address(24),
                    )
                ]),
            )

    def test_bounded_primary_passthrough_verifies_transaction_identity(self):
        sender = sdk_test_address(31)
        receiver = sdk_test_address(32)
        params = transaction.SuggestedParams(
            1000,
            1,
            100,
            base64.b64encode(bytes(32)).decode(),
            "testnet-v1.0",
            flat_fee=True,
        )
        txn = transaction.PaymentTxn(sender, params, receiver, 1000)
        other = transaction.PaymentTxn(sender, params, receiver, 2000)
        canonical, _ = encode_transaction(txn)
        logic_sig = transaction.LogicSigAccount(bytes.fromhex("033120320312"))

        def signed_hex(value):
            encoded = algo_encoding.msgpack_encode(
                transaction.LogicSigTransaction(value, logic_sig)
            )
            return base64.b64decode(encoded).hex()

        user = make_client()
        user.sign_requests = MagicMock(
            return_value=GroupSignResponse(signed=[signed_hex(txn)])
        )
        _, passthrough = _request_bounded_primary_passthrough(
            user,
            [canonical],
            1,
            set(),
            {},
            [{"target_index": 0, "auth_address": sender}],
        )
        assert len(passthrough) == 1

        user.sign_requests.return_value = GroupSignResponse(signed=[signed_hex(other)])
        with pytest.raises(SignerError, match="does not match"):
            _request_bounded_primary_passthrough(
                user,
                [canonical],
                1,
                set(),
                {},
                [{"target_index": 0, "auth_address": sender}],
            )

    def test_prepared_cosigned_listed_rekey_skips_the_cosigner(self):
        """A listed rekey takes no cosigner component: the base component names
        the listed path, the cosigner sees nothing, and assembly carries no
        cosigner signature."""
        bounded = sdk_test_address(13)
        target = sdk_test_address(14)
        user = make_client()
        cosigner = make_client("http://cosigner:11270")
        user.request_components = MagicMock(return_value=ComponentResponse(
            request_id="base-id",
            components=[{
                "target_index": 0, "kind": COMPONENT_TARGET_KIND_BOUNDED_BASE,
                "auth_address": bounded, "base_signatures": ["base-sig"],
                "assembly_receipt": "receipt", "signature_scheme": "aplane.falcon1024.v1",
                "path": COMPONENT_PATH_LISTED_REKEY,
            }],
        ))
        user.plan_requests = MagicMock(side_effect=lambda requests: {
            "transactions": [requests[0]["txn_bytes_hex"]],
        })
        cosigner.request_components = MagicMock(
            side_effect=AssertionError("the cosigner was asked about a listed rekey")
        )
        params = transaction.SuggestedParams(
            1000, 1, 100, base64.b64encode(bytes(32)).decode(), "testnet-v1.0", flat_fee=True,
        )
        txn = transaction.PaymentTxn(bounded, params, bounded, 0, rekey_to=target)

        def signed_txn_hex(signed_txn):
            logic_sig = transaction.LogicSigAccount(bytes.fromhex("033120320312"))
            encoded = algo_encoding.msgpack_encode(transaction.LogicSigTransaction(signed_txn, logic_sig))
            return base64.b64decode(encoded).hex()

        def listed_assemble(req):
            assert req.targets[0].cosigner_signature == ""
            assert req.targets[0].cosigner_source_request_id == ""
            return AssemblyResponse(request_id="assembly-id", signed_group=[signed_txn_hex(txn)])

        user.request_assemble = MagicMock(side_effect=listed_assemble)
        key = KeyInfo(
            address=bounded,
            key_type="aplane.falcon1024.v1",
            signing_flow=SIGNING_FLOW_COSIGNED1,
            cosigner_component_key_type=KEY_TYPE_WITNESS_FALCON1024,
            logic_sig_resources=LogicSigResourceProfile(
                spend=LogicSigResourceUsage(5308, 3358, 20000),
                spending_rekey=LogicSigResourceUsage(5308, 2846, 20000),
                listed_rekey=LogicSigResourceUsage(5308, 1583, 20000),
            ),
            bounded_authorization=BoundedAuthorizationInfo(
                contract="bounded2",
                base_signature_arg_layout=BoundedSignatureArgLayout(count=1, max_sizes=[1280]),
                spend_effects=["pay"],
                max_fee=1000,
                rekey="spending_key",
                runtime_args=[],
                derived_args=[],
                argument_layout=[],
                layer3_policy="merkle_allowlist",
                cosigner=BoundedCosignerAuthorizationInfo(
                    contract="cosigner1",
                    component_key_type=KEY_TYPE_WITNESS_FALCON1024,
                    public_key_hex="aabb",
                ),
                rekey_list=BoundedRekeyListInfo(contract="rekey_list1", depth=4),
            ),
        )
        result = sign_prepared_cosigned_group(
            user_client=user,
            cosigner_client=cosigner,
            cosigner_component_key="COSIGNER_COMPONENT",
            prepared_group=PreparedGroup([
                PreparedTransaction(transaction=txn, auth_address=bounded, signer_key=key)
            ]),
        )
        assert result.signed_group == [signed_txn_hex(txn)]
        assert result.cosigner_component_responses == []
        cosigner.request_components.assert_not_called()

    def test_prepared_cosigned_mixed_paths(self):
        """A listed rekey (0), two spends under one cosigner key (1, 2) and a
        primary slot (3): one cosigner request for the spends with the other
        positions as context, path-selected resources on the primary /sign, and
        cosigner material only where the path needs it. A cosigner signature in
        another scheme than the account's cosigner key type is refused."""
        listed = sdk_test_address(31)
        spend_a = sdk_test_address(32)
        spend_b = sdk_test_address(33)
        primary = sdk_test_address(34)
        receiver = sdk_test_address(35)
        rekey_target = sdk_test_address(36)
        params = transaction.SuggestedParams(
            1000, 1, 100, base64.b64encode(bytes(32)).decode(), "testnet-v1.0", flat_fee=True,
        )
        txns = transaction.assign_group_id([
            transaction.PaymentTxn(listed, params, listed, 0, rekey_to=rekey_target),
            transaction.PaymentTxn(spend_a, params, receiver, 1000),
            transaction.PaymentTxn(spend_b, params, receiver, 2000),
            transaction.PaymentTxn(primary, params, receiver, 3000),
        ])

        def signed_txn_hex(signed_txn):
            logic_sig = transaction.LogicSigAccount(bytes.fromhex("033120320312"))
            encoded = algo_encoding.msgpack_encode(transaction.LogicSigTransaction(signed_txn, logic_sig))
            return base64.b64decode(encoded).hex()

        def cosigned_key(address):
            return KeyInfo(
                address=address,
                key_type="aplane.falcon1024.v1",
                signing_flow=SIGNING_FLOW_COSIGNED1,
                cosigner_component_key_type=KEY_TYPE_WITNESS_FALCON1024,
                logic_sig_resources=LogicSigResourceProfile(
                    spend=LogicSigResourceUsage(5308, 3358, 20000),
                    spending_rekey=LogicSigResourceUsage(5308, 2846, 20000),
                    listed_rekey=LogicSigResourceUsage(5308, 1583, 20000),
                ),
                bounded_authorization=BoundedAuthorizationInfo(
                    contract="plain1",
                    base_signature_arg_layout=BoundedSignatureArgLayout(count=1, max_sizes=[1280]),
                    spend_effects=[],
                    max_fee=None,
                    rekey="spending_key",
                    runtime_args=[],
                    derived_args=[],
                    argument_layout=[],
                    layer3_policy="",
                    cosigner=BoundedCosignerAuthorizationInfo(
                        contract="cosigner1",
                        component_key_type=KEY_TYPE_WITNESS_FALCON1024,
                        public_key_hex="aabb",
                    ),
                    rekey_list=BoundedRekeyListInfo(contract="rekey_list1", depth=4),
                ),
            )

        def base(index, account, path):
            return {
                "target_index": index, "kind": COMPONENT_TARGET_KIND_BOUNDED_BASE,
                "auth_address": account, "base_signatures": ["base-sig"],
                "assembly_receipt": "receipt", "signature_scheme": "aplane.falcon1024.v1",
                "path": path,
            }

        for wrong_scheme in (False, True):
            user = make_client()
            cosigner = make_client("http://cosigner:11270")
            user.plan_requests = MagicMock(side_effect=lambda requests: {
                "transactions": [request["txn_bytes_hex"] for request in requests],
            })
            user.request_components = MagicMock(return_value=ComponentResponse(
                request_id="base-id",
                components=[
                    base(0, listed, COMPONENT_PATH_LISTED_REKEY),
                    base(1, spend_a, "spend"),
                    base(2, spend_b, "spend"),
                ],
            ))
            user.sign_requests = MagicMock(return_value=GroupSignResponse(
                signed=[signed_txn_hex(txn) for txn in txns],
            ))
            user.request_assemble = MagicMock(side_effect=lambda req: AssemblyResponse(
                request_id="assembly-id", signed_group=[signed_txn_hex(txn) for txn in txns],
            ))
            scheme = "aplane.falcon1024.v1" if wrong_scheme else KEY_TYPE_WITNESS_FALCON1024
            cosigner.request_components = MagicMock(side_effect=lambda req: component_response(
                request_id="cosigner-id",
                signatures=[
                    component_signature(target["target_index"], f"cosigner-sig-{target['target_index']}", scheme)
                    for target in req.targets
                ],
            ))
            prepared = PreparedGroup([
                PreparedTransaction(transaction=txns[0], auth_address=listed,
                                    signer_key=cosigned_key(listed), app_call_info={"mode": "listed"}),
                PreparedTransaction(transaction=txns[1], auth_address=spend_a, signer_key=cosigned_key(spend_a)),
                PreparedTransaction(transaction=txns[2], auth_address=spend_b, signer_key=cosigned_key(spend_b)),
                PreparedTransaction(
                    transaction=txns[3], auth_address=primary, app_call_info={"mode": "primary"},
                    signer_key=KeyInfo(address=primary, key_type="ed25519", authorization_kind="ed25519"),
                ),
            ])
            sign = lambda: sign_prepared_cosigned_group(
                user_client=user,
                cosigner_client=cosigner,
                cosigner_component_key="COSIGNER_COMPONENT",
                prepared_group=prepared,
            )
            if wrong_scheme:
                with pytest.raises(SignerError, match="used scheme"):
                    sign()
                user.request_assemble.assert_not_called()
                continue
            result = sign()

            assert cosigner.request_components.call_count == 1
            cosigner_request = cosigner.request_components.call_args.args[0]
            assert [target["target_index"] for target in cosigner_request.targets] == [1, 2]
            assert {target["component_key"] for target in cosigner_request.targets} == {"COSIGNER_COMPONENT"}
            assert {
                position["target_index"]: position.get("app_call_info")
                for position in cosigner_request.contextual_positions
            } == {0: {"mode": "listed"}, 3: {"mode": "primary"}}

            # The user signer's approval shows the primary slot's app call.
            base_request = user.request_components.call_args.args[0]
            assert [
                (position["target_index"], position.get("app_call_info"))
                for position in base_request.contextual_positions
            ] == [(3, {"mode": "primary"})]
            primary_requests = user.sign_requests.call_args.args[0]
            assert len(primary_requests) == 4
            for index, argument_bytes in {0: 1583, 1: 3358, 2: 3358}.items():
                assert "auth_address" not in primary_requests[index]
                assert primary_requests[index]["lsig_resources"]["argument_bytes"] == argument_bytes
            assert primary_requests[3]["auth_address"] == primary
            assert primary_requests[3]["app_call_info"] == {"mode": "primary"}

            assembly = user.request_assemble.call_args.args[0]
            by_index = {target.target_index: target for target in assembly.targets}
            assert sorted(by_index) == [0, 1, 2]
            assert by_index[0].cosigner_signature == "" and by_index[0].cosigner_source_request_id == ""
            for index in (1, 2):
                assert by_index[index].cosigner_signature == f"cosigner-sig-{index}"
                assert by_index[index].cosigner_source_request_id == "cosigner-id"
            assert [item.target_index for item in assembly.passthrough] == [3]
            assert len(result.signed_group) == 4
            assert len(result.cosigner_component_responses) == 1

    def test_prepared_bounded_cosigner_uses_user_first_flow(self):
        bounded = sdk_test_address(11)
        receiver = sdk_test_address(12)
        user = make_client()
        cosigner = make_client("http://cosigner:11270")

        def bounded_component(req):
            assert isinstance(req, ComponentRequest)
            assert req.targets[0]["auth_address"] == bounded
            return ComponentResponse(
                request_id="base-id",
                components=[{
                    "target_index": 0, "kind": COMPONENT_TARGET_KIND_BOUNDED_BASE,
                    "auth_address": bounded, "base_signatures": ["base-sig"],
                    "runtime_args": {"proof": "aabb"}, "assembly_receipt": "receipt",
                    "signature_scheme": "aplane.falcon1024.v1", "path": "spend",
                }],
            )

        user.request_components = MagicMock(side_effect=bounded_component)
        user.plan_requests = MagicMock(side_effect=lambda requests: {
            "transactions": [requests[0]["txn_bytes_hex"]],
        })
        cosigner.request_components = MagicMock(return_value=component_response(
            request_id="cosigner-id",
            signatures=[component_signature(
                0, "cosigner-sig", KEY_TYPE_WITNESS_FALCON1024
            )],
        ))

        def signed_txn_hex(signed_txn):
            logic_sig = transaction.LogicSigAccount(bytes.fromhex("033120320312"))
            encoded = algo_encoding.msgpack_encode(
                transaction.LogicSigTransaction(signed_txn, logic_sig)
            )
            return base64.b64decode(encoded).hex()

        assembled_txn = [None]

        def bounded_assemble(req):
            assert req.targets[0].base_signatures == ["base-sig"]
            assert req.targets[0].assembly_receipt == "receipt"
            assert req.targets[0].cosigner_signature == "cosigner-sig"
            return AssemblyResponse(
                request_id="assembly-id",
                signed_group=[signed_txn_hex(assembled_txn[0])],
            )

        user.request_assemble = MagicMock(side_effect=bounded_assemble)
        user.sign_requests = MagicMock(
            side_effect=AssertionError("all-bounded path must not call /sign")
        )

        params = transaction.SuggestedParams(
            1000,
            1,
            100,
            base64.b64encode(bytes(32)).decode(),
            "testnet-v1.0",
            flat_fee=True,
        )
        txn = transaction.PaymentTxn(bounded, params, receiver, 1000)
        prepared_group = PreparedGroup(
            [
                PreparedTransaction(
                    transaction=txn,
                    auth_address=bounded,
                    app_call_info={"mode": "raw"},
                    signer_key=KeyInfo(
                        address=bounded,
                        key_type="aplane.falcon1024.v1",
                        signing_flow=SIGNING_FLOW_COSIGNED1,
                        cosigner_component_key_type=KEY_TYPE_WITNESS_FALCON1024,
                        logic_sig_resources=LogicSigResourceProfile(
                            spend=LogicSigResourceUsage(5308, 3358, 20000)
                        ),
                        bounded_authorization=BoundedAuthorizationInfo(
                            contract="bounded2",
                            base_signature_arg_layout=BoundedSignatureArgLayout(
                                count=1, max_sizes=[1280]
                            ),
                            spend_effects=["pay"],
                            max_fee=1000,
                            rekey="refused",
                            runtime_args=[],
                            derived_args=[],
                            argument_layout=[],
                            layer3_policy="merkle_allowlist",
                            cosigner=BoundedCosignerAuthorizationInfo(
                                contract="cosigner1",
                                component_key_type=KEY_TYPE_WITNESS_FALCON1024,
                                public_key_hex="aabb",
                            ),
                        ),
                    ),
                )
            ]
        )
        assembled_txn[0] = transaction.PaymentTxn(
            bounded, params, receiver, 2000
        )
        with pytest.raises(
            SignerError, match="does not match the submitted canonical bytes"
        ):
            sign_prepared_cosigned_group(
                user_client=user,
                cosigner_client=cosigner,
                cosigner_component_key="COSIGNER_COMPONENT",
                prepared_group=prepared_group,
            )

        assembled_txn[0] = txn
        result = sign_prepared_cosigned_group(
            user_client=user,
            cosigner_client=cosigner,
            cosigner_component_key="COSIGNER_COMPONENT",
            prepared_group=prepared_group,
        )

        assert result.signed_group == [signed_txn_hex(txn)]
        assert result.bounded_component_response is not None
        assert result.bounded_assembly_response is not None
        cosigner_req = cosigner.request_components.call_args.args[0]
        assert len(cosigner_req.group_bytes_hex) == 1
        assert cosigner_req.group_bytes_hex[0].startswith("5458")
        assert [target["target_index"] for target in cosigner_req.targets] == [0]
        assert cosigner_req.targets[0]["app_call_info"] == {"mode": "raw"}

        user.request_components.reset_mock()
        prepared_group.transactions[0].signer_key.bounded_authorization.max_fee = 999
        with pytest.raises(SignerError, match="exceeds advertised max_fee"):
            sign_prepared_cosigned_group(
                user_client=user,
                cosigner_client=cosigner,
                cosigner_component_key="COSIGNER_COMPONENT",
                prepared_group=prepared_group,
            )
        user.request_components.assert_not_called()

    @pytest.mark.parametrize("reject_sign", [False, True])
    def test_prepared_bounded_cosigner_sends_held_primary_as_signers_own(self, reject_sign):
        """A non-cosigned position the signer holds is sent as the signer's
        own: in sign mode on /plan, and as a contextual position with
        auth_address on /sign/component. The signer sizes it and can charge
        it; no hint is sent. Here the plan puts the group's authorization
        charge on the held primary, which the SDK must accept and sign.
        """
        bounded = sdk_test_address(41)
        native_pq = sdk_test_address(42)
        receiver = sdk_test_address(43)
        user = make_client()
        cosigner = make_client("http://cosigner:11270")
        captured = {}

        params = transaction.SuggestedParams(
            1000,
            1,
            100,
            base64.b64encode(bytes(32)).decode(),
            "testnet-v1.0",
            flat_fee=True,
        )
        bounded_txn = transaction.PaymentTxn(bounded, params, receiver, 1000)
        native_txn = transaction.PaymentTxn(native_pq, params, receiver, 2000)
        transaction.assign_group_id([bounded_txn, native_txn])
        # The bounded target stays at its 1000 fee ceiling; the held primary
        # carries the charge.
        planned_bounded = copy.deepcopy(bounded_txn)
        planned_native = copy.deepcopy(native_txn)
        planned_native.fee += 2000
        planned_bounded.group = planned_native.group = None
        transaction.assign_group_id([planned_bounded, planned_native])
        planned_hex = [
            encode_transaction(planned_bounded)[0],
            encode_transaction(planned_native)[0],
        ]

        def bounded_component(req):
            assert req.group_bytes_hex == planned_hex
            assert len(req.targets) == 1
            assert len(req.contextual_positions) == 1
            # The held position names its account and carries no size hint.
            position = req.contextual_positions[0]
            assert position["auth_address"] == native_pq
            assert "pq_scheme" not in position and "lsig_resources" not in position
            return ComponentResponse(
                request_id="base-id",
                components=[{
                    "target_index": 0, "kind": COMPONENT_TARGET_KIND_BOUNDED_BASE,
                    "auth_address": bounded, "base_signatures": ["base-sig"],
                    "assembly_receipt": "receipt",
                    "signature_scheme": "aplane.falcon1024.v1", "path": "spend",
                }],
            )

        def signed_txn_hex(signed_txn):
            logic_sig = transaction.LogicSigAccount(bytes.fromhex("033120320312"))
            encoded = algo_encoding.msgpack_encode(
                transaction.LogicSigTransaction(signed_txn, logic_sig)
            )
            return base64.b64decode(encoded).hex()

        user.request_components = MagicMock(side_effect=bounded_component)
        user.plan_requests = MagicMock(side_effect=lambda requests: (
            captured.update(primary=requests[1]) or {
                "transactions": planned_hex,
                "mutations": {
                    "group_id_changed": True,
                    "fees_modified": [1],
                    "total_fees_delta": 2000,
                    "dummies_added": 0,
                    "original_count": 2,
                    "final_count": 2,
                },
            }
        ))
        cosigner.request_components = MagicMock(return_value=component_response(
            request_id="cosigner-id",
            signatures=[component_signature(
                0, "cosigner-sig", KEY_TYPE_WITNESS_FALCON1024
            )],
        ))
        user.sign_requests = MagicMock(return_value=GroupSignResponse(
            signed=["", signed_txn_hex(planned_native)]
        ))
        if reject_sign:
            user.sign_requests = MagicMock(
                side_effect=SignerError("rejected by signer policy")
            )
        user.request_assemble = MagicMock(return_value=AssemblyResponse(
            request_id="assembly-id",
            signed_group=[signed_txn_hex(planned_bounded), signed_txn_hex(planned_native)],
        ))

        events = []
        record_call_order(
            events,
            base=user.request_components,
            cosigner=cosigner.request_components,
            sign=user.sign_requests,
            assemble=user.request_assemble,
        )

        def run():
            return sign_prepared_cosigned_group(
                user_client=user,
                cosigner_client=cosigner,
                cosigner_component_key="COSIGNER_COMPONENT",
                prepared_group=PreparedGroup([
                    PreparedTransaction(
                        transaction=bounded_txn,
                        auth_address=bounded,
                        signer_key=KeyInfo(
                            address=bounded,
                            key_type="aplane.falcon1024.v1",
                            authorization_kind=AUTHORIZATION_KIND_LOGIC_SIG,
                            signing_flow=SIGNING_FLOW_COSIGNED1,
                            cosigner_component_key_type=KEY_TYPE_WITNESS_FALCON1024,
                            logic_sig_resources=LogicSigResourceProfile(
                                spend=LogicSigResourceUsage(5308, 3358, 20000)
                            ),
                            bounded_authorization=BoundedAuthorizationInfo(
                                contract="bounded2",
                                base_signature_arg_layout=BoundedSignatureArgLayout(
                                    count=1, max_sizes=[1280]
                                ),
                                spend_effects=["pay"],
                                max_fee=1000,
                                rekey="refused",
                                runtime_args=[],
                                derived_args=[],
                                argument_layout=[],
                                layer3_policy="merkle_allowlist",
                                cosigner=BoundedCosignerAuthorizationInfo(
                                    contract="cosigner1",
                                    component_key_type=KEY_TYPE_WITNESS_FALCON1024,
                                    public_key_hex="aabb",
                                ),
                            ),
                        ),
                    ),
                    PreparedTransaction(
                        transaction=native_txn,
                        auth_address=native_pq,
                        signer_key=KeyInfo(
                            address=native_pq,
                            key_type="falcon1024",
                            authorization_kind=AUTHORIZATION_KIND_NATIVE_PQ,
                        ),
                    ),
                ]),
            )

        if reject_sign:
            with pytest.raises(SignerError, match="rejected by signer policy"):
                run()
            assert events == ["base", "sign"]
            return
        result = run()
        assert events == ["base", "sign", "cosigner", "assemble"]
        # The result carries what the plan added, so the caller can read the
        # fee the signer charged.
        assert result.plan_mutations["total_fees_delta"] == 2000
        assert result.plan_mutations["fees_modified"] == [1]

        # A held position is sent as the signer's own: sign mode on /plan,
        # with no size hint.
        assert captured["primary"]["auth_address"] == native_pq
        assert "pq_scheme" not in captured["primary"]
        assert "lsig_resources" not in captured["primary"]

    def test_prepared_group_rejects_unsupported_signing_flow(self):
        cosigned = sdk_test_address(1)
        receiver = sdk_test_address(2)
        user = MagicMock()

        params = transaction.SuggestedParams(
            1000,
            1,
            100,
            base64.b64encode(bytes(32)).decode(),
            "testnet-v1.0",
            flat_fee=True,
        )
        txn = transaction.PaymentTxn(cosigned, params, receiver, 1000)
        with pytest.raises(ValueError, match="signing flow 'cosigner2'"):
            sign_prepared_cosigned_group(
                user_client=user,
                prepared_group=PreparedGroup([
                    PreparedTransaction(
                        transaction=txn,
                        auth_address=cosigned,
                        signer_key=KeyInfo(
                            address=cosigned,
                            key_type="aplane.future-cosigned.v1",
                            signing_flow="cosigner2",
                            logic_sig_resources=LogicSigResourceProfile(
                                spend=LogicSigResourceUsage(1612, 1423, 20000)
                            ),
                        ),
                    )
                ]),
            )

    def test_prepared_group_names_the_position_of_a_bad_primary(self):
        """A held primary takes no size hint; the error names its index."""
        account = sdk_test_address(1)
        params = transaction.SuggestedParams(
            1000,
            1,
            100,
            base64.b64encode(bytes(32)).decode(),
            "testnet-v1.0",
            flat_fee=True,
        )
        txn = transaction.PaymentTxn(account, params, sdk_test_address(2), 1000)
        with pytest.raises(
            ValueError,
            match="prepared transaction 0: pq_scheme is allowed only for foreign transactions",
        ):
            sign_prepared_cosigned_group(
                user_client=MagicMock(),
                prepared_group=PreparedGroup([
                    PreparedTransaction(
                        transaction=txn,
                        auth_address=account,
                        pq_scheme="f1",
                        signer_key=KeyInfo(address=account, key_type="falcon1024"),
                    )
                ]),
            )

    def test_prepared_group_refuses_cosigner1_as_unknown_flow(self):
        """cosigner1, the retired dedicated cosigned flow, fails closed before any request."""
        account = sdk_test_address(1)
        user = make_client()
        params = transaction.SuggestedParams(
            1000,
            1,
            100,
            base64.b64encode(bytes(32)).decode(),
            "testnet-v1.0",
            flat_fee=True,
        )
        txn = transaction.PaymentTxn(account, params, sdk_test_address(2), 1000)
        with patch.object(user.session, "post") as mock_post, patch.object(
            user.session, "get"
        ) as mock_get:
            with pytest.raises(ValueError, match="signing flow 'cosigner1', which this SDK does not support"):
                sign_prepared_cosigned_group(
                    user_client=user,
                    prepared_group=PreparedGroup([
                        PreparedTransaction(
                            transaction=txn,
                            auth_address=account,
                            signer_key=KeyInfo(
                                address=account,
                                key_type="aplane.falcon1024-cosigner1024.v1",
                                signing_flow="cosigner1",
                                cosigner_component_key_type=KEY_TYPE_WITNESS_FALCON1024,
                                logic_sig_resources=LogicSigResourceProfile(
                                    spend=LogicSigResourceUsage(1612, 1423, 20000)
                                ),
                            ),
                        )
                    ]),
                )
        mock_post.assert_not_called()
        mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# plan_group
# ---------------------------------------------------------------------------

class TestPlanGroup:
    def test_returns_plan(self):
        client = make_client()
        txn = fake_signer.payment()
        post = fake_signer.signer_post(fee_raise={0: 2000}, dummies=1)
        with patch.object(client.session, "post", side_effect=post):
            result = client.plan_group([txn])

        assert "transactions" in result
        assert len(result["transactions"]) == 2
        assert result["mutations"]["dummies_added"] == 1
        assert result["mutations"]["total_fees_delta"] == 2000

    def test_rejects_a_plan_that_changes_the_transaction(self):
        client = make_client()
        txn = fake_signer.payment(41, 42, 1_000_000)
        other = fake_signer.payment(41, 45, 100_000_000)

        def substitute(body):
            body["transactions"] = [fake_signer.plan_response(fake_signer.sign_entries(other))["transactions"][0]]

        with patch.object(client.session, "post", side_effect=fake_signer.signer_post(tamper=substitute)):
            with pytest.raises(SignerError, match="unreported fields at original position 1"):
                client.plan_group([txn])

    @pytest.mark.parametrize(
        ("tamper", "error"),
        [
            (lambda body: body["mutations"].update(dummies_added=0), "dummies_added 0 does not match appended count 1"),
            (lambda body: body["mutations"].update(total_fees_delta=1), "total_fees_delta 1 does not match observed delta 2000"),
            (lambda body: body["mutations"].update(fees_modified=[]), "unreported fields at original position 1"),
            (lambda body: body["transactions"].__setitem__(0, body["transactions"][0][4:]), "planned transaction 1: missing TX prefix"),
            (lambda body: body["transactions"].__setitem__(0, body["transactions"][0] + "00"), "planned transaction 1"),
            (lambda body: body.update(transactions=body["transactions"][:0]), "want at least 1"),
            (lambda body: body.pop("mutations"), "appended 1 transaction\\(s\\) without a mutation report"),
        ],
    )
    def test_rejects_a_plan_that_disagrees_with_its_report(self, tamper, error):
        client = make_client()
        post = fake_signer.signer_post(fee_raise={0: 2000}, dummies=1, tamper=tamper)
        with patch.object(client.session, "post", side_effect=post):
            with pytest.raises(SignerError, match=error):
                client.plan_group([fake_signer.payment()])

    def test_auth_error(self):
        client = make_client()
        with patch.object(client.session, "post", return_value=mock_response(401)):
            with pytest.raises(AuthenticationError):
                client.plan_group([fake_signer.payment()])

    def test_server_error_in_response(self):
        client = make_client()
        resp = mock_response(200, {"error": "Internal error"})
        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerError):
                client.plan_group([fake_signer.payment()])


class TestClientSideSignedSimulation:
    def test_simulate_prepared_group_signs_then_calls_client_algod(self):
        private_key, sender = account.generate_account()
        receiver = sdk_test_address(2)
        params = transaction.SuggestedParams(
            1000,
            1,
            100,
            base64.b64encode(bytes(32)).decode(),
            "testnet-v1.0",
            flat_fee=True,
        )
        txn = transaction.PaymentTxn(sender, params, receiver, 1)
        signed = txn.sign(private_key)
        signed_b64 = algo_encoding.msgpack_encode(signed)
        signed_hex = base64.b64decode(signed_b64).hex()

        client = make_client()
        sign_response = mock_response(200, {
            "signed": [signed_hex],
            "mutations": {"original_count": 1, "final_count": 1},
        })
        algod_client = MagicMock()
        algod_client.simulate_transactions.return_value = {
            "last-round": 7,
            "version": 2,
            "txn-groups": [{"failure-message": "logic eval error"}],
        }
        prepared = PreparedTransaction(
            transaction=txn,
            auth_address=sender,
        )

        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", return_value=sign_response) as mock_post:
            result = client.simulate_prepared_group(
                algod_client,
                PreparedGroup([prepared]),
                request_id="simulate-id",
            )

        assert mock_post.call_args.args[0] == "http://localhost:11270/sign"
        assert mock_post.call_args.kwargs["json"]["request_id"] == "simulate-id"
        assert algod_client.simulate_transactions.call_count == 1
        simulate_request = algod_client.simulate_transactions.call_args.args[0]
        assert simulate_request.allow_empty_signatures is False
        assert simulate_request.exec_trace_config.enable is True
        assert algo_encoding.msgpack_encode(
            simulate_request.txn_groups[0].txns[0]
        ) == signed_b64
        assert result.signed_group == [signed_hex]
        assert result.tx_ids == [txn.get_txid()]
        assert result.mutations == {"original_count": 1, "final_count": 1}
        assert result.failed is True

    def test_native_post_quantum_signature_survives_simulation_and_the_canonical_check(self):
        # A native post-quantum signature travels in pqsig. A py-algorand-sdk
        # without that type decodes the bytes as an unsigned transaction.
        from aplanesdk.signer import (
            _verify_signed_transaction_matches_canonical,
            encode_transaction,
        )

        sender = fake_signer.pq_account(7)
        params = transaction.SuggestedParams(
            1000, 1, 100, base64.b64encode(bytes(32)).decode(), "testnet-v1.0", flat_fee=True,
        )
        txn = transaction.PaymentTxn(sender, params, sdk_test_address(2), 1)
        signed = fake_signer.authorize(txn, sender)
        assert isinstance(signed, transaction.PQSignedTransaction)
        signed_b64 = algo_encoding.msgpack_encode(signed)
        signed_hex = base64.b64decode(signed_b64).hex()

        canonical_hex, _ = encode_transaction(txn)
        _verify_signed_transaction_matches_canonical("assembled transaction", 0, signed_hex, canonical_hex)

        client = make_client()
        sign_response = mock_response(200, {
            "signed": [signed_hex],
            "mutations": {"original_count": 1, "final_count": 1},
        })
        algod_client = MagicMock()
        algod_client.simulate_transactions.return_value = {
            "last-round": 7, "version": 2, "txn-groups": [{}],
        }
        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", return_value=sign_response):
            result = client.simulate_prepared_group(
                algod_client,
                PreparedGroup([PreparedTransaction(transaction=txn, auth_address=sender)]),
            )

        simulated = algod_client.simulate_transactions.call_args.args[0].txn_groups[0].txns[0]
        assert isinstance(simulated, transaction.PQSignedTransaction)
        assert algo_encoding.msgpack_encode(simulated) == signed_b64
        assert result.signed_group == [signed_hex]

    def test_requires_algod_before_contacting_signer(self):
        client = make_client()
        with patch.object(client.session, "post") as mock_post:
            with pytest.raises(ValueError, match="algod_client is required"):
                client.simulate_prepared_group(None, PreparedGroup([]))
        mock_post.assert_not_called()

    def test_cosigned_requires_algod_before_signing(self):
        with pytest.raises(ValueError, match="algod_client is required"):
            simulate_prepared_cosigned_group(None)


class TestConfigAndConstruction:
    def test_load_config_parse_error(self, tmp_path):
        (tmp_path / "config.yaml").write_text("ssh:\n  host: [\n", encoding="utf-8")
        with pytest.raises(SignerError, match="failed to parse config.yaml"):
            load_config(str(tmp_path))

    def test_constructor_requires_base_url(self):
        with pytest.raises(SignerError, match="base_url is required"):
            SignerClient("")

    def test_constructor_sends_no_credential_header(self):
        # The SSH connection carries the client's identity; no header does.
        client = SignerClient("http://localhost:11270")
        assert "Authorization" not in client.session.headers


# ---------------------------------------------------------------------------
# signing errors
# ---------------------------------------------------------------------------

class TestSigningErrors:
    def _make_mock_txn(self, sender=None):
        return fake_signer.payment(sender=sender)

    def test_auth_error(self):
        client = make_client()
        with patch.object(client.session, "post", return_value=mock_response(401)):
            with pytest.raises(AuthenticationError):
                client.sign_transaction(self._make_mock_txn())

    def test_signing_rejected(self):
        client = make_client()
        resp = mock_response(403, {"error": "Operator rejected", "code": "forbidden"})
        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SigningRejectedError):
                client.sign_transaction(self._make_mock_txn())

    @pytest.mark.parametrize("body", [None, {"error": "Operator rejected"}])
    def test_forbidden_without_code_is_generic_error(self, body):
        client = make_client()
        resp = mock_response(403, body)
        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerError) as exc_info:
                client.sign_transaction(self._make_mock_txn())
        assert type(exc_info.value) is SignerError
        assert exc_info.value.code == ""

    def test_signer_unavailable(self):
        client = make_client()
        resp = mock_response(503, {"error": "Signer locked"})
        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerUnavailableError):
                client.sign_transaction(self._make_mock_txn())

    def test_key_not_found(self):
        client = make_client()
        resp = mock_response(400, {"error": "Key not found: INVALID_ADDRESS", "code": "not_found"})
        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(KeyNotFoundError):
                client.sign_transaction(self._make_mock_txn())

    def test_not_found_message_without_code_is_not_key_not_found(self):
        client = make_client()
        resp = mock_response(400, {"error": "Key not found: INVALID_ADDRESS"})
        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerError) as exc_info:
                client.sign_transaction(self._make_mock_txn())
        assert not isinstance(exc_info.value, KeyNotFoundError)
        assert exc_info.value.code == ""

    def test_key_not_found_by_code_regardless_of_wording(self):
        client = make_client()
        resp = mock_response(400, {"error": "auth address unavailable", "code": "not_found"})
        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(KeyNotFoundError):
                client.sign_transaction(self._make_mock_txn())

    def test_non_not_found_code_is_not_key_not_found(self):
        client = make_client()
        resp = mock_response(400, {"error": "group not found in request", "code": "bad_request"})
        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerError) as exc_info:
                client.sign_transaction(self._make_mock_txn())
            assert not isinstance(exc_info.value, KeyNotFoundError)

    def test_uses_discovered_approval_wait_plus_slack(self):
        client = SignerClient("http://localhost:11270")
        client._cache_approval_wait(120)

        assert client._sign_request_timeout() == 150

    def test_falls_back_for_invalid_approval_wait(self):
        client = SignerClient("http://localhost:11270")
        client._cache_approval_wait(31 * 60)

        assert client._sign_request_timeout() == 360

    def test_status_discovery_failure_does_not_fail_sign(self):
        client = make_client()
        txn = self._make_mock_txn()
        with patch.object(client, "get_status", side_effect=SignerUnavailableError("down")), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post()):
            signed = client.sign_transaction(txn)

        assert base64.b64decode(signed) == bytes.fromhex(fake_signer.signed_hex(txn))

    def test_timeout(self):
        import requests
        client = make_client()
        with patch.object(client.session, "post", side_effect=requests.ConnectionError("timed out")):
            with pytest.raises(SignerUnavailableError):
                client.sign_transaction(self._make_mock_txn())

    def test_timeout_sends_best_effort_cancel(self):
        import requests
        client = make_client()
        cancel_resp = mock_response(200, {"success": True, "state": "canceled"})
        with patch.object(client.session, "post", side_effect=[
            requests.Timeout("timed out"),
            cancel_resp,
        ]) as mock_post, \
             patch("aplanesdk.signer._new_sign_request_id", return_value="sdk-test"):
            with pytest.raises(SignerUnavailableError):
                client.sign_transaction(self._make_mock_txn())

        assert mock_post.call_args_list[0].args[0] == "http://localhost:11270/sign"
        assert mock_post.call_args_list[0].kwargs["json"]["request_id"] == "sdk-test"
        assert mock_post.call_args_list[1].args[0] == "http://localhost:11270/sign/cancel"
        assert mock_post.call_args_list[1].kwargs["json"] == {"request_id": "sdk-test"}

    def test_sign_transaction_accepts_caller_request_id(self):
        client = make_client()
        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post()) as mock_post:
            client.sign_transaction(self._make_mock_txn(), request_id="app-owned-id")

        assert mock_post.call_args.kwargs["json"]["request_id"] == "app-owned-id"

    def test_sign_transaction_validates_caller_request_id(self):
        client = make_client()
        with pytest.raises(ValueError, match="invalid character"):
            client.sign_transaction(self._make_mock_txn(), request_id="bad id")


class TestCancelSignRequest:
    def test_cancel_sign_request_returns_state(self):
        client = make_client()
        resp = mock_response(200, {"success": True, "state": "not_found"})

        with patch.object(client.session, "post", return_value=resp) as mock_post:
            result = client.cancel_sign_request("sdk-test")

        assert result.success is True
        assert result.state == "not_found"
        assert mock_post.call_args.args[0] == "http://localhost:11270/sign/cancel"
        assert mock_post.call_args.kwargs["json"] == {"request_id": "sdk-test"}
        assert mock_post.call_args.kwargs["timeout"] == 5

    def test_cancel_sign_request_validates_id(self):
        client = make_client()
        with pytest.raises(ValueError, match="request_id is required"):
            client.cancel_sign_request("")
        with pytest.raises(ValueError, match="invalid character"):
            _validate_sign_request_id("bad id", required=True)


class TestSignRequests:
    def test_sign_requests_sends_raw_request(self):
        client = make_client()
        txn = fake_signer.payment()
        entry = {
            "txn_bytes_hex": encode_transaction(txn)[0],
            "auth_address": txn.sender,
            "txn_sender": "SENDER",
        }

        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post()) as mock_post:
            result = client.sign_requests([dict(entry)], request_id="raw-requests-id")

        assert result.signed == [fake_signer.signed_hex(txn)]
        assert mock_post.call_args.args[0] == "http://localhost:11270/sign"
        assert mock_post.call_args.kwargs["json"] == {
            "request_id": "raw-requests-id",
            "requests": [entry],
        }

    def test_sign_requests_rejects_noncanonical_transaction_bytes_before_http(self):
        client = make_client()
        canonical = encode_transaction(fake_signer.payment())[0]
        with patch.object(client.session, "post") as mock_post:
            with pytest.raises(SignerError, match="invalid sign request: transaction 1: txn_bytes_hex: missing TX prefix"):
                client.sign_requests([{"txn_bytes_hex": canonical[4:], "auth_address": "AUTH"}])
            with pytest.raises(SignerError, match="invalid msgpack|not canonical"):
                client.sign_requests([{"txn_bytes_hex": canonical + "00", "auth_address": "AUTH"}])
        mock_post.assert_not_called()

    def test_sign_requests_validates_request_id(self):
        client = make_client()
        with pytest.raises(ValueError, match="invalid character"):
            client.sign_requests([{"txn_bytes_hex": "545801"}], request_id="bad id")

    def test_sign_requests_rejects_unsupported_pq_scheme_before_http(self):
        client = make_client()
        with patch.object(client.session, "post") as mock_post:
            with pytest.raises(ValueError, match="unsupported pq_scheme"):
                client.sign_requests(
                    [
                        {
                            "txn_bytes_hex": "545801",
                            "pq_scheme": "f2",
                        }
                    ]
                )
        mock_post.assert_not_called()

    @pytest.mark.parametrize(
        ("entries", "error"),
        [
            (
                [
                    {
                        "txn_bytes_hex": "545801",
                        "auth_address": "AUTH",
                        "lsig_resources": {
                            "program_bytes": 1,
                            "argument_bytes": 0,
                            "max_opcode_cost": 1,
                        },
                    }
                ],
                "lsig_resources is allowed only for foreign or passthrough",
            ),
            (
                [
                    {
                        "signed_txn_hex": "aabb",
                        "lsig_resources": {
                            "program_bytes": 0,
                            "argument_bytes": 0,
                            "max_opcode_cost": 0,
                        },
                    }
                ],
                "LogicSig resources are invalid",
            ),
            (
                [
                    {"txn_bytes_hex": "545801", "pq_scheme": "f1"},
                    {"signed_txn_hex": "aabb"},
                ],
                "cannot mix passthrough and foreign transactions",
            ),
            (
                [{"txn_bytes_hex": "545801", "pq_scheme": "f1"}],
                "no signable transactions",
            ),
        ],
    )
    def test_sign_requests_validates_full_raw_request_contract(self, entries, error):
        client = make_client()
        with patch.object(client.session, "post") as mock_post:
            with pytest.raises(ValueError, match=error):
                client.sign_requests(entries)
        mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# sign_transactions with foreign entries
# ---------------------------------------------------------------------------

class TestSignTransactionsForeign:
    def _make_mock_txn(self, sender=None):
        return fake_signer.payment(sender=sender)

    def test_rejects_foreign_in_sign_transactions(self):
        client = make_client()
        with patch.object(client.session, "post") as mock_post:
            with pytest.raises(SignerError, match="foreign entries are only supported on /plan"):
                client.sign_transactions(
                    [self._make_mock_txn(), self._make_mock_txn()],
                    auth_addresses=[fake_signer.account(41), None],
                )
        mock_post.assert_not_called()

    def test_sign_transactions_list_rejects_foreign(self):
        client = make_client()
        with patch.object(client.session, "post") as mock_post:
            with pytest.raises(SignerError, match="foreign entries are only supported on /plan"):
                client.sign_transactions_list(
                [self._make_mock_txn(), self._make_mock_txn()],
                auth_addresses=[fake_signer.account(41), None],
            )
        mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# request building
# ---------------------------------------------------------------------------

class TestBuildSignRequests:
    def _make_mock_txn(self, sender=None):
        return fake_signer.payment(sender=sender)

    def test_builds_request_with_auth_address(self):
        client = make_client()
        txn = self._make_mock_txn()
        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post()) as mock_post:
            client.sign_transaction(txn, auth_address=fake_signer.account(50))

        call_kwargs = mock_post.call_args
        body = call_kwargs[1]["json"]
        assert body["request_id"]
        assert len(body["requests"]) == 1
        assert body["requests"][0]["auth_address"] == fake_signer.account(50)
        assert body["requests"][0]["txn_bytes_hex"] == encode_transaction(txn)[0]

    def test_defaults_auth_address_to_sender(self):
        client = make_client()
        sender = fake_signer.account(77)
        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post()) as mock_post:
            client.sign_transaction(self._make_mock_txn(sender=sender))

        call_kwargs = mock_post.call_args
        body = call_kwargs[1]["json"]
        assert body["requests"][0]["auth_address"] == sender

    def test_includes_lsig_args_as_hex(self):
        client = make_client()
        sender = fake_signer.lsig_account(78)
        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post()) as mock_post:
            client.sign_transaction(
                self._make_mock_txn(sender=sender),
                auth_address=sender,
                lsig_args={"preimage": b"secret"},
            )

        call_kwargs = mock_post.call_args
        body = call_kwargs[1]["json"]
        assert body["requests"][0]["lsig_args"] is not None
        assert body["requests"][0]["lsig_args"]["preimage"] == "736563726574"

    @pytest.mark.parametrize("auth_address", [None, ""])
    def test_lsig_args_follow_the_sender_when_no_auth_address_is_given(self, auth_address):
        client = make_client()
        txn = self._make_mock_txn()
        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post()) as mock_post:
            client.sign_transaction(txn, auth_address=auth_address, lsig_args={"preimage": b"secret"})

        request = mock_post.call_args[1]["json"]["requests"][0]
        assert request["auth_address"] == txn.sender
        assert request["lsig_args"] == {"preimage": "736563726574"}

    def test_rejects_lsig_args_no_position_matches(self):
        client = make_client()
        txn = self._make_mock_txn()
        stray = {sdk_test_address(79): {"preimage": b"secret"}}
        error = "no transaction in the request has auth address"
        with patch.object(client.session, "post") as mock_post:
            with pytest.raises(ValueError, match=error):
                client.sign_transactions([txn], lsig_args_map=stray)
            with pytest.raises(ValueError, match=error):
                client.sign_transactions_list([txn], lsig_args_map=stray)
            with pytest.raises(ValueError, match=error):
                client.plan_group([txn], lsig_args_map=stray)
        mock_post.assert_not_called()

    def test_ignores_lsig_args_entries_with_no_args(self):
        client = make_client()
        txn = self._make_mock_txn()
        empty = {sdk_test_address(79): None, sdk_test_address(80): {}, txn.sender: {}}
        body = client._build_sign_requests([txn], [txn.sender], empty)
        assert "lsig_args" not in body[0]

    def test_accepts_a_reused_lsig_args_map(self):
        # One args map serves every call over a group: the plan with a foreign
        # position, and the final signing once that position came back signed.
        client = make_client()
        grouped = [fake_signer.payment(41, 42), fake_signer.payment(43, 44)]
        transaction.assign_group_id(grouped)
        first, second = grouped[0].sender, grouped[1].sender
        args = {first: {"preimage": b"one"}, second: {"preimage": b"two"}}

        body = client._build_sign_requests(grouped, [first, None], args)
        assert body[0]["lsig_args"] == {"preimage": b"one".hex()}
        assert "lsig_args" not in body[1]

        signed_second = base64.b64encode(
            bytes.fromhex(fake_signer.signed_hex(grouped[1]))
        ).decode()
        cases = {
            "auth address given": (grouped, [first, second]),
            "sender of the slot": (grouped, [first, None]),
            "only the signed bytes": ([grouped[0], None], [first, None]),
        }
        for name, (txns, auths) in cases.items():
            body = client._build_sign_requests(
                txns, auths, args, passthrough={1: signed_second}, allow_foreign=False
            )
            assert body[0]["lsig_args"] == {"preimage": b"one".hex()}, name
            assert set(body[1]) == {"signed_txn_hex"}, name

        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post()):
            signed = client.sign_transactions_list(
                grouped, lsig_args_map=args, passthrough={1: signed_second}
            )
        assert signed[1] == signed_second

    def test_lsig_args_are_matched_to_the_authorizer_not_a_rekeyed_sender(self):
        # Args keyed under the sender of a rekeyed account would be sent with
        # no position, and the signature made without them.
        client = make_client()
        sender = fake_signer.account(41)  # S, rekeyed
        passthrough_key = fake_signer.account(45)  # K, signed position 1 for S
        lsig = fake_signer.lsig_account(7)  # L, signs position 2 for S
        grouped = [
            fake_signer.payment(41, 42, 1, sender=sender),
            fake_signer.payment(41, 43, 2, sender=sender),
        ]
        transaction.assign_group_id(grouped)
        # Position 1 was signed by K on S's behalf, so its signed bytes name K.
        # (Signed by S itself, S would be that position's authorizer and a key
        # under S would rightly match it.)
        presigned = fake_signer.authorize(grouped[0], passthrough_key)
        assert presigned.authorizing_address == passthrough_key
        passthrough = {
            0: base64.b64encode(bytes.fromhex(fake_signer.encode_signed(presigned))).decode()
        }
        auths = [None, lsig]
        args = {"preimage": b"secret"}
        error = "no transaction in the request has auth address"

        def build(lsig_args_map):
            return client._build_sign_requests(
                grouped, auths, lsig_args_map, passthrough=passthrough, allow_foreign=False
            )

        with pytest.raises(ValueError, match=error):
            build({sender: args})
        # The same without the passthrough: a sign position's sender is not
        # its authorizer.
        with pytest.raises(ValueError, match=error):
            client._build_sign_requests([grouped[1]], [lsig], {sender: args})

        # Keyed under the authorizer, the args are sent with its position.
        entries = build({lsig: args})
        assert entries[1]["lsig_args"] == {"preimage": b"secret".hex()}
        assert "lsig_args" not in entries[0]
        # Keyed under the passthrough's signer, they are accepted and not
        # sent: one map serves the call where K signs and this one.
        entries = build({passthrough_key: args, lsig: args})
        assert set(entries[0]) == {"signed_txn_hex"}

    def test_carries_lsig_resources_on_passthrough(self):
        client = make_client()
        presigned = fake_signer.signed_hex(fake_signer.payment())
        body = client._build_sign_requests(
            [None],
            [None],
            passthrough={0: base64.b64encode(bytes.fromhex(presigned)).decode()},
            lsig_resources={
                0: LogicSigResourceUsage(1612, 1423, 20000),
            },
            allow_foreign=False,
        )
        assert body == [{
            "signed_txn_hex": presigned,
            "lsig_resources": {
                "program_bytes": 1612,
                "argument_bytes": 1423,
                "max_opcode_cost": 20000,
            },
        }]

    def test_rejects_indexed_lsig_resources_on_sign_mode(self):
        client = make_client()
        with patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER")):
            with pytest.raises(ValueError, match="allowed only for foreign or passthrough"):
                client._build_sign_requests(
                    [self._make_mock_txn()],
                    ["AUTH"],
                    lsig_resources={
                        0: LogicSigResourceUsage(1612, 1423, 20000),
                    },
                    allow_foreign=False,
                )


class TestPreparedGroup:
    def _make_mock_txn(self):
        txn = MagicMock()
        txn.sender = "SENDER_ADDR"
        return txn

    def test_to_sign_requests_sign_mode(self):
        prepared = PreparedGroup([
            PreparedTransaction(
                transaction=self._make_mock_txn(),
                auth_address="AUTH_ADDR",
                txn_sender="DISPLAY_SENDER",
                lsig_args={"preimage": b"secret"},
                app_call_info={"mode": "abi", "method": "do(uint64)void"},
            )
        ])

        with patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            requests = prepared.to_sign_requests()

        assert requests == [{
            "txn_bytes_hex": "deadbeef",
            "auth_address": "AUTH_ADDR",
            "txn_sender": "DISPLAY_SENDER",
            "lsig_args": {"preimage": "736563726574"},
            "app_call_info": {"mode": "abi", "method": "do(uint64)void"},
        }]

    def test_to_sign_requests_foreign_mode(self):
        prepared = PreparedGroup([
            PreparedTransaction(
                transaction=self._make_mock_txn(),
                lsig_resources=LogicSigResourceUsage(1612, 1423, 20000),
            )
        ])

        with patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            requests = prepared.to_sign_requests()

        assert requests == [{
            "txn_bytes_hex": "deadbeef",
            "lsig_resources": {
                "program_bytes": 1612,
                "argument_bytes": 1423,
                "max_opcode_cost": 20000,
            },
        }]

    def test_to_sign_requests_passthrough_mode(self):
        prepared = PreparedGroup([
            PreparedTransaction(
                signed_transaction_base64=base64.b64encode(b"signed-txn").decode(),
                lsig_resources=LogicSigResourceUsage(1612, 1423, 20000),
            )
        ])

        assert prepared.to_sign_requests() == [{
            "signed_txn_hex": b"signed-txn".hex(),
            "lsig_resources": {
                "program_bytes": 1612,
                "argument_bytes": 1423,
                "max_opcode_cost": 20000,
            },
        }]

    @pytest.mark.parametrize(
        ("prepared", "message"),
        [
            (
                PreparedTransaction(
                    transaction=MagicMock(sender="SENDER_ADDR"),
                    auth_address="AUTH_ADDR",
                    pq_scheme="f1",
                ),
                "pq_scheme is allowed only for foreign transactions",
            ),
            (
                PreparedTransaction(
                    transaction=MagicMock(sender="SENDER_ADDR"),
                    auth_address="AUTH_ADDR",
                    lsig_resources=LogicSigResourceUsage(1612, 1423, 20000),
                ),
                "lsig_resources is allowed only for foreign or passthrough transactions",
            ),
            (
                PreparedTransaction(
                    signed_transaction_base64=base64.b64encode(b"signed-txn").decode(),
                    pq_scheme="f1",
                ),
                "pq_scheme is allowed only for foreign transactions",
            ),
        ],
    )
    def test_rejects_authorization_hints_outside_foreign_mode(self, prepared, message):
        with patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            with pytest.raises(ValueError, match=message):
                PreparedGroup([prepared]).to_sign_requests()

    def test_rejects_empty_group(self):
        with pytest.raises(ValueError, match="prepared group is empty"):
            PreparedGroup([]).to_sign_requests()


def test_package_root_exports_native_falcon_scheme():
    assert aplanesdk.PQ_SCHEME_FALCON1024 == "f1"


class TestPrepHelpers:
    def _status(self):
        return mock_response(200, {
            "state": "unlocked",
            "signer_locked": False,
            "ready_for_signing": True,
            "key_count": 1,
            "keyset_revision": 1,
        })

    def _keys(self, address):
        return mock_response(200, {
            "count": 1,
            "keys": [{"address": address, "key_type": "ed25519"}],
        })

    def test_prepare_payment(self):
        sender = sdk_test_address(1)
        receiver = sdk_test_address(2)
        algod = MockAlgod({
            sender: {"amount": 2_000_000, "min-balance": 100_000},
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_payment(
                algod,
                sender=sender,
                receiver=receiver,
                amount=10_000,
                fee=1000,
            )

        assert prepared.auth_address == sender
        assert prepared.signer_key.address == sender
        assert prepared.transaction.receiver == receiver
        assert prepared.transaction.fee == 1000
        assert prepared.checks[0].name == "payment_balance"

    def test_prepare_payment_rejects_insufficient_funds(self):
        sender = sdk_test_address(1)
        receiver = sdk_test_address(2)
        algod = MockAlgod({
            sender: {"amount": 101_000, "min-balance": 100_000},
        })
        client = make_client()
        with pytest.raises(SignerError, match="insufficient funds"):
            client.prepare_payment(
                algod,
                sender=sender,
                receiver=receiver,
                amount=10_000,
            )

    def test_prepare_asa_transfer(self):
        sender = sdk_test_address(1)
        receiver = sdk_test_address(2)
        algod = MockAlgod({
            sender: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 25}],
            },
            receiver: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 0}],
            },
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_asa_transfer(
                algod,
                sender=sender,
                receiver=receiver,
                asset_id=1001,
                amount=5,
            )

        assert prepared.auth_address == sender
        assert prepared.signer_key.address == sender
        assert prepared.transaction.index == 1001
        assert prepared.transaction.amount == 5
        assert prepared.checks[0].name == "asa_transfer"

    def test_prepare_asa_transfer_rejects_receiver_not_opted_in(self):
        sender = sdk_test_address(1)
        receiver = sdk_test_address(2)
        algod = MockAlgod({
            sender: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 25}],
            },
            receiver: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [],
            },
        })
        client = make_client()
        with pytest.raises(SignerError, match="receiver is not opted into asset"):
            client.prepare_asa_transfer(
                algod,
                sender=sender,
                receiver=receiver,
                asset_id=1001,
                amount=5,
            )

    def test_prepare_asa_opt_in(self):
        sender = sdk_test_address(1)
        algod = MockAlgod({
            sender: {"amount": 2_000_000, "min-balance": 100_000},
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_asa_opt_in(
                algod,
                sender=sender,
                asset_id=1001,
            )

        assert prepared.transaction.receiver == sender
        assert prepared.transaction.amount == 0
        assert prepared.checks[0].name == "asa_opt_in"

    def test_prepare_asa_opt_out(self):
        sender = sdk_test_address(1)
        close_to = sdk_test_address(2)
        algod = MockAlgod({
            sender: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 25}],
            },
            close_to: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 0}],
            },
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_asa_opt_out(
                algod,
                sender=sender,
                asset_id=1001,
                close_to=close_to,
            )

        assert prepared.transaction.close_assets_to == close_to
        assert prepared.checks[0].name == "asa_opt_out"

    def test_prepare_account_close(self):
        sender = sdk_test_address(1)
        close_to = sdk_test_address(2)
        algod = MockAlgod({
            sender: {"amount": 2_000_000, "min-balance": 100_000},
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_account_close(
                algod,
                sender=sender,
                close_to=close_to,
            )

        assert prepared.transaction.close_remainder_to == close_to
        assert prepared.checks[0].name == "account_close"

    def test_prepare_account_close_rejects_asset_holdings(self):
        sender = sdk_test_address(1)
        close_to = sdk_test_address(2)
        algod = MockAlgod({
            sender: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 0}],
            },
        })
        client = make_client()
        with pytest.raises(SignerError, match="ASA holdings"):
            client.prepare_account_close(algod, sender=sender, close_to=close_to)

    def test_prepare_rekey(self):
        sender = sdk_test_address(1)
        rekey_to = sdk_test_address(2)
        algod = MockAlgod({
            sender: {"amount": 2_000_000, "min-balance": 100_000},
            rekey_to: {"amount": 2_000_000, "min-balance": 100_000},
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_rekey(
                algod,
                sender=sender,
                rekey_to=rekey_to,
            )

        assert prepared.transaction.rekey_to == rekey_to
        assert prepared.checks[0].name == "rekey"

    @pytest.mark.parametrize("flow,want", [
        ("rotating1", "rotating account"),
        ("rotating2", "signing flow 'rotating2'"),
    ])
    def test_prepare_rekey_refuses_unroutable_signer_target(self, flow, want):
        sender = sdk_test_address(1)
        rekey_to = sdk_test_address(2)
        algod = MockAlgod({
            sender: {"amount": 2_000_000, "min-balance": 100_000},
            rekey_to: {"amount": 2_000_000, "min-balance": 100_000},
        })
        client = make_client()
        keys = mock_response(200, {
            "count": 2,
            "keys": [
                {"address": sender, "key_type": "ed25519"},
                {"address": rekey_to, "key_type": "test.rotating", "signing_flow": flow},
            ],
        })
        with patch.object(client.session, "get", side_effect=[self._status(), keys]):
            with pytest.raises(SignerError, match=want):
                client.prepare_rekey(algod, sender=sender, rekey_to=rekey_to)

    def test_prepare_rekey_rejects_rekey_chain(self):
        sender = sdk_test_address(1)
        rekey_to = sdk_test_address(2)
        other = sdk_test_address(3)
        algod = MockAlgod({
            sender: {"amount": 2_000_000, "min-balance": 100_000},
            rekey_to: {"amount": 2_000_000, "min-balance": 100_000, "auth-addr": other},
        })
        client = make_client()
        with pytest.raises(SignerError, match="rekey target is itself rekeyed"):
            client.prepare_rekey(algod, sender=sender, rekey_to=rekey_to)

    def _keyreg_algod(self, sender, already_eligible=False, amount=5_000_000):
        return MockAlgod({
            sender: {
                "amount": amount,
                "min-balance": 100_000,
                "incentive-eligible": already_eligible,
            },
        })

    @staticmethod
    def _online_keyreg():
        key32 = base64.b64encode(bytes(32)).decode()
        key64 = base64.b64encode(bytes(64)).decode()
        return dict(
            mode="online",
            votekey=key32,
            selkey=key32,
            sprfkey=key64,
            votefst=10,
            votelst=20,
            votekd=5,
        )

    def test_prepare_keyreg_requires_mode(self):
        # The mode is always explicit, so a forgotten key never takes an
        # account offline.
        sender = sdk_test_address(1)
        algod = self._keyreg_algod(sender)
        client = make_client()
        with pytest.raises(TypeError, match="mode"):
            client.prepare_keyreg(algod, sender=sender)  # type: ignore[call-arg]
        with pytest.raises(ValueError, match='mode is required: "online" or "offline"'):
            client.prepare_keyreg(algod, sender=sender, mode="")
        with pytest.raises(ValueError, match="mode 'part' is not \"online\" or \"offline\""):
            client.prepare_keyreg(algod, sender=sender, mode="part")

    def test_prepare_keyreg_online_requires_participation_keys(self):
        sender = sdk_test_address(1)
        algod = self._keyreg_algod(sender)
        client = make_client()
        with pytest.raises(ValueError, match="votekey is required"):
            client.prepare_keyreg(algod, sender=sender, mode="online")
        # The network refuses an online keyreg without a state proof key.
        online = self._online_keyreg()
        online["sprfkey"] = None
        with pytest.raises(ValueError, match="sprfkey is required"):
            client.prepare_keyreg(algod, sender=sender, **online)

    def test_prepare_keyreg_refuses_unaffordable_fee(self):
        # The fee, including the 2 ALGO incentive fee, must be payable without
        # going below the minimum balance.
        sender = sdk_test_address(1)
        algod = self._keyreg_algod(sender, amount=1_600_000)
        client = make_client()
        with pytest.raises(
            SignerError,
            match="insufficient funds for keyreg fee: available 1500000, fee 2000000",
        ):
            client.prepare_keyreg(
                algod, sender=sender, incentive_eligible=True, **self._online_keyreg()
            )

    def test_prepare_keyreg_offline_treats_empty_fields_as_unset(self):
        # Like Go, 0 and an empty key count as unset on an offline keyreg.
        sender = sdk_test_address(1)
        algod = self._keyreg_algod(sender)
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_keyreg(
                algod, sender=sender, mode="offline", votekey="", votefst=0, votekd=0
            )
        assert prepared.checks[0].data == {"mode": "offline"}

    def test_prepare_keyreg_online(self):
        sender = sdk_test_address(1)
        algod = self._keyreg_algod(sender)
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_keyreg(algod, sender=sender, **self._online_keyreg())

        assert prepared.transaction.votefst == 10
        assert prepared.transaction.votelst == 20
        assert not prepared.transaction.nonpart
        assert prepared.transaction.fee < 2_000_000
        assert prepared.checks[0].data["mode"] == "online"
        assert prepared.checks[0].data["incentive_fee_charged"] is False

    def test_prepare_keyreg_offline(self):
        sender = sdk_test_address(1)
        algod = self._keyreg_algod(sender)
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_keyreg(algod, sender=sender, mode="offline")

        txn = prepared.transaction
        assert isinstance(txn, transaction.KeyregOfflineTxn)
        assert txn.votepk is None and txn.selkey is None and txn.sprfkey is None
        assert txn.votefst is None and txn.votelst is None and txn.votekd is None
        assert not txn.nonpart
        assert prepared.checks[0].data == {"mode": "offline"}

    @pytest.mark.parametrize("field,extra", [
        ("but votekey is set", {"votekey": base64.b64encode(bytes(32)).decode()}),
        ("but selkey is set", {"selkey": base64.b64encode(bytes(32)).decode()}),
        ("but sprfkey is set", {"sprfkey": base64.b64encode(bytes(64)).decode()}),
        ("but votefst is set", {"votefst": 1}),
        ("but votelst is set", {"votelst": 100}),
        ("but votekd is set", {"votekd": 10}),
        ("incentive eligibility needs an online keyreg", {"incentive_eligible": True}),
    ])
    def test_prepare_keyreg_offline_refuses_online_fields(self, field, extra):
        # Offline with any participation field, or with incentive
        # eligibility, is contradictory, so it is refused rather than
        # building either registration.
        sender = sdk_test_address(1)
        algod = self._keyreg_algod(sender)
        client = make_client()
        with pytest.raises(ValueError, match=field):
            client.prepare_keyreg(algod, sender=sender, mode="offline", **extra)

    @pytest.mark.parametrize("already_eligible,fee,want_fee,charged", [
        (False, None, 2_000_000, True),
        (False, 3_000_000, 3_000_000, True),
        (True, None, None, False),
    ])
    def test_prepare_keyreg_incentive_eligibility(self, already_eligible, fee, want_fee, charged):
        # Incentive eligibility raises the fee to the protocol's 2 ALGO,
        # unless the account is already eligible: an online re-registration
        # keeps it.
        sender = sdk_test_address(1)
        algod = self._keyreg_algod(sender, already_eligible=already_eligible)
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_keyreg(
                algod,
                sender=sender,
                incentive_eligible=True,
                fee=fee,
                **self._online_keyreg(),
            )

        if want_fee is None:
            assert prepared.transaction.fee < 2_000_000
        else:
            assert prepared.transaction.fee == want_fee
        check = prepared.checks[0]
        assert check.data["incentive_eligible"] is True
        assert check.data["incentive_fee_charged"] is charged
        assert check.message

    def test_prepare_keyreg_incentive_eligibility_refuses_low_explicit_fee(self):
        # An explicit fee below the 2 ALGO the protocol needs is refused, not
        # overridden.
        sender = sdk_test_address(1)
        algod = self._keyreg_algod(sender)
        client = make_client()
        with pytest.raises(
            SignerError,
            match="needs a keyreg fee of at least 2000000 microAlgos, but fee is set to 0",
        ):
            client.prepare_keyreg(
                algod, sender=sender, incentive_eligible=True, fee=0, **self._online_keyreg()
            )

    def test_prepare_app_call(self):
        sender = sdk_test_address(1)
        receiver = sdk_test_address(2)
        algod = MockAlgod({
            sender: {"amount": 2_000_000, "min-balance": 100_000},
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_app_call(
                algod,
                sender=sender,
                app_id=7,
                on_complete=transaction.OnComplete.NoOpOC,
                app_args=[b"raw"],
                accounts=[receiver],
                foreign_apps=[8],
                foreign_assets=[1001],
                fee=1000,
            )

        assert prepared.auth_address == sender
        assert prepared.transaction.index == 7
        assert prepared.transaction.app_args == [b"raw"]
        assert prepared.transaction.accounts == [receiver]
        assert prepared.app_call_info == {"mode": "raw"}
        assert prepared.checks[0].name == "app_call"
        assert prepared.to_sign_request()["app_call_info"] == {"mode": "raw"}

    def test_prepare_abi_app_call(self):
        sender = sdk_test_address(1)
        receiver = sdk_test_address(2)
        algod = MockAlgod({
            sender: {"amount": 2_000_000, "min-balance": 100_000},
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_abi_app_call(
                algod,
                sender=sender,
                app_id=7,
                method_signature="do(uint64,string,account,application,asset)void",
                args=[42, "hi", receiver, 8, 1002],
                foreign_apps=[9],
                foreign_assets=[1001],
            )

        txn = prepared.transaction
        assert prepared.app_call_info == {
            "mode": "abi",
            "method": "do(uint64,string,account,application,asset)void",
        }
        assert len(txn.app_args) == 6
        assert len(txn.app_args[0]) == 4
        assert txn.accounts == [receiver]
        assert txn.foreign_apps == [9, 8]
        assert txn.foreign_assets == [1001, 1002]
        assert txn.app_args[3] == b"\x01"
        assert txn.app_args[4] == b"\x02"
        assert txn.app_args[5] == b"\x01"
        assert prepared.to_sign_request()["app_call_info"] == {
            "mode": "abi",
            "method": "do(uint64,string,account,application,asset)void",
        }

    def test_prepare_app_deploy(self):
        sender = sdk_test_address(1)
        algod = MockAlgod({
            sender: {"amount": 2_000_000, "min-balance": 100_000},
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_app_deploy(
                algod,
                sender=sender,
                approval_program=b"\x01\x02",
                clear_program=b"\x01",
                global_schema=transaction.StateSchema(1, 0),
                local_schema=transaction.StateSchema(0, 1),
                extra_pages=1,
            )

        assert prepared.transaction.index == 0
        assert prepared.app_call_info == {"mode": "raw"}
        assert prepared.checks[0].name == "app_deploy"

    def test_prepare_sweep_group(self):
        sender = sdk_test_address(1)
        receiver = sdk_test_address(2)
        algod = MockAlgod({
            sender: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 25}],
            },
            receiver: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 0}],
            },
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
            self._status(),
        ]):
            group = client.prepare_sweep_group(
                algod,
                asa_transfers=[
                    {"sender": sender, "receiver": receiver, "asset_id": 1001, "amount": 5},
                ],
                payments=[
                    {"sender": sender, "receiver": receiver, "amount": 10_000},
                ],
            )

        assert len(group.transactions) == 2
        assert group.checks[0].name == "sweep_group"

    def test_prepare_payment_group_preserves_order(self):
        sender = sdk_test_address(1)
        receiver1 = sdk_test_address(2)
        receiver2 = sdk_test_address(3)
        algod = MockAlgod({
            sender: {"amount": 2_000_000, "min-balance": 100_000},
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
            self._status(),
        ]):
            group = client.prepare_payment_group(algod, [
                {"sender": sender, "receiver": receiver1, "amount": 10_000},
                {"sender": sender, "receiver": receiver2, "amount": 20_000},
            ])

        assert len(group.transactions) == 2
        assert group.transactions[0].transaction.receiver == receiver1
        assert group.transactions[1].transaction.receiver == receiver2
        assert group.checks[0].name == "payment_group"
        assert group.checks[1].name == "group_algo_balance"

    def test_prepare_payment_group_rejects_aggregate_insufficient_funds(self):
        sender = sdk_test_address(1)
        receiver1 = sdk_test_address(2)
        receiver2 = sdk_test_address(3)
        algod = MockAlgod({
            sender: {"amount": 121_000, "min-balance": 100_000},
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
            self._status(),
        ]):
            with pytest.raises(SignerError, match="group insufficient funds"):
                client.prepare_payment_group(algod, [
                    {
                        "sender": sender,
                        "receiver": receiver1,
                        "amount": 10_000,
                        "fee": 1000,
                    },
                    {
                        "sender": sender,
                        "receiver": receiver2,
                        "amount": 10_000,
                        "fee": 1000,
                    },
                ])

    def test_prepare_asa_transfer_group_preserves_order(self):
        sender = sdk_test_address(1)
        receiver = sdk_test_address(2)
        algod = MockAlgod({
            sender: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 25}],
            },
            receiver: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 0}],
            },
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
            self._status(),
        ]):
            group = client.prepare_asa_transfer_group(algod, [
                {"sender": sender, "receiver": receiver, "asset_id": 1001, "amount": 5},
                {"sender": sender, "receiver": receiver, "asset_id": 1001, "amount": 7},
            ])

        assert len(group.transactions) == 2
        assert group.transactions[0].transaction.amount == 5
        assert group.transactions[1].transaction.amount == 7
        assert group.checks[0].name == "asa_transfer_group"
        assert group.checks[1].name == "asa_transfer_group_balance"

    def test_prepare_asa_transfer_group_rejects_aggregate_insufficient_asset_balance(self):
        sender = sdk_test_address(1)
        receiver = sdk_test_address(2)
        algod = MockAlgod({
            sender: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 10}],
            },
            receiver: {
                "amount": 2_000_000,
                "min-balance": 100_000,
                "assets": [{"asset-id": 1001, "amount": 0}],
            },
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
            self._status(),
        ]):
            with pytest.raises(SignerError, match="ASA transfer group insufficient asset balance"):
                client.prepare_asa_transfer_group(algod, [
                    {"sender": sender, "receiver": receiver, "asset_id": 1001, "amount": 6},
                    {"sender": sender, "receiver": receiver, "asset_id": 1001, "amount": 6},
                ])

    def test_prepare_payment_app_call_group(self):
        sender = sdk_test_address(1)
        receiver = sdk_test_address(2)
        sp = transaction.SuggestedParams(
            1000,
            1,
            100,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            gen="testnet-v1",
            flat_fee=True,
        )
        payment_txn = transaction.PaymentTxn(sender=sender, sp=sp, receiver=receiver, amt=1)
        app_txn = transaction.ApplicationCallTxn(
            sender=sender,
            sp=sp,
            index=7,
            on_complete=transaction.OnComplete.NoOpOC,
        )
        client = make_client()

        group = client.prepare_payment_app_call_group(
            PreparedTransaction(transaction=payment_txn, auth_address="PAY_AUTH"),
            PreparedTransaction(
                transaction=app_txn,
                auth_address="APP_AUTH",
                app_call_info={"mode": "raw"},
            ),
        )

        assert len(group.transactions) == 2
        assert group.transactions[0].auth_address == "PAY_AUTH"
        assert group.transactions[1].app_call_info == {"mode": "raw"}
        assert group.checks[0].name == "payment_app_call_order"


class TestFromEnv:
    def test_throws_when_default_endpoint_missing(self, tmp_path):
        with pytest.raises(SignerError, match="no default signer endpoint"):
            SignerClient.from_env(data_dir=str(tmp_path))

    def test_connects_named_endpoint_with_its_own_identity(self, tmp_path):
        (tmp_path / "endpoints.yaml").write_text(
            "schema_version: 2\nendpoints:\n"
            "  primary:\n    role: signer\n    url: ssh://signer.example.com/\n"
            "  qa:\n    role: cosigner\n    url: ssh://127.0.0.1:1/\n    identity_file: keys/qa\n"
        )
        # The key is the only credential, so a missing identity file is the
        # first failure.
        with pytest.raises(SignerError, match=re.escape(f"SSH key not found at {tmp_path / 'keys' / 'qa'}")):
            SignerClient.from_env(data_dir=str(tmp_path), endpoint="qa", timeout=7)

    @pytest.mark.parametrize(
        "fixture,want",
        [
            ("invalid_self_signer.yaml", 'endpoint "primary": url "self" is not supported'),
            ("invalid_self_cosigner.yaml", 'endpoint "cosigner": url "self" is not supported'),
        ],
    )
    def test_rejects_invalid_endpoint_before_connecting(self, tmp_path, fixture, want):
        source = os.path.join("..", "contracts", "clientconfig", fixture)
        with open(source, "rb") as fixture_file:
            (tmp_path / "endpoints.yaml").write_bytes(fixture_file.read())
        with pytest.raises(SignerError, match=re.escape(want)):
            SignerClient.from_env(data_dir=str(tmp_path))


class TestSignReturnFormat:
    def _make_mock_txn(self, sender=None):
        return fake_signer.payment(sender=sender)

    def test_sign_transactions_list_returns_individual_base64(self):
        client = make_client()
        txns = [fake_signer.payment(41, 42), fake_signer.payment(43, 44)]
        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post()):
            result = client.sign_transactions_list(txns)

        assert len(result) == 2
        # Each slot signs its own transaction, changed only by the group ID
        # the signer assigned.
        for item, txn in zip(result, txns):
            signed = algo_encoding.msgpack_decode(item)
            assert signed.transaction.group is not None
            signed.transaction.group = None
            assert signed.transaction == txn

    def test_sign_transactions_returns_concatenated_base64(self):
        client = make_client()
        txns = [fake_signer.payment(41, 42), fake_signer.payment(43, 44)]
        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post()):
            result = client.sign_transactions(txns)
            individual = client.sign_transactions_list(txns)

        assert base64.b64decode(result) == b"".join(base64.b64decode(item) for item in individual)

    def test_sign_transactions_rejects_empty_slot(self):
        client = make_client()

        def blank(body):
            body["signed"][1] = ""

        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post(tamper=blank)):
            with pytest.raises(SignerError, match="no signature for position 2"):
                client.sign_transactions([fake_signer.payment(41, 42), fake_signer.payment(43, 44)])

    def test_sign_transactions_list_rejects_empty_slot(self):
        client = make_client()

        def blank(body):
            body["signed"][1] = ""

        with patch.object(client, "_discover_approval_wait"), \
             patch.object(client.session, "post", side_effect=fake_signer.signer_post(tamper=blank)):
            with pytest.raises(SignerError, match="no signature for position 2"):
                client.sign_transactions_list(
                    [fake_signer.payment(41, 42), fake_signer.payment(43, 44)]
                )


class TestRequestEnrollmentFromEnv:
    def test_enrolls_selected_endpoint_identity(self, tmp_path):
        (tmp_path / "endpoints.yaml").write_text(
            "schema_version: 2\nendpoints:\n"
            "  primary:\n    role: signer\n    url: ssh://signer.example.com\n"
            "  qa:\n    role: cosigner\n    url: ssh://cosigner.example.com:2222\n"
        )
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_ed25519").write_text("dummy-private-key")

        with patch(
            "aplanesdk.signer.request_enrollment",
            return_value=EnrollmentResult(fingerprint="SHA256:abc", pending=True),
        ) as enroll:
            result = request_enrollment_from_env(
                data_dir=str(tmp_path),
                endpoint="qa",
                label="ci",
            )

        assert result == EnrollmentResult(fingerprint="SHA256:abc", pending=True)
        assert enroll.call_args.kwargs["host"] == "cosigner.example.com"
        assert enroll.call_args.kwargs["ssh_port"] == 2222
        assert enroll.call_args.kwargs["label"] == "ci"
        assert enroll.call_args.kwargs["ssh_key_path"] == str(ssh_dir / "id_ed25519")
        assert enroll.call_args.kwargs["known_hosts_path"] == str(
            tmp_path / ".ssh" / "known_hosts"
        )
        # Nothing is stored on the client: the key is its credential.
        assert sorted(p.name for p in tmp_path.iterdir()) == [".ssh", "endpoints.yaml"]


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# encoding utilities
# ---------------------------------------------------------------------------

class TestEncoding:
    def test_encode_transaction(self):
        """encode_transaction returns (hex, sender)."""
        from aplanesdk.signer import encode_transaction
        txn = MagicMock()
        txn.sender = "SENDER_ADDR"
        txn.dictify.return_value = {"snd": b"\x00" * 32}
        txn.get_txid.return_value = "TXID"

        with patch("aplanesdk.signer.encoding.msgpack_encode", return_value="gqNzbmTEIAAA"):
            result = encode_transaction(txn)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], str)  # hex string
        assert result[1] == "SENDER_ADDR"  # sender

    def test_hex_round_trip(self):
        """bytes -> hex -> bytes round-trip."""
        original = bytes([0, 1, 255, 16, 171])
        hex_str = original.hex()
        assert hex_str == "0001ff10ab"
        assert bytes.fromhex(hex_str) == original

    def test_hex_empty(self):
        assert bytes().hex() == ""
        assert bytes.fromhex("") == b""

    def test_base64_round_trip(self):
        """hex -> base64 (like signed txn conversion)."""
        hex_str = "deadbeef"
        decoded = bytes.fromhex(hex_str)
        b64 = base64.b64encode(decoded).decode()
        assert base64.b64decode(b64) == decoded

    def test_concatenate_signed_txns(self):
        """Concatenate hex strings to base64 (like signTransaction does)."""
        hexes = ["0102", "0304"]
        all_bytes = b"".join(bytes.fromhex(h) for h in hexes)
        result = base64.b64encode(all_bytes).decode()
        assert result == "AQIDBA=="

    def test_concatenate_single(self):
        hexes = ["deadbeef"]
        all_bytes = b"".join(bytes.fromhex(h) for h in hexes)
        result = base64.b64encode(all_bytes).decode()
        assert result == "3q2+7w=="


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_default_config(self, tmp_path):
        config = load_config(str(tmp_path))
        assert config.network == "testnet"
        assert config.networks_allowed == []
        assert config.theme == "auto"

    def test_rejects_obsolete_endpoint_routing(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "endpoint:\n"
            "  signer_port: 12345\n"
            "  ssh:\n"
            "    host: signer.example.com\n"
            "    port: 2222\n"
            "    identity_file: .ssh/mykey\n"
            "    known_hosts_path: .ssh/hosts\n"
            "    trust_on_first_use: true\n"
        )
        with pytest.raises(SignerError, match="configure endpoints.yaml"):
            load_config(str(tmp_path))

    def test_rejects_malformed_yaml(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("network: [")
        with pytest.raises(SignerError, match="failed to parse config.yaml"):
            load_config(str(tmp_path))


class TestLoadClientEndpointRegistry:
    @staticmethod
    def _fixture(tmp_path, name):
        source = os.path.join("..", "contracts", "clientconfig", name)
        (tmp_path / "endpoints.yaml").write_bytes(open(source, "rb").read())

    def test_loads_shared_valid_fixture(self, tmp_path):
        self._fixture(tmp_path, "valid.yaml")
        registry = load_client_endpoint_registry(str(tmp_path))
        assert registry.default == "primary"
        assert registry.endpoints is not None
        primary = registry.endpoints["primary"]
        assert primary.url == "ssh://signer.example.com:2222"
        assert primary.identity_file == str(tmp_path / ".ssh" / "primary")
        cosigner = registry.endpoints["cosigner.qa"]
        assert cosigner.url == "ssh://cosigner.example.com"
        assert cosigner.identity_file == str(tmp_path / "credentials" / "cosigner")
        assert cosigner.known_hosts_path == str(tmp_path / ".ssh" / "known_hosts")

    @pytest.mark.parametrize(
        "name",
        [
            "invalid_default_type.yaml",
            "invalid_identity_file_type.yaml",
            "invalid_multiple_signers.yaml",
            "invalid_remote_http.yaml",
            "invalid_loopback_http.yaml",
            "invalid_https.yaml",
            "invalid_schema_version_float.yaml",
            "invalid_ssh_port_zero.yaml",
            "invalid_unknown_field.yaml",
            "invalid_unknown_tag.yaml",
        ],
    )
    def test_rejects_shared_invalid_fixtures(self, tmp_path, name):
        self._fixture(tmp_path, name)
        with pytest.raises(SignerError):
            load_client_endpoint_registry(str(tmp_path))

    @pytest.mark.parametrize(
        "name,want",
        [
            ("invalid_self_signer.yaml", 'endpoint "primary": url "self" is not supported'),
            ("invalid_self_cosigner.yaml", 'endpoint "cosigner": url "self" is not supported'),
            ("invalid_13_cosigner_endpoints.yaml", "configures 13 cosigner endpoints; maximum is 12"),
            ("invalid_v2_published_cosigners.yaml", "published_cosigners"),
        ],
    )
    def test_rejects_shared_fixture_for_expected_reason(self, tmp_path, name, want):
        self._fixture(tmp_path, name)
        with pytest.raises(SignerError, match=re.escape(want)):
            load_client_endpoint_registry(str(tmp_path))

    @pytest.mark.parametrize(
        "name",
        [
            "valid_12_cosigner_endpoints.yaml",
            "valid_retired_port_fields.yaml",
        ],
    )
    def test_accepts_shared_edge_fixtures(self, tmp_path, name):
        self._fixture(tmp_path, name)
        registry = load_client_endpoint_registry(str(tmp_path))
        assert registry.schema_version == 2
        if name == "valid_12_cosigner_endpoints.yaml":
            assert len(registry.endpoints) == 12
        if name == "valid_retired_port_fields.yaml":
            primary = registry.endpoints["primary"]
            assert primary.url == "ssh://signer.example.com:2222"
            assert primary.identity_file == str(tmp_path / ".ssh" / "id_ed25519")
            assert "cosigner" in registry.endpoints

    @pytest.mark.parametrize(
        "name,want",
        [
            ("invalid_schema_version_missing.yaml", "endpoints.yaml schema_version = 0, want 2"),
            ("invalid_schema_version_zero.yaml", "endpoints.yaml schema_version = 0, want 2"),
            ("invalid_schema_version_null.yaml", "endpoints.yaml schema_version = None, want 2"),
            ("invalid_schema_version_one.yaml", "endpoints.yaml schema_version = 1, want 2"),
            ("invalid_v1_published_cosigners.yaml", "endpoints.yaml schema_version = 1, want 2"),
        ],
    )
    def test_requires_schema_version_2(self, tmp_path, name, want):
        self._fixture(tmp_path, name)
        with pytest.raises(SignerError, match=re.escape(want)):
            load_client_endpoint_registry(str(tmp_path))

    def test_derives_default_and_client_identity(self, tmp_path):
        (tmp_path / "endpoints.yaml").write_text(
            "schema_version: 2\nendpoints:\n"
            "  main:\n    role: signer\n    url: ssh://localhost\n"
            "  qa:\n    role: cosigner\n    url: ssh://127.0.0.1:2222\n"
        )
        registry = load_client_endpoint_registry(str(tmp_path))
        assert registry.default == "main"
        assert registry.endpoints is not None
        for alias in ("main", "qa"):
            assert registry.endpoints[alias].identity_file == str(tmp_path / ".ssh" / "id_ed25519")
            assert registry.endpoints[alias].known_hosts_path == str(
                tmp_path / ".ssh" / "known_hosts"
            )
        assert resolve_client_endpoint(registry)[0] == "main"
        assert resolve_client_endpoint(registry, "qa")[1].role == "cosigner"


class TestRequestEnrollment:
    # The signer answers at once: queued for the operator (pending) or already
    # enrolled. Either way the fingerprint must be the authenticating key's.
    def test_parses_pending_and_enrolled_replies(self):
        from aplanesdk.signer import _parse_enrollment_reply

        fp = "SHA256:abc"
        assert _parse_enrollment_reply(f"pending {fp}", fp) == EnrollmentResult(fp, True)
        assert _parse_enrollment_reply(f"enrolled {fp}", fp) == EnrollmentResult(fp, False)
        with pytest.raises(EnrollmentError, match="this client authenticated with SHA256:abc"):
            _parse_enrollment_reply("pending SHA256:other", fp)
        for reply in ("enrolled ", f"ok {fp}", ""):
            with pytest.raises(EnrollmentError, match="Unexpected enrollment response"):
                _parse_enrollment_reply(reply, fp)

    def test_requires_explicit_known_hosts_path(self):
        with pytest.raises(TypeError, match="known_hosts_path"):
            request_enrollment("signer.example.com", "/apclient/.ssh/id_ed25519")

    def test_auto_add_host_requires_bool(self):
        with pytest.raises(TypeError, match="auto_add_host must be a bool"):
            request_enrollment(
                "signer.example.com",
                "/apclient/.ssh/id_ed25519",
                known_hosts_path="/apclient/.ssh/known_hosts",
                auto_add_host="false",  # type: ignore[arg-type]
            )

        with pytest.raises(TypeError, match="auto_add_host must be a bool"):
            request_enrollment_from_env(auto_add_host="false")  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "label", ["x" * 65, "two\nlines", " padded", "tab\tbed"]
    )
    def test_rejects_bad_labels_before_any_network_activity(self, label):
        with pytest.raises(SignerError, match="enrollment label"):
            request_enrollment(
                "signer.example.com",
                "/nonexistent/key",
                known_hosts_path="/nonexistent/known_hosts",
                label=label,
            )


class _FeeParams:
    """Minimal SuggestedParams stand-in for _apply_prep_fee tests."""

    def __init__(self):
        self.fee = 7
        self.flat_fee = False


class TestApplyPrepFee:
    """The unified fee model: a positive fee is always flat microAlgos, an
    explicit flat zero is applied, and None leaves the suggested fee intact."""

    def test_positive_fee_is_flat(self):
        from aplanesdk.signer import _apply_prep_fee

        p = _FeeParams()
        _apply_prep_fee(p, 5000)
        assert p.fee == 5000 and p.flat_fee is True

    def test_explicit_zero_is_flat(self):
        from aplanesdk.signer import _apply_prep_fee

        p = _FeeParams()
        _apply_prep_fee(p, 0)
        assert p.fee == 0 and p.flat_fee is True

    def test_none_keeps_suggested(self):
        from aplanesdk.signer import _apply_prep_fee

        p = _FeeParams()
        _apply_prep_fee(p, None)
        assert p.fee == 7 and p.flat_fee is False


def _bounded_info(contract, max_fee):
    from aplanesdk.signer import BoundedAuthorizationInfo, BoundedSignatureArgLayout

    return BoundedAuthorizationInfo(
        contract=contract,
        base_signature_arg_layout=BoundedSignatureArgLayout(1, [1280]),
        spend_effects=[],
        max_fee=max_fee,
        rekey="refused",
        runtime_args=[],
        derived_args=[],
        argument_layout=[],
        layer3_policy="none",
    )


@pytest.mark.parametrize(
    ("contract", "max_fee", "ceiling", "error"),
    [
        ("bounded2", 10_000, 10_000, None),
        ("bounded2", None, None, "has no max_fee"),
        ("plain1", None, None, None),
        ("plain1", 0, None, "never has"),
        ("bounded3", 1, None, "not supported"),
    ],
)
def test_bounded_fee_ceiling_follows_the_contract(contract, max_fee, ceiling, error):
    from aplanesdk.signer import _bounded_fee_ceiling

    info = _bounded_info(contract, max_fee)
    if error:
        with pytest.raises(SignerError, match=error):
            _bounded_fee_ceiling(info)
    else:
        assert _bounded_fee_ceiling(info) == ceiling


def test_bounded_authorization_parses_an_absent_fee_ceiling():
    from aplanesdk.signer import _parse_bounded_authorization

    info = _parse_bounded_authorization({"contract": "plain1", "rekey": "refused", "layer3_policy": "none"})
    assert info is not None and info.max_fee is None
    with pytest.raises(SignerError, match="non-negative integer"):
        _parse_bounded_authorization({"contract": "bounded2", "max_fee": -1})
