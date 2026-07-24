# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Tests for aplane Python SDK client."""

import base64
import copy
import json
from unittest.mock import patch, MagicMock
import os

import pytest
from algosdk import account, encoding as algo_encoding, transaction

from aplanesdk.signer import (
    SignerClient,
    AuthenticationError,
    SigningRejectedError,
    SignerUnavailableError,
    SignerError,
    KeyNotFoundError,
    KeyDeletionError,
    assemble_group,
    sign_guarded_group,
    sign_prepared_guarded_group,
    simulate_guarded_group,
    load_config,
    load_client_endpoint_registry,
    resolve_client_endpoint,
    SSHConfig,
    ClientConfig,
    ComponentSignRequest,
    ComponentSignature,
    ComponentSignResponse,
    GroupSignResponse,
    KeyInfo,
    GuardedAssemblyRequest,
    GuardedAssemblyTarget,
    GuardedAssemblyResponse,
    BoundedComponentRequest,
    BoundedBaseComponent,
    BoundedComponentResponse,
    BoundedAssemblyResponse,
    BoundedSentryAuthorizationInfo,
    BoundedAuthorizationInfo,
    BoundedSignatureArgLayout,
    GuardedSignTarget,
    GuardedPrimarySignTarget,
    SentryReferenceCandidate,
    PreparedTransaction,
    PreparedGroup,
    COMPONENT_SIGN_ROLE_SENTRY,
    KEY_TYPE_GUARDED_FALCON1024_SENTRY1024,
    KEY_TYPE_WITNESS_FALCON1024,
    SIGNING_FLOW_SENTRY1,
    SIGNING_FLOW_BOUNDED_SENTRY1,
    request_token,
    request_token_to_file,
    encode_transaction,
    _validate_sign_request_id,
    _create_guarded_dummies,
    _request_bounded_primary_passthrough,
    _sign_guarded_dummies,
    _validate_bounded_component_request,
    _validate_bounded_component_response,
    _validate_bounded_component_plan,
    _validate_bounded_target_fees,
    _decode_canonical_group,
)


def make_client(base_url="http://localhost:11270", token="test-token"):
    """Create a SignerClient with no SSH tunnel."""
    return SignerClient(base_url, token, timeout=10)


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
            "identity_id": "default",
            "state": "unlocked",
            "signer_locked": False,
            "ready_for_signing": True,
            "key_count": 37,
            "keyset_revision": 4,
            "approval_wait_seconds": 60,
        })

        with patch.object(client.session, "get", return_value=resp) as mock_get:
            identity = client.get_status()

        assert identity.identity_id == "default"
        assert identity.keyset_revision == 4
        assert identity.approval_wait_seconds == 60
        assert mock_get.call_args.args[0] == "http://localhost:11270/status"
        assert mock_get.call_args.kwargs["timeout"] == 5

    def test_locked_state_is_success(self):
        client = make_client()
        resp = mock_response(200, {
            "identity_id": "default",
            "state": "locked",
            "signer_locked": True,
            "ready_for_signing": False,
            "key_count": 0,
            "keyset_revision": 2,
        })

        with patch.object(client.session, "get", return_value=resp):
            identity = client.get_status()

        assert identity.state == "locked"
        assert identity.signer_locked is True
        assert identity.ready_for_signing is False

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
                {"address": "ADDR1", "key_type": "ed25519", "public_key_hex": "abcd", "lsig_size": 0},
                {
                    "address": "ADDR2",
                    "key_type": "aplane.falcon1024.v1",
                    "lsig_size": 3035,
                    "template_status": "unavailable",
                    "template_warning": "template fingerprint unavailable",
                },
            ],
        })
        with patch.object(client.session, "get", return_value=resp):
            keys = client.list_keys()

        assert len(keys) == 2
        assert keys[0].address == "ADDR1"
        assert keys[0].key_type == "ed25519"
        assert keys[0].public_key_hex == "abcd"
        assert keys[1].lsig_size == 3035
        assert keys[1].template_status == "unavailable"
        assert keys[1].template_warning == "template fingerprint unavailable"
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
            "identity_id": "default",
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
        resp = mock_response(200, {"signed": ["aa"]})
        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerError, match="want at least 2"):
                client.sign_requests([
                    {"auth_address": "AUTH1", "txn_bytes_hex": "5458aa"},
                    {"auth_address": "AUTH2", "txn_bytes_hex": "5458bb"},
                ])

    def test_foreign_slot_and_trailing_dummies_tolerated(self):
        client = make_client()
        resp = mock_response(200, {"signed": ["aa", "", "dd"]})
        with patch.object(client.session, "post", return_value=resp):
            result = client.sign_requests([
                {"auth_address": "AUTH1", "txn_bytes_hex": "5458aa"},
                {"txn_bytes_hex": "5458bb"},
            ])
        assert result.signed == ["aa", "", "dd"]

    def test_locked_error(self):
        client = make_client()
        with patch.object(client.session, "post", return_value=mock_response(403)):
            with pytest.raises(SignerUnavailableError):
                client.generate_key("ed25519")

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
# sentry low-level endpoints
# ---------------------------------------------------------------------------

class TestSpecializedLowLevelEndpoints:
    def test_request_component_sign_posts_to_component_endpoint(self):
        client = make_client()
        resp = mock_response(200, {
            "request_id": "sdk-generated",
            "signatures": [
                {
                    "target_index": 0,
                    "signature": "aabb",
                    "signature_scheme": KEY_TYPE_WITNESS_FALCON1024,
                },
            ],
        })

        with patch.object(client.session, "post", return_value=resp) as mock_post:
            result = client.request_component_sign(ComponentSignRequest(
                request_id="sdk-generated",
                role=COMPONENT_SIGN_ROLE_SENTRY,
                component_key="COMPONENT",
                group_bytes_hex=["5458aa"],
                target_indices=[0],
            ))

        assert result.signatures[0].signature == "aabb"
        assert mock_post.call_args.args[0] == "http://localhost:11270/sign/component"
        body = mock_post.call_args.kwargs["json"]
        assert body["request_id"].startswith("sdk-")
        assert body["role"] == COMPONENT_SIGN_ROLE_SENTRY
        assert body["component_key"] == "COMPONENT"

    def test_request_component_sign_rejects_malformed_response(self):
        client = make_client()
        resp = mock_response(200, {"request_id": "sdk-test"})

        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerError, match="invalid component sign response"):
                client.request_component_sign({
                    "role": COMPONENT_SIGN_ROLE_SENTRY,
                    "group_bytes_hex": ["5458aa"],
                    "target_indices": [0],
                })

    def test_request_component_sign_rejects_foreign_target_index(self):
        client = make_client()
        resp = mock_response(200, {
            "request_id": "sdk-component",
            "signatures": [{
                "target_index": 1,
                "signature": "aabb",
                "signature_scheme": KEY_TYPE_WITNESS_FALCON1024,
            }],
        })

        with patch.object(client.session, "post", return_value=resp):
            with pytest.raises(SignerError, match="indices do not match"):
                client.request_component_sign({
                    "request_id": "sdk-component",
                    "role": COMPONENT_SIGN_ROLE_SENTRY,
                    "group_bytes_hex": ["5458aa", "5458bb"],
                    "target_indices": [0],
                })

    def test_request_guarded_assemble_posts_to_assemble_endpoint(self):
        client = make_client()
        resp = mock_response(200, {
            "request_id": "sdk-assembly",
            "signed_group": ["ccdd"],
        })

        with patch.object(client.session, "post", return_value=resp) as mock_post:
            result = client.request_guarded_assemble(GuardedAssemblyRequest(
                group_bytes_hex=["5458aa"],
                targets=[
                    GuardedAssemblyTarget(
                        target_index=0,
                        guarded_account="GUARDED",
                        user_signature="aabb",
                        sentry_signature="bbcc",
                    ),
                ],
            ))

        assert result.signed_group == ["ccdd"]
        assert mock_post.call_args.args[0] == "http://localhost:11270/sign/assemble"
        body = mock_post.call_args.kwargs["json"]
        assert body["request_id"].startswith("sdk-")
        assert body["targets"][0]["guarded_account"] == "GUARDED"

    def test_request_guarded_assemble_rejects_missing_coverage(self):
        client = make_client()
        with patch.object(client.session, "post") as mock_post:
            with pytest.raises(ValueError, match="not covered"):
                client.request_guarded_assemble(GuardedAssemblyRequest(
                    group_bytes_hex=["5458aa", "5458bb"],
                    targets=[
                        GuardedAssemblyTarget(
                            target_index=0,
                            guarded_account="GUARDED",
                            user_signature="aabb",
                            sentry_signature="bbcc",
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
                "transactions": ["5458aa"],
                "components": [{
                    "target_index": 0,
                    "bounded_account": "BOUNDED",
                    "base_signatures": ["base-sig"],
                    "assembly_receipt": "receipt",
                    "signature_scheme": "aplane.falcon1024.v1",
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
            component = client.request_bounded_component(BoundedComponentRequest(
                request_id="bounded-base-id",
                requests=[{
                    "auth_address": "BOUNDED",
                    "txn_bytes_hex": "5458aa",
                }],
            ))
            assembly = client.request_bounded_assemble({
                "request_id": "bounded-assembly-id",
                "group_bytes_hex": ["5458aa"],
                "targets": [{
                    "target_index": 0,
                    "bounded_account": "BOUNDED",
                    "base_signatures": ["base-sig"],
                    "assembly_receipt": "receipt",
                    "sentry_signature": "sentry-sig",
                }],
            })

        assert component.components[0].assembly_receipt == "receipt"
        assert assembly.signed_group == ["signed"]
        assert mock_post.call_args_list[0].args[0].endswith(
            "/sign/bounded-component"
        )
        assert mock_post.call_args_list[1].args[0].endswith(
            "/sign/bounded-assemble"
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
                client.request_bounded_component(BoundedComponentRequest(
                    request_id="bounded-cancel-id",
                    requests=[{
                        "auth_address": "BOUNDED",
                        "txn_bytes_hex": "5458aa",
                    }],
                ))

        assert mock_post.call_args_list[0].args[0].endswith(
            "/sign/bounded-component"
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
                client.request_bounded_component(BoundedComponentRequest(
                    request_id="bounded-not-found",
                    requests=[{
                        "auth_address": "BOUNDED",
                        "txn_bytes_hex": "5458aa",
                    }],
                ))

    def test_bounded_endpoints_surface_200_error_bodies(self):
        client = make_client()
        error_response = mock_response(200, {"error": "bounded failed"})
        with patch.object(
            client.session, "post", return_value=error_response
        ), patch.object(client, "_discover_approval_wait"):
            with pytest.raises(SignerError, match="bounded failed"):
                client.request_bounded_component(BoundedComponentRequest(
                    request_id="bounded-base-id",
                    requests=[{
                        "auth_address": "BOUNDED",
                        "txn_bytes_hex": "5458aa",
                    }],
                ))

        with patch.object(client.session, "post", return_value=error_response):
            with pytest.raises(SignerError, match="bounded failed"):
                client.request_bounded_assemble({
                    "request_id": "bounded-assembly-id",
                    "group_bytes_hex": ["5458aa"],
                    "targets": [{
                        "target_index": 0,
                        "bounded_account": "BOUNDED",
                        "base_signatures": ["base-sig"],
                        "assembly_receipt": "receipt",
                        "sentry_signature": "sentry-sig",
                    }],
                })

    def test_admin_sync_sentry_references_posts_to_admin_endpoint(self):
        client = make_client()
        resp = mock_response(200, {"added": 1, "updated": 0, "removed": 0, "count": 1})

        with patch.object(client.session, "post", return_value=resp) as mock_post:
            result = client.admin_sync_sentry_references([
                SentryReferenceCandidate(
                    endpoint_alias="sentry-local",
                    component_key="COMPONENT",
                    key_type=KEY_TYPE_WITNESS_FALCON1024,
                    public_key_hex="aabb",
                ),
            ])

        assert result.added == 1
        assert result.count == 1
        assert mock_post.call_args.args[0] == "http://localhost:11270/admin/sentries/sync"
        body = mock_post.call_args.kwargs["json"]
        assert body["candidates"][0]["component_key"] == "COMPONENT"


class TestSignGuardedGroup:
    def test_signs_one_guarded_target(self):
        user = make_client()
        sentry = make_client("http://sentry:11270")

        user.request_component_sign = MagicMock(return_value=ComponentSignResponse(
            request_id="user-id",
            signatures=[ComponentSignature(0, "user-sig", KEY_TYPE_WITNESS_FALCON1024)],
        ))
        sentry.request_component_sign = MagicMock(return_value=ComponentSignResponse(
            request_id="sentry-id",
            signatures=[ComponentSignature(0, "sentry-sig", KEY_TYPE_WITNESS_FALCON1024)],
        ))

        def assemble(req):
            assert req.targets[0].user_signature == "user-sig"
            assert req.targets[0].sentry_signature == "sentry-sig"
            return GuardedAssemblyResponse(
                request_id=req.request_id or "assembly-id",
                signed_group=["signed-guarded"],
            )

        user.request_guarded_assemble = MagicMock(side_effect=assemble)

        result = sign_guarded_group(
            user_client=user,
            sentry_client=sentry,
            sentry_component_key="SENTRY_COMPONENT",
            group_bytes_hex=["5458aa"],
            guarded_targets=[GuardedSignTarget(target_index=0, guarded_account="GUARDED")],
        )

        assert result.signed_group == ["signed-guarded"]
        user_req = user.request_component_sign.call_args.args[0]
        assert user_req.role == "user"
        assert user_req.component_key == "GUARDED"
        sentry_req = sentry.request_component_sign.call_args.args[0]
        assert sentry_req.role == COMPONENT_SIGN_ROLE_SENTRY
        assert sentry_req.component_key == "SENTRY_COMPONENT"

    def test_batches_targets_for_shared_sentry_key(self):
        user = make_client()
        sentry = make_client("http://sentry:11270")
        user.request_component_sign = MagicMock(return_value=ComponentSignResponse(
            request_id="user-id",
            signatures=[
                ComponentSignature(0, "user-0", KEY_TYPE_WITNESS_FALCON1024),
                ComponentSignature(1, "user-1", KEY_TYPE_WITNESS_FALCON1024),
            ],
        ))
        sentry.request_component_sign = MagicMock(return_value=ComponentSignResponse(
            request_id="sentry-id",
            signatures=[
                ComponentSignature(0, "sentry-0", KEY_TYPE_WITNESS_FALCON1024),
                ComponentSignature(1, "sentry-1", KEY_TYPE_WITNESS_FALCON1024),
            ],
        ))
        user.request_guarded_assemble = MagicMock(return_value=GuardedAssemblyResponse(
            request_id="assembly-id",
            signed_group=["signed-0", "signed-1"],
        ))

        sign_guarded_group(
            user_client=user,
            sentry_client=sentry,
            sentry_component_key="SENTRY_COMPONENT",
            group_bytes_hex=["5458aa", "5458bb"],
            guarded_targets=[
                GuardedSignTarget(target_index=0, guarded_account="GUARDED"),
                GuardedSignTarget(target_index=1, guarded_account="GUARDED"),
            ],
        )

        assert sentry.request_component_sign.call_count == 1
        assert sentry.request_component_sign.call_args.args[0].target_indices == [0, 1]

    def test_mixed_primary_and_guarded_group(self):
        user = make_client()
        sentry = make_client("http://sentry:11270")
        sender = sdk_test_address(7)
        receiver = sdk_test_address(8)
        params = transaction.SuggestedParams(
            1000,
            1,
            100,
            base64.b64encode(bytes(32)).decode(),
            "testnet-v1.0",
            flat_fee=True,
        )
        primary_txn = transaction.PaymentTxn(sender, params, receiver, 1000)
        primary_hex, _ = encode_transaction(primary_txn)
        logic_sig = transaction.LogicSigAccount(bytes.fromhex("033120320312"))
        primary_signed = base64.b64decode(algo_encoding.msgpack_encode(
            transaction.LogicSigTransaction(primary_txn, logic_sig)
        )).hex()
        user.request_component_sign = MagicMock(return_value=ComponentSignResponse(
            request_id="user-id",
            signatures=[ComponentSignature(1, "user-sig", KEY_TYPE_WITNESS_FALCON1024)],
        ))
        sentry.request_component_sign = MagicMock(return_value=ComponentSignResponse(
            request_id="sentry-id",
            signatures=[ComponentSignature(1, "sentry-sig", KEY_TYPE_WITNESS_FALCON1024)],
        ))
        user.sign_requests = MagicMock(return_value=GroupSignResponse(
            signed=[primary_signed, ""],
        ))

        def assemble(req):
            assert req.passthrough[0].target_index == 0
            assert req.passthrough[0].signed_txn_hex == primary_signed
            return GuardedAssemblyResponse(
                request_id="assembly-id",
                signed_group=[primary_signed, "guarded-signed"],
            )

        user.request_guarded_assemble = MagicMock(side_effect=assemble)

        result = sign_guarded_group(
            user_client=user,
            sentry_client=sentry,
            sentry_component_key="SENTRY_COMPONENT",
            group_bytes_hex=[primary_hex, "5458bb"],
            primary_targets=[
                GuardedPrimarySignTarget(target_index=0, auth_address="AUTH"),
            ],
            guarded_targets=[GuardedSignTarget(target_index=1, guarded_account="GUARDED")],
        )

        assert result.signed_group[1] == "guarded-signed"
        sign_requests = user.sign_requests.call_args.args[0]
        assert sign_requests[0]["auth_address"] == "AUTH"
        assert "auth_address" not in sign_requests[1]

    def test_prepared_all_guarded_adds_dummies_without_plan_or_sign(self):
        guarded = sdk_test_address(1)
        receiver = sdk_test_address(2)
        user = make_client()
        sentry = make_client("http://sentry:11270")

        user.request_component_sign = MagicMock(return_value=ComponentSignResponse(
            request_id="user-id",
            signatures=[ComponentSignature(0, "user-sig", KEY_TYPE_WITNESS_FALCON1024)],
        ))
        sentry.request_component_sign = MagicMock(return_value=ComponentSignResponse(
            request_id="sentry-id",
            signatures=[ComponentSignature(0, "sentry-sig", KEY_TYPE_WITNESS_FALCON1024)],
        ))
        user.sign_requests = MagicMock(side_effect=AssertionError("all-guarded path must not call /sign"))
        user.plan_group = MagicMock(side_effect=AssertionError("all-guarded path must not call /plan"))

        def assemble(req):
            assert len(req.group_bytes_hex) == 4
            assert len(req.passthrough) == 3
            assert [item.target_index for item in req.passthrough] == [1, 2, 3]
            assert all(item.signed_txn_hex for item in req.passthrough)
            return GuardedAssemblyResponse(
                request_id="assembly-id",
                signed_group=["guarded-signed", "dummy-1", "dummy-2", "dummy-3"],
            )

        user.request_guarded_assemble = MagicMock(side_effect=assemble)

        params = transaction.SuggestedParams(
            1000,
            1,
            100,
            base64.b64encode(bytes(32)).decode(),
            "testnet-v1.0",
            flat_fee=True,
        )
        txn = transaction.PaymentTxn(guarded, params, receiver, 1000)
        result = sign_prepared_guarded_group(
            user_client=user,
            sentry_client=sentry,
            sentry_component_key="SENTRY_COMPONENT",
            prepared_group=PreparedGroup([
                PreparedTransaction(
                    transaction=txn,
                    auth_address=guarded,
                    signer_key=KeyInfo(
                        address=guarded,
                        key_type=KEY_TYPE_GUARDED_FALCON1024_SENTRY1024,
                        signing_flow=SIGNING_FLOW_SENTRY1,
                        sentry_component_key_type=KEY_TYPE_WITNESS_FALCON1024,
                        lsig_size=3035,
                        parameters={"sentry_public_key": "aabbcc"},
                    ),
                )
            ]),
        )

        assert len(result.signed_group) == 4
        assert result.primary_sign_response is None
        user_req = user.request_component_sign.call_args.args[0]
        assert user_req.component_key == guarded
        assert len(user_req.group_bytes_hex) == 4
        sentry_req = sentry.request_component_sign.call_args.args[0]
        assert sentry_req.component_key == "SENTRY_COMPONENT"
        assert len(sentry_req.group_bytes_hex) == 4

    def test_bounded_component_plan_rejects_unreported_changes_and_bad_dummies(self):
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
        dummy = _create_guarded_dummies(original, 1)[0]
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

        _validate_bounded_component_plan([original], planned, mutations)

        changed = copy.deepcopy(planned)
        changed[0].receiver = sdk_test_address(23)
        with pytest.raises(SignerError, match="unreported fields"):
            _validate_bounded_component_plan([original], changed, mutations)

        changed = copy.deepcopy(planned)
        changed[1].amt = 1
        with pytest.raises(SignerError, match="canonical guarded budget dummy"):
            _validate_bounded_component_plan([original], changed, mutations)
        with pytest.raises(SignerError, match="canonical guarded budget dummy"):
            _sign_guarded_dummies(changed[1:], 1)

        grouped = copy.deepcopy(original)
        grouped.group = bytes([0x31]) * 32
        regrouped = copy.deepcopy(grouped)
        regrouped.group = bytes([0x32]) * 32
        with pytest.raises(SignerError, match="existing bounded group ID"):
            _validate_bounded_component_plan(
                [grouped],
                [regrouped],
                {
                    "group_id_changed": True,
                    "original_count": 1,
                    "final_count": 1,
                },
            )

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
        with pytest.raises(SignerError, match="does not match decoded transactions"):
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

    def test_bounded_component_rejects_passthrough_and_mixed_flows(self):
        with pytest.raises(ValueError, match="does not accept signed passthrough"):
            _validate_bounded_component_request({
                "request_id": "bounded-request",
                "requests": [{"signed_txn_hex": "abcd"}],
            })

        with pytest.raises(ValueError, match="invalid or duplicate target_index"):
            _validate_bounded_component_response({
                "request_id": "bounded-response",
                "transactions": ["5458aa"],
                "components": [
                    {
                        "target_index": 0,
                        "bounded_account": "BOUNDED",
                        "base_signatures": ["base"],
                        "assembly_receipt": "receipt",
                        "signature_scheme": "aplane.falcon1024.v1",
                    },
                    {
                        "target_index": 0,
                        "bounded_account": "BOUNDED",
                        "base_signatures": ["base"],
                        "assembly_receipt": "receipt",
                        "signature_scheme": "aplane.falcon1024.v1",
                    },
                ],
            })

        with pytest.raises(ValueError, match="cannot mix sentry1 and bounded-sentry1"):
            sign_prepared_guarded_group(
                user_client=make_client(),
                prepared_group=PreparedGroup([
                    PreparedTransaction(
                        signer_key=KeyInfo(
                            address="bounded",
                            key_type="bounded",
                            signing_flow=SIGNING_FLOW_BOUNDED_SENTRY1,
                        )
                    ),
                    PreparedTransaction(
                        signer_key=KeyInfo(
                            address="guarded",
                            key_type="guarded",
                            signing_flow=SIGNING_FLOW_SENTRY1,
                        )
                    ),
                ]),
            )

        user = make_client()
        user.get_key_info = MagicMock(
            side_effect=AuthenticationError("Invalid or missing token")
        )
        with pytest.raises(AuthenticationError):
            sign_prepared_guarded_group(
                user_client=user,
                prepared_group=PreparedGroup([
                    PreparedTransaction(auth_address=sdk_test_address(24))
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

    def test_prepared_bounded_sentry_uses_user_first_flow(self):
        bounded = sdk_test_address(11)
        receiver = sdk_test_address(12)
        user = make_client()
        sentry = make_client("http://sentry:11270")

        def bounded_component(req):
            assert isinstance(req, BoundedComponentRequest)
            assert req.requests[0]["auth_address"] == bounded
            return BoundedComponentResponse(
                request_id="base-id",
                transactions=[req.requests[0]["txn_bytes_hex"]],
                components=[BoundedBaseComponent(
                    target_index=0,
                    bounded_account=bounded,
                    base_signatures=["base-sig"],
                    runtime_args={"proof": "aabb"},
                    assembly_receipt="receipt",
                    signature_scheme="aplane.falcon1024.v1",
                )],
            )

        user.request_bounded_component = MagicMock(side_effect=bounded_component)
        sentry.request_component_sign = MagicMock(return_value=ComponentSignResponse(
            request_id="sentry-id",
            signatures=[ComponentSignature(
                0, "sentry-sig", KEY_TYPE_WITNESS_FALCON1024
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
            assert req.targets[0].sentry_signature == "sentry-sig"
            return BoundedAssemblyResponse(
                request_id="assembly-id",
                signed_group=[signed_txn_hex(assembled_txn[0])],
            )

        user.request_bounded_assemble = MagicMock(side_effect=bounded_assemble)
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
                    signer_key=KeyInfo(
                        address=bounded,
                        key_type="aplane.corridor.v1",
                        signing_flow=SIGNING_FLOW_BOUNDED_SENTRY1,
                        sentry_component_key_type=KEY_TYPE_WITNESS_FALCON1024,
                        lsig_size=9012,
                        bounded_authorization=BoundedAuthorizationInfo(
                            contract="bounded1",
                            base_signature_arg_layout=BoundedSignatureArgLayout(
                                count=1, max_sizes=[1280]
                            ),
                            spend_effects=["pay"],
                            max_fee=1000,
                            admin_operations=[],
                            runtime_args=[],
                            derived_args=[],
                            argument_layout=[],
                            layer3_policy="merkle_allowlist",
                            sentry=BoundedSentryAuthorizationInfo(
                                contract="sentry1",
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
            sign_prepared_guarded_group(
                user_client=user,
                sentry_client=sentry,
                sentry_component_key="SENTRY_COMPONENT",
                prepared_group=prepared_group,
            )

        assembled_txn[0] = txn
        result = sign_prepared_guarded_group(
            user_client=user,
            sentry_client=sentry,
            sentry_component_key="SENTRY_COMPONENT",
            prepared_group=prepared_group,
        )

        assert result.signed_group == [signed_txn_hex(txn)]
        assert result.assembly_response is None
        assert result.bounded_component_response is not None
        assert result.bounded_assembly_response is not None
        sentry_req = sentry.request_component_sign.call_args.args[0]
        assert len(sentry_req.group_bytes_hex) == 1
        assert sentry_req.group_bytes_hex[0].startswith("5458")
        assert sentry_req.target_indices == [0]

    def test_prepared_group_rejects_unsupported_signing_flow(self):
        guarded = sdk_test_address(1)
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
        txn = transaction.PaymentTxn(guarded, params, receiver, 1000)
        with pytest.raises(ValueError, match="signing flow 'sentry2'"):
            sign_prepared_guarded_group(
                user_client=user,
                prepared_group=PreparedGroup([
                    PreparedTransaction(
                        transaction=txn,
                        auth_address=guarded,
                        signer_key=KeyInfo(
                            address=guarded,
                            key_type="aplane.future-guarded.v1",
                            signing_flow="sentry2",
                            lsig_size=3035,
                        ),
                    )
                ]),
            )


# ---------------------------------------------------------------------------
# plan_group
# ---------------------------------------------------------------------------

class TestPlanGroup:
    def _make_mock_txn(self, sender="SENDER_ADDR"):
        txn = MagicMock()
        txn.sender = sender
        txn.dictify.return_value = {}
        txn.get_txid.return_value = "TXID"
        return txn

    def test_returns_plan(self):
        client = make_client()
        resp = mock_response(200, {
            "transactions": ["5458deadbeef", "5458cafebabe"],
            "mutations": {
                "dummies_added": 1,
                "group_id_changed": True,
                "original_count": 1,
                "final_count": 2,
            },
        })
        with patch.object(client.session, "post", return_value=resp), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            result = client.plan_group([self._make_mock_txn()])

        assert "transactions" in result
        assert len(result["transactions"]) == 2
        assert result["mutations"]["dummies_added"] == 1

    def test_auth_error(self):
        client = make_client()
        with patch.object(client.session, "post", return_value=mock_response(401)), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            with pytest.raises(AuthenticationError):
                client.plan_group([self._make_mock_txn()])

    def test_server_error_in_response(self):
        client = make_client()
        resp = mock_response(200, {"error": "Internal error"})
        with patch.object(client.session, "post", return_value=resp), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            with pytest.raises(SignerError):
                client.plan_group([self._make_mock_txn()])


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

    def test_requires_algod_before_contacting_signer(self):
        client = make_client()
        with patch.object(client.session, "post") as mock_post:
            with pytest.raises(ValueError, match="algod_client is required"):
                client.simulate_prepared_group(None, PreparedGroup([]))
        mock_post.assert_not_called()

    def test_guarded_requires_algod_before_signing(self):
        with pytest.raises(ValueError, match="algod_client is required"):
            simulate_guarded_group(None)


class TestConfigAndConstruction:
    def test_load_config_parse_error(self, tmp_path):
        (tmp_path / "config.yaml").write_text("ssh:\n  host: [\n", encoding="utf-8")
        with pytest.raises(SignerError, match="failed to parse config.yaml"):
            load_config(str(tmp_path))

    def test_constructor_requires_base_url(self):
        with pytest.raises(SignerError, match="base_url is required"):
            SignerClient("", "token")

    def test_constructor_requires_token(self):
        with pytest.raises(SignerError, match="token is required"):
            SignerClient("http://localhost:11270", "")


# ---------------------------------------------------------------------------
# signing errors
# ---------------------------------------------------------------------------

class TestSigningErrors:
    def _make_mock_txn(self, sender="SENDER_ADDR"):
        txn = MagicMock()
        txn.sender = sender
        return txn

    def test_auth_error(self):
        client = make_client()
        with patch.object(client.session, "post", return_value=mock_response(401)), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            with pytest.raises(AuthenticationError):
                client.sign_transaction(self._make_mock_txn())

    def test_signing_rejected(self):
        client = make_client()
        resp = mock_response(403, {"error": "Operator rejected"})
        with patch.object(client.session, "post", return_value=resp), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            with pytest.raises(SigningRejectedError):
                client.sign_transaction(self._make_mock_txn())

    def test_signer_unavailable(self):
        client = make_client()
        resp = mock_response(503, {"error": "Signer locked"})
        with patch.object(client.session, "post", return_value=resp), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            with pytest.raises(SignerUnavailableError):
                client.sign_transaction(self._make_mock_txn())

    def test_key_not_found(self):
        client = make_client()
        resp = mock_response(400, {"error": "Key not found: INVALID_ADDRESS"})
        with patch.object(client.session, "post", return_value=resp), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            with pytest.raises(KeyNotFoundError):
                client.sign_transaction(self._make_mock_txn())

    def test_key_not_found_by_code_regardless_of_wording(self):
        client = make_client()
        resp = mock_response(400, {"error": "auth address unavailable", "code": "not_found"})
        with patch.object(client.session, "post", return_value=resp), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            with pytest.raises(KeyNotFoundError):
                client.sign_transaction(self._make_mock_txn())

    def test_non_not_found_code_is_not_key_not_found(self):
        client = make_client()
        resp = mock_response(400, {"error": "group not found in request", "code": "bad_request"})
        with patch.object(client.session, "post", return_value=resp), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            with pytest.raises(SignerError) as exc_info:
                client.sign_transaction(self._make_mock_txn())
            assert not isinstance(exc_info.value, KeyNotFoundError)

    def test_uses_discovered_approval_wait_plus_slack(self):
        client = SignerClient("http://localhost:11270", "test-token")
        client._cache_approval_wait(120)

        assert client._sign_request_timeout() == 150

    def test_falls_back_for_invalid_approval_wait(self):
        client = SignerClient("http://localhost:11270", "test-token")
        client._cache_approval_wait(31 * 60)

        assert client._sign_request_timeout() == 360

    def test_status_discovery_failure_does_not_fail_sign(self):
        client = make_client()
        resp = mock_response(200, {"signed": ["deadbeef"]})
        with patch.object(client, "get_status", side_effect=SignerUnavailableError("down")), \
             patch.object(client.session, "post", return_value=resp), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            signed = client.sign_transaction(self._make_mock_txn())

        assert base64.b64decode(signed) == bytes.fromhex("deadbeef")

    def test_timeout(self):
        import requests
        client = make_client()
        with patch.object(client.session, "post", side_effect=requests.ConnectionError("timed out")), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
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
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")), \
             patch("aplanesdk.signer._new_sign_request_id", return_value="sdk-test"):
            with pytest.raises(SignerUnavailableError):
                client.sign_transaction(self._make_mock_txn())

        assert mock_post.call_args_list[0].args[0] == "http://localhost:11270/sign"
        assert mock_post.call_args_list[0].kwargs["json"]["request_id"] == "sdk-test"
        assert mock_post.call_args_list[1].args[0] == "http://localhost:11270/sign/cancel"
        assert mock_post.call_args_list[1].kwargs["json"] == {"request_id": "sdk-test"}

    def test_sign_transaction_accepts_caller_request_id(self):
        client = make_client()
        resp = mock_response(200, {"signed": ["deadbeef"]})
        with patch.object(client.session, "post", return_value=resp) as mock_post, \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
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
        resp = mock_response(200, {"signed": ["deadbeef"]})

        with patch.object(client.session, "post", return_value=resp) as mock_post:
            result = client.sign_requests(
                [
                    {
                        "txn_bytes_hex": "545801",
                        "auth_address": "AUTH",
                        "txn_sender": "SENDER",
                    },
                ],
                request_id="raw-requests-id",
            )

        assert result.signed == ["deadbeef"]
        assert mock_post.call_args.args[0] == "http://localhost:11270/sign"
        assert mock_post.call_args.kwargs["json"] == {
            "request_id": "raw-requests-id",
            "requests": [
                {
                    "txn_bytes_hex": "545801",
                    "auth_address": "AUTH",
                    "txn_sender": "SENDER",
                },
            ],
        }

    def test_sign_requests_validates_request_id(self):
        client = make_client()
        with pytest.raises(ValueError, match="invalid character"):
            client.sign_requests([{"txn_bytes_hex": "545801"}], request_id="bad id")


# ---------------------------------------------------------------------------
# sign_transactions with foreign entries
# ---------------------------------------------------------------------------

class TestSignTransactionsForeign:
    def _make_mock_txn(self, sender="SENDER_ADDR"):
        txn = MagicMock()
        txn.sender = sender
        return txn

    def test_rejects_foreign_in_sign_transactions(self):
        client = make_client()
        with patch.object(client.session, "post") as mock_post, \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            with pytest.raises(SignerError, match="foreign entries are only supported on /plan"):
                client.sign_transactions(
                    [self._make_mock_txn(), self._make_mock_txn()],
                    auth_addresses=["AUTH1", None],
                )
        mock_post.assert_not_called()

    def test_sign_transactions_list_rejects_foreign(self):
        client = make_client()
        with patch.object(client.session, "post") as mock_post, \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            with pytest.raises(SignerError, match="foreign entries are only supported on /plan"):
                client.sign_transactions_list(
                [self._make_mock_txn(), self._make_mock_txn()],
                auth_addresses=["AUTH1", None],
            )
        mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# assemble_group
# ---------------------------------------------------------------------------

class TestBuildSignRequests:
    def _make_mock_txn(self, sender="SENDER_ADDR"):
        txn = MagicMock()
        txn.sender = sender
        return txn

    def test_builds_request_with_auth_address(self):
        client = make_client()
        resp = mock_response(200, {"signed": ["deadbeef"]})
        with patch.object(client.session, "post", return_value=resp) as mock_post, \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            client.sign_transaction(self._make_mock_txn(), auth_address="AUTH_ADDR")

        call_kwargs = mock_post.call_args
        body = call_kwargs[1]["json"]
        assert body["request_id"]
        assert len(body["requests"]) == 1
        assert body["requests"][0]["auth_address"] == "AUTH_ADDR"
        assert body["requests"][0]["txn_bytes_hex"] == "deadbeef"

    def test_defaults_auth_address_to_sender(self):
        client = make_client()
        resp = mock_response(200, {"signed": ["deadbeef"]})
        with patch.object(client.session, "post", return_value=resp) as mock_post, \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "MY_SENDER")):
            client.sign_transaction(self._make_mock_txn(sender="MY_SENDER"))

        call_kwargs = mock_post.call_args
        body = call_kwargs[1]["json"]
        assert body["requests"][0]["auth_address"] == "MY_SENDER"

    def test_includes_lsig_args_as_hex(self):
        client = make_client()
        resp = mock_response(200, {"signed": ["deadbeef"]})
        with patch.object(client.session, "post", return_value=resp) as mock_post, \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "LSIG_ADDR")):
            client.sign_transaction(
                self._make_mock_txn(sender="LSIG_ADDR"),
                auth_address="LSIG_ADDR",
                lsig_args={"preimage": b"secret"},
            )

        call_kwargs = mock_post.call_args
        body = call_kwargs[1]["json"]
        assert body["requests"][0]["lsig_args"] is not None
        assert body["requests"][0]["lsig_args"]["preimage"] == "736563726574"


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
                lsig_size=3035,
            )
        ])

        with patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            requests = prepared.to_sign_requests()

        assert requests == [{
            "txn_bytes_hex": "deadbeef",
            "lsig_size": 3035,
        }]

    def test_to_sign_requests_passthrough_mode(self):
        prepared = PreparedGroup([
            PreparedTransaction(
                signed_transaction_base64=base64.b64encode(b"signed-txn").decode(),
            )
        ])

        assert prepared.to_sign_requests() == [{
            "signed_txn_hex": b"signed-txn".hex(),
        }]

    def test_rejects_empty_group(self):
        with pytest.raises(ValueError, match="prepared group is empty"):
            PreparedGroup([]).to_sign_requests()


class TestPrepHelpers:
    def _status(self):
        return mock_response(200, {
            "identity_id": "default",
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
                use_flat_fee=True,
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

    def test_prepare_keyreg_nonparticipation(self):
        sender = sdk_test_address(1)
        algod = MockAlgod({
            sender: {"amount": 2_000_000, "min-balance": 100_000},
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_keyreg(
                algod,
                sender=sender,
                nonpart=True,
            )

        assert prepared.transaction.nonpart is True
        assert prepared.checks[0].name == "keyreg"

    def test_prepare_keyreg_online(self):
        sender = sdk_test_address(1)
        key32 = base64.b64encode(bytes(32)).decode()
        key64 = base64.b64encode(bytes(64)).decode()
        algod = MockAlgod({
            sender: {"amount": 2_000_000, "min-balance": 100_000},
        })
        client = make_client()
        with patch.object(client.session, "get", side_effect=[
            self._status(),
            self._keys(sender),
        ]):
            prepared = client.prepare_keyreg(
                algod,
                sender=sender,
                votekey=key32,
                selkey=key32,
                sprfkey=key64,
                votefst=10,
                votelst=20,
                votekd=5,
            )

        assert prepared.transaction.votefst == 10
        assert prepared.transaction.votelst == 20

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
                use_flat_fee=True,
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
        assert group.checks[1].name == "payment_group_balance"

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
            with pytest.raises(SignerError, match="payment group insufficient funds"):
                client.prepare_payment_group(algod, [
                    {
                        "sender": sender,
                        "receiver": receiver1,
                        "amount": 10_000,
                        "fee": 1000,
                        "use_flat_fee": True,
                    },
                    {
                        "sender": sender,
                        "receiver": receiver2,
                        "amount": 10_000,
                        "fee": 1000,
                        "use_flat_fee": True,
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

    def test_uses_named_direct_endpoint_and_token(self, tmp_path):
        (tmp_path / "tokens").mkdir()
        (tmp_path / "tokens" / "qa.token").write_text("qa-token")
        (tmp_path / "endpoints.yaml").write_text(
            "schema_version: 1\nendpoints:\n"
            "  primary:\n    role: signer\n    url: https://signer.example.com/\n"
            "  qa:\n    role: sentry\n    url: http://127.0.0.1:11271/\n"
        )
        client = SignerClient.from_env(
            data_dir=str(tmp_path), endpoint="qa", timeout=7
        )
        assert client.base_url == "http://127.0.0.1:11271"
        assert client.token == "qa-token"
        assert client.timeout == 7

    def test_rejects_self_endpoint(self, tmp_path):
        (tmp_path / "endpoints.yaml").write_text(
            "schema_version: 1\nendpoints:\n"
            "  primary:\n    role: signer\n    url: self\n"
        )
        with pytest.raises(SignerError, match="not supported by the external SDK"):
            SignerClient.from_env(data_dir=str(tmp_path))


class TestSignReturnFormat:
    def _make_mock_txn(self, sender="SENDER_ADDR"):
        txn = MagicMock()
        txn.sender = sender
        return txn

    def test_sign_transactions_list_returns_individual_base64(self):
        client = make_client()
        hex1 = b"signed-txn-1".hex()
        hex2 = b"signed-txn-2".hex()
        resp = mock_response(200, {"signed": [hex1, hex2]})
        with patch.object(client.session, "post", return_value=resp), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            result = client.sign_transactions_list(
                [self._make_mock_txn(), self._make_mock_txn()]
            )

        assert len(result) == 2
        assert base64.b64decode(result[0]) == b"signed-txn-1"
        assert base64.b64decode(result[1]) == b"signed-txn-2"

    def test_sign_transactions_returns_concatenated_base64(self):
        client = make_client()
        hex1 = b"signed-txn-1".hex()
        hex2 = b"signed-txn-2".hex()
        resp = mock_response(200, {"signed": [hex1, hex2]})
        with patch.object(client.session, "post", return_value=resp), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            result = client.sign_transactions(
                [self._make_mock_txn(), self._make_mock_txn()]
            )

        decoded = base64.b64decode(result)
        assert decoded == b"signed-txn-1signed-txn-2"

    def test_sign_transactions_rejects_empty_slot(self):
        client = make_client()
        resp = mock_response(200, {"signed": [b"signed-txn-1".hex(), ""]})
        with patch.object(client.session, "post", return_value=resp), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            with pytest.raises(SignerError, match="no signature for position 2"):
                client.sign_transactions(
                    [self._make_mock_txn(), self._make_mock_txn()]
                )

    def test_sign_transactions_list_rejects_empty_slot(self):
        client = make_client()
        resp = mock_response(200, {"signed": [b"signed-txn-1".hex(), ""]})
        with patch.object(client.session, "post", return_value=resp), \
             patch("aplanesdk.signer.encode_transaction", return_value=("deadbeef", "SENDER_ADDR")):
            with pytest.raises(SignerError, match="no signature for position 2"):
                client.sign_transactions_list(
                    [self._make_mock_txn(), self._make_mock_txn()]
                )


class TestRequestTokenToFile:
    def test_creates_token_file_with_secure_permissions(self, tmp_path):
        (tmp_path / "config.yaml").write_text("endpoint:\n  ssh:\n    host: example.com\n    port: 1127\n")
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_ed25519").write_text("dummy-private-key")

        with patch("aplanesdk.signer.request_token", return_value="test-token"):
            path = request_token_to_file(
                data_dir=str(tmp_path),
                host="example.com",
            )

        assert os.path.exists(path)
        assert (tmp_path / "aplane.token").read_text() == "test-token"
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600


class TestAssembleGroup:
    def test_merges_two_signers(self):
        alice_signed = [
            base64.b64encode(bytes([1, 2])).decode(),
            "",
            base64.b64encode(bytes([5, 6])).decode(),
        ]
        bob_signed = [
            "",
            base64.b64encode(bytes([3, 4])).decode(),
            "",
        ]

        result = assemble_group([alice_signed, bob_signed])
        expected = base64.b64encode(bytes([1, 2, 3, 4, 5, 6])).decode()
        assert result == expected

    def test_empty_input(self):
        with pytest.raises(ValueError, match="must not be empty"):
            assemble_group([])

    def test_mismatched_lengths(self):
        with pytest.raises(ValueError, match="expected 2"):
            assemble_group([["a", "b"], ["c"]])

    def test_no_signer_for_slot(self):
        with pytest.raises(ValueError, match="slot 1: no signer"):
            assemble_group([["a", ""], ["", ""]])

    def test_multiple_signers_for_slot(self):
        with pytest.raises(ValueError, match="slot 0: multiple signers"):
            assemble_group([["a", "b"], ["c", "d"]])


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
        assert config.signer_port == 11270
        assert config.ssh is None

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
        assert primary.signer_port == 11271
        assert primary.local_port == 18080
        assert primary.identity_file == str(tmp_path / ".ssh" / "primary")
        assert primary.token_file == str(tmp_path / "aplane.token")
        sentry = registry.endpoints["sentry.qa"]
        assert sentry.token_file == str(tmp_path / "credentials" / "sentry.token")

    @pytest.mark.parametrize(
        "name",
        [
            "invalid_multiple_signers.yaml",
            "invalid_remote_http.yaml",
            "invalid_unknown_field.yaml",
        ],
    )
    def test_rejects_shared_invalid_fixtures(self, tmp_path, name):
        self._fixture(tmp_path, name)
        with pytest.raises(SignerError):
            load_client_endpoint_registry(str(tmp_path))

    def test_derives_default_and_alias_token_paths(self, tmp_path):
        (tmp_path / "endpoints.yaml").write_text(
            "schema_version: 1\nendpoints:\n"
            "  main:\n    role: signer\n    url: ssh://localhost\n"
            "  qa:\n    role: sentry\n    url: http://127.0.0.1:11271\n"
        )
        registry = load_client_endpoint_registry(str(tmp_path))
        assert registry.default == "main"
        assert registry.endpoints is not None
        assert registry.endpoints["main"].token_file == str(
            tmp_path / "tokens" / "main.token"
        )
        assert resolve_client_endpoint(registry)[0] == "main"
        assert resolve_client_endpoint(registry, "qa")[1].role == "sentry"


class TestRequestToken:
    def test_rejects_unsupported_identity_locally(self):
        with pytest.raises(SignerError, match="unsupported identity"):
            request_token(
                host="signer.example.com",
                ssh_key_path="~/.ssh/id_ed25519",
                identity="other-identity",
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
        _apply_prep_fee(p, 5000, False)
        assert p.fee == 5000 and p.flat_fee is True

    def test_explicit_zero_is_flat(self):
        from aplanesdk.signer import _apply_prep_fee

        p = _FeeParams()
        _apply_prep_fee(p, 0, False)
        assert p.fee == 0 and p.flat_fee is True

    def test_none_keeps_suggested(self):
        from aplanesdk.signer import _apply_prep_fee

        p = _FeeParams()
        _apply_prep_fee(p, None, False)
        assert p.fee == 7 and p.flat_fee is False


class TestCreateGuardedDummies:
    def test_requires_genesis_hash(self):
        from aplanesdk.signer import _create_guarded_dummies, SignerError

        class FakeTxn:
            genesis_hash = ""
            fee = 1000
            first_valid_round = 1
            last_valid_round = 100
            genesis_id = "x"

        with pytest.raises(SignerError, match="genesis hash"):
            _create_guarded_dummies(FakeTxn(), 1)
