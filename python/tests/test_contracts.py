# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Signer API contract fixture tests for the Python SDK."""

import json
import base64
from pathlib import Path
from unittest.mock import MagicMock, patch

from aplanesdk.signer import (
    AdminSyncSentryReferencesRequest,
    AdminSyncSentryReferencesResponse,
    CancelSignResponse,
    ComponentSignRequest,
    ComponentSignResponse,
    GuardedAssemblyRequest,
    GuardedAssemblyResponse,
    SignerClient,
    StatusResponse,
)


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "contracts" / "signerapi"
EXPECTED_FIXTURE_NAMES = [
    "admin_delete_response_success.json",
    "admin_generate_request_generic.json",
    "admin_generate_response_component.json",
    "admin_generate_response_generic.json",
    "admin_sync_sentries_request.json",
    "admin_sync_sentries_response.json",
    "cancel_sign_request.json",
    "cancel_sign_response_not_found.json",
    "cancel_sign_response_success.json",
    "component_sign_request_sentry.json",
    "component_sign_response_sentry.json",
    "error_response.json",
    "group_plan_response_mutated.json",
    "group_sign_request_mixed.json",
    "group_sign_response_mutated.json",
    "group_simulate_response_mutated.json",
    "guarded_assembly_request_mixed.json",
    "guarded_assembly_response.json",
    "health_response_ready.json",
    "keys_response_component.json",
    "keys_response_generic.json",
    "keys_response_guarded.json",
    "keytypes_response_full.json",
    "status_response_ready.json",
]


def fixture(name: str) -> dict:
    with open(FIXTURE_DIR / name, "r", encoding="utf-8") as f:
        return json.load(f)


def make_client(base_url="http://localhost:11270", token="test-token"):
    return SignerClient(base_url, token, timeout=10)


def mock_response(status_code=200, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = json.dumps(json_data).encode() if json_data else b""
    resp.json.return_value = json_data if json_data else {}
    return resp


def committed_fixture_names() -> list[str]:
    return sorted(path.name for path in FIXTURE_DIR.glob("*.json"))


def test_accounts_for_every_committed_fixture():
    assert committed_fixture_names() == EXPECTED_FIXTURE_NAMES
    for name in EXPECTED_FIXTURE_NAMES:
        assert isinstance(fixture(name), dict)


def test_encodes_mixed_group_sign_request_wire_fields():
    client = make_client()
    sign_txn = MagicMock()
    sign_txn.sender = "SENDERADDR0000000000000000000000000000000000000000000"
    foreign_txn = MagicMock()
    foreign_txn.sender = "FOREIGNADDR000000000000000000000000000000000000000000"
    passthrough = base64.b64encode(bytes.fromhex("82a3736967c440")).decode()

    with patch("aplanesdk.signer.encoding.msgpack_encode", side_effect=["AQ==", "Ag=="]):
        body = client._build_sign_request_body(
            [sign_txn, None, foreign_txn],
            ["AUTHADDR00000000000000000000000000000000000000000000000", None, None],
            {
                "AUTHADDR00000000000000000000000000000000000000000000000": {
                    "preimage": b"secret",
                    "recipient": bytes.fromhex("aabbccdd"),
                }
            },
            {1: passthrough},
            {2: 3035},
        )

    expected = fixture("group_sign_request_mixed.json")
    del expected["requests"][0]["app_call_info"]
    assert body == expected


def test_list_keys_maps_generic_lsig_metadata():
    client = make_client()
    resp = mock_response(200, fixture("keys_response_generic.json"))

    with patch.object(client.session, "get", return_value=resp):
        keys = client.list_keys(refresh=True)

    assert len(keys) == 2
    generic = keys[1]
    assert generic.public_key_hex == "ffeeddccbbaa99887766554433221100"
    assert generic.key_type == "aplane.timed-whitelist.v1"
    assert generic.lsig_size == 512
    assert generic.is_generic_lsig is True
    assert generic.signing_args is not None
    assert generic.signing_args[0].name == "preimage"
    assert generic.signing_args[0].label == "Preimage"
    assert generic.signing_args[0].required is True
    assert generic.signing_args[0].byte_length == 32


def test_list_key_types_maps_creation_and_runtime_metadata():
    client = make_client()
    resp = mock_response(200, fixture("keytypes_response_full.json"))

    with patch.object(client.session, "get", return_value=resp):
        key_types = client.list_key_types()

    timed_whitelist = key_types[1]
    assert timed_whitelist.key_type == "aplane.timed-whitelist.v1"
    assert timed_whitelist.display_name == "Timed Whitelist"
    assert timed_whitelist.requires_logicsig is True
    assert timed_whitelist.mnemonic_import is False
    assert timed_whitelist.creation_params is not None
    assert timed_whitelist.creation_params[1].param_type == "address[]"
    assert timed_whitelist.creation_params[1].min_items == 1
    assert timed_whitelist.creation_params[1].max_items == 8
    assert timed_whitelist.creation_params[2].min == 1
    assert timed_whitelist.creation_params[2].max == 999999999
    assert timed_whitelist.creation_params[3].max_length == 32
    assert timed_whitelist.creation_params[3].input_modes is not None
    assert timed_whitelist.creation_params[3].input_modes[1].name == "sha256"
    assert timed_whitelist.creation_params[3].input_modes[1].transform == "sha256"
    assert timed_whitelist.creation_params[3].input_modes[1].byte_length == 32
    assert timed_whitelist.creation_params[3].input_modes[1].input_type == "bytes"
    assert timed_whitelist.creation_params[4].param_type == "select"
    assert timed_whitelist.creation_params[4].options == ["lab-sentry", "backup-sentry"]
    assert timed_whitelist.runtime_args is not None
    assert timed_whitelist.runtime_args[0].label == "Preimage"
    assert timed_whitelist.runtime_args[0].required is True
    assert timed_whitelist.runtime_args[0].byte_length == 32


def test_status_fixture_maps_metadata():
    data = fixture("status_response_ready.json")
    identity = StatusResponse(**data)

    assert identity.identity_id == "default"
    assert identity.node_role == "signer"
    assert identity.state == "unlocked"
    assert identity.signer_locked is False
    assert identity.ready_for_signing is True
    assert identity.key_count == 37
    assert identity.keyset_revision == 4
    assert identity.approval_wait_seconds == 60


def test_cancel_response_fixture_maps_state():
    data = fixture("cancel_sign_response_success.json")
    result = CancelSignResponse(**data)

    assert result.success is True
    assert result.state == "canceled"


def test_list_keys_maps_template_warning_fields():
    client = make_client()
    resp = mock_response(200, {
        "count": 1,
        "keys": [
            {
                "address": "ADDR1",
                "public_key_hex": "abcd",
                    "key_type": "aplane.timed-whitelist.v1",
                "template_provenance_status": "conflict",
                "template_provenance_note": "template fingerprint differs",
            }
        ],
    })

    with patch.object(client.session, "get", return_value=resp):
        keys = client.list_keys(refresh=True)

    assert keys[0].template_status == "conflict"
    assert keys[0].template_warning == "template fingerprint differs"
    assert keys[0].template_provenance_status == "conflict"
    assert keys[0].template_provenance_note == "template fingerprint differs"


def test_list_keys_maps_component_and_guarded_metadata():
    client = make_client()
    with patch.object(client.session, "get", return_value=mock_response(200, fixture("keys_response_component.json"))):
        component = client.list_keys(refresh=True)[0]
    assert component.key_type == "aplane.sentry-ed25519.v1"
    assert component.is_component_key is True
    assert component.is_spending_account is False

    with patch.object(client.session, "get", return_value=mock_response(200, fixture("keys_response_guarded.json"))):
        guarded = client.list_keys(refresh=True)[0]
    assert guarded.key_type == "aplane.falcon1024-sentry-ed25519.v1"
    assert guarded.parameters is not None
    assert guarded.parameters["sentry_public_key"]


def test_plan_group_returns_wire_mutation_report():
    client = make_client()
    resp = mock_response(200, fixture("group_plan_response_mutated.json"))
    txn = MagicMock()
    txn.sender = "SENDERADDR0000000000000000000000000000000000000000000"

    with patch("aplanesdk.signer.encoding.msgpack_encode", return_value="AQ=="):
        with patch.object(client.session, "post", return_value=resp):
            plan = client.plan_group(
                [txn],
                auth_addresses=["AUTHADDR00000000000000000000000000000000000000000000000"],
            )

    assert plan["transactions"] == ["545801", "545802", "545803"]
    assert plan["mutations"]["dummies_added"] == 1
    assert plan["mutations"]["group_id_changed"] is True
    assert plan["mutations"]["fees_modified"] == [0, 2]
    assert plan["mutations"]["total_fees_delta"] == 1000
    assert plan["mutations"]["original_count"] == 2
    assert plan["mutations"]["final_count"] == 3
    assert plan["mutations"]["foreign_count"] == 1


def test_simulate_requests_maps_wire_response():
    client = make_client()
    resp = mock_response(200, fixture("group_simulate_response_mutated.json"))

    with patch.object(client.session, "post", return_value=resp):
        simulation = client.simulate_requests([
            {
                "txn_bytes_hex": "545801",
                "auth_address": "AUTHADDR00000000000000000000000000000000000000000000000",
            },
        ])

    assert simulation.tx_ids == ["SIMTXID1", "SIMTXID2", "SIMTXID3"]
    assert simulation.transactions == ["545801", "545802", "545803"]
    assert simulation.mutations["dummies_added"] == 1
    assert simulation.mutations["group_id_changed"] is True
    assert simulation.mutations["fees_modified"] == [0, 2]
    assert simulation.mutations["foreign_count"] == 1
    assert simulation.failed is True
    assert "Group size: 3" in simulation.output


def test_generate_key_maps_admin_generate_response():
    client = make_client()
    resp = mock_response(200, fixture("admin_generate_response_generic.json"))

    with patch.object(client.session, "post", return_value=resp):
        generated = client.generate_key("aplane.timed-whitelist.v1", {"unlock_round": "123456"})

    assert generated.address == "GENERATEDADDR0000000000000000000000000000000000000000000"
    assert generated.key_type == "aplane.timed-whitelist.v1"
    assert generated.parameters is not None
    assert generated.parameters["unlock_round"] == "123456"


def test_generate_key_maps_component_response():
    client = make_client()
    resp = mock_response(200, fixture("admin_generate_response_component.json"))

    with patch.object(client.session, "post", return_value=resp):
        generated = client.generate_key("aplane.sentry-ed25519.v1")

    assert generated.address == "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
    assert generated.public_key_hex == "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    assert generated.key_type == "aplane.sentry-ed25519.v1"
    assert generated.is_component_key is True
    assert generated.is_spending_account is False


def test_sentry_dtos_round_trip_fixtures():
    component_req = ComponentSignRequest(**fixture("component_sign_request_sentry.json"))
    assert component_req.role == "sentry"
    component_resp_data = fixture("component_sign_response_sentry.json")
    component_resp = ComponentSignResponse(
        request_id=component_resp_data["request_id"],
        component_key=component_resp_data["component_key"],
        signatures=component_resp_data["signatures"],
    )
    assert component_resp.signatures[0]["signature_scheme"] == "aplane.sentry-ed25519.v1"

    assembly_req = GuardedAssemblyRequest(**fixture("guarded_assembly_request_mixed.json"))
    assert assembly_req.group_bytes_hex[0].startswith("5458")
    assembly_resp = GuardedAssemblyResponse(**fixture("guarded_assembly_response.json"))
    assert len(assembly_resp.signed_group) == 2

    sync_req = AdminSyncSentryReferencesRequest(**fixture("admin_sync_sentries_request.json"))
    assert sync_req.candidates[0]["component_key"]
    sync_resp = AdminSyncSentryReferencesResponse(**fixture("admin_sync_sentries_response.json"))
    assert sync_resp.records[0]["source"] == "client_discovery"
