# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Signer API contract fixture tests for the Python SDK."""

import json
import base64
import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

from aplanesdk.signer import (
    AdminSyncSentryReferencesRequest,
    AdminSyncSentryReferencesResponse,
    CancelSignResponse,
    ComponentSignRequest,
    ComponentSignResponse,
    ERR_CODE_BAD_REQUEST,
    ERR_CODE_CACHE_REFRESH,
    ERR_CODE_FORBIDDEN,
    ERR_CODE_INTERNAL,
    ERR_CODE_BOUNDED_ADMIN_REQUIRED,
    ERR_CODE_INVALID_PASSPHRASE,
    ERR_CODE_LOCKED,
    ERR_CODE_NOT_FOUND,
    ERR_CODE_UNAUTHORIZED,
    ERR_CODE_UNAVAILABLE,
    GuardedAssemblyRequest,
    GuardedAssemblyTarget,
    GuardedSimulateRequest,
    GuardedSimulateTarget,
    GuardedSimulateResponse,
    GuardedAssemblyResponse,
    SignerClient,
    StatusResponse,
)


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "contracts" / "signerapi"
CONTRACT_SCHEMA_VERSION = 1
HASH_MANIFEST_NAME = "SHA256SUMS"
CONTRACT_METADATA_FILES = {
    "fixture_manifest.json",
    "error_codes.json",
    "error_code_classifications.json",
}


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
    return sorted(
        path.name
        for path in FIXTURE_DIR.glob("*.json")
        if path.name not in CONTRACT_METADATA_FILES
    )


def expected_fixture_names() -> list[str]:
    manifest = fixture("fixture_manifest.json")
    assert manifest["schema_version"] == CONTRACT_SCHEMA_VERSION
    names = sorted(manifest["fixtures"])
    assert len(names) == len(set(names))
    assert all(name.endswith(".json") for name in names)
    assert all(name not in CONTRACT_METADATA_FILES for name in names)
    return names


def sdk_error_codes() -> list[str]:
    return [
        ERR_CODE_BAD_REQUEST,
        ERR_CODE_UNAUTHORIZED,
        ERR_CODE_FORBIDDEN,
        ERR_CODE_LOCKED,
        ERR_CODE_NOT_FOUND,
        ERR_CODE_INVALID_PASSPHRASE,
        ERR_CODE_UNAVAILABLE,
        ERR_CODE_CACHE_REFRESH,
        ERR_CODE_INTERNAL,
        ERR_CODE_BOUNDED_ADMIN_REQUIRED,
    ]


def hash_manifest() -> dict[str, str]:
    hashes: dict[str, str] = {}
    with open(FIXTURE_DIR / HASH_MANIFEST_NAME, "r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            assert len(fields) == 2, f"{HASH_MANIFEST_NAME}:{line_no}"
            digest, name = fields
            assert len(digest) == 64, f"{HASH_MANIFEST_NAME}:{line_no}"
            int(digest, 16)
            assert name != HASH_MANIFEST_NAME
            assert Path(name).name == name
            assert name not in hashes
            hashes[name] = digest
    return hashes


def computed_hashes() -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in FIXTURE_DIR.iterdir():
        if path.is_file() and path.name != HASH_MANIFEST_NAME:
            hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def test_accounts_for_every_committed_fixture():
    expected = expected_fixture_names()
    assert committed_fixture_names() == expected
    for name in expected:
        assert isinstance(fixture(name), dict)


def test_error_code_fixture_matches_sdk_constants():
    data = fixture("error_codes.json")
    assert data["schema_version"] == CONTRACT_SCHEMA_VERSION
    assert sorted(data["codes"]) == sorted(sdk_error_codes())


def test_error_code_classifications_cover_sdk_constants():
    data = fixture("error_code_classifications.json")
    assert data["schema_version"] == CONTRACT_SCHEMA_VERSION
    classifications = data["classifications"]
    assert sorted(classifications.keys()) == sorted(sdk_error_codes())
    assert all(str(value).strip() for value in classifications.values())


def test_hash_manifest_matches_contract_files():
    assert computed_hashes() == hash_manifest()


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
    assert generic.key_type == "aplane.timed-allowlist.v1"
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

    timed_allowlist = key_types[1]
    assert timed_allowlist.key_type == "aplane.timed-allowlist.v1"
    assert timed_allowlist.display_name == "Timed Allowlist"
    assert timed_allowlist.requires_logicsig is True
    assert timed_allowlist.mnemonic_import is False
    assert timed_allowlist.creation_params is not None
    assert timed_allowlist.creation_params[1].param_type == "address[]"
    assert timed_allowlist.creation_params[1].min_items == 1
    assert timed_allowlist.creation_params[1].max_items == 8
    assert timed_allowlist.creation_params[2].min == 1
    assert timed_allowlist.creation_params[2].max == 999999999
    assert timed_allowlist.creation_params[3].max_length == 32
    assert timed_allowlist.creation_params[3].input_modes is not None
    assert timed_allowlist.creation_params[3].input_modes[1].name == "sha256"
    assert timed_allowlist.creation_params[3].input_modes[1].transform == "sha256"
    assert timed_allowlist.creation_params[3].input_modes[1].byte_length == 32
    assert timed_allowlist.creation_params[3].input_modes[1].input_type == "bytes"
    assert timed_allowlist.creation_params[4].param_type == "select"
    assert timed_allowlist.creation_params[4].options == ["lab-sentry", "backup-sentry"]
    assert timed_allowlist.runtime_args is not None
    assert timed_allowlist.runtime_args[0].label == "Preimage"
    assert timed_allowlist.runtime_args[0].required is True
    assert timed_allowlist.runtime_args[0].byte_length == 32


def test_status_fixture_maps_metadata():
    data = fixture("status_response_ready.json")
    identity = StatusResponse(**data)

    assert identity.identity_id == "default"
    assert identity.node_role == "signer"
    assert identity.protocol_version is not None
    assert identity.protocol_version.major == 1
    assert identity.protocol_version.minor == 0
    assert identity.build_version.startswith("v0.30.0 ")
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
                    "key_type": "aplane.timed-allowlist.v1",
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
        generated = client.generate_key("aplane.timed-allowlist.v1", {"unlock_round": "123456"})

    assert generated.address == "GENERATEDADDR0000000000000000000000000000000000000000000"
    assert generated.key_type == "aplane.timed-allowlist.v1"
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


def test_guarded_simulate_dtos_round_trip_fixtures():
    simulate_req = GuardedSimulateRequest(**fixture("guarded_simulate_request_mixed.json"))
    assert len(simulate_req.requests) == 3
    assert simulate_req.requests[1]["auth_address"].startswith("AUTHADDRESS")
    simulate_target = GuardedSimulateTarget(**simulate_req.targets[0])
    assert simulate_target.guarded_account.startswith("LOGICSIGACCOUNT")
    assert simulate_target.sentry_signature
    assert simulate_target.runtime_args == ["aa01", "bb02"]
    assert simulate_req.passthrough[0]["target_index"] == 2

    simulate_resp = GuardedSimulateResponse(**fixture("guarded_simulate_response.json"))
    assert len(simulate_resp.tx_ids) == 3
    assert len(simulate_resp.transactions) == 3
    assert "Simulation FAILED" in simulate_resp.output
    assert simulate_resp.failed is True


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
    assembly_target = GuardedAssemblyTarget(**assembly_req.targets[0])
    assert assembly_target.user_signature
    assert assembly_target.sentry_signature
    assert assembly_target.runtime_args == ["aa01", "bb02"]
    assembly_resp = GuardedAssemblyResponse(**fixture("guarded_assembly_response.json"))
    assert len(assembly_resp.signed_group) == 2

    sync_req = AdminSyncSentryReferencesRequest(**fixture("admin_sync_sentries_request.json"))
    assert sync_req.candidates[0]["component_key"]
    sync_resp = AdminSyncSentryReferencesResponse(**fixture("admin_sync_sentries_response.json"))
    assert sync_resp.records[0]["source"] == "client_discovery"


def test_bounded_inventory_projects_layer3_policy():
    client = make_client()
    with patch.object(client.session, "get", return_value=mock_response(200, fixture("keys_response_bounded.json"))):
        key = client.list_keys(refresh=True)[0]
    assert key.signing_flow == "bounded1"
    assert key.lsig_size == 6592
    assert key.bounded_authorization.layer3_policy == "fixed_allowlist"
    assert key.bounded_authorization.admin_key_id
    assert key.bounded_authorization.post_signing_lsig_size == 7872
    assert key.bounded_authorization.spend_effects == ["pay", "axfer", "asset_opt_in"]
    assert key.bounded_authorization.admin_operations[0].policy_gate == "none"
    assert key.bounded_authorization.argument_layout[1].source == "admin"

    with patch.object(client.session, "get", return_value=mock_response(200, fixture("keytypes_response_bounded.json"))):
        key_type = client.list_key_types()[0]
    assert key_type.bounded_authorization.layer3_policy == "fixed_allowlist"
    assert key_type.bounded_authorization.admin_key_id == ""
