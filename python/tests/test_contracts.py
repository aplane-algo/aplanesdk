# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Signer API contract fixture tests for the Python SDK."""

import json
import base64
from pathlib import Path
from unittest.mock import MagicMock, patch

from aplanesdk.signer import CancelSignResponse, SignerClient, StatusResponse


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "contracts" / "signerapi"
EXPECTED_FIXTURE_NAMES = [
    "admin_delete_response_success.json",
    "admin_generate_request_generic.json",
    "admin_generate_response_generic.json",
    "cancel_sign_request.json",
    "cancel_sign_response_not_found.json",
    "cancel_sign_response_success.json",
    "error_response.json",
    "group_plan_response_mutated.json",
    "group_sign_request_mixed.json",
    "group_sign_response_mutated.json",
    "health_response_ready.json",
    "keys_response_generic.json",
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
    assert generic.key_type == "aplane.timelock.v1"
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

    timelock = key_types[1]
    assert timelock.key_type == "aplane.timelock.v1"
    assert timelock.display_name == "Timelock"
    assert timelock.requires_logicsig is True
    assert timelock.mnemonic_import is False
    assert timelock.creation_params is not None
    assert timelock.creation_params[1].param_type == "address[]"
    assert timelock.creation_params[1].min_items == 1
    assert timelock.creation_params[1].max_items == 8
    assert timelock.creation_params[2].min == 1
    assert timelock.creation_params[2].max == 999999999
    assert timelock.creation_params[3].max_length == 32
    assert timelock.creation_params[3].input_modes is not None
    assert timelock.creation_params[3].input_modes[1].name == "sha256"
    assert timelock.creation_params[3].input_modes[1].transform == "sha256"
    assert timelock.creation_params[3].input_modes[1].byte_length == 32
    assert timelock.creation_params[3].input_modes[1].input_type == "bytes"
    assert timelock.runtime_args is not None
    assert timelock.runtime_args[0].label == "Preimage"
    assert timelock.runtime_args[0].required is True
    assert timelock.runtime_args[0].byte_length == 32


def test_status_fixture_maps_metadata():
    data = fixture("status_response_ready.json")
    identity = StatusResponse(**data)

    assert identity.identity_id == "default"
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
                "key_type": "aplane.timelock.v1",
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


def test_generate_key_maps_admin_generate_response():
    client = make_client()
    resp = mock_response(200, fixture("admin_generate_response_generic.json"))

    with patch.object(client.session, "post", return_value=resp):
        generated = client.generate_key("aplane.timelock.v1", {"unlock_round": "123456"})

    assert generated.address == "GENERATEDADDR0000000000000000000000000000000000000000000"
    assert generated.key_type == "aplane.timelock.v1"
    assert generated.parameters is not None
    assert generated.parameters["unlock_round"] == "123456"
