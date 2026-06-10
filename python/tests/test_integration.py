# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Live signer integration tests for the Python SDK."""

import base64
import os
import time
from pathlib import Path

import pytest
import yaml
from algosdk import encoding, transaction

from aplanesdk.algokit import ApsignerAccount
from aplanesdk.signer import encode_transaction
from aplanesdk.signer import SignerClient


def _integration_enabled() -> bool:
    return os.environ.get("APLANE_SDK_INTEGRATION") == "1"


def _live_signer_client() -> tuple[SignerClient, str]:
    base_url = os.environ.get("APLANE_SDK_SIGNER_URL", "").rstrip("/")
    if not base_url:
        port = _live_signer_port()
        base_url = f"http://127.0.0.1:{port}"

    token = _live_signer_token()
    key_type = os.environ.get("APLANE_SDK_KEY_TYPE") or "ed25519"
    return SignerClient(base_url, token), key_type


def _live_signer_port() -> int:
    data_dir = os.environ.get("APSIGNER_DATA")
    if not data_dir:
        raise AssertionError("APLANE_SDK_SIGNER_URL or APSIGNER_DATA must be set")

    with open(Path(data_dir) / "config.yaml", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}
    port = int((config.get("endpoint") or {}).get("signer_port") or 0)
    if port == 0:
        raise AssertionError("endpoint.signer_port not set in signer config")
    return port


def _live_signer_token() -> str:
    token = os.environ.get("APLANE_SDK_TOKEN", "").strip()
    if token:
        return token

    candidates = [os.environ.get("APLANE_SDK_TOKEN_FILE", "")]
    if client_data := os.environ.get("APCLIENT_DATA"):
        candidates.append(str(Path(client_data) / "aplane.token"))
    if signer_data := os.environ.get("APSIGNER_DATA"):
        candidates.append(str(Path(signer_data) / "identities" / "default" / "aplane.token"))

    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if not path.exists():
            continue
        token = path.read_text(encoding="utf-8").strip()
        if token:
            return token

    raise AssertionError(
        "APLANE_SDK_TOKEN, APLANE_SDK_TOKEN_FILE, APCLIENT_DATA, or APSIGNER_DATA must provide a token"
    )


@pytest.mark.skipif(not _integration_enabled(), reason="set APLANE_SDK_INTEGRATION=1")
def test_live_signer_client_workflow():
    client, key_type = _live_signer_client()
    address = ""
    cleanup = False
    try:
        assert client.health() is True

        before = client.get_status()
        assert before.ready_for_signing is True
        assert before.signer_locked is False

        key_types = client.list_key_types()
        assert any(item.key_type == key_type for item in key_types)

        generated = client.generate_key(key_type, {})
        address = generated.address
        cleanup = True
        assert address

        after_generate = _wait_for_keyset_revision(client, before.keyset_revision, "generate")

        keys = client.list_keys(refresh=True)
        assert any(key.address == address for key in keys)

        signed = client.sign_transaction(_self_payment_txn(address), auth_address=address)
        assert base64.b64decode(signed)

        if key_type == "ed25519":
            account = ApsignerAccount(
                client,
                address,
                auth_address=address,
                encode_transaction=_adapter_encode_transaction,
            )
            signed_blobs = account.signer([_self_payment_txn(address)], [0])
            assert len(signed_blobs) == 1
            assert _decode_signed_blob(signed_blobs[0])

        client.delete_key(address)
        cleanup = False

        _wait_for_keyset_revision(client, after_generate.keyset_revision, "delete")

        keys = client.list_keys(refresh=True)
        assert all(key.address != address for key in keys)
    finally:
        if cleanup and address:
            try:
                client.delete_key(address)
            except Exception:
                pass
        client.close()


def _self_payment_txn(address: str) -> transaction.PaymentTxn:
    params = transaction.SuggestedParams(
        fee=1000,
        first=1,
        last=1000,
        gh="SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",
        gen="testnet-v1.0",
        flat_fee=True,
    )
    return transaction.PaymentTxn(sender=address, sp=params, receiver=address, amt=0)


def _adapter_encode_transaction(txn: transaction.Transaction) -> bytes:
    txn_bytes_hex, _ = encode_transaction(txn)
    return bytes.fromhex(txn_bytes_hex)


def _decode_signed_blob(blob: bytes) -> dict:
    return encoding.msgpack.unpackb(blob, raw=False)


def _wait_for_keyset_revision(client: SignerClient, previous: int, action: str):
    deadline = time.time() + 5
    last = None
    last_error = None
    while time.time() < deadline:
        try:
            last = client.get_status()
            if last.keyset_revision > previous:
                return last
        except Exception as exc:
            last_error = exc
        time.sleep(0.1)

    if last_error is not None:
        raise AssertionError(f"get identity after {action}: {last_error}") from last_error
    if last is None:
        raise AssertionError(f"identity was unavailable after {action}")
    raise AssertionError(
        f"keyset revision did not advance after {action}: "
        f"before={previous} after={last.keyset_revision}"
    )
