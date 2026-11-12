# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Live signer integration tests for the Python SDK."""

import base64
import os
import time
from pathlib import Path

import pytest
import yaml
from algosdk import encoding, kmd, transaction
from algosdk.error import AlgodHTTPError
from algosdk.v2client import algod

from aplanesdk.signer import SignerClient, _verify_signed_transaction_matches_canonical


def _integration_enabled() -> bool:
    return os.environ.get("APLANE_SDK_INTEGRATION") == "1"


def _live_signer_client() -> SignerClient:
    if host := os.environ.get("APLANE_SDK_SSH_HOST", "").strip():
        client = SignerClient.connect_ssh(
            host,
            _required_ssh_env("APLANE_SDK_SSH_KEY_PATH"),
            ssh_port=_required_ssh_port("APLANE_SDK_SSH_PORT"),
            known_hosts_path=_required_ssh_env("APLANE_SDK_KNOWN_HOSTS_PATH"),
        )
        return client

    base_url = os.environ.get("APLANE_SDK_SIGNER_URL", "").rstrip("/")
    if not base_url:
        port = _live_signer_port()
        base_url = f"http://127.0.0.1:{port}"
    # A base URL names a caller-owned tunnel; the loopback REST port of a
    # signer answers only /health.
    return SignerClient(base_url)


def _required_ssh_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise AssertionError(f"{name} must be set when APLANE_SDK_SSH_HOST is set")
    return value


def _required_ssh_port(name: str) -> int:
    value = _required_ssh_env(name)
    try:
        port = int(value)
    except ValueError as exc:
        raise AssertionError(f"{name} must be a valid TCP port, got {value!r}") from exc
    if port < 1 or port > 65535:
        raise AssertionError(f"{name} must be a valid TCP port, got {value!r}")
    return port


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


@pytest.mark.skipif(not _integration_enabled(), reason="set APLANE_SDK_INTEGRATION=1")
def test_live_signer_ed25519_workflow():
    key_type = "ed25519"
    client = _live_signer_client()
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
        assert signed and all(type(entry) is bytes and entry for entry in signed)

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


@pytest.mark.skipif(not _integration_enabled(), reason="set APLANE_SDK_INTEGRATION=1")
def test_live_signer_native_falcon_signing():
    key_type = "falcon1024"
    client = _live_signer_client()
    address = ""
    cleanup = False
    try:
        key_types = client.list_key_types()
        assert any(item.key_type == key_type for item in key_types)

        before = client.get_status()
        generated = client.generate_key(key_type, {})
        address = generated.address
        cleanup = True
        assert address

        after_generate = _wait_for_keyset_revision(
            client, before.keyset_revision, "native Falcon generate"
        )
        signed = client.sign_transaction(_self_payment_txn(address), auth_address=address)
        _assert_native_falcon_envelope(signed[0])

        client.delete_key(address)
        cleanup = False
        _wait_for_keyset_revision(client, after_generate.keyset_revision, "native Falcon delete")
    finally:
        if cleanup and address:
            try:
                client.delete_key(address)
            except Exception:
                pass
        client.close()


@pytest.mark.skipif(not _integration_enabled(), reason="set APLANE_SDK_INTEGRATION=1")
def test_live_signer_logicsig_account_signing():
    """A LogicSig account's real response passes the SDK's checks.

    The signer raises the fee, appends resource dummies and groups them, and
    signs with the account's program. The SDK verifies all of that, so this
    is the live check that its rules accept what the signer really returns.
    """
    key_type = "aplane.falcon1024.v1"
    client = _live_signer_client()
    address = ""
    try:
        if not any(item.key_type == key_type for item in client.list_key_types()):
            pytest.skip(f"the signer does not offer {key_type}")
        before = client.get_status()
        address = client.generate_key(key_type, {"rekey_authority": "spending_key"}).address
        assert address
        _wait_for_keyset_revision(client, before.keyset_revision, "LogicSig generate")

        single = client.sign_transaction(_self_payment_txn(address), auth_address=address)
        assert len(single) > 1, "a Falcon LogicSig account needs resource dummies"
        first = _decode_signed_blob(single[0])
        assert first.get("lsig", {}).get("l"), "the position is not signed by a LogicSig"

        pair = client.sign_transactions(
            [_self_payment_txn(address), _self_payment_txn(address, note=b"second")],
            [address, address],
        )
        assert len(pair) > 2
    finally:
        if address:
            try:
                client.delete_key(address)
            except Exception:
                pass
        client.close()


@pytest.mark.skipif(not _integration_enabled(), reason="set APLANE_SDK_INTEGRATION=1")
def test_live_native_falcon_signature_verifies_on_localnet():
    """A real native Falcon signature survives the SDK and the network accepts it.

    The signing test above checks only the envelope's shape. Here the node
    verifies the signature: simulation runs with empty signatures disallowed,
    a tampered copy must fail, and the untouched transaction must confirm.
    """
    if not _localnet_available():
        pytest.skip("needs a LocalNet algod and KMD (ALGOD_URL, APLANE_LOCALNET_KMD_URL)")
    algod_client = algod.AlgodClient(
        os.environ.get("ALGOD_TOKEN", ""), os.environ["ALGOD_URL"].strip()
    )
    client = _live_signer_client()
    address = ""
    try:
        before = client.get_status()
        address = client.generate_key("falcon1024", {}).address
        assert address
        _wait_for_keyset_revision(client, before.keyset_revision, "native Falcon generate")
        _fund_from_localnet_kmd(algod_client, address, 500_000)

        prepared = client.prepare_payment(algod_client, sender=address, receiver=address, amount=0)
        result = client.simulate_prepared_transaction(algod_client, prepared)
        assert not result.failed, _simulation_failure(result.response)
        assert len(result.signed_group) == 1

        signed_bytes = result.signed_group[0]
        _assert_native_falcon_envelope(signed_bytes)

        # The check the cosigned flow runs on every assembled transaction,
        # against canonical bytes taken from the wire and not from the SDK's
        # own decoding of them.
        envelope = _decode_signed_blob(signed_bytes)
        canonical = b"TX" + encoding.msgpack.packb(envelope["txn"], use_bin_type=True)
        _verify_signed_transaction_matches_canonical(
            "native Falcon transaction", 0, signed_bytes.hex(), canonical.hex()
        )
        assert result.transactions[0] == canonical.hex()

        tampered = _decode_signed_blob(signed_bytes)
        signature = bytearray(tampered["pqsig"]["sig"])
        signature[len(signature) // 2] ^= 0x01
        tampered["pqsig"]["sig"] = bytes(signature)
        rejection = _raw_simulation_rejection(
            algod_client, encoding.msgpack.packb(tampered, use_bin_type=True)
        )
        assert (
            "signature" in rejection
        ), f"the node did not reject a tampered native Falcon signature: {rejection[-200:]!r}"

        tx_id = algod_client.send_raw_transaction(base64.b64encode(signed_bytes).decode())
        assert tx_id == result.tx_ids[0]
        transaction.wait_for_confirmation(algod_client, tx_id, 10)
    finally:
        if address:
            try:
                client.delete_key(address)
            except Exception:
                pass
        client.close()


LIVE_ROTATING_KEY_TYPE = "aplane.rotating-triple-wotsc.v1"

# The rotating families the live test runs, each with a limit, in seconds, on
# its whole run. SLH-DSA signs slowly.
LIVE_ROTATING_FAMILIES = [
    ("aplane.rotating-triple-wotsc.v1", 5 * 60),
    ("aplane.rotating-triple-xmss.v1", 5 * 60),
    ("aplane.rotating-triple-slhdsa.v1", 20 * 60),
]


@pytest.mark.skipif(not _integration_enabled(), reason="set APLANE_SDK_INTEGRATION=1")
@pytest.mark.parametrize(
    "key_type,limit", LIVE_ROTATING_FAMILIES, ids=[key_type for key_type, _ in LIVE_ROTATING_FAMILIES]
)
def test_live_rotating_send_on_localnet(key_type, limit):
    """A rotating account of each family the signer has enabled spends
    through send_payment on a real node, twice in a row. The second spend is
    the one that shows the flow works after stage 0: the account's authorizer
    is then a stage address the signer does not list, and the unsigned
    simulation has to accept it. A family the signer does not list is skipped
    by name."""
    if not _localnet_available():
        pytest.skip("needs a LocalNet algod and KMD (ALGOD_URL, APLANE_LOCALNET_KMD_URL)")
    algod_client = algod.AlgodClient(
        os.environ.get("ALGOD_TOKEN", ""), os.environ["ALGOD_URL"].strip()
    )
    deadline = time.monotonic() + limit

    def remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise AssertionError(f"{key_type}: the family's {limit} second limit passed")
        return left

    client = _live_signer_client()
    account = ""
    try:
        if not any(item.key_type == key_type for item in client.list_key_types()):
            pytest.skip(
                f"key type {key_type} is not enabled at the signer "
                f"(apadmin keytype enable {key_type})"
            )
        genesis_hash = algod_client.suggested_params().gh
        before = client.get_status()
        account = client.generate_key(key_type, {"network": genesis_hash}).address
        assert account
        _wait_for_keyset_revision(client, before.keyset_revision, "rotating generate")
        _fund_from_localnet_kmd(algod_client, account, 2_000_000)

        receiver = account  # a self-payment moves nothing and still rotates
        last_target = 0
        last_rekey_to = ""
        for spend in range(2):
            result = client.send_payment(
                algod_client, sender=account, receiver=receiver, amount=0, timeout=remaining()
            )
            details = result.rotating
            assert result.flow == "rotating1" and details is not None, result
            assert result.outcome == "confirmed" and result.confirmed_round > 0, result
            assert (details.stage, details.target) == (spend, spend + 1), details
            if spend > 0:
                assert details.stage == last_target
                assert details.rekey_to != last_rekey_to
            # The chain agrees with what the SDK bound: the account is now
            # authorized by the address the signer reported.
            info = algod_client.account_info(account)
            assert info.get("auth-addr") == details.rekey_to
            last_target, last_rekey_to = details.target, details.rekey_to

        if key_type != LIVE_ROTATING_KEY_TYPE:
            return

        # A third spend, one step at a time, as a caller managing submission
        # itself would do it.
        payment = client.prepare_payment(algod_client, sender=account, receiver=account, amount=0)
        prepared = client.prepare_rotating(payment.transaction, timeout=remaining())
        simulation = client.simulate_prepared_rotating(algod_client, prepared)
        assert not simulation.failed, _simulation_failure(simulation.response)
        signed = client.sign_prepared_rotating(prepared, timeout=remaining())
        assert signed.stage == last_target
        submitted = client.submit_signed_group(algod_client, signed.signed_group)
        assert submitted.outcome == "confirmed" and submitted.tx_ids[0] == signed.txid
        last_target = signed.target

        # The steps on their own: prepare and simulate use no key.
        payment = client.prepare_payment(algod_client, sender=account, receiver=account, amount=0)
        assert payment.auth_address == account, "want the rotating account itself"
        prepared = client.prepare_rotating(payment.transaction, timeout=remaining())
        assert prepared.stage == last_target
        simulation = client.simulate_prepared_rotating(algod_client, prepared)
        assert not simulation.failed, _simulation_failure(simulation.response)
    finally:
        if account:
            try:
                client.delete_key(account)
            except Exception:
                pass
        client.close()


@pytest.mark.skipif(not _integration_enabled(), reason="set APLANE_SDK_INTEGRATION=1")
def test_live_send_transactions_on_localnet():
    """A payment built with algosdk's own constructor goes out through
    send_transactions and confirms, and the object passed is not changed."""
    if not _localnet_available():
        pytest.skip("needs a LocalNet algod and KMD (ALGOD_URL, APLANE_LOCALNET_KMD_URL)")
    algod_client = algod.AlgodClient(
        os.environ.get("ALGOD_TOKEN", ""), os.environ["ALGOD_URL"].strip()
    )
    client = _live_signer_client()
    address = ""
    try:
        before = client.get_status()
        address = client.generate_key("ed25519", {}).address
        assert address
        _wait_for_keyset_revision(client, before.keyset_revision, "ed25519 generate")
        _fund_from_localnet_kmd(algod_client, address, 500_000)

        payment = transaction.PaymentTxn(
            sender=address, sp=algod_client.suggested_params(), receiver=address, amt=0
        )
        encoded = encoding.msgpack_encode(payment)
        result = client.send_transactions(algod_client, [payment])

        assert result.outcome == "confirmed" and result.confirmed_round > 0, result
        assert all(type(entry) is bytes for entry in result.signed_group)
        assert encoding.msgpack_encode(payment) == encoded
        info = algod_client.pending_transaction_info(result.tx_ids[0])
        assert info.get("confirmed-round") == result.confirmed_round
    finally:
        if address:
            try:
                client.delete_key(address)
            except Exception:
                pass
        client.close()


@pytest.mark.skipif(not _integration_enabled(), reason="set APLANE_SDK_INTEGRATION=1")
def test_endpoint_registry_connection():
    data_dir = os.environ.get("APCLIENT_DATA")
    if not data_dir or not (Path(data_dir) / "endpoints.yaml").exists():
        pytest.skip("APCLIENT_DATA/endpoints.yaml is not available")
    with SignerClient.from_env(data_dir=data_dir) as client:
        assert client.health() is True


def _self_payment_txn(address: str, note: bytes = b"") -> transaction.PaymentTxn:
    genesis_hash = os.environ.get(
        "APLANE_INTEGRATION_GENESIS_HASH",
        "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",
    ).strip()
    genesis_id = os.environ.get("APLANE_INTEGRATION_GENESIS_ID", "testnet-v1.0").strip()
    params = transaction.SuggestedParams(
        fee=1000,
        first=1,
        last=1000,
        gh=genesis_hash,
        gen=genesis_id,
        flat_fee=True,
    )
    return transaction.PaymentTxn(
        sender=address, sp=params, receiver=address, amt=0, note=note or None
    )


def _localnet_available() -> bool:
    return bool(
        os.environ.get("ALGOD_URL", "").strip()
        and os.environ.get("APLANE_LOCALNET_KMD_URL", "").strip()
    )


def _fund_from_localnet_kmd(algod_client, receiver: str, amount: int) -> None:
    """Pay `receiver` from the richest account in the LocalNet KMD wallet."""
    kmd_client = kmd.KMDClient(
        os.environ.get("APLANE_LOCALNET_TOKEN", ""),
        os.environ["APLANE_LOCALNET_KMD_URL"].strip(),
    )
    wallet_name = os.environ.get("APLANE_LOCALNET_WALLET", "unencrypted-default-wallet")
    password = os.environ.get("APLANE_LOCALNET_WALLET_PASSWORD", "")
    wallet_id = next((w["id"] for w in kmd_client.list_wallets() if w["name"] == wallet_name), None)
    assert wallet_id, f"LocalNet KMD has no wallet named {wallet_name!r}"
    handle = kmd_client.init_wallet_handle(wallet_id, password)
    try:
        funder = max(
            kmd_client.list_keys(handle),
            key=lambda item: algod_client.account_info(item)["amount"],
        )
        payment = transaction.PaymentTxn(
            sender=funder,
            sp=algod_client.suggested_params(),
            receiver=receiver,
            amt=amount,
        )
        signed = kmd_client.sign_transaction(handle, password, payment)
    finally:
        kmd_client.release_wallet_handle(handle)
    tx_id = algod_client.send_transaction(signed)
    transaction.wait_for_confirmation(algod_client, tx_id, 10)


def _simulation_failure(response: dict) -> str:
    groups = response.get("txn-groups") or []
    return groups[0].get("failure-message", "") if groups else ""


def _raw_simulation_rejection(algod_client, signed_bytes: bytes) -> str:
    """Why the node refuses these signed bytes; empty when it accepts them."""
    signed = encoding.msgpack_decode(base64.b64encode(signed_bytes).decode())
    try:
        response = algod_client.simulate_raw_transactions([signed])
    except AlgodHTTPError as exc:
        return str(exc) or "rejected"
    return _simulation_failure(response)


def _decode_signed_blob(blob: bytes) -> dict:
    return encoding.msgpack.unpackb(blob, raw=False)


def _assert_native_falcon_envelope(blob: bytes) -> None:
    envelope = _decode_signed_blob(blob)
    pq_signature = envelope.get("pqsig")
    assert isinstance(pq_signature, dict)
    assert pq_signature.get("sch") == b"f1"
    assert pq_signature.get("pk")
    assert pq_signature.get("sig")


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
