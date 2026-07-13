# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

import json
from pathlib import Path
import threading

import pytest
import paramiko

from aplanesdk._ssh_tokenproof import (
    DOMAIN,
    TokenProofClient,
    compute_proof,
    decode_bytes,
    encode_bytes,
    encode_transcript,
    parse_message,
)
from aplanesdk.signer import (
    SignerError,
    _SSHTunnel,
    _continue_keyboard_interactive_auth,
)


def _vector():
    path = Path(__file__).parents[2] / "contracts" / "sshtunnel" / "token_proof_v1.json"
    return json.loads(path.read_text())


def test_token_proof_contract_vector():
    vector = _vector()
    decode = lambda value: decode_bytes(value, 32)
    transcript = encode_transcript(
        vector["identity_id"],
        decode(vector["host_key_hash"]),
        decode(vector["client_nonce"]),
        decode(vector["server_nonce"]),
    )
    assert transcript.hex() == vector["transcript_hex"]
    assert (
        encode_bytes(compute_proof(vector["token"], "server", transcript)) == vector["server_proof"]
    )

    proof = TokenProofClient(vector["token"])
    proof._host_hash = decode(vector["host_key_hash"])
    proof._client_nonce = decode(vector["client_nonce"])
    proof._round = 1
    answer = proof.challenge(
        DOMAIN,
        "",
        [(vector["server_proof_question"], False)],
    )
    assert answer == [vector["client_proof_answer"]]
    assert proof.server_verified


def test_token_proof_rejects_duplicate_and_padded_fields():
    with pytest.raises(ValueError, match="duplicate"):
        parse_message('{"version":1,"version":1,"step":"client_nonce"}', {"version", "step"})
    with pytest.raises(ValueError, match="canonical"):
        decode_bytes("ERERERERERERERERERERERERERERERERERERERERERERE=", 32)


def test_token_proof_requires_verified_host_key():
    proof = TokenProofClient("token")
    with pytest.raises(ValueError, match="challenge shape"):
        proof.challenge(DOMAIN, "", [('{"version":1,"step":"client_nonce"}', False)])


def test_token_proof_clear_releases_authentication_state():
    proof = TokenProofClient("token")
    proof._host_hash = b"h" * 32
    proof._client_nonce = b"n" * 32
    proof._round = 2
    proof._verified = True

    proof.clear()

    assert proof._token == ""
    assert proof._host_hash == b""
    assert proof._client_nonce == b""
    assert proof._round == -1
    assert proof.server_verified is False


def _tunnel(known_hosts: Path, trust_on_first_use: bool) -> _SSHTunnel:
    return _SSHTunnel(
        ssh_host="signer.example",
        ssh_port=1127,
        token="token",
        ssh_pkey_path="unused",
        remote_host="127.0.0.1",
        remote_port=11270,
        local_port=12345,
        known_hosts_path=str(known_hosts),
        trust_on_first_use=trust_on_first_use,
    )


def test_host_key_verification_rejects_unknown_by_default(tmp_path):
    key = paramiko.RSAKey.generate(1024)
    with pytest.raises(SignerError, match="Unknown SSH host key"):
        _tunnel(tmp_path / "known_hosts", False)._verify_host_key(key)


def test_host_key_verification_persists_tofu_and_rejects_mismatch(tmp_path):
    known_hosts = tmp_path / ".ssh" / "known_hosts"
    key = paramiko.RSAKey.generate(1024)
    _tunnel(known_hosts, True)._verify_host_key(key)
    assert known_hosts.stat().st_mode & 0o777 == 0o600
    _tunnel(known_hosts, False)._verify_host_key(key)
    with pytest.raises(SignerError, match="mismatch"):
        _tunnel(known_hosts, False)._verify_host_key(paramiko.RSAKey.generate(1024))


def test_partial_auth_continuation_sends_only_userauth_request():
    class AuthHandler:
        def wait_for_response(self, event):
            assert event is self.auth_event
            return []

    class Transport:
        def __init__(self):
            self.auth_handler = AuthHandler()
            self.lock = threading.Lock()
            self.saved_exception = RuntimeError("stale partial result")
            self.sent = []

        def _send_message(self, message):
            self.sent.append(bytes(message))

    transport = Transport()
    callback = lambda _title, _instructions, _prompts: ["answer"]
    assert _continue_keyboard_interactive_auth(transport, "default", callback) == []
    assert transport.saved_exception is None
    assert transport.auth_handler.interactive_handler is callback

    request = paramiko.Message(transport.sent[0])
    assert request.get_byte() == paramiko.common.cMSG_USERAUTH_REQUEST
    assert request.get_text() == "default"
    assert request.get_text() == "ssh-connection"
    assert request.get_text() == "keyboard-interactive"
    assert request.get_text() == ""
    assert request.get_text() == ""
    assert request.get_remainder() == b""
