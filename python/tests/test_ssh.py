# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""SSH tunnel and enrollment behavior that needs no live signer."""

import socket
import threading
from pathlib import Path

import paramiko
import pytest

from aplanesdk.signer import (
    SSH_ENROLLMENT_USERNAME,
    SSH_USERNAME,
    EnrollmentError,
    SignerError,
    _SSHTunnel,
    _ssh_fingerprint_sha256,
    request_enrollment,
)


def test_ssh_usernames_match_the_signer():
    assert SSH_USERNAME == "aplane"
    assert SSH_ENROLLMENT_USERNAME == "request-enrollment"


def test_fingerprint_matches_openssh_format():
    key = paramiko.ECDSAKey.generate()
    fingerprint = _ssh_fingerprint_sha256(key)
    assert fingerprint.startswith("SHA256:")
    assert "=" not in fingerprint
    assert fingerprint == key.fingerprint


def _tunnel(known_hosts: Path, trust_on_first_use: bool) -> _SSHTunnel:
    return _SSHTunnel(
        ssh_host="signer.example",
        ssh_port=1127,
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


def _start_stalled_peer():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    accepted = threading.Event()
    peer_closed = threading.Event()

    def stall_peer():
        conn, _ = listener.accept()
        accepted.set()
        conn.settimeout(2)
        try:
            while conn.recv(1024):
                pass
            peer_closed.set()
        except OSError:
            pass
        finally:
            conn.close()

    thread = threading.Thread(target=stall_peer, daemon=True)
    thread.start()
    return listener, accepted, peer_closed, thread


def test_ssh_setup_timeout_closes_stalled_peer(tmp_path):
    listener, accepted, peer_closed, thread = _start_stalled_peer()
    key_path = tmp_path / "id_ecdsa"
    paramiko.ECDSAKey.generate().write_private_key_file(str(key_path))
    tunnel = _SSHTunnel(
        ssh_host="127.0.0.1",
        ssh_port=listener.getsockname()[1],
        ssh_pkey_path=str(key_path),
        remote_host="127.0.0.1",
        remote_port=11270,
        local_port=0,
        known_hosts_path=str(tmp_path / "known_hosts"),
        setup_timeout=0.05,
    )

    try:
        with pytest.raises(SignerError, match="SSH setup timed out"):
            tunnel.start()
        assert accepted.wait(1)
        assert peer_closed.wait(1)
    finally:
        listener.close()
        thread.join(timeout=1)


def test_enrollment_setup_timeout_closes_stalled_peer(tmp_path):
    listener, accepted, peer_closed, thread = _start_stalled_peer()
    key_path = tmp_path / "id_ecdsa"
    paramiko.ECDSAKey.generate().write_private_key_file(str(key_path))

    try:
        with pytest.raises(EnrollmentError, match="SSH setup timed out"):
            request_enrollment(
                "127.0.0.1",
                str(key_path),
                ssh_port=listener.getsockname()[1],
                known_hosts_path=str(tmp_path / "known_hosts"),
                setup_timeout=0.05,
            )
        assert accepted.wait(1)
        assert peer_closed.wait(1)
    finally:
        listener.close()
        thread.join(timeout=1)


def _start_key_exchange_peer():
    """Serve SSH key exchange so the client reaches its host-key policy."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host_key = paramiko.RSAKey.generate(1024)
    done = threading.Event()

    def serve():
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        transport = paramiko.Transport(conn)
        transport.add_server_key(host_key)
        try:
            transport.start_server(server=paramiko.ServerInterface())
            done.wait(5)
        except Exception:
            pass
        finally:
            transport.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return listener, done, thread


def test_enrollment_host_key_prompt_does_not_consume_setup_deadline(tmp_path, monkeypatch):
    listener, done, thread = _start_key_exchange_peer()
    key_path = tmp_path / "id_ecdsa"
    paramiko.ECDSAKey.generate().write_private_key_file(str(key_path))
    setup_timeout = 0.5

    def slow_operator(_prompt):
        # The operator takes longer than the whole setup budget to answer.
        threading.Event().wait(setup_timeout * 2)
        return "n"

    monkeypatch.setattr("builtins.input", slow_operator)
    try:
        with pytest.raises(EnrollmentError) as excinfo:
            request_enrollment(
                "127.0.0.1",
                str(key_path),
                ssh_port=listener.getsockname()[1],
                known_hosts_path=str(tmp_path / "known_hosts"),
                setup_timeout=setup_timeout,
            )
        assert "Host key rejected by user" in str(excinfo.value)
        assert "timed out" not in str(excinfo.value)
    finally:
        done.set()
        listener.close()
        thread.join(timeout=2)
