# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""SSH tunnel and enrollment behavior that needs no live signer."""

import http.server
import inspect
import socket
import threading
import time
from pathlib import Path

import paramiko
import pytest
import requests
import urllib3.exceptions

import aplanesdk.signer as signer_module
from aplanesdk.signer import (
    SSH_ENROLLMENT_USERNAME,
    SSH_USERNAME,
    EnrollmentError,
    SignerClient,
    SignerError,
    _SSHConfigError,
    _SSHTunnel,
    _ssh_fingerprint_sha256,
    request_enrollment,
)


def test_ssh_usernames_match_the_signer():
    assert SSH_USERNAME == "aplane"
    assert SSH_ENROLLMENT_USERNAME == "enroll"


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


def test_a_host_key_that_cannot_be_saved_is_a_configuration_error(tmp_path):
    # The known_hosts directory cannot be made: a file stands where it goes.
    blocker = tmp_path / "not_a_directory"
    blocker.write_text("")
    known_hosts = blocker / "known_hosts"
    with pytest.raises(_SSHConfigError) as excinfo:
        _tunnel(known_hosts, True)._verify_host_key(paramiko.RSAKey.generate(1024))
    assert str(excinfo.value).startswith(f"cannot save the host key to {known_hosts}: ")
    assert isinstance(excinfo.value.__cause__, OSError)


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


# -----------------------------------------------------------------------------
# Requests over SSH channels
# -----------------------------------------------------------------------------


class _ChannelHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Serves HTTP/1.1 on one SSH channel, as the signer's REST listener
    serves each channel its SSH server hands over."""

    protocol_version = "HTTP/1.1"

    def _record(self) -> None:
        self.server.requests.append(
            (self.command, self.path, self.headers.get("Host"), self.request.get_id())
        )

    def _answer(self, body: bytes) -> None:
        self._record()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/close":
            # The server closes the connection after this response, and its
            # body arrives after its head.
            self._record()
            body = b'{"closing":true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            time.sleep(0.2)
            self.wfile.write(body)
            self.close_connection = True
            return
        self._answer(b'{"status":"ok"}')

    def do_POST(self):
        self._answer(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

    def log_message(self, format, *args):
        pass


class _SignerSSHInterface(paramiko.ServerInterface):
    def __init__(self, signer: "_FakeSSHSigner"):
        self._signer = signer

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_publickey(self, username, key):
        if username == SSH_USERNAME and key.asbytes() == self._signer.client_key.asbytes():
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        # A test holds a channel's opening by clearing release_channels.
        self._signer.release_channels.wait(5)
        self._signer.destinations.append(destination)
        if destination[0] != "127.0.0.1":
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        return paramiko.OPEN_SUCCEEDED


class _FakeSSHSigner:
    """An SSH server that authenticates one client key and serves HTTP on
    each direct-tcpip channel it accepts, as the signer's SSH server forwards
    each channel to its own REST listener. No HTTP listener is involved."""

    def __init__(self, tmp_path: Path):
        self.client_key = paramiko.ECDSAKey.generate()
        self.key_path = tmp_path / "id_ecdsa"
        self.client_key.write_private_key_file(str(self.key_path))
        self.known_hosts = tmp_path / "known_hosts"
        self._host_key = paramiko.ECDSAKey.generate()
        # The destination of each channel the client asked for, and each
        # request served: (method, path, Host header, channel id).
        self.destinations: list = []
        self.requests: list = []
        self.channels: list = []
        self.transports: list = []
        self.release_channels = threading.Event()
        self.release_channels.set()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            transport = paramiko.Transport(conn)
            transport.add_server_key(self._host_key)
            self.transports.append(transport)
            try:
                transport.start_server(server=_SignerSSHInterface(self))
            except Exception:
                transport.close()
                continue
            threading.Thread(target=self._accept_channels, args=(transport,), daemon=True).start()

    def _accept_channels(self, transport):
        while transport.is_active():
            channel = transport.accept(0.1)
            if channel is None:
                continue
            self.channels.append(channel)
            threading.Thread(target=self._serve_http, args=(channel,), daemon=True).start()

    def _serve_http(self, channel):
        try:
            _ChannelHTTPHandler(channel, ("127.0.0.1", 0), self)
        except Exception:
            pass
        finally:
            try:
                channel.close()
            except Exception:
                pass  # the SSH connection is already gone

    def connect(self) -> SignerClient:
        return SignerClient.connect_ssh(
            "127.0.0.1",
            str(self.key_path),
            ssh_port=self.port,
            known_hosts_path=str(self.known_hosts),
            trust_on_first_use=True,
            ssh_setup_timeout=5,
        )

    def close(self):
        self.release_channels.set()
        self._listener.close()
        for transport in self.transports:
            transport.close()


@pytest.fixture
def ssh_signer(tmp_path):
    signer = _FakeSSHSigner(tmp_path)
    yield signer
    signer.close()


def _wait_for(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def test_connect_ssh_takes_no_local_port():
    assert "local_port" not in inspect.signature(SignerClient.connect_ssh).parameters
    assert not hasattr(signer_module, "_find_free_port")


def test_connect_ssh_opens_no_listener_and_sends_requests_over_ssh_channels(
    ssh_signer, monkeypatch
):
    # Every socket the server needs exists already; from here on nothing in
    # this process may bind or listen.
    calls = []
    real_bind, real_listen = socket.socket.bind, socket.socket.listen

    def bind(sock, *args):
        calls.append(("bind", args))
        return real_bind(sock, *args)

    def listen(sock, *args):
        calls.append(("listen", args))
        return real_listen(sock, *args)

    monkeypatch.setattr(socket.socket, "bind", bind)
    monkeypatch.setattr(socket.socket, "listen", listen)

    with ssh_signer.connect() as client:
        assert client.base_url == "http://signer.aplane.invalid"
        assert client.health()
        answer = client.session.post(f"{client.base_url}/echo", json={"n": 1}, timeout=5)
        assert answer.json() == {"n": 1}
        # The tunnel keeps no listener or local port.
        assert not {"_server_socket", "local_bind_port"} & vars(client._tunnel).keys()

    assert calls == []
    # One channel, named for the nominal loopback REST port, carried the
    # connect-time health check and both requests: the connection is reused.
    assert ssh_signer.destinations == [("127.0.0.1", 11270)]
    assert [request[:3] for request in ssh_signer.requests] == [
        ("GET", "/health", "signer.aplane.invalid"),
        ("GET", "/health", "signer.aplane.invalid"),
        ("POST", "/echo", "signer.aplane.invalid"),
    ]
    assert len({request[3] for request in ssh_signer.requests}) == 1


def test_closing_the_client_closes_every_channel_and_the_ssh_transport(ssh_signer):
    client = ssh_signer.connect()
    tunnel = client._tunnel
    transport = tunnel._transport
    # A channel in use alongside the pooled one.
    in_use = tunnel.open_channel(5)
    channels = list(tunnel._channels)
    assert len(channels) == 2 and in_use in channels

    client.close()

    assert all(channel.closed for channel in channels)
    assert not transport.is_active()
    assert not tunnel.active
    assert client._tunnel is None
    assert _wait_for(lambda: all(channel.closed for channel in ssh_signer.channels))
    assert _wait_for(lambda: not any(t.is_active() for t in ssh_signer.transports))
    with pytest.raises(ConnectionError, match="the SSH tunnel is closed"):
        tunnel.open_channel(5)


def test_an_idle_connection_is_not_reused_after_the_idle_timeout(ssh_signer, monkeypatch):
    with ssh_signer.connect() as client:
        assert client.health()
        assert len(ssh_signer.destinations) == 1
        first = ssh_signer.channels[0]

        monkeypatch.setattr(signer_module, "_TUNNEL_IDLE_TIMEOUT", 0.0)
        assert client.health()
        # The idle connection was closed, not reused, and a new channel
        # carried the request.
        assert len(ssh_signer.destinations) == 2
        assert len({request[3] for request in ssh_signer.requests}) == 2
        assert _wait_for(lambda: first.closed)


def test_the_idle_timeout_is_shorter_than_the_signers():
    # The signer's HTTP server closes an idle connection after 120 seconds.
    assert 0 < signer_module._TUNNEL_IDLE_TIMEOUT < 120


def test_tunnel_requests_ignore_a_proxy_setting(ssh_signer, monkeypatch):
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    with ssh_signer.connect() as client:
        assert client.health()
    assert [request[1] for request in ssh_signer.requests] == ["/health", "/health"]


def test_a_stopped_tunnel_fails_requests_as_connection_errors(ssh_signer):
    client = ssh_signer.connect()
    try:
        client._tunnel.stop()
        with pytest.raises(requests.ConnectionError):
            client.session.get(f"{client.base_url}/health", timeout=5)
        assert not client.health()
    finally:
        client.close()


def test_a_channel_not_open_within_the_connect_timeout_is_a_connect_timeout(ssh_signer):
    client = ssh_signer.connect()
    try:
        # The pooled connection is gone, and the next channel is held open
        # longer than the request's connect timeout.
        client.session.close()
        ssh_signer.release_channels.clear()
        with pytest.raises(requests.ConnectTimeout):
            client.session.get(f"{client.base_url}/health", timeout=(0.2, 5))
    finally:
        ssh_signer.release_channels.set()
        client.close()


def test_a_channel_connection_refuses_another_host():
    opened = []
    conn = signer_module._ChannelHTTPConnection(
        host="signer.example.com", port=80, open_signer_channel=opened.append
    )
    with pytest.raises(urllib3.exceptions.NewConnectionError, match="signer.example.com"):
        conn.connect()
    assert opened == []


def test_a_response_the_signer_closes_the_connection_after_is_read_in_full(ssh_signer):
    with ssh_signer.connect() as client:
        answer = client.session.get(f"{client.base_url}/close", timeout=5)
        assert answer.json() == {"closing": True}
        # The next request opens a new channel.
        assert client.health()
    assert len(ssh_signer.destinations) == 2


def test_a_dropped_ssh_connection_fails_requests_as_connection_errors(ssh_signer):
    client = ssh_signer.connect()
    try:
        for transport in ssh_signer.transports:
            transport.close()
        assert _wait_for(lambda: not client._tunnel.active)
        with pytest.raises(requests.ConnectionError):
            client.session.get(f"{client.base_url}/health", timeout=5)
        assert not client.health()
    finally:
        client.close()


class _FailingChannel:
    """A channel whose SSH connection failed under it."""

    def __init__(self):
        self.closed = False

    def sendall(self, data):
        raise EOFError()

    def recv(self, size):
        raise paramiko.SSHException("Key-exchange timed out waiting for key negotiation")

    def close(self):
        self.closed = True
        raise EOFError()


def test_a_channel_socket_reports_ssh_failures_as_connection_resets():
    sock = signer_module._ChannelSocket(_FailingChannel())
    with pytest.raises(ConnectionResetError):
        sock.sendall(b"GET / HTTP/1.1\r\n")
    with pytest.raises(ConnectionResetError):
        sock.recv(1)
    with pytest.raises(ConnectionResetError):
        sock.makefile("rb").read(1)
    # Closing a failed channel does not raise.
    sock.close()


def test_a_channel_socket_closes_its_channel_once_its_files_are_closed():
    channel = _FailingChannel()
    sock = signer_module._ChannelSocket(channel)
    first, second = sock.makefile("rb"), sock.makefile("rb")
    sock.close()
    assert not channel.closed
    first.close()
    first.close()
    assert not channel.closed
    second.close()
    assert channel.closed
    with pytest.raises(ValueError):
        sock.makefile("wb")
