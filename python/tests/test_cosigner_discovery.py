# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Cosigner discovery from endpoints.yaml: EndpointCosignerResolver, and the
cosigned flow's use of it and of every resolver.

Each cosigner endpoint is a local HTTP fake. SignerClient.connect_ssh is
replaced so that "connecting" to an endpoint's ssh:// host either returns a
client for its fake or raises what the SSH layer would.
"""

import threading
import time

import pytest

from aplanesdk import (
    KEY_TYPE_WITNESS_FALCON1024,
    AuthenticationError,
    ClientEndpointConfig,
    ClientEndpointRegistry,
    CosignerDiscoveryError,
    EndpointCosignerResolver,
    SignerError,
    SignerClient,
    SignerUnavailableError,
)
from aplanesdk import signer as signer_module
from aplanesdk import witness_key_id
from aplanesdk.signer import SendTimeoutError, _SSHConfigError, _SSHHostKeyMismatchError
from tests import fake_signer
from tests.send_fakes import HTTPFake, reply, truncated
from tests.test_send import CosignedFixture, fakes  # noqa: F401 (fixture)

WITNESS = KEY_TYPE_WITNESS_FALCON1024
PUBLIC_A = bytes([0xA1]) * 40
PUBLIC_B = bytes([0xB2]) * 40
# The cosigned fixture's account names cosigner public key aabb.
FIXTURE_PUBLIC = bytes.fromhex("aabb")


def witness_record(public_key, key_type=WITNESS, address=None, public_key_hex=None):
    return {
        "address": address if address is not None else witness_key_id(key_type, public_key),
        "key_type": key_type,
        "public_key_hex": public_key_hex if public_key_hex is not None else public_key.hex(),
        "is_witness_key": True,
    }


def testwitness_key_id_vectors():
    assert (
        witness_key_id(WITNESS, bytes(1793))
        == "ROGAFDACF7ASC3EMZRWNKVM73NXHO4P6O4EB7ZXWER37SM63BMFQ"
    )
    assert (
        witness_key_id(WITNESS, bytes(i % 251 for i in range(1793)))
        == "HJPRU4QEGLKF7RD6FYHQSG4SFAADHULJYVCVFPSCMIYZLAYW5MNA"
    )
    assert len(witness_key_id(WITNESS, b"\x01")) == 52


class Endpoint:
    """One cosigner endpoint's fake: what /keys answers, how often it was
    asked, and, instead of a listing, what connecting to it raises."""

    def __init__(self, keys=None, answer=None, connect_error=None, delay=0.0):
        self.keys = list(keys or [])
        self.answer = answer
        self.connect_error = connect_error
        self.delay = delay
        self.key_reads = 0
        self.components = []
        self.http = HTTPFake(self.app)

    def app(self, method, path, body):
        if path == "/keys":
            self.key_reads += 1
            if self.delay:
                time.sleep(self.delay)
            if self.answer is not None:
                return self.answer
            return reply(200, {"count": len(self.keys), "keys": self.keys})
        if path == "/sign/component":
            import json

            request = json.loads(body)
            self.components.append(request)
            return reply(
                200,
                {
                    "request_id": request["request_id"],
                    "components": [
                        {
                            "kind": "cosigner",
                            "target_index": target["target_index"],
                            "signature": "cosigner-sig",
                            "signature_scheme": WITNESS,
                        }
                        for target in request["targets"]
                    ],
                },
            )
        raise AssertionError(f"unexpected cosigner path {path}")


class Network:
    """The cosigner endpoints, by alias, behind a replaced connect_ssh."""

    def __init__(self, monkeypatch, endpoints, extra=None):
        self.endpoints = endpoints
        self.connects = []
        self.clients = []
        self.closed = []
        self.active = 0
        self.most_active = 0
        self.lock = threading.Lock()
        network = self

        def connect_ssh(cls, host, ssh_key_path, ssh_port=1127, **options):
            alias = host.split(".")[0]
            with network.lock:
                network.connects.append((alias, ssh_key_path, ssh_port, options))
                network.active += 1
                network.most_active = max(network.most_active, network.active)
            try:
                endpoint = network.endpoints[alias]
                time.sleep(0.02)
                if endpoint.connect_error is not None:
                    raise endpoint.connect_error
                client = SignerClient(endpoint.http.url, timeout=options.get("timeout"))
                close = client.close

                def closing():
                    network.closed.append(alias)
                    close()

                client.close = closing
                client.alias = alias
                network.clients.append(client)
                return client
            finally:
                with network.lock:
                    network.active -= 1

        monkeypatch.setattr(SignerClient, "connect_ssh", classmethod(connect_ssh))
        configs = {"primary": ClientEndpointConfig(role="signer", url="ssh://primary.example")}
        for alias in endpoints:
            configs[alias] = ClientEndpointConfig(
                role="cosigner",
                url=f"ssh://{alias}.example:2222",
                identity_file=f"/keys/{alias}",
                known_hosts_path=f"/known/{alias}",
            )
        configs.update(extra or {})
        self.registry = ClientEndpointRegistry(default="primary", endpoints=configs)

    def close(self):
        for endpoint in self.endpoints.values():
            endpoint.http.close()

    def resolver(self, **options):
        return EndpointCosignerResolver(registry=self.registry, **options)


@pytest.fixture
def network(monkeypatch):
    made = []

    def build(endpoints, extra=None):
        net = Network(monkeypatch, endpoints, extra)
        made.append(net)
        return net

    yield build
    for net in made:
        net.close()


class TestChoosing:
    def test_exactly_one_endpoint_lists_the_key(self, network):
        net = network(
            {
                "alpha": Endpoint([witness_record(PUBLIC_A)]),
                "beta": Endpoint([witness_record(PUBLIC_B)]),
            }
        )
        with net.resolver() as resolver:
            client, component_key = resolver.resolve(PUBLIC_B.hex(), WITNESS)
        assert client.alias == "beta"
        assert component_key == witness_key_id(WITNESS, PUBLIC_B)
        # Each endpoint was connected with its own identity and known hosts.
        connected = {alias: (key, port, options) for alias, key, port, options in net.connects}
        assert connected["alpha"][0] == "/keys/alpha" and connected["alpha"][1] == 2222
        assert connected["alpha"][2]["known_hosts_path"] == "/known/alpha"
        assert "primary" not in connected

    def test_the_public_key_compares_in_either_case(self, network):
        net = network(
            {
                "alpha": Endpoint([witness_record(PUBLIC_A, public_key_hex=PUBLIC_A.hex().upper())]),
                "beta": Endpoint([witness_record(PUBLIC_B)]),
            }
        )
        with net.resolver() as resolver:
            client, component_key = resolver.resolve(PUBLIC_A.hex(), WITNESS)
            assert client.alias == "alpha"
            assert component_key == witness_key_id(WITNESS, PUBLIC_A)
            client, _ = resolver.resolve(PUBLIC_B.hex().upper(), WITNESS)
            assert client.alias == "beta"

    def test_a_key_type_must_match_too(self, network):
        other = "aplane.witness-other.v1"
        net = network({"alpha": Endpoint([witness_record(PUBLIC_A, key_type=other)])})
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError, match="no endpoint"):
            resolver.resolve(PUBLIC_A.hex(), WITNESS)

    def test_records_that_are_not_witness_keys_do_not_count(self, network):
        record = witness_record(PUBLIC_A)
        net = network(
            {
                "alpha": Endpoint([dict(record, is_witness_key=False)]),
                "beta": Endpoint([dict(record, key_type="")]),
                "gamma": Endpoint([record]),
            }
        )
        with net.resolver() as resolver:
            client, _ = resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert client.alias == "gamma"

    def test_more_than_one_endpoint_is_refused(self, network):
        net = network(
            {
                "zeta": Endpoint([witness_record(PUBLIC_A)]),
                "alpha": Endpoint([witness_record(PUBLIC_A)]),
                "mid": Endpoint([witness_record(PUBLIC_B)]),
            }
        )
        key_id = witness_key_id(WITNESS, PUBLIC_A)
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert str(excinfo.value) == (
            f"cosigner discovery: Witness Key ID {key_id} ({WITNESS}) is listed by endpoints "
            '"alpha", "zeta"; each witness key needs exactly one endpoint'
        )

    def test_none_names_every_endpoint_and_its_state(self, network):
        locked = reply(403, {"error": "signer is locked", "code": "locked"})
        net = network(
            {
                "ok": Endpoint([witness_record(PUBLIC_B)]),
                "down": Endpoint(connect_error=SignerUnavailableError("SSH tunnel failed")),
                "five": Endpoint(answer=reply(503, {"error": "busy", "code": "unavailable"})),
                "locked": Endpoint(answer=locked),
                "noauth": Endpoint(connect_error=AuthenticationError("not enrolled")),
                "forbid": Endpoint(answer=reply(403, {"error": "no", "code": "forbidden"})),
                "badhex": Endpoint([witness_record(PUBLIC_A, public_key_hex="zz")]),
                "badid": Endpoint([witness_record(PUBLIC_A, address="NOTTHEID")]),
                "cut": Endpoint(answer=truncated(b'{"keys": [')),
                "unknown": Endpoint(connect_error=_SSHConfigError("Unknown SSH host key")),
                "missing": Endpoint(answer=reply(404, {"error": "no such path"})),
            }
        )
        key_id = witness_key_id(WITNESS, PUBLIC_A)
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
        # Registry order is not alias order; the message sorts by alias.
        assert str(excinfo.value) == (
            f"cosigner discovery: no endpoint lists Witness Key ID {key_id} ({WITNESS}); "
            'endpoints: "badhex" invalid cosigner metadata, "badid" invalid cosigner metadata, '
            '"cut" invalid cosigner metadata, "down" unreachable, "five" unreachable, '
            '"forbid" authentication failed, "locked" locked, "missing" configuration invalid, '
            '"noauth" authentication failed, "ok" ok, "unknown" configuration invalid'
        )

    def test_more_endpoint_states(self, network):
        net = network(
            {
                "unauth": Endpoint(answer=reply(401, {"error": "no", "code": "unauthorized"})),
                # A 401 is the identity refused, even with the locked code.
                "unauthlocked": Endpoint(
                    answer=reply(401, {"error": "signer is locked", "code": "locked"})
                ),
                "spelled": Endpoint(
                    [{"address": _respelled(fake_signer.test_address(7)), "key_type": "ed25519"}]
                ),
                "lockedfive": Endpoint(
                    answer=reply(503, {"error": "signer is locked", "code": "locked"})
                ),
                "teapot": Endpoint(answer=reply(418, "no")),
                "badurl": Endpoint(),
            },
            extra={"badurl": ClientEndpointConfig(role="cosigner", url="ssh://:99999")},
        )
        key_id = witness_key_id(WITNESS, PUBLIC_A)
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert str(excinfo.value) == (
            f"cosigner discovery: no endpoint lists Witness Key ID {key_id} ({WITNESS}); "
            'endpoints: "badurl" configuration invalid, "lockedfive" locked, '
            '"spelled" invalid cosigner metadata, "teapot" configuration invalid, '
            '"unauth" authentication failed, "unauthlocked" authentication failed'
        )

    def test_one_bad_record_makes_the_whole_listing_invalid(self, network):
        # The needed key is listed correctly; another record is not, so the
        # endpoint is not used at all.
        net = network(
            {
                "mixed": Endpoint(
                    [witness_record(PUBLIC_A), witness_record(PUBLIC_B, address="WRONG")]
                )
            }
        )
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert str(excinfo.value).endswith('endpoints: "mixed" invalid cosigner metadata')

    def test_failed_endpoints_that_were_not_needed_are_not_reported(self, network):
        net = network(
            {
                "down": Endpoint(connect_error=SignerUnavailableError("SSH tunnel failed")),
                "ok": Endpoint([witness_record(PUBLIC_A)]),
            }
        )
        with net.resolver() as resolver:
            client, _ = resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert client.alias == "ok"

    def test_no_cosigner_endpoint_configured(self, network):
        net = network({})
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert str(excinfo.value) == (
            "cosigner discovery: endpoints.yaml lists no cosigner endpoint"
        )
        assert net.connects == []

    def test_a_host_key_mismatch_anywhere_aborts_discovery(self, network):
        mismatch = _SSHHostKeyMismatchError("SSH host key mismatch for rogue.example:2222")
        net = network(
            {
                "good": Endpoint([witness_record(PUBLIC_A)]),
                "rogue": Endpoint(connect_error=mismatch),
            }
        )
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert str(excinfo.value) == (
            'cosigner discovery: endpoint "rogue": SSH host key mismatch for rogue.example:2222'
        )
        # The good endpoint's connection was closed with the aborted sweep.
        assert "good" in net.closed

    @pytest.mark.parametrize("public_key", ["xyz", "abc", ""])
    def test_a_required_public_key_that_is_not_hex_is_refused(self, network, public_key):
        net = network({"alpha": Endpoint([witness_record(PUBLIC_A)])})
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(public_key, WITNESS)
        assert str(excinfo.value) == (
            f'cosigner discovery: the account\'s cosigner public key "{public_key}" is not '
            "valid hex"
        )
        assert net.connects == []

    def test_a_required_key_type_is_needed(self, network):
        net = network({"alpha": Endpoint([witness_record(PUBLIC_A)])})
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_A.hex(), "")
        assert str(excinfo.value) == "cosigner discovery: the account names no cosigner key type"
        assert net.connects == []

    def test_an_empty_listed_public_key_makes_the_listing_invalid(self, network):
        net = network(
            {
                # Its address is even the Witness Key ID of an empty key.
                "empty": Endpoint([witness_record(b"")]),
                "ok": Endpoint([witness_record(PUBLIC_A)]),
            }
        )
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_B.hex(), WITNESS)
        assert str(excinfo.value).endswith(
            'endpoints: "empty" invalid cosigner metadata, "ok" ok'
        )

    def test_a_key_listed_twice_by_one_endpoint_is_one_listing(self, network):
        record = witness_record(PUBLIC_A)
        net = network({"alpha": Endpoint([record, dict(record)])})
        with net.resolver() as resolver:
            client, _ = resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert client.alias == "alpha"

    def test_the_errors_are_sdk_errors(self):
        assert issubclass(CosignerDiscoveryError, SignerError)


class _Tunnel:
    """Stands in for a client's SSH tunnel: up or not."""

    def __init__(self, active):
        self.is_up = active
        self.stopped = False

    @property
    def active(self):
        return self.is_up and not self.stopped

    def stop(self):
        self.stopped = True


def test_a_tunnel_is_active_while_its_ssh_transport_is():
    tunnel = signer_module._SSHTunnel("h", 22, "/k", "127.0.0.1", 1, 0)
    assert tunnel.active is False

    class Transport:
        up = True

        def is_active(self):
            return self.up

        def close(self):
            self.up = False

    tunnel._transport = Transport()
    tunnel._running = True
    assert tunnel.active is True
    tunnel._transport.up = False
    assert tunnel.active is False
    tunnel._transport.up = True
    tunnel.stop()
    assert tunnel.active is False


def test_a_client_is_open_until_closed():
    client = SignerClient("http://127.0.0.1:9")
    assert signer_module._client_connection_open(client)
    client._tunnel = _Tunnel(active=False)
    assert not signer_module._client_connection_open(client)
    client._tunnel = _Tunnel(active=True)
    assert signer_module._client_connection_open(client)
    client.close()
    assert not signer_module._client_connection_open(client)


def _respelled(address):
    from tests.send_fakes import alternate_spelling

    return alternate_spelling(address)


class TestLimits:
    def test_at_most_four_endpoints_at_once(self, network):
        net = network({f"e{index}": Endpoint([], delay=0.1) for index in range(9)})
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError):
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert len(net.connects) == 9
        assert net.most_active <= 4

    def test_an_endpoint_that_takes_too_long_is_unreachable(self, network, monkeypatch):
        monkeypatch.setattr(signer_module, "_COSIGNER_ENDPOINT_TIMEOUT", 0.3)
        net = network(
            {
                "slow": Endpoint([witness_record(PUBLIC_A)], delay=1.5),
                "fast": Endpoint([witness_record(PUBLIC_B)]),
            }
        )
        started = time.monotonic()
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert time.monotonic() - started < 1.4
        assert str(excinfo.value).endswith('endpoints: "fast" ok, "slow" unreachable')

    def test_endpoints_the_sweep_had_no_time_for_are_unreachable(self, network, monkeypatch):
        monkeypatch.setattr(signer_module, "_COSIGNER_SWEEP_TIMEOUT", 0.3)
        monkeypatch.setattr(signer_module, "_COSIGNER_SWEEP_WORKERS", 1)
        net = network(
            {
                "a1": Endpoint([], delay=0.5),
                "a2": Endpoint([witness_record(PUBLIC_A)]),
            }
        )
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert str(excinfo.value).endswith('endpoints: "a1" unreachable, "a2" unreachable')
        assert [alias for alias, *_ in net.connects] == ["a1"]

    def test_more_than_twelve_cosigner_endpoints_are_refused(self, network):
        net = network({f"e{index:02}": Endpoint([]) for index in range(13)})
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert str(excinfo.value) == (
            "cosigner discovery: endpoints.yaml lists 13 cosigner endpoints; the limit is 12"
        )
        assert net.connects == []

    def test_the_calls_time_limit_ends_discovery(self, network):
        net = network({"slow": Endpoint([witness_record(PUBLIC_A)], delay=1.0)})
        with net.resolver() as resolver:
            with signer_module._time_limit(0.3):
                with pytest.raises(CosignerDiscoveryError) as excinfo:
                    resolver.resolve(PUBLIC_A.hex(), WITNESS)
            # It is the call's timeout as well as a discovery error, and
            # nothing from that sweep is kept.
            assert isinstance(excinfo.value, SendTimeoutError)
            assert str(excinfo.value).startswith(
                "cosigner discovery: the time limit of 0.3 seconds passed"
            )
            assert resolver._probes is None
            assert "slow" in net.closed or net.clients == []

    def test_a_time_limit_already_passed_connects_to_nothing(self, network):
        net = network({"alpha": Endpoint([witness_record(PUBLIC_A)])})
        with net.resolver() as resolver, signer_module._time_limit(0.01):
            time.sleep(0.05)
            with pytest.raises(SendTimeoutError, match="^cosigner discovery: "):
                resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert net.connects == []


class TestCache:
    def test_a_kept_sweep_answers_again(self, network):
        alpha = Endpoint([witness_record(PUBLIC_A)])
        net = network({"alpha": alpha})
        with net.resolver() as resolver:
            first = resolver.resolve(PUBLIC_A.hex(), WITNESS)
            second = resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert first[0] is second[0]
        assert alpha.key_reads == 1

    def test_a_miss_makes_one_fresh_sweep(self, network):
        alpha = Endpoint([witness_record(PUBLIC_A)])
        net = network({"alpha": alpha})
        with net.resolver() as resolver:
            first, _ = resolver.resolve(PUBLIC_A.hex(), WITNESS)
            # A key the kept sweep does not hold: one fresh sweep, then the
            # error.
            with pytest.raises(CosignerDiscoveryError, match="no endpoint"):
                resolver.resolve(PUBLIC_B.hex(), WITNESS)
            assert alpha.key_reads == 2 and resolver._sweeps == 2
            # The new key appears: one more sweep finds it.
            alpha.keys.append(witness_record(PUBLIC_B))
            client, _ = resolver.resolve(PUBLIC_B.hex(), WITNESS)
            assert alpha.key_reads == 3 and resolver._sweeps == 3
            # A live connection is read again, not reopened.
            assert client is first
            assert len(net.connects) == 1 and net.closed == []
        assert net.closed == ["alpha"]

    def test_a_fresh_sweep_reconnects_what_failed_and_closes_what_it_drops(self, network):
        alpha = Endpoint([witness_record(PUBLIC_A)])
        beta = Endpoint(connect_error=SignerUnavailableError("SSH tunnel failed"))
        net = network({"alpha": alpha, "beta": beta})
        with net.resolver() as resolver:
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
            # beta comes up and lists the key; alpha's connection stops
            # answering, so the fresh sweep connects to it again.
            beta.connect_error = None
            beta.keys = [witness_record(PUBLIC_B)]
            alpha.answer = reply(500, {"error": "gone"})
            client, _ = resolver.resolve(PUBLIC_B.hex(), WITNESS)
            assert client.alias == "beta"
            connected = [alias for alias, *_ in net.connects]
            assert sorted(connected) == ["alpha", "alpha", "beta", "beta"]
            # The old alpha connection was closed, and so was the new one,
            # which did not answer either.
            assert net.closed == ["alpha", "alpha"]
        assert sorted(net.closed) == ["alpha", "alpha", "beta"]

    def test_a_closed_kept_connection_is_a_miss(self, network):
        alpha = Endpoint([witness_record(PUBLIC_A)])
        net = network({"alpha": alpha})
        with net.resolver() as resolver:
            first, _ = resolver.resolve(PUBLIC_A.hex(), WITNESS)
            first.close()
            # One fresh sweep, which connects again rather than reading
            # through the closed client.
            second, _ = resolver.resolve(PUBLIC_A.hex(), WITNESS)
            assert second is not first and not second._closed
            assert resolver._sweeps == 2 and len(net.connects) == 2
            assert alpha.key_reads == 2
            # The new connection is kept.
            assert resolver.resolve(PUBLIC_A.hex(), WITNESS)[0] is second
            assert resolver._sweeps == 2

    def test_a_kept_connection_whose_ssh_link_is_down_is_a_miss(self, network):
        alpha = Endpoint([witness_record(PUBLIC_A)])
        net = network({"alpha": alpha})
        with net.resolver() as resolver:
            first, _ = resolver.resolve(PUBLIC_A.hex(), WITNESS)
            first._tunnel = _Tunnel(active=True)
            assert resolver.resolve(PUBLIC_A.hex(), WITNESS)[0] is first
            assert resolver._sweeps == 1 and alpha.key_reads == 1
            # The link drops. Seeing so asks the endpoint nothing.
            first._tunnel.is_up = False
            second, _ = resolver.resolve(PUBLIC_A.hex(), WITNESS)
            assert second is not first
            assert resolver._sweeps == 2 and len(net.connects) == 2
            # The dead connection was closed, and was not read again.
            assert net.closed == ["alpha"] and first._closed
            assert alpha.key_reads == 2

    def test_nothing_from_a_mismatched_sweep_is_kept(self, network):
        mismatch = _SSHHostKeyMismatchError("SSH host key mismatch for rogue.example:2222")
        net = network(
            {
                "good": Endpoint([witness_record(PUBLIC_A)]),
                "rogue": Endpoint(connect_error=mismatch),
                "zrogue": Endpoint(connect_error=_SSHHostKeyMismatchError("second mismatch")),
            }
        )
        with net.resolver() as resolver:
            with pytest.raises(CosignerDiscoveryError, match='endpoint "rogue"'):
                resolver.resolve(PUBLIC_A.hex(), WITNESS)
            assert resolver._probes is None
            net.endpoints["rogue"].connect_error = None
            net.endpoints["zrogue"].connect_error = None
            client, _ = resolver.resolve(PUBLIC_A.hex(), WITNESS)
            assert client.alias == "good"
            assert [alias for alias, *_ in net.connects].count("good") == 2

    def test_close_closes_every_connection(self, network):
        net = network(
            {"alpha": Endpoint([witness_record(PUBLIC_A)]), "beta": Endpoint([])}
        )
        resolver = net.resolver()
        resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert net.closed == []
        resolver.close()
        assert sorted(net.closed) == ["alpha", "beta"]
        with pytest.raises(CosignerDiscoveryError, match="closed"):
            resolver.resolve(PUBLIC_A.hex(), WITNESS)

    def test_from_env_keeps_what_the_default_resolver_needs(self, tmp_path, network):
        # A client from a data directory finds cosigners from its registry,
        # connecting with the options it was created with.
        net = network({"primary": Endpoint(), "cosign": Endpoint([witness_record(PUBLIC_A)])})
        (tmp_path / "endpoints.yaml").write_text(
            "schema_version: 2\nendpoints:\n"
            "  primary:\n    role: signer\n    url: ssh://primary.example\n"
            "  cosign:\n    role: cosigner\n    url: ssh://cosign.example:2222\n"
        )
        (tmp_path / ".ssh").mkdir()
        (tmp_path / ".ssh" / "id_ed25519").write_text("key")
        client = SignerClient.from_env(
            data_dir=str(tmp_path), timeout=7, trust_on_first_use=True, ssh_setup_timeout=12.5
        )
        resolver = client._default_cosigner_resolver()
        assert resolver is client._default_cosigner_resolver()
        cosigner, _ = resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert cosigner.alias == "cosign"
        options = [options for alias, _, _, options in net.connects if alias == "cosign"][0]
        assert options["timeout"] == 7
        assert options["trust_on_first_use"] is True
        assert options["ssh_setup_timeout"] == 12.5
        client.close()
        assert "cosign" in net.closed
        assert SignerClient("http://127.0.0.1:1")._default_cosigner_resolver() is None

    def test_it_reads_a_data_directory(self, tmp_path, network):
        net = network({"alpha": Endpoint([witness_record(PUBLIC_A)])})
        (tmp_path / "endpoints.yaml").write_text(
            "schema_version: 2\nendpoints:\n"
            "  primary:\n    role: signer\n    url: ssh://primary.example\n"
            "  alpha:\n    role: cosigner\n    url: ssh://alpha.example:2222\n"
        )
        with EndpointCosignerResolver(str(tmp_path)) as resolver:
            client, _ = resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert client.alias == "alpha"
        assert net.connects[0][1] == str(tmp_path / ".ssh" / "id_ed25519")


# -----------------------------------------------------------------------------
# The cosigned flow
# -----------------------------------------------------------------------------

APPROVAL_PATHS = ("/sign/component", "/sign", "/sign/assemble")


def _from_data_directory(client, registry, **connection):
    """Mark a client as from_env makes it, from the given registry."""
    client._endpoint_registry = registry
    client._cosigner_connection = dict(
        {"timeout": 7, "trust_on_first_use": True, "ssh_setup_timeout": 12.5}, **connection
    )
    return client


def _fixture_cosigner(**options):
    return Endpoint([witness_record(FIXTURE_PUBLIC)], **options)


class TestCosignedFlow:
    def test_a_client_from_a_data_directory_finds_its_cosigner(self, fakes, network):
        fixture = CosignedFixture(fakes)
        cosigner = _fixture_cosigner()
        net = network({"cosign": cosigner, "other": Endpoint([witness_record(PUBLIC_A)])})
        _from_data_directory(fixture.user_client, net.registry)
        result = fixture.send()
        assert result.signed_group
        (request,) = cosigner.components
        assert request["targets"][0]["component_key"] == witness_key_id(WITNESS, FIXTURE_PUBLIC)
        # It connects as the signer client was created.
        options = net.connects[0][3]
        assert options["timeout"] == 7
        assert options["trust_on_first_use"] is True
        assert options["ssh_setup_timeout"] == 12.5
        # The resolver it made is kept on the client and closed with it.
        resolver = fixture.user_client._cosigner_resolver
        assert isinstance(resolver, EndpointCosignerResolver)
        fixture.send()
        assert fixture.user_client._cosigner_resolver is resolver
        assert cosigner.key_reads == 1
        fixture.user_client.close()
        assert sorted(net.closed) == ["cosign", "other"]
        assert fixture.user_client._cosigner_resolver is None

    def test_a_discovery_failure_is_raised_before_any_approval(self, fakes, network):
        fixture = CosignedFixture(fakes)
        net = network({"other": Endpoint([witness_record(PUBLIC_A)])})
        _from_data_directory(fixture.user_client, net.registry)
        with pytest.raises(CosignerDiscoveryError, match="no endpoint lists Witness Key ID"):
            fixture.send()
        assert not any(path in fixture.user.paths for path in APPROVAL_PATHS)

    def test_any_resolver_runs_before_any_approval(self, fakes):
        fixture = CosignedFixture(fakes)
        calls = []

        def resolver(target):
            calls.append(list(fixture.user.paths))
            raise SignerError("no cosigner here")

        with pytest.raises(SignerError, match="no cosigner here"):
            fixture.send(cosigner_resolver=resolver)
        assert len(calls) == 1
        assert not any(path in calls[0] for path in APPROVAL_PATHS)
        assert not any(path in fixture.user.paths for path in APPROVAL_PATHS)

    def test_nothing_configured_fails_before_any_approval(self, fakes):
        fixture = CosignedFixture(fakes)
        with pytest.raises(SignerError, match="cosigner_client or cosigner_resolver is required"):
            fixture.send()
        assert not any(path in fixture.user.paths for path in APPROVAL_PATHS)

    def test_an_explicit_cosigner_wins(self, fakes, network):
        fixture = CosignedFixture(fakes)
        net = network({"cosign": _fixture_cosigner()})
        _from_data_directory(fixture.user_client, net.registry)
        fixture.send(
            cosigner_client=fixture.cosigner_client, cosigner_component_key="COSIGNER_COMPONENT"
        )
        assert net.connects == []
        assert fixture.user_client._cosigner_resolver is None

    def test_a_listed_rekey_needs_no_cosigner(self, fakes, network):
        # The escape hatch works with no cosigner configured, and with every
        # cosigner endpoint down.
        fixture = CosignedFixture(fakes, rekey_path="listed_rekey")
        assert fixture.send().signed_group
        down = Endpoint(connect_error=SignerUnavailableError("SSH tunnel failed"))
        net = network({"cosign": down})
        _from_data_directory(fixture.user_client, net.registry)
        assert fixture.send().signed_group
        assert net.connects == []

    def test_a_rekey_that_needs_its_cosigner_resolves_it_after_the_base(
        self, fakes, network, monkeypatch
    ):
        fixture = CosignedFixture(fakes, rekey_path="spending_rekey")
        cosigner = _fixture_cosigner()
        net = network({"cosign": cosigner})
        _from_data_directory(fixture.user_client, net.registry)
        seen = []
        original = EndpointCosignerResolver.resolve

        def spy(self, public_key, key_type):
            seen.append(list(fixture.user.paths))
            return original(self, public_key, key_type)

        monkeypatch.setattr(EndpointCosignerResolver, "resolve", spy)
        assert fixture.send().signed_group
        assert len(seen) == 1 and "/sign/component" in seen[0]
        assert len(cosigner.components) == 1


def _cosigned_key(address, public_key_hex):
    from aplanesdk import (
        SIGNING_FLOW_COSIGNED1,
        BoundedAuthorizationInfo,
        BoundedCosignerAuthorizationInfo,
        BoundedSignatureArgLayout,
        KeyInfo,
        LogicSigResourceProfile,
        LogicSigResourceUsage,
    )

    return KeyInfo(
        address=address,
        key_type="aplane.falcon1024.v1",
        signing_flow=SIGNING_FLOW_COSIGNED1,
        cosigner_component_key_type=WITNESS,
        logic_sig_resources=LogicSigResourceProfile(spend=LogicSigResourceUsage(5308, 3358, 20000)),
        bounded_authorization=BoundedAuthorizationInfo(
            contract="plain1",
            base_signature_arg_layout=BoundedSignatureArgLayout(count=1, max_sizes=[1280]),
            spend_effects=[],
            max_fee=None,
            rekey="refused",
            runtime_args=[],
            derived_args=[],
            argument_layout=[],
            layer3_policy="",
            cosigner=BoundedCosignerAuthorizationInfo(
                contract="cosigner1", component_key_type=WITNESS, public_key_hex=public_key_hex
            ),
        ),
    )


class TestCosignedOrder:
    """Two cosigned accounts with different cosigners: the cosigners are
    resolved in (key type, public key) order, and asked in the order of
    their first target position."""

    def _run(self, resolver):
        from unittest.mock import MagicMock

        from algosdk import transaction

        from aplanesdk import (
            AssemblyResponse,
            ComponentResponse,
            PreparedGroup,
            PreparedTransaction,
            sign_prepared_cosigned_group,
        )
        from tests.test_send import _signed_group_for

        first = fake_signer.test_address(61)
        second = fake_signer.test_address(62)
        params = transaction.SuggestedParams(
            1000, 1, 100, "A" * 43 + "=", "testnet-v1.0", flat_fee=True
        )
        txns = transaction.assign_group_id(
            [
                transaction.PaymentTxn(first, params, fake_signer.test_address(63), 1),
                transaction.PaymentTxn(second, params, fake_signer.test_address(63), 2),
            ]
        )
        user = SignerClient("http://127.0.0.1:9")
        user.list_keys_if_keyset_changed = MagicMock(
            return_value=[_cosigned_key(first, "bbbb"), _cosigned_key(second, "aaaa")]
        )
        user.plan_requests = MagicMock(
            side_effect=lambda requests: {
                "transactions": [request["txn_bytes_hex"] for request in requests]
            }
        )
        user.request_components = MagicMock(
            return_value=ComponentResponse(
                request_id="base-id",
                components=[
                    {
                        "target_index": index,
                        "kind": "bounded-base",
                        "auth_address": account,
                        "base_signatures": ["base-sig"],
                        "assembly_receipt": "receipt",
                        "signature_scheme": "aplane.falcon1024.v1",
                        "path": "spend",
                    }
                    for index, account in enumerate((first, second))
                ],
            )
        )
        user.request_assemble = MagicMock(
            side_effect=lambda request: AssemblyResponse(
                request_id="assembly-id",
                signed_group=_signed_group_for(request.group_bytes_hex),
            )
        )
        asked = []

        def cosigner(name):
            client = SignerClient(f"http://{name}:9")

            def answer(request):
                asked.append(name)
                return ComponentResponse(
                    request_id=f"{name}-id",
                    components=[
                        {
                            "kind": "cosigner",
                            "target_index": target["target_index"],
                            "signature": "sig",
                            "signature_scheme": WITNESS,
                        }
                        for target in request.targets
                    ],
                )

            client.request_components = MagicMock(side_effect=answer)
            return client

        clients = {"bbbb": cosigner("b"), "aaaa": cosigner("a")}
        resolved = []

        def resolve(target):
            resolved.append(target["cosigner_public_key_hex"])
            return resolver(target, clients)

        prepared = PreparedGroup(
            [
                PreparedTransaction(transaction=txns[0], auth_address=first),
                PreparedTransaction(transaction=txns[1], auth_address=second),
            ]
        )
        result = sign_prepared_cosigned_group(
            user_client=user, prepared_group=prepared, cosigner_resolver=resolve
        )
        return result, resolved, asked

    def test_resolution_and_request_order(self):
        _, resolved, asked = self._run(
            lambda target, clients: (clients[target["cosigner_public_key_hex"]], "KEY")
        )
        assert resolved == ["aaaa", "bbbb"]
        assert asked == ["b", "a"]

    def test_a_resolver_that_returns_no_client(self):
        with pytest.raises(SignerError) as excinfo:
            self._run(
                lambda target, clients: (None, "KEY")
                if target["cosigner_public_key_hex"] == "bbbb"
                else (clients["aaaa"], "KEY")
            )
        assert str(excinfo.value) == (
            "cosigner resolver returned no client for prepared transaction 0"
        )


def test_an_unreadable_identity_file_is_a_configuration_error(tmp_path):
    # Through the real connection code: the key is read before anything is
    # dialed.
    registry = ClientEndpointRegistry(
        endpoints={
            "cosign": ClientEndpointConfig(
                role="cosigner",
                url="ssh://127.0.0.1:9",
                identity_file=str(tmp_path / "missing_key"),
                known_hosts_path=str(tmp_path / "known_hosts"),
            )
        }
    )
    with EndpointCosignerResolver(registry=registry) as resolver:
        with pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
    assert str(excinfo.value).endswith('endpoints: "cosign" configuration invalid')


def test_an_endpoint_nobody_answers_at_is_unreachable(tmp_path):
    import paramiko

    key_path = tmp_path / "id_ed25519"
    paramiko.ECDSAKey.generate().write_private_key_file(str(key_path))
    listener = __import__("socket").socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()  # nothing listens there now
    registry = ClientEndpointRegistry(
        endpoints={
            "cosign": ClientEndpointConfig(
                role="cosigner",
                url=f"ssh://127.0.0.1:{port}",
                identity_file=str(key_path),
                known_hosts_path=str(tmp_path / "known_hosts"),
            )
        }
    )
    with EndpointCosignerResolver(registry=registry) as resolver:
        with pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
    assert str(excinfo.value).endswith('endpoints: "cosign" unreachable')
