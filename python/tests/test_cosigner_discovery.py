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
from aplanesdk.signer import (
    _SSHConfigError,
    _SSHHostKeyMismatchError,
    _witness_key_id,
)
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
        "address": address if address is not None else _witness_key_id(key_type, public_key),
        "key_type": key_type,
        "public_key_hex": public_key_hex if public_key_hex is not None else public_key.hex(),
        "is_witness_key": True,
    }


def test_witness_key_id_vectors():
    assert (
        _witness_key_id(WITNESS, bytes(1793))
        == "ROGAFDACF7ASC3EMZRWNKVM73NXHO4P6O4EB7ZXWER37SM63BMFQ"
    )
    assert (
        _witness_key_id(WITNESS, bytes(i % 251 for i in range(1793)))
        == "HJPRU4QEGLKF7RD6FYHQSG4SFAADHULJYVCVFPSCMIYZLAYW5MNA"
    )
    assert len(_witness_key_id(WITNESS, b"\x01")) == 52


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
        assert component_key == _witness_key_id(WITNESS, PUBLIC_B)
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
            assert component_key == _witness_key_id(WITNESS, PUBLIC_A)
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
        key_id = _witness_key_id(WITNESS, PUBLIC_A)
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
        key_id = _witness_key_id(WITNESS, PUBLIC_A)
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
        key_id = _witness_key_id(WITNESS, PUBLIC_A)
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError) as excinfo:
            resolver.resolve(PUBLIC_A.hex(), WITNESS)
        assert str(excinfo.value) == (
            f"cosigner discovery: no endpoint lists Witness Key ID {key_id} ({WITNESS}); "
            'endpoints: "badurl" configuration invalid, "lockedfive" locked, '
            '"spelled" invalid cosigner metadata, "teapot" configuration invalid, '
            '"unauth" authentication failed'
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

    def test_a_public_key_that_is_not_hex_is_refused(self, network):
        net = network({"alpha": Endpoint([witness_record(PUBLIC_A)])})
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError, match="not hex"):
            resolver.resolve("xyz", WITNESS)

    def test_the_errors_are_sdk_errors(self):
        assert issubclass(CosignerDiscoveryError, SignerError)


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
        with net.resolver() as resolver, pytest.raises(CosignerDiscoveryError, match="maximum is 12"):
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
            assert alpha.key_reads == 2
            # The new key appears: one more sweep finds it.
            alpha.keys.append(witness_record(PUBLIC_B))
            client, _ = resolver.resolve(PUBLIC_B.hex(), WITNESS)
            assert alpha.key_reads == 3
            # The client a resolve returned before is kept open until the
            # resolver closes.
            assert net.closed.count("alpha") == 1
        assert net.closed.count("alpha") == 3

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
        assert request["targets"][0]["component_key"] == _witness_key_id(WITNESS, FIXTURE_PUBLIC)
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
