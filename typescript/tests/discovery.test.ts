// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

// Cosigner discovery from endpoints.yaml: the Witness Key ID, the
// EndpointCosignerResolver's sweep, cache and choice, the default resolver of
// a client created from a data directory, and when the cosigned sequence
// resolves its targets.

import { describe, it, afterEach, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  SignerClient,
  rememberDataDirOrigin,
  type CosignedCosignerResolver,
  type CosignedSignTarget,
} from "../src/client.js";
import {
  EndpointCosignerResolver,
  discoveryHooks,
  discoveryTiming,
  type EndpointCosignerResolverOptions,
} from "../src/discovery.js";
import { witnessKeyId } from "../src/witness.js";
import {
  AuthenticationError,
  CosignerDiscoveryError,
  SignOutcomeUnknownError,
  SignerError,
  SignerUnavailableError,
  errorText,
  markLostAnswer,
} from "../src/errors.js";
import { markSshSetupFailure, type SshSetupFailure } from "../src/ssh.js";
import {
  KEY_TYPE_WITNESS_FALCON1024,
  type ClientEndpointConfig,
  type ClientEndpointRegistry,
} from "../src/types.js";
import { hexToBytes } from "../src/encoding.js";
import { fakeAddress } from "./fakeSigner.js";
import {
  FakeAlgod,
  alternateSpellings,
  installSigners,
  type FakeHandler,
  type WireKey,
} from "./fakeNetwork.js";
import {
  CosignedUser,
  CosignerEndpoint,
  cosignedKey,
  cosignedPayment,
  group,
  witnessRecord,
} from "./fakeCosigned.js";

const SIGNER = "http://signer.test";
const WITNESS_A = "a1".repeat(32);
const WITNESS_B = "b2".repeat(32);
const WITNESS_C = "c3".repeat(32);
const id = (hex: string, keyType = KEY_TYPE_WITNESS_FALCON1024) => witnessKeyId(keyType, hexToBytes(hex.toLowerCase()));

const originalConnect = discoveryHooks.connect;
const originalTiming = { ...discoveryTiming };
let restore: (() => void) | undefined;
afterEach(() => {
  restore?.();
  restore = undefined;
  discoveryHooks.connect = originalConnect;
  Object.assign(discoveryTiming, originalTiming);
});

type ConnectBehaviour = (signal: AbortSignal) => Promise<SignerClient>;

/**
 * The fake network: the cosigner endpoints by alias, how a connection to
 * each behaves, and every connection made.
 */
class Network {
  endpoints = new Map<string, CosignerEndpoint>();
  behaviour = new Map<string, ConnectBehaviour>();
  connects: string[] = [];
  connectOptions: Array<EndpointCosignerResolverOptions & { signal: AbortSignal }> = [];
  clients = new Map<string, SignerClient[]>();
  closed: string[] = [];
  /** Delay every connection by this many milliseconds. */
  delayMs = 0;
  inFlight = 0;
  maxInFlight = 0;

  add(alias: string, keys: WireKey[]): CosignerEndpoint {
    const endpoint = new CosignerEndpoint(alias, keys);
    this.endpoints.set(alias, endpoint);
    return endpoint;
  }

  /** A client of an endpoint, as a connection makes one, that records its close. */
  client(alias: string): SignerClient {
    const client = new SignerClient(`http://${alias}.test`);
    const close = client.close.bind(client);
    client.close = async () => {
      this.closed.push(alias);
      return close();
    };
    const list = this.clients.get(alias) ?? [];
    list.push(client);
    this.clients.set(alias, list);
    return client;
  }

  install(user?: FakeHandler): void {
    const handlers: Record<string, FakeHandler> = {};
    if (user) handlers[SIGNER] = user;
    for (const [alias, endpoint] of this.endpoints) handlers[`http://${alias}.test`] = endpoint.handle;
    restore = installSigners(handlers);
    discoveryHooks.connect = async (alias, _endpoint, options) => {
      this.connects.push(alias);
      this.connectOptions.push(options);
      this.inFlight++;
      this.maxInFlight = Math.max(this.maxInFlight, this.inFlight);
      try {
        if (this.delayMs > 0) await new Promise((resolve) => setTimeout(resolve, this.delayMs));
        const behaviour = this.behaviour.get(alias);
        if (behaviour) return await behaviour(options.signal);
        return this.client(alias);
      } finally {
        this.inFlight--;
      }
    };
  }
}

function endpointConfig(alias: string, url = `ssh://${alias}.example:1127`): ClientEndpointConfig {
  return { role: "cosigner", url, identityFile: "/nonexistent/.ssh/id_ed25519", knownHostsPath: "/nonexistent/.ssh/known_hosts" };
}

/** A registry with a signer endpoint and cosigner endpoints of these aliases. */
function registry(...aliases: string[]): ClientEndpointRegistry {
  const endpoints: Record<string, ClientEndpointConfig> = {
    primary: { ...endpointConfig("primary"), role: "signer" },
  };
  for (const alias of aliases) endpoints[alias] = endpointConfig(alias);
  return { schemaVersion: 2, default: "primary", endpoints };
}

function target(publicKeyHex: string, keyType = KEY_TYPE_WITNESS_FALCON1024, index = 0): CosignedSignTarget {
  return {
    targetIndex: index,
    cosignedAccount: fakeAddress(21),
    cosignerPublicKeyHex: publicKeyHex,
    cosignerComponentKeyType: keyType,
    logicSigResources: { programBytes: 1, argumentBytes: 1, maxOpcodeCost: 1 },
  };
}

/** Assert a CosignerDiscoveryError with exactly this message. */
function discoveryError(message: string) {
  return (error: unknown) => {
    assert.ok(error instanceof CosignerDiscoveryError, `error is ${String(error)}`);
    assert.ok(error instanceof SignerError, "a discovery error is an SDK error");
    assert.equal(errorText(error), message, "discovery error text");
    return true;
  };
}

function hostKeyMismatch(alias: string): Error {
  return markSshSetupFailure(
    new SignerUnavailableError(
      `SSH host key mismatch for [${alias}.example]:1127 (possible MITM attack); remove the old key from /nonexistent/.ssh/known_hosts to connect`,
    ),
    "host-key-mismatch",
  );
}

function setupFailure(kind: SshSetupFailure): ConnectBehaviour {
  return async () => {
    throw markSshSetupFailure(new SignerUnavailableError(`setup failed: ${kind}`), kind);
  };
}

describe("Witness Key ID", () => {
  it("matches the shared vectors", () => {
    const zero = new Uint8Array(1793);
    const counting = new Uint8Array(1793).map((_, index) => index % 251);
    assert.equal(
      witnessKeyId("aplane.witness-falcon1024.v1", zero),
      "ROGAFDACF7ASC3EMZRWNKVM73NXHO4P6O4EB7ZXWER37SM63BMFQ",
      "all-zero public key",
    );
    assert.equal(
      witnessKeyId("aplane.witness-falcon1024.v1", counting),
      "HJPRU4QEGLKF7RD6FYHQSG4SFAADHULJYVCVFPSCMIYZLAYW5MNA",
      "counting public key",
    );
  });

  it("is 52 uppercase base32 characters, for any key type and length", () => {
    for (const [keyType, length] of [["x", 0], ["some.other-type.v9", 7], [KEY_TYPE_WITNESS_FALCON1024, 32]] as const) {
      const value = witnessKeyId(keyType, new Uint8Array(length).fill(3));
      assert.match(value, /^[A-Z2-7]{52}$/, `${keyType}/${length}: ${value}`);
    }
  });
});

describe("EndpointCosignerResolver", () => {
  it("routes a key to the one endpoint that lists it, under its Witness Key ID", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    net.add("beta", [witnessRecord(WITNESS_B)]);
    net.install();
    const resolver = new EndpointCosignerResolver(registry("beta", "alpha"));
    const resolved = await resolver.resolve(target(WITNESS_B));
    assert.equal(resolved.client, net.clients.get("beta")?.[0], "routed to another endpoint's client");
    assert.equal(resolved.componentKey, id(WITNESS_B), "component key is not the Witness Key ID");
    assert.deepEqual([...net.connects].sort(), ["alpha", "beta"], "not every cosigner endpoint was probed");
    await resolver.close();
  });

  it("compares public keys without regard to case", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A.toUpperCase())]);
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha"));
    const resolved = await resolver.resolve(target(WITNESS_A));
    assert.equal(resolved.componentKey, id(WITNESS_A), "component key");
    const again = await resolver.resolve(target(WITNESS_A.toUpperCase()));
    assert.equal(again.client, resolved.client, "an uppercase required key did not match");
    await resolver.close();
  });

  it("refuses a key that more than one endpoint lists", async () => {
    const net = new Network();
    net.add("zulu", [witnessRecord(WITNESS_A)]);
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    net.add("mike", [witnessRecord(WITNESS_B)]);
    net.install();
    const resolver = new EndpointCosignerResolver(registry("zulu", "mike", "alpha"));
    await assert.rejects(
      resolver.resolve(target(WITNESS_A)),
      discoveryError(
        `cosigner discovery: Witness Key ID ${id(WITNESS_A)} (${KEY_TYPE_WITNESS_FALCON1024}) is listed by endpoints ` +
          '"alpha", "zulu"; each witness key needs exactly one endpoint',
      ),
    );
    await resolver.close();
  });

  it("refuses a key no endpoint lists, naming every endpoint's state", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    net.add("beta", []);
    net.behaviour.set("beta", async () => {
      throw new SignerUnavailableError("Failed to connect: ECONNREFUSED");
    });
    net.install();
    const resolver = new EndpointCosignerResolver(registry("beta", "alpha"));
    await assert.rejects(
      resolver.resolve(target(WITNESS_C)),
      discoveryError(
        `cosigner discovery: no endpoint lists Witness Key ID ${id(WITNESS_C)} (${KEY_TYPE_WITNESS_FALCON1024}); ` +
          'endpoints: "alpha" ok, "beta" unreachable',
      ),
    );
    await resolver.close();
  });

  it("refuses when endpoints.yaml lists no cosigner endpoint", async () => {
    const net = new Network();
    net.install();
    const resolver = new EndpointCosignerResolver(registry());
    await assert.rejects(
      resolver.resolve(target(WITNESS_A)),
      discoveryError("cosigner discovery: endpoints.yaml lists no cosigner endpoint"),
    );
    assert.deepEqual(net.connects, [], "an endpoint was connected");
  });

  it("does not report an endpoint that failed but was not needed", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    net.add("beta", []).keysReply = () => ({ status: 403, body: { error: "signer is locked", code: "locked" } });
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha", "beta"));
    const resolved = await resolver.resolve(target(WITNESS_A));
    assert.equal(resolved.componentKey, id(WITNESS_A), "a failed endpoint that was not needed failed the resolve");
    await resolver.close();
  });

  it("aborts the whole discovery on a host key mismatch at any endpoint, needed or not", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    net.add("beta", [witnessRecord(WITNESS_B)]);
    const mismatch = hostKeyMismatch("beta");
    // The mismatch shows once alpha has been read.
    net.behaviour.set("beta", async () => {
      await new Promise((resolve) => setTimeout(resolve, 30));
      throw mismatch;
    });
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha", "beta"));
    await assert.rejects(resolver.resolve(target(WITNESS_A)), (error: unknown) => {
      discoveryError(`cosigner discovery: endpoint "beta": ${mismatch.message}`)(error);
      assert.equal((error as CosignerDiscoveryError).cause, mismatch, "the cause is not the mismatch");
      return true;
    });
    // Nothing found is kept: alpha's connection is closed too.
    assert.ok(net.closed.includes("alpha"), `connections still open: closed ${net.closed.join(", ")}`);
    await resolver.close();
  });

  it("maps each failure to the endpoint's state", async () => {
    const net = new Network();
    const failures: Array<[string, (endpoint: CosignerEndpoint) => void, string]> = [
      ["a-ok", () => undefined, "ok"],
      ["b-refused", () => net.behaviour.set("b-refused", async () => {
        throw new SignerUnavailableError("Failed to connect: ECONNREFUSED");
      }), "unreachable"],
      ["c-unenrolled", () => net.behaviour.set("c-unenrolled", async () => {
        throw new AuthenticationError("SSH connection failed: the client's SSH key is not enrolled at the signer");
      }), "authentication failed"],
      ["d-unknown-host", () => net.behaviour.set("d-unknown-host", setupFailure("unknown-host-key")), "configuration invalid"],
      ["e-identity", () => net.behaviour.set("e-identity", setupFailure("identity")), "configuration invalid"],
      ["f-known-hosts", () => net.behaviour.set("f-known-hosts", setupFailure("known-hosts")), "configuration invalid"],
      ["g-401", (endpoint) => {
        endpoint.keysReply = () => ({ status: 401, body: { error: "no authenticated principal", code: "unauthorized" } });
      }, "authentication failed"],
      ["h-403", (endpoint) => {
        endpoint.keysReply = () => ({ status: 403, body: { error: "forbidden", code: "forbidden" } });
      }, "authentication failed"],
      ["i-locked", (endpoint) => {
        endpoint.keysReply = () => ({ status: 403, body: { error: "signer is locked", code: "locked" } });
      }, "locked"],
      ["j-503", (endpoint) => {
        endpoint.keysReply = () => ({ status: 503, body: { error: "product runtime unavailable", code: "unavailable" } });
      }, "unreachable"],
      ["k-404", (endpoint) => {
        endpoint.keysReply = () => ({ status: 404, body: { error: "not found", code: "not_found" } });
      }, "configuration invalid"],
      ["l-unreadable", (endpoint) => {
        endpoint.keysReply = () => ({ raw: '{"keys": [' });
      }, "invalid cosigner metadata"],
    ];
    for (const [alias, set] of failures) set(net.add(alias, [witnessRecord(WITNESS_B)]));
    net.install();
    const resolver = new EndpointCosignerResolver(registry(...failures.map(([alias]) => alias).reverse()));
    const states = failures.map(([alias, , state]) => `"${alias}" ${state}`).join(", ");
    await assert.rejects(
      resolver.resolve(target(WITNESS_A)),
      discoveryError(
        `cosigner discovery: no endpoint lists Witness Key ID ${id(WITNESS_A)} (${KEY_TYPE_WITNESS_FALCON1024}); endpoints: ${states}`,
      ),
    );
    // A connection to an endpoint that failed is not kept.
    for (const [alias, , state] of failures) {
      if (state === "ok" || !net.clients.has(alias)) continue;
      assert.ok(net.closed.includes(alias), `${alias}'s connection was kept`);
    }
    await resolver.close();
  });

  it("maps the other failures to the endpoint's state", async () => {
    discoveryTiming.endpointMs = 40;
    const net = new Network();
    const misspelled = alternateSpellings(fakeAddress(9))[0];
    const failures: Array<[string, (endpoint: CosignerEndpoint) => void, string]> = [
      ["a-locked-503", (endpoint) => {
        endpoint.keysReply = () => ({ status: 503, body: { error: "signer is locked", code: "locked" } });
      }, "locked"],
      ["b-dropped", (endpoint) => {
        endpoint.keysReply = () => "drop";
      }, "unreachable"],
      ["c-hangs", () => net.behaviour.set("c-hangs", () => new Promise<SignerClient>(() => undefined)), "unreachable"],
      ["d-bad-hex", (endpoint) => {
        endpoint.keys.push({ ...witnessRecord(WITNESS_C), public_key_hex: "a1b" });
      }, "invalid cosigner metadata"],
      ["e-wrong-id", (endpoint) => {
        endpoint.keys.push({ ...witnessRecord(WITNESS_C), address: id(WITNESS_A) });
      }, "invalid cosigner metadata"],
      ["f-misspelled", (endpoint) => {
        endpoint.keys.push({ address: misspelled, key_type: "ed25519" });
      }, "invalid cosigner metadata"],
      ["g-not-hex", (endpoint) => {
        endpoint.keys.push({ ...witnessRecord(WITNESS_C), public_key_hex: "zz" });
      }, "invalid cosigner metadata"],
      ["h-teapot", (endpoint) => {
        endpoint.keysReply = () => ({ status: 418, body: { error: "teapot" } });
      }, "configuration invalid"],
      ["h-unkeyed", (endpoint) => {
        // Its address is the Witness Key ID of an empty key, so only the
        // empty public key is wrong.
        endpoint.keys.push(witnessRecord(""));
      }, "invalid cosigner metadata"],
    ];
    for (const [alias, set] of failures) set(net.add(alias, [witnessRecord(WITNESS_B)]));
    net.install();
    const reg = registry(...failures.map(([alias]) => alias));
    reg.endpoints["i-bad-url"] = endpointConfig("i-bad-url", "http://i-bad-url.example");
    const resolver = new EndpointCosignerResolver(reg);
    const states = [...failures.map(([alias, , state]) => `"${alias}" ${state}`), '"i-bad-url" configuration invalid'].join(", ");
    await assert.rejects(
      resolver.resolve(target(WITNESS_A)),
      discoveryError(
        `cosigner discovery: no endpoint lists Witness Key ID ${id(WITNESS_A)} (${KEY_TYPE_WITNESS_FALCON1024}); endpoints: ${states}`,
      ),
    );
    assert.ok(!net.connects.includes("i-bad-url"), "an endpoint with a bad URL was connected");
    await resolver.close();
  });

  it("skips records that are not witness keys, or name no key type", async () => {
    const net = new Network();
    net.add("alpha", [
      { address: fakeAddress(3), key_type: "ed25519", public_key_hex: "not hex" },
      { address: "NOT-AN-ID", key_type: "", public_key_hex: "zz", is_witness_key: true },
      witnessRecord(WITNESS_A),
    ]);
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha"));
    const resolved = await resolver.resolve(target(WITNESS_A));
    assert.equal(resolved.componentKey, id(WITNESS_A), "component key");
    await resolver.close();
  });

  it("matches the key type as well as the public key", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A, "aplane.witness-other.v1")]);
    net.add("beta", [witnessRecord(WITNESS_A)]);
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha", "beta"));
    const resolved = await resolver.resolve(target(WITNESS_A));
    assert.equal(resolved.client, net.clients.get("beta")?.[0], "matched a record of another key type");
    const other = await resolver.resolve(target(WITNESS_A, "aplane.witness-other.v1"));
    assert.equal(other.client, net.clients.get("alpha")?.[0], "the other key type");
    assert.equal(other.componentKey, id(WITNESS_A, "aplane.witness-other.v1"), "other key type's ID");
    await resolver.close();
  });

  it("probes at most four endpoints at once", async () => {
    const net = new Network();
    const aliases = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
    for (const alias of aliases) net.add(alias, []);
    net.add("j", [witnessRecord(WITNESS_A)]);
    net.delayMs = 15;
    net.install();
    const resolver = new EndpointCosignerResolver(registry(...aliases, "j"));
    await resolver.resolve(target(WITNESS_A));
    assert.equal(net.maxInFlight, 4, `${net.maxInFlight} endpoints were probed at once`);
    assert.equal(net.connects.length, 10, "not every endpoint was probed");
    await resolver.close();
  });

  it("gives an endpoint that does not answer up after its own limit, and closes its late connection", async () => {
    discoveryTiming.endpointMs = 30;
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    net.add("slow", [witnessRecord(WITNESS_B)]);
    // A connection that ignores the signal and arrives late.
    net.behaviour.set("slow", () => new Promise((resolve) => setTimeout(() => resolve(net.client("slow")), 120)));
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha", "slow"));
    const started = Date.now();
    await assert.rejects(
      resolver.resolve(target(WITNESS_B)),
      discoveryError(
        `cosigner discovery: no endpoint lists Witness Key ID ${id(WITNESS_B)} (${KEY_TYPE_WITNESS_FALCON1024}); ` +
          'endpoints: "alpha" ok, "slow" unreachable',
      ),
    );
    assert.ok(Date.now() - started < 110, `the resolve waited ${Date.now() - started} ms for a slow endpoint`);
    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.ok(net.closed.includes("slow"), "the late connection was left open");
    await resolver.close();
  });

  it("ends the sweep at its time limit, and an endpoint not yet probed is unreachable", async () => {
    discoveryTiming.endpointMs = 5_000;
    discoveryTiming.sweepMs = 60;
    const net = new Network();
    const aliases = ["a", "b", "c", "d", "e", "f"];
    for (const alias of aliases) {
      net.add(alias, []);
      net.behaviour.set(alias, (signal) => new Promise((_, reject) => {
        signal.addEventListener("abort", () => reject(new SignerUnavailableError("SSH setup canceled")), { once: true });
      }));
    }
    net.install();
    const resolver = new EndpointCosignerResolver(registry(...aliases));
    const started = Date.now();
    await assert.rejects(
      resolver.resolve(target(WITNESS_A)),
      discoveryError(
        `cosigner discovery: no endpoint lists Witness Key ID ${id(WITNESS_A)} (${KEY_TYPE_WITNESS_FALCON1024}); ` +
          `endpoints: ${aliases.map((alias) => `"${alias}" unreachable`).join(", ")}`,
      ),
    );
    assert.ok(Date.now() - started < 1_000, `the sweep took ${Date.now() - started} ms`);
    assert.equal(net.connects.length, 4, `${net.connects.length} endpoints were probed; the rest should not be`);
    await resolver.close();
  });

  it("refuses a target that names no valid cosigner key, before connecting", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha"));
    await assert.rejects(
      resolver.resolve(target("")),
      discoveryError('cosigner discovery: the account\'s cosigner public key "" is not valid hex'),
    );
    await assert.rejects(
      resolver.resolve(target("xyz")),
      discoveryError('cosigner discovery: the account\'s cosigner public key "xyz" is not valid hex'),
    );
    // The public key is checked first.
    await assert.rejects(
      resolver.resolve(target("a1b", "")),
      discoveryError('cosigner discovery: the account\'s cosigner public key "a1b" is not valid hex'),
    );
    await assert.rejects(
      resolver.resolve(target(WITNESS_A, "")),
      discoveryError("cosigner discovery: the account names no cosigner key type"),
    );
    assert.deepEqual(net.connects, [], "an endpoint was connected for an invalid target");
    // A closed resolver still checks the key first.
    await resolver.close();
    await assert.rejects(resolver.resolve(target("")), discoveryError('cosigner discovery: the account\'s cosigner public key "" is not valid hex'));
    await assert.rejects(resolver.resolve(target(WITNESS_A)), discoveryError("cosigner discovery: the resolver is closed"));
  });

  it("refuses a registry with more cosigner endpoints than the limit when it resolves", async () => {
    const net = new Network();
    net.install();
    const aliases = Array.from({ length: 13 }, (_, index) => `c${index}`);
    const resolver = new EndpointCosignerResolver(registry(...aliases));
    await assert.rejects(
      resolver.resolve(target(WITNESS_A)),
      discoveryError("cosigner discovery: endpoints.yaml lists 13 cosigner endpoints; the limit is 12"),
    );
    assert.deepEqual(net.connects, [], "an endpoint was connected");
  });

  it("counts a key one endpoint lists twice as one listing", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A), witnessRecord(WITNESS_A.toUpperCase())]);
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha"));
    const resolved = await resolver.resolve(target(WITNESS_A));
    assert.equal(resolved.componentKey, id(WITNESS_A), "a key listed twice by one endpoint was refused");
    await resolver.close();
  });

  it("reports the first host key mismatch in alias order, and keeps nothing from that sweep", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    net.add("mike", []);
    net.add("zulu", []);
    const mike = hostKeyMismatch("mike");
    const zulu = hostKeyMismatch("zulu");
    // Both mismatches show at once; mike's is reported, being first by alias.
    net.behaviour.set("zulu", async () => {
      throw zulu;
    });
    net.behaviour.set("mike", async () => {
      throw mike;
    });
    net.install();
    const resolver = new EndpointCosignerResolver(registry("zulu", "mike", "alpha"));
    await assert.rejects(resolver.resolve(target(WITNESS_A)), discoveryError(`cosigner discovery: endpoint "mike": ${mike.message}`));
    // Nothing was kept: the next call sweeps again.
    net.behaviour.delete("mike");
    net.behaviour.delete("zulu");
    const resolved = await resolver.resolve(target(WITNESS_A));
    assert.equal(resolved.componentKey, id(WITNESS_A), "the sweep after a mismatch did not route the key");
    assert.equal(net.connects.filter((alias) => alias === "alpha").length, 2, `alpha connects: ${net.connects.join(", ")}`);
    await resolver.close();
  });

  it("connects with the options it was given", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha"), {
      trustOnFirstUse: true,
      sshSetupTimeout: 1234,
      timeout: 5678,
    });
    await resolver.resolve(target(WITNESS_A));
    const options = net.connectOptions[0];
    assert.equal(options.trustOnFirstUse, true, "trustOnFirstUse");
    assert.equal(options.sshSetupTimeout, 1234, "sshSetupTimeout");
    assert.equal(options.timeout, 5678, "timeout");
    await resolver.close();
  });
});

describe("EndpointCosignerResolver's cache", () => {
  it("keeps the sweep, and sweeps once more for each miss", async () => {
    const net = new Network();
    const alpha = net.add("alpha", [witnessRecord(WITNESS_A)]);
    const beta = net.add("beta", [witnessRecord(WITNESS_B)]);
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha", "beta"));
    const reads = () => [alpha.count("/keys"), beta.count("/keys")];

    await resolver.resolve(target(WITNESS_A));
    await resolver.resolve(target(WITNESS_B));
    await resolver.resolve(target(WITNESS_A));
    assert.deepEqual(reads(), [1, 1], "a key the kept sweep routes was swept for again");

    // A miss sweeps once more, and only once.
    await assert.rejects(resolver.resolve(target(WITNESS_C)), CosignerDiscoveryError);
    assert.deepEqual(reads(), [2, 2], "a miss did not sweep exactly once");
    await assert.rejects(resolver.resolve(target(WITNESS_C)), CosignerDiscoveryError);
    assert.deepEqual(reads(), [3, 3], "a second miss did not sweep exactly once");

    // The fresh sweep finds a key listed since.
    beta.keys.push(witnessRecord(WITNESS_C));
    const resolved = await resolver.resolve(target(WITNESS_C));
    assert.equal(resolved.client, net.clients.get("beta")?.[0], "the key listed since was not found");
    assert.deepEqual(reads(), [4, 4], "finding a new key did not sweep exactly once");
    // The connections were kept across the sweeps.
    assert.deepEqual([...net.connects].sort(), ["alpha", "beta"], "a fresh sweep reconnected");
    await resolver.close();
  });

  it("reads kept connections again on a fresh sweep, reconnects failed endpoints, and closes what it drops", async () => {
    const net = new Network();
    const alpha = net.add("alpha", [witnessRecord(WITNESS_A)]);
    const beta = net.add("beta", [witnessRecord(WITNESS_B)]);
    beta.keysReply = () => ({ status: 403, body: { error: "signer is locked", code: "locked" } });
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha", "beta"));
    await resolver.resolve(target(WITNESS_A));
    assert.deepEqual(net.closed, ["beta"], "a locked endpoint's connection was kept");

    // beta unlocks; alpha's kept connection now fails its read.
    beta.keysReply = undefined;
    let alphaReads = 0;
    alpha.keysReply = () => (++alphaReads === 1
      ? { status: 403, body: { error: "signer is locked", code: "locked" } }
      : { body: { count: 1, keys: alpha.keys } });
    const resolved = await resolver.resolve(target(WITNESS_B));
    assert.equal(resolved.client, net.clients.get("beta")?.[1], "beta was not connected afresh");
    assert.deepEqual([...net.connects].sort(), ["alpha", "alpha", "beta", "beta"], `connects: ${net.connects.join(", ")}`);
    assert.equal(net.closed.filter((alias) => alias === "alpha").length, 1, `alpha's failed connection was not closed: ${net.closed.join(", ")}`);
    const again = await resolver.resolve(target(WITNESS_A));
    assert.equal(again.client, net.clients.get("alpha")?.[1], "alpha's new connection was not kept");
    await resolver.close();
  });

  it("keeps nothing from a fresh sweep the caller's signal ended, and closes the kept connections", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    const beta = net.add("beta", []);
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha", "beta"));
    await resolver.resolve(target(WITNESS_A));
    const controller = new AbortController();
    beta.keysReply = () => {
      controller.abort();
      return { body: { count: 0, keys: [] } };
    };
    await assert.rejects(
      resolver.resolve(target(WITNESS_C), { signal: controller.signal }),
      discoveryError("cosigner discovery: Request aborted by caller"),
    );
    assert.ok(net.closed.includes("alpha"), `alpha's kept connection was left open: closed ${net.closed.join(", ")}`);
    beta.keysReply = undefined;
    const resolved = await resolver.resolve(target(WITNESS_A));
    assert.equal(resolved.client, net.clients.get("alpha")?.[1], "the next resolve answered from the ended sweep");
    await resolver.close();
  });

  it("replaces a connection that went down", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha"));
    const first = await resolver.resolve(target(WITNESS_A));
    await first.client.close();
    const second = await resolver.resolve(target(WITNESS_A));
    assert.notEqual(second.client, first.client, "a closed connection was handed out again");
    assert.deepEqual(net.connects, ["alpha", "alpha"], "the endpoint was not connected again");
    await resolver.close();
  });

  it("closes every connection it opened, and resolves nothing after", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    net.add("beta", [witnessRecord(WITNESS_B)]);
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha", "beta"));
    await resolver.resolve(target(WITNESS_A));
    await resolver.close();
    assert.deepEqual([...net.closed].sort(), ["alpha", "beta"], "a connection was left open");
    await assert.rejects(resolver.resolve(target(WITNESS_A)), discoveryError("cosigner discovery: the resolver is closed"));
  });

  it("stops a sweep when the caller's signal aborts, and keeps nothing from it", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    const controller = new AbortController();
    let hang = true;
    net.behaviour.set("alpha", (signal) => {
      if (!hang) return Promise.resolve(net.client("alpha"));
      controller.abort();
      return new Promise((_, reject) => {
        signal.addEventListener("abort", () => reject(new SignerUnavailableError("SSH setup canceled")), { once: true });
      });
    });
    net.install();
    const resolver = new EndpointCosignerResolver(registry("alpha"));
    await assert.rejects(
      resolver.resolve(target(WITNESS_A), { signal: controller.signal }),
      discoveryError("cosigner discovery: Request aborted by caller"),
    );
    hang = false;
    const resolved = await resolver.resolve(target(WITNESS_A));
    assert.equal(resolved.componentKey, id(WITNESS_A), "the next resolve did not sweep again");
    await resolver.close();
  });
});

/** A function resolver that records the targets it is asked for, and the user requests made before. */
function recordingResolver(user: CosignedUser, answer: (target: CosignedSignTarget) => Promise<any>) {
  const calls: Array<{ index: number; before: string[] }> = [];
  const resolver: CosignedCosignerResolver = async (item) => {
    calls.push({ index: item.targetIndex, before: [...user.paths] });
    return answer(item);
  };
  return { resolver, calls };
}

describe("the cosigned sequence's cosigner resolution", () => {
  const account = fakeAddress(21);

  for (const [name, setup] of [
    ["discovery that finds no endpoint", (net: Network) => {
      net.add("alpha", [witnessRecord(WITNESS_B)]);
      return { cosignerResolver: new EndpointCosignerResolver(registry("alpha")) };
    }],
    ["a resolver that throws", () => ({
      cosignerResolver: async () => {
        throw new RangeError("no cosigner for this account");
      },
    })],
    ["nothing configured", () => ({})],
  ] as Array<[string, (net: Network) => Record<string, unknown>]>) {
    it(`${name} fails a spend before any approval-bearing request`, async () => {
      const net = new Network();
      const options = setup(net);
      const user = new CosignedUser([cosignedKey(account, WITNESS_A)]);
      net.install(user.handle);
      const node = new FakeAlgod();
      const client = new SignerClient(SIGNER);
      await assert.rejects(client.sendPrepared(node as any, group(cosignedPayment(account)), options), (error: unknown) => {
        assert.ok(!(error instanceof SignOutcomeUnknownError), `error is an unknown outcome: ${String(error)}`);
        return true;
      });
      assert.deepEqual(user.approvalRequests(), [], `approval-bearing requests were made: ${user.paths.join(", ")}`);
      assert.ok(!user.paths.includes("/plan"), `the group was planned: ${user.paths.join(", ")}`);
      for (const endpoint of net.endpoints.values()) {
        assert.equal(endpoint.count("/sign/component"), 0, "the cosigner was asked to sign");
      }
      assert.equal(node.submitted.length, 0, "something was submitted");
    });
  }

  it("refuses a resolver that returns no client, naming the position", async () => {
    const net = new Network();
    const first = fakeAddress(25);
    const second = fakeAddress(26);
    const user = new CosignedUser([cosignedKey(first, WITNESS_A), cosignedKey(second, WITNESS_B)]);
    net.install(user.handle);
    const cosignerClient = new SignerClient("http://alpha.test");
    await assert.rejects(
      new SignerClient(SIGNER).sendPrepared(new FakeAlgod() as any, group(cosignedPayment(first), cosignedPayment(second)), {
        cosignerResolver: async (item) => (item.targetIndex === 1 ? ({} as any) : { client: cosignerClient }),
      }),
      (error: unknown) => {
        assert.ok(error instanceof SignerError && !(error instanceof SignOutcomeUnknownError), `error is ${String(error)}`);
        assert.equal(errorText(error), "cosigner resolver returned no client for prepared transaction 1", "error text");
        return true;
      },
    );
    assert.deepEqual(user.approvalRequests(), [], `approval-bearing requests were made: ${user.paths.join(", ")}`);
  });

  it("sends the cosigner requests in the order of their first target position", async () => {
    const net = new Network();
    const accounts = [fakeAddress(25), fakeAddress(26), fakeAddress(27)];
    // Position 0 and 2 need beta's key, position 1 alpha's: beta is asked first.
    const alpha = net.add("alpha", [witnessRecord(WITNESS_A)]);
    const beta = net.add("beta", [witnessRecord(WITNESS_B)]);
    const user = new CosignedUser([
      cosignedKey(accounts[0], WITNESS_B),
      cosignedKey(accounts[1], WITNESS_A),
      cosignedKey(accounts[2], WITNESS_B),
    ]);
    const asked: string[] = [];
    const record = (endpoint: CosignerEndpoint) => {
      const handle = endpoint.handle;
      endpoint.handle = (path, body) => {
        if (path === "/sign/component") asked.push(endpoint.alias);
        return handle(path, body);
      };
    };
    record(alpha);
    record(beta);
    net.install(user.handle);
    const resolver = new EndpointCosignerResolver(registry("alpha", "beta"));
    await new SignerClient(SIGNER).sendPrepared(new FakeAlgod() as any, group(...accounts.map((account) => cosignedPayment(account))), {
      cosignerResolver: resolver,
    });
    assert.deepEqual(asked, ["beta", "alpha"], `cosigner request order: ${asked.join(", ")}`);
    assert.deepEqual(beta.componentRequests[0].targets.map((item: any) => item.target_index), [0, 2], "beta's targets");
    await resolver.close();
  });

  it("passes a resolver's own error on as it is", async () => {
    const net = new Network();
    const user = new CosignedUser([cosignedKey(account, WITNESS_A)]);
    net.install(user.handle);
    const own = new RangeError("no cosigner for this account");
    await assert.rejects(
      new SignerClient(SIGNER).sendPrepared(new FakeAlgod() as any, group(cosignedPayment(account)), {
        cosignerResolver: async () => {
          throw own;
        },
      }),
      (error: unknown) => {
        assert.equal(error, own, `error is ${String(error)}`);
        return true;
      },
    );
  });

  // A resolver that throws what a lost answer elsewhere left it: an Error
  // whose cause carries the mark, or the marked error itself.
  const lostElsewhere = () => markLostAnswer(new SignerError("Server returned invalid JSON"), "sdk-elsewhere");
  for (const [when, mayTakeListedPath] of [["up front", false], ["late", true]] as Array<[string, boolean]>) {
    for (const [what, thrown] of [
      ["an Error whose cause is a lost answer", () => new Error("cosigner lookup failed", { cause: lostElsewhere() })],
      ["a lost answer itself", lostElsewhere],
    ] as Array<[string, () => Error]>) {
      it(`a resolver that throws ${what}, ${when}, is a plain error passed on as it is`, async () => {
        const net = new Network();
        const user = new CosignedUser([cosignedKey(account, WITNESS_A, mayTakeListedPath)]);
        user.pathFor = () => "spending_rekey";
        net.install(user.handle);
        const own = thrown();
        const keysBefore = Object.keys(own);
        const { resolver, calls } = recordingResolver(user, async () => {
          throw own;
        });
        const node = new FakeAlgod();
        await assert.rejects(
          new SignerClient(SIGNER).sendPrepared(
            node as any,
            group(cosignedPayment(account, mayTakeListedPath ? fakeAddress(23) : undefined)),
            { cosignerResolver: resolver },
          ),
          (error: unknown) => {
            assert.ok(!(error instanceof SignOutcomeUnknownError), `error is an unknown outcome: ${String(error)}`);
            assert.equal(error, own, `error is not the resolver's own: ${String(error)}`);
            assert.equal(errorText(error), errorText(own), "the resolver's error text changed");
            assert.deepEqual(Object.keys(own), keysBefore, "the resolver's error gained an enumerable property");
            return true;
          },
        );
        assert.equal(calls.length, 1, `resolver calls ${calls.length}`);
        assert.equal(
          calls[0].before.includes("/sign/component"),
          mayTakeListedPath,
          `resolved ${mayTakeListedPath ? "before" : "after"} the base component: ${calls[0].before.join(", ")}`,
        );
        assert.ok(!user.paths.includes("/sign/assemble"), `the group was assembled: ${user.paths.join(", ")}`);
        assert.equal(node.submitted.length, 0, "something was submitted");
      });
    }
  }

  it("a listed rekey needs no cosigner, configured or not", async () => {
    const net = new Network();
    const user = new CosignedUser([cosignedKey(account, WITNESS_A, true)]);
    user.pathFor = () => "listed_rekey";
    net.install(user.handle);
    const node = new FakeAlgod();
    const client = new SignerClient(SIGNER);
    const result = await client.sendPrepared(node as any, group(cosignedPayment(account, fakeAddress(23))));
    assert.equal(result.outcome, "confirmed", "the listed rekey was not sent");
    const { resolver, calls } = recordingResolver(user, async () => {
      throw new Error("the resolver was asked about a listed rekey");
    });
    const again = await client.sendPrepared(node as any, group(cosignedPayment(account, fakeAddress(23))), {
      cosignerResolver: resolver,
    });
    assert.equal(again.outcome, "confirmed", "the listed rekey was not sent with a resolver");
    assert.deepEqual(calls, [], "the resolver was asked about a listed rekey");
  });

  it("resolves a target that may take the listed path after its base component, when it needs the cosigner", async () => {
    const net = new Network();
    const cosigner = net.add("alpha", [witnessRecord(WITNESS_A)]);
    const user = new CosignedUser([cosignedKey(account, WITNESS_A, true)]);
    user.pathFor = () => "spending_rekey";
    net.install(user.handle);
    const cosignerClient = net.client("alpha");
    const { resolver, calls } = recordingResolver(user, async () => ({ client: cosignerClient, componentKey: id(WITNESS_A) }));
    const result = await new SignerClient(SIGNER).sendPrepared(
      new FakeAlgod() as any,
      group(cosignedPayment(account, fakeAddress(23))),
      { cosignerResolver: resolver },
    );
    assert.equal(result.outcome, "confirmed", "the rekey was not sent");
    assert.equal(calls.length, 1, `resolver calls ${calls.length}`);
    assert.ok(calls[0].before.includes("/sign/component"), `resolved before the base component: ${calls[0].before.join(", ")}`);
    assert.equal(cosigner.count("/sign/component"), 1, "the cosigner was not asked");
  });

  it("a spend from an account with a rekey list is resolved up front", async () => {
    const net = new Network();
    const user = new CosignedUser([cosignedKey(account, WITNESS_A, true)]);
    net.install(user.handle);
    const { resolver, calls } = recordingResolver(user, async () => {
      throw new RangeError("no cosigner");
    });
    await assert.rejects(
      new SignerClient(SIGNER).sendPrepared(new FakeAlgod() as any, group(cosignedPayment(account)), { cosignerResolver: resolver }),
      RangeError,
    );
    assert.equal(calls.length, 1, `resolver calls ${calls.length}`);
    assert.deepEqual(user.approvalRequests(), [], `approval-bearing requests were made: ${user.paths.join(", ")}`);
  });

  it("a late resolution's failure is still a plain error", async () => {
    const net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_B)]);
    const user = new CosignedUser([cosignedKey(account, WITNESS_A, true)]);
    user.pathFor = () => "spending_rekey";
    net.install(user.handle);
    await assert.rejects(
      new SignerClient(SIGNER).sendPrepared(new FakeAlgod() as any, group(cosignedPayment(account, fakeAddress(23))), {
        cosignerResolver: new EndpointCosignerResolver(registry("alpha")),
      }),
      (error: unknown) => {
        assert.ok(error instanceof CosignerDiscoveryError, `error is ${String(error)}`);
        return true;
      },
    );
    assert.ok(user.paths.includes("/sign/component"), `asked ${user.paths.join(", ")}`);
    assert.ok(!user.paths.includes("/sign/assemble"), `asked ${user.paths.join(", ")}`);
  });

  it("resolves targets in the order of the witness keys they need", async () => {
    const net = new Network();
    const first = fakeAddress(25);
    const second = fakeAddress(26);
    const user = new CosignedUser([cosignedKey(first, WITNESS_C), cosignedKey(second, WITNESS_A)]);
    net.add("alpha", []);
    net.install(user.handle);
    const { resolver, calls } = recordingResolver(user, async () => {
      throw new RangeError("stop");
    });
    await assert.rejects(
      new SignerClient(SIGNER).sendPrepared(new FakeAlgod() as any, group(cosignedPayment(first), cosignedPayment(second)), {
        cosignerResolver: resolver,
      }),
      RangeError,
    );
    assert.deepEqual(calls.map((call) => call.index), [1], "the first key in order was not resolved first");
    // Discovery reports the first missing key in that order.
    await assert.rejects(
      new SignerClient(SIGNER).sendPrepared(new FakeAlgod() as any, group(cosignedPayment(first), cosignedPayment(second)), {
        cosignerResolver: new EndpointCosignerResolver(registry("alpha")),
      }),
      discoveryError(
        `cosigner discovery: no endpoint lists Witness Key ID ${id(WITNESS_A)} (${KEY_TYPE_WITNESS_FALCON1024}); endpoints: "alpha" ok`,
      ),
    );
  });

  it("sends with an EndpointCosignerResolver, each target routed to its endpoint", async () => {
    const net = new Network();
    const first = fakeAddress(25);
    const second = fakeAddress(26);
    const alpha = net.add("alpha", [witnessRecord(WITNESS_A)]);
    const beta = net.add("beta", [witnessRecord(WITNESS_B)]);
    const user = new CosignedUser([cosignedKey(first, WITNESS_A), cosignedKey(second, WITNESS_B)]);
    net.install(user.handle);
    const resolver = new EndpointCosignerResolver(registry("alpha", "beta"));
    const result = await new SignerClient(SIGNER).sendPrepared(
      new FakeAlgod() as any,
      group(cosignedPayment(first), cosignedPayment(second)),
      { cosignerResolver: resolver },
    );
    assert.equal(result.outcome, "confirmed", "the group was not sent");
    assert.equal(alpha.componentRequests.length, 1, "alpha was not asked once");
    assert.equal(beta.componentRequests.length, 1, "beta was not asked once");
    assert.deepEqual(alpha.componentRequests[0].targets.map((item: any) => [item.target_index, item.component_key]), [[0, id(WITNESS_A)]], "alpha's targets");
    assert.deepEqual(beta.componentRequests[0].targets.map((item: any) => [item.target_index, item.component_key]), [[1, id(WITNESS_B)]], "beta's targets");
    await resolver.close();
  });
});

describe("the default cosigner resolver of a client created from a data directory", () => {
  const account = fakeAddress(21);
  let net: Network;
  let user: CosignedUser;
  let client: SignerClient;
  const options = { trustOnFirstUse: true, sshSetupTimeout: 4321, timeout: 8765 };

  beforeEach(() => {
    net = new Network();
    net.add("alpha", [witnessRecord(WITNESS_A)]);
    user = new CosignedUser([cosignedKey(account, WITNESS_A)]);
    net.install(user.handle);
    client = new SignerClient(SIGNER);
    rememberDataDirOrigin(client, registry("alpha"), options);
  });

  it("finds the cosigner in the registry when a send names none", async () => {
    const result = await client.sendPrepared(new FakeAlgod() as any, group(cosignedPayment(account)));
    assert.equal(result.outcome, "confirmed", "the group was not sent");
    assert.deepEqual(net.connects, ["alpha"], "the registry's cosigner was not connected");
    assert.equal(net.endpoints.get("alpha")?.count("/sign/component"), 1, "the cosigner was not asked");
    const used = net.connectOptions[0];
    assert.equal(used.trustOnFirstUse, true, "trustOnFirstUse is not the client's");
    assert.equal(used.sshSetupTimeout, 4321, "sshSetupTimeout is not the client's");
    assert.equal(used.timeout, 8765, "timeout is not the client's");
    await client.close();
  });

  it("is made once, kept, and closed with the client", async () => {
    await client.sendPrepared(new FakeAlgod() as any, group(cosignedPayment(account)));
    await client.sendPrepared(new FakeAlgod() as any, group(cosignedPayment(account)));
    assert.deepEqual(net.connects, ["alpha"], "the default resolver was made, or swept, again");
    assert.equal(net.endpoints.get("alpha")?.count("/keys"), 1, "the kept sweep was not reused");
    assert.deepEqual(net.closed, [], "a connection was closed before the client");
    await client.close();
    assert.deepEqual(net.closed, ["alpha"], "the cosigner connection was not closed with the client");
  });

  it("serves the lower-level cosigned call too", async () => {
    const { signPreparedCosignedGroup } = await import("../src/client.js");
    const signed = await signPreparedCosignedGroup({ userClient: client, preparedGroup: group(cosignedPayment(account)) });
    assert.equal(signed.signedGroup.length, 1, "the group was not signed");
    assert.deepEqual(net.connects, ["alpha"], "the registry's cosigner was not connected");
    await client.close();
  });

  it("gives way to an explicit cosigner client or resolver", async () => {
    const explicit = net.client("alpha");
    const result = await client.sendPrepared(new FakeAlgod() as any, group(cosignedPayment(account)), {
      cosignerClient: explicit,
      cosignerComponentKey: id(WITNESS_A),
    });
    assert.equal(result.outcome, "confirmed", "the group was not sent with the explicit client");
    const { resolver, calls } = recordingResolver(user, async () => ({ client: explicit, componentKey: id(WITNESS_A) }));
    await client.sendPrepared(new FakeAlgod() as any, group(cosignedPayment(account)), { cosignerResolver: resolver });
    assert.equal(calls.length, 1, "the explicit resolver was not used");
    assert.deepEqual(net.connects, [], "discovery ran beside an explicit cosigner");
    await client.close();
  });

  it("a client not created from a data directory still asks for a cosigner", async () => {
    const plain = new SignerClient(SIGNER);
    await assert.rejects(
      plain.sendPrepared(new FakeAlgod() as any, group(cosignedPayment(account))),
      /cosignerClient or cosignerResolver is required/,
    );
    assert.deepEqual(net.connects, [], "a plain client ran discovery");
    await client.close();
  });
});
