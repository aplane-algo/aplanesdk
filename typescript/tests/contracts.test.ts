// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { SignerClient } from "../src/client.js";
import { ErrorCodes } from "../src/types.js";
import type {
  AdminSyncSentryReferencesRequest,
  AdminSyncSentryReferencesResponse,
  CancelSignResponse,
  ComponentSignRequest,
  ComponentSignResponse,
  GuardedAssemblyRequest,
  GuardedAssemblyResponse,
  GuardedSimulateRequest,
  GuardedSimulateResponse,
} from "../src/types.js";

interface MockFetch {
  (...args: any[]): Promise<any>;
  mock: { calls: any[][] };
  mockResolvedValueOnce(val: any): MockFetch;
  mockReset(): void;
}

function createMockFetch(): MockFetch {
  const calls: any[][] = [];
  const queue: any[] = [];

  const fn = ((...args: any[]) => {
    calls.push(args);
    const entry = queue.shift();
    if (!entry) return Promise.reject(new Error("mock: no queued response"));
    return Promise.resolve(entry);
  }) as MockFetch;

  fn.mock = { calls };
  fn.mockResolvedValueOnce = (val) => {
    queue.push(val);
    return fn;
  };
  fn.mockReset = () => {
    calls.length = 0;
    queue.length = 0;
  };

  return fn;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtureDir = path.resolve(__dirname, "../../contracts/signerapi");
const contractSchemaVersion = 1;
const hashManifestName = "SHA256SUMS";
const contractMetadataFiles = new Set([
  "fixture_manifest.json",
  "error_codes.json",
  "error_code_classifications.json",
]);

function fixture(name: string): any {
  return JSON.parse(fs.readFileSync(path.join(fixtureDir, name), "utf-8"));
}

function committedFixtureNames(): string[] {
  return fs
    .readdirSync(fixtureDir)
    .filter((name) => name.endsWith(".json") && !contractMetadataFiles.has(name))
    .sort();
}

function expectedFixtureNames(): string[] {
  const manifest = fixture("fixture_manifest.json");
  assert.equal(manifest.schema_version, contractSchemaVersion);
  const names = [...manifest.fixtures].sort();
  assert.equal(new Set(names).size, names.length);
  for (const name of names) {
    assert.equal(name.endsWith(".json"), true);
    assert.equal(contractMetadataFiles.has(name), false);
  }
  return names;
}

function sdkErrorCodes(): string[] {
  return Object.values(ErrorCodes).sort();
}

function readHashManifest(): Record<string, string> {
  const hashes: Record<string, string> = {};
  const lines = fs.readFileSync(path.join(fixtureDir, hashManifestName), "utf-8").split(/\r?\n/);
  lines.forEach((rawLine, index) => {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) return;
    const fields = line.split(/\s+/);
    assert.equal(fields.length, 2, `${hashManifestName}:${index + 1}`);
    const [digest, name] = fields;
    assert.match(digest, /^[0-9a-f]{64}$/);
    assert.notEqual(name, hashManifestName);
    assert.equal(path.basename(name), name);
    assert.equal(Object.hasOwn(hashes, name), false);
    hashes[name] = digest;
  });
  return hashes;
}

function computedHashes(): Record<string, string> {
  const hashes: Record<string, string> = {};
  for (const name of fs.readdirSync(fixtureDir)) {
    const fullPath = path.join(fixtureDir, name);
    if (fs.statSync(fullPath).isFile() && name !== hashManifestName) {
      hashes[name] = createHash("sha256").update(fs.readFileSync(fullPath)).digest("hex");
    }
  }
  return hashes;
}

const originalFetch = globalThis.fetch;
const mockFetch = createMockFetch();

describe("signer API contract fixtures", () => {
  beforeEach(() => {
    mockFetch.mockReset();
    globalThis.fetch = mockFetch as any;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("accounts for every committed fixture", () => {
    const expected = expectedFixtureNames();
    assert.deepEqual(committedFixtureNames(), expected);
    for (const name of expected) {
      assert.doesNotThrow(() => fixture(name), name);
    }
  });

  it("matches signer API error-code fixtures", () => {
    const codes = fixture("error_codes.json");
    assert.equal(codes.schema_version, contractSchemaVersion);
    assert.deepEqual([...codes.codes].sort(), sdkErrorCodes());

    const classifications = fixture("error_code_classifications.json");
    assert.equal(classifications.schema_version, contractSchemaVersion);
    assert.deepEqual(Object.keys(classifications.classifications).sort(), sdkErrorCodes());
    for (const classification of Object.values(classifications.classifications)) {
      assert.equal(String(classification).trim().length > 0, true);
    }
  });

  it("matches the contract hash manifest", () => {
    assert.deepEqual(computedHashes(), readHashManifest());
  });

  it("encodes mixed group sign request wire fields", () => {
    const client = new SignerClient("http://localhost:11270", "test-token");
    const signTxn = {
      sender: { toString: () => "SENDERADDR0000000000000000000000000000000000000000000" },
      toByte: () => new Uint8Array([1]),
    };
    const foreignTxn = {
      sender: { toString: () => "FOREIGNADDR000000000000000000000000000000000000000000" },
      toByte: () => new Uint8Array([2]),
    };

    const body = (client as any).buildSignRequestBody(
      [signTxn, null, foreignTxn],
      ["AUTHADDR00000000000000000000000000000000000000000000000", null, null],
      {
        AUTHADDR00000000000000000000000000000000000000000000000: {
          preimage: Buffer.from("secret"),
          recipient: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
        },
      },
      { 1: Buffer.from("82a3736967c440", "hex").toString("base64") },
      { 2: 3035 },
    );

    const expected = fixture("group_sign_request_mixed.json");
    delete expected.requests[0].app_call_info;
    assert.deepEqual(body, expected);
  });

  it("maps /keys wire fields to public KeyInfo fields", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => fixture("keys_response_generic.json"),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const keys = await client.listKeys(true);

    assert.equal(keys.length, 2);
    assert.equal(keys[1].publicKeyHex, "ffeeddccbbaa99887766554433221100");
    assert.equal(keys[1].keyType, "aplane.timed-allowlist.v1");
    assert.equal(keys[1].lsigSize, 512);
    assert.equal(keys[1].isGenericLsig, true);
    assert.equal(keys[1].signingArgs?.[0].name, "preimage");
    assert.equal(keys[1].signingArgs?.[0].label, "Preimage");
    assert.equal(keys[1].signingArgs?.[0].required, true);
    assert.equal(keys[1].signingArgs?.[0].byteLength, 32);
  });

  it("maps /keytypes wire fields to public KeyTypeInfo fields", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => fixture("keytypes_response_full.json"),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const keyTypes = await client.listKeyTypes();
    const timedAllowlist = keyTypes[1];

    assert.equal(timedAllowlist.keyType, "aplane.timed-allowlist.v1");
    assert.equal(timedAllowlist.displayName, "Timed Allowlist");
    assert.equal(timedAllowlist.requiresLogicsig, true);
    assert.equal(timedAllowlist.mnemonicWordCount, 0);
    assert.equal(timedAllowlist.mnemonicImport, false);
    assert.equal(timedAllowlist.creationParams?.[1].paramType, "address[]");
    assert.equal(timedAllowlist.creationParams?.[1].minItems, 1);
    assert.equal(timedAllowlist.creationParams?.[1].maxItems, 8);
    assert.equal(timedAllowlist.creationParams?.[2].min, 1);
    assert.equal(timedAllowlist.creationParams?.[2].max, 999999999);
    assert.equal(timedAllowlist.creationParams?.[3].maxLength, 32);
    assert.equal(timedAllowlist.creationParams?.[3].inputModes?.[1].name, "sha256");
    assert.equal(timedAllowlist.creationParams?.[3].inputModes?.[1].transform, "sha256");
    assert.equal(timedAllowlist.creationParams?.[3].inputModes?.[1].byteLength, 32);
    assert.equal(timedAllowlist.creationParams?.[3].inputModes?.[1].inputType, "bytes");
    assert.equal(timedAllowlist.creationParams?.[4].paramType, "select");
    assert.deepEqual(timedAllowlist.creationParams?.[4].options, ["lab-sentry", "backup-sentry"]);
    assert.equal(timedAllowlist.runtimeArgs?.[0].label, "Preimage");
    assert.equal(timedAllowlist.runtimeArgs?.[0].required, true);
    assert.equal(timedAllowlist.runtimeArgs?.[0].byteLength, 32);
  });

  it("maps /status wire fields to public StatusResponse fields", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => fixture("status_response_ready.json"),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const identity = await client.getStatus();

    assert.equal(identity.identityId, "default");
    assert.equal(identity.nodeRole, "signer");
    assert.deepEqual(identity.protocolVersion, { major: 1, minor: 0 });
    assert.match(identity.buildVersion || "", /^v0\.30\.0 /);
    assert.equal(identity.state, "unlocked");
    assert.equal(identity.signerLocked, false);
    assert.equal(identity.readyForSigning, true);
    assert.equal(identity.keyCount, 37);
    assert.equal(identity.keysetRevision, 4);
    assert.equal(identity.approvalWaitSeconds, 60);
  });

  it("maps /sign/cancel response state", () => {
    const result = fixture("cancel_sign_response_success.json") as CancelSignResponse;

    assert.equal(result.success, true);
    assert.equal(result.state, "canceled");
  });

  it("maps optional /keys template warning fields", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => ({
        count: 1,
        keys: [
          {
            address: "ADDR1",
            public_key_hex: "abcd",
            key_type: "aplane.timed-allowlist.v1",
            template_provenance_status: "conflict",
            template_provenance_note: "template fingerprint differs",
          },
        ],
      }),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const keys = await client.listKeys(true);

    assert.equal(keys[0].templateStatus, "conflict");
    assert.equal(keys[0].templateWarning, "template fingerprint differs");
    assert.equal(keys[0].templateProvenanceStatus, "conflict");
    assert.equal(keys[0].templateProvenanceNote, "template fingerprint differs");
  });

  it("maps sentry component and guarded key metadata", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => fixture("keys_response_component.json"),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const component = (await client.listKeys(true))[0];
    assert.equal(component.keyType, "aplane.sentry-ed25519.v1");
    assert.equal(component.isComponentKey, true);
    assert.equal(component.isSpendingAccount, false);

    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => fixture("keys_response_guarded.json"),
    });
    const guarded = (await client.listKeys(true))[0];
    assert.equal(guarded.keyType, "aplane.falcon1024-sentry-ed25519.v1");
    assert.ok(guarded.parameters?.sentry_public_key);
  });

  it("maps /plan mutation wire fields to public MutationReport fields", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => fixture("group_plan_response_mutated.json"),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const fakeTxn = {
      sender: { toString: () => "SENDERADDR0000000000000000000000000000000000000000000" },
      toByte: () => new Uint8Array([1, 2, 3]),
    };

    const plan = await client.planGroup([fakeTxn as any], [
      "AUTHADDR00000000000000000000000000000000000000000000000",
    ]);

    assert.deepEqual(plan.transactions, ["545801", "545802", "545803"]);
    assert.equal(plan.mutations?.dummiesAdded, 1);
    assert.equal(plan.mutations?.groupIdChanged, true);
    assert.deepEqual(plan.mutations?.feesModified, [0, 2]);
    assert.equal(plan.mutations?.totalFeesDelta, 1000);
    assert.equal(plan.mutations?.originalCount, 2);
    assert.equal(plan.mutations?.finalCount, 3);
    assert.equal(plan.mutations?.foreignCount, 1);
  });

  it("maps /simulate response wire fields", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => fixture("group_simulate_response_mutated.json"),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const simulation = await client.simulateRequests([
      {
        txn_bytes_hex: "545801",
        auth_address: "AUTHADDR00000000000000000000000000000000000000000000000",
      },
    ]);

    assert.deepEqual(simulation.tx_ids, ["SIMTXID1", "SIMTXID2", "SIMTXID3"]);
    assert.deepEqual(simulation.transactions, ["545801", "545802", "545803"]);
    assert.equal(simulation.mutations?.dummiesAdded, 1);
    assert.equal(simulation.mutations?.groupIdChanged, true);
    assert.deepEqual(simulation.mutations?.feesModified, [0, 2]);
    assert.equal(simulation.mutations?.foreignCount, 1);
    assert.equal(simulation.failed, true);
    assert.match(simulation.output ?? "", /Group size: 3/);
  });

  it("maps /admin/generate response fields", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => fixture("admin_generate_response_generic.json"),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const generated = await client.generateKey("aplane.timed-allowlist.v1", {
      unlock_round: "123456",
    });

    assert.equal(generated.address, "GENERATEDADDR0000000000000000000000000000000000000000000");
    assert.equal(generated.keyType, "aplane.timed-allowlist.v1");
    assert.equal(generated.parameters?.unlock_round, "123456");
  });

  it("maps /admin/generate component response fields", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => fixture("admin_generate_response_component.json"),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const generated = await client.generateKey("aplane.sentry-ed25519.v1");

    assert.equal(generated.address, "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ");
    assert.equal(generated.publicKeyHex, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    assert.equal(generated.keyType, "aplane.sentry-ed25519.v1");
    assert.equal(generated.isComponentKey, true);
    assert.equal(generated.isSpendingAccount, false);
  });

  it("round-trips sentry component and assembly fixture DTOs", () => {
    const componentReq = fixture("component_sign_request_sentry.json") as ComponentSignRequest;
    assert.equal(componentReq.role, "sentry");
    assert.equal(componentReq.target_indices[0], 0);

    const componentResp = fixture("component_sign_response_sentry.json") as ComponentSignResponse;
    assert.equal(componentResp.signatures[0].signature_scheme, "aplane.sentry-ed25519.v1");

    const assemblyReq = fixture("guarded_assembly_request_mixed.json") as GuardedAssemblyRequest;
    assert.equal(assemblyReq.targets?.[0].guarded_account, "LOGICSIGACCOUNTADDRESSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    const assemblyResp = fixture("guarded_assembly_response.json") as GuardedAssemblyResponse;
    assert.equal(assemblyResp.signed_group.length, 2);
  });

  it("round-trips guarded simulate fixture DTOs", () => {
    const simulateReq = fixture("guarded_simulate_request_mixed.json") as GuardedSimulateRequest;
    assert.equal(simulateReq.requests.length, 3);
    assert.equal(simulateReq.requests[1].auth_address, "AUTHADDRESSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert.equal(simulateReq.targets[0].guarded_account, "LOGICSIGACCOUNTADDRESSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert.equal(simulateReq.targets[0].sentry_signature, "cccccccccccccccccccccccccccccccc");
    assert.equal(simulateReq.passthrough?.[0].target_index, 2);

    const simulateResp = fixture("guarded_simulate_response.json") as GuardedSimulateResponse;
    assert.equal(simulateResp.tx_ids?.length, 3);
    assert.equal(simulateResp.transactions?.length, 3);
    assert.ok(simulateResp.output?.includes("Simulation successful"));
  });

  it("round-trips admin sentry sync fixture DTOs", () => {
    const syncReq = fixture("admin_sync_sentries_request.json") as AdminSyncSentryReferencesRequest;
    assert.equal(syncReq.candidates[0].key_type, "aplane.sentry-ed25519.v1");

    const syncResp = fixture("admin_sync_sentries_response.json") as AdminSyncSentryReferencesResponse;
    assert.equal(syncResp.added, 1);
    assert.equal(syncResp.records?.[0].source, "client_discovery");
  });
});
