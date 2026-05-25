// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { SignerClient } from "../src/client.js";
import type { CancelSignResponse } from "../src/types.js";

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
const expectedFixtureNames = [
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
];

function fixture(name: string): any {
  return JSON.parse(fs.readFileSync(path.join(fixtureDir, name), "utf-8"));
}

function committedFixtureNames(): string[] {
  return fs.readdirSync(fixtureDir).filter((name) => name.endsWith(".json")).sort();
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
    assert.deepEqual(committedFixtureNames(), expectedFixtureNames);
    for (const name of expectedFixtureNames) {
      assert.doesNotThrow(() => fixture(name), name);
    }
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
    assert.equal(keys[1].keyType, "aplane.timelock.v1");
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
    const timelock = keyTypes[1];

    assert.equal(timelock.keyType, "aplane.timelock.v1");
    assert.equal(timelock.displayName, "Timelock");
    assert.equal(timelock.requiresLogicsig, true);
    assert.equal(timelock.mnemonicWordCount, 0);
    assert.equal(timelock.mnemonicImport, false);
    assert.equal(timelock.creationParams?.[1].paramType, "address[]");
    assert.equal(timelock.creationParams?.[1].minItems, 1);
    assert.equal(timelock.creationParams?.[1].maxItems, 8);
    assert.equal(timelock.creationParams?.[2].min, 1);
    assert.equal(timelock.creationParams?.[2].max, 999999999);
    assert.equal(timelock.creationParams?.[3].maxLength, 32);
    assert.equal(timelock.creationParams?.[3].inputModes?.[1].name, "sha256");
    assert.equal(timelock.creationParams?.[3].inputModes?.[1].transform, "sha256");
    assert.equal(timelock.creationParams?.[3].inputModes?.[1].byteLength, 32);
    assert.equal(timelock.creationParams?.[3].inputModes?.[1].inputType, "bytes");
    assert.equal(timelock.runtimeArgs?.[0].label, "Preimage");
    assert.equal(timelock.runtimeArgs?.[0].required, true);
    assert.equal(timelock.runtimeArgs?.[0].byteLength, 32);
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
            key_type: "aplane.timelock.v1",
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

  it("maps /admin/generate response fields", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => fixture("admin_generate_response_generic.json"),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const generated = await client.generateKey("aplane.timelock.v1", {
      unlock_round: "123456",
    });

    assert.equal(generated.address, "GENERATEDADDR0000000000000000000000000000000000000000000");
    assert.equal(generated.keyType, "aplane.timelock.v1");
    assert.equal(generated.parameters?.unlock_round, "123456");
  });
});
