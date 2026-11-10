// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import algosdk from "algosdk";
import {
  SignerClient,
  boundedFeeCeiling,
  signPreparedCosignedGroup,
  simulatePreparedCosignedGroup,
} from "../src/client.js";
import {
  KEY_TYPE_WITNESS_FALCON1024,
  SIGNING_FLOW_COSIGNED1,
  type BoundedAuthorizationInfo,
} from "../src/types.js";
import {
  AuthenticationError,
  SigningRejectedError,
  SignerUnavailableError,
  SignerError,
  KeyNotFoundError,
  KeyDeletionError,
} from "../src/errors.js";
import { parseEnrollmentReply, requestEnrollment, requestEnrollmentFromEnv } from "../src/utils.js";
import { bytesToHex, hexToBytes, concatenateSignedTxns, encodeTransaction, encodeLsigArgs } from "../src/encoding.js";
import { assembleGroup } from "../src/utils.js";
import {
  loadClientEndpointRegistry,
  loadConfig,
  resolveClientEndpoint,
} from "../src/config.js";
import { preparedGroupToSignRequests } from "../src/prepared.js";
import {
  fakeAddress,
  fakePayment,
  signEntries,
  signedHex,
  signerFetch,
} from "./fakeSigner.js";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as net from "net";
import { generateKeyPairSync } from "node:crypto";

// --- Mock fetch helper ---

interface MockFetch {
  (...args: any[]): Promise<any>;
  mock: { calls: any[][] };
  mockResolvedValueOnce(val: any): MockFetch;
  mockRejectedValueOnce(err: any): MockFetch;
  /** Queue a response computed from the call's arguments. */
  mockImplementationOnce(fn: (...args: any[]) => any): MockFetch;
  mockReset(): void;
}

function createMockFetch(): MockFetch {
  const calls: any[][] = [];
  const queue: Array<{ type: "resolve" | "reject" | "compute"; value: any }> = [];

  const fn = ((...args: any[]) => {
    calls.push(args);
    const entry = queue.shift();
    if (!entry) return Promise.reject(new Error("mock: no queued response"));
    if (entry.type === "reject") return Promise.reject(entry.value);
    if (entry.type === "compute") {
      try {
        return Promise.resolve(entry.value(...args));
      } catch (error) {
        return Promise.reject(error);
      }
    }
    return Promise.resolve(entry.value);
  }) as MockFetch;

  fn.mock = { calls };
  fn.mockResolvedValueOnce = (val) => {
    queue.push({ type: "resolve", value: val });
    return fn;
  };
  fn.mockRejectedValueOnce = (err) => {
    queue.push({ type: "reject", value: err });
    return fn;
  };
  fn.mockImplementationOnce = (impl) => {
    queue.push({ type: "compute", value: impl });
    return fn;
  };
  fn.mockReset = () => {
    calls.length = 0;
    queue.length = 0;
  };

  return fn;
}

// A peer that sends its SSH identification and then closes before the
// handshake completes. ssh2 reports this with close (no error) and clears its
// readyTimeout, so setup must fail on close rather than wait for a deadline.
async function withEarlyClosingSSHPeer(
  prefix: string,
  run: (port: number, keyPath: string, knownHostsPath: string) => Promise<void>,
): Promise<void> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.end("SSH-2.0-aplane-test\r\n");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
  });
  const keyPath = path.join(tmpDir, "id_rsa");
  fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });
  try {
    await run(address.port, keyPath, path.join(tmpDir, "known_hosts"));
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(tmpDir, { recursive: true });
  }
}

function settlesWithin<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const watchdog = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`did not settle within ${ms}ms`)), ms);
  });
  return Promise.race([promise, watchdog]).finally(() => clearTimeout(timer));
}

async function waitForSocketsToClose(sockets: Set<net.Socket>): Promise<void> {
  const deadline = Date.now() + 1_000;
  while (sockets.size > 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function cosignedTestResources() {
  return { programBytes: 1612, argumentBytes: 1423, maxOpcodeCost: 20000 };
}

// --- Setup global fetch mock ---

const originalFetch = globalThis.fetch;
const mockFetch = createMockFetch();
globalThis.fetch = mockFetch as any;

function queueStatusResponse(
  approvalWaitSeconds: number = 60,
  keysetRevision: number = 4,
): void {
  mockFetch.mockResolvedValueOnce({
    status: 200,
    ok: true,
    json: async () => ({
      state: "unlocked",
      signer_locked: false,
      ready_for_signing: true,
      key_count: 37,
      keyset_revision: keysetRevision,
      approval_wait_seconds: approvalWaitSeconds,
    }),
  });
}

function testAddress(seed: number): string {
  const bytes = new Uint8Array(32);
  bytes[31] = seed;
  return algosdk.encodeAddress(bytes);
}

function mockAlgod(accounts: Record<string, any>): any {
  return {
    getTransactionParams: () => ({
      do: async () => ({
        fee: 1000n,
        minFee: 1000n,
        flatFee: false,
        firstValid: 1n,
        lastValid: 100n,
        genesisHash: new Uint8Array(32),
        genesisID: "testnet-v1",
      }),
    }),
    accountInformation: (address: string) => ({
      do: async () => accounts[address],
    }),
  };
}

// Restore on process exit
process.on("exit", () => {
  globalThis.fetch = originalFetch;
});

// --- Tests ---

describe("SignerClient", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  describe("health", () => {
    it("returns true when signer is healthy", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
      });

      const client = new SignerClient("http://localhost:11270");
      const result = await client.health();

      assert.equal(result, true);
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/health");
      assert.equal(mockFetch.mock.calls[0][1].method, "GET");
    });

    it("returns false when signer is unavailable", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 503,
        ok: false,
      });

      const client = new SignerClient("http://localhost:11270");
      const result = await client.health();

      assert.equal(result, false);
    });

    it("returns false on network error", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network error"));

      const client = new SignerClient("http://localhost:11270");
      const result = await client.health();

      assert.equal(result, false);
    });
  });

  describe("getStatus", () => {
    it("returns authenticated signer status", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          state: "unlocked",
          signer_locked: false,
          ready_for_signing: true,
          key_count: 37,
          keyset_revision: 4,
          approval_wait_seconds: 60,
          warnings: ["authenticated prune is required", 7],
        }),
      });

      const client = new SignerClient("http://localhost:11270");
      const status = await client.getStatus();

      assert.equal(status.keysetRevision, 4);
      assert.equal(status.approvalWaitSeconds, 60);
      assert.deepEqual(status.warnings, ["authenticated prune is required"]);
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/status");
      assert.equal(mockFetch.mock.calls[0][1].method, "GET");
    });

    it("returns locked state as successful status data", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          state: "locked",
          signer_locked: true,
          ready_for_signing: false,
          key_count: 0,
          keyset_revision: 2,
        }),
      });

      const client = new SignerClient("http://localhost:11270");
      const status = await client.getStatus();

      assert.equal(status.state, "locked");
      assert.equal(status.signerLocked, true);
      assert.equal(status.readyForSigning, false);
    });

    it("throws AuthenticationError on 401", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 401,
        ok: false,
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(client.getStatus(), AuthenticationError);
    });
  });

  describe("listKeys", () => {
    it("returns list of keys", async () => {
      const mockKeys = {
        count: 2,
        keys: [
          {
            address: "ADDR1",
            public_key_hex: "abc123",
            key_type: "ed25519",
            is_generic_lsig: false,
          },
          {
            address: "ADDR2",
            public_key_hex: "def456",
            key_type: "aplane.falcon1024.v1",
            logic_sig_resources: {
              spend: { program_bytes: 1612, argument_bytes: 1423, max_opcode_cost: 20000 },
            },
            is_generic_lsig: false,
            template_provenance_status: "unavailable",
            template_provenance_note: "template fingerprint unavailable",
          },
        ],
      };

      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => mockKeys,
      });

      const client = new SignerClient("http://localhost:11270");
      const keys = await client.listKeys();

      assert.equal(keys.length, 2);
      assert.equal(keys[0].address, "ADDR1");
      assert.equal(keys[0].keyType, "ed25519");
      assert.equal(keys[1].address, "ADDR2");
      assert.equal(keys[1].logicSigResources?.spend?.programBytes, 1612);
      assert.equal(keys[1].templateProvenanceStatus, "unavailable");
      assert.equal(keys[1].templateProvenanceNote, "template fingerprint unavailable");
    });

    it("throws AuthenticationError on 401", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 401,
        ok: false,
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(client.listKeys(), AuthenticationError);
    });

    it("surfaces signer JSON error bodies", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 500,
        ok: false,
        json: async () => ({ error: "inventory unavailable" }),
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(client.listKeys(true), /inventory unavailable/);
    });

    it("uses cache on subsequent calls", async () => {
      const mockKeys = {
        count: 1,
        keys: [{ address: "ADDR1", key_type: "ed25519" }],
      };

      mockFetch
        .mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: async () => mockKeys,
        })
        .mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: async () => mockKeys,
        });

      const client = new SignerClient("http://localhost:11270");

      // First call fetches from server
      await client.listKeys();
      assert.equal(mockFetch.mock.calls.length, 1);

      // Second call uses cache
      await client.listKeys();
      assert.equal(mockFetch.mock.calls.length, 1);

      // Third call with refresh fetches again
      await client.listKeys(true);
      assert.equal(mockFetch.mock.calls.length, 2);
    });
  });

  describe("auth resolution", () => {
    const keysResponse = (...addresses: string[]) => ({
      status: 200,
      ok: true,
      json: async () => ({
        count: addresses.length,
        keys: addresses.map((address) => ({ address, key_type: "ed25519" })),
      }),
    });

    it("refreshes keys only when keyset revision changes", async () => {
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse("ADDR1"));
      queueStatusResponse(60, 1);
      queueStatusResponse(60, 2);
      mockFetch.mockResolvedValueOnce(keysResponse("ADDR2"));

      const client = new SignerClient("http://localhost:11270");
      const first = await client.listKeysIfKeysetChanged();
      const second = await client.listKeysIfKeysetChanged();
      const third = await client.listKeysIfKeysetChanged();

      assert.deepEqual(first.map((key) => key.address), ["ADDR1"]);
      assert.deepEqual(second.map((key) => key.address), ["ADDR1"]);
      assert.deepEqual(third.map((key) => key.address), ["ADDR2"]);
      assert.equal(
        mockFetch.mock.calls.filter((call) => call[0] === "http://localhost:11270/keys").length,
        2,
      );
    });

    it("resolves self-signing accounts", async () => {
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse("SENDER"));

      const client = new SignerClient("http://localhost:11270");
      const resolved = await client.resolveAuthAddress("SENDER", () => ({}));

      assert.equal(resolved.address, "SENDER");
      assert.equal(resolved.authAddress, "SENDER");
      assert.equal(resolved.isRekeyed, false);
      assert.equal(resolved.keyInfo.address, "SENDER");
    });

    it("resolves rekeyed accounts", async () => {
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse("AUTH"));

      const client = new SignerClient("http://localhost:11270");
      const resolved = await client.resolveAuthAddress(
        "SENDER",
        () => ({ "auth-addr": "AUTH" }),
      );

      assert.equal(resolved.address, "SENDER");
      assert.equal(resolved.authAddress, "AUTH");
      assert.equal(resolved.isRekeyed, true);
      assert.equal(resolved.keyInfo.address, "AUTH");
    });

    // Audit finding 25: algosdk v3 account models carry the auth address as
    // an Address object, which never compares equal to an address string.
    it("resolves rekeyed accounts from an algosdk account model", async () => {
      const sender = testAddress(1);
      const auth = testAddress(2);
      const account = new algosdk.modelsv2.Account({
        address: sender,
        amount: 2_000_000,
        amountWithoutPendingRewards: 2_000_000,
        minBalance: 100_000,
        pendingRewards: 0,
        rewards: 0,
        round: 1,
        status: "Offline",
        totalAppsOptedIn: 0,
        totalAssetsOptedIn: 0,
        totalCreatedApps: 0,
        totalCreatedAssets: 0,
        authAddr: auth,
      });
      assert.ok(account.authAddr instanceof algosdk.Address);
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(auth));

      const client = new SignerClient("http://localhost:11270");
      const resolved = await client.resolveAuthAddress(sender, () => account as any);

      assert.equal(resolved.authAddress, auth);
      assert.equal(typeof resolved.authAddress, "string");
      assert.equal(resolved.isRekeyed, true);
      assert.equal(resolved.keyInfo.address, auth);
    });

    it("treats an account model whose auth address is its own address as not rekeyed", async () => {
      const sender = testAddress(1);
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const resolved = await client.resolveAuthAddress(
        sender,
        () => ({ authAddr: algosdk.Address.fromString(sender) }),
      );

      assert.equal(resolved.authAddress, sender);
      assert.equal(resolved.isRekeyed, false);
    });

    it("rejects rekeyed accounts whose auth address is not signable", async () => {
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse("SENDER"));

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.resolveAuthAddress("SENDER", () => ({ "auth-addr": "AUTH" })),
        /not signable/,
      );
    });
  });

  describe("prep helpers", () => {
    const keysResponse = (address: string) => ({
      status: 200,
      ok: true,
      json: async () => ({
        count: 1,
        keys: [{ address, key_type: "ed25519" }],
      }),
    });

    it("prepares payment transactions", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.preparePayment(algod, {
        sender,
        receiver,
        amount: 10_000,
        fee: 1000,
      });

      assert.equal(prepared.authAddress, sender);
      assert.equal(prepared.signerKey?.address, sender);
      assert.equal((prepared.transaction as any).payment.receiver.toString(), receiver);
      assert.equal(String((prepared.transaction as any).fee), "1000");
      assert.equal(prepared.checks?.[0].name, "payment_balance");
    });

    it("prepares a payment for a rekeyed sender whose auth address is an Address object", async () => {
      const sender = testAddress(1);
      const auth = testAddress(3);
      const receiver = testAddress(2);
      const algod = mockAlgod({
        [sender]: {
          amount: 2_000_000,
          minBalance: 100_000,
          authAddr: algosdk.Address.fromString(auth),
        },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(auth));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.preparePayment(algod, {
        sender,
        receiver,
        amount: 10_000,
        fee: 1000,
      });

      assert.equal(prepared.authAddress, auth);
      assert.equal(prepared.signerKey?.address, auth);
      assert.equal((prepared.transaction as any).sender.toString(), sender);
    });

    it("treats a set fee as flat microAlgos", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({ [sender]: { amount: 2_000_000, minBalance: 100_000 } });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.preparePayment(algod, {
        sender,
        receiver,
        amount: 10_000,
        fee: 5000, // must be a flat 5000, never EstimateSize*5000
      });

      assert.equal(String((prepared.transaction as any).fee), "5000");
    });

    it("applies an explicit zero fee as a flat zero", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({ [sender]: { amount: 2_000_000, minBalance: 100_000 } });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.preparePayment(algod, {
        sender,
        receiver,
        amount: 10_000,
        fee: 0,
      });

      assert.equal(String((prepared.transaction as any).fee), "0");
    });

    it("rejects payment transactions with insufficient funds", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({
        [sender]: { amount: 101_000, minBalance: 100_000 },
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.preparePayment(algod, { sender, receiver, amount: 10_000 }),
        /insufficient funds/,
      );
    });

    it("checks payment sufficiency exactly above 2^53 microAlgos", async () => {
      // balance 2^53, amount 2^53 + 1: a Number()-based check rounds the amount
      // down to 2^53 and would wrongly accept; the BigInt check rejects.
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({
        [sender]: { amount: 9007199254740992n, minBalance: 0n },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.preparePayment(algod, {
          sender,
          receiver,
          amount: 9007199254740993n,
          fee: 0,
        }),
        /insufficient funds/,
      );
    });

    it("prepares ASA transfer transactions", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({
        [sender]: {
          amount: 2_000_000,
          minBalance: 100_000,
          assets: [{ assetId: 1001, amount: 25 }],
        },
        [receiver]: {
          amount: 2_000_000,
          minBalance: 100_000,
          assets: [{ assetId: 1001, amount: 0 }],
        },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.prepareAsaTransfer(algod, {
        sender,
        receiver,
        assetId: 1001,
        amount: 5,
      });

      assert.equal(prepared.authAddress, sender);
      assert.equal(prepared.signerKey?.address, sender);
      assert.equal(String((prepared.transaction as any).assetTransfer.assetIndex), "1001");
      assert.equal(String((prepared.transaction as any).assetTransfer.amount), "5");
      assert.equal(prepared.checks?.[0].name, "asa_transfer");
    });

    it("rejects ASA transfers when the receiver is not opted in", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({
        [sender]: {
          amount: 2_000_000,
          minBalance: 100_000,
          assets: [{ assetId: 1001, amount: 25 }],
        },
        [receiver]: {
          amount: 2_000_000,
          minBalance: 100_000,
          assets: [],
        },
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.prepareAsaTransfer(algod, {
          sender,
          receiver,
          assetId: 1001,
          amount: 5,
        }),
        /receiver is not opted into asset/,
      );
    });

    it("prepares ASA opt-ins", async () => {
      const sender = testAddress(1);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.prepareAsaOptIn(algod, {
        sender,
        assetId: 1001,
      });

      const assetTransfer = (prepared.transaction as any).assetTransfer;
      assert.equal(assetTransfer.receiver.toString(), sender);
      assert.equal(String(assetTransfer.amount), "0");
      assert.equal(prepared.checks?.[0].name, "asa_opt_in");
    });

    it("prepares ASA opt-outs", async () => {
      const sender = testAddress(1);
      const closeTo = testAddress(2);
      const algod = mockAlgod({
        [sender]: {
          amount: 2_000_000,
          minBalance: 100_000,
          assets: [{ assetId: 1001, amount: 25 }],
        },
        [closeTo]: {
          amount: 2_000_000,
          minBalance: 100_000,
          assets: [{ assetId: 1001, amount: 0 }],
        },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.prepareAsaOptOut(algod, {
        sender,
        assetId: 1001,
        closeTo,
      });

      const assetTransfer = (prepared.transaction as any).assetTransfer;
      assert.equal(assetTransfer.closeRemainderTo.toString(), closeTo);
      assert.equal(prepared.checks?.[0].name, "asa_opt_out");
    });

    it("prepares account closes", async () => {
      const sender = testAddress(1);
      const closeTo = testAddress(2);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.prepareAccountClose(algod, {
        sender,
        closeTo,
      });

      assert.equal((prepared.transaction as any).payment.closeRemainderTo.toString(), closeTo);
      assert.equal(prepared.checks?.[0].name, "account_close");
    });

    it("rejects account closes with ASA holdings", async () => {
      const sender = testAddress(1);
      const closeTo = testAddress(2);
      const algod = mockAlgod({
        [sender]: {
          amount: 2_000_000,
          minBalance: 100_000,
          assets: [{ assetId: 1001, amount: 0 }],
        },
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.prepareAccountClose(algod, { sender, closeTo }),
        /ASA holdings/,
      );
    });

    it("prepares rekeys", async () => {
      const sender = testAddress(1);
      const rekeyTo = testAddress(2);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
        [rekeyTo]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.prepareRekey(algod, { sender, rekeyTo });

      assert.equal((prepared.transaction as any).rekeyTo.toString(), rekeyTo);
      assert.equal(prepared.checks?.[0].name, "rekey");
    });

    for (const [flow, want] of [
      ["rotating1", /rotating account/],
      ["rotating2", /signing flow "rotating2"/],
    ] as const) {
      it(`refuses rekeys to a ${flow} signer key`, async () => {
        const sender = testAddress(1);
        const rekeyTo = testAddress(2);
        const algod = mockAlgod({
          [sender]: { amount: 2_000_000, minBalance: 100_000 },
          [rekeyTo]: { amount: 2_000_000, minBalance: 100_000 },
        });
        queueStatusResponse(60, 1);
        mockFetch.mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: async () => ({
            count: 2,
            keys: [
              { address: sender, key_type: "ed25519" },
              { address: rekeyTo, key_type: "test.rotating", signing_flow: flow },
            ],
          }),
        });

        const client = new SignerClient("http://localhost:11270");
        await assert.rejects(client.prepareRekey(algod, { sender, rekeyTo }), want);
      });
    }

    it("rejects rekey chains", async () => {
      const sender = testAddress(1);
      const rekeyTo = testAddress(2);
      const other = testAddress(3);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
        [rekeyTo]: { amount: 2_000_000, minBalance: 100_000, authAddr: other },
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.prepareRekey(algod, { sender, rekeyTo }),
        /rekey target is itself rekeyed/,
      );
    });

    // The mode is always explicit, so a forgotten key never takes an account
    // offline.
    it("requires a keyreg mode", async () => {
      const sender = testAddress(1);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.prepareKeyreg(algod, { sender } as any),
        /mode is required: "online" or "offline"/,
      );
      await assert.rejects(
        client.prepareKeyreg(algod, { sender, mode: "part" } as any),
        /mode "part" is not "online" or "offline"/,
      );
    });

    it("requires participation keys for an online keyreg", async () => {
      const sender = testAddress(1);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.prepareKeyreg(algod, { sender, mode: "online" }),
        /voteKey is required/,
      );
      // The network refuses an online keyreg without a state proof key.
      await assert.rejects(
        client.prepareKeyreg(algod, { ...onlineKeyreg(sender), stateProofKey: undefined }),
        /stateProofKey is required/,
      );
    });

    // The fee, including the 2 ALGO incentive fee, must be payable without
    // going below the minimum balance.
    it("refuses an unaffordable keyreg fee", async () => {
      const sender = testAddress(1);
      const algod = mockAlgod({
        [sender]: { amount: 1_600_000, minBalance: 100_000 },
      });
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.prepareKeyreg(algod, { ...onlineKeyreg(sender), incentiveEligible: true }),
        /insufficient funds for keyreg fee: available 1500000, fee 2000000/,
      );
    });

    // Like Go, 0 and an empty key count as unset on an offline keyreg.
    it("treats empty participation fields as unset on an offline keyreg", async () => {
      const sender = testAddress(1);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));
      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.prepareKeyreg(algod, {
        sender,
        mode: "offline",
        voteKey: "",
        selectionKey: new Uint8Array(0),
        voteFirst: 0,
        voteLast: 0n,
        voteKeyDilution: 0,
      });
      assert.deepEqual(prepared.checks[0].data, { mode: "offline" });
    });

    const onlineKeyreg = (sender: string) => ({
      sender,
      mode: "online" as const,
      voteKey: new Uint8Array(32).fill(1),
      selectionKey: new Uint8Array(32).fill(1),
      stateProofKey: new Uint8Array(64).fill(2),
      voteFirst: 10,
      voteLast: 20,
      voteKeyDilution: 5,
    });

    it("prepares online keyreg", async () => {
      const sender = testAddress(1);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.prepareKeyreg(algod, onlineKeyreg(sender));

      const keyreg = (prepared.transaction as any).keyreg;
      assert.equal(String(keyreg.voteFirst), "10");
      assert.equal(String(keyreg.voteLast), "20");
      assert.equal(keyreg.nonParticipation, false);
      assert.ok(prepared.transaction.fee < 2_000_000n);
      assert.equal(prepared.checks[0].data?.mode, "online");
      assert.equal(prepared.checks[0].data?.incentiveFeeCharged, false);
    });

    it("prepares offline keyreg", async () => {
      const sender = testAddress(1);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.prepareKeyreg(algod, { sender, mode: "offline" });

      const keyreg = (prepared.transaction as any).keyreg;
      assert.equal(prepared.transaction.type, algosdk.TransactionType.keyreg);
      assert.equal(keyreg.voteKey, undefined);
      assert.equal(keyreg.selectionKey, undefined);
      assert.equal(keyreg.stateProofKey, undefined);
      assert.equal(keyreg.voteFirst, undefined);
      assert.equal(keyreg.nonParticipation, false);
      assert.deepEqual(prepared.checks[0].data, { mode: "offline" });
    });

    // Offline with any participation field, or with incentive eligibility, is
    // contradictory, so it is refused rather than building either registration.
    it("refuses online fields on an offline keyreg", async () => {
      const sender = testAddress(1);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      const client = new SignerClient("http://localhost:11270");
      const key32 = new Uint8Array(32).fill(1);
      const key64 = new Uint8Array(64).fill(2);
      const cases: [RegExp, Record<string, unknown>][] = [
        [/but voteKey is set/, { voteKey: key32 }],
        [/but selectionKey is set/, { selectionKey: key32 }],
        [/but stateProofKey is set/, { stateProofKey: key64 }],
        [/but voteFirst is set/, { voteFirst: 1 }],
        [/but voteLast is set/, { voteLast: 100 }],
        [/but voteKeyDilution is set/, { voteKeyDilution: 10 }],
        [/incentive eligibility needs an online keyreg/, { incentiveEligible: true }],
      ];
      for (const [want, extra] of cases) {
        await assert.rejects(client.prepareKeyreg(algod, { sender, mode: "offline", ...extra }), want);
      }
    });

    // Incentive eligibility raises the fee to the protocol's 2 ALGO, unless
    // the account is already eligible: an online re-registration keeps it.
    for (const tc of [
      { name: "not yet eligible", alreadyEligible: false, fee: undefined, wantFee: 2_000_000n, charged: true },
      { name: "a higher explicit fee is kept", alreadyEligible: false, fee: 3_000_000, wantFee: 3_000_000n, charged: true },
      { name: "already eligible", alreadyEligible: true, fee: undefined, wantFee: undefined, charged: false },
    ]) {
      it(`prepares incentive-eligible keyreg: ${tc.name}`, async () => {
        const sender = testAddress(1);
        const algod = mockAlgod({
          [sender]: { amount: 5_000_000, minBalance: 100_000, incentiveEligible: tc.alreadyEligible },
        });
        queueStatusResponse(60, 1);
        mockFetch.mockResolvedValueOnce(keysResponse(sender));

        const client = new SignerClient("http://localhost:11270");
        const prepared = await client.prepareKeyreg(algod, {
          ...onlineKeyreg(sender),
          incentiveEligible: true,
          fee: tc.fee,
        });

        if (tc.wantFee === undefined) {
          assert.ok(prepared.transaction.fee < 2_000_000n, `fee ${prepared.transaction.fee} was raised`);
        } else {
          assert.equal(prepared.transaction.fee, tc.wantFee);
        }
        assert.equal(prepared.checks[0].data?.incentiveEligible, true);
        assert.equal(prepared.checks[0].data?.incentiveFeeCharged, tc.charged);
        assert.ok(prepared.checks[0].message);
      });
    }

    // An explicit fee below the 2 ALGO the protocol needs is refused, not
    // overridden.
    it("refuses a low explicit fee on an incentive-eligible keyreg", async () => {
      const sender = testAddress(1);
      const algod = mockAlgod({
        [sender]: { amount: 5_000_000, minBalance: 100_000 },
      });
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.prepareKeyreg(algod, { ...onlineKeyreg(sender), incentiveEligible: true, fee: 0 }),
        /incentive eligibility needs a keyreg fee of at least 2000000 microAlgos, but fee is set to 0/,
      );
    });

    it("prepares raw app calls with app call info", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.prepareAppCall(algod, {
        sender,
        appId: 7,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [new Uint8Array([1, 2, 3])],
        accounts: [receiver],
        foreignApps: [8],
        foreignAssets: [1001],
        fee: 1000,
      });

      const appCall = (prepared.transaction as any).applicationCall;
      assert.equal(prepared.authAddress, sender);
      assert.equal(String(appCall.appIndex), "7");
      assert.deepEqual(Array.from(appCall.appArgs[0]), [1, 2, 3]);
      assert.equal(appCall.accounts[0].toString(), receiver);
      assert.equal(prepared.appCallInfo?.mode, "raw");
      assert.equal(prepared.checks?.[0].name, "app_call");
      assert.equal(preparedGroupToSignRequests({ transactions: [prepared] })[0].app_call_info?.mode, "raw");
    });

    it("prepares ABI app calls with selector and reference args", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.prepareAbiAppCall(algod, {
        sender,
        appId: 7,
        methodSignature: "do(uint64,string,account,application,asset)void",
        args: [42, "hi", receiver, 8, 1002],
        foreignApps: [9],
        foreignAssets: [1001],
      });

      const appCall = (prepared.transaction as any).applicationCall;
      assert.equal(prepared.appCallInfo?.mode, "abi");
      assert.equal(prepared.appCallInfo?.method, "do(uint64,string,account,application,asset)void");
      assert.equal(appCall.appArgs.length, 6);
      assert.equal(appCall.appArgs[0].length, 4);
      assert.equal(appCall.accounts[0].toString(), receiver);
      assert.deepEqual(appCall.foreignApps.map(String), ["9", "8"]);
      assert.deepEqual(appCall.foreignAssets.map(String), ["1001", "1002"]);
      assert.deepEqual(Array.from(appCall.appArgs[3]), [1]);
      assert.deepEqual(Array.from(appCall.appArgs[4]), [2]);
      assert.deepEqual(Array.from(appCall.appArgs[5]), [1]);
      assert.equal(
        preparedGroupToSignRequests({ transactions: [prepared] })[0].app_call_info?.method,
        "do(uint64,string,account,application,asset)void",
      );
    });

    it("prepares app deploys", async () => {
      const sender = testAddress(1);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270");
      const prepared = await client.prepareAppDeploy(algod, {
        sender,
        approvalProgram: new Uint8Array([1, 2]),
        clearProgram: new Uint8Array([1]),
        numGlobalInts: 1,
        numLocalByteSlices: 1,
        extraPages: 1,
      });

      assert.equal(String((prepared.transaction as any).applicationCall.appIndex), "0");
      assert.equal(prepared.appCallInfo?.mode, "raw");
      assert.equal(prepared.checks?.[0].name, "app_deploy");
    });

    it("prepares sweep groups", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({
        [sender]: {
          amount: 2_000_000,
          minBalance: 100_000,
          assets: [{ assetId: 1001, amount: 25 }],
        },
        [receiver]: {
          amount: 2_000_000,
          minBalance: 100_000,
          assets: [{ assetId: 1001, amount: 0 }],
        },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));
      queueStatusResponse(60, 1);

      const client = new SignerClient("http://localhost:11270");
      const group = await client.prepareSweepGroup(algod, {
        asaTransfers: [{ sender, receiver, assetId: 1001, amount: 5 }],
        payments: [{ sender, receiver, amount: 10_000 }],
      });

      assert.equal(group.transactions.length, 2);
      assert.equal(group.checks?.[0].name, "sweep_group");
    });

    it("prepares payment groups in caller order", async () => {
      const sender = testAddress(1);
      const receiver1 = testAddress(2);
      const receiver2 = testAddress(3);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));
      queueStatusResponse(60, 1);

      const client = new SignerClient("http://localhost:11270");
      const group = await client.preparePaymentGroup(algod, [
        { sender, receiver: receiver1, amount: 10_000 },
        { sender, receiver: receiver2, amount: 20_000 },
      ]);

      assert.equal(group.transactions.length, 2);
      assert.equal((group.transactions[0].transaction as any).payment.receiver.toString(), receiver1);
      assert.equal((group.transactions[1].transaction as any).payment.receiver.toString(), receiver2);
      assert.equal(group.checks?.[0].name, "payment_group");
      assert.equal(group.checks?.[1].name, "payment_group_balance");
    });

    it("rejects payment groups with aggregate insufficient funds", async () => {
      const sender = testAddress(1);
      const receiver1 = testAddress(2);
      const receiver2 = testAddress(3);
      const algod = mockAlgod({
        [sender]: { amount: 121_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));
      queueStatusResponse(60, 1);

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.preparePaymentGroup(algod, [
          { sender, receiver: receiver1, amount: 10_000, fee: 1000 },
          { sender, receiver: receiver2, amount: 10_000, fee: 1000 },
        ]),
        /payment group insufficient funds/,
      );
    });

    it("prepares ASA transfer groups in caller order", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({
        [sender]: {
          amount: 2_000_000,
          minBalance: 100_000,
          assets: [{ assetId: 1001, amount: 25 }],
        },
        [receiver]: {
          amount: 2_000_000,
          minBalance: 100_000,
          assets: [{ assetId: 1001, amount: 0 }],
        },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));
      queueStatusResponse(60, 1);

      const client = new SignerClient("http://localhost:11270");
      const group = await client.prepareAsaTransferGroup(algod, [
        { sender, receiver, assetId: 1001, amount: 5 },
        { sender, receiver, assetId: 1001, amount: 7 },
      ]);

      assert.equal(group.transactions.length, 2);
      assert.equal(String((group.transactions[0].transaction as any).assetTransfer.amount), "5");
      assert.equal(String((group.transactions[1].transaction as any).assetTransfer.amount), "7");
      assert.equal(group.checks?.[0].name, "asa_transfer_group");
      assert.equal(group.checks?.[1].name, "asa_transfer_group_balance");
    });

    it("rejects ASA transfer groups with aggregate insufficient asset balance", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({
        [sender]: {
          amount: 2_000_000,
          minBalance: 100_000,
          assets: [{ assetId: 1001, amount: 10 }],
        },
        [receiver]: {
          amount: 2_000_000,
          minBalance: 100_000,
          assets: [{ assetId: 1001, amount: 0 }],
        },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));
      queueStatusResponse(60, 1);

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.prepareAsaTransferGroup(algod, [
          { sender, receiver, assetId: 1001, amount: 6 },
          { sender, receiver, assetId: 1001, amount: 6 },
        ]),
        /ASA transfer group insufficient asset balance/,
      );
    });

    it("builds payment-first payment plus app-call groups", () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const suggestedParams = {
        fee: 1000n,
        minFee: 1000n,
        flatFee: true,
        firstValid: 1n,
        lastValid: 100n,
        genesisHash: new Uint8Array(32),
        genesisID: "testnet-v1",
      };
      const paymentTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender,
        receiver,
        amount: 1,
        suggestedParams,
      });
      const appTxn = algosdk.makeApplicationCallTxnFromObject({
        sender,
        appIndex: 7,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        suggestedParams,
      });

      const client = new SignerClient("http://localhost:11270");
      const group = client.preparePaymentAppCallGroup(
        { transaction: paymentTxn, authAddress: "PAY_AUTH" },
        { transaction: appTxn, authAddress: "APP_AUTH", appCallInfo: { mode: "raw" } },
      );

      assert.equal(group.transactions.length, 2);
      assert.equal(group.transactions[0].authAddress, "PAY_AUTH");
      assert.equal(group.transactions[1].appCallInfo?.mode, "raw");
      assert.equal(group.checks?.[0].name, "payment_app_call_order");
    });
  });

  describe("listKeyTypes", () => {
    it("returns list of key types", async () => {
      const mockKeyTypes = {
        key_types: [
          {
            key_type: "ed25519",
            family: "ed25519",
            display_name: "Ed25519",
            description: "Standard Ed25519 key",
            requires_logicsig: false,
            mnemonic_import: true,
          },
          {
            key_type: "aplane.falcon1024.v1",
            family: "falcon",
            display_name: "Falcon-1024",
            requires_logicsig: true,
            mnemonic_import: true,
            creation_params: [
              { name: "network", label: "Network", type: "string", required: true },
              {
                name: "recipients",
                label: "Recipients",
                type: "address[]",
                required: true,
              },
            ],
          },
        ],
      };

      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => mockKeyTypes,
      });

      const client = new SignerClient("http://localhost:11270");
      const types = await client.listKeyTypes();

      assert.equal(types.length, 2);
      assert.equal(types[0].keyType, "ed25519");
      assert.equal(types[0].family, "ed25519");
      assert.equal(types[0].requiresLogicsig, false);
      assert.equal(types[0].mnemonicImport, true);
      assert.equal(types[1].keyType, "aplane.falcon1024.v1");
      assert.equal(types[1].mnemonicImport, true);
      assert.equal(types[1].creationParams!.length, 2);
      assert.equal(types[1].creationParams![0].name, "network");
      assert.equal(types[1].creationParams![0].required, true);
      assert.equal(types[1].creationParams![1].paramType, "address[]");
    });

    it("throws AuthenticationError on 401", async () => {
      mockFetch.mockResolvedValueOnce({ status: 401, ok: false });
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(client.listKeyTypes(), AuthenticationError);
    });
  });

  describe("generateKey", () => {
    it("generates a key and returns result", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          address: "NEWADDR123",
          key_type: "ed25519",
        }),
      });

      const client = new SignerClient("http://localhost:11270");
      const result = await client.generateKey("ed25519");

      assert.equal(result.address, "NEWADDR123");
      assert.equal(result.keyType, "ed25519");
    });

    it("passes parameters to server", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          address: "NEWADDR456",
          key_type: "aplane.falcon1024.v1",
          parameters: { network: "testnet" },
        }),
      });

      const client = new SignerClient("http://localhost:11270");
      const result = await client.generateKey("aplane.falcon1024.v1", { network: "testnet" });

      assert.equal(result.address, "NEWADDR456");
      assert.deepEqual(result.parameters, { network: "testnet" });

      // Verify request body
      const callArgs = mockFetch.mock.calls[0];
      const body = JSON.parse(callArgs[1].body);
      assert.equal(body.key_type, "aplane.falcon1024.v1");
      assert.deepEqual(body.parameters, { network: "testnet" });
    });

    it("throws on 401", async () => {
      mockFetch.mockResolvedValueOnce({ status: 401, ok: false });
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(client.generateKey("ed25519"), AuthenticationError);
    });

    for (const [label, mock] of [
      ["no body", { status: 403, ok: false }],
      ["an uncoded body", {
        status: 403,
        ok: false,
        json: async () => ({ error: "forbidden" }),
      }],
    ] as const) {
      it(`treats 403 with ${label} as a generic error, not locked`, async () => {
        mockFetch.mockResolvedValueOnce(mock);
        const client = new SignerClient("http://localhost:11270");
        await assert.rejects(client.generateKey("ed25519"), (error: unknown) => {
          assert.ok(error instanceof SignerError);
          assert.ok(!(error instanceof SignerUnavailableError));
          assert.equal(error.code, "");
          return true;
        });
      });
    }

    it("treats 403 with locked code as locked", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 403,
        ok: false,
        json: async () => ({ error: "signer is locked", code: "locked" }),
      });
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(client.generateKey("ed25519"), (err: unknown) => {
        assert.ok(err instanceof SignerUnavailableError);
        assert.equal(err.code, "locked");
        return true;
      });
    });

    it("does not treat 403 with forbidden code as locked", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 403,
        ok: false,
        json: async () => ({
          error: "key generation not allowed for node role",
          code: "forbidden",
        }),
      });
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(client.generateKey("ed25519"), (err: unknown) => {
        assert.ok(err instanceof SignerError);
        assert.ok(!(err instanceof SignerUnavailableError));
        assert.equal(err.code, "forbidden");
        assert.equal(err.message, "key generation not allowed for node role");
        return true;
      });
    });
  });

  describe("deleteKey", () => {
    it("deletes a key successfully", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({}),
      });

      const client = new SignerClient("http://localhost:11270");
      const result = await client.deleteKey("ADDR_TO_DELETE");
      assert.equal(result, undefined);
    });

    it("throws KeyDeletionError on 404", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 404,
        ok: false,
        json: async () => ({ error: "Key not found: MISSING" }),
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(client.deleteKey("MISSING"), KeyDeletionError);
    });

    it("throws on 401", async () => {
      mockFetch.mockResolvedValueOnce({ status: 401, ok: false });
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(client.deleteKey("ADDR"), AuthenticationError);
    });
  });

  describe("specialized low-level endpoints", () => {
    it("posts component signing requests to /sign/component", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          request_id: "sdk-generated",
          components: [
            {
              target_index: 0,
              kind: "cosigner",
              signature: "aabb",
              signature_scheme: KEY_TYPE_WITNESS_FALCON1024,
            },
          ],
        }),
      });

      const client = new SignerClient("http://localhost:11270");
      const result = await client.requestComponents({
        request_id: "sdk-generated",
        group_bytes_hex: ["5458aa"],
        targets: [{ target_index: 0, kind: "cosigner", component_key: "COMPONENT" }],
      });

      assert.equal(result.components[0].signature, "aabb");
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/sign/component");
      assert.equal(mockFetch.mock.calls[0][1].method, "POST");
      // The SSH connection carries the client's identity; no header does.
      assert.equal(mockFetch.mock.calls[0][1].headers.Authorization, undefined);
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      assert.match(body.request_id, /^sdk-/);
      assert.equal(body.targets[0].kind, "cosigner");
      assert.equal(body.targets[0].component_key, "COMPONENT");
    });

    it("rejects a cosigner key on the deny-all default", async () => {
      const witnessKeyId = "A".repeat(52);
      const message = "cosigner policy rejected request: txn 1: [transaction_type:pay] "
        + "pay transactions are rejected by policy";
      mockFetch.mockResolvedValueOnce({
        status: 403,
        ok: false,
        json: async () => ({ error: message, code: "forbidden" }),
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.requestComponents({
          group_bytes_hex: ["5458aa"],
          targets: [{ target_index: 0, kind: "cosigner", component_key: witnessKeyId }],
        }),
        (error: unknown) => {
          assert.ok(error instanceof SigningRejectedError);
          assert.equal(error.code, "forbidden");
          assert.equal(error.message, message);
          return true;
        },
      );
      assert.equal(mockFetch.mock.calls.length, 1);
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/sign/component");
    });

    it("rejects malformed component signing responses", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ request_id: "sdk-test" }),
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.requestComponents({
          group_bytes_hex: ["5458aa"],
          targets: [{ target_index: 0, kind: "cosigner" }],
        }),
        { message: /invalid component response: components array is empty/ },
      );
    });

    it("rejects component signatures for unrequested targets", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          request_id: "sdk-component",
          components: [{
            target_index: 1,
            kind: "cosigner",
            signature: "aabb",
            signature_scheme: KEY_TYPE_WITNESS_FALCON1024,
          }],
        }),
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.requestComponents({
          request_id: "sdk-component",
          group_bytes_hex: ["5458aa", "5458bb"],
          targets: [{ target_index: 0, kind: "cosigner" }],
          contextual_positions: [{ target_index: 1 }],
        }),
        { message: /indices or kinds do not match request/ },
      );
    });

    it("rejects component signatures outside the frozen group", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          request_id: "sdk-component",
          components: [{
            target_index: 2,
            kind: "cosigner",
            signature: "aabb",
            signature_scheme: KEY_TYPE_WITNESS_FALCON1024,
          }],
        }),
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.requestComponents({
          request_id: "sdk-component",
          group_bytes_hex: ["5458aa"],
          targets: [{ target_index: 0, kind: "cosigner", component_key: "COMPONENT" }],
        }),
        { message: /invalid component response: component 1 target_index is outside the frozen group/ },
      );
    });

    it("posts cosigned assembly requests to /sign/assemble", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          request_id: "sdk-assembly",
          signed_group: ["ccdd"],
        }),
      });

      const client = new SignerClient("http://localhost:11270");
      const result = await client.requestAssemble({
        group_bytes_hex: ["5458aa"],
        targets: [
          {
            target_index: 0,
            kind: "bounded-cosigner",
            auth_address: "BOUNDED",
            base_signatures: ["aabb"],
            assembly_receipt: "eeff",
            cosigner_signature: "bbcc",
          },
        ],
      });

      assert.deepEqual(result.signed_group, ["ccdd"]);
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/sign/assemble");
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      assert.match(body.request_id, /^sdk-/);
      assert.equal(body.targets[0].kind, "bounded-cosigner");
      assert.equal(body.targets[0].auth_address, "BOUNDED");
    });

    it("rejects cosigned assembly requests with missing coverage before fetch", async () => {
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.requestAssemble({
          group_bytes_hex: ["5458aa", "5458bb"],
          targets: [
            {
              target_index: 0,
              kind: "bounded-cosigner",
              auth_address: "BOUNDED",
              base_signatures: ["aabb"],
              assembly_receipt: "eeff",
              cosigner_signature: "bbcc",
            },
          ],
        }),
        { message: /not covered/ },
      );
      assert.equal(mockFetch.mock.calls.length, 0);
    });

    it("posts bounded component and assembly requests", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          request_id: "bounded-base-id",
          transactions: ["5458aa"],
          components: [{
            target_index: 0,
            kind: "bounded-base",
            auth_address: "BOUNDED",
            base_signatures: ["base-sig"],
            assembly_receipt: "receipt",
            signature_scheme: "aplane.falcon1024.v1",
            path: "spend",
          }],
          mutations: {
            dummies_added: 1,
            original_count: 1,
            final_count: 2,
          },
        }),
      });
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          request_id: "bounded-assembly-id",
          signed_group: ["signed"],
        }),
      });

      const client = new SignerClient("http://localhost:11270");
      const component = await client.requestComponents({
        request_id: "bounded-base-id",
        group_bytes_hex: ["5458aa"],
        targets: [{ target_index: 0, kind: "bounded-base", auth_address: "BOUNDED" }],
      });
      const assembly = await client.requestAssemble({
        request_id: "bounded-assembly-id",
        group_bytes_hex: ["5458aa"],
        targets: [{
          target_index: 0,
          kind: "bounded-cosigner",
          auth_address: "BOUNDED",
          base_signatures: ["base-sig"],
          assembly_receipt: "receipt",
          cosigner_signature: "cosigner-sig",
        }],
      });

      assert.equal(component.components[0].assembly_receipt, "receipt");
      assert.deepEqual(assembly.signed_group, ["signed"]);
      assert.equal(mockFetch.mock.calls[1][0], "http://localhost:11270/sign/component");
      assert.equal(mockFetch.mock.calls[2][0], "http://localhost:11270/sign/assemble");
    });

    it("cancels bounded component approval after timeout", async () => {
      const abortError = new Error("Abort");
      abortError.name = "AbortError";
      queueStatusResponse();
      mockFetch.mockRejectedValueOnce(abortError);
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ success: true, state: "canceled" }),
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.requestComponents({
          request_id: "bounded-cancel-id",
          group_bytes_hex: ["5458aa"],
          targets: [{ target_index: 0, kind: "bounded-base", auth_address: "BOUNDED" }],
        }),
        SignerUnavailableError,
      );

      assert.equal(mockFetch.mock.calls[1][0], "http://localhost:11270/sign/component");
      assert.equal(mockFetch.mock.calls[2][0], "http://localhost:11270/sign/cancel");
      assert.equal(
        JSON.parse(mockFetch.mock.calls[2][1].body).request_id,
        "bounded-cancel-id",
      );
    });

    it("classifies bounded endpoint not_found responses", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 400,
        ok: false,
        json: async () => ({ error: "key not found", code: "not_found" }),
        text: async () => "key not found",
      });

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.requestComponents({
          request_id: "bounded-not-found",
          group_bytes_hex: ["5458aa"],
          targets: [{ target_index: 0, kind: "bounded-base", auth_address: "BOUNDED" }],
        }),
        KeyNotFoundError,
      );
    });

    it("rejects an incomplete bounded component partition before fetch", async () => {
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.requestComponents({
          request_id: "bounded-base-id",
          group_bytes_hex: [],
          targets: [{ target_index: 0, kind: "bounded-base", auth_address: "BOUNDED" }],
        }),
        /group_bytes_hex is empty/,
      );
      assert.equal(mockFetch.mock.calls.length, 0);
    });

    it("wraps malformed bounded endpoint JSON", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => {
          throw new SyntaxError("bad json");
        },
      });
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.requestComponents({
          request_id: "bounded-base-id",
          group_bytes_hex: ["5458aa"],
          targets: [{ target_index: 0, kind: "bounded-base", auth_address: "BOUNDED" }],
        }),
        (error: unknown) => error instanceof SignerError &&
          error.message === "Server returned invalid JSON",
      );
    });

    it("rejects malformed bounded component targets", async () => {
      queueStatusResponse();
      const component = {
        target_index: 0,
        kind: "bounded-base",
        auth_address: "BOUNDED",
        base_signatures: ["base"],
        assembly_receipt: "receipt",
        signature_scheme: "aplane.falcon1024.v1",
        path: "spend",
      };
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          request_id: "bounded-base-id",
          transactions: ["5458aa"],
          components: [component, component],
        }),
      });
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.requestComponents({
          request_id: "bounded-base-id",
          group_bytes_hex: ["5458aa"],
          targets: [{ target_index: 0, kind: "bounded-base", auth_address: "BOUNDED" }],
        }),
        /invalid or duplicate target_index/,
      );
    });

  });

  describe("signPreparedCosignedGroup", () => {
    it("plans repeated LogicSig addresses with per-slot args and app metadata", async () => {
      const cosigned = testAddress(31);
      const receiver = testAddress(32);
      const user = new SignerClient("http://localhost:11270");
      const suggestedParams = {
        fee: 1000n,
        minFee: 1000n,
        firstValid: 1n,
        lastValid: 100n,
        genesisHash: new Uint8Array(32),
        genesisID: "testnet-v1",
        flatFee: true,
      };
      const signerKey = {
        address: cosigned,
        publicKeyHex: "",
        keyType: "aplane.falcon1024.v1",
        signingFlow: SIGNING_FLOW_COSIGNED1,
        cosignerComponentKeyType: KEY_TYPE_WITNESS_FALCON1024,
        logicSigResources: {
          spend: { programBytes: 1612, argumentBytes: 1423, maxOpcodeCost: 20000 },
        },
        isGenericLsig: false,
        boundedAuthorization: {
          contract: "plain1",
          baseSignatureArgLayout: { count: 1, maxSizes: [1280] },
          spendEffects: [],
          rekey: "refused",
          runtimeArgs: [],
          derivedArgs: [],
          argumentLayout: [],
          layer3Policy: "none",
          cosigner: {
            contract: "cosigner1",
            componentKeyType: KEY_TYPE_WITNESS_FALCON1024,
            publicKeyHex: "aabbcc",
            signatureMaxSize: 1423,
            requiredOn: ["spend"],
          },
        },
      };
      (user as any).planRequests = async (requests: any[]) => {
        assert.equal(requests.length, 2);
        assert.deepEqual(requests.map((request) => request.lsig_args), [
          { preimage: "616c706861" },
          { preimage: "62657461" },
        ]);
        assert.deepEqual(requests.map((request) => request.app_call_info), [
          { mode: "raw", method: "first" },
          { mode: "abi", method: "second" },
        ]);
        throw new Error("stop after per-slot plan assertion");
      };

      await assert.rejects(
        signPreparedCosignedGroup({
          userClient: user,
          preparedGroup: {
            transactions: [
              {
                transaction: algosdk.makePaymentTxnWithSuggestedParamsFromObject({
                  sender: cosigned, receiver, amount: 1n, suggestedParams,
                }),
                authAddress: cosigned,
                signerKey,
                lsigArgs: { preimage: new TextEncoder().encode("alpha") },
                appCallInfo: { mode: "raw", method: "first" },
              },
              {
                transaction: algosdk.makePaymentTxnWithSuggestedParamsFromObject({
                  sender: cosigned, receiver, amount: 2n, suggestedParams,
                }),
                authAddress: cosigned,
                signerKey,
                lsigArgs: { preimage: new TextEncoder().encode("beta") },
                appCallInfo: { mode: "abi", method: "second" },
              },
            ],
          },
        }),
        /stop after per-slot plan assertion/,
      );
    });

    it("skips the cosigner for a listed rekey on a cosigned account", async () => {
      const bounded = testAddress(13);
      const target = testAddress(14);
      const user = new SignerClient("http://localhost:11270");
      const cosigner = new SignerClient("http://cosigner:11270");
      (user as any).planRequests = async (requests: any[]) => ({ transactions: [requests[0].txn_bytes_hex] });
      (user as any).requestComponents = async () => ({
        request_id: "base-id",
        components: [{
          target_index: 0,
          kind: "bounded-base",
          auth_address: bounded,
          base_signatures: ["base-sig"],
          assembly_receipt: "receipt",
          signature_scheme: "aplane.falcon1024.v1",
          path: "listed_rekey",
        }],
      });
      (cosigner as any).requestComponents = async () => {
        throw new Error("the cosigner was asked about a listed rekey");
      };
      const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: bounded,
        receiver: bounded,
        amount: 0n,
        rekeyTo: target,
        suggestedParams: {
          fee: 1000n, minFee: 1000n, firstValid: 1n, lastValid: 100n,
          genesisHash: new Uint8Array(32), genesisID: "testnet-v1", flatFee: true,
        },
      });
      (user as any).requestAssemble = async (request: any) => {
        assert.equal(request.targets[0].cosigner_signature, undefined);
        assert.equal(request.targets[0].cosigner_source_request_id, undefined);
        const signature = new Uint8Array(64);
        signature[63] = 1;
        return {
          request_id: "assembly-id",
          signed_group: [bytesToHex(algosdk.encodeMsgpack(new algosdk.SignedTransaction({ txn, sig: signature })))],
        };
      };
      const result = await signPreparedCosignedGroup({
        userClient: user,
        cosignerClient: cosigner,
        cosignerComponentKey: "COSIGNER_COMPONENT",
        preparedGroup: {
          transactions: [{
            transaction: txn,
            authAddress: bounded,
            signerKey: {
              address: bounded,
              publicKeyHex: "",
              keyType: "aplane.falcon1024.v1",
              signingFlow: SIGNING_FLOW_COSIGNED1,
              cosignerComponentKeyType: KEY_TYPE_WITNESS_FALCON1024,
              logicSigResources: {
                spend: { programBytes: 5308, argumentBytes: 3358, maxOpcodeCost: 20000 },
                spendingRekey: { programBytes: 5308, argumentBytes: 2846, maxOpcodeCost: 20000 },
                listedRekey: { programBytes: 5308, argumentBytes: 1583, maxOpcodeCost: 20000 },
              },
              isGenericLsig: false,
              boundedAuthorization: {
                contract: "bounded2",
                baseSignatureArgLayout: { count: 1, maxSizes: [1280] },
                spendEffects: ["pay"],
                maxFee: 1000,
                rekey: "spending_key",
                rekeyList: { contract: "rekey_list1", depth: 4 },
                cosigner: {
                  contract: "cosigner1",
                  componentKeyType: KEY_TYPE_WITNESS_FALCON1024,
                  publicKeyHex: "aabb",
                  signatureMaxSize: 1280,
                  requiredOn: ["spend", "spending_rekey"],
                },
                runtimeArgs: [],
                derivedArgs: [],
                argumentLayout: [],
                layer3Policy: "merkle_allowlist",
              },
            },
          }],
        },
      } as any);
      assert.equal(result.signedGroup.length, 1);
      assert.deepEqual(result.cosignerComponentResponses, []);
    });

    it("asks the cosigner once for the spends of a mixed cosigned group", async () => {
      // A listed rekey (0), two spends under one cosigner key (1, 2) and a
      // primary slot (3). A cosigner signature in another scheme than the
      // account's cosigner key type is refused.
      const listed = testAddress(41);
      const spendA = testAddress(42);
      const spendB = testAddress(43);
      const primary = testAddress(44);
      const receiver = testAddress(45);
      const rekeyTarget = testAddress(46);
      const suggestedParams = {
        fee: 1000n, minFee: 1000n, firstValid: 1n, lastValid: 100n,
        genesisHash: new Uint8Array(32), genesisID: "testnet-v1", flatFee: true,
      };
      const txns = algosdk.assignGroupID([
        algosdk.makePaymentTxnWithSuggestedParamsFromObject({
          sender: listed, receiver: listed, amount: 0n, rekeyTo: rekeyTarget, suggestedParams,
        }),
        algosdk.makePaymentTxnWithSuggestedParamsFromObject({ sender: spendA, receiver, amount: 1000n, suggestedParams }),
        algosdk.makePaymentTxnWithSuggestedParamsFromObject({ sender: spendB, receiver, amount: 2000n, suggestedParams }),
        algosdk.makePaymentTxnWithSuggestedParamsFromObject({ sender: primary, receiver, amount: 3000n, suggestedParams }),
      ]);
      const signature = new Uint8Array(64);
      signature[63] = 1;
      const signedGroup = txns.map((txn) =>
        bytesToHex(algosdk.encodeMsgpack(new algosdk.SignedTransaction({ txn, sig: signature }))));
      const cosignedKey = (address: string) => ({
        address,
        publicKeyHex: "",
        keyType: "aplane.falcon1024.v1",
        signingFlow: SIGNING_FLOW_COSIGNED1,
        cosignerComponentKeyType: KEY_TYPE_WITNESS_FALCON1024,
        logicSigResources: {
          spend: { programBytes: 5308, argumentBytes: 3358, maxOpcodeCost: 20000 },
          spendingRekey: { programBytes: 5308, argumentBytes: 2846, maxOpcodeCost: 20000 },
          listedRekey: { programBytes: 5308, argumentBytes: 1583, maxOpcodeCost: 20000 },
        },
        isGenericLsig: false,
        boundedAuthorization: {
          contract: "plain1",
          baseSignatureArgLayout: { count: 1, maxSizes: [1280] },
          spendEffects: [],
          rekey: "spending_key",
          rekeyList: { contract: "rekey_list1", depth: 4 },
          cosigner: {
            contract: "cosigner1",
            componentKeyType: KEY_TYPE_WITNESS_FALCON1024,
            publicKeyHex: "aabb",
            signatureMaxSize: 1280,
            requiredOn: ["spend", "spending_rekey"],
          },
          runtimeArgs: [],
          derivedArgs: [],
          argumentLayout: [],
          layer3Policy: "",
        },
      });
      const base = (index: number, account: string, path: string) => ({
        target_index: index,
        kind: "bounded-base",
        auth_address: account,
        base_signatures: ["base-sig"],
        assembly_receipt: "receipt",
        signature_scheme: "aplane.falcon1024.v1",
        path,
      });

      for (const wrongScheme of [false, true]) {
        const user = new SignerClient("http://localhost:11270");
        const cosigner = new SignerClient("http://cosigner:11270");
        const cosignerRequests: any[] = [];
        let primaryRequests: any[] | undefined;
        let assembly: any;
        (user as any).planRequests = async (requests: any[]) => ({
          transactions: requests.map((request) => request.txn_bytes_hex),
        });
        let baseRequest: any;
        (user as any).requestComponents = async (request: any) => {
          baseRequest = request;
          return {
            request_id: "base-id",
            components: [base(0, listed, "listed_rekey"), base(1, spendA, "spend"), base(2, spendB, "spend")],
          };
        };
        (user as any).signRequests = async (requests: any[]) => {
          primaryRequests = requests;
          return { signed: signedGroup };
        };
        (user as any).requestAssemble = async (request: any) => {
          assembly = request;
          return { request_id: "assembly-id", signed_group: signedGroup };
        };
        (cosigner as any).requestComponents = async (request: any) => {
          cosignerRequests.push(request);
          return {
            request_id: "cosigner-id",
            components: request.targets.map((target: any) => ({
              target_index: target.target_index,
              kind: "cosigner",
              signature: `cosigner-sig-${target.target_index}`,
              signature_scheme: wrongScheme ? "aplane.falcon1024.v1" : KEY_TYPE_WITNESS_FALCON1024,
            })),
          };
        };
        const sign = () => signPreparedCosignedGroup({
          userClient: user,
          cosignerClient: cosigner,
          cosignerComponentKey: "COSIGNER_COMPONENT",
          preparedGroup: {
            transactions: [
              { transaction: txns[0], authAddress: listed, signerKey: cosignedKey(listed), appCallInfo: { mode: "listed" } },
              { transaction: txns[1], authAddress: spendA, signerKey: cosignedKey(spendA) },
              { transaction: txns[2], authAddress: spendB, signerKey: cosignedKey(spendB) },
              {
                transaction: txns[3], authAddress: primary, appCallInfo: { mode: "primary" },
                signerKey: { address: primary, publicKeyHex: "", keyType: "ed25519", authorizationKind: "ed25519", isGenericLsig: false },
              },
            ],
          },
        } as any);
        if (wrongScheme) {
          await assert.rejects(sign(), /used scheme/);
          assert.equal(assembly, undefined);
          continue;
        }
        const result = await sign();

        // The user signer's approval shows the primary slot's app call.
        assert.deepEqual(
          baseRequest.contextual_positions.map((position: any) => [position.target_index, position.app_call_info]),
          [[3, { mode: "primary" }]],
        );
        assert.equal(cosignerRequests.length, 1);
        const cosignerRequest = cosignerRequests[0];
        assert.deepEqual(cosignerRequest.targets.map((target: any) => target.target_index), [1, 2]);
        assert.deepEqual(
          [...new Set(cosignerRequest.targets.map((target: any) => target.component_key))],
          ["COSIGNER_COMPONENT"],
        );
        assert.deepEqual(
          Object.fromEntries(cosignerRequest.contextual_positions.map((position: any) =>
            [position.target_index, position.app_call_info])),
          { 0: { mode: "listed" }, 3: { mode: "primary" } },
        );

        assert.equal(primaryRequests?.length, 4);
        for (const [index, argumentBytes] of [[0, 1583], [1, 3358], [2, 3358]]) {
          assert.equal(primaryRequests?.[index].auth_address, undefined);
          assert.equal(primaryRequests?.[index].lsig_resources.argument_bytes, argumentBytes);
        }
        assert.equal(primaryRequests?.[3].auth_address, primary);
        assert.deepEqual(primaryRequests?.[3].app_call_info, { mode: "primary" });

        const byIndex = new Map(assembly.targets.map((target: any) => [target.target_index, target]));
        assert.deepEqual([...byIndex.keys()].sort(), [0, 1, 2]);
        assert.equal((byIndex.get(0) as any).cosigner_signature, undefined);
        for (const index of [1, 2]) {
          assert.equal((byIndex.get(index) as any).cosigner_signature, `cosigner-sig-${index}`);
          assert.equal((byIndex.get(index) as any).cosigner_source_request_id, "cosigner-id");
        }
        assert.deepEqual(assembly.passthrough.map((item: any) => item.target_index), [3]);
        assert.equal(result.signedGroup.length, 4);
        assert.equal(result.cosignerComponentResponses.length, 1);
      }
    });

    it("routes prepared bounded-cosigner groups through the user-first flow", async () => {
      const bounded = testAddress(11);
      const receiver = testAddress(12);
      const user = new SignerClient("http://localhost:11270");
      const cosigner = new SignerClient("http://cosigner:11270");
      let plannedTransactions: string[] | undefined;
      let plannedMutations: any;
      let baseComponentCalls = 0;

      // The real planRequests runs, so the plan is checked against the
      // requests where every caller's plan is checked.
      (user as any).fetch = async (path: string, init: any) => {
        assert.equal(path, "/plan");
        const requests = JSON.parse(init.body).requests;
        return {
          status: 200,
          ok: true,
          json: async () => ({
            transactions: plannedTransactions ?? [requests[0].txn_bytes_hex],
            mutations: plannedMutations,
          }),
        };
      };
      (user as any).requestComponents = async (request: any) => {
        baseComponentCalls += 1;
        assert.equal(request.targets[0].auth_address, bounded);
        return {
          request_id: "base-id",
          components: [{
            target_index: 0,
            kind: "bounded-base",
            auth_address: bounded,
            base_signatures: ["base-sig"],
            runtime_args: { proof: "aabb" },
            assembly_receipt: "receipt",
            signature_scheme: "aplane.falcon1024.v1",
            path: "spend",
          }],
          mutations: plannedMutations,
        };
      };
      (cosigner as any).requestComponents = async (request: any) => {
        assert.equal(request.targets[0].component_key, "COSIGNER_COMPONENT");
        assert.deepEqual(request.targets[0].app_call_info, { mode: "raw" });
        assert.deepEqual(request.targets.map((target: any) => target.target_index), [0]);
        assert.equal(request.group_bytes_hex.length, 1);
        return {
          request_id: "cosigner-id",
          components: [{
            target_index: 0,
            kind: "cosigner",
            signature: "cosigner-sig",
            signature_scheme: KEY_TYPE_WITNESS_FALCON1024,
          }],
        };
      };
      (user as any).signRequests = async () => {
        throw new Error("all-bounded path must not call /sign");
      };
      let assembledTxn: algosdk.Transaction;
      const signedTxnHex = (txn: algosdk.Transaction): string => {
        const signature = new Uint8Array(64);
        signature[63] = 1;
        return bytesToHex(algosdk.encodeMsgpack(
          new algosdk.SignedTransaction({ txn, sig: signature }),
        ));
      };
      (user as any).requestAssemble = async (request: any) => {
        assert.deepEqual(request.targets[0].base_signatures, ["base-sig"]);
        assert.equal(request.targets[0].assembly_receipt, "receipt");
        assert.equal(request.targets[0].cosigner_signature, "cosigner-sig");
        return { request_id: "assembly-id", signed_group: [signedTxnHex(assembledTxn)] };
      };

      const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: bounded,
        receiver,
        amount: 1000n,
        suggestedParams: {
          fee: 1000n,
          minFee: 1000n,
          firstValid: 1n,
          lastValid: 100n,
          genesisHash: new Uint8Array(32),
          genesisID: "testnet-v1",
          flatFee: true,
        },
      });
      const options = {
        userClient: user,
        cosignerClient: cosigner,
        cosignerComponentKey: "COSIGNER_COMPONENT",
        preparedGroup: {
          transactions: [{
            transaction: txn,
            authAddress: bounded,
            appCallInfo: { mode: "raw" },
            signerKey: {
              address: bounded,
              publicKeyHex: "",
              keyType: "aplane.falcon1024.v1",
              signingFlow: SIGNING_FLOW_COSIGNED1,
              cosignerComponentKeyType: KEY_TYPE_WITNESS_FALCON1024,
              logicSigResources: {
                spend: { programBytes: 5308, argumentBytes: 3358, maxOpcodeCost: 20000 },
              },
              isGenericLsig: false,
              boundedAuthorization: {
                contract: "bounded2",
                baseSignatureArgLayout: { count: 1, maxSizes: [1280] },
                spendEffects: ["pay"],
                maxFee: 1000,
                rekey: "refused",
                cosigner: {
                  contract: "cosigner1",
                  componentKeyType: KEY_TYPE_WITNESS_FALCON1024,
                  publicKeyHex: "aabb",
                  signatureMaxSize: 1280,
                  requiredOn: ["spend"],
                },
                runtimeArgs: [],
                derivedArgs: [],
                argumentLayout: [],
                layer3Policy: "merkle_allowlist",
              },
            },
          }],
        },
      };
      const fabricatedFirst = algosdk.decodeUnsignedTransaction(txn.toByte());
      const fabricatedSecond = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: bounded,
        receiver,
        amount: 2n,
        suggestedParams: {
          fee: 1000n,
          minFee: 1000n,
          firstValid: 1n,
          lastValid: 100n,
          genesisHash: new Uint8Array(32),
          genesisID: "testnet-v1",
          flatFee: true,
        },
      });
      fabricatedFirst.group = new Uint8Array(32).fill(0x44);
      fabricatedSecond.group = new Uint8Array(32).fill(0x44);
      plannedTransactions = [
        encodeTransaction(fabricatedFirst)[0],
        encodeTransaction(fabricatedSecond)[0],
      ];
      plannedMutations = {
        dummiesAdded: 1,
        groupIdChanged: true,
        feesModified: [],
        totalFeesDelta: 0,
        originalCount: 1,
        finalCount: 2,
      };
      await assert.rejects(
        signPreparedCosignedGroup(options),
        /verify signer plan: returned transaction 1 does not carry the canonical group ID/,
      );

      const changedPlanTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: bounded,
        receiver,
        amount: 2000n,
        suggestedParams: {
          fee: 1000n,
          minFee: 1000n,
          firstValid: 1n,
          lastValid: 100n,
          genesisHash: new Uint8Array(32),
          genesisID: "testnet-v1",
          flatFee: true,
        },
      });
      plannedTransactions = [encodeTransaction(changedPlanTxn)[0]];
      plannedMutations = undefined;
      await assert.rejects(
        signPreparedCosignedGroup(options),
        /changed unreported fields/,
      );

      const inflatedFeeTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: bounded,
        receiver,
        amount: 1000n,
        suggestedParams: {
          fee: 2000n,
          minFee: 1000n,
          firstValid: 1n,
          lastValid: 100n,
          genesisHash: new Uint8Array(32),
          genesisID: "testnet-v1",
          flatFee: true,
        },
      });
      plannedTransactions = [encodeTransaction(inflatedFeeTxn)[0]];
      plannedMutations = {
        dummiesAdded: 0,
        groupIdChanged: false,
        feesModified: [0],
        totalFeesDelta: 1000,
        originalCount: 1,
        finalCount: 1,
      };
      const callsBeforeInflatedFee = baseComponentCalls;
      await assert.rejects(
        signPreparedCosignedGroup(options),
        /exceeds advertised max_fee/,
      );
      assert.equal(baseComponentCalls, callsBeforeInflatedFee);

      const badDummy = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: bounded,
        receiver: bounded,
        amount: 1n,
        note: new Uint8Array([0]),
        suggestedParams: {
          fee: 0n,
          minFee: 1000n,
          firstValid: 1n,
          lastValid: 100n,
          genesisHash: new Uint8Array(32),
          genesisID: "testnet-v1",
          flatFee: true,
        },
      });
      const badDummyGroup = [
        algosdk.decodeUnsignedTransaction(txn.toByte()),
        badDummy,
      ];
      algosdk.assignGroupID(badDummyGroup);
      plannedTransactions = badDummyGroup.map((item) => encodeTransaction(item)[0]);
      plannedMutations = {
        dummiesAdded: 1,
        groupIdChanged: true,
        feesModified: [],
        totalFeesDelta: 0,
        originalCount: 1,
        finalCount: 2,
      };
      await assert.rejects(
        signPreparedCosignedGroup(options),
        /appended transaction 1 is not the canonical resource dummy/,
      );
      plannedTransactions = undefined;
      plannedMutations = undefined;

      assembledTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: bounded,
        receiver,
        amount: 2000n,
        suggestedParams: {
          fee: 1000n,
          minFee: 1000n,
          firstValid: 1n,
          lastValid: 100n,
          genesisHash: new Uint8Array(32),
          genesisID: "testnet-v1",
          flatFee: true,
        },
      });
      await assert.rejects(
        signPreparedCosignedGroup(options),
        /does not match the submitted canonical bytes/,
      );

      assembledTxn = txn;
      const result = await signPreparedCosignedGroup(options);

      assert.deepEqual(result.signedGroup, [signedTxnHex(txn)]);
      assert.ok(result.boundedComponentResponse);
      assert.ok(result.boundedAssemblyResponse);
    });

    it("selects bounded LogicSig resources from the prepared transaction path", async () => {
      const bounded = testAddress(41);
      const receiver = testAddress(42);
      const rekeyTo = testAddress(43);
      const suggestedParams = {
        fee: 1000n,
        minFee: 1000n,
        firstValid: 1n,
        lastValid: 100n,
        genesisHash: new Uint8Array(32),
        genesisID: "testnet-v1",
        flatFee: true,
      };
      const profiles = {
        spend: { programBytes: 1001, argumentBytes: 101, maxOpcodeCost: 10001 },
        spendingRekey: { programBytes: 2002, argumentBytes: 202, maxOpcodeCost: 20002 },
        listedRekey: { programBytes: 1001, argumentBytes: 1583, maxOpcodeCost: 20003 },
      };
      const unavailable = /bounded rekey authorization metadata is unavailable/;
      const cases: Array<{
        name: string;
        rekeySetting: string;
        rekeyList?: boolean;
        rekey: boolean;
        expected?: typeof profiles.spend;
        error?: RegExp;
      }> = [
        // Only these addresses: the signer checks the target and adds the proof.
        { name: "listed rekey", rekeySetting: "refused", rekeyList: true, rekey: true, expected: profiles.listedRekey },
        { name: "spend on a list account", rekeySetting: "refused", rekeyList: true, rekey: false, expected: profiles.spend },
        { name: "spend on a refused account", rekeySetting: "refused", rekey: false, expected: profiles.spend },
        { name: "spend", rekeySetting: "spending_key", rekey: false, expected: profiles.spend },
        { name: "spending rekey", rekeySetting: "spending_key", rekey: true, expected: profiles.spendingRekey },
        // Only spending_key authorizes a rekey without a list. refused says so;
        // a missing setting and any other value (such as the removed admin_key
        // authorization) are unavailable metadata.
        { name: "refused rekey", rekeySetting: "refused", rekey: true, error: /the account refuses rekeys/ },
        { name: "missing rekey setting", rekeySetting: "", rekey: true, error: unavailable },
        { name: "unknown rekey setting", rekeySetting: "admin_key", rekey: true, error: unavailable },
      ];

      for (const item of cases) {
        const user = new SignerClient("http://localhost:11270");
        const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
          sender: bounded,
          receiver: item.rekey ? bounded : receiver,
          amount: item.rekey ? 0n : 1n,
          suggestedParams,
          ...(item.rekey ? { rekeyTo } : {}),
        });
        (user as any).planRequests = async (requests: any[]) => ({
          transactions: [requests[0].txn_bytes_hex],
        });
        (user as any).requestComponents = async (_request: any) => ({
          request_id: `component-${item.name}`,
          components: [{
            target_index: 0,
            kind: "bounded-base",
            auth_address: bounded,
            base_signatures: ["base-sig"],
            assembly_receipt: "receipt",
            signature_scheme: "aplane.falcon1024.v1",
            path: "spend",
          }],
        });

        await assert.rejects(
          signPreparedCosignedGroup({
            userClient: user,
            cosignerResolver: async (target) => {
              assert.deepEqual(target.logicSigResources, item.expected);
              throw new Error(`observed ${item.name}`);
            },
            preparedGroup: {
              transactions: [{
                transaction: txn,
                authAddress: bounded,
                signerKey: {
                  address: bounded,
                  publicKeyHex: "",
                  keyType: "aplane.falcon1024.v1",
                  signingFlow: SIGNING_FLOW_COSIGNED1,
                  cosignerComponentKeyType: KEY_TYPE_WITNESS_FALCON1024,
                  logicSigResources: profiles,
                  isGenericLsig: false,
                  boundedAuthorization: {
                    contract: "bounded2",
                    baseSignatureArgLayout: { count: 1, maxSizes: [1423] },
                    spendEffects: ["pay"],
                    maxFee: 1000,
                    rekey: item.rekeySetting,
                    rekeyList: item.rekeyList ? { contract: "rekey_list1", depth: 4 } : undefined,
                    cosigner: {
                      contract: "cosigner1",
                      componentKeyType: KEY_TYPE_WITNESS_FALCON1024,
                      publicKeyHex: "aabb",
                      signatureMaxSize: 1423,
                      requiredOn: ["spend"],
                    },
                    runtimeArgs: [],
                    derivedArgs: [],
                    argumentLayout: [],
                    layer3Policy: "fixed_allowlist",
                  },
                },
              }],
            },
          }),
          item.error ?? new RegExp(`observed ${item.name}`),
        );
      }
    });

    it("names the position of a held primary that carries a size hint", async () => {
      const account = testAddress(41);
      await assert.rejects(
        signPreparedCosignedGroup({
          userClient: new SignerClient("http://localhost:11270"),
          preparedGroup: {
            transactions: [
              {
                transaction: algosdk.makePaymentTxnWithSuggestedParamsFromObject({
                  sender: account,
                  receiver: testAddress(42),
                  amount: 1n,
                  suggestedParams: {
                    fee: 1000n,
                    minFee: 1000n,
                    firstValid: 1n,
                    lastValid: 100n,
                    genesisHash: new Uint8Array(32),
                    genesisID: "testnet-v1",
                    flatFee: true,
                  },
                }),
                authAddress: account,
                pqScheme: "f1",
                signerKey: {
                  address: account,
                  publicKeyHex: "",
                  keyType: "falcon1024",
                  isGenericLsig: false,
                },
              },
            ],
          },
        }),
        /prepared transaction 0: pqScheme is allowed only for foreign transactions/,
      );
    });

    it("refuses cosigner1 as an unknown signing flow before any request", async () => {
      const account = testAddress(41);
      const user = new SignerClient("http://localhost:11270");
      const suggestedParams = {
        fee: 1000n,
        minFee: 1000n,
        firstValid: 1n,
        lastValid: 100n,
        genesisHash: new Uint8Array(32),
        genesisID: "testnet-v1",
        flatFee: true,
      };
      await assert.rejects(
        signPreparedCosignedGroup({
          userClient: user,
          preparedGroup: {
            transactions: [
              {
                transaction: algosdk.makePaymentTxnWithSuggestedParamsFromObject({
                  sender: account, receiver: testAddress(42), amount: 1n, suggestedParams,
                }),
                authAddress: account,
                signerKey: {
                  address: account,
                  publicKeyHex: "",
                  keyType: "aplane.falcon1024-cosigner1024.v1",
                  signingFlow: "cosigner1",
                  cosignerComponentKeyType: KEY_TYPE_WITNESS_FALCON1024,
                  logicSigResources: {
                    spend: { programBytes: 1612, argumentBytes: 1423, maxOpcodeCost: 20000 },
                  },
                  isGenericLsig: false,
                },
              },
            ],
          },
        }),
        /signing flow "cosigner1", which this SDK does not support/,
      );
      assert.equal(mockFetch.mock.calls.length, 0);
    });

    it("verifies bounded primary passthrough transaction identity", async () => {
      const bounded = testAddress(21);
      const primary = testAddress(22);
      const receiver = testAddress(23);
      const user = new SignerClient("http://localhost:11270");
      const cosigner = new SignerClient("http://cosigner:11270");
      const suggestedParams = {
        fee: 1000n,
        minFee: 1000n,
        firstValid: 1n,
        lastValid: 100n,
        genesisHash: new Uint8Array(32),
        genesisID: "testnet-v1",
        flatFee: true,
      };
      const boundedTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: bounded,
        receiver,
        amount: 1000n,
        suggestedParams,
      });
      const primaryTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: primary,
        receiver,
        amount: 2000n,
        suggestedParams,
      });
      const wrongPrimaryTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: primary,
        receiver,
        amount: 3000n,
        suggestedParams,
      });
      const signedTxnHex = (txn: algosdk.Transaction): string => {
        const logicSig = new algosdk.LogicSigAccount(
          new Uint8Array([0x03, 0x31, 0x20, 0x32, 0x03, 0x12]),
        );
        return bytesToHex(algosdk.signLogicSigTransactionObject(txn, logicSig).blob);
      };
      let plannedGroup: algosdk.Transaction[] = [];

      (user as any).planRequests = async (requests: any[]) => {
        const planned = requests.map((entry: any) =>
          algosdk.decodeUnsignedTransaction(hexToBytes(entry.txn_bytes_hex).slice(2))
        );
        algosdk.assignGroupID(planned);
        plannedGroup = planned;
        return {
          transactions: planned.map((item: algosdk.Transaction) => encodeTransaction(item)[0]),
          mutations: {
            dummiesAdded: 0,
            groupIdChanged: true,
            feesModified: [],
            totalFeesDelta: 0,
            originalCount: planned.length,
            finalCount: planned.length,
          },
        };
      };
      (user as any).requestComponents = async (_request: any) => ({
          request_id: "base-id",
          components: [{
            target_index: 0,
            kind: "bounded-base",
            auth_address: bounded,
            base_signatures: ["base-sig"],
            assembly_receipt: "receipt",
            signature_scheme: "aplane.falcon1024.v1",
            path: "spend",
          }],
        });
      (cosigner as any).requestComponents = async () => ({
        request_id: "cosigner-id",
        components: [{
          target_index: 0,
          kind: "cosigner",
          signature: "cosigner-sig",
          signature_scheme: KEY_TYPE_WITNESS_FALCON1024,
        }],
      });
      let useWrongPrimary = true;
      (user as any).signRequests = async () => {
        const primarySignedTxn = algosdk.decodeUnsignedTransaction(
          (useWrongPrimary ? wrongPrimaryTxn : plannedGroup[1]).toByte(),
        );
        primarySignedTxn.group = plannedGroup[1].group;
        return { signed: ["", signedTxnHex(primarySignedTxn)] };
      };
      (user as any).requestAssemble = async () => ({
        request_id: "assembly-id",
        signed_group: plannedGroup.map(signedTxnHex),
      });

      const options = {
        userClient: user,
        cosignerClient: cosigner,
        cosignerComponentKey: "COSIGNER_COMPONENT",
        preparedGroup: {
          transactions: [
            {
              transaction: boundedTxn,
              authAddress: bounded,
              signerKey: {
                address: bounded,
                publicKeyHex: "",
                keyType: "aplane.falcon1024.v1",
                signingFlow: SIGNING_FLOW_COSIGNED1,
                cosignerComponentKeyType: KEY_TYPE_WITNESS_FALCON1024,
                logicSigResources: {
                  spend: { programBytes: 5308, argumentBytes: 3358, maxOpcodeCost: 20000 },
                },
                isGenericLsig: false,
                boundedAuthorization: {
                  contract: "bounded2",
                  baseSignatureArgLayout: { count: 1, maxSizes: [1280] },
                  spendEffects: ["pay"],
                  maxFee: 1000,
                  rekey: "refused",
                  cosigner: {
                    contract: "cosigner1",
                    componentKeyType: KEY_TYPE_WITNESS_FALCON1024,
                    publicKeyHex: "aabb",
                    signatureMaxSize: 1280,
                    requiredOn: ["spend"],
                  },
                  runtimeArgs: [],
                  derivedArgs: [],
                  argumentLayout: [],
                },
              },
            },
            {
              transaction: primaryTxn,
              authAddress: primary,
              signerKey: {
                address: primary,
                publicKeyHex: "",
                keyType: "aplane.falcon1024.v1",
                signingFlow: "",
                isGenericLsig: false,
              },
            },
          ],
        },
      };
      await assert.rejects(
        signPreparedCosignedGroup(options),
        /primary passthrough 1 does not match/,
      );
      useWrongPrimary = false;
      const result = await signPreparedCosignedGroup(options);
      assert.equal(result.signedGroup.length, 2);
    });

    // A non-cosigned position the signer holds is sent as the signer's own:
    // in sign mode on /plan, and as a contextual position with auth_address
    // on /sign/component. The signer sizes it and can charge it; no hint is
    // sent. Here the plan puts the group's authorization charge on the held
    // primary, which the SDK must accept and sign.
    for (const rejectSign of [false, true]) {
    it(`sends a held native-PQ primary slot as the signer's own in bounded-cosigner groups${rejectSign ? " (user-first when /sign rejects)" : " (user-first order)"}`, async () => {
      const events: string[] = [];
      const bounded = testAddress(31);
      const nativePq = testAddress(32);
      const receiver = testAddress(33);
      const user = new SignerClient("http://localhost:11270");
      const cosigner = new SignerClient("http://cosigner:11270");
      const suggestedParams = {
        fee: 1000n,
        minFee: 1000n,
        firstValid: 1n,
        lastValid: 100n,
        genesisHash: new Uint8Array(32),
        genesisID: "testnet-v1",
        flatFee: true,
      };
      const boundedTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: bounded, receiver, amount: 1000n, suggestedParams,
      });
      const nativeTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: nativePq, receiver, amount: 2000n, suggestedParams,
      });
      const signedTxnHex = (txn: algosdk.Transaction): string => {
        const logicSig = new algosdk.LogicSigAccount(
          new Uint8Array([0x03, 0x31, 0x20, 0x32, 0x03, 0x12]),
        );
        return bytesToHex(algosdk.signLogicSigTransactionObject(txn, logicSig).blob);
      };
      let plannedGroup: algosdk.Transaction[] = [];
      let primaryRequest: any;

      (user as any).planRequests = async (requests: any[]) => {
        primaryRequest = requests[1];
        const planned = requests.map((entry: any) =>
          algosdk.decodeUnsignedTransaction(hexToBytes(entry.txn_bytes_hex).slice(2))
        );
        // The bounded target stays at its 1000 fee ceiling; the held primary
        // carries the charge.
        planned[1].fee += 2000n;
        algosdk.assignGroupID(planned);
        plannedGroup = planned;
        return {
          transactions: planned.map((item: algosdk.Transaction) => encodeTransaction(item)[0]),
          mutations: {
            dummiesAdded: 0,
            groupIdChanged: true,
            feesModified: [1],
            totalFeesDelta: 2000,
            originalCount: planned.length,
            finalCount: planned.length,
          },
        };
      };
      (user as any).requestComponents = async (request: any) => {
        events.push("base");
        assert.deepEqual(
          request.group_bytes_hex,
          plannedGroup.map((item) => encodeTransaction(item)[0]),
        );
        assert.equal(request.targets.length, 1);
        assert.equal(request.contextual_positions.length, 1);
        // The held position names its account and carries no size hint.
        assert.equal(request.contextual_positions[0].auth_address, nativePq);
        assert.equal(request.contextual_positions[0].pq_scheme, undefined);
        assert.equal(request.contextual_positions[0].lsig_resources, undefined);
        return {
          request_id: "base-id",
          components: [{
            target_index: 0,
            kind: "bounded-base",
            auth_address: bounded,
            base_signatures: ["base-sig"],
            assembly_receipt: "receipt",
            signature_scheme: "aplane.falcon1024.v1",
            path: "spend",
          }],
        };
      };
      (cosigner as any).requestComponents = async () => {
        events.push("cosigner");
        return {
          request_id: "cosigner-id",
          components: [{
            target_index: 0,
            kind: "cosigner",
            signature: "cosigner-sig",
            signature_scheme: KEY_TYPE_WITNESS_FALCON1024,
          }],
        };
      };
      (user as any).signRequests = async () => {
        events.push("sign");
        if (rejectSign) {
          throw new SignerError("rejected by signer policy");
        }
        return { signed: ["", signedTxnHex(plannedGroup[1])] };
      };
      (user as any).requestAssemble = async () => {
        events.push("assemble");
        return {
          request_id: "assembly-id",
          signed_group: plannedGroup.map(signedTxnHex),
        };
      };

      const run = () => signPreparedCosignedGroup({
        userClient: user,
        cosignerClient: cosigner,
        cosignerComponentKey: "COSIGNER_COMPONENT",
        preparedGroup: {
          transactions: [
            {
              transaction: boundedTxn,
              authAddress: bounded,
              signerKey: {
                address: bounded,
                publicKeyHex: "",
                keyType: "aplane.falcon1024.v1",
                authorizationKind: "logic_sig",
                signingFlow: SIGNING_FLOW_COSIGNED1,
                cosignerComponentKeyType: KEY_TYPE_WITNESS_FALCON1024,
                isGenericLsig: false,
                logicSigResources: {
                  spend: { programBytes: 5308, argumentBytes: 3358, maxOpcodeCost: 20000 },
                },
                boundedAuthorization: {
                  contract: "bounded2",
                  baseSignatureArgLayout: { count: 1, maxSizes: [1280] },
                  spendEffects: ["pay"],
                  maxFee: 1000,
                  rekey: "refused",
                  cosigner: {
                    contract: "cosigner1",
                    componentKeyType: KEY_TYPE_WITNESS_FALCON1024,
                    publicKeyHex: "aabb",
                    signatureMaxSize: 1280,
                    requiredOn: ["spend"],
                  },
                  runtimeArgs: [],
                  derivedArgs: [],
                  argumentLayout: [],
                },
              },
            },
            {
              transaction: nativeTxn,
              authAddress: nativePq,
              signerKey: {
                address: nativePq,
                publicKeyHex: "",
                keyType: "falcon1024",
                authorizationKind: "native_pq",
                isGenericLsig: false,
              },
            },
          ],
        },
      } as any);
      if (rejectSign) {
        await assert.rejects(run(), /rejected by signer policy/);
        assert.deepEqual(events, ["base", "sign"]);
        return;
      }
      await run();
      assert.deepEqual(events, ["base", "sign", "cosigner", "assemble"]);
      // Sign mode on /plan, with no size hint.
      assert.equal(primaryRequest.auth_address, nativePq);
      assert.equal(primaryRequest.pq_scheme, undefined);
      assert.equal(primaryRequest.lsig_resources, undefined);
    });
    }

    it("rejects prepared groups whose keys require an unsupported signing flow", async () => {
      const cosigned = testAddress(1);
      const receiver = testAddress(2);
      const user = new SignerClient("http://localhost:11270");

      const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: cosigned,
        receiver,
        amount: 1000n,
        suggestedParams: {
          fee: 1000n,
          minFee: 1000n,
          firstValid: 1n,
          lastValid: 100n,
          genesisHash: new Uint8Array(32),
          genesisID: "testnet-v1",
          flatFee: true,
        },
      });

      await assert.rejects(
        signPreparedCosignedGroup({
          userClient: user,
          preparedGroup: {
            transactions: [
              {
                transaction: txn,
                authAddress: cosigned,
                signerKey: {
                  address: cosigned,
                  publicKeyHex: "",
                  keyType: "aplane.future-cosigned.v1",
                  signingFlow: "cosigner2",
                  logicSigResources: {
                    spend: { programBytes: 1612, argumentBytes: 1423, maxOpcodeCost: 20000 },
                  },
                  isGenericLsig: false,
                },
              },
            ],
          },
        }),
        /signing flow "cosigner2"/,
      );
    });
  });

  describe("planGroup", () => {
    const createMockTxn = () => fakePayment();

    it("returns plan with transactions and mutations", async () => {
      mockFetch.mockImplementationOnce(signerFetch({ feeRaise: { 0: 2000 }, dummies: 1 }));

      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.planGroup>[0][0];
      const result = await client.planGroup([mockTxn]);

      assert.equal(result.transactions.length, 2);
      assert.equal(result.mutations?.dummiesAdded, 1);
      assert.equal(result.mutations?.totalFeesDelta, 2000);
    });

    it("rejects a plan that changes the transaction", async () => {
      const other = fakePayment(41, 45, 100_000_000);
      mockFetch.mockImplementationOnce(signerFetch({
        tamper: (body) => {
          body.transactions = [encodeTransaction(other)[0]];
        },
      }));

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.planGroup([createMockTxn()]),
        /verify signer plan: signer changed unreported fields at original position 1/,
      );
    });

    it("rejects a plan that disagrees with its mutation report", async () => {
      const cases: Array<[(body: any) => void, RegExp]> = [
        [(body) => { body.mutations.dummies_added = 0; }, /dummies_added 0 does not match appended count 1/],
        [(body) => { body.mutations.total_fees_delta = 1; }, /total_fees_delta 1 does not match observed delta 2000/],
        [(body) => { body.mutations.fees_modified = []; }, /unreported fields at original position 1/],
        [(body) => { body.transactions[0] = body.transactions[0].slice(4); }, /planned transaction 1: missing TX prefix/],
        [(body) => { body.transactions[0] += "00"; }, /planned transaction 1: /],
        [(body) => { body.transactions = []; }, /want at least 1/],
        [(body) => { delete body.mutations; }, /appended 1 transaction\(s\) without a mutation report/],
      ];
      const client = new SignerClient("http://localhost:11270");
      for (const [tamper, error] of cases) {
        mockFetch.mockImplementationOnce(signerFetch({ feeRaise: { 0: 2000 }, dummies: 1, tamper }));
        await assert.rejects(client.planGroup([createMockTxn()]), error);
      }
    });

    it("throws AuthenticationError on 401", async () => {
      mockFetch.mockResolvedValueOnce({ status: 401, ok: false });
      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.planGroup>[0][0];
      await assert.rejects(client.planGroup([mockTxn]), AuthenticationError);
    });

    it("throws on server error in response", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ error: "Internal error" }),
      });
      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.planGroup>[0][0];
      await assert.rejects(client.planGroup([mockTxn]), SignerError);
    });

    // Object keys are strings at runtime. A key that Number() maps onto a
    // plausible index but that no numeric lookup matches, or one that yields
    // NaN and so passes every relational range check, would otherwise be
    // dropped silently and the request would go out with no declaration.
    it("rejects non-canonical index keys instead of dropping the entry", async () => {
      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.planGroup>[0][0];
      const resources = { programBytes: 1612, argumentBytes: 1423, maxOpcodeCost: 20000 };

      for (const key of ["01", "1.0", " 1", "abc", "1e0", ""]) {
        await assert.rejects(
          client.planGroup([mockTxn, mockTxn], [null, null], undefined, undefined, {
            [key]: resources,
          } as any),
          /lsigResources index .* is not a canonical transaction index/,
          `lsigResources key ${JSON.stringify(key)} should be rejected`,
        );
        await assert.rejects(
          client.planGroup([mockTxn, mockTxn], [null, null], undefined, {
            [key]: "AAAA",
          } as any),
          /passthrough index .* is not a canonical transaction index/,
          `passthrough key ${JSON.stringify(key)} should be rejected`,
        );
      }

      await assert.rejects(
        client.planGroup([mockTxn], [null], undefined, undefined, { 5: resources }),
        /lsigResources index 5 out of range for 1 transactions/,
      );
      await assert.rejects(
        client.planGroup([mockTxn], [null], undefined, undefined, { "-1": resources } as any),
        /lsigResources index -1 out of range for 1 transactions/,
      );
    });

    it("applies a canonical index key to the matching slot", async () => {
      mockFetch.mockImplementationOnce(signerFetch());
      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.planGroup>[0][0];

      await client.planGroup([mockTxn, fakePayment(43, 44)], ["AUTH_ADDR", null], undefined, undefined, {
        1: { programBytes: 1612, argumentBytes: 1423, maxOpcodeCost: 20000 },
      });

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      assert.equal(body.requests[0].lsig_resources, undefined);
      assert.equal(body.requests[1].lsig_resources.program_bytes, 1612);
    });
  });

  describe("signTransactions with passthrough", () => {
    const createMockTxn = () => fakePayment();

    it("carries LogicSig resources on passthrough entries", () => {
      const client = new SignerClient("http://localhost:11270");
      const body = (client as any).buildSignRequestBody(
        [null],
        [null],
        undefined,
        { 0: Buffer.from("signed-txn").toString("base64") },
        { 0: { programBytes: 1612, argumentBytes: 1423, maxOpcodeCost: 20000 } },
        false,
      );
      assert.deepEqual(body.requests, [{
        signed_txn_hex: Buffer.from("signed-txn").toString("hex"),
        lsig_resources: {
          program_bytes: 1612,
          argument_bytes: 1423,
          max_opcode_cost: 20000,
        },
      }]);
    });

    it("rejects indexed LogicSig resources on sign-mode entries", () => {
      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransactions>[0][0];
      assert.throws(
        () => (client as any).buildSignRequestBody(
          [mockTxn],
          ["AUTH"],
          undefined,
          undefined,
          { 0: { programBytes: 1612, argumentBytes: 1423, maxOpcodeCost: 20000 } },
          false,
        ),
        /allowed only for foreign or passthrough/,
      );
    });

    it("rejects foreign entries before calling /sign", async () => {
      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransactions>[0][0];

      await assert.rejects(
        client.signTransactions([mockTxn, mockTxn], ["AUTH1", null]),
        { message: /foreign entries are only supported on \/plan/ },
      );
      assert.equal(mockFetch.mock.calls.length, 0);
    });

    it("signTransactionsList rejects foreign entries before calling /sign", async () => {
      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransactionsList>[0][0];
      await assert.rejects(
        client.signTransactionsList([mockTxn, mockTxn], ["AUTH1", null]),
        { message: /foreign entries are only supported on \/plan/ },
      );
      assert.equal(mockFetch.mock.calls.length, 0);
    });
  });

  describe("signing errors", () => {
    const createMockTxn = () => fakePayment();

    it("rejects truncated /sign responses", async () => {
      queueStatusResponse();
      mockFetch.mockImplementationOnce(signerFetch({
        tamper: (body) => {
          body.signed = body.signed.slice(0, 1);
        },
      }));

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.signRequests(signEntries(fakePayment(41, 42), fakePayment(43, 44))),
        /want at least 2/
      );
    });

    it("rejects empty signed slot for sign-mode request", async () => {
      queueStatusResponse();
      mockFetch.mockImplementationOnce(signerFetch({
        tamper: (body) => {
          body.signed[1] = "";
        },
      }));

      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.signRequests(signEntries(fakePayment(41, 42), fakePayment(43, 44))),
        /no signature for position 2/
      );
    });

    it("leaves a foreign slot empty", async () => {
      queueStatusResponse();
      mockFetch.mockImplementationOnce(signerFetch());

      const grouped = algosdk.assignGroupID([fakePayment(41, 42), fakePayment(43, 44)]);
      const entries = signEntries(...grouped);
      entries[1] = { txn_bytes_hex: entries[1].txn_bytes_hex };
      const client = new SignerClient("http://localhost:11270");
      const data = await client.signRequests(entries);
      assert.deepEqual(data.signed, [signedHex(grouped[0]), ""]);
      assert.equal(data.mutations?.foreignCount, 1);
    });

    it("throws AuthenticationError on 401", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 401,
        ok: false,
      });

      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await assert.rejects(client.signTransaction(mockTxn), AuthenticationError);
    });

    it("throws locked error when sign 403 carries locked code", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 403,
        ok: false,
        json: async () => ({ error: "signer is locked", code: "locked" }),
      });

      const client = new SignerClient("http://localhost:11270");
      const lockedTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];
      await assert.rejects(
        client.signTransaction(lockedTxn, "A".repeat(58)),
        SignerUnavailableError
      );
    });

    it("treats sign 403 without a code as a generic error, not rejected", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 403,
        ok: false,
        json: async () => ({ error: "Operator rejected" }),
      });

      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await assert.rejects(client.signTransaction(mockTxn), (error: unknown) => {
        assert.ok(error instanceof SignerError);
        assert.ok(!(error instanceof SigningRejectedError));
        assert.ok(!(error instanceof SignerUnavailableError));
        assert.equal(error.code, "");
        return true;
      });
    });

    it("throws SigningRejectedError on 403", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 403,
        ok: false,
        json: async () => ({ error: "Operator rejected", code: "forbidden" }),
      });

      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await assert.rejects(client.signTransaction(mockTxn), SigningRejectedError);
    });

    it("throws SignerUnavailableError on 503", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 503,
        ok: false,
        json: async () => ({ error: "Signer locked" }),
      });

      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await assert.rejects(client.signTransaction(mockTxn), SignerUnavailableError);
    });

    it("does not map an uncoded 'not found' message to KeyNotFoundError", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 400,
        ok: false,
        json: async () => ({ error: "Key not found: INVALID_ADDRESS" }),
        text: async () => "Key not found: INVALID_ADDRESS",
      });

      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await assert.rejects(client.signTransaction(mockTxn), (error: unknown) => {
        assert.ok(error instanceof SignerError);
        assert.ok(!(error instanceof KeyNotFoundError));
        assert.equal(error.code, "");
        return true;
      });
    });

    it("throws KeyNotFoundError on 400 with not_found code regardless of wording", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 400,
        ok: false,
        json: async () => ({ error: "auth address unavailable", code: "not_found" }),
        text: async () => "auth address unavailable",
      });

      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await assert.rejects(client.signTransaction(mockTxn), KeyNotFoundError);
    });

    it("does not map 400 with a non-not_found code to KeyNotFoundError", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 400,
        ok: false,
        json: async () => ({ error: "group not found in request", code: "bad_request" }),
        text: async () => "group not found in request",
      });

      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await assert.rejects(
        client.signTransaction(mockTxn),
        (err: unknown) => err instanceof SignerError && !(err instanceof KeyNotFoundError)
      );
    });

    it("throws SignerUnavailableError on timeout", async () => {
      const abortError = new Error("Abort");
      abortError.name = "AbortError";
      queueStatusResponse();
      mockFetch.mockRejectedValueOnce(abortError);
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ success: true, state: "canceled" }),
      });

      const client = new SignerClient("http://localhost:11270", 100);
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await assert.rejects(client.signTransaction(mockTxn), SignerUnavailableError);
      assert.equal(mockFetch.mock.calls.length, 3);
      assert.equal(mockFetch.mock.calls[1][0], "http://localhost:11270/sign");
      const signBody = JSON.parse(mockFetch.mock.calls[1][1].body);
      assert.match(signBody.request_id, /^sdk-[0-9a-f]{32}$/);
      assert.equal(mockFetch.mock.calls[2][0], "http://localhost:11270/sign/cancel");
      const cancelBody = JSON.parse(mockFetch.mock.calls[2][1].body);
      assert.equal(cancelBody.request_id, signBody.request_id);
    });

    it("uses caller-supplied requestId for signing and cancel", async () => {
      const abortError = new Error("Abort");
      abortError.name = "AbortError";
      queueStatusResponse();
      mockFetch.mockRejectedValueOnce(abortError);
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ success: true, state: "canceled" }),
      });

      const client = new SignerClient("http://localhost:11270", 100);
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await assert.rejects(
        client.signTransaction(mockTxn, undefined, undefined, { requestId: "app-owned-id" }),
        SignerUnavailableError,
      );

      const signBody = JSON.parse(mockFetch.mock.calls[1][1].body);
      const cancelBody = JSON.parse(mockFetch.mock.calls[2][1].body);
      assert.equal(signBody.request_id, "app-owned-id");
      assert.equal(cancelBody.request_id, "app-owned-id");
    });

    it("sends best-effort cancel when caller AbortSignal aborts signing", async () => {
      const previousFetch = globalThis.fetch;
      const calls: any[][] = [];
      const controller = new AbortController();
      const abortError = new Error("Abort");
      abortError.name = "AbortError";

      globalThis.fetch = (async (url: string, options: any) => {
        calls.push([url, options]);
        if (url.endsWith("/status")) {
          return {
            status: 200,
            ok: true,
            json: async () => ({
              state: "unlocked",
              signer_locked: false,
              ready_for_signing: true,
              key_count: 37,
              keyset_revision: 4,
              approval_wait_seconds: 60,
            }),
          } as Response;
        }
        if (url.endsWith("/sign")) {
          if (options.signal.aborted) {
            throw abortError;
          }
          await new Promise((_resolve, reject) => {
            options.signal.addEventListener("abort", () => reject(abortError), { once: true });
            controller.abort();
          });
        }
        return {
          status: 200,
          ok: true,
          json: async () => ({ success: true, state: "canceled" }),
        } as Response;
      }) as typeof fetch;

      try {
        const client = new SignerClient("http://localhost:11270");
        const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

        await assert.rejects(
          client.signTransaction(mockTxn, undefined, undefined, {
            requestId: "abort-owned-id",
            signal: controller.signal,
          }),
          SignerUnavailableError,
        );
      } finally {
        globalThis.fetch = previousFetch;
      }

      assert.equal(calls[1][0], "http://localhost:11270/sign");
      assert.equal(calls[2][0], "http://localhost:11270/sign/cancel");
      assert.equal(JSON.parse(calls[2][1].body).request_id, "abort-owned-id");
    });

    it("continues signing with fallback timeout when status discovery fails", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 503,
        ok: false,
        json: async () => ({ error: "locked" }),
      });
      mockFetch.mockImplementationOnce(signerFetch());

      const client = new SignerClient("http://localhost:11270");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      const signed = await client.signTransaction(mockTxn);

      assert.equal(Buffer.from(signed, "base64").toString("hex"), signedHex(mockTxn));
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/status");
      assert.equal(mockFetch.mock.calls[1][0], "http://localhost:11270/sign");
    });

    it("uses discovered approval wait plus slack for signing timeout", async () => {
      queueStatusResponse(120);

      const client = new SignerClient("http://localhost:11270");
      await client.getStatus();

      assert.equal((client as any).signRequestTimeout(), 150000);
    });

    it("falls back for invalid discovered approval wait", async () => {
      queueStatusResponse(31 * 60);

      const client = new SignerClient("http://localhost:11270");
      await client.getStatus();

      assert.equal((client as any).signRequestTimeout(), 360000);
    });
  });

  describe("signRequests", () => {
    // Audit finding 24: the wire report is snake_case, and callers read the
    // typed camelCase fields.
    it("returns the mutation report in its typed camelCase form", async () => {
      queueStatusResponse();
      mockFetch.mockImplementationOnce(signerFetch({ feeRaise: { 0: 2000 }, dummies: 1 }));

      const client = new SignerClient("http://localhost:11270");
      const result = await client.signRequests(signEntries(fakePayment()));

      assert.equal(result.mutations?.dummiesAdded, 1);
      assert.equal(result.mutations?.groupIdChanged, true);
      assert.deepEqual(result.mutations?.feesModified, [0]);
      assert.equal(result.mutations?.totalFeesDelta, 2000);
      assert.equal(result.mutations?.originalCount, 1);
      assert.equal(result.mutations?.finalCount, 2);
    });

    it("sends raw signing requests and returns raw response", async () => {
      queueStatusResponse();
      mockFetch.mockImplementationOnce(signerFetch());

      const txn = fakePayment();
      const entry = {
        txn_bytes_hex: encodeTransaction(txn)[0],
        auth_address: "AUTH",
        txn_sender: "SENDER",
      };
      const client = new SignerClient("http://localhost:11270");
      const result = await client.signRequests([{ ...entry }], { requestId: "raw-requests-id" });

      assert.deepEqual(result, { signed: [signedHex(txn)] });
      assert.equal(mockFetch.mock.calls[1][0], "http://localhost:11270/sign");
      assert.deepEqual(JSON.parse(mockFetch.mock.calls[1][1].body), {
        request_id: "raw-requests-id",
        requests: [entry],
      });
    });

    it("rejects non-canonical transaction bytes before fetch", async () => {
      const client = new SignerClient("http://localhost:11270");
      const canonical = encodeTransaction(fakePayment())[0];
      const callsBefore = mockFetch.mock.calls.length;
      await assert.rejects(
        client.signRequests([{ txn_bytes_hex: canonical.slice(4), auth_address: "AUTH" }]),
        /transaction 1: txn_bytes_hex: missing TX prefix/,
      );
      await assert.rejects(
        client.signRequests([{ txn_bytes_hex: `${canonical}00`, auth_address: "AUTH" }]),
        /transaction 1: txn_bytes_hex: /,
      );
      assert.equal(mockFetch.mock.calls.length, callsBefore);
    });

    it("validates raw group request IDs", async () => {
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.signRequests([{ txn_bytes_hex: "545801" }], { requestId: "bad id" }),
        { message: /invalid character/ },
      );
    });

    it("rejects unsupported raw native-PQ schemes before fetch", async () => {
      const client = new SignerClient("http://localhost:11270");
      const callsBefore = mockFetch.mock.calls.length;
      await assert.rejects(
        client.signRequests([{ txn_bytes_hex: "545801", pq_scheme: "f2" }]),
        /unsupported pq_scheme/,
      );
      assert.equal(mockFetch.mock.calls.length, callsBefore);
    });

    const invalidRawRequestCases: Array<{
      name: string;
      requests: any[];
      error: RegExp;
    }> = [
      {
        name: "LogicSig resources on a sign-mode slot",
        requests: [{
          txn_bytes_hex: "545801",
          auth_address: "AUTH",
          lsig_resources: { program_bytes: 1, argument_bytes: 0, max_opcode_cost: 1 },
        }],
        error: /lsig_resources is allowed only for foreign or passthrough/,
      },
      {
        name: "invalid passthrough LogicSig resources",
        requests: [{
          signed_txn_hex: "aabb",
          lsig_resources: { program_bytes: 0, argument_bytes: 0, max_opcode_cost: 0 },
        }],
        error: /LogicSig resources are invalid/,
      },
      {
        name: "mixed passthrough and foreign slots",
        requests: [
          { txn_bytes_hex: "545801", pq_scheme: "f1" },
          { signed_txn_hex: "aabb" },
        ],
        error: /cannot mix passthrough and foreign transactions/,
      },
      {
        name: "an all-foreign group",
        requests: [{ txn_bytes_hex: "545801", pq_scheme: "f1" }],
        error: /no signable transactions/,
      },
    ];
    for (const testCase of invalidRawRequestCases) {
      it(`rejects raw ${testCase.name} before fetch`, async () => {
        const client = new SignerClient("http://localhost:11270");
        const callsBefore = mockFetch.mock.calls.length;
        await assert.rejects(client.signRequests(testCase.requests), testCase.error);
        assert.equal(mockFetch.mock.calls.length, callsBefore);
      });
    }
  });

  describe("client-side signed simulation", () => {
    it("uses ordinary signing before calling the caller's algod", async () => {
      const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: testAddress(1),
        receiver: testAddress(2),
        amount: 1n,
        suggestedParams: {
          fee: 1000n,
          minFee: 1000n,
          firstValid: 1n,
          lastValid: 100n,
          genesisHash: new Uint8Array(32),
          genesisID: "testnet-v1",
          flatFee: true,
        },
      });
      const signature = new Uint8Array(64);
      signature[63] = 1;
      const signedBytes = algosdk.encodeMsgpack(
        new algosdk.SignedTransaction({ txn, sig: signature }),
      );
      const signedHex = bytesToHex(signedBytes);

      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          signed: [signedHex],
          mutations: { original_count: 1, final_count: 1 },
        }),
      });

      const simulationRequests: algosdk.modelsv2.SimulateRequest[] = [];
      const algodClient = {
        simulateTransactions: (request: algosdk.modelsv2.SimulateRequest) => {
          simulationRequests.push(request);
          return {
            do: async () => ({
              lastRound: 7n,
              version: 2n,
              txnGroups: [{ failureMessage: "logic eval error", txnResults: [] }],
            }),
          };
        },
      } as any;

      const client = new SignerClient("http://localhost:11270");
      const result = await client.simulatePreparedGroup(algodClient, {
        transactions: [{ transaction: txn, authAddress: testAddress(1) }],
      });

      assert.equal(mockFetch.mock.calls[1][0], "http://localhost:11270/sign");
      assert.equal(mockFetch.mock.calls.some((call) => call[0].endsWith("/simulate")), false);
      assert.equal(simulationRequests.length, 1);
      assert.equal(simulationRequests[0].allowEmptySignatures, false);
      assert.equal(simulationRequests[0].fixSigners, false);
      assert.deepEqual(
        algosdk.encodeMsgpack(simulationRequests[0].txnGroups[0].txns[0]),
        signedBytes,
      );
      assert.deepEqual(result.signedGroup, [signedHex]);
      assert.deepEqual(result.txIds, [txn.txID()]);
      assert.equal(result.mutations?.finalCount, 1);
      assert.equal(result.failed, true);
    });

    // A native post-quantum signature travels in pqsig. An algosdk without that
    // field drops it on decode, so simulation would see an unsigned transaction.
    it("keeps a native post-quantum signature through simulation", async () => {
      const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: testAddress(1),
        receiver: testAddress(2),
        amount: 1n,
        suggestedParams: {
          fee: 1000n,
          minFee: 1000n,
          firstValid: 1n,
          lastValid: 100n,
          genesisHash: new Uint8Array(32),
          genesisID: "testnet-v1",
          flatFee: true,
        },
      });
      const pqsig = {
        sch: new TextEncoder().encode("f1"),
        slt: 3,
        pk: new Uint8Array(1793).fill(7),
        sig: new Uint8Array(1232).fill(9),
      };
      const signedBytes = algosdk.encodeMsgpack(new algosdk.SignedTransaction({ txn, pqsig }));
      const signedHex = bytesToHex(signedBytes);

      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          signed: [signedHex],
          mutations: { original_count: 1, final_count: 1 },
        }),
      });

      const simulationRequests: algosdk.modelsv2.SimulateRequest[] = [];
      const algodClient = {
        simulateTransactions: (request: algosdk.modelsv2.SimulateRequest) => {
          simulationRequests.push(request);
          return {
            do: async () => ({ lastRound: 7n, version: 2n, txnGroups: [{ txnResults: [] }] }),
          };
        },
      } as any;

      const client = new SignerClient("http://localhost:11270");
      const result = await client.simulatePreparedGroup(algodClient, {
        transactions: [{ transaction: txn, authAddress: testAddress(1) }],
      });

      const simulated = simulationRequests[0].txnGroups[0].txns[0];
      assert.deepEqual(simulated.pqsig?.sig, pqsig.sig);
      assert.deepEqual(simulated.pqsig?.pk, pqsig.pk);
      assert.deepEqual(algosdk.encodeMsgpack(simulated), signedBytes);
      assert.deepEqual(result.signedGroup, [signedHex]);
    });

    it("requires algod before contacting the signer", async () => {
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(
        client.simulatePreparedGroup(null as any, { transactions: [] }),
        /algodClient is required/,
      );
      assert.equal(mockFetch.mock.calls.length, 0);
    });

    it("requires algod before starting cosigned signing", async () => {
      await assert.rejects(
        simulatePreparedCosignedGroup(null as any, {} as any),
        /algodClient is required/,
      );
      assert.equal(mockFetch.mock.calls.length, 0);
    });
  });

  describe("cancelSignRequest", () => {
    it("returns cancel state", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ success: true, state: "not_found" }),
      });

      const client = new SignerClient("http://localhost:11270");
      const result = await client.cancelSignRequest("sdk-test");

      assert.equal(result.success, true);
      assert.equal(result.state, "not_found");
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/sign/cancel");
      assert.deepEqual(JSON.parse(mockFetch.mock.calls[0][1].body), { request_id: "sdk-test" });
    });

    it("validates request id", async () => {
      const client = new SignerClient("http://localhost:11270");
      await assert.rejects(client.cancelSignRequest(""), { message: /request_id is required/ });
      await assert.rejects(client.cancelSignRequest("bad id"), { message: /invalid character/ });
    });
  });
});

describe("encoding utilities", () => {
  describe("bytesToHex", () => {
    it("converts Uint8Array to hex string", () => {
      const bytes = new Uint8Array([0, 1, 255, 16, 171]);
      assert.equal(bytesToHex(bytes), "0001ff10ab");
    });

    it("handles empty array", () => {
      assert.equal(bytesToHex(new Uint8Array([])), "");
    });
  });

  describe("hexToBytes", () => {
    it("converts hex string to Uint8Array", () => {
      const hex = "0001ff10ab";
      const bytes = hexToBytes(hex);
      assert.deepEqual(bytes, new Uint8Array([0, 1, 255, 16, 171]));
    });

    it("handles empty string", () => {
      assert.deepEqual(hexToBytes(""), new Uint8Array([]));
    });

    it("rejects invalid hex", () => {
      assert.throws(() => hexToBytes("zz"), SignerError);
    });

    it("rejects odd-length hex", () => {
      assert.throws(() => hexToBytes("abc"), SignerError);
    });
  });

  describe("concatenateSignedTxns", () => {
    it("concatenates hex strings to base64", () => {
      const hexes = ["0102", "0304"];
      const result = concatenateSignedTxns(hexes);
      // Should be base64 of [1, 2, 3, 4]
      assert.equal(result, "AQIDBA==");
    });

    it("handles single transaction", () => {
      const hexes = ["deadbeef"];
      const result = concatenateSignedTxns(hexes);
      // Should be base64 of [0xde, 0xad, 0xbe, 0xef]
      assert.equal(result, "3q2+7w==");
    });

    it("encodes a large group without exceeding the argument-spread limit", () => {
      // ~64 KB across 16 entries: would overflow String.fromCharCode(...bytes)
      // in the browser fallback if not chunked. Verify it round-trips.
      const big = "ab".repeat(2048); // 2 KB per entry
      const hexes = Array.from({ length: 16 }, () => big);
      const result = concatenateSignedTxns(hexes);
      const decoded = Buffer.from(result, "base64");
      assert.equal(decoded.length, 16 * 2048);
    });
  });
});

describe("loadConfig", () => {
  it("returns defaults when no config file", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-test-"));
    try {
      const config = loadConfig(tmpDir);
      assert.equal(config.network, "testnet");
      assert.equal(config.theme, "auto");
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("rejects obsolete endpoint routing", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-test-"));
    try {
      fs.writeFileSync(
        path.join(tmpDir, "config.yaml"),
        "endpoint:\n" +
        "  signer_port: 12345\n" +
        "  ssh:\n" +
        "    host: signer.example.com\n" +
        "    port: 2222\n" +
        "    identity_file: .ssh/mykey\n" +
        "    known_hosts_path: .ssh/hosts\n" +
        "    trust_on_first_use: true\n"
      );
      assert.throws(
        () => loadConfig(tmpDir),
        /remove "endpoint" and configure endpoints.yaml/,
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("rejects malformed YAML", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-test-"));
    try {
      fs.writeFileSync(
        path.join(tmpDir, "config.yaml"),
        "network: ["
      );
      assert.throws(() => loadConfig(tmpDir), /failed to parse config.yaml/);
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });
});

describe("loadClientEndpointRegistry", () => {
  function fixtureDir(name: string): string {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-endpoints-"));
    fs.copyFileSync(
      path.join("..", "contracts", "clientconfig", name),
      path.join(tmpDir, "endpoints.yaml"),
    );
    return tmpDir;
  }

  it("loads the shared valid fixture", () => {
    const tmpDir = fixtureDir("valid.yaml");
    try {
      const registry = loadClientEndpointRegistry(tmpDir);
      assert.equal(registry.default, "primary");
      assert.equal(registry.endpoints.primary.url, "ssh://signer.example.com:2222");
      assert.equal(
        registry.endpoints.primary.identityFile,
        path.join(tmpDir, ".ssh", "primary"),
      );
      assert.equal(registry.endpoints["cosigner.qa"].url, "ssh://cosigner.example.com");
      assert.equal(
        registry.endpoints["cosigner.qa"].identityFile,
        path.join(tmpDir, "credentials", "cosigner"),
      );
      assert.equal(
        registry.endpoints["cosigner.qa"].knownHostsPath,
        path.join(tmpDir, ".ssh", "known_hosts"),
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  for (const fixture of [
    "invalid_default_type.yaml",
    "invalid_identity_file_type.yaml",
    "invalid_multiple_signers.yaml",
    "invalid_remote_http.yaml",
    "invalid_loopback_http.yaml",
    "invalid_https.yaml",
    "invalid_schema_version_float.yaml",
    "invalid_ssh_port_zero.yaml",
    "invalid_unknown_field.yaml",
    "invalid_unknown_tag.yaml",
  ]) {
    it(`rejects ${fixture}`, () => {
      const tmpDir = fixtureDir(fixture);
      try {
        assert.throws(() => loadClientEndpointRegistry(tmpDir));
      } finally {
        fs.rmSync(tmpDir, { recursive: true });
      }
    });
  }

  for (const [fixture, message] of [
    ["invalid_self_signer.yaml", 'endpoint "primary": url "self" is not supported'],
    ["invalid_self_cosigner.yaml", 'endpoint "cosigner": url "self" is not supported'],
    ["invalid_13_cosigner_endpoints.yaml", "configures 13 cosigner endpoints; maximum is 12"],
    ["invalid_v2_published_cosigners.yaml", "published_cosigners"],
  ]) {
    it(`rejects ${fixture} for the expected reason`, () => {
      const tmpDir = fixtureDir(fixture);
      try {
        assert.throws(() => loadClientEndpointRegistry(tmpDir), (error: unknown) =>
          error instanceof Error && error.message.includes(message),
        );
      } finally {
        fs.rmSync(tmpDir, { recursive: true });
      }
    });
  }

  for (const fixture of [
    "valid_12_cosigner_endpoints.yaml",
    "valid_retired_port_fields.yaml",
  ]) {
    it(`accepts ${fixture}`, () => {
      const tmpDir = fixtureDir(fixture);
      try {
        const registry = loadClientEndpointRegistry(tmpDir);
        assert.equal(registry.schemaVersion, 2);
        if (fixture === "valid_12_cosigner_endpoints.yaml") {
          assert.equal(Object.keys(registry.endpoints).length, 12);
        }
        if (fixture === "valid_retired_port_fields.yaml") {
          assert.equal(registry.endpoints.primary.url, "ssh://signer.example.com:2222");
          assert.equal(
            registry.endpoints.primary.identityFile,
            path.join(tmpDir, ".ssh", "id_ed25519"),
          );
          assert.ok(registry.endpoints.cosigner);
        }
      } finally {
        fs.rmSync(tmpDir, { recursive: true });
      }
    });
  }

  for (const [fixture, message] of [
    ["invalid_schema_version_missing.yaml", "endpoints.yaml schema_version = 0, want 2"],
    ["invalid_schema_version_zero.yaml", "endpoints.yaml schema_version = 0, want 2"],
    ["invalid_schema_version_null.yaml", "endpoints.yaml schema_version = null, want 2"],
    ["invalid_schema_version_float.yaml", "endpoints.yaml schema_version = 2.0, want 2"],
    ["invalid_schema_version_one.yaml", "endpoints.yaml schema_version = 1, want 2"],
    ["invalid_v1_published_cosigners.yaml", "endpoints.yaml schema_version = 1, want 2"],
  ]) {
    it(`requires schema_version 2 (${fixture})`, () => {
      const tmpDir = fixtureDir(fixture);
      try {
        assert.throws(() => loadClientEndpointRegistry(tmpDir), (error: unknown) =>
          error instanceof Error && error.message.includes(message),
        );
      } finally {
        fs.rmSync(tmpDir, { recursive: true });
      }
    });
  }

  it("derives the signer default and the default client identity", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-endpoints-"));
    try {
      fs.writeFileSync(
        path.join(tmpDir, "endpoints.yaml"),
        "schema_version: 2\nendpoints:\n" +
        "  main:\n    role: signer\n    url: ssh://localhost\n" +
        "  qa:\n    role: cosigner\n    url: ssh://127.0.0.1:2222\n",
      );
      const registry = loadClientEndpointRegistry(tmpDir);
      assert.equal(registry.default, "main");
      for (const alias of ["main", "qa"]) {
        assert.equal(
          registry.endpoints[alias].identityFile,
          path.join(tmpDir, ".ssh", "id_ed25519"),
        );
        assert.equal(
          registry.endpoints[alias].knownHostsPath,
          path.join(tmpDir, ".ssh", "known_hosts"),
        );
      }
      assert.equal(resolveClientEndpoint(registry).alias, "main");
      assert.equal(resolveClientEndpoint(registry, "qa").endpoint.role, "cosigner");
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });
});

describe("requestEnrollment", () => {
  // The signer answers at once: queued for the operator (pending) or already
  // enrolled. Either way the fingerprint must be the authenticating key's.
  it("parses pending and enrolled replies for the authenticating key", () => {
    const fp = "SHA256:abc";
    assert.deepEqual(parseEnrollmentReply(`pending ${fp}`, fp), { fingerprint: fp, pending: true });
    assert.deepEqual(parseEnrollmentReply(`enrolled ${fp}`, fp), { fingerprint: fp, pending: false });
    assert.throws(() => parseEnrollmentReply("pending SHA256:other", fp), /this client authenticated with SHA256:abc/);
    for (const reply of ["enrolled ", `ok ${fp}`, ""]) {
      assert.throws(() => parseEnrollmentReply(reply, fp), /Unexpected enrollment response/);
    }
  });

  it("rejects missing known_hosts path locally", async () => {
    await assert.rejects(
      requestEnrollment("signer.example.com", "~/aplane/apclient/.ssh/id_ed25519"),
      { message: /known_hosts path is required/ },
    );
  });

  it("rejects bad labels before any network activity", async () => {
    for (const label of ["x".repeat(65), "two\nlines", " padded", "tab\tbed"]) {
      await assert.rejects(
        requestEnrollment("signer.example.com", "/nonexistent/key", {
          knownHostsPath: "/nonexistent/known_hosts",
          label,
        }),
        { message: /enrollment label/ },
      );
    }
  });

  it("closes a stalled SSH handshake at the setup deadline", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-token-timeout-"));
    const sockets = new Set<net.Socket>();
    const server = net.createServer((socket) => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
      socket.resume();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const { privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "pkcs1", format: "pem" },
    });
    const keyPath = path.join(tmpDir, "id_rsa");
    fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });

    try {
      await assert.rejects(
        requestEnrollment("127.0.0.1", keyPath, {
          sshPort: address.port,
          knownHostsPath: path.join(tmpDir, "known_hosts"),
          setupTimeout: 50,
        }),
        /timed out|timeout/i,
      );
      await waitForSocketsToClose(sockets);
      assert.equal(sockets.size, 0);
    } finally {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("fails when the peer closes before the handshake completes", async () => {
    await withEarlyClosingSSHPeer("aplane-token-early-close-", async (port, keyPath, knownHostsPath) => {
      await assert.rejects(
        settlesWithin(
          requestEnrollment("127.0.0.1", keyPath, { sshPort: port, knownHostsPath, setupTimeout: 60_000 }),
          2_000,
        ),
        /closed before setup completed/,
      );
    });
  });
});

describe("requestEnrollmentFromEnv", () => {
  it("rejects removed host routing options at runtime", async () => {
    await assert.rejects(
      requestEnrollmentFromEnv({
        host: "signer.example.com",
      } as unknown as Parameters<typeof requestEnrollmentFromEnv>[0]),
      { message: /option "host" was removed/ },
    );
  });

  it("selects a named SSH endpoint", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-token-"));
    try {
      fs.writeFileSync(
        path.join(tmpDir, "endpoints.yaml"),
        "schema_version: 2\nendpoints:\n" +
        "  primary:\n    role: signer\n    url: ssh://signer.example.com\n" +
        "  qa:\n    role: cosigner\n    url: ssh://cosigner.example.com:2222\n" +
        "    identity_file: .ssh/qa\n",
      );
      await assert.rejects(
        requestEnrollmentFromEnv({ dataDir: tmpDir, endpoint: "qa" }),
        { message: /SSH key not found at .*qa/ },
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("rejects non-SSH endpoints at registry load", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-token-"));
    try {
      fs.writeFileSync(
        path.join(tmpDir, "endpoints.yaml"),
        "schema_version: 2\nendpoints:\n" +
        "  primary:\n    role: signer\n    url: https://signer.example.com\n",
      );
      await assert.rejects(
        requestEnrollmentFromEnv({ dataDir: tmpDir }),
        { message: /unsupported url scheme "https"/ },
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });
});

describe("buildSignRequests", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  const createMockTxn = (sender?: string) => fakePayment(41, 42, 1_000_000, sender);

  it("builds request with auth address", async () => {
    queueStatusResponse();
    mockFetch.mockImplementationOnce(signerFetch());

    const client = new SignerClient("http://localhost:11270");
    const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];
    await client.signTransaction(mockTxn, "AUTH_ADDR");

    const capturedBody = JSON.parse(mockFetch.mock.calls[1][1].body);
    assert.match(capturedBody.request_id, /^sdk-[0-9a-f]{32}$/);
    assert.equal(capturedBody.requests.length, 1);
    assert.equal(capturedBody.requests[0].auth_address, "AUTH_ADDR");
    assert.notEqual(capturedBody.requests[0].txn_bytes_hex, undefined);
  });

  it("defaults auth address to sender", async () => {
    queueStatusResponse();
    mockFetch.mockImplementationOnce(signerFetch());

    const client = new SignerClient("http://localhost:11270");
    const mockTxn = createMockTxn(fakeAddress(77)) as Parameters<typeof client.signTransaction>[0];
    await client.signTransaction(mockTxn);

    const capturedBody = JSON.parse(mockFetch.mock.calls[1][1].body);
    assert.equal(capturedBody.requests[0].auth_address, fakeAddress(77));
  });

  it("includes lsig args as hex", async () => {
    queueStatusResponse();
    mockFetch.mockImplementationOnce(signerFetch());

    const client = new SignerClient("http://localhost:11270");
    const mockTxn = createMockTxn(fakeAddress(78)) as Parameters<typeof client.signTransaction>[0];
    await client.signTransaction(mockTxn, fakeAddress(78), {
      preimage: new Uint8Array([0x73, 0x65, 0x63, 0x72, 0x65, 0x74]),
    });

    const capturedBody = JSON.parse(mockFetch.mock.calls[1][1].body);
    assert.notEqual(capturedBody.requests[0].lsig_args, undefined);
    assert.equal(capturedBody.requests[0].lsig_args.preimage, "736563726574");
  });

  // Audit finding 22: args keyed under an address no position signs with were
  // dropped without a word.
  it("sends lsig args for the sender when no auth address is given", async () => {
    const mockTxn = createMockTxn();
    for (const authAddress of [undefined, ""]) {
      const client = new SignerClient("http://localhost:11270");
      mockFetch.mockReset();
      queueStatusResponse();
      mockFetch.mockImplementationOnce(signerFetch());
      await client.signTransaction(mockTxn, authAddress, { preimage: new Uint8Array([0x73]) });

      const request = JSON.parse(mockFetch.mock.calls.at(-1)?.[1].body).requests[0];
      assert.equal(request.auth_address, mockTxn.sender.toString());
      assert.deepEqual(request.lsig_args, { preimage: "73" });
    }
  });

  it("rejects lsig args no position matches", async () => {
    const client = new SignerClient("http://localhost:11270");
    const mockTxn = createMockTxn();
    const stray = { [fakeAddress(79)]: { preimage: new Uint8Array([0x73]) } };
    const unmatched = /no transaction in the request has auth address/;

    await assert.rejects(client.signTransactions([mockTxn], undefined, stray), unmatched);
    await assert.rejects(client.signTransactionsList([mockTxn], undefined, stray), unmatched);
    await assert.rejects(client.planGroup([mockTxn], undefined, stray), unmatched);
    assert.equal(mockFetch.mock.calls.length, 0);
  });

  it("ignores lsig args entries with no args", () => {
    const client = new SignerClient("http://localhost:11270");
    const mockTxn = createMockTxn();
    const sender = mockTxn.sender.toString();
    const body = (client as any).buildSignRequestBody([mockTxn], [sender], {
      [fakeAddress(79)]: undefined,
      [fakeAddress(80)]: {},
    });
    assert.equal(body.requests[0].lsig_args, undefined);
  });

  // One args map serves every call over a group: the plan with a foreign
  // position, and the final signing once that position came back signed.
  it("accepts a reused lsig args map", async () => {
    const client = new SignerClient("http://localhost:11270");
    const grouped = algosdk.assignGroupID([fakePayment(41, 42), fakePayment(43, 44)]);
    const first = grouped[0].sender.toString();
    const second = grouped[1].sender.toString();
    const args = {
      [first]: { preimage: new Uint8Array([1]) },
      [second]: { preimage: new Uint8Array([2]) },
    };

    const planBody = (client as any).buildSignRequestBody(grouped, [first, null], args);
    assert.deepEqual(planBody.requests[0].lsig_args, { preimage: "01" });
    assert.equal(planBody.requests[1].lsig_args, undefined);

    const signedSecond = Buffer.from(signedHex(grouped[1]), "hex").toString("base64");
    const cases: Array<[string, any[], Array<string | null>]> = [
      ["auth address given", grouped, [first, second]],
      ["sender of the slot", grouped, [first, null]],
      ["only the signed bytes", [grouped[0], null], [first, null]],
    ];
    for (const [name, txns, auths] of cases) {
      const body = (client as any).buildSignRequestBody(
        txns, auths, args, { 1: signedSecond }, undefined, false,
      );
      assert.deepEqual(body.requests[0].lsig_args, { preimage: "01" }, name);
      assert.deepEqual(Object.keys(body.requests[1]), ["signed_txn_hex"], name);
    }

    queueStatusResponse();
    mockFetch.mockImplementationOnce(signerFetch());
    const signed = await client.signTransactionsList(
      grouped, [first, second], args, { 1: signedSecond },
    );
    assert.equal(signed[1], signedSecond);
  });
});

describe("preparedGroupToSignRequests", () => {
  const createMockTxn = (sender = "SENDER_ADDRESS") => ({
    sender: { toString: () => sender },
    toByte: () => new Uint8Array([1, 2, 3]),
  });

  it("builds sign-mode requests", () => {
    const requests = preparedGroupToSignRequests({
      transactions: [{
        transaction: createMockTxn() as any,
        authAddress: "AUTH_ADDR",
        txnSender: "DISPLAY_SENDER",
        lsigArgs: {
          preimage: new Uint8Array([0x73, 0x65, 0x63, 0x72, 0x65, 0x74]),
        },
        appCallInfo: {
          mode: "abi",
          method: "do(uint64)void",
        },
      }],
    });

    assert.equal(requests.length, 1);
    assert.equal(requests[0].txn_bytes_hex, "5458010203");
    assert.equal(requests[0].auth_address, "AUTH_ADDR");
    assert.equal(requests[0].txn_sender, "DISPLAY_SENDER");
    assert.equal(requests[0].lsig_args?.preimage, "736563726574");
    assert.equal(requests[0].app_call_info?.method, "do(uint64)void");
  });

  it("builds foreign-mode requests", () => {
    const requests = preparedGroupToSignRequests({
      transactions: [{
        transaction: createMockTxn() as any,
        lsigResources: { programBytes: 1612, argumentBytes: 1423, maxOpcodeCost: 20000 },
      }],
    });

    assert.equal(requests.length, 1);
    assert.equal(requests[0].txn_bytes_hex, "5458010203");
    assert.equal(requests[0].auth_address, undefined);
    assert.equal(requests[0].lsig_resources?.program_bytes, 1612);
  });

  it("builds passthrough requests", () => {
    const requests = preparedGroupToSignRequests({
      transactions: [{
        signedTransactionBase64: Buffer.from("signed-txn").toString("base64"),
        lsigResources: { programBytes: 1612, argumentBytes: 1423, maxOpcodeCost: 20000 },
      }],
    });

    assert.deepEqual(requests, [{
      signed_txn_hex: Buffer.from("signed-txn").toString("hex"),
      lsig_resources: {
        program_bytes: 1612,
        argument_bytes: 1423,
        max_opcode_cost: 20000,
      },
    }]);
  });

  it("rejects authorization hints in sign and passthrough modes", () => {
    assert.throws(
      () => preparedGroupToSignRequests({
        transactions: [{
          transaction: createMockTxn() as any,
          authAddress: "AUTH_ADDR",
          pqScheme: "f1",
        }],
      }),
      /pqScheme is allowed only for foreign transactions/,
    );
    assert.throws(
      () => preparedGroupToSignRequests({
        transactions: [{
          transaction: createMockTxn() as any,
          authAddress: "AUTH_ADDR",
          lsigResources: { programBytes: 1612, argumentBytes: 1423, maxOpcodeCost: 20000 },
        }],
      }),
      /lsigResources is allowed only for foreign or passthrough transactions/,
    );
    assert.throws(
      () => preparedGroupToSignRequests({
        transactions: [{
          signedTransactionBase64: Buffer.from("signed-txn").toString("base64"),
          pqScheme: "f1",
        }],
      }),
      /pqScheme is allowed only for foreign transactions/,
    );
  });

  it("rejects empty groups", () => {
    assert.throws(
      () => preparedGroupToSignRequests({ transactions: [] }),
      /prepared group is empty/,
    );
  });
});

describe("fromEnv", () => {
  it("throws when no default endpoint is configured", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-test-"));
    try {
      await assert.rejects(
        SignerClient.fromEnv({ dataDir: tmpDir }),
        { message: /no default signer endpoint/ },
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("connects a named endpoint with its own SSH identity", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-test-"));
    try {
      fs.writeFileSync(
        path.join(tmpDir, "endpoints.yaml"),
        "schema_version: 2\nendpoints:\n" +
        "  primary:\n    role: signer\n    url: ssh://signer.example.com/\n" +
        "  qa:\n    role: cosigner\n    url: ssh://127.0.0.1:1/\n    identity_file: keys/qa\n",
      );
      // The key is the only credential, so a missing identity file is the
      // first failure.
      await assert.rejects(
        SignerClient.fromEnv({ dataDir: tmpDir, endpoint: "qa", timeout: 7000 }),
        { message: new RegExp(`SSH key not found at .*${path.join("keys", "qa")}`) },
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("forwards maxFeeIncrease to the connection", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-ts-fee-"));
    const original = SignerClient.connectSsh;
    let forwarded: any;
    (SignerClient as any).connectSsh = async (_host: string, _key: string, options: any) => {
      forwarded = options;
      return new SignerClient("http://localhost:11270", undefined, null, options);
    };
    try {
      fs.writeFileSync(
        path.join(tmpDir, "endpoints.yaml"),
        "schema_version: 2\nendpoints:\n" +
        "  primary:\n    role: signer\n    url: ssh://signer.example.com/\n    identity_file: key\n",
      );
      fs.writeFileSync(path.join(tmpDir, "key"), "dummy-private-key");
      const client = await SignerClient.fromEnv({ dataDir: tmpDir, maxFeeIncrease: 250_000 });
      assert.equal(forwarded.maxFeeIncrease, 250_000);
      assert.strictEqual(client.maxFeeIncrease, 250_000);
    } finally {
      (SignerClient as any).connectSsh = original;
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  for (const [fixture, message] of [
    ["invalid_self_signer.yaml", 'endpoint "primary": url "self" is not supported'],
    ["invalid_self_cosigner.yaml", 'endpoint "cosigner": url "self" is not supported'],
  ]) {
    it(`rejects ${fixture} before connecting`, async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-test-"));
      try {
        fs.copyFileSync(
          path.join("..", "contracts", "clientconfig", fixture),
          path.join(tmpDir, "endpoints.yaml"),
        );
        await assert.rejects(SignerClient.fromEnv({ dataDir: tmpDir }), (error: unknown) =>
          error instanceof Error && error.message.includes(message),
        );
      } finally {
        fs.rmSync(tmpDir, { recursive: true });
      }
    });
  }
});

describe("connectSsh", () => {
  it("rejects missing knownHostsPath at method entry", async () => {
    await assert.rejects(
      SignerClient.connectSsh("example.com", "~/aplane/apclient/.ssh/id_ed25519"),
      { message: /known_hosts path is required/ },
    );
  });

  it("closes a stalled SSH handshake at the setup deadline", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-ssh-timeout-"));
    const sockets = new Set<net.Socket>();
    const server = net.createServer((socket) => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
      socket.resume();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const { privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "pkcs1", format: "pem" },
    });
    const keyPath = path.join(tmpDir, "id_rsa");
    fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });

    try {
      await assert.rejects(
        SignerClient.connectSsh("127.0.0.1", keyPath, {
          sshPort: address.port,
          knownHostsPath: path.join(tmpDir, "known_hosts"),
          sshSetupTimeout: 50,
        }),
        /timed out|timeout/i,
      );
      await waitForSocketsToClose(sockets);
      assert.equal(sockets.size, 0);
    } finally {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("fails when the peer closes before the handshake completes", async () => {
    await withEarlyClosingSSHPeer("aplane-ssh-early-close-", async (port, keyPath, knownHostsPath) => {
      await assert.rejects(
        settlesWithin(
          SignerClient.connectSsh("127.0.0.1", keyPath, {
            sshPort: port,
            knownHostsPath,
            sshSetupTimeout: 60_000,
          }),
          2_000,
        ),
        /closed before setup completed/,
      );
    });
  });

  it("cancels a stalled SSH handshake and closes its socket", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-ssh-cancel-"));
    const sockets = new Set<net.Socket>();
    const server = net.createServer((socket) => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
      socket.resume();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const { privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "pkcs1", format: "pem" },
    });
    const keyPath = path.join(tmpDir, "id_rsa");
    fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });
    const controller = new AbortController();

    try {
      const connecting = SignerClient.connectSsh("127.0.0.1", keyPath, {
        sshPort: address.port,
        knownHostsPath: path.join(tmpDir, "known_hosts"),
        sshSetupTimeout: 1_000,
        signal: controller.signal,
      });
      controller.abort();
      await assert.rejects(connecting, /SSH setup canceled/);
      await waitForSocketsToClose(sockets);
      assert.equal(sockets.size, 0);
    } finally {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      fs.rmSync(tmpDir, { recursive: true });
    }
  });
});

describe("sign return format", () => {
  const createMockTxn = () => fakePayment();

  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("signTransactionsList returns individual base64 strings", async () => {
    queueStatusResponse();
    mockFetch.mockImplementationOnce(signerFetch());

    const client = new SignerClient("http://localhost:11270");
    const txns = [fakePayment(41, 42), fakePayment(43, 44)];
    const result = await client.signTransactionsList(txns);

    assert.equal(result.length, 2);
    // Each slot signs its own transaction, changed only by the group ID the
    // signer assigned.
    result.forEach((item, index) => {
      const signed = algosdk.decodeSignedTransaction(Buffer.from(item, "base64"));
      assert.notEqual(signed.txn.group, undefined);
      signed.txn.group = undefined;
      assert.deepEqual(signed.txn.toByte(), txns[index].toByte());
    });
  });

  it("signTransactions returns concatenated base64", async () => {
    const client = new SignerClient("http://localhost:11270");
    const txns = [fakePayment(41, 42), fakePayment(43, 44)];

    queueStatusResponse();
    mockFetch.mockImplementationOnce(signerFetch());
    const result = await client.signTransactions(txns);
    mockFetch.mockImplementationOnce(signerFetch());
    const individual = await client.signTransactionsList(txns);

    assert.deepEqual(
      Buffer.from(result, "base64"),
      Buffer.concat(individual.map((item) => Buffer.from(item, "base64"))),
    );
  });

  it("signTransactions rejects empty transaction arrays locally", async () => {
    mockFetch.mockReset();
    const client = new SignerClient("http://localhost:11270");
    await assert.rejects(client.signTransactions([]), SignerError);
    assert.equal(mockFetch.mock.calls.length, 0);
  });

  it("signTransactionsList rejects empty transaction arrays locally", async () => {
    mockFetch.mockReset();
    const client = new SignerClient("http://localhost:11270");
    await assert.rejects(client.signTransactionsList([]), SignerError);
    assert.equal(mockFetch.mock.calls.length, 0);
  });

  it("planGroup uses SignerError for auth address length mismatch", async () => {
    const client = new SignerClient("http://localhost:11270");
    const mockTxn = createMockTxn() as Parameters<typeof client.planGroup>[0][0];
    await assert.rejects(client.planGroup([mockTxn], ["A", "B"]), SignerError);
  });
});

describe("assembleGroup", () => {
  it("merges two signers into one group", () => {
    // Alice signed slots 0,2; Bob signed slot 1
    const aliceSigned = [
      Buffer.from([1, 2]).toString("base64"),
      "",
      Buffer.from([5, 6]).toString("base64"),
    ];
    const bobSigned = [
      "",
      Buffer.from([3, 4]).toString("base64"),
      "",
    ];

    const result = assembleGroup([aliceSigned, bobSigned]);
    // Should be base64 of [1,2,3,4,5,6]
    assert.equal(result, Buffer.from([1, 2, 3, 4, 5, 6]).toString("base64"));
  });

  it("throws on empty input", () => {
    assert.throws(() => assembleGroup([]), { message: /must not be empty/ });
  });

  it("throws on mismatched lengths", () => {
    assert.throws(() => assembleGroup([["a", "b"], ["c"]]), { message: /expected 2/ });
  });

  it("throws on slot with no signer", () => {
    assert.throws(() => assembleGroup([["a", ""], ["", ""]]), { message: /slot 1: no signer/ });
  });

  it("throws on slot with multiple signers", () => {
    assert.throws(() => assembleGroup([["a", "b"], ["c", "d"]]), { message: /slot 0: multiple signers/ });
  });
});

describe("boundedFeeCeiling", () => {
  const info = (contract: string, maxFee?: number): BoundedAuthorizationInfo => ({
    contract,
    baseSignatureArgLayout: { count: 1, maxSizes: [1280] },
    spendEffects: [],
    maxFee,
    rekey: "refused",
    runtimeArgs: [],
    derivedArgs: [],
    argumentLayout: [],
    layer3Policy: "none",
  });

  it("follows the contract", () => {
    assert.equal(boundedFeeCeiling(info("bounded2", 10_000)), 10_000);
    assert.equal(boundedFeeCeiling(info("plain1")), undefined);
    assert.throws(() => boundedFeeCeiling(info("bounded2")), /has no max_fee/);
    assert.throws(() => boundedFeeCeiling(info("plain1", 0)), /never has/);
    assert.throws(() => boundedFeeCeiling(info("bounded3", 1)), /not supported/);
  });
});
