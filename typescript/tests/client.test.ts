// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import algosdk from "algosdk";
import {
  SignerClient,
  signGuardedGroup,
  signPreparedGuardedGroup,
  simulateGuardedGroup,
} from "../src/client.js";
import {
  COMPONENT_SIGN_ROLE_SENTRY,
  KEY_TYPE_GUARDED_FALCON1024_SENTRY1024,
  KEY_TYPE_WITNESS_FALCON1024,
  SIGNING_FLOW_SENTRY1,
  SIGNING_FLOW_BOUNDED_SENTRY1,
} from "../src/types.js";
import {
  AuthenticationError,
  SigningRejectedError,
  SignerUnavailableError,
  SignerError,
  KeyNotFoundError,
  KeyDeletionError,
} from "../src/errors.js";
import { requestToken, requestTokenToFile } from "../src/utils.js";
import { bytesToHex, hexToBytes, concatenateSignedTxns, encodeTransaction, encodeLsigArgs } from "../src/encoding.js";
import { assembleGroup } from "../src/utils.js";
import {
  loadClientEndpointRegistry,
  loadConfig,
  loadTokenFromDir,
  resolveClientEndpoint,
} from "../src/config.js";
import { preparedGroupToSignRequests } from "../src/prepared.js";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

// --- Mock fetch helper ---

interface MockFetch {
  (...args: any[]): Promise<any>;
  mock: { calls: any[][] };
  mockResolvedValueOnce(val: any): MockFetch;
  mockRejectedValueOnce(err: any): MockFetch;
  mockReset(): void;
}

function createMockFetch(): MockFetch {
  const calls: any[][] = [];
  const queue: Array<{ type: "resolve" | "reject"; value: any }> = [];

  const fn = ((...args: any[]) => {
    calls.push(args);
    const entry = queue.shift();
    if (!entry) return Promise.reject(new Error("mock: no queued response"));
    if (entry.type === "reject") return Promise.reject(entry.value);
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
  fn.mockReset = () => {
    calls.length = 0;
    queue.length = 0;
  };

  return fn;
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
      identity_id: "default",
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
      const result = await client.health();

      assert.equal(result, false);
    });

    it("returns false on network error", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network error"));

      const client = new SignerClient("http://localhost:11270", "test-token");
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
          identity_id: "default",
          state: "unlocked",
          signer_locked: false,
          ready_for_signing: true,
          key_count: 37,
          keyset_revision: 4,
          approval_wait_seconds: 60,
        }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      const identity = await client.getStatus();

      assert.equal(identity.identityId, "default");
      assert.equal(identity.keysetRevision, 4);
      assert.equal(identity.approvalWaitSeconds, 60);
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/status");
      assert.equal(mockFetch.mock.calls[0][1].method, "GET");
    });

    it("returns locked state as successful status data", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          identity_id: "default",
          state: "locked",
          signer_locked: true,
          ready_for_signing: false,
          key_count: 0,
          keyset_revision: 2,
        }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      const identity = await client.getStatus();

      assert.equal(identity.state, "locked");
      assert.equal(identity.signerLocked, true);
      assert.equal(identity.readyForSigning, false);
    });

    it("throws AuthenticationError on 401", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 401,
        ok: false,
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
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
            lsig_size: 0,
            is_generic_lsig: false,
          },
          {
            address: "ADDR2",
            public_key_hex: "def456",
            key_type: "aplane.falcon1024.v1",
            lsig_size: 3035,
            is_generic_lsig: false,
            template_status: "unavailable",
            template_warning: "template fingerprint unavailable",
          },
        ],
      };

      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => mockKeys,
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      const keys = await client.listKeys();

      assert.equal(keys.length, 2);
      assert.equal(keys[0].address, "ADDR1");
      assert.equal(keys[0].keyType, "ed25519");
      assert.equal(keys[1].address, "ADDR2");
      assert.equal(keys[1].lsigSize, 3035);
      assert.equal(keys[1].templateStatus, "unavailable");
      assert.equal(keys[1].templateWarning, "template fingerprint unavailable");
      assert.equal(keys[1].templateProvenanceStatus, "unavailable");
      assert.equal(keys[1].templateProvenanceNote, "template fingerprint unavailable");
    });

    it("throws AuthenticationError on 401", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 401,
        ok: false,
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(client.listKeys(), AuthenticationError);
    });

    it("surfaces signer JSON error bodies", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 500,
        ok: false,
        json: async () => ({ error: "inventory unavailable" }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");

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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
      const resolved = await client.resolveAuthAddress("SENDER", () => ({}));

      assert.equal(resolved.address, "SENDER");
      assert.equal(resolved.authAddress, "SENDER");
      assert.equal(resolved.isRekeyed, false);
      assert.equal(resolved.keyInfo.address, "SENDER");
    });

    it("resolves rekeyed accounts", async () => {
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse("AUTH"));

      const client = new SignerClient("http://localhost:11270", "test-token");
      const resolved = await client.resolveAuthAddress(
        "SENDER",
        () => ({ "auth-addr": "AUTH" }),
      );

      assert.equal(resolved.address, "SENDER");
      assert.equal(resolved.authAddress, "AUTH");
      assert.equal(resolved.isRekeyed, true);
      assert.equal(resolved.keyInfo.address, "AUTH");
    });

    it("rejects rekeyed accounts whose auth address is not signable", async () => {
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse("SENDER"));

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
      const prepared = await client.preparePayment(algod, {
        sender,
        receiver,
        amount: 10_000,
        fee: 1000,
        useFlatFee: true,
      });

      assert.equal(prepared.authAddress, sender);
      assert.equal(prepared.signerKey?.address, sender);
      assert.equal((prepared.transaction as any).payment.receiver.toString(), receiver);
      assert.equal(String((prepared.transaction as any).fee), "1000");
      assert.equal(prepared.checks?.[0].name, "payment_balance");
    });

    it("treats a set fee as flat microAlgos without useFlatFee", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({ [sender]: { amount: 2_000_000, minBalance: 100_000 } });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270", "test-token");
      const prepared = await client.preparePayment(algod, {
        sender,
        receiver,
        amount: 10_000,
        fee: 5000, // no useFlatFee: must still be a flat 5000, never EstimateSize*5000
      });

      assert.equal(String((prepared.transaction as any).fee), "5000");
    });

    it("applies an explicit zero fee as a flat zero", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({ [sender]: { amount: 2_000_000, minBalance: 100_000 } });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
      const prepared = await client.prepareRekey(algod, { sender, rekeyTo });

      assert.equal((prepared.transaction as any).rekeyTo.toString(), rekeyTo);
      assert.equal(prepared.checks?.[0].name, "rekey");
    });

    it("rejects rekey chains", async () => {
      const sender = testAddress(1);
      const rekeyTo = testAddress(2);
      const other = testAddress(3);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
        [rekeyTo]: { amount: 2_000_000, minBalance: 100_000, authAddr: other },
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.prepareRekey(algod, { sender, rekeyTo }),
        /rekey target is itself rekeyed/,
      );
    });

    it("prepares keyreg nonparticipation", async () => {
      const sender = testAddress(1);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270", "test-token");
      const prepared = await client.prepareKeyreg(algod, {
        sender,
        nonParticipation: true,
      });

      assert.equal((prepared.transaction as any).keyreg.nonParticipation, true);
      assert.equal(prepared.checks?.[0].name, "keyreg");
    });

    it("prepares online keyreg", async () => {
      const sender = testAddress(1);
      const key32 = new Uint8Array(32).fill(1);
      const key64 = new Uint8Array(64).fill(2);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270", "test-token");
      const prepared = await client.prepareKeyreg(algod, {
        sender,
        voteKey: key32,
        selectionKey: key32,
        stateProofKey: key64,
        voteFirst: 10,
        voteLast: 20,
        voteKeyDilution: 5,
      });

      assert.equal(String((prepared.transaction as any).keyreg.voteFirst), "10");
      assert.equal(String((prepared.transaction as any).keyreg.voteLast), "20");
    });

    it("prepares raw app calls with app call info", async () => {
      const sender = testAddress(1);
      const receiver = testAddress(2);
      const algod = mockAlgod({
        [sender]: { amount: 2_000_000, minBalance: 100_000 },
      });
      queueStatusResponse(60, 1);
      mockFetch.mockResolvedValueOnce(keysResponse(sender));

      const client = new SignerClient("http://localhost:11270", "test-token");
      const prepared = await client.prepareAppCall(algod, {
        sender,
        appId: 7,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [new Uint8Array([1, 2, 3])],
        accounts: [receiver],
        foreignApps: [8],
        foreignAssets: [1001],
        fee: 1000,
        useFlatFee: true,
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.preparePaymentGroup(algod, [
          { sender, receiver: receiver1, amount: 10_000, fee: 1000, useFlatFee: true },
          { sender, receiver: receiver2, amount: 10_000, fee: 1000, useFlatFee: true },
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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
      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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
      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(client.generateKey("ed25519"), AuthenticationError);
    });

    it("throws on 403 (locked)", async () => {
      mockFetch.mockResolvedValueOnce({ status: 403, ok: false });
      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(client.generateKey("ed25519"), SignerUnavailableError);
    });

    it("treats 403 with locked code as locked", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 403,
        ok: false,
        json: async () => ({ error: "signer is locked", code: "locked" }),
      });
      const client = new SignerClient("http://localhost:11270", "test-token");
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
      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
      const result = await client.deleteKey("ADDR_TO_DELETE");
      assert.equal(result, undefined);
    });

    it("throws KeyDeletionError on 404", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 404,
        ok: false,
        json: async () => ({ error: "Key not found: MISSING" }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(client.deleteKey("MISSING"), KeyDeletionError);
    });

    it("throws on 401", async () => {
      mockFetch.mockResolvedValueOnce({ status: 401, ok: false });
      const client = new SignerClient("http://localhost:11270", "test-token");
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
          signatures: [
            {
              target_index: 0,
              signature: "aabb",
              signature_scheme: KEY_TYPE_WITNESS_FALCON1024,
            },
          ],
        }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      const result = await client.requestComponentSign({
        request_id: "sdk-generated",
        role: COMPONENT_SIGN_ROLE_SENTRY,
        component_key: "COMPONENT",
        group_bytes_hex: ["5458aa"],
        target_indices: [0],
      });

      assert.equal(result.signatures[0].signature, "aabb");
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/sign/component");
      assert.equal(mockFetch.mock.calls[0][1].method, "POST");
      assert.equal(mockFetch.mock.calls[0][1].headers.Authorization, "aplane test-token");
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      assert.match(body.request_id, /^sdk-/);
      assert.equal(body.role, COMPONENT_SIGN_ROLE_SENTRY);
      assert.equal(body.component_key, "COMPONENT");
    });

    it("rejects malformed component signing responses", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ request_id: "sdk-test" }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.requestComponentSign({
          role: COMPONENT_SIGN_ROLE_SENTRY,
          group_bytes_hex: ["5458aa"],
          target_indices: [0],
        }),
        { message: /invalid component sign response/ },
      );
    });

    it("rejects component signatures for unrequested targets", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          request_id: "sdk-component",
          signatures: [{
            target_index: 1,
            signature: "aabb",
            signature_scheme: KEY_TYPE_WITNESS_FALCON1024,
          }],
        }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.requestComponentSign({
          request_id: "sdk-component",
          role: COMPONENT_SIGN_ROLE_SENTRY,
          group_bytes_hex: ["5458aa", "5458bb"],
          target_indices: [0],
        }),
        { message: /indices do not match request/ },
      );
    });

    it("posts guarded assembly requests to /sign/assemble", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          request_id: "sdk-assembly",
          signed_group: ["ccdd"],
        }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      const result = await client.requestGuardedAssemble({
        group_bytes_hex: ["5458aa"],
        targets: [
          {
            target_index: 0,
            guarded_account: "GUARDED",
            user_signature: "aabb",
            sentry_signature: "bbcc",
          },
        ],
      });

      assert.deepEqual(result.signed_group, ["ccdd"]);
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/sign/assemble");
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      assert.match(body.request_id, /^sdk-/);
      assert.equal(body.targets[0].guarded_account, "GUARDED");
    });

    it("rejects guarded assembly requests with missing coverage before fetch", async () => {
      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.requestGuardedAssemble({
          group_bytes_hex: ["5458aa", "5458bb"],
          targets: [
            {
              target_index: 0,
              guarded_account: "GUARDED",
              user_signature: "aabb",
              sentry_signature: "bbcc",
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
            bounded_account: "BOUNDED",
            base_signatures: ["base-sig"],
            assembly_receipt: "receipt",
            signature_scheme: "aplane.falcon1024.v1",
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

      const client = new SignerClient("http://localhost:11270", "test-token");
      const component = await client.requestBoundedComponent({
        request_id: "bounded-base-id",
        requests: [{ auth_address: "BOUNDED", txn_bytes_hex: "5458aa" }],
      });
      const assembly = await client.requestBoundedAssemble({
        request_id: "bounded-assembly-id",
        group_bytes_hex: ["5458aa"],
        targets: [{
          target_index: 0,
          bounded_account: "BOUNDED",
          base_signatures: ["base-sig"],
          assembly_receipt: "receipt",
          sentry_signature: "sentry-sig",
        }],
      });

      assert.equal(component.components[0].assembly_receipt, "receipt");
      assert.equal(component.mutations?.dummiesAdded, 1);
      assert.equal(component.mutations?.originalCount, 1);
      assert.deepEqual(assembly.signed_group, ["signed"]);
      assert.equal(mockFetch.mock.calls[1][0], "http://localhost:11270/sign/bounded-component");
      assert.equal(mockFetch.mock.calls[2][0], "http://localhost:11270/sign/bounded-assemble");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.requestBoundedComponent({
          request_id: "bounded-cancel-id",
          requests: [{ auth_address: "BOUNDED", txn_bytes_hex: "5458aa" }],
        }),
        SignerUnavailableError,
      );

      assert.equal(mockFetch.mock.calls[1][0], "http://localhost:11270/sign/bounded-component");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.requestBoundedComponent({
          request_id: "bounded-not-found",
          requests: [{ auth_address: "BOUNDED", txn_bytes_hex: "5458aa" }],
        }),
        KeyNotFoundError,
      );
    });

    it("rejects bounded component passthrough before fetch", async () => {
      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.requestBoundedComponent({
          request_id: "bounded-base-id",
          requests: [{ signed_txn_hex: "abcd" }],
        }),
        /does not accept signed passthrough/,
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
      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.requestBoundedComponent({
          request_id: "bounded-base-id",
          requests: [{ auth_address: "BOUNDED", txn_bytes_hex: "5458aa" }],
        }),
        (error: unknown) => error instanceof SignerError &&
          error.message === "Server returned invalid JSON",
      );
    });

    it("rejects malformed bounded component targets", async () => {
      queueStatusResponse();
      const component = {
        target_index: 0,
        bounded_account: "BOUNDED",
        base_signatures: ["base"],
        assembly_receipt: "receipt",
        signature_scheme: "aplane.falcon1024.v1",
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
      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.requestBoundedComponent({
          request_id: "bounded-base-id",
          requests: [{ auth_address: "BOUNDED", txn_bytes_hex: "5458aa" }],
        }),
        /invalid or duplicate target_index/,
      );
    });

    it("posts sentry reference sync requests to the admin endpoint", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ added: 1, updated: 0, removed: 0, count: 1 }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      const result = await client.adminSyncSentryReferences([
        {
          endpoint_alias: "sentry-local",
          component_key: "COMPONENT",
          key_type: KEY_TYPE_WITNESS_FALCON1024,
          public_key_hex: "aabb",
        },
      ]);

      assert.equal(result.added, 1);
      assert.equal(result.count, 1);
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/admin/sentries/sync");
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      assert.equal(body.candidates[0].component_key, "COMPONENT");
    });
  });

  describe("signGuardedGroup", () => {
    it("signs one guarded target", async () => {
      const user = new SignerClient("http://localhost:11270", "test-token");
      const sentry = new SignerClient("http://sentry:11270", "sentry-token");

      (user as any).requestComponentSign = async (request: any) => {
        assert.equal(request.role, "user");
        assert.equal(request.component_key, "GUARDED");
        return {
          request_id: "user-id",
          signatures: [
            { target_index: 0, signature: "user-sig", signature_scheme: KEY_TYPE_WITNESS_FALCON1024 },
          ],
        };
      };
      (sentry as any).requestComponentSign = async (request: any) => {
        assert.equal(request.role, COMPONENT_SIGN_ROLE_SENTRY);
        assert.equal(request.component_key, "SENTRY_COMPONENT");
        return {
          request_id: "sentry-id",
          signatures: [
            { target_index: 0, signature: "sentry-sig", signature_scheme: KEY_TYPE_WITNESS_FALCON1024 },
          ],
        };
      };
      (user as any).requestGuardedAssemble = async (request: any) => {
        assert.equal(request.targets[0].user_signature, "user-sig");
        assert.equal(request.targets[0].sentry_signature, "sentry-sig");
        return { request_id: "assembly-id", signed_group: ["signed-guarded"] };
      };

      const result = await signGuardedGroup({
        userClient: user,
        sentryClient: sentry,
        sentryComponentKey: "SENTRY_COMPONENT",
        groupBytesHex: ["5458aa"],
        guardedTargets: [{ targetIndex: 0, guardedAccount: "GUARDED" }],
      });

      assert.deepEqual(result.signedGroup, ["signed-guarded"]);
    });

    it("batches targets for a shared sentry key", async () => {
      const user = new SignerClient("http://localhost:11270", "test-token");
      const sentry = new SignerClient("http://sentry:11270", "sentry-token");
      let sentryCalls = 0;

      (user as any).requestComponentSign = async (request: any) => {
        assert.deepEqual(request.target_indices, [0, 1]);
        return {
          request_id: "user-id",
          signatures: [
            { target_index: 0, signature: "user-0", signature_scheme: KEY_TYPE_WITNESS_FALCON1024 },
            { target_index: 1, signature: "user-1", signature_scheme: KEY_TYPE_WITNESS_FALCON1024 },
          ],
        };
      };
      (sentry as any).requestComponentSign = async (request: any) => {
        sentryCalls += 1;
        assert.deepEqual(request.target_indices, [0, 1]);
        return {
          request_id: "sentry-id",
          signatures: [
            { target_index: 0, signature: "sentry-0", signature_scheme: KEY_TYPE_WITNESS_FALCON1024 },
            { target_index: 1, signature: "sentry-1", signature_scheme: KEY_TYPE_WITNESS_FALCON1024 },
          ],
        };
      };
      (user as any).requestGuardedAssemble = async () => ({
        request_id: "assembly-id",
        signed_group: ["signed-0", "signed-1"],
      });

      await signGuardedGroup({
        userClient: user,
        sentryClient: sentry,
        sentryComponentKey: "SENTRY_COMPONENT",
        groupBytesHex: ["5458aa", "5458bb"],
        guardedTargets: [
          { targetIndex: 0, guardedAccount: "GUARDED" },
          { targetIndex: 1, guardedAccount: "GUARDED" },
        ],
      });

      assert.equal(sentryCalls, 1);
    });

    it("handles mixed primary and guarded groups", async () => {
      const user = new SignerClient("http://localhost:11270", "test-token");
      const sentry = new SignerClient("http://sentry:11270", "sentry-token");

      (user as any).requestComponentSign = async () => ({
        request_id: "user-id",
        signatures: [
          { target_index: 1, signature: "user-sig", signature_scheme: KEY_TYPE_WITNESS_FALCON1024 },
        ],
      });
      (sentry as any).requestComponentSign = async () => ({
        request_id: "sentry-id",
        signatures: [
          { target_index: 1, signature: "sentry-sig", signature_scheme: KEY_TYPE_WITNESS_FALCON1024 },
        ],
      });
      (user as any).signRequests = async (requests: any[]) => {
        assert.equal(requests[0].auth_address, "AUTH");
        assert.equal(requests[1].auth_address, undefined);
        return { signed: ["primary-signed", ""] };
      };
      (user as any).requestGuardedAssemble = async (request: any) => {
        assert.equal(request.passthrough[0].target_index, 0);
        assert.equal(request.passthrough[0].signed_txn_hex, "primary-signed");
        return { request_id: "assembly-id", signed_group: ["primary-signed", "guarded-signed"] };
      };

      const result = await signGuardedGroup({
        userClient: user,
        sentryClient: sentry,
        sentryComponentKey: "SENTRY_COMPONENT",
        groupBytesHex: ["5458aa", "5458bb"],
        primaryTargets: [{ targetIndex: 0, authAddress: "AUTH" }],
        guardedTargets: [{ targetIndex: 1, guardedAccount: "GUARDED" }],
      });

      assert.equal(result.signedGroup[1], "guarded-signed");
      assert.ok(result.primarySignResponse);
    });

    it("handles prepared all-guarded groups without plan or sign", async () => {
      const guarded = testAddress(1);
      const receiver = testAddress(2);
      const user = new SignerClient("http://localhost:11270", "test-token");
      const sentry = new SignerClient("http://sentry:11270", "sentry-token");

      (user as any).requestComponentSign = async (request: any) => {
        assert.equal(request.component_key, guarded);
        assert.equal(request.group_bytes_hex.length, 4);
        assert.deepEqual(request.target_indices, [0]);
        return {
          request_id: "user-id",
          signatures: [
            { target_index: 0, signature: "user-sig", signature_scheme: KEY_TYPE_WITNESS_FALCON1024 },
          ],
        };
      };
      (sentry as any).requestComponentSign = async (request: any) => {
        assert.equal(request.component_key, "SENTRY_COMPONENT");
        assert.equal(request.group_bytes_hex.length, 4);
        assert.deepEqual(request.target_indices, [0]);
        return {
          request_id: "sentry-id",
          signatures: [
            { target_index: 0, signature: "sentry-sig", signature_scheme: KEY_TYPE_WITNESS_FALCON1024 },
          ],
        };
      };
      (user as any).signRequests = async () => {
        throw new Error("all-guarded path must not call /sign");
      };
      (user as any).planGroup = async () => {
        throw new Error("all-guarded path must not call /plan");
      };
      (user as any).requestGuardedAssemble = async (request: any) => {
        assert.equal(request.group_bytes_hex.length, 4);
        assert.equal(request.passthrough.length, 3);
        assert.deepEqual(request.passthrough.map((item: any) => item.target_index), [1, 2, 3]);
        assert.ok(request.passthrough.every((item: any) => item.signed_txn_hex));
        return {
          request_id: "assembly-id",
          signed_group: ["guarded-signed", "dummy-1", "dummy-2", "dummy-3"],
        };
      };

      const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: guarded,
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

      const result = await signPreparedGuardedGroup({
        userClient: user,
        sentryClient: sentry,
        sentryComponentKey: "SENTRY_COMPONENT",
        preparedGroup: {
          transactions: [
            {
              transaction: txn,
              authAddress: guarded,
              signerKey: {
                address: guarded,
                publicKeyHex: "",
                keyType: KEY_TYPE_GUARDED_FALCON1024_SENTRY1024,
                signingFlow: SIGNING_FLOW_SENTRY1,
                sentryComponentKeyType: KEY_TYPE_WITNESS_FALCON1024,
                lsigSize: 3035,
                isGenericLsig: false,
                parameters: { sentry_public_key: "aabbcc" },
              },
            },
          ],
        },
      });

      assert.equal(result.signedGroup.length, 4);
      assert.equal(result.primarySignResponse, undefined);
    });

    it("routes prepared bounded-sentry groups through the user-first flow", async () => {
      const bounded = testAddress(11);
      const receiver = testAddress(12);
      const user = new SignerClient("http://localhost:11270", "test-token");
      const sentry = new SignerClient("http://sentry:11270", "sentry-token");
      let plannedTransactions: string[] | undefined;
      let plannedMutations: any;

      (user as any).requestBoundedComponent = async (request: any) => {
        assert.equal(request.requests[0].auth_address, bounded);
        return {
          request_id: "base-id",
          transactions: plannedTransactions ?? [request.requests[0].txn_bytes_hex],
          components: [{
            target_index: 0,
            bounded_account: bounded,
            base_signatures: ["base-sig"],
            runtime_args: { proof: "aabb" },
            assembly_receipt: "receipt",
            signature_scheme: "aplane.falcon1024.v1",
          }],
          mutations: plannedMutations,
        };
      };
      (sentry as any).requestComponentSign = async (request: any) => {
        assert.equal(request.component_key, "SENTRY_COMPONENT");
        assert.deepEqual(request.target_indices, [0]);
        assert.equal(request.group_bytes_hex.length, 1);
        return {
          request_id: "sentry-id",
          signatures: [{
            target_index: 0,
            signature: "sentry-sig",
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
      (user as any).requestBoundedAssemble = async (request: any) => {
        assert.deepEqual(request.targets[0].base_signatures, ["base-sig"]);
        assert.equal(request.targets[0].assembly_receipt, "receipt");
        assert.equal(request.targets[0].sentry_signature, "sentry-sig");
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
        sentryClient: sentry,
        sentryComponentKey: "SENTRY_COMPONENT",
        preparedGroup: {
          transactions: [{
            transaction: txn,
            authAddress: bounded,
            signerKey: {
              address: bounded,
              publicKeyHex: "",
              keyType: "aplane.corridor.v1",
              signingFlow: SIGNING_FLOW_BOUNDED_SENTRY1,
              sentryComponentKeyType: KEY_TYPE_WITNESS_FALCON1024,
              lsigSize: 9012,
              isGenericLsig: false,
              boundedAuthorization: {
                contract: "bounded1",
                baseSignatureArgLayout: { count: 1, maxSizes: [1280] },
                spendEffects: ["pay"],
                maxFee: 1000,
                adminOperations: [],
                sentry: {
                  contract: "sentry1",
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
        signPreparedGuardedGroup(options),
        /group ID does not match decoded transactions/,
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
        signPreparedGuardedGroup(options),
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
      await assert.rejects(
        signPreparedGuardedGroup(options),
        /exceeds advertised max_fee/,
      );

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
        signPreparedGuardedGroup(options),
        /canonical guarded budget dummy/,
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
        signPreparedGuardedGroup(options),
        /does not match the submitted canonical bytes/,
      );

      assembledTxn = txn;
      const result = await signPreparedGuardedGroup(options);

      assert.deepEqual(result.signedGroup, [signedTxnHex(txn)]);
      assert.deepEqual(result.assemblyResponse, result.boundedAssemblyResponse);
      assert.ok(result.boundedComponentResponse);
      assert.ok(result.boundedAssemblyResponse);
    });

    it("rejects mixed sentry1 and bounded-sentry1 prepared groups", async () => {
      const user = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        signPreparedGuardedGroup({
          userClient: user,
          preparedGroup: {
            transactions: [
              {
                signerKey: {
                  address: "bounded",
                  publicKeyHex: "",
                  keyType: "bounded",
                  signingFlow: SIGNING_FLOW_BOUNDED_SENTRY1,
                  lsigSize: 0,
                  isGenericLsig: false,
                },
              },
              {
                signerKey: {
                  address: "guarded",
                  publicKeyHex: "",
                  keyType: "guarded",
                  signingFlow: SIGNING_FLOW_SENTRY1,
                  lsigSize: 0,
                  isGenericLsig: false,
                },
              },
            ],
          },
        }),
        /cannot mix sentry1 and bounded-sentry1/,
      );
    });

    it("verifies bounded primary passthrough transaction identity", async () => {
      const bounded = testAddress(21);
      const primary = testAddress(22);
      const receiver = testAddress(23);
      const user = new SignerClient("http://localhost:11270", "test-token");
      const sentry = new SignerClient("http://sentry:11270", "sentry-token");
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

      (user as any).requestBoundedComponent = async (request: any) => {
        const planned = request.requests.map((entry: any) =>
          algosdk.decodeUnsignedTransaction(hexToBytes(entry.txn_bytes_hex).slice(2))
        );
        algosdk.assignGroupID(planned);
        plannedGroup = planned;
        return {
          request_id: "base-id",
          transactions: planned.map((item: algosdk.Transaction) => encodeTransaction(item)[0]),
          components: [{
            target_index: 0,
            bounded_account: bounded,
            base_signatures: ["base-sig"],
            assembly_receipt: "receipt",
            signature_scheme: "aplane.falcon1024.v1",
          }],
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
      (sentry as any).requestComponentSign = async () => ({
        request_id: "sentry-id",
        signatures: [{
          target_index: 0,
          signature: "sentry-sig",
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
      (user as any).requestBoundedAssemble = async () => ({
        request_id: "assembly-id",
        signed_group: plannedGroup.map(signedTxnHex),
      });

      const options = {
        userClient: user,
        sentryClient: sentry,
        sentryComponentKey: "SENTRY_COMPONENT",
        preparedGroup: {
          transactions: [
            {
              transaction: boundedTxn,
              authAddress: bounded,
              signerKey: {
                address: bounded,
                publicKeyHex: "",
                keyType: "aplane.corridor.v1",
                signingFlow: SIGNING_FLOW_BOUNDED_SENTRY1,
                sentryComponentKeyType: KEY_TYPE_WITNESS_FALCON1024,
                lsigSize: 9012,
                isGenericLsig: false,
                boundedAuthorization: {
                  contract: "bounded1",
                  baseSignatureArgLayout: { count: 1, maxSizes: [1280] },
                  spendEffects: ["pay"],
                  maxFee: 1000,
                  adminOperations: [],
                  sentry: {
                    contract: "sentry1",
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
                lsigSize: 0,
                isGenericLsig: false,
              },
            },
          ],
        },
      };
      await assert.rejects(
        signPreparedGuardedGroup(options),
        /primary passthrough 1 does not match/,
      );
      useWrongPrimary = false;
      const result = await signPreparedGuardedGroup(options);
      assert.equal(result.signedGroup.length, 2);
    });

    it("rejects prepared groups whose keys require an unsupported signing flow", async () => {
      const guarded = testAddress(1);
      const receiver = testAddress(2);
      const user = new SignerClient("http://localhost:11270", "test-token");

      const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: guarded,
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
        signPreparedGuardedGroup({
          userClient: user,
          preparedGroup: {
            transactions: [
              {
                transaction: txn,
                authAddress: guarded,
                signerKey: {
                  address: guarded,
                  publicKeyHex: "",
                  keyType: "aplane.future-guarded.v1",
                  signingFlow: "sentry2",
                  lsigSize: 3035,
                  isGenericLsig: false,
                },
              },
            ],
          },
        }),
        /signing flow "sentry2"/,
      );
    });
  });

  describe("planGroup", () => {
    const createMockTxn = () => ({
      sender: { toString: () => "SENDER_ADDRESS" },
      toByte: () => new Uint8Array([1, 2, 3, 4]),
    });

    it("returns plan with transactions and mutations", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          transactions: ["5458deadbeef", "5458cafebabe"],
          mutations: {
            dummies_added: 1,
            group_id_changed: true,
            original_count: 1,
            final_count: 2,
          },
        }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      const mockTxn = createMockTxn() as Parameters<typeof client.planGroup>[0][0];
      const result = await client.planGroup([mockTxn]);

      assert.equal(result.transactions.length, 2);
      assert.notEqual(result.mutations, undefined);
    });

    it("throws AuthenticationError on 401", async () => {
      mockFetch.mockResolvedValueOnce({ status: 401, ok: false });
      const client = new SignerClient("http://localhost:11270", "test-token");
      const mockTxn = createMockTxn() as Parameters<typeof client.planGroup>[0][0];
      await assert.rejects(client.planGroup([mockTxn]), AuthenticationError);
    });

    it("throws on server error in response", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ error: "Internal error" }),
      });
      const client = new SignerClient("http://localhost:11270", "test-token");
      const mockTxn = createMockTxn() as Parameters<typeof client.planGroup>[0][0];
      await assert.rejects(client.planGroup([mockTxn]), SignerError);
    });
  });

  describe("signTransactions with passthrough", () => {
    const createMockTxn = () => ({
      sender: { toString: () => "SENDER_ADDRESS" },
      toByte: () => new Uint8Array([1, 2, 3, 4]),
    });

    it("rejects foreign entries before calling /sign", async () => {
      const client = new SignerClient("http://localhost:11270", "test-token");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransactions>[0][0];

      await assert.rejects(
        client.signTransactions([mockTxn, mockTxn], ["AUTH1", null]),
        { message: /foreign entries are only supported on \/plan/ },
      );
      assert.equal(mockFetch.mock.calls.length, 0);
    });

    it("signTransactionsList rejects foreign entries before calling /sign", async () => {
      const client = new SignerClient("http://localhost:11270", "test-token");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransactionsList>[0][0];
      await assert.rejects(
        client.signTransactionsList([mockTxn, mockTxn], ["AUTH1", null]),
        { message: /foreign entries are only supported on \/plan/ },
      );
      assert.equal(mockFetch.mock.calls.length, 0);
    });
  });

  describe("signing errors", () => {
    const createMockTxn = () => ({
      sender: {
        toString: () => "SENDER_ADDRESS",
      },
      toByte: () => new Uint8Array([1, 2, 3, 4]),
    });

    it("rejects truncated /sign responses", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ signed: ["aa"] }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.signRequests([
          { auth_address: "AUTH1", txn_bytes_hex: "5458aa" },
          { auth_address: "AUTH2", txn_bytes_hex: "5458bb" },
        ]),
        /want at least 2/
      );
    });

    it("rejects empty signed slot for sign-mode request", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ signed: ["aa", ""] }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.signRequests([
          { auth_address: "AUTH1", txn_bytes_hex: "5458aa" },
          { auth_address: "AUTH2", txn_bytes_hex: "5458bb" },
        ]),
        /no signature for position 2/
      );
    });

    it("tolerates empty foreign slot and trailing dummies", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ signed: ["aa", "", "dd"] }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      const data = await client.signRequests([
        { auth_address: "AUTH1", txn_bytes_hex: "5458aa" },
        { txn_bytes_hex: "5458bb" },
      ]);
      assert.deepEqual(data.signed, ["aa", "", "dd"]);
    });

    it("throws AuthenticationError on 401", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 401,
        ok: false,
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
      const lockedTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];
      await assert.rejects(
        client.signTransaction(lockedTxn, "A".repeat(58)),
        SignerUnavailableError
      );
    });

    it("throws SigningRejectedError on 403", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 403,
        ok: false,
        json: async () => ({ error: "Operator rejected", code: "forbidden" }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await assert.rejects(client.signTransaction(mockTxn), SignerUnavailableError);
    });

    it("throws KeyNotFoundError on 400 with 'not found'", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 400,
        ok: false,
        json: async () => ({ error: "Key not found: INVALID_ADDRESS" }),
        text: async () => "Key not found: INVALID_ADDRESS",
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await assert.rejects(client.signTransaction(mockTxn), KeyNotFoundError);
    });

    it("throws KeyNotFoundError on 400 with not_found code regardless of wording", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 400,
        ok: false,
        json: async () => ({ error: "auth address unavailable", code: "not_found" }),
        text: async () => "auth address unavailable",
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

      const client = new SignerClient("http://localhost:11270", "test-token", 100);
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

      const client = new SignerClient("http://localhost:11270", "test-token", 100);
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
              identity_id: "default",
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
        const client = new SignerClient("http://localhost:11270", "test-token");
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
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ signed: ["deadbeef"] }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      const signed = await client.signTransaction(mockTxn);

      assert.equal(Buffer.from(signed, "base64").toString("hex"), "deadbeef");
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/status");
      assert.equal(mockFetch.mock.calls[1][0], "http://localhost:11270/sign");
    });

    it("uses discovered approval wait plus slack for signing timeout", async () => {
      queueStatusResponse(120);

      const client = new SignerClient("http://localhost:11270", "test-token");
      await client.getStatus();

      assert.equal((client as any).signRequestTimeout(), 150000);
    });

    it("falls back for invalid discovered approval wait", async () => {
      queueStatusResponse(31 * 60);

      const client = new SignerClient("http://localhost:11270", "test-token");
      await client.getStatus();

      assert.equal((client as any).signRequestTimeout(), 360000);
    });
  });

  describe("signRequests", () => {
    it("sends raw signing requests and returns raw response", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ signed: ["deadbeef"] }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      const result = await client.signRequests(
        [
          {
            txn_bytes_hex: "545801",
            auth_address: "AUTH",
            txn_sender: "SENDER",
          },
        ],
        { requestId: "raw-requests-id" },
      );

      assert.deepEqual(result, { signed: ["deadbeef"] });
      assert.equal(mockFetch.mock.calls[1][0], "http://localhost:11270/sign");
      assert.deepEqual(JSON.parse(mockFetch.mock.calls[1][1].body), {
        request_id: "raw-requests-id",
        requests: [
          {
            txn_bytes_hex: "545801",
            auth_address: "AUTH",
            txn_sender: "SENDER",
          },
        ],
      });
    });

    it("validates raw group request IDs", async () => {
      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.signRequests([{ txn_bytes_hex: "545801" }], { requestId: "bad id" }),
        { message: /invalid character/ },
      );
    });
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

      const client = new SignerClient("http://localhost:11270", "test-token");
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

    it("requires algod before contacting the signer", async () => {
      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.simulatePreparedGroup(null as any, { transactions: [] }),
        /algodClient is required/,
      );
      assert.equal(mockFetch.mock.calls.length, 0);
    });

    it("requires algod before starting guarded signing", async () => {
      await assert.rejects(
        simulateGuardedGroup(null as any, {} as any),
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

      const client = new SignerClient("http://localhost:11270", "test-token");
      const result = await client.cancelSignRequest("sdk-test");

      assert.equal(result.success, true);
      assert.equal(result.state, "not_found");
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/sign/cancel");
      assert.deepEqual(JSON.parse(mockFetch.mock.calls[0][1].body), { request_id: "sdk-test" });
    });

    it("validates request id", async () => {
      const client = new SignerClient("http://localhost:11270", "test-token");
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
      assert.equal(registry.endpoints.primary.signerPort, 11271);
      assert.equal(registry.endpoints.primary.localPort, 18080);
      assert.equal(
        registry.endpoints.primary.identityFile,
        path.join(tmpDir, ".ssh", "primary"),
      );
      assert.equal(
        registry.endpoints.primary.tokenFile,
        path.join(tmpDir, "aplane.token"),
      );
      assert.equal(
        registry.endpoints["sentry.qa"].tokenFile,
        path.join(tmpDir, "credentials", "sentry.token"),
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  for (const fixture of [
    "invalid_multiple_signers.yaml",
    "invalid_remote_http.yaml",
    "invalid_ssh_port_zero.yaml",
    "invalid_unknown_field.yaml",
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

  it("derives the signer default and alias-based token paths", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-endpoints-"));
    try {
      fs.writeFileSync(
        path.join(tmpDir, "endpoints.yaml"),
        "schema_version: 1\nendpoints:\n" +
        "  main:\n    role: signer\n    url: ssh://localhost\n" +
        "  qa:\n    role: sentry\n    url: http://127.0.0.1:11271\n",
      );
      const registry = loadClientEndpointRegistry(tmpDir);
      assert.equal(registry.default, "main");
      assert.equal(
        registry.endpoints.main.tokenFile,
        path.join(tmpDir, "tokens", "main.token"),
      );
      assert.equal(resolveClientEndpoint(registry).alias, "main");
      assert.equal(resolveClientEndpoint(registry, "qa").endpoint.role, "sentry");
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });
});

describe("requestToken", () => {
  it("rejects unsupported identity locally", async () => {
    await assert.rejects(
      requestToken("signer.example.com", "~/.ssh/id_ed25519", { identity: "other-identity" }),
      { message: /unsupported identity/ },
    );
  });

  it("rejects missing known_hosts path locally", async () => {
    await assert.rejects(
      requestToken("signer.example.com", "~/.ssh/id_ed25519"),
      { message: /known_hosts path is required/ },
    );
  });
});

describe("requestTokenToFile", () => {
  it("rejects removed host routing options at runtime", async () => {
    await assert.rejects(
      requestTokenToFile({
        host: "signer.example.com",
      } as unknown as Parameters<typeof requestTokenToFile>[0]),
      { message: /option "host" was removed/ },
    );
  });

  it("selects a named SSH endpoint", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-token-"));
    try {
      fs.writeFileSync(
        path.join(tmpDir, "endpoints.yaml"),
        "schema_version: 1\nendpoints:\n" +
        "  primary:\n    role: signer\n    url: ssh://signer.example.com\n" +
        "  qa:\n    role: sentry\n    url: ssh://sentry.example.com:2222\n" +
        "    identity_file: .ssh/qa\n",
      );
      await assert.rejects(
        requestTokenToFile({ dataDir: tmpDir, endpoint: "qa" }),
        { message: /SSH key not found at .*qa/ },
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("rejects non-SSH enrollment endpoints", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-token-"));
    try {
      fs.writeFileSync(
        path.join(tmpDir, "endpoints.yaml"),
        "schema_version: 1\nendpoints:\n" +
        "  primary:\n    role: signer\n    url: https://signer.example.com\n",
      );
      await assert.rejects(
        requestTokenToFile({ dataDir: tmpDir }),
        { message: /requires ssh:\/\// },
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

  const createMockTxn = (sender = "SENDER_ADDRESS") => ({
    sender: { toString: () => sender },
    toByte: () => new Uint8Array([1, 2, 3, 4]),
  });

  it("builds request with auth address", async () => {
    queueStatusResponse();
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => ({ signed: ["deadbeef"] }),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
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
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => ({ signed: ["deadbeef"] }),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const mockTxn = createMockTxn("MY_SENDER") as Parameters<typeof client.signTransaction>[0];
    await client.signTransaction(mockTxn);

    const capturedBody = JSON.parse(mockFetch.mock.calls[1][1].body);
    assert.equal(capturedBody.requests[0].auth_address, "MY_SENDER");
  });

  it("includes lsig args as hex", async () => {
    queueStatusResponse();
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => ({ signed: ["deadbeef"] }),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const mockTxn = createMockTxn("LSIG_ADDR") as Parameters<typeof client.signTransaction>[0];
    await client.signTransaction(mockTxn, "LSIG_ADDR", {
      preimage: new Uint8Array([0x73, 0x65, 0x63, 0x72, 0x65, 0x74]),
    });

    const capturedBody = JSON.parse(mockFetch.mock.calls[1][1].body);
    assert.notEqual(capturedBody.requests[0].lsig_args, undefined);
    assert.equal(capturedBody.requests[0].lsig_args.preimage, "736563726574");
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
        lsigSize: 3035,
      }],
    });

    assert.equal(requests.length, 1);
    assert.equal(requests[0].txn_bytes_hex, "5458010203");
    assert.equal(requests[0].auth_address, undefined);
    assert.equal(requests[0].lsig_size, 3035);
  });

  it("builds passthrough requests", () => {
    const requests = preparedGroupToSignRequests({
      transactions: [{
        signedTransactionBase64: Buffer.from("signed-txn").toString("base64"),
      }],
    });

    assert.deepEqual(requests, [{
      signed_txn_hex: Buffer.from("signed-txn").toString("hex"),
    }]);
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

  it("uses a named direct endpoint and its token", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-test-"));
    try {
      fs.mkdirSync(path.join(tmpDir, "tokens"));
      fs.writeFileSync(
        path.join(tmpDir, "endpoints.yaml"),
        "schema_version: 1\nendpoints:\n" +
        "  primary:\n    role: signer\n    url: https://signer.example.com/\n" +
        "  qa:\n    role: sentry\n    url: http://127.0.0.1:11271/\n",
      );
      fs.writeFileSync(path.join(tmpDir, "tokens", "qa.token"), "qa-token");
      const client = await SignerClient.fromEnv({
        dataDir: tmpDir,
        endpoint: "qa",
        timeout: 7000,
      });
      assert.equal(
        (client as unknown as { baseUrl: string }).baseUrl,
        "http://127.0.0.1:11271",
      );
      assert.equal(
        (client as unknown as { token: string }).token,
        "qa-token",
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("rejects self endpoints", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-test-"));
    try {
      fs.writeFileSync(
        path.join(tmpDir, "endpoints.yaml"),
        "schema_version: 1\nendpoints:\n" +
        "  primary:\n    role: signer\n    url: self\n",
      );

      await assert.rejects(
        SignerClient.fromEnv({ dataDir: tmpDir }),
        { message: /not supported by the external SDK/ },
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });
});

describe("connectSsh", () => {
  it("rejects missing knownHostsPath at method entry", async () => {
    await assert.rejects(
      SignerClient.connectSsh("example.com", "token", "~/.ssh/id_ed25519"),
      { message: /known_hosts path is required/ },
    );
  });
});

describe("sign return format", () => {
  const createMockTxn = () => ({
    sender: { toString: () => "SENDER_ADDRESS" },
    toByte: () => new Uint8Array([1, 2, 3, 4]),
  });

  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("signTransactionsList returns individual base64 strings", async () => {
    const hex1 = Buffer.from("signed-txn-1").toString("hex");
    const hex2 = Buffer.from("signed-txn-2").toString("hex");

    queueStatusResponse();
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => ({ signed: [hex1, hex2] }),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const mockTxn = createMockTxn() as Parameters<typeof client.signTransactionsList>[0][0];
    const result = await client.signTransactionsList([mockTxn, mockTxn]);

    assert.equal(result.length, 2);
    assert.equal(Buffer.from(result[0], "base64").toString(), "signed-txn-1");
    assert.equal(Buffer.from(result[1], "base64").toString(), "signed-txn-2");
  });

  it("signTransactions returns concatenated base64", async () => {
    const hex1 = Buffer.from("signed-txn-1").toString("hex");
    const hex2 = Buffer.from("signed-txn-2").toString("hex");

    queueStatusResponse();
    mockFetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => ({ signed: [hex1, hex2] }),
    });

    const client = new SignerClient("http://localhost:11270", "test-token");
    const mockTxn = createMockTxn() as Parameters<typeof client.signTransactions>[0][0];
    const result = await client.signTransactions([mockTxn, mockTxn]);

    const decoded = Buffer.from(result, "base64").toString();
    assert.equal(decoded, "signed-txn-1signed-txn-2");
  });

  it("signTransactions rejects empty transaction arrays locally", async () => {
    mockFetch.mockReset();
    const client = new SignerClient("http://localhost:11270", "test-token");
    await assert.rejects(client.signTransactions([]), SignerError);
    assert.equal(mockFetch.mock.calls.length, 0);
  });

  it("signTransactionsList rejects empty transaction arrays locally", async () => {
    mockFetch.mockReset();
    const client = new SignerClient("http://localhost:11270", "test-token");
    await assert.rejects(client.signTransactionsList([]), SignerError);
    assert.equal(mockFetch.mock.calls.length, 0);
  });

  it("planGroup uses SignerError for auth address length mismatch", async () => {
    const client = new SignerClient("http://localhost:11270", "test-token");
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
