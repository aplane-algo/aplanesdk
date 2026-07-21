// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import algosdk from "algosdk";
import { SignerClient, signGuardedGroup, signPreparedGuardedGroup } from "../src/client.js";
import {
  COMPONENT_SIGN_ROLE_SENTRY,
  KEY_TYPE_GUARDED_FALCON1024_SENTRY1024,
  KEY_TYPE_WITNESS_FALCON1024,
  SIGNING_FLOW_SENTRY1,
} from "../src/types.js";
import {
  AuthenticationError,
  SigningRejectedError,
  SignerUnavailableError,
  SignerError,
  KeyNotFoundError,
  KeyDeletionError,
} from "../src/errors.js";
import { requestToken } from "../src/utils.js";
import { bytesToHex, hexToBytes, concatenateSignedTxns, encodeTransaction, encodeLsigArgs } from "../src/encoding.js";
import { assembleGroup } from "../src/utils.js";
import { loadConfig, loadTokenFromDir } from "../src/config.js";
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

  describe("simulateRequests", () => {
    it("sends raw simulate requests and returns diagnostics", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          tx_ids: ["SIMTXID1"],
          transactions: ["545801"],
          mutations: { dummies_added: 1 },
          output: "Simulation failed\nlogic eval error",
          failed: true,
        }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      const result = await client.simulateRequests(
        [
          {
            txn_bytes_hex: "545801",
            auth_address: "AUTH",
            txn_sender: "SENDER",
          },
        ],
        { requestId: "simulate-id" },
      );

      assert.deepEqual(result.tx_ids, ["SIMTXID1"]);
      assert.deepEqual(result.transactions, ["545801"]);
      assert.equal(result.mutations?.dummiesAdded, 1);
      assert.equal(result.failed, true);
      assert.match(result.output ?? "", /logic eval error/);
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/simulate");
      assert.deepEqual(JSON.parse(mockFetch.mock.calls[0][1].body), {
        request_id: "simulate-id",
        requests: [
          {
            txn_bytes_hex: "545801",
            auth_address: "AUTH",
            txn_sender: "SENDER",
          },
        ],
      });
    });

    it("simulates prepared groups", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ tx_ids: ["SIMTXID1"] }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      const mockTxn = {
        sender: { toString: () => "SENDER" },
        toByte: () => new Uint8Array([1, 2, 3, 4]),
      };
      const result = await client.simulatePreparedGroup({
        transactions: [
          {
            transaction: mockTxn as any,
            authAddress: "AUTH",
            txnSender: "SENDER",
          },
        ],
      });

      assert.deepEqual(result.tx_ids, ["SIMTXID1"]);
      assert.equal(mockFetch.mock.calls[0][0], "http://localhost:11270/simulate");
      assert.equal(JSON.parse(mockFetch.mock.calls[0][1].body).requests[0].auth_address, "AUTH");
    });

    it("throws on server error in response", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({ error: "simulation unavailable" }),
      });

      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.simulateRequests([{ txn_bytes_hex: "545801", auth_address: "AUTH" }]),
        /simulation unavailable/,
      );
    });

    it("validates raw simulate request IDs", async () => {
      const client = new SignerClient("http://localhost:11270", "test-token");
      await assert.rejects(
        client.simulateRequests([{ txn_bytes_hex: "545801" }], { requestId: "bad id" }),
        { message: /invalid character/ },
      );
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
      assert.equal(config.signerPort, 11270);
      assert.equal(config.ssh, undefined);
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("parses SSH config", () => {
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
      const config = loadConfig(tmpDir);
      assert.equal(config.signerPort, 12345);
      assert.notEqual(config.ssh, undefined);
      assert.equal(config.ssh!.host, "signer.example.com");
      assert.equal(config.ssh!.port, 2222);
      assert.equal(config.ssh!.identityFile, ".ssh/mykey");
      assert.equal(config.ssh!.knownHostsPath, ".ssh/hosts");
      assert.equal(config.ssh!.trustOnFirstUse, true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("defaults trust_on_first_use to false", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-test-"));
    try {
      fs.writeFileSync(
        path.join(tmpDir, "config.yaml"),
        "endpoint:\n  ssh:\n    host: example.com\n"
      );
      const config = loadConfig(tmpDir);
      assert.equal(config.ssh!.trustOnFirstUse, false);
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
  it("throws when SSH not configured", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-test-"));
    try {
      fs.writeFileSync(path.join(tmpDir, "config.yaml"), "endpoint:\n  signer_port: 11270\n");
      fs.writeFileSync(path.join(tmpDir, "aplane.token"), "test-token");

      await assert.rejects(
        SignerClient.fromEnv({ dataDir: tmpDir }),
        { message: /No endpoint.ssh block/ },
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("throws when SSH host is empty", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-test-"));
    try {
      fs.writeFileSync(
        path.join(tmpDir, "config.yaml"),
        "endpoint:\n  signer_port: 11270\n  ssh:\n    port: 1127\n"
      );
      fs.writeFileSync(path.join(tmpDir, "aplane.token"), "test-token");

      await assert.rejects(
        SignerClient.fromEnv({ dataDir: tmpDir }),
        { message: /No endpoint.ssh block/ },
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("throws when token is missing", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-test-"));
    try {
      fs.writeFileSync(
        path.join(tmpDir, "config.yaml"),
        "endpoint:\n  ssh:\n    host: example.com\n    port: 1127\n"
      );
      // No token file

      await assert.rejects(
        SignerClient.fromEnv({ dataDir: tmpDir }),
        { message: /No token/ },
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
