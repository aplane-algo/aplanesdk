// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { SignerClient } from "../src/client.js";
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

function queueStatusResponse(approvalWaitSeconds: number = 60): void {
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
      approval_wait_seconds: approvalWaitSeconds,
    }),
  });
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

    it("throws SigningRejectedError on 403", async () => {
      queueStatusResponse();
      mockFetch.mockResolvedValueOnce({
        status: 403,
        ok: false,
        json: async () => ({ error: "Operator rejected" }),
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
        "signer_port: 12345\n" +
        "ssh:\n" +
        "  host: signer.example.com\n" +
        "  port: 2222\n" +
        "  identity_file: .ssh/mykey\n" +
        "  known_hosts_path: .ssh/hosts\n" +
        "  trust_on_first_use: true\n"
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
        "ssh:\n  host: example.com\n"
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

describe("fromEnv", () => {
  it("throws when SSH not configured", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-test-"));
    try {
      fs.writeFileSync(path.join(tmpDir, "config.yaml"), "signer_port: 11270\n");
      fs.writeFileSync(path.join(tmpDir, "aplane.token"), "test-token");

      await assert.rejects(
        SignerClient.fromEnv({ dataDir: tmpDir }),
        { message: /No ssh block/ },
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
        "signer_port: 11270\nssh:\n  port: 1127\n"
      );
      fs.writeFileSync(path.join(tmpDir, "aplane.token"), "test-token");

      await assert.rejects(
        SignerClient.fromEnv({ dataDir: tmpDir }),
        { message: /No ssh block/ },
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
        "ssh:\n  host: example.com\n  port: 1127\n"
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
