// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ApsignerAlgoKitAccount,
  createApsignerAccount,
  listApsignerAccounts,
} from "../src/algokit.js";
import type { GroupSignResponse, KeyInfo, SignOptions, SignRequest } from "../src/types.js";

const zeroAddress = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ";

class MockSignerClient {
  signCalls: Array<{ requests: SignRequest[]; options?: SignOptions }> = [];

  async signRequests(
    requests: SignRequest[],
    options?: SignOptions,
  ): Promise<GroupSignResponse> {
    this.signCalls.push({ requests, options });
    return { signed: ["aabb", "ccdd"] };
  }

  async listKeys(_refresh = false): Promise<KeyInfo[]> {
    return [
      {
        address: zeroAddress,
        keyType: "ed25519",
        publicKeyHex: "",
        lsigSize: 0,
        isGenericLsig: false,
      },
    ];
  }
}

describe("AlgoKit adapter", () => {
  it("exposes an address-like account and signs requested indexes", async () => {
    const client = new MockSignerClient();
    const signal = new AbortController().signal;
    const account = new ApsignerAlgoKitAccount({
      client,
      address: zeroAddress,
      authAddress: "AUTHADDR",
      newRequestId: () => "sdk-algokit-test",
      signal,
      lsigArgs: { preimage: new Uint8Array([1, 2]) },
      encodeTransaction: async (txn) => new Uint8Array([84, 88, Number(txn.sender?.toString())]),
    });

    assert.equal(account.addr.toString(), zeroAddress);
    assert.equal(account.authAddress, "AUTHADDR");

    const signed = await account.signer(
      [
        { sender: { toString: () => "1" } },
        { sender: { toString: () => "2" } },
        { sender: { toString: () => "3" } },
      ],
      [0, 2],
    );

    assert.deepEqual(signed, [new Uint8Array([0xaa, 0xbb]), new Uint8Array([0xcc, 0xdd])]);
    assert.equal(client.signCalls.length, 1);
    assert.deepEqual(client.signCalls[0].requests, [
      {
        txn_bytes_hex: "545801",
        txn_sender: "1",
        auth_address: "AUTHADDR",
        lsig_args: { preimage: "0102" },
      },
      {
        txn_bytes_hex: "545803",
        txn_sender: "3",
        auth_address: "AUTHADDR",
        lsig_args: { preimage: "0102" },
      },
    ]);
    assert.equal(client.signCalls[0].options?.requestId, "sdk-algokit-test");
    assert.equal(client.signCalls[0].options?.signal, signal);
  });

  it("lists signer keys as AlgoKit accounts", async () => {
    const client = new MockSignerClient();
    const accounts = await listApsignerAccounts(client, { refresh: true });

    assert.equal(accounts.length, 1);
    assert.equal(accounts[0].addr.toString(), zeroAddress);
    assert.equal(accounts[0].authAddress, zeroAddress);
  });

  it("createApsignerAccount returns the adapter shape", () => {
    const client = new MockSignerClient();
    const account = createApsignerAccount({
      client,
      address: zeroAddress,
      encodeTransaction: () => new Uint8Array([84, 88]),
    });

    assert.equal(account.addr.toString(), zeroAddress);
    assert.equal(typeof account.signer, "function");
  });

  it("allows signer responses with additional APlane-managed transactions", async () => {
    const client = new MockSignerClient();
    client.signRequests = async (requests, options) => {
      client.signCalls.push({ requests, options });
      return { signed: ["aabb", "ccdd"] };
    };
    const account = createApsignerAccount({
      client,
      address: zeroAddress,
      encodeTransaction: () => new Uint8Array([84, 88]),
    });

    const signed = await account.signer([{ sender: { toString: () => zeroAddress } }], [0]);

    assert.deepEqual(signed, [new Uint8Array([0xaa, 0xbb]), new Uint8Array([0xcc, 0xdd])]);
  });

  it("rejects signer responses with too few signed transactions", async () => {
    const client = new MockSignerClient();
    client.signRequests = async (requests, options) => {
      client.signCalls.push({ requests, options });
      return { signed: ["aabb"] };
    };
    const account = createApsignerAccount({
      client,
      address: zeroAddress,
      encodeTransaction: () => new Uint8Array([84, 88]),
    });

    await assert.rejects(
      account.signer(
        [
          { sender: { toString: () => zeroAddress } },
          { sender: { toString: () => zeroAddress } },
        ],
        [0, 1],
      ),
      /fewer signed transactions/,
    );
  });
});
