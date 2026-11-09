// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import algosdk from "algosdk";
import {
  ApsignerAlgoKitAccount,
  createApsignerAccount,
  listApsignerAccounts,
} from "../src/algokit.js";
import { bytesToHex, hexToBytes } from "../src/encoding.js";
import type { GroupSignResponse, KeyInfo, SignOptions, SignRequest } from "../src/types.js";

const zeroAddress = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ";
const signingKey = algosdk.generateAccount();
// Real addresses: the zero address is left out of a canonical encoding, which
// AlgoKit's encoder writes out, so a transaction naming it never round-trips.
const sender = algosdk.generateAccount().addr;
const receiver = algosdk.generateAccount().addr;

// payment builds a distinct transaction; algosdk's Transaction has the sender
// the adapter reads.
function payment(note: number, fee = 1_000): algosdk.Transaction {
  return algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender,
    receiver,
    amount: 0,
    note: new Uint8Array([note]),
    suggestedParams: {
      fee,
      firstValid: 1,
      lastValid: 1_000,
      genesisHash: new Uint8Array(32).fill(7),
      genesisID: "testnet-v1.0",
      flatFee: true,
    },
  });
}

const encodeForTest = (txn: unknown) => (txn as algosdk.Transaction).bytesToSign();

// signHonestly signs exactly the transactions requested, as apsigner does when
// it changes nothing.
function signHonestly(requests: SignRequest[]): string[] {
  return requests.map((request) => {
    const txn = algosdk.decodeUnsignedTransaction(hexToBytes(request.txn_bytes_hex).slice(2));
    return bytesToHex(txn.signTxn(signingKey.sk));
  });
}

class MockSignerClient {
  signCalls: Array<{ requests: SignRequest[]; options?: SignOptions }> = [];
  respond: (requests: SignRequest[]) => GroupSignResponse = (requests) => ({
    signed: signHonestly(requests),
  });

  async signRequests(
    requests: SignRequest[],
    options?: SignOptions,
  ): Promise<GroupSignResponse> {
    this.signCalls.push({ requests, options });
    return this.respond(requests);
  }

  async listKeys(_refresh = false): Promise<KeyInfo[]> {
    return [
      {
        address: zeroAddress,
        keyType: "ed25519",
        publicKeyHex: "",
        isGenericLsig: false,
      },
    ];
  }
}

function makeAccount(client: MockSignerClient): ApsignerAlgoKitAccount {
  return new ApsignerAlgoKitAccount({
    client,
    address: zeroAddress,
    authAddress: "AUTHADDR",
    newRequestId: () => "sdk-algokit-test",
    encodeTransaction: encodeForTest,
  });
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
      encodeTransaction: encodeForTest,
    });

    assert.equal(account.addr.toString(), zeroAddress);
    assert.equal(account.authAddress, "AUTHADDR");

    const group = [payment(1), payment(2), payment(3)];
    const signed = await account.signer(group, [0, 2]);

    assert.deepEqual(signed, [
      group[0].signTxn(signingKey.sk),
      group[2].signTxn(signingKey.sk),
    ]);
    assert.equal(client.signCalls.length, 1);
    assert.deepEqual(client.signCalls[0].requests, [
      {
        txn_bytes_hex: bytesToHex(group[0].bytesToSign()),
        txn_sender: sender.toString(),
        auth_address: "AUTHADDR",
        lsig_args: { preimage: "0102" },
      },
      {
        txn_bytes_hex: bytesToHex(group[2].bytesToSign()),
        txn_sender: sender.toString(),
        auth_address: "AUTHADDR",
        lsig_args: { preimage: "0102" },
      },
    ]);
    assert.equal(client.signCalls[0].options?.requestId, "sdk-algokit-test");
    assert.equal(client.signCalls[0].options?.signal, signal);
  });

  it("rejects a re-grouped response (signer added dummies / recomputed group ID)", async () => {
    for (const mutations of [{ dummiesAdded: 2 }, { groupIdChanged: true }]) {
      const client = new MockSignerClient();
      client.respond = (requests) => ({ signed: signHonestly(requests), mutations });
      await assert.rejects(makeAccount(client).signer([payment(1)], [0]), /re-grouped/);
    }
  });

  it("rejects a response whose signed count differs from the requested count", async () => {
    const client = new MockSignerClient();
    client.respond = (requests) => ({ signed: [...signHonestly(requests), ...signHonestly(requests)] });
    await assert.rejects(
      makeAccount(client).signer([payment(1)], [0]),
      /returned 2 signed transaction\(s\), but AlgoKit requested 1/,
    );
  });

  // Audit finding 4: for a lone transaction from a native Falcon or LogicSig
  // account, apsigner adds the authorization charge to the fee without
  // regrouping. AlgoKit would submit the raised transaction and wait on the
  // ID of its own copy, report a failure for a payment that went through, and
  // a retry would pay twice. The adapter refuses before AlgoKit submits.
  it("refuses a transaction whose fee the signer raised", async () => {
    const client = new MockSignerClient();
    client.respond = () => ({
      signed: [bytesToHex(payment(1, 3_000).signTxn(signingKey.sk))],
      mutations: { feesModified: [0], totalFeesDelta: 2_000 },
    });
    await assert.rejects(
      makeAccount(client).signer([payment(1)], [0]),
      /raised the fee of AlgoKit transaction 0 by the account's authorization charge \(2000 microAlgos in total\); AlgoKit's transaction ID would no longer match what is submitted, so nothing was submitted/,
    );
  });

  it("refuses any other change to a signed transaction, reported or not", async () => {
    const group = [payment(1), payment(2)];
    const client = new MockSignerClient();
    client.respond = (requests) => {
      const signed = signHonestly(requests);
      signed[1] = bytesToHex(payment(9).signTxn(signingKey.sk));
      return { signed };
    };
    await assert.rejects(
      makeAccount(client).signer(group, [0, 1]),
      /apsigner returned AlgoKit transaction 1 changed/,
    );
  });

  it("refuses a signed transaction it can't read", async () => {
    const client = new MockSignerClient();
    client.respond = () => ({ signed: ["aabb"] });
    await assert.rejects(
      makeAccount(client).signer([payment(1)], [0]),
      /unreadable signed transaction for AlgoKit transaction 0/,
    );
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

  // AlgoKit's encoder and algosdk's must agree on a transaction's bytes, or
  // the adapter would refuse a transaction apsigner signed unchanged.
  it("uses the current AlgoKit Utils v10 encoder by default", async () => {
    const client = new MockSignerClient();
    const account = createApsignerAccount({
      client: client as unknown as MockSignerClient,
      address: sender.toString(),
    });
    const transact = (await import("@algorandfoundation/algokit-utils/transact")) as unknown as {
      encodeTransaction(txn: unknown): Uint8Array;
    };
    const txn = {
      type: "pay",
      sender,
      fee: 1_000n,
      firstValid: 1n,
      lastValid: 1_000n,
      genesisHash: new Uint8Array(32).fill(7),
      genesisId: "testnet-v1.0",
      note: new Uint8Array([1]),
      payment: { receiver, amount: 5n },
    };

    const signed = await account.signer([txn], [0]);

    const requested = client.signCalls[0].requests;
    assert.equal(requested.length, 1);
    assert.equal(requested[0].txn_bytes_hex, bytesToHex(transact.encodeTransaction(txn)));
    assert.deepEqual(signed, signHonestly(requested).map(hexToBytes));
  });

  it("rejects signer responses with too few signed transactions", async () => {
    const client = new MockSignerClient();
    client.respond = (requests) => ({ signed: signHonestly(requests).slice(0, 1) });

    await assert.rejects(
      makeAccount(client).signer([payment(1), payment(2)], [0, 1]),
      /returned 1 signed transaction\(s\), but AlgoKit requested 2/,
    );
  });
});
