// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

// Prepare-helper argument checks, preflight fees, and the smaller client checks.

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import algosdk from "algosdk";
import { SignerClient, signPreparedCosignedGroup } from "../src/client.js";
import * as sdk from "../src/index.js";
import { isNetworkAllowed, loadConfig, sendRawTransaction } from "../src/utils.js";
import { base64ToBytes } from "../src/encoding.js";
import { preparedGroupToSignRequests } from "../src/prepared.js";
import { fakeAddress, fakePayment, signedHex } from "./fakeSigner.js";

const sender = fakeAddress(1);
const receiver = fakeAddress(2);

/** An algod as a real network answers: a zero per-byte fee and a 1000 minimum. */
function algodWith(accounts: Record<string, any>): any {
  return {
    getTransactionParams: () => ({
      do: async () => ({
        fee: 0n,
        minFee: 1000n,
        flatFee: false,
        firstValid: 1n,
        lastValid: 100n,
        genesisHash: new Uint8Array(32),
        genesisID: "testnet-v1",
      }),
    }),
    accountInformation: (address: string) => ({ do: async () => accounts[address] }),
  };
}

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

/** Answer /status and /keys as a signer holding one Ed25519 key. */
function signerHolding(address: string): void {
  globalThis.fetch = (async (url: string) => {
    const body = String(url).endsWith("/status")
      ? { state: "unlocked", ready_for_signing: true, key_count: 1, keyset_revision: 1 }
      : { count: 1, keys: [{ address, key_type: "ed25519" }] };
    return { status: 200, ok: true, json: async () => body };
  }) as any;
}

const badIntegers: any[] = [123.9, "123", true, -1, 2n ** 64n, Number.NaN];

describe("prepare helpers require whole numbers", () => {
  const client = new SignerClient("http://localhost:11270");
  const noAlgod = {
    getTransactionParams: () => {
      throw new Error("algod was reached with an invalid argument");
    },
  } as any;

  for (const bad of [...badIntegers, 0]) {
    it(`refuses app ID ${String(bad)}`, async () => {
      await assert.rejects(
        client.prepareAppCall(noAlgod, { sender, appId: bad }),
        /appId must be/,
      );
      await assert.rejects(
        client.prepareAbiAppCall(noAlgod, { sender, appId: bad, methodSignature: "do()void" }),
        /appId must be/,
      );
    });
    it(`refuses asset ID ${String(bad)}`, async () => {
      await assert.rejects(
        client.prepareAsaTransfer(noAlgod, { sender, receiver, assetId: bad, amount: 1 }),
        /assetId must be/,
      );
      await assert.rejects(client.prepareAsaOptIn(noAlgod, { sender, assetId: bad }), /assetId must be/);
      await assert.rejects(
        client.prepareAsaOptOut(noAlgod, { sender, assetId: bad, closeTo: receiver }),
        /assetId must be/,
      );
    });
  }

  for (const bad of badIntegers) {
    it(`refuses amount, fee and foreign reference ${String(bad)}`, async () => {
      const algod = algodWith({ [sender]: { amount: 2_000_000, minBalance: 100_000 } });
      await assert.rejects(
        client.preparePayment(noAlgod, { sender, receiver, amount: bad }),
        /amount must be/,
      );
      await assert.rejects(
        client.prepareAsaTransfer(noAlgod, { sender, receiver, assetId: 5, amount: bad }),
        /amount must be/,
      );
      await assert.rejects(
        client.preparePayment(algod, { sender, receiver, amount: 1, fee: bad }),
        /fee must be/,
      );
      await assert.rejects(
        client.prepareAppCall(noAlgod, { sender, appId: 7, foreignApps: [bad] }),
        /foreignApps\[0\] must be/,
      );
      await assert.rejects(
        client.prepareAppCall(noAlgod, { sender, appId: 7, foreignAssets: [5, bad] }),
        /foreignAssets\[1\] must be/,
      );
    });
  }

  it("accepts safe integers and bigints", async () => {
    signerHolding(sender);
    const algod = algodWith({ [sender]: { amount: 2_000_000, minBalance: 100_000 } });
    const fresh = new SignerClient("http://localhost:11270");
    const call = await fresh.prepareAppCall(algod, {
      sender, appId: 123n, foreignApps: [7], foreignAssets: [9n],
    });
    assert.equal((call.transaction as any).applicationCall.appIndex, 123n);
    const payment = await fresh.preparePayment(algod, { sender, receiver, amount: 0, fee: 0 });
    assert.equal((payment.transaction as any).fee, 0n);
  });
});

// The opt-in and close preflights compare the balance with the fee the built
// transaction pays. The suggested fee is per byte, zero on a real network, so
// comparing against it checked nothing.
describe("opt-in and close preflights", () => {
  it("check the opt-in against the transaction's fee", async () => {
    signerHolding(sender);
    const client = new SignerClient("http://localhost:11270");
    const prepared = await client.prepareAsaOptIn(
      algodWith({ [sender]: { amount: 1000, minBalance: 0 } }),
      { sender, assetId: 1001 },
    );
    assert.equal((prepared.transaction as any).fee, 1000n);
    assert.equal(prepared.checks?.[0].data?.fee, 1000);

    await assert.rejects(
      client.prepareAsaOptIn(algodWith({ [sender]: { amount: 999, minBalance: 0 } }), { sender, assetId: 1001 }),
      /insufficient funds for opt-in fee: balance 999, fee 1000/,
    );
    // An explicit flat fee is the fee that is checked.
    await assert.rejects(
      client.prepareAsaOptIn(
        algodWith({ [sender]: { amount: 4999, minBalance: 0 } }),
        { sender, assetId: 1001, fee: 5000 },
      ),
      /balance 4999, fee 5000/,
    );
    // No minimum-balance rule was added: a balance that covers the fee passes.
    await client.prepareAsaOptIn(
      algodWith({ [sender]: { amount: 1000, minBalance: 100_000 } }),
      { sender, assetId: 1001 },
    );
  });

  it("check the close against the transaction's fee", async () => {
    signerHolding(sender);
    const client = new SignerClient("http://localhost:11270");
    const prepared = await client.prepareAccountClose(
      algodWith({ [sender]: { amount: 1000, minBalance: 0 } }),
      { sender, closeTo: receiver },
    );
    assert.equal(prepared.checks?.[0].data?.fee, 1000);
    await assert.rejects(
      client.prepareAccountClose(
        algodWith({ [sender]: { amount: 999, minBalance: 0 } }),
        { sender, closeTo: receiver },
      ),
      /insufficient funds for close fee: balance 999, fee 1000/,
    );
  });
});

describe("sweep group", () => {
  it("counts ASA transfer fees against the paying sender", async () => {
    signerHolding(sender);
    const sweep = (balance: number) => {
      const client = new SignerClient("http://localhost:11270");
      return client.prepareSweepGroup(
        algodWith({
          [sender]: {
            amount: balance,
            minBalance: 100_000,
            assets: [{ assetId: 1001, amount: 25 }],
          },
          [receiver]: {
            amount: 2_000_000,
            minBalance: 100_000,
            assets: [{ assetId: 1001, amount: 0 }],
          },
        }),
        {
          asaTransfers: [{ sender, receiver, assetId: 1001, amount: 5 }],
          payments: [{ sender, receiver, amount: 10_000 }],
        },
      );
    };
    // Available is the balance less the 100,000 minimum. The sender pays
    // 10,000 plus two 1000 fees: its own and the ASA transfer's.
    assert.equal((await sweep(112_000)).transactions.length, 2);
    await assert.rejects(sweep(111_999), /available 11999, required 12000/);
  });
});

describe("cosigned group", () => {
  it("refuses a signer key for another address", async () => {
    const txn = fakePayment();
    const userClient = new SignerClient("http://localhost:11270");
    globalThis.fetch = (async () => {
      throw new Error("the signer was contacted for a group with a mismatched signer key");
    }) as any;
    await assert.rejects(
      signPreparedCosignedGroup({
        userClient,
        preparedGroup: {
          transactions: [{
            transaction: txn,
            authAddress: txn.sender.toString(),
            signerKey: { address: fakeAddress(9), keyType: "ed25519" } as any,
          }],
        },
      }),
      /signer key is for .*, not the position's auth address/,
    );
  });
});

describe("strict base64", () => {
  const good = Buffer.from(signedHex(fakePayment()), "hex").toString("base64");
  const lenient: Array<[string, string]> = [
    ["data after the padding", `${Buffer.from("ab").toString("base64")}AAAA`],
    ["a character outside the alphabet", `${good.slice(0, 8)}*${good.slice(9)}`],
    ["whitespace", `${good.slice(0, 8)} ${good.slice(8)}`],
    ["the URL-safe alphabet", "-_-_"],
    ["missing padding", "QUI"],
  ];

  it("decodes standard base64", () => {
    assert.deepEqual(Buffer.from(base64ToBytes(good)).toString("base64"), good);
    assert.deepEqual(base64ToBytes(""), new Uint8Array());
    assert.deepEqual(base64ToBytes("QUI="), new Uint8Array([0x41, 0x42]));
  });

  for (const [name, value] of lenient) {
    it(`refuses ${name}`, async () => {
      assert.throws(() => base64ToBytes(value, "input"), /input is not valid base64/);
      // The same strings Buffer.from would have taken, at each caller-facing site.
      assert.throws(
        () => preparedGroupToSignRequests({ transactions: [{ signedTransactionBase64: value }] }),
        /signedTransactionBase64 is not valid base64/,
      );
      const client = new SignerClient("http://localhost:11270");
      assert.throws(
        () => (client as any).buildSignRequestBody([null], [null], undefined, { 0: value }),
        /passthrough\[0\] is not valid base64/,
      );
      const algod = { sendRawTransaction: () => { throw new Error("submitted"); } } as any;
      await assert.rejects(sendRawTransaction(algod, value), /not valid base64/);
    });
  }
});

describe("networks_allowed", () => {
  const write = (content: string): string => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-ts-net-"));
    fs.writeFileSync(path.join(dir, "config.yaml"), content);
    return dir;
  };

  it("refuses a default network outside the allowlist", () => {
    const dir = write("network: mainnet\nnetworks_allowed: [testnet]\n");
    try {
      assert.throws(() => loadConfig(dir), /network "mainnet" is not in networks_allowed/);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it("answers whether a network is allowed", () => {
    const dir = write("network: testnet\nnetworks_allowed: [testnet]\n");
    const open = write("network: testnet\n");
    try {
      const config = loadConfig(dir);
      assert.equal(isNetworkAllowed(config, "testnet"), true);
      assert.equal(isNetworkAllowed(config, "mainnet"), false);
      assert.equal(isNetworkAllowed(loadConfig(open), "mainnet"), true);
    } finally {
      fs.rmSync(dir, { recursive: true });
      fs.rmSync(open, { recursive: true });
    }
  });
});

describe("removed helpers", () => {
  it("no longer exports assembleGroup", () => {
    assert.equal((sdk as any).assembleGroup, undefined);
    assert.equal(typeof sdk.sendRawTransaction, "function");
    assert.ok(algosdk);
  });
});
