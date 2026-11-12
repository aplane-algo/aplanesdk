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
import { KeyNotFoundError } from "../src/errors.js";
import { isNetworkAllowed, loadConfig } from "../src/utils.js";
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

// Every sender is checked against everything it pays across a group: the
// ALGO it sends and the fee of every position, payments or not.
describe("group ALGO balance", () => {
  const accounts = (balance: number, otherBalance = 2_000_000) => ({
    [sender]: { amount: balance, minBalance: 100_000, assets: [{ assetId: 1001, amount: 25 }] },
    [receiver]: { amount: otherBalance, minBalance: 100_000, assets: [{ assetId: 1001, amount: 25 }] },
  });
  const holdingBoth = () => {
    globalThis.fetch = (async (url: string) => {
      const body = String(url).endsWith("/status")
        ? { state: "unlocked", ready_for_signing: true, key_count: 2, keyset_revision: 1 }
        : { count: 2, keys: [{ address: sender, key_type: "ed25519" }, { address: receiver, key_type: "ed25519" }] };
      return { status: 200, ok: true, json: async () => body };
    }) as any;
  };
  const transfer = { sender, receiver, assetId: 1001, amount: 5 };
  const payment = { sender, receiver, amount: 10_000 };
  const sweep = (balance: number, params: any, otherBalance?: number) =>
    new SignerClient("http://localhost:11270").prepareSweepGroup(
      algodWith(accounts(balance, otherBalance)), params,
    );

  it("counts ASA transfer fees against the paying sender", async () => {
    holdingBoth();
    // Available is the balance less the 100,000 minimum. The sender pays
    // 10,000 plus two 1000 fees: its own and the ASA transfer's.
    const group = await sweep(112_000, { asaTransfers: [transfer], payments: [payment] });
    assert.equal(group.checks?.at(-1)?.name, "group_algo_balance");
    await assert.rejects(
      sweep(111_999, { asaTransfers: [transfer], payments: [payment] }),
      /available 11999, required 12000/,
    );
  });

  it("checks the fees of a sweep with no payments", async () => {
    holdingBoth();
    await sweep(102_000, { asaTransfers: [transfer, transfer] });
    await assert.rejects(
      sweep(101_999, { asaTransfers: [transfer, transfer] }),
      /available 1999, required 2000/,
    );
  });

  it("checks a sender that has only asset transfers", async () => {
    holdingBoth();
    const otherTransfer = { sender: receiver, receiver: sender, assetId: 1001, amount: 1 };
    const both = [otherTransfer, otherTransfer];
    await sweep(2_000_000, { asaTransfers: both, payments: [payment] }, 102_000);
    await assert.rejects(
      sweep(2_000_000, { asaTransfers: both, payments: [payment] }, 101_999),
      new RegExp(`group insufficient funds for ${receiver}`),
    );
  });

  // An asset transfer's own check compares its fee with the sender's
  // spendable ALGO, so a single transfer and a group of one agree.
  it("checks an asset transfer's fee in the transfer's own check", async () => {
    holdingBoth();
    const single = (balance: number) =>
      new SignerClient("http://localhost:11270").prepareAsaTransfer(
        algodWith(accounts(balance)), transfer,
      );
    const group = (balance: number) =>
      new SignerClient("http://localhost:11270").prepareAsaTransferGroup(
        algodWith(accounts(balance)), [transfer],
      );
    const prepared = await single(2_000_000);
    // The two checks, and the data all three SDKs record.
    assert.deepEqual(prepared.checks?.map((check) => check.name), ["asa_transfer", "spendable_algo"]);
    assert.deepEqual(prepared.checks?.[0].data, { assetId: 1001, amount: 5, balance: 25n, fee: 1000n });
    assert.deepEqual(prepared.checks?.[1].data, { available: 1_900_000n });

    // Exactly the fee above the 100,000 minimum is enough.
    await single(101_000);
    await group(101_000);
    // One microAlgo short: the single helper and both group helpers refuse
    // with the transfer's own message.
    const message = /insufficient funds for asset transfer fee: available 999, fee 1000/;
    await assert.rejects(single(100_999), message);
    await assert.rejects(group(100_999), message);
    await assert.rejects(sweep(100_999, { asaTransfers: [transfer] }), message);
    // An account below its minimum has nothing to spend, not a negative amount.
    await assert.rejects(single(50_000), /available 0, fee 1000/);
  });

  // The group check's balance comes from the spendable_algo check and nowhere
  // else. A position without it, or with a value that is not a whole number,
  // is refused, not passed, even beside a position of the same sender that
  // has one.
  const tampered: Array<[string, () => any[], RegExp]> = [
    ["no check", () => [], /no ALGO balance on record/],
    [
      "available under another name",
      () => [{ name: "payment_balance", status: "ok", data: { available: 5000n } }],
      /no ALGO balance on record/,
    ],
    ["no available amount", () => [{ name: "spendable_algo", status: "ok", data: { balance: 5000n } }], /has no available amount/],
    ["no data", () => [{ name: "spendable_algo", status: "ok" }], /has no available amount/],
    ["a null amount", () => [{ name: "spendable_algo", status: "ok", data: { available: null } }], /available amount must be/],
    ["a string amount", () => [{ name: "spendable_algo", status: "ok", data: { available: "5000" } }], /available amount must be/],
    ["a fractional amount", () => [{ name: "spendable_algo", status: "ok", data: { available: 5000.5 } }], /available amount must be/],
    ["a negative amount", () => [{ name: "spendable_algo", status: "ok", data: { available: -1n } }], /available amount must be/],
  ];
  // Positions of one sender each read its balance on their own. The group
  // check takes the lowest value recorded, whatever their order.
  for (const recorded of [[5000n, 1999n], [1999n, 5000n], [5000n, 2000n], [2000n, 5000n]]) {
    it(`checks the lowest spendable ALGO recorded for a sender (${recorded.join(", ")})`, async () => {
      holdingBoth();
      const client = new SignerClient("http://localhost:11270");
      const real = client.prepareAsaTransfer.bind(client);
      let calls = 0;
      (client as any).prepareAsaTransfer = async (algod: any, params: any) => {
        const prepared = await real(algod, params);
        const own = (prepared.checks || []).filter((check) => check.name !== "spendable_algo");
        const spendable = { name: "spendable_algo", status: "ok", data: { available: recorded[calls++] } };
        return { ...prepared, checks: [...own, spendable] };
      };
      const group = client.prepareAsaTransferGroup(algodWith(accounts(2_000_000)), [transfer, transfer]);
      if (recorded.includes(1999n)) {
        await assert.rejects(group, /available 1999, required 2000/);
      } else {
        await group;
      }
    });
  }

  for (const [name, change, message] of tampered) {
    it(`refuses a group position with ${name} for its spendable ALGO`, async () => {
      holdingBoth();
      const client = new SignerClient("http://localhost:11270");
      const real = client.prepareAsaTransfer.bind(client);
      let calls = 0;
      // The second position's checks are replaced; the first keeps its own.
      (client as any).prepareAsaTransfer = async (algod: any, params: any) => {
        const prepared = await real(algod, params);
        const own = (prepared.checks || []).filter((check) => check.name !== "spendable_algo");
        return ++calls === 2 ? { ...prepared, checks: [...own, ...change()] } : prepared;
      };
      await assert.rejects(
        client.prepareAsaTransferGroup(algodWith(accounts(2_000_000)), [transfer, transfer]),
        (error: unknown) => {
          assert.ok(error instanceof sdk.SignerError);
          assert.match(error.message, /group transaction 1, sender /);
          assert.match(error.message, message);
          return true;
        },
      );
    });
  }

  it("makes the same check in the ASA transfer group helper", async () => {
    holdingBoth();
    await assert.rejects(
      new SignerClient("http://localhost:11270").prepareAsaTransferGroup(
        algodWith(accounts(101_999)), [transfer, transfer],
      ),
      /available 1999, required 2000/,
    );
  });
});

// ABI reference arguments (application, asset) are IDs too, and every ID is
// checked before anything is encoded, so the caller gets a SignerError and
// never BigInt()'s RangeError.
describe("IDs, counts and indexes everywhere", () => {
  const client = new SignerClient("http://localhost:11270");
  const noAlgod = {
    getTransactionParams: () => {
      throw new Error("algod was reached with an invalid argument");
    },
  } as any;
  const isSignerError = (pattern: RegExp) => (error: unknown) => {
    assert.ok(error instanceof sdk.SignerError, `expected SignerError, got ${String(error)}`);
    assert.match((error as Error).message, pattern);
    return true;
  };
  const program = new Uint8Array([0x06, 0x81, 0x01]);
  const deploy = { sender, approvalProgram: program, clearProgram: program };

  for (const bad of [123.9, "123", true, -1, 0, 2n ** 64n] as any[]) {
    it(`refuses ABI reference argument ${String(bad)}`, async () => {
      await assert.rejects(
        client.prepareAbiAppCall(noAlgod, {
          sender, appId: 7, methodSignature: "f(asset)void", args: [bad],
        }),
        isSignerError(/asset argument must/),
      );
      await assert.rejects(
        client.prepareAbiAppCall(noAlgod, {
          sender, appId: 7, methodSignature: "f(application)void", args: [bad],
        }),
        isSignerError(/application argument must/),
      );
    });
  }

  for (const bad of [123.9, "123", true, -1, 2n ** 64n] as any[]) {
    it(`refuses ${String(bad)} on the ABI path before encoding`, async () => {
      await assert.rejects(
        client.prepareAbiAppCall(noAlgod, { sender, appId: bad, methodSignature: "f()void" }),
        isSignerError(/appId must/),
      );
      await assert.rejects(
        client.prepareAbiAppCall(noAlgod, {
          sender, appId: 7, methodSignature: "f(application)void", args: [9], foreignApps: [bad],
        }),
        isSignerError(/foreignApps\[0\] must/),
      );
    });

    it(`refuses ${String(bad)} in deploy, box and key-registration fields`, async () => {
      await assert.rejects(
        client.prepareAppDeploy(noAlgod, { ...deploy, extraPages: bad }),
        isSignerError(/extraPages must/),
      );
      await assert.rejects(
        client.prepareAppDeploy(noAlgod, { ...deploy, foreignApps: [bad] }),
        isSignerError(/foreignApps\[0\] must/),
      );
      await assert.rejects(
        client.prepareAppDeploy(noAlgod, { ...deploy, foreignAssets: [bad] }),
        isSignerError(/foreignAssets\[0\] must/),
      );
      for (const count of [
        "numLocalInts", "numLocalByteSlices", "numGlobalInts", "numGlobalByteSlices",
      ]) {
        await assert.rejects(
          client.prepareAppDeploy(noAlgod, { ...deploy, [count]: bad }),
          isSignerError(new RegExp(`${count} must`)),
        );
        await assert.rejects(
          client.prepareAppCall(noAlgod, { sender, appId: 7, [count]: bad }),
          isSignerError(new RegExp(`${count} must`)),
        );
      }
      await assert.rejects(
        client.prepareAppCall(noAlgod, { sender, appId: 7, extraPages: bad }),
        isSignerError(/extraPages must/),
      );
      const boxes = [{ appIndex: bad, name: new Uint8Array([1]) }];
      await assert.rejects(
        client.prepareAppDeploy(noAlgod, { ...deploy, boxes }),
        isSignerError(/boxes\[0\]\.appIndex must/),
      );
      await assert.rejects(
        client.prepareAppCall(noAlgod, { sender, appId: 7, boxes }),
        isSignerError(/boxes\[0\]\.appIndex must/),
      );
      await assert.rejects(
        client.prepareAbiAppCall(noAlgod, { sender, appId: 7, methodSignature: "f()void", boxes }),
        isSignerError(/boxes\[0\]\.appIndex must/),
      );
      const online = {
        sender, mode: "online" as const, voteKey: "k", selectionKey: "k", stateProofKey: "k",
        voteFirst: 1, voteLast: 10, voteKeyDilution: 3,
      };
      for (const field of ["voteFirst", "voteLast", "voteKeyDilution"]) {
        await assert.rejects(
          client.prepareKeyreg(noAlgod, { ...online, [field]: bad } as any),
          isSignerError(new RegExp(`${field} must`)),
        );
      }
    });
  }

  for (const bad of [1.9, "1", true, -1, 6, 1n] as any[]) {
    it(`refuses onComplete ${String(bad)}${typeof bad === "bigint" ? "n" : ""}`, async () => {
      await assert.rejects(
        client.prepareAppCall(noAlgod, { sender, appId: 7, onComplete: bad }),
        isSignerError(/invalid onComplete/),
      );
    });
  }

  it("refuses a boolean where an ABI method takes an integer", async () => {
    await assert.rejects(
      client.prepareAbiAppCall(noAlgod, {
        sender, appId: 7, methodSignature: "f(uint64)void", args: [true],
      }),
    );
  });

  it("accepts whole-number schema counts and leaves unset ones at zero", async () => {
    signerHolding(sender);
    const algod = algodWith({ [sender]: { amount: 2_000_000, minBalance: 100_000 } });
    const fresh = new SignerClient("http://localhost:11270");
    const prepared = await fresh.prepareAppDeploy(algod, {
      ...deploy, numGlobalInts: 2, numGlobalByteSlices: 3n, extraPages: 1, numLocalInts: undefined,
    });
    const call = (prepared.transaction as any).applicationCall;
    assert.equal(Number(call.numGlobalInts), 2);
    assert.equal(Number(call.numGlobalByteSlices), 3);
    assert.equal(Number(call.numLocalInts), 0);
    assert.equal(Number(call.extraPages), 1);
  });

  it("accepts whole-number references, box indexes and reference arguments", async () => {
    signerHolding(sender);
    const algod = algodWith({ [sender]: { amount: 2_000_000, minBalance: 100_000 } });
    const fresh = new SignerClient("http://localhost:11270");
    const prepared = await fresh.prepareAbiAppCall(algod, {
      sender,
      appId: 7,
      methodSignature: "f(asset,application,account)void",
      args: [1001, 9n, receiver],
      boxes: [{ appIndex: 0, name: new Uint8Array([1]) }, { appIndex: 9, name: new Uint8Array([2]) }],
    });
    const call = (prepared.transaction as any).applicationCall;
    assert.deepEqual(call.foreignAssets, [1001n]);
    assert.deepEqual(call.foreignApps, [9n]);
    assert.equal(call.accounts[0].toString(), receiver);
    assert.equal(call.boxes.length, 2);
  });
});

describe("cosigned group key record", () => {
  // The flow takes each key's flow, resources and fee ceiling from the
  // signer's own record: the spendable key for the position's auth address,
  // read from a key list refreshed when the signer's keyset revision changes.
  // It is the lookup the prepare helpers make. A prepared transaction carries
  // no key of its own.
  it("is the spendable key from the signer's current keyset", async () => {
    const txn = fakePayment();
    const sender = txn.sender.toString();
    const userClient = new SignerClient("http://localhost:11270");
    const witness = { address: sender, key_type: "aplane.witness-falcon1024.v1", is_spending_account: false };
    // Two rows for one address, the non-spending one last. A second spendable
    // row follows as well: the first one is the one chosen, from the fresh
    // list and from the cache alike.
    const signer = {
      revision: 1,
      keys: [
        { ...witness, signing_flow: "witness8" },
        { address: sender, key_type: "ed25519", signing_flow: "cosigner9" },
        { address: sender, key_type: "ed25519", signing_flow: "cosigner11" },
        { ...witness, signing_flow: "witness9" },
      ] as Record<string, unknown>[],
      fetches: 0,
    };
    globalThis.fetch = (async (url: string) => {
      const path = new URL(String(url)).pathname;
      let body: unknown;
      if (path === "/status") {
        body = { state: "unlocked", keyset_revision: signer.revision };
      } else if (path === "/keys") {
        signer.fetches++;
        body = { count: signer.keys.length, keys: signer.keys };
      } else {
        assert.fail(`unexpected request ${url}: the flow must stop at the key record`);
      }
      return { status: 200, ok: true, json: async () => body };
    }) as any;
    const attempt = () =>
      signPreparedCosignedGroup({
        userClient,
        preparedGroup: { transactions: [{ transaction: txn, authAddress: sender }] },
      });

    // The spendable row decides the flow, on the fresh read and from the cache.
    for (let i = 0; i < 2; i++) {
      await assert.rejects(attempt(), /signing flow "cosigner9"/);
    }
    // An unchanged keyset revision costs no further /keys request.
    assert.equal(signer.fetches, 1);
    // The prepare helpers select the same row from the same list.
    const resolved = await userClient.resolveAuthAddress(sender, async () => ({}));
    assert.equal(resolved.keyInfo.signingFlow, "cosigner9");
    assert.equal(signer.fetches, 1);

    // The operator changes the key: a new revision, and the next call reads
    // the new record.
    signer.revision = 2;
    signer.keys = [{ address: sender, key_type: "ed25519", signing_flow: "cosigner10" }];
    await assert.rejects(attempt(), /signing flow "cosigner10"/);
    assert.equal(signer.fetches, 2);

    // Only a non-spending row for the address: there is no key to sign with.
    signer.revision = 3;
    signer.keys = [witness];
    await assert.rejects(attempt(), (err: unknown) => {
      assert.ok(err instanceof KeyNotFoundError);
      assert.match(err.message, /is not available for signing/);
      return true;
    });
    // A position with no auth address has nothing to look a key up by.
    await assert.rejects(
      signPreparedCosignedGroup({ userClient, preparedGroup: { transactions: [{ transaction: txn }] } }),
      /auth address is required/,
    );
  });
});

describe("strict base64", () => {
  const good = Buffer.from(signedHex(fakePayment()), "hex").toString("base64");
  // The case list the Go and Python suites run too: the three SDKs accept and
  // refuse the same strings.
  const accepted = ["", "QQ==", "QUI=", "QUJD", "QUJDRA==", "+/+/", "AAAA"];
  const lenient: Array<[string, string]> = [
    ["a trailing line feed", "QUJD\n"],
    ["a trailing CRLF", "QUJD\r\n"],
    ["a line feed inside", "QU\nJD"],
    ["a wrapped line", "QUJD\r\nQUJD"],
    ["a leading line feed", "\nQUJD"],
    ["a space", "QU JD"],
    ["a trailing space", "QUJD "],
    ["a tab", "\tQUJD"],
    ["a character outside the alphabet", "QU*D"],
    ["the URL-safe alphabet", "-_-_"],
    ["missing padding", "QUI"],
    ["short padding", "QQ="],
    ["long padding", "QQ==="],
    ["data after the padding", "QUI=QUJD"],
    ["padding first", "=QUJ"],
    ["one character", "Q"],
  ];

  it("decodes standard base64", () => {
    assert.deepEqual(Buffer.from(base64ToBytes(good)).toString("base64"), good);
    for (const value of accepted) {
      assert.equal(Buffer.from(base64ToBytes(value)).toString("base64"), value);
    }
  });

  for (const [name, value] of lenient) {
    it(`refuses ${name}`, async () => {
      assert.throws(() => base64ToBytes(value, "input"), /input is not valid base64/);
    });
  }

  // The caller-facing sites take the signed bytes themselves, so no string,
  // valid base64 or not, is decoded there.
  it("is not applied to a signed transaction a caller supplies, which must be bytes", () => {
    const client = new SignerClient("http://localhost:11270");
    for (const value of [good, ...lenient.map(([, text]) => text)]) {
      assert.throws(
        () => preparedGroupToSignRequests({ transactions: [{ signedTransaction: value as any }] }),
        { message: "prepared transaction 0: signedTransaction must be signed transaction bytes (a Uint8Array), not a string" },
      );
      assert.throws(
        () => (client as any).buildSignRequestBody([null], [null], undefined, { 0: value }),
        { message: "passthrough[0] must be signed transaction bytes (a Uint8Array), not a string" },
      );
    }
  });
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

  // A networks_allowed that cannot be read must not become an empty list,
  // which permits every network, and an entry that is not text is not a
  // network name. The Go and Python suites run the same cases.
  for (const value of [
    "mainnet", "{a: b}", "[testnet, [a]]", "[testnet, Mainnet]", "[testnet, 1.5]", "[testnet, -x]",
    "[testnet, 1]", "[testnet, true]", "[testnet, null]", "[testnet, ~]",
  ]) {
    it(`refuses networks_allowed: ${value}`, () => {
      const dir = write(`network: testnet\nnetworks_allowed: ${value}\n`);
      try {
        assert.throws(() => loadConfig(dir), /networks_allowed/);
      } finally {
        fs.rmSync(dir, { recursive: true });
      }
    });
  }

  const readable: Array<[string, string[]]> = [
    ["[]", []],
    ["", []],
    // A name made of digits, or spelled like a boolean, is fine once quoted.
    ['[testnet, "1"]', ["testnet", "1"]],
    ['[testnet, "true"]', ["testnet", "true"]],
    ["[testnet, my_net-2]", ["testnet", "my_net-2"]],
  ];
  for (const [value, allowed] of readable) {
    it(`reads networks_allowed: ${value || "(empty)"}`, () => {
      const dir = write(`network: testnet\nnetworks_allowed: ${value}\n`);
      try {
        assert.deepEqual(loadConfig(dir).networksAllowed, allowed);
      } finally {
        fs.rmSync(dir, { recursive: true });
      }
    });
  }

  // Whole config files the Go and Python suites load too. A YAML alias is
  // read as the value it stands for, and the default network must be text
  // like the allowlist's entries.
  const loadable: Array<[string, string, string[]]> = [
    ["nets: &nets [testnet]\nnetworks_allowed: *nets\n", "testnet", ["testnet"]],
    ["name: &name testnet\nnetworks_allowed: [*name, mainnet]\n", "testnet", ["testnet", "mainnet"]],
    ["name: &name mainnet\nnetwork: *name\n", "mainnet", []],
    ["network: ~\n", "testnet", []],
    ["network: \"1\"\n", "1", []],
    ["network: \"1\"\nnetworks_allowed: [\"1\"]\n", "1", ["1"]],
  ];
  for (const [content, network, allowed] of loadable) {
    it(`loads ${JSON.stringify(content)}`, () => {
      const dir = write(content);
      try {
        const config = loadConfig(dir);
        assert.equal(config.network, network);
        assert.deepEqual(config.networksAllowed, allowed);
      } finally {
        fs.rmSync(dir, { recursive: true });
      }
    });
  }
  const refusedFiles: Array<[string, RegExp]> = [
    ["n: &n 1\nnetworks_allowed: [*n]\n", /networks_allowed/],
    ["n: &n {a: b}\nnetworks_allowed: *n\n", /networks_allowed/],
    ["network: 1\n", /invalid network in config.yaml/],
    ["network: 1\nnetworks_allowed: [testnet]\n", /invalid network in config.yaml/],
    ["network: true\n", /invalid network in config.yaml/],
    ["network: 1.5\n", /invalid network in config.yaml/],
    ["network: [a]\n", /invalid network in config.yaml/],
    ["network: Mainnet\n", /invalid network in config.yaml/],
    ["n: &n 1\nnetwork: *n\n", /invalid network in config.yaml/],
  ];
  for (const [content, message] of refusedFiles) {
    it(`refuses ${JSON.stringify(content)}`, () => {
      const dir = write(content);
      try {
        assert.throws(() => loadConfig(dir), (error: unknown) => {
          assert.ok(error instanceof sdk.SignerError);
          assert.match(error.message, message);
          return true;
        });
      } finally {
        fs.rmSync(dir, { recursive: true });
      }
    });
  }

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
  it("no longer exports assembleGroup or the submit helper", () => {
    assert.equal((sdk as any).assembleGroup, undefined);
    assert.equal((sdk as any).sendRawTransaction, undefined);
    assert.equal(typeof sdk.SignerClient, "function");
    assert.ok(algosdk);
  });
});
