// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * Fake signers and a fake algod for the send and rotating tests. The signers
 * answer HTTP through a stand-in for fetch, so the client's own transport,
 * status mapping and lost-answer marking are exercised; the algod is an
 * object with the algosdk client's methods.
 */

import algosdk, { type Transaction } from "algosdk";
import type { SignRequest } from "../src/types.js";
import { bytesToHex, hexToBytes } from "../src/encoding.js";
import { signResponse, type FakeSignerOptions } from "./fakeSigner.js";

/** What a fake signer does with one request. */
export type FakeReply =
  | { status?: number; body: unknown }
  | "drop" // the connection closes with no answer
  | { status?: number; raw: string }; // a body sent as is, such as one cut short

export type FakeHandler = (path: string, body: any) => FakeReply | Promise<FakeReply>;

/**
 * Answer the client's fetch calls with the handler registered for each base
 * URL. Returns a function that restores the previous fetch.
 */
export function installSigners(handlers: Record<string, FakeHandler>): () => void {
  const previous = globalThis.fetch;
  globalThis.fetch = (async (input: unknown, init?: { body?: string; signal?: AbortSignal }) => {
    const url = new URL(String(input));
    const handler = handlers[url.origin];
    if (!handler) {
      throw new TypeError(`fetch failed: no fake signer at ${url.origin}`);
    }
    // As fetch does, an already aborted signal sends nothing.
    if (init?.signal?.aborted) {
      throw new DOMException("This operation was aborted", "AbortError");
    }
    const body = init?.body ? JSON.parse(init.body) : undefined;
    const reply = await handler(url.pathname, body);
    if (reply === "drop") {
      throw new TypeError("fetch failed: connection closed");
    }
    if ("raw" in reply) {
      return new Response(reply.raw, { status: reply.status ?? 200 });
    }
    return new Response(JSON.stringify(reply.body), {
      status: reply.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;
  return () => {
    globalThis.fetch = previous;
  };
}

/** A /keys entry as the signer sends it. */
export interface WireKey {
  address: string;
  key_type?: string;
  signing_flow?: string;
  is_spending_account?: boolean;
  [field: string]: unknown;
}

export function statusBody(approvalWaitSeconds = 60): unknown {
  return {
    state: "unlocked",
    signer_locked: false,
    ready_for_signing: true,
    key_count: 1,
    keyset_revision: 1,
    approval_wait_seconds: approvalWaitSeconds,
  };
}

/** A fake signer for send tests. sign answers /sign; unset, it signs every position as its auth address. */
export class SendSigner {
  keys: WireKey[];
  sign?: (body: any) => FakeReply;
  /** What the default /sign answer does to the group. */
  behaviour: FakeSignerOptions = {};
  paths: string[] = [];

  constructor(keys: WireKey[], options: { sign?: (body: any) => FakeReply; behaviour?: FakeSignerOptions } = {}) {
    this.keys = keys;
    this.sign = options.sign;
    this.behaviour = options.behaviour ?? {};
  }

  count(path: string): number {
    return this.paths.filter((entry) => entry === path).length;
  }

  handle = (path: string, body: any): FakeReply => {
    this.paths.push(path);
    switch (path) {
      case "/status":
        return { body: statusBody() };
      case "/keys":
        return { body: { count: this.keys.length, keys: this.keys } };
      case "/sign":
        if (this.sign) return this.sign(body);
        return { body: signResponse(body.requests as SignRequest[], this.behaviour) };
      case "/sign/cancel":
        return { body: { state: "canceled" } };
      default:
        throw new Error(`unexpected signer path ${path}`);
    }
  };
}

/** An error as algosdk's HTTP client throws it for a non-2xx answer. */
export function algodHttpError(status: number, message: string): Error {
  const error = new Error(`Network request error. Received status ${status} (test): ${message}`) as Error & {
    response: { status: number; body: Uint8Array; headers: Record<string, string> };
  };
  error.response = {
    status,
    body: new TextEncoder().encode(JSON.stringify({ message })),
    headers: {},
  };
  return error;
}

/** The first signed transaction of a concatenated submission. */
export function firstSignedTransaction(blob: Uint8Array): algosdk.SignedTransaction {
  // A prefix shorter than the first transaction is cut short and a longer one
  // has bytes left over, so its end is the one prefix that decodes.
  let low = 1;
  let high = blob.length;
  while (low <= high) {
    const mid = (low + high) >> 1;
    try {
      return algosdk.decodeSignedTransaction(blob.slice(0, mid));
    } catch (error) {
      if (/extra/i.test(String(error))) {
        high = mid - 1;
      } else {
        low = mid + 1;
      }
    }
  }
  throw new Error("submission holds no signed transaction");
}

export const testGenesisHash = (() => {
  const hash = new Uint8Array(32);
  hash[0] = 7;
  return hash;
})();

/** A node's passing result for a simulated group of count transactions. */
export function passingGroupResult(count: number): { txnResults: unknown[] } {
  return { txnResults: Array.from({ length: count }, () => ({ txnResult: {} })) };
}

/** A fake node for send tests. */
export class FakeAlgod {
  /** The node's current round. */
  round = 10n;
  /** Answers a submission; unset, it accepts the group and reports its first transaction's ID. */
  submit?: (blob: Uint8Array) => unknown;
  /** Answers the pending-transaction lookup; unset, it confirms in round 12. */
  pending?: () => { poolError?: string; confirmedRound?: bigint };
  /** The chain's auth address per account. */
  authAddrs: Record<string, string> = {};
  /**
   * Answers a simulation; unset, it reports success, with one transaction
   * result per transaction simulated.
   */
  simulate?: (request: algosdk.modelsv2.SimulateRequest) => unknown;
  /** Answers an account lookup in place of the default. */
  account?: (address: string) => unknown;

  submitted: Uint8Array[] = [];
  simulated: algosdk.modelsv2.SimulateRequest[] = [];
  lookups = 0;
  /** The rounds each wait-for-block call asked to follow. */
  waits: string[] = [];

  status() {
    return { do: async () => ({ lastRound: this.round }) };
  }

  statusAfterBlock(round: number | bigint) {
    return {
      do: async () => {
        this.waits.push(String(round));
        return { lastRound: this.round };
      },
    };
  }

  getTransactionParams() {
    return {
      do: async () => ({
        fee: 0n,
        minFee: 1000n,
        flatFee: false,
        firstValid: this.round,
        lastValid: this.round + 1000n,
        genesisID: "testnet-v1.0",
        genesisHash: testGenesisHash,
      }),
    };
  }

  accountInformation(address: string) {
    return {
      do: async () => {
        if (this.account) return this.account(address);
        const info: Record<string, unknown> = { address, amount: 5_000_000n, minBalance: 100_000n };
        if (this.authAddrs[address]) info.authAddr = this.authAddrs[address];
        return info;
      },
    };
  }

  sendRawTransaction(blob: Uint8Array) {
    return {
      do: async () => {
        this.submitted.push(blob);
        if (this.submit) return this.submit(blob);
        return { txid: firstSignedTransaction(blob).txn.txID() };
      },
    };
  }

  pendingTransactionInformation(_txid: string) {
    return {
      do: async () => {
        this.lookups++;
        const info = this.pending ? this.pending() : { confirmedRound: 12n };
        return { poolError: "", ...info };
      },
    };
  }

  simulateTransactions(request: algosdk.modelsv2.SimulateRequest) {
    return {
      do: async () => {
        this.simulated.push(request);
        if (this.simulate) return this.simulate(request);
        return { lastRound: this.round, version: 2, txnGroups: [passingGroupResult(request.txnGroups[0].txns.length)] };
      },
    };
  }
}

export function signedHexOf(signed: algosdk.SignedTransaction): string {
  return bytesToHex(algosdk.encodeMsgpack(signed));
}

export function decodeSignedHex(hex: string): algosdk.SignedTransaction {
  return algosdk.decodeSignedTransaction(hexToBytes(hex));
}

/** Concatenated hex of a submission, for comparing with a signed group. */
export function blobHex(blob: Uint8Array): string {
  return bytesToHex(blob);
}

export function transactionHex(txn: Transaction): string {
  return bytesToHex(txn.toByte());
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * The other spellings of an address: the same 288 bits with the unused low
 * two bits of the last base32 character set otherwise. algosdk reads them as
 * the address; the Go SDK refuses them.
 */
export function alternateSpellings(address: string): string[] {
  const last = BASE32.indexOf(address[address.length - 1]);
  const spellings: string[] = [];
  for (let low = 0; low < 4; low++) {
    const value = (last & ~3) | low;
    if (value !== last) spellings.push(address.slice(0, -1) + BASE32[value]);
  }
  return spellings;
}

/**
 * Make target[method] throw a TypeError, a fault in the SDK and not a
 * refusal, on the first call after skip further calls once it is armed.
 * restore puts the method back.
 */
export function faultOnce(target: any, method: string, skip = 0) {
  const original = target[method];
  let armed = false;
  let left = skip;
  let fired = false;
  target[method] = function (this: unknown, ...args: unknown[]) {
    if (armed) {
      if (left > 0) {
        left--;
      } else {
        armed = false;
        fired = true;
        throw new TypeError(`injected fault in ${method}`);
      }
    }
    return original.apply(this, args);
  };
  return {
    arm: () => {
      armed = true;
    },
    fired: () => fired,
    restore: () => {
      target[method] = original;
    },
  };
}
