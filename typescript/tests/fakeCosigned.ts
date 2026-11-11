// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * Fakes for cosigned sends: a cosigner endpoint that lists witness keys and
 * signs components, and a user signer holding cosigned accounts.
 */

import algosdk, { type Transaction } from "algosdk";
import { witnessKeyId } from "../src/witness.js";
import { KEY_TYPE_WITNESS_FALCON1024, SIGNING_FLOW_COSIGNED1, type PreparedGroup } from "../src/types.js";
import { hexToBytes } from "../src/encoding.js";
import { fakeAddress, planResponse } from "./fakeSigner.js";
import { signedHexOf, statusBody, type FakeHandler, type FakeReply, type WireKey } from "./fakeNetwork.js";

/** A /keys record of a witness key, as a cosigner lists it. */
export function witnessRecord(publicKeyHex: string, keyType = KEY_TYPE_WITNESS_FALCON1024): WireKey {
  return {
    address: witnessKeyId(keyType, hexToBytes(publicKeyHex.toLowerCase())),
    public_key_hex: publicKeyHex,
    key_type: keyType,
    is_witness_key: true,
    is_spending_account: false,
  };
}

/** A fake cosigner endpoint: what its /keys lists, and its component signatures. */
export class CosignerEndpoint {
  alias: string;
  keys: WireKey[];
  /** Answers /keys in place of the listing. */
  keysReply?: () => FakeReply;
  paths: string[] = [];
  componentRequests: any[] = [];

  constructor(alias: string, keys: WireKey[]) {
    this.alias = alias;
    this.keys = keys;
  }

  count(path: string): number {
    return this.paths.filter((entry) => entry === path).length;
  }

  handle: FakeHandler = (path, body) => {
    if (path === "/health") return { body: { status: "healthy" } };
    this.paths.push(path);
    switch (path) {
      case "/keys":
        return this.keysReply ? this.keysReply() : { body: { count: this.keys.length, keys: this.keys } };
      case "/sign/component":
        this.componentRequests.push(body);
        return {
          body: {
            request_id: body.request_id,
            components: body.targets.map((target: any) => ({
              kind: "cosigner",
              target_index: target.target_index,
              signature: `cosigner-sig-${this.alias}`,
              signature_scheme: KEY_TYPE_WITNESS_FALCON1024,
            })),
          },
        };
      default:
        throw new Error(`unexpected cosigner path ${path}`);
    }
  };
}

/** A cosigned account's /keys record, whose cosigner holds witnessHex. */
export function cosignedKey(address: string, witnessHex: string, rekeyList = false): WireKey {
  const usage = { program_bytes: 5308, argument_bytes: 3358, max_opcode_cost: 20000 };
  const key: any = {
    address,
    key_type: "aplane.falcon1024.v1",
    signing_flow: SIGNING_FLOW_COSIGNED1,
    logic_sig_resources: { spend: usage, spending_rekey: usage, listed_rekey: usage },
    cosigner_component_key_type: KEY_TYPE_WITNESS_FALCON1024,
    bounded_authorization: {
      contract: "bounded2",
      max_fee: 1000,
      rekey: "spending_key",
      cosigner: { component_key_type: KEY_TYPE_WITNESS_FALCON1024, public_key_hex: witnessHex },
    },
  };
  if (rekeyList) {
    key.bounded_authorization.rekey_list = { contract: "rekey_list1", depth: 4, root: "00".repeat(32) };
  }
  return key;
}

export function cosignedPayment(sender: string, rekeyTo?: string): Transaction {
  return algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender,
    receiver: fakeAddress(22),
    amount: 1000,
    rekeyTo,
    suggestedParams: {
      fee: 1000, flatFee: true, minFee: 1000, firstValid: 1, lastValid: 100,
      genesisID: "testnet-v1.0", genesisHash: new Uint8Array(32),
    },
  });
}

/** A user signer holding cosigned accounts; each base component names the path pathFor gives. */
export class CosignedUser {
  keys: WireKey[];
  paths: string[] = [];
  pathFor: (index: number) => string = () => "spend";
  /** Called as each request arrives. */
  onRequest?: (path: string) => void;

  constructor(keys: WireKey[]) {
    this.keys = keys;
  }

  approvalRequests(): string[] {
    return this.paths.filter((path) => path === "/sign/component" || path === "/sign" || path === "/sign/assemble");
  }

  handle: FakeHandler = (path, body) => {
    if (path === "/health") return { body: { status: "healthy" } };
    this.paths.push(path);
    this.onRequest?.(path);
    switch (path) {
      case "/status":
        return { body: statusBody() };
      case "/keys":
        return { body: { count: this.keys.length, keys: this.keys } };
      case "/plan":
        return { body: planResponse(body.requests) };
      case "/sign/component":
        return {
          body: {
            request_id: body.request_id,
            components: body.targets.map((item: any) => ({
              target_index: item.target_index,
              kind: "bounded-base",
              auth_address: item.auth_address,
              base_signatures: ["base-sig"],
              runtime_args: { proof: "aabb" },
              assembly_receipt: "receipt",
              signature_scheme: "aplane.falcon1024.v1",
              path: this.pathFor(item.target_index),
            })),
          },
        };
      case "/sign/assemble":
        return {
          body: {
            request_id: body.request_id,
            signed_group: (body.group_bytes_hex as string[]).map((txnHex) => {
              const txn = algosdk.decodeUnsignedTransaction(hexToBytes(txnHex).slice(2));
              const lsig = new algosdk.LogicSig(new Uint8Array([0x0a, 0x81, 0x01]), [new Uint8Array([1])]);
              return signedHexOf(new algosdk.SignedTransaction({ txn, lsig }));
            }),
          },
        };
      case "/sign/cancel":
        return { body: { state: "canceled" } };
      default:
        throw new Error(`unexpected user path ${path}`);
    }
  };
}

export function group(...txns: Transaction[]): PreparedGroup {
  return { transactions: txns.map((txn) => ({ transaction: txn, authAddress: txn.sender.toString() })) };
}
