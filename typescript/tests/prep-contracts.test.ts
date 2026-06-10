// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import algosdk from "algosdk";
import { preparedGroupToSignRequests } from "../src/prepared.js";
import type { PreparedGroup, SignRequest } from "../src/types.js";

interface PrepParityCase {
  name: string;
  expected_requests: SignRequest[];
}

interface PrepParityFixture {
  addresses: Record<string, string>;
  cases: PrepParityCase[];
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(__dirname, "../../contracts/prep/sign_request_shapes.json");
const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf-8")) as PrepParityFixture;

function bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function suggestedParams(): any {
  return {
    fee: 1000n,
    minFee: 1000n,
    firstValid: 100n,
    lastValid: 200n,
    genesisHash: new Uint8Array(32).fill(9),
    genesisID: "testnet-v1",
    flatFee: true,
  };
}

function buildGroups(addresses: Record<string, string>): Record<string, PreparedGroup> {
  const sender = addresses.sender;
  const receiver = addresses.receiver;
  const auth = addresses.auth;
  const closeTo = addresses.close_to;
  const rekeyTo = addresses.rekey_to;
  const foreign = addresses.foreign;
  const appAccount = addresses.app_account;
  const passthrough = Buffer.from("82a3736967c440", "hex").toString("base64");

  const payment = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender,
    receiver,
    amount: 12345n,
    note: bytes("pay"),
    suggestedParams: suggestedParams(),
  });
  const asa = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
    sender,
    receiver,
    amount: 5n,
    assetIndex: 1001n,
    note: bytes("asa"),
    suggestedParams: suggestedParams(),
  });
  const optIn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
    sender,
    receiver: sender,
    amount: 0n,
    assetIndex: 1001n,
    note: bytes("optin"),
    suggestedParams: suggestedParams(),
  });
  const optOut = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
    sender,
    receiver: sender,
    amount: 0n,
    assetIndex: 1001n,
    closeRemainderTo: closeTo,
    note: bytes("optout"),
    suggestedParams: suggestedParams(),
  });
  const close = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender,
    receiver: closeTo,
    amount: 0n,
    closeRemainderTo: closeTo,
    note: bytes("close"),
    suggestedParams: suggestedParams(),
  });
  const rekey = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender,
    receiver: sender,
    amount: 0n,
    rekeyTo,
    note: bytes("rekey"),
    suggestedParams: suggestedParams(),
  });
  const keyreg = algosdk.makeKeyRegistrationTxnWithSuggestedParamsFromObject({
    sender,
    nonParticipation: true,
    note: bytes("keyreg"),
    suggestedParams: suggestedParams(),
  });
  const rawApp = algosdk.makeApplicationCallTxnFromObject({
    sender,
    appIndex: 7n,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [bytes("raw")],
    accounts: [appAccount],
    foreignApps: [8n],
    foreignAssets: [1001n],
    note: bytes("rawapp"),
    suggestedParams: suggestedParams(),
  });
  const abiApp = algosdk.makeApplicationCallTxnFromObject({
    sender,
    appIndex: 7n,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [new Uint8Array([0x01, 0x02, 0x03, 0x04]), new Uint8Array([0, 0, 0, 0, 0, 0, 0, 42])],
    accounts: [appAccount],
    foreignApps: [8n],
    foreignAssets: [1001n],
    note: bytes("abiapp"),
    suggestedParams: suggestedParams(),
  });
  const appDeploy = algosdk.makeApplicationCreateTxnFromObject({
    sender,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    approvalProgram: new Uint8Array([0x01, 0x20, 0x01, 0x01, 0x22]),
    clearProgram: new Uint8Array([0x01, 0x20, 0x01, 0x01, 0x22]),
    numLocalInts: 0n,
    numLocalByteSlices: 1n,
    numGlobalInts: 1n,
    numGlobalByteSlices: 0n,
    extraPages: 1n,
    appArgs: [bytes("init")],
    note: bytes("deploy"),
    suggestedParams: suggestedParams(),
  });
  const foreignPayment = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: foreign,
    receiver,
    amount: 500n,
    note: bytes("foreign"),
    suggestedParams: suggestedParams(),
  });
  const secondPayment = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender,
    receiver: closeTo,
    amount: 6789n,
    note: bytes("pay2"),
    suggestedParams: suggestedParams(),
  });

  const signed = (transaction: any, extra: Partial<PreparedGroup["transactions"][number]> = {}) => ({
    transaction,
    authAddress: auth,
    ...extra,
  });
  const foreignSlot = (transaction: any) => ({ transaction, lsigSize: 3035 });
  const passthroughSlot = { signedTransactionBase64: passthrough };

  return {
    payment_sign_mode_lsig_args: {
      transactions: [signed(payment, {
        lsigArgs: {
          preimage: bytes("secret"),
          recipient: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
        },
      })],
    },
    asa_transfer: { transactions: [signed(asa)] },
    asa_opt_in: { transactions: [signed(optIn)] },
    asa_opt_out: { transactions: [signed(optOut)] },
    account_close: { transactions: [signed(close)] },
    rekey: { transactions: [signed(rekey)] },
    keyreg_nonparticipation: { transactions: [signed(keyreg)] },
    raw_app_call_info: {
      transactions: [signed(rawApp, { appCallInfo: { mode: "raw" } })],
    },
    abi_app_call_info: {
      transactions: [signed(abiApp, { appCallInfo: { mode: "abi", method: "do(uint64)void" } })],
    },
    app_deploy: {
      transactions: [signed(appDeploy, { appCallInfo: { mode: "raw" } })],
    },
    payment_plus_app_group: {
      transactions: [signed(payment), signed(rawApp, { appCallInfo: { mode: "raw" } })],
    },
    grouped_payments: {
      transactions: [signed(payment), signed(secondPayment)],
    },
    foreign_lsig_context: {
      transactions: [foreignSlot(foreignPayment)],
    },
    passthrough_signed_slot: {
      transactions: [passthroughSlot],
    },
    mixed_sign_foreign_passthrough: {
      transactions: [signed(payment), foreignSlot(foreignPayment), passthroughSlot],
    },
  };
}

describe("prepared sign request parity fixtures", () => {
  const groups = buildGroups(fixture.addresses);

  for (const testCase of fixture.cases) {
    it(testCase.name, () => {
      const group = groups[testCase.name];
      assert.ok(group, `missing builder for ${testCase.name}`);
      assert.deepEqual(preparedGroupToSignRequests(group), testCase.expected_requests);
    });
  }
});
