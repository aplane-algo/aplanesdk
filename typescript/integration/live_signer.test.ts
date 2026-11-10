// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import YAML from "yaml";
import algosdk from "algosdk";
import { SignerClient } from "../src/client.js";

function integrationEnabled(): boolean {
  return process.env.APLANE_SDK_INTEGRATION === "1";
}

async function liveSignerClient(): Promise<SignerClient> {
  const sshHost = (process.env.APLANE_SDK_SSH_HOST || "").trim();
  if (sshHost) {
    const client = await SignerClient.connectSsh(
      sshHost,
      requiredSshEnv("APLANE_SDK_SSH_KEY_PATH"),
      {
        sshPort: requiredSshPort("APLANE_SDK_SSH_PORT"),
        knownHostsPath: requiredSshEnv("APLANE_SDK_KNOWN_HOSTS_PATH"),
      }
    );
    return client;
  }

  let baseUrl = (process.env.APLANE_SDK_SIGNER_URL || "").replace(/\/+$/, "");
  if (!baseUrl) {
    baseUrl = `http://127.0.0.1:${liveSignerPort()}`;
  }
  // A base URL names a caller-owned tunnel; the loopback REST port of a
  // signer answers only /health.
  return new SignerClient(baseUrl);
}

function requiredSshEnv(name: string): string {
  const value = (process.env[name] || "").trim();
  if (!value) {
    throw new Error(`${name} must be set when APLANE_SDK_SSH_HOST is set`);
  }
  return value;
}

function requiredSshPort(name: string): number {
  const value = requiredSshEnv(name);
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${name} must be a valid TCP port, got ${JSON.stringify(value)}`);
  }
  return port;
}

function liveSignerPort(): number {
  const dataDir = process.env.APSIGNER_DATA;
  if (!dataDir) {
    throw new Error("APLANE_SDK_SIGNER_URL or APSIGNER_DATA must be set");
  }

  const config = YAML.parse(
    fs.readFileSync(path.join(dataDir, "config.yaml"), "utf-8")
  ) as { endpoint?: { signer_port?: number } };
  if (!config.endpoint?.signer_port) {
    throw new Error("endpoint.signer_port not set in signer config");
  }
  return config.endpoint.signer_port;
}

test(
  "integration: live signer Ed25519 workflow",
  { skip: integrationEnabled() ? false : "set APLANE_SDK_INTEGRATION=1" },
  async () => {
    const keyType = "ed25519";
    const client = await liveSignerClient();
    let address = "";
    let cleanup = false;

    try {
      assert.equal(await client.health(), true);

      const before = await client.getStatus();
      assert.equal(before.readyForSigning, true);
      assert.equal(before.signerLocked, false);

      const keyTypes = await client.listKeyTypes();
      assert.ok(keyTypes.some((item) => item.keyType === keyType));

      const generated = await client.generateKey(keyType, {});
      address = generated.address;
      cleanup = true;
      assert.ok(address);

      const afterGenerate = await waitForKeysetRevision(client, before.keysetRevision, "generate");

      const keys = await client.listKeys(true);
      assert.ok(keys.some((key) => key.address === address));

      const signed = await client.signTransaction(selfPaymentTxn(address), address);
      assert.ok(Buffer.from(signed, "base64").length > 0);

      await client.deleteKey(address);
      cleanup = false;

      await waitForKeysetRevision(client, afterGenerate.keysetRevision, "delete");

      const refreshed = await client.listKeys(true);
      assert.ok(refreshed.every((key) => key.address !== address));
    } finally {
      if (cleanup && address) {
        try {
          await client.deleteKey(address);
        } catch {
          // Best-effort cleanup; the primary failure above should remain visible.
        }
      }
      await client.close();
    }
  }
);

test(
  "integration: live signer native Falcon signing",
  { skip: integrationEnabled() ? false : "set APLANE_SDK_INTEGRATION=1" },
  async () => {
    const keyType = "falcon1024";
    const client = await liveSignerClient();
    let address = "";
    let cleanup = false;

    try {
      const keyTypes = await client.listKeyTypes();
      assert.ok(keyTypes.some((item) => item.keyType === keyType));

      const before = await client.getStatus();
      const generated = await client.generateKey(keyType, {});
      address = generated.address;
      cleanup = true;
      assert.ok(address);

      const afterGenerate = await waitForKeysetRevision(
        client,
        before.keysetRevision,
        "native Falcon generate"
      );
      const signed = await client.signTransaction(selfPaymentTxn(address), address);
      assertNativeFalconEnvelope(Buffer.from(signed, "base64"));

      await client.deleteKey(address);
      cleanup = false;
      await waitForKeysetRevision(
        client,
        afterGenerate.keysetRevision,
        "native Falcon delete"
      );
    } finally {
      if (cleanup && address) {
        try {
          await client.deleteKey(address);
        } catch {
          // Best-effort cleanup; the primary failure above should remain visible.
        }
      }
      await client.close();
    }
  }
);

test(
  "integration: live signer LogicSig account signing",
  { skip: integrationEnabled() ? false : "set APLANE_SDK_INTEGRATION=1" },
  async (t) => {
    // A LogicSig account's real response passes the SDK's checks. The signer
    // raises the fee, appends resource dummies and groups them, and signs
    // with the account's program; the SDK verifies all of that, so this is
    // the live check that its rules accept what the signer really returns.
    const keyType = "aplane.falcon1024.v1";
    const client = await liveSignerClient();
    let address = "";

    try {
      const keyTypes = await client.listKeyTypes();
      if (!keyTypes.some((item) => item.keyType === keyType)) {
        t.skip(`the signer does not offer ${keyType}`);
        return;
      }
      const before = await client.getStatus();
      address = (await client.generateKey(keyType, { rekey_authority: "spending_key" })).address;
      assert.ok(address);
      await waitForKeysetRevision(client, before.keysetRevision, "LogicSig generate");

      const single = await client.signTransactionsList([selfPaymentTxn(address)], [address]);
      assert.ok(single.length > 1, "a Falcon LogicSig account needs resource dummies");
      const first = algosdk.decodeObj(Buffer.from(single[0], "base64")) as {
        lsig?: { l?: Uint8Array };
      };
      assert.ok(first.lsig?.l?.length, "the position is not signed by a LogicSig");

      const pair = await client.signTransactionsList(
        [selfPaymentTxn(address), selfPaymentTxn(address, "second")],
        [address, address]
      );
      assert.ok(pair.length > 2);
    } finally {
      if (address) {
        try {
          await client.deleteKey(address);
        } catch {
          // Best-effort cleanup; the primary failure above should remain visible.
        }
      }
      await client.close();
    }
  }
);

test(
  "integration: native Falcon signature verifies on LocalNet",
  {
    skip: !integrationEnabled()
      ? "set APLANE_SDK_INTEGRATION=1"
      : localnetAvailable()
        ? false
        : "needs a LocalNet algod and KMD (ALGOD_URL, APLANE_LOCALNET_KMD_URL)",
  },
  async () => {
    // The signing test above checks only the envelope's shape. Here the node
    // verifies the signature: simulation runs with empty signatures
    // disallowed, a tampered copy must fail, and the untouched transaction
    // must confirm.
    const algodClient = clientFromUrl(
      algosdk.Algodv2,
      process.env.ALGOD_TOKEN || "",
      process.env.ALGOD_URL || ""
    );
    const client = await liveSignerClient();
    let address = "";

    try {
      const before = await client.getStatus();
      address = (await client.generateKey("falcon1024", {})).address;
      assert.ok(address);
      await waitForKeysetRevision(client, before.keysetRevision, "native Falcon generate");
      await fundFromLocalnetKmd(algodClient, address, 500_000);

      const prepared = await client.preparePayment(algodClient, {
        sender: address,
        receiver: address,
        amount: 0,
      });
      const result = await client.simulatePreparedTransaction(algodClient, prepared);
      assert.equal(result.failed, false, result.response.txnGroups?.[0]?.failureMessage);
      assert.equal(result.signedGroup.length, 1);

      const signedBytes = Buffer.from(result.signedGroup[0], "hex");
      assertNativeFalconEnvelope(signedBytes);

      // Flip one byte of the signature in place, so nothing else in the
      // encoding changes.
      const envelope = algosdk.decodeObj(signedBytes) as { pqsig: { sig: Uint8Array } };
      const signatureAt = signedBytes.indexOf(Buffer.from(envelope.pqsig.sig));
      assert.ok(signatureAt >= 0);
      const tampered = Buffer.from(signedBytes);
      tampered[signatureAt + (envelope.pqsig.sig.length >> 1)] ^= 0x01;
      const rejection = await rawSimulationRejection(algodClient, tampered);
      assert.match(rejection, /signature/, "the node accepted a tampered native Falcon signature");

      const { txid } = await algodClient.sendRawTransaction(signedBytes).do();
      assert.equal(txid, result.txIds[0]);
      await algosdk.waitForConfirmation(algodClient, txid, 10);
    } finally {
      if (address) {
        try {
          await client.deleteKey(address);
        } catch {
          // Best-effort cleanup; the primary failure above should remain visible.
        }
      }
      await client.close();
    }
  }
);

test(
  "integration: endpoints.yaml connection",
  { skip: integrationEnabled() ? false : "set APLANE_SDK_INTEGRATION=1" },
  async (context) => {
    const dataDir = process.env.APCLIENT_DATA;
    if (!dataDir || !fs.existsSync(path.join(dataDir, "endpoints.yaml"))) {
      context.skip("APCLIENT_DATA/endpoints.yaml is not available");
      return;
    }
    const client = await SignerClient.fromEnv({ dataDir });
    try {
      assert.equal(await client.health(), true);
    } finally {
      await client.close();
    }
  },
);

function selfPaymentTxn(address: string, note = ""): algosdk.Transaction {
  const genesisHash =
    (process.env.APLANE_INTEGRATION_GENESIS_HASH || "").trim() ||
    "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=";
  const genesisID =
    (process.env.APLANE_INTEGRATION_GENESIS_ID || "").trim() || "testnet-v1.0";
  return algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: address,
    receiver: address,
    amount: 0,
    note: note ? new TextEncoder().encode(note) : undefined,
    suggestedParams: {
      fee: 1000,
      minFee: 1000,
      firstValid: 1,
      lastValid: 1000,
      genesisHash: Buffer.from(genesisHash, "base64"),
      genesisID,
      flatFee: true,
    },
  });
}

function localnetAvailable(): boolean {
  return Boolean(
    (process.env.ALGOD_URL || "").trim() &&
      (process.env.APLANE_LOCALNET_KMD_URL || "").trim()
  );
}

function clientFromUrl<T>(
  ctor: new (token: string, server: string, port: string) => T,
  token: string,
  rawUrl: string
): T {
  const url = new URL(rawUrl.trim());
  return new ctor(token, `${url.protocol}//${url.hostname}`, url.port);
}

/** Pay `receiver` from the richest account in the LocalNet KMD wallet. */
async function fundFromLocalnetKmd(
  algodClient: algosdk.Algodv2,
  receiver: string,
  amount: number
): Promise<void> {
  const kmd = clientFromUrl(
    algosdk.Kmd,
    process.env.APLANE_LOCALNET_TOKEN || "",
    process.env.APLANE_LOCALNET_KMD_URL || ""
  );
  const walletName = process.env.APLANE_LOCALNET_WALLET || "unencrypted-default-wallet";
  const password = process.env.APLANE_LOCALNET_WALLET_PASSWORD || "";
  const wallets: { id: string; name: string }[] = (await kmd.listWallets()).wallets;
  const wallet = wallets.find((item) => item.name === walletName);
  assert.ok(wallet, `LocalNet KMD has no wallet named ${JSON.stringify(walletName)}`);
  const handle: string = (await kmd.initWalletHandle(wallet.id, password)).wallet_handle_token;
  let signed: Uint8Array;
  try {
    const addresses: string[] = (await kmd.listKeys(handle)).addresses;
    let funder = "";
    let richest = -1n;
    for (const candidate of addresses) {
      const { amount: balance } = await algodClient.accountInformation(candidate).do();
      if (balance > richest) {
        richest = balance;
        funder = candidate;
      }
    }
    assert.ok(funder, "LocalNet KMD wallet has no accounts");
    const payment = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: funder,
      receiver,
      amount,
      suggestedParams: await algodClient.getTransactionParams().do(),
    });
    signed = await kmd.signTransaction(handle, password, payment);
  } finally {
    await kmd.releaseWalletHandle(handle);
  }
  const { txid } = await algodClient.sendRawTransaction(signed).do();
  await algosdk.waitForConfirmation(algodClient, txid, 10);
}

/** Why the node refuses these signed bytes; empty when it accepts them. */
async function rawSimulationRejection(
  algodClient: algosdk.Algodv2,
  signedBytes: Uint8Array
): Promise<string> {
  try {
    const response = await algodClient.simulateRawTransactions(signedBytes).do();
    return response.txnGroups?.[0]?.failureMessage ?? "";
  } catch (error) {
    return (error instanceof Error ? error.message : String(error)) || "rejected";
  }
}

function assertNativeFalconEnvelope(blob: Uint8Array): void {
  const envelope = algosdk.decodeObj(blob) as {
    pqsig?: { sch?: Uint8Array; pk?: Uint8Array; sig?: Uint8Array };
  };
  assert.ok(envelope.pqsig);
  assert.deepEqual(Buffer.from(envelope.pqsig.sch || []), Buffer.from("f1"));
  assert.ok(envelope.pqsig.pk?.length);
  assert.ok(envelope.pqsig.sig?.length);
}

async function waitForKeysetRevision(
  client: SignerClient,
  previous: number,
  action: string
) {
  const deadline = Date.now() + 5000;
  let last: Awaited<ReturnType<SignerClient["getStatus"]>> | undefined;
  let lastError: unknown;

  while (Date.now() < deadline) {
    try {
      last = await client.getStatus();
      if (last.keysetRevision > previous) {
        return last;
      }
    } catch (err) {
      lastError = err;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  if (lastError) {
    throw new Error(`get identity after ${action}: ${String(lastError)}`);
  }
  if (!last) {
    throw new Error(`identity was unavailable after ${action}`);
  }
  throw new Error(
    `keyset revision did not advance after ${action}: before=${previous} after=${last.keysetRevision}`
  );
}
