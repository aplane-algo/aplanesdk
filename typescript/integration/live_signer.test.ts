// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import YAML from "yaml";
import algosdk from "algosdk";
import { SignerClient } from "../src/client.js";
import { createApsignerAccount } from "../src/algokit.js";
import { encodeTransaction, hexToBytes } from "../src/encoding.js";

function integrationEnabled(): boolean {
  return process.env.APLANE_SDK_INTEGRATION === "1";
}

async function liveSignerClient(): Promise<{ client: SignerClient; keyType: string }> {
  const token = liveSignerToken();
  const keyType = process.env.APLANE_SDK_KEY_TYPE || "ed25519";

  const sshHost = (process.env.APLANE_SDK_SSH_HOST || "").trim();
  if (sshHost) {
    const client = await SignerClient.connectSsh(
      sshHost,
      token,
      requiredSshEnv("APLANE_SDK_SSH_KEY_PATH"),
      {
        sshPort: requiredSshPort("APLANE_SDK_SSH_PORT"),
        signerPort: requiredSshPort("APLANE_SDK_SIGNER_PORT"),
        knownHostsPath: requiredSshEnv("APLANE_SDK_KNOWN_HOSTS_PATH"),
      }
    );
    return { client, keyType };
  }

  let baseUrl = (process.env.APLANE_SDK_SIGNER_URL || "").replace(/\/+$/, "");
  if (!baseUrl) {
    baseUrl = `http://127.0.0.1:${liveSignerPort()}`;
  }
  return { client: new SignerClient(baseUrl, token), keyType };
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

function liveSignerToken(): string {
  const inlineToken = (process.env.APLANE_SDK_TOKEN || "").trim();
  if (inlineToken) {
    return inlineToken;
  }

  const candidates = [process.env.APLANE_SDK_TOKEN_FILE || ""];
  if (process.env.APCLIENT_DATA) {
    candidates.push(path.join(process.env.APCLIENT_DATA, "aplane.token"));
  }
  if (process.env.APSIGNER_DATA) {
    candidates.push(
      path.join(process.env.APSIGNER_DATA, "identities", "default", "aplane.token")
    );
  }

  for (const candidate of candidates) {
    if (!candidate || !fs.existsSync(candidate)) {
      continue;
    }
    const token = fs.readFileSync(candidate, "utf-8").trim();
    if (token) {
      return token;
    }
  }

  throw new Error(
    "APLANE_SDK_TOKEN, APLANE_SDK_TOKEN_FILE, APCLIENT_DATA, or APSIGNER_DATA must provide a token"
  );
}

test(
  "integration: live signer client workflow",
  { skip: integrationEnabled() ? false : "set APLANE_SDK_INTEGRATION=1" },
  async () => {
    const { client, keyType } = await liveSignerClient();
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

      if (keyType === "ed25519") {
        const account = createApsignerAccount({
          client,
          address,
          authAddress: address,
          encodeTransaction: (txn) => {
            const [txnBytesHex] = encodeTransaction(txn as algosdk.Transaction);
            return hexToBytes(txnBytesHex);
          },
        });
        const signedBlobs = await account.signer([selfPaymentTxn(address)], [0]);
        assert.equal(signedBlobs.length, 1);
        assert.ok(algosdk.decodeSignedTransaction(signedBlobs[0]));
      }

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

function selfPaymentTxn(address: string): algosdk.Transaction {
  return algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: address,
    receiver: address,
    amount: 0,
    suggestedParams: {
      fee: 1000,
      firstValid: 1,
      lastValid: 1000,
      genesisHash: Buffer.from("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=", "base64"),
      genesisID: "testnet-v1.0",
      flatFee: true,
    },
  });
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
