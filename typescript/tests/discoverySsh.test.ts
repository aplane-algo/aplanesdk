// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

// Cosigner discovery over real SSH: a client made with fromEnv finds its
// cosigner in endpoints.yaml, connects to it as it connects to its signer,
// and an endpoint's host key decides whether discovery runs at all. Each node
// is an ssh2 server forwarding to an HTTP stand-in for the signer.

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as http from "http";
import * as net from "net";
import * as os from "os";
import * as path from "path";
import { generateKeyPairSync } from "crypto";
import ssh2 from "ssh2";
import { SignerClient } from "../src/client.js";
import { EndpointCosignerResolver } from "../src/discovery.js";
import { CosignerDiscoveryError, errorText } from "../src/errors.js";
import { witnessKeyId } from "../src/witness.js";
import { KEY_TYPE_WITNESS_FALCON1024 } from "../src/types.js";
import { hexToBytes } from "../src/encoding.js";
import { fakeAddress } from "./fakeSigner.js";
import { FakeAlgod, type FakeHandler } from "./fakeNetwork.js";
import { CosignedUser, CosignerEndpoint, cosignedKey, cosignedPayment, group, witnessRecord } from "./fakeCosigned.js";

const { Server, utils: sshUtils } = ssh2;
const WITNESS = "a1".repeat(32);

function rsaPem(): string {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
  }).privateKey;
}

/** The SSH wire form of a private key's public half, as known_hosts pins it. */
function publicBlob(pem: string): Buffer {
  const parsed = sshUtils.parseKey(pem);
  if (parsed instanceof Error) throw parsed;
  const key = Array.isArray(parsed) ? parsed[0] : parsed;
  return key.getPublicSSH();
}

/** A node: an SSH server whose forwarded channels reach an HTTP handler. */
interface SshNode {
  port: number;
  hostKey: string;
  /** SSH sessions that are open. */
  sessions: () => number;
  close: () => Promise<void>;
}

async function startNode(handler: FakeHandler): Promise<SshNode> {
  const httpServer = http.createServer((request, response) => {
    let raw = "";
    request.on("data", (chunk) => {
      raw += chunk;
    });
    request.on("end", async () => {
      const reply = await handler(new URL(request.url ?? "/", "http://node").pathname, raw ? JSON.parse(raw) : undefined);
      if (reply === "drop") {
        request.socket.destroy();
        return;
      }
      response.writeHead(reply.status ?? 200, { "Content-Type": "application/json" });
      response.end("raw" in reply ? reply.raw : JSON.stringify(reply.body));
    });
  });
  await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const httpPort = (httpServer.address() as net.AddressInfo).port;

  const hostKey = rsaPem();
  let open = 0;
  const sockets = new Set<net.Socket>();
  const sshServer = new Server({ hostKeys: [hostKey] }, (client) => {
    open++;
    client.on("close", () => {
      open--;
    });
    client.on("error", () => undefined);
    client.on("authentication", (context) => {
      if (context.method === "publickey") context.accept();
      else context.reject(["publickey"]);
    });
    client.on("ready", () => {
      client.on("tcpip", (accept) => {
        const stream = accept();
        const socket = net.connect(httpPort, "127.0.0.1");
        sockets.add(socket);
        socket.on("close", () => sockets.delete(socket));
        socket.on("error", () => stream.destroy());
        stream.on("error", () => socket.destroy());
        stream.pipe(socket).pipe(stream);
      });
    });
  });
  await new Promise<void>((resolve) => sshServer.listen(0, "127.0.0.1", resolve));
  const port = (sshServer.address() as net.AddressInfo).port;
  return {
    port,
    hostKey,
    sessions: () => open,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => sshServer.close(() => resolve()));
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    },
  };
}

/** A data directory with endpoints.yaml, an identity and known_hosts pins. */
function dataDir(
  endpoints: Array<{ alias: string; role: string; node: SshNode; pin?: string | null }>,
): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-discovery-"));
  fs.mkdirSync(path.join(dir, ".ssh"));
  fs.writeFileSync(path.join(dir, ".ssh", "id_rsa"), rsaPem(), { mode: 0o600 });
  const lines = ["schema_version: 2", "endpoints:"];
  const pins: string[] = [];
  for (const { alias, role, node, pin } of endpoints) {
    lines.push(`  ${alias}:`, `    role: ${role}`, `    url: ssh://127.0.0.1:${node.port}`, "    identity_file: .ssh/id_rsa");
    // null leaves the host unpinned; a string pins that key in its place.
    if (pin === null) continue;
    const blob = publicBlob(pin ?? node.hostKey);
    pins.push(`[127.0.0.1]:${node.port} ssh-rsa ${blob.toString("base64")}`);
  }
  fs.writeFileSync(path.join(dir, "endpoints.yaml"), `${lines.join("\n")}\n`);
  fs.writeFileSync(path.join(dir, ".ssh", "known_hosts"), `${pins.join("\n")}\n`, { mode: 0o600 });
  return dir;
}

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()?.();
});

async function waitFor(condition: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (!condition()) {
    if (Date.now() > deadline) assert.fail(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

describe("cosigner discovery over SSH", () => {
  const account = fakeAddress(21);

  async function nodes(cosignerKeys = [witnessRecord(WITNESS)]) {
    const user = new CosignedUser([cosignedKey(account, WITNESS)]);
    const cosigner = new CosignerEndpoint("alpha", cosignerKeys);
    const userNode = await startNode(user.handle);
    const cosignerNode = await startNode(cosigner.handle);
    cleanups.push(() => userNode.close(), () => cosignerNode.close());
    return { user, cosigner, userNode, cosignerNode };
  }

  it("a client from fromEnv finds its cosigner, and closes the connection with itself", async () => {
    const { user, cosigner, userNode, cosignerNode } = await nodes();
    const dir = dataDir([
      { alias: "primary", role: "signer", node: userNode },
      { alias: "alpha", role: "cosigner", node: cosignerNode },
    ]);
    cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
    const client = await SignerClient.fromEnv({ dataDir: dir });
    try {
      const result = await client.sendPrepared(new FakeAlgod() as any, group(cosignedPayment(account)));
      assert.equal(result.outcome, "confirmed", "the cosigned group was not sent");
      assert.equal(cosigner.count("/keys"), 1, "the cosigner's keys were not read once");
      assert.equal(cosigner.componentRequests.length, 1, "the cosigner was not asked to sign");
      assert.equal(
        cosigner.componentRequests[0].targets[0].component_key,
        witnessKeyId(KEY_TYPE_WITNESS_FALCON1024, hexToBytes(WITNESS)),
        "the cosigner was asked under another component key",
      );
      assert.ok(user.paths.includes("/sign/assemble"), "the group was not assembled");
      assert.equal(cosignerNode.sessions(), 1, "the cosigner connection is not held");
    } finally {
      await client.close();
    }
    await waitFor(() => cosignerNode.sessions() === 0, "the cosigner connection to close");
  });

  it("aborts on a cosigner whose host key differs from the pinned one", async () => {
    const { userNode, cosignerNode } = await nodes();
    const other = await startNode(new CosignerEndpoint("beta", []).handle);
    cleanups.push(() => other.close());
    const dir = dataDir([
      { alias: "primary", role: "signer", node: userNode },
      { alias: "alpha", role: "cosigner", node: cosignerNode },
      { alias: "beta", role: "cosigner", node: other, pin: rsaPem() },
    ]);
    cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
    const resolver = EndpointCosignerResolver.fromDataDir(dir);
    cleanups.push(() => resolver.close());
    const knownHosts = path.join(dir, ".ssh", "known_hosts");
    await assert.rejects(
      resolver.resolve({
        targetIndex: 0,
        cosignedAccount: account,
        cosignerPublicKeyHex: WITNESS,
        cosignerComponentKeyType: KEY_TYPE_WITNESS_FALCON1024,
        logicSigResources: { programBytes: 1, argumentBytes: 1, maxOpcodeCost: 1 },
      }),
      (error: unknown) => {
        assert.ok(error instanceof CosignerDiscoveryError, `error is ${String(error)}`);
        assert.equal(
          errorText(error),
          `cosigner discovery: endpoint "beta": SSH host key mismatch for [127.0.0.1]:${other.port} ` +
            `(possible MITM attack); remove the old key from ${knownHosts} to connect`,
          "mismatch text",
        );
        return true;
      },
    );
    await waitFor(() => cosignerNode.sessions() === 0, "alpha's connection to close after the abort");
  });

  it("reports an unpinned cosigner as configuration invalid", async () => {
    const { userNode, cosignerNode } = await nodes([]);
    const dir = dataDir([
      { alias: "primary", role: "signer", node: userNode },
      { alias: "alpha", role: "cosigner", node: cosignerNode, pin: null },
    ]);
    cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
    const resolver = EndpointCosignerResolver.fromDataDir(dir);
    cleanups.push(() => resolver.close());
    const id = witnessKeyId(KEY_TYPE_WITNESS_FALCON1024, hexToBytes(WITNESS));
    await assert.rejects(
      resolver.resolve({
        targetIndex: 0,
        cosignedAccount: account,
        cosignerPublicKeyHex: WITNESS,
        cosignerComponentKeyType: KEY_TYPE_WITNESS_FALCON1024,
        logicSigResources: { programBytes: 1, argumentBytes: 1, maxOpcodeCost: 1 },
      }),
      (error: unknown) => {
        assert.ok(error instanceof CosignerDiscoveryError, `error is ${String(error)}`);
        assert.equal(
          errorText(error),
          `cosigner discovery: no endpoint lists Witness Key ID ${id} (${KEY_TYPE_WITNESS_FALCON1024}); ` +
            'endpoints: "alpha" configuration invalid',
          "discovery text",
        );
        return true;
      },
    );
  });
});
