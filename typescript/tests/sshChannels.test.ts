// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

// A client connected over SSH sends every request on a channel it opens
// itself on its SSH connection, and listens on no local port another process
// on the machine could use to send requests under the client's key.

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as net from "net";
import * as os from "os";
import * as path from "path";
import { Duplex } from "stream";
import { SignerClient } from "../src/client.js";
import { SignerUnavailableError } from "../src/errors.js";
import { ChannelAgent, SSH_SIGNER_HOST, agentFetch, sshHttpTiming } from "../src/sshhttp.js";
import { statusBody, type FakeHandler } from "./fakeNetwork.js";
import { publicBlob, rsaPem, startNode, type SshNode } from "./fakeSshNode.js";

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()?.();
});

const answer: FakeHandler = (requestPath) => {
  if (requestPath === "/health") return { body: { status: "ok" } };
  if (requestPath === "/status") return { body: statusBody() };
  return { status: 404, body: { error: "not found" } };
};

async function node(handler: FakeHandler = answer): Promise<SshNode> {
  const started = await startNode(handler);
  cleanups.push(() => started.close());
  return started;
}

/** Connect to node with a fresh identity whose known_hosts pins the node. */
async function connect(target: SshNode, options: { timeout?: number } = {}): Promise<SignerClient> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-channels-"));
  cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  const keyPath = path.join(dir, "id_rsa");
  fs.writeFileSync(keyPath, rsaPem(), { mode: 0o600 });
  const knownHosts = path.join(dir, "known_hosts");
  fs.writeFileSync(
    knownHosts,
    `[127.0.0.1]:${target.port} ssh-rsa ${publicBlob(target.hostKey).toString("base64")}\n`,
    { mode: 0o600 },
  );
  const client = await SignerClient.connectSsh("127.0.0.1", keyPath, {
    sshPort: target.port,
    knownHostsPath: knownHosts,
    timeout: options.timeout,
  });
  cleanups.push(() => client.close());
  return client;
}

async function waitFor(condition: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (!condition()) {
    if (Date.now() > deadline) assert.fail(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/** Long enough for an answered request's connection to go back to the pool. */
function settle(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 50));
}

describe("a client connected over SSH", () => {
  it("opens no listening socket, and sends every request on a channel of its SSH connection", async () => {
    const target = await node();
    const listen = net.Server.prototype.listen;
    const listened: unknown[][] = [];
    net.Server.prototype.listen = function spy(this: net.Server, ...args: unknown[]) {
      listened.push(args);
      return (listen as (...a: unknown[]) => net.Server).apply(this, args);
    } as typeof listen;
    try {
      const client = await connect(target);
      const status = await client.getStatus();
      assert.equal(status.state, "unlocked", "the signer's status did not arrive");
      await client.close();
    } finally {
      net.Server.prototype.listen = listen;
    }
    assert.deepEqual(listened, [], "the client opened a listening socket");
    assert.deepEqual(
      target.requests.map((request) => request.path),
      ["/health", "/status"],
      "the signer did not receive the client's requests",
    );
    assert.ok(target.channels.length > 0, "no channel was opened");
    for (const channel of target.channels) {
      assert.equal(channel.destination, "127.0.0.1:11270", "a channel named another destination");
    }
    for (const request of target.requests) {
      assert.equal(request.host, SSH_SIGNER_HOST, "a request named another host");
    }
  });

  it("keeps a channel for the next request, and closes it once idle", async (t) => {
    const idleMs = sshHttpTiming.idleMs;
    t.after(() => {
      sshHttpTiming.idleMs = idleMs;
    });
    // The client's idle timeout closes before the signer's 120-second one.
    assert.ok(idleMs > 0 && idleMs < 120_000, `idle timeout ${idleMs} ms`);
    sshHttpTiming.idleMs = 300;

    const target = await node();
    const client = await connect(target);
    await settle();
    await client.getStatus();
    assert.equal(target.channels.length, 1, "the second request did not reuse the first one's channel");

    await waitFor(() => !target.channels[0].open, "the idle channel to close");
    await client.getStatus();
    assert.equal(target.channels.length, 2, "the request after the idle close did not open a new channel");
    assert.equal(target.sessions(), 1, "the requests did not share one SSH connection");
  });

  it("closing the client ends its SSH connection and channels, and a later request fails", async () => {
    const target = await node();
    const client = await connect(target);
    await client.getStatus();
    await client.close();
    await waitFor(() => target.sessions() === 0, "the SSH connection to close");
    await waitFor(() => target.channels.every((channel) => !channel.open), "the channels to close");

    const seen = target.requests.length;
    await assert.rejects(client.getStatus(), (error: unknown) => {
      assert.ok(error instanceof SignerUnavailableError, `error is ${String(error)}`);
      assert.match(error.message, /^Failed to connect: the SSH connection to the signer is closed/);
      return true;
    });
    assert.equal(target.requests.length, seen, "a request after close reached the signer");
  });

  it("a request's timeout, and the caller's abort, end it and close its channel", async () => {
    const target = await node((requestPath) =>
      requestPath === "/health" ? { body: { status: "ok" } } : new Promise(() => undefined),
    );
    const client = await connect(target, { timeout: 200 });
    await settle();

    await assert.rejects(client.getStatus(), (error: unknown) => {
      assert.ok(error instanceof SignerUnavailableError, `error is ${String(error)}`);
      assert.equal(error.message, "Request timed out after 200ms");
      return true;
    });
    // The timed-out request was sent on the channel /health was answered on.
    await waitFor(() => !target.channels[0].open, "the timed-out request's channel to close");
    const controller = new AbortController();
    const aborted = client.getStatus({ signal: controller.signal });
    await waitFor(() => target.requests.length === 3, "the second /status to arrive");
    controller.abort();
    await assert.rejects(aborted, (error: unknown) => {
      assert.ok(error instanceof SignerUnavailableError, `error is ${String(error)}`);
      assert.equal(error.message, "Request aborted by caller");
      return true;
    });
    await waitFor(() => target.channels.every((channel) => !channel.open), "the aborted request's channel to close");
    assert.equal(target.channels.length, 2, "the requests did not use the channels expected");
  });
});

/**
 * A channel that answers the first request it reads with answer, then ends
 * and closes at once, as one TCP read can deliver an answer and the node's
 * close of the channel together.
 */
class ClosingAnswerChannel extends Duplex {
  private request = "";
  constructor(private readonly answer: string) {
    super();
  }
  override _read(): void {}
  override _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.request += chunk.toString("latin1");
    callback();
    if (this.request.includes("\r\n\r\n")) {
      this.push(this.answer);
      this.push(null);
      this.destroy();
    }
  }
}

/**
 * A channel that behaves as ssh2's does when destroyed: destroy only ends
 * it, the node's close arrives as the end of its readable side, and close is
 * emitted only once that end has been read.
 */
class Ssh2LikeChannel extends Duplex {
  override _read(): void {}
  override _write(_chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    callback();
  }
  override destroy(): this {
    this.end();
    this.once("end", () => this.emit("close"));
    setImmediate(() => this.push(null));
    return this;
  }
}

describe("the SSH channel agent", () => {
  it("reads a complete answer whose channel closes right behind it", async () => {
    const body = JSON.stringify({ error: "Forbidden", code: "forbidden" });
    const answer = `HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`;
    const agent = new ChannelAgent(async () => new ClosingAnswerChannel(answer));
    cleanups.push(() => agent.destroy());
    for (let i = 0; i < 5; i++) {
      const response = await agentFetch(agent, `http://${SSH_SIGNER_HOST}/status`, { method: "GET", headers: {} });
      assert.equal(response.status, 403);
      assert.deepEqual(await response.json(), { error: "Forbidden", code: "forbidden" });
    }
  });

  it("keeps at most two idle channels", () => {
    const agent = new ChannelAgent(async () => new Ssh2LikeChannel());
    cleanups.push(() => agent.destroy());
    assert.equal(agent.maxFreeSockets, 2);
  });

  it("lets a channel that opened after its request was aborted leave the pool", async () => {
    let release: (channel: Duplex) => void = () => {};
    const agent = new ChannelAgent(() => new Promise<Duplex>((resolve) => { release = resolve; }));
    cleanups.push(() => agent.destroy());
    const controller = new AbortController();
    const aborted = agentFetch(agent, `http://${SSH_SIGNER_HOST}/status`, { method: "GET", headers: {}, signal: controller.signal });
    controller.abort();
    await assert.rejects(aborted, (error: unknown) => error instanceof Error && error.name === "AbortError");
    const channel = new Ssh2LikeChannel();
    release(channel);
    await waitFor(() => Object.keys(agent.sockets).length === 0, "the late channel to leave the agent's pool");
  });

  it("refuses a request for any host but the placeholder, without opening a channel", async () => {
    let opened = 0;
    const agent = new ChannelAgent(async () => {
      opened++;
      throw new Error("no channel in this test");
    });
    cleanups.push(() => agent.destroy());
    await assert.rejects(
      agentFetch(agent, "http://127.0.0.1:11270/status", { method: "GET", headers: {} }),
      /unexpected HTTP destination 127\.0\.0\.1/,
    );
    assert.equal(opened, 0, "a channel was opened");
  });

  it("rejects with the signal's reason when it is already aborted", async () => {
    const agent = new ChannelAgent(async () => {
      throw new Error("no channel in this test");
    });
    cleanups.push(() => agent.destroy());
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      agentFetch(agent, `http://${SSH_SIGNER_HOST}/status`, { method: "GET", headers: {}, signal: controller.signal }),
      (error: unknown) => error instanceof Error && error.name === "AbortError",
    );
  });
});
