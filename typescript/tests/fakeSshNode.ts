// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

// A node reached over real SSH, for the tests that connect with connectSsh or
// fromEnv: an ssh2 server whose forwarded channels reach an HTTP stand-in for
// the signer.

import * as http from "http";
import * as net from "net";
import { generateKeyPairSync } from "crypto";
import ssh2 from "ssh2";
import type { FakeHandler } from "./fakeNetwork.js";

const { Server, utils: sshUtils } = ssh2;

export function rsaPem(): string {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
  }).privateKey;
}

/** The SSH wire form of a private key's public half, as known_hosts pins it. */
export function publicBlob(pem: string): Buffer {
  const parsed = sshUtils.parseKey(pem);
  if (parsed instanceof Error) throw parsed;
  const key = Array.isArray(parsed) ? parsed[0] : parsed;
  return key.getPublicSSH();
}

/** One channel a client asked the node to forward. */
export interface ForwardedChannel {
  /** The destination the channel request named. */
  destination: string;
  /** Whether the channel is still open. */
  open: boolean;
}

/** A node: an SSH server whose forwarded channels reach an HTTP handler. */
export interface SshNode {
  port: number;
  hostKey: string;
  /** SSH sessions that are open. */
  sessions: () => number;
  /** Every channel a client asked the node to forward, in order. */
  channels: ForwardedChannel[];
  /** The path and Host header of every request the node received, in order. */
  requests: Array<{ path: string; host: string }>;
  close: () => Promise<void>;
}

export async function startNode(handler: FakeHandler): Promise<SshNode> {
  const requests: Array<{ path: string; host: string }> = [];
  const httpServer = http.createServer((request, response) => {
    const path = new URL(request.url ?? "/", "http://node").pathname;
    requests.push({ path, host: request.headers.host ?? "" });
    let raw = "";
    request.on("data", (chunk) => {
      raw += chunk;
    });
    request.on("end", async () => {
      const reply = await handler(path, raw ? JSON.parse(raw) : undefined);
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
  const channels: ForwardedChannel[] = [];
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
      client.on("tcpip", (accept, _reject, info) => {
        const channel: ForwardedChannel = { destination: `${info.destIP}:${info.destPort}`, open: true };
        channels.push(channel);
        const stream = accept();
        stream.on("close", () => {
          channel.open = false;
        });
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
    channels,
    requests,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => sshServer.close(() => resolve()));
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    },
  };
}
