// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * HTTP to a node over the client's SSH connection, with nothing listening on
 * this machine. Each HTTP connection is a direct-tcpip channel the client
 * opens itself on its authenticated SSH connection, so no other process on
 * the machine can send a request under the client's enrolled key.
 */

import * as http from "http";
import type { Duplex } from "stream";

/**
 * The host named by requests over SSH. No host is resolved or dialed: every
 * connection is a channel on the SSH connection, and .invalid names no real
 * host (RFC 6761).
 */
export const SSH_SIGNER_HOST = "signer.aplane.invalid";
export const SSH_SIGNER_BASE_URL = `http://${SSH_SIGNER_HOST}`;

/**
 * How long an idle connection is kept for the next request. It closes before
 * the node's HTTP server closes an idle connection (its IdleTimeout is 120
 * seconds), so a request is never sent on a connection the server is
 * closing. Tests shorten it; it is not part of the package's exports.
 */
export const sshHttpTiming = { idleMs: 90_000 };

/** Opens one channel to the node's REST listener. */
export type ChannelOpener = () => Promise<Duplex>;

/**
 * An HTTP agent whose every connection is a channel from openChannel. A
 * connection is kept for the next request and closed after
 * sshHttpTiming.idleMs idle.
 */
export class ChannelAgent extends http.Agent {
  private readonly openChannel: ChannelOpener;
  private readonly idleTimers = new Map<Duplex, ReturnType<typeof setTimeout>>();

  constructor(openChannel: ChannelOpener) {
    super({ keepAlive: true });
    this.openChannel = openChannel;
  }

  override createConnection(
    options: http.ClientRequestArgs,
    callback?: (err: Error | null, stream: Duplex) => void,
  ): Duplex | null | undefined {
    const done = (error: Error | null, channel?: Duplex) => {
      callback?.(error, channel as Duplex);
    };
    // The client sends nothing but its own requests to the node.
    if (options.host !== SSH_SIGNER_HOST) {
      process.nextTick(() => done(new Error(`unexpected HTTP destination ${String(options.host)}`)));
      return undefined;
    }
    this.openChannel().then(
      (channel) => {
        channel.once("close", () => this.stopIdleTimer(channel));
        done(null, asConnection(channel));
      },
      (error: unknown) => done(error instanceof Error ? error : new Error(String(error))),
    );
    return undefined;
  }

  // Returns whether the connection is kept, as the agent reads it.
  override keepSocketAlive(socket: Duplex): boolean {
    this.stopIdleTimer(socket);
    const timer = setTimeout(() => {
      this.idleTimers.delete(socket);
      // Destroying a channel only asks the node to close it, and until the
      // node answers the channel would stay in the pool. agentRemove takes it
      // out now, so no request is sent on it meanwhile (the agent drops a
      // pooled connection only once it is no longer writable, which destroy
      // makes it).
      socket.destroy();
      socket.emit("agentRemove");
    }, sshHttpTiming.idleMs);
    timer.unref();
    this.idleTimers.set(socket, timer);
    return true;
  }

  override reuseSocket(socket: Duplex, request: http.ClientRequest): void {
    this.stopIdleTimer(socket);
    super.reuseSocket(socket, request);
  }

  override destroy(): void {
    for (const timer of this.idleTimers.values()) clearTimeout(timer);
    this.idleTimers.clear();
    super.destroy();
  }

  private stopIdleTimer(socket: Duplex): void {
    const timer = this.idleTimers.get(socket);
    if (timer !== undefined) {
      clearTimeout(timer);
      this.idleTimers.delete(socket);
    }
  }
}

/**
 * channel, with the net.Socket methods the agent calls on a pooled
 * connection (it refs one it reuses). A channel has no handle of its own to
 * hold the process open; the SSH connection does.
 */
function asConnection(channel: Duplex): Duplex {
  return Object.assign(channel, {
    ref: () => channel,
    unref: () => channel,
  });
}

/** The fields of fetch's RequestInit a request to a node uses. */
export interface ChannelRequestInit {
  method: string;
  headers: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
}

/** Statuses whose response fetch gives no body. */
const NULL_BODY_STATUSES = new Set([204, 205, 304]);

/** What an aborted signal rejects with, as fetch rejects with it. */
function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException("This operation was aborted", "AbortError");
}

/**
 * fetch, for one request sent through agent. It resolves with a Response
 * when the headers arrive, whose body streams the rest, and rejects with the
 * transport's error when the exchange fails first. Signal aborts it as it
 * aborts fetch: before the headers the promise rejects with the signal's
 * reason, after them the body fails with it.
 */
export function agentFetch(agent: http.Agent, url: string, init: ChannelRequestInit): Promise<Response> {
  const { signal } = init;
  if (signal?.aborted) {
    return Promise.reject(abortReason(signal));
  }
  const payload = init.body === undefined ? undefined : Buffer.from(init.body, "utf8");
  const headers: Record<string, string> = { ...init.headers };
  if (payload !== undefined) {
    headers["Content-Length"] = String(payload.length);
  }

  return new Promise<Response>((resolve, reject) => {
    // The exchange ends once: with the body read whole, or with the first
    // failure, which goes to the promise until the headers arrive and to the
    // body after them.
    let done = false;
    let fail: (error: unknown) => void = reject;
    let closedEarly = "the connection closed before the signer answered";
    const end = (error?: unknown): void => {
      if (done) return;
      done = true;
      signal?.removeEventListener("abort", onAbort);
      if (error !== undefined) fail(error);
    };
    const onAbort = (): void => {
      end(abortReason(signal as AbortSignal));
      request.destroy();
    };

    const request = http.request(url, { method: init.method, headers, agent }, (incoming) => {
      if (done) {
        incoming.destroy();
        return;
      }
      closedEarly = "the connection closed before the answer was complete";
      const status = incoming.statusCode ?? 0;
      const responseHeaders = new Headers();
      for (let i = 0; i + 1 < incoming.rawHeaders.length; i += 2) {
        responseHeaders.append(incoming.rawHeaders[i], incoming.rawHeaders[i + 1]);
      }

      let body: ReadableStream<Uint8Array> | null = null;
      if (NULL_BODY_STATUSES.has(status)) {
        incoming.resume();
        end();
      } else {
        // The body is read as it arrives, so an answer nobody reads still
        // frees its connection for the next request.
        body = new ReadableStream<Uint8Array>({
          start(controller) {
            fail = (error) => controller.error(error);
            incoming.on("data", (chunk: Buffer) => {
              if (!done) controller.enqueue(new Uint8Array(chunk));
            });
            incoming.on("end", () => {
              if (done) return;
              end();
              controller.close();
            });
            incoming.on("error", (error) => end(error));
            incoming.on("close", () => end(new Error(closedEarly)));
          },
          cancel() {
            end();
            incoming.destroy();
          },
        });
      }

      try {
        resolve(new Response(body, {
          status,
          statusText: incoming.statusMessage ?? "",
          headers: responseHeaders,
        }));
      } catch (error) {
        // A status or header the Response constructor refuses.
        done = true;
        signal?.removeEventListener("abort", onAbort);
        incoming.destroy();
        reject(error);
      }
    });

    signal?.addEventListener("abort", onAbort, { once: true });
    request.on("error", (error) => end(error));
    request.on("close", () => end(new Error(closedEarly)));
    request.end(payload);
  });
}
