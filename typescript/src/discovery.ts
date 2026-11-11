// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * Cosigner discovery: find the cosigner endpoint of endpoints.yaml that holds
 * the witness key a cosigned account names, from each endpoint's /keys.
 */

import {
  SignerClient,
  clientConnectionOpen,
  readKeyRecordsOf,
  type CosignedCosignerResolution,
  type CosignedCosignerResolveOptions,
  type CosignedCosignerResolverObject,
  type CosignedSignTarget,
} from "./client.js";
import type { ClientEndpointConfig, ClientEndpointRegistry } from "./types.js";
import { ErrorCodes } from "./types.js";
import {
  CLIENT_ENDPOINTS_FILE,
  MAX_CLIENT_COSIGNER_ENDPOINTS,
  clientEndpointSshHostPort,
  loadClientEndpointRegistry,
  resolveDataDir,
} from "./config.js";
import {
  AuthenticationError,
  CosignerDiscoveryError,
  SignerError,
  SignerUnavailableError,
  callerAborted,
  errorText,
} from "./errors.js";
import { hexToBytes } from "./encoding.js";
import { normalizeSSHSetupTimeout, sshSetupFailure } from "./ssh.js";
import { witnessKeyId } from "./witness.js";

/** How a cosigner endpoint fared in the last sweep. */
export type CosignerEndpointState =
  | "ok"
  | "unreachable"
  | "locked"
  | "authentication failed"
  | "invalid cosigner metadata"
  | "configuration invalid";

/** How an EndpointCosignerResolver connects to cosigner endpoints. */
export interface EndpointCosignerResolverOptions {
  /** Trust and save an endpoint's unknown SSH host key. Default false. */
  trustOnFirstUse?: boolean;
  /** TCP connection and SSH authentication timeout, in milliseconds. */
  sshSetupTimeout?: number;
  /** An explicit shorter request timeout for the cosigner clients, in milliseconds. */
  timeout?: number;
}

/**
 * The sweep's limits: each endpoint gets endpointMs, the whole sweep
 * sweepMs, and at most DISCOVERY_CONCURRENCY endpoints are probed at once.
 * Tests shorten them; they are not part of the package's exports.
 */
export const discoveryTiming = { endpointMs: 10_000, sweepMs: 30_000 };
const DISCOVERY_CONCURRENCY = 4;

/** Connects to one cosigner endpoint, as a signer endpoint is connected. */
export type CosignerEndpointConnector = (
  alias: string,
  endpoint: ClientEndpointConfig,
  options: EndpointCosignerResolverOptions & { signal: AbortSignal },
) => Promise<SignerClient>;

async function connectCosignerEndpoint(
  _alias: string,
  endpoint: ClientEndpointConfig,
  options: EndpointCosignerResolverOptions & { signal: AbortSignal },
): Promise<SignerClient> {
  const { host, port } = clientEndpointSshHostPort(endpoint);
  return SignerClient.connectSsh(host, endpoint.identityFile, {
    sshPort: port,
    timeout: options.timeout,
    sshSetupTimeout: options.sshSetupTimeout,
    signal: options.signal,
    knownHostsPath: endpoint.knownHostsPath,
    trustOnFirstUse: options.trustOnFirstUse ?? false,
  });
}

/** Tests replace the connector; it is not part of the package's exports. */
export const discoveryHooks: { connect: CosignerEndpointConnector } = { connect: connectCosignerEndpoint };

const HEX = /^(?:[0-9a-fA-F]{2})*$/;

/** A witness key an endpoint lists. */
interface ListedWitnessKey {
  keyType: string;
  /** Lowercase. */
  publicKeyHex: string;
  /** The record's address: its Witness Key ID. */
  address: string;
}

/** What a sweep found at one endpoint. */
interface EndpointListing {
  state: CosignerEndpointState;
  keys: ListedWitnessKey[];
}

interface ProbeResult extends EndpointListing {
  /** The connection, kept only for an endpoint whose state is ok. */
  client?: SignerClient;
  /** The SSH host key mismatch the endpoint's connection met. */
  mismatch?: unknown;
}

/** The witness key a target needs. */
interface RequiredWitnessKey {
  keyType: string;
  publicKeyHex: string;
  id: string;
}

/** The witness key a target needs, checked before anything is connected. */
function requiredWitnessKey(target: CosignedSignTarget): RequiredWitnessKey {
  const keyType = target?.cosignerComponentKeyType ?? "";
  const publicKeyHex = target?.cosignerPublicKeyHex ?? "";
  if (typeof publicKeyHex !== "string" || publicKeyHex === "" || !HEX.test(publicKeyHex)) {
    throw new CosignerDiscoveryError(
      `cosigner discovery: the account's cosigner public key ${JSON.stringify(String(publicKeyHex))} is not valid hex`,
    );
  }
  if (typeof keyType !== "string" || keyType === "") {
    throw new CosignerDiscoveryError("cosigner discovery: the account names no cosigner key type");
  }
  const lower = publicKeyHex.toLowerCase();
  return { keyType, publicKeyHex: lower, id: witnessKeyId(keyType, hexToBytes(lower)) };
}

/**
 * The witness keys a /keys answer lists, or undefined when any witness
 * record is invalid: a record whose public key is empty or not hex, or whose
 * address is not the Witness Key ID of its key type and public key, makes the
 * whole listing invalid.
 */
function witnessKeys(records: Record<string, any>[]): ListedWitnessKey[] | undefined {
  const keys: ListedWitnessKey[] = [];
  for (const record of records) {
    if (record.is_witness_key !== true || typeof record.key_type !== "string" || record.key_type === "") continue;
    const hex = record.public_key_hex;
    if (typeof hex !== "string" || hex === "" || !HEX.test(hex)) return undefined;
    const publicKeyHex = hex.toLowerCase();
    if (record.address !== witnessKeyId(record.key_type, hexToBytes(publicKeyHex))) return undefined;
    keys.push({ keyType: record.key_type, publicKeyHex, address: record.address });
  }
  return keys;
}

/** The state of an endpoint that refused /keys with this status and code. */
function refusalState(status: number, code: string): CosignerEndpointState {
  if (code === ErrorCodes.Locked) return "locked";
  if (status === 401 || status === 403) return "authentication failed";
  if (status >= 500) return "unreachable";
  return "configuration invalid";
}

/** Read an endpoint's /keys and the witness keys it lists. */
async function readListing(client: SignerClient, signal: AbortSignal): Promise<EndpointListing> {
  let read: Awaited<ReturnType<typeof readKeyRecordsOf>>;
  try {
    read = await readKeyRecordsOf(client, signal);
  } catch (error) {
    // A failed exchange; otherwise an answer that could not be read, or one
    // listing an address in an alternate spelling.
    if (error instanceof SignerUnavailableError) return { state: "unreachable", keys: [] };
    return { state: "invalid cosigner metadata", keys: [] };
  }
  if ("status" in read) return { state: refusalState(read.status, read.code), keys: [] };
  const keys = witnessKeys(read.records);
  return keys ? { state: "ok", keys } : { state: "invalid cosigner metadata", keys: [] };
}

/** The state of an endpoint whose connection failed, or "mismatch". */
function connectFailure(error: unknown): CosignerEndpointState | "mismatch" {
  const kind = sshSetupFailure(error);
  if (kind === "host-key-mismatch") return "mismatch";
  if (kind !== undefined) return "configuration invalid";
  if (error instanceof AuthenticationError) return "authentication failed";
  return "unreachable";
}

/**
 * promise, or a rejection as soon as signal aborts. What promise settles to
 * afterwards is passed to late.
 */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal, late?: (value: T) => void): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let done = false;
    const onAbort = () => {
      done = true;
      reject(callerAborted());
    };
    if (signal.aborted) {
      onAbort();
    } else {
      signal.addEventListener("abort", onAbort, { once: true });
    }
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        if (done) {
          late?.(value);
          return;
        }
        done = true;
        resolve(value);
      },
      (reason) => {
        signal.removeEventListener("abort", onAbort);
        if (done) return;
        done = true;
        reject(reason);
      },
    );
  });
}

/** Close a client, ignoring a failure: the connection is no longer needed. */
async function closeQuietly(client: SignerClient | undefined): Promise<void> {
  try {
    await client?.close();
  } catch {
    // Nothing more to release.
  }
}

/**
 * Finds a cosigned account's cosigner from the client's endpoint registry
 * (endpoints.yaml): it connects to every endpoint with role "cosigner", each
 * with its own identity file and known_hosts path, reads its /keys, and
 * routes a target to the one endpoint that lists the target's witness key.
 * Pass it as cosignerResolver; a client created with SignerClient.fromEnv
 * uses one on its own when a cosigned call names no cosigner.
 *
 * A /keys record counts when it is a witness key with a key type. Its
 * public key must be hex and its address the Witness Key ID derived from its
 * key type and public key; a record that is neither makes the endpoint's
 * whole listing invalid ("invalid cosigner metadata").
 *
 * The first resolve sweeps every cosigner endpoint (10 seconds each, 30 for
 * the sweep, 4 at once) and keeps the result; a witness key the kept result
 * does not route triggers one fresh sweep. An SSH host key that differs from
 * the pinned one at any cosigner endpoint aborts the sweep. The connections
 * it opens are its own: close() closes them.
 */
export class EndpointCosignerResolver implements CosignedCosignerResolverObject {
  readonly #endpoints: ReadonlyArray<readonly [string, ClientEndpointConfig]>;
  readonly #options: EndpointCosignerResolverOptions;
  readonly #connections = new Map<string, SignerClient>();
  #listings?: Map<string, EndpointListing>;
  #closed = false;
  #queue: Promise<unknown> = Promise.resolve();

  /** A resolver over a loaded endpoint registry, such as loadClientEndpointRegistry returns. */
  constructor(registry: ClientEndpointRegistry, options: EndpointCosignerResolverOptions = {}) {
    if (typeof registry !== "object" || registry === null || typeof registry.endpoints !== "object" || registry.endpoints === null) {
      throw new SignerError("an endpoint registry is required");
    }
    if (typeof options !== "object" || options === null) {
      throw new SignerError("EndpointCosignerResolver options must be an object");
    }
    const endpoints = Object.entries(registry.endpoints)
      .filter(([, endpoint]) => endpoint?.role === "cosigner")
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    try {
      normalizeSSHSetupTimeout(options.sshSetupTimeout);
    } catch (error) {
      throw new SignerError(errorText(error));
    }
    this.#endpoints = Object.freeze(endpoints.map(([alias, endpoint]) => Object.freeze([alias, { ...endpoint }] as const)));
    this.#options = { ...options };
  }

  /**
   * A resolver over dataDir/endpoints.yaml: the data directory
   * SignerClient.fromEnv uses (dataDir, else APCLIENT_DATA).
   */
  static fromDataDir(dataDir?: string, options?: EndpointCosignerResolverOptions): EndpointCosignerResolver {
    return new EndpointCosignerResolver(loadClientEndpointRegistry(resolveDataDir(dataDir)), options);
  }

  /**
   * The client of the one cosigner endpoint that lists target's witness key,
   * and that key's Witness Key ID as the component key. It throws a
   * CosignerDiscoveryError when no endpoint lists it, when more than one
   * does, when no cosigner endpoint is configured, or when an endpoint's SSH
   * host key differs from the pinned one.
   */
  async resolve(
    target: CosignedSignTarget,
    options?: CosignedCosignerResolveOptions,
  ): Promise<CosignedCosignerResolution> {
    const required = requiredWitnessKey(target);
    // One resolve at a time, so a sweep's result serves the calls queued
    // behind it.
    const run = this.#queue.then(() => this.#resolve(required, options?.signal));
    this.#queue = run.catch(() => undefined);
    return run;
  }

  /** Close every connection the resolver opened. It cannot resolve after. */
  async close(): Promise<void> {
    this.#closed = true;
    const clients = [...this.#connections.values()];
    this.#connections.clear();
    this.#listings = undefined;
    await Promise.all(clients.map(closeQuietly));
  }

  async #resolve(required: RequiredWitnessKey, signal: AbortSignal | undefined): Promise<CosignedCosignerResolution> {
    if (this.#closed) throw closedError();
    let swept = false;
    if (!this.#listings) {
      await this.#sweep(signal);
      swept = true;
    }
    let matches = this.#matches(required);
    if (matches.length === 0 && !swept) {
      await this.#sweep(signal);
      matches = this.#matches(required);
    }
    const label = `Witness Key ID ${required.id} (${required.keyType})`;
    if (matches.length > 1) {
      throw new CosignerDiscoveryError(
        `cosigner discovery: ${label} is listed by endpoints ${matches.map(([alias]) => `"${alias}"`).join(", ")}; ` +
          "each witness key needs exactly one endpoint",
      );
    }
    if (matches.length === 1) {
      const [alias, key] = matches[0];
      const client = this.#connections.get(alias) as SignerClient;
      return { client, componentKey: key.address };
    }
    const states = this.#endpoints
      .map(([alias]) => `"${alias}" ${this.#listings?.get(alias)?.state ?? "unreachable"}`)
      .join(", ");
    throw new CosignerDiscoveryError(`cosigner discovery: no endpoint lists ${label}; endpoints: ${states}`);
  }

  /** The endpoints of the kept sweep that list the key and are still connected, by alias. */
  #matches(required: RequiredWitnessKey): Array<[string, ListedWitnessKey]> {
    const matches: Array<[string, ListedWitnessKey]> = [];
    for (const [alias] of this.#endpoints) {
      const listing = this.#listings?.get(alias);
      const client = this.#connections.get(alias);
      if (listing?.state !== "ok" || !client || !clientConnectionOpen(client)) continue;
      const key = listing.keys.find(
        (candidate) => candidate.keyType === required.keyType && candidate.publicKeyHex === required.publicKeyHex,
      );
      if (key) matches.push([alias, key]);
    }
    return matches;
  }

  /**
   * Probe every cosigner endpoint and keep what was found. An endpoint whose
   * connection was kept is read again, and connected afresh if that read
   * fails. A host key mismatch at any endpoint, or the caller's signal
   * ending, keeps nothing and closes every connection.
   */
  async #sweep(signal: AbortSignal | undefined): Promise<void> {
    if (this.#endpoints.length === 0) {
      throw new CosignerDiscoveryError(`cosigner discovery: ${CLIENT_ENDPOINTS_FILE} lists no cosigner endpoint`);
    }
    if (this.#endpoints.length > MAX_CLIENT_COSIGNER_ENDPOINTS) {
      throw new CosignerDiscoveryError(
        `cosigner discovery: ${CLIENT_ENDPOINTS_FILE} lists ${this.#endpoints.length} cosigner endpoints; ` +
          `the limit is ${MAX_CLIENT_COSIGNER_ENDPOINTS}`,
      );
    }
    if (signal?.aborted) throw signalEnded();
    const sweep = new AbortController();
    const onAbort = () => sweep.abort();
    signal?.addEventListener("abort", onAbort, { once: true });
    const timer = setTimeout(() => sweep.abort(), discoveryTiming.sweepMs);
    const results = new Map<string, ProbeResult>();
    let next = 0;
    const worker = async () => {
      while (next < this.#endpoints.length) {
        const [alias, endpoint] = this.#endpoints[next++];
        // The sweep's time ran out before this endpoint was probed.
        if (sweep.signal.aborted) {
          results.set(alias, { state: "unreachable", keys: [] });
          continue;
        }
        const result = await this.#probe(alias, endpoint, sweep.signal);
        results.set(alias, result);
        // A host key mismatch: nothing else matters.
        if (result.mismatch !== undefined) sweep.abort();
      }
    };
    try {
      await Promise.all(
        Array.from({ length: Math.min(DISCOVERY_CONCURRENCY, this.#endpoints.length) }, () => worker()),
      );
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }

    // Every connection goes, and nothing found is kept.
    const abandon = async () => {
      const stale = new Set<SignerClient>(this.#connections.values());
      for (const result of results.values()) {
        if (result.client) stale.add(result.client);
      }
      this.#connections.clear();
      this.#listings = undefined;
      await Promise.all([...stale].map(closeQuietly));
    };
    if (this.#closed) {
      await abandon();
      throw closedError();
    }
    // The first mismatch in alias order is the one reported.
    const mismatched = this.#endpoints.find(([alias]) => results.get(alias)?.mismatch !== undefined);
    if (mismatched !== undefined) {
      const [alias] = mismatched;
      const error = results.get(alias)?.mismatch;
      await abandon();
      throw new CosignerDiscoveryError(`cosigner discovery: endpoint "${alias}": ${errorText(error)}`, error);
    }
    // The caller's own end is not a finding about the endpoints.
    if (signal?.aborted) {
      await abandon();
      throw signalEnded();
    }

    const listings = new Map<string, EndpointListing>();
    const stale: SignerClient[] = [];
    for (const [alias] of this.#endpoints) {
      const result = results.get(alias) ?? { state: "unreachable" as const, keys: [] };
      listings.set(alias, { state: result.state, keys: result.keys });
      const previous = this.#connections.get(alias);
      if (result.state === "ok" && result.client) {
        if (previous && previous !== result.client) stale.push(previous);
        this.#connections.set(alias, result.client);
      } else {
        if (previous) stale.push(previous);
        if (result.client && result.client !== previous) stale.push(result.client);
        this.#connections.delete(alias);
      }
    }
    this.#listings = listings;
    await Promise.all(stale.map(closeQuietly));
  }

  /**
   * Probe one endpoint within its time limit. An endpoint whose time runs out,
   * or whose sweep ends first, is unreachable; a connection it opens later is
   * closed.
   */
  async #probe(alias: string, endpoint: ClientEndpointConfig, sweepSignal: AbortSignal): Promise<ProbeResult> {
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    sweepSignal.addEventListener("abort", onAbort, { once: true });
    if (sweepSignal.aborted) controller.abort();
    const timer = setTimeout(() => controller.abort(), discoveryTiming.endpointMs);
    try {
      return await untilAborted(this.#probeEndpoint(alias, endpoint, controller.signal), controller.signal, (late) => {
        if (late.client && late.client !== this.#connections.get(alias)) void closeQuietly(late.client);
      });
    } catch {
      return { state: "unreachable", keys: [] };
    } finally {
      clearTimeout(timer);
      sweepSignal.removeEventListener("abort", onAbort);
    }
  }

  async #probeEndpoint(alias: string, endpoint: ClientEndpointConfig, signal: AbortSignal): Promise<ProbeResult> {
    try {
      clientEndpointSshHostPort(endpoint);
    } catch {
      return { state: "configuration invalid", keys: [] };
    }
    // A connection kept from the last sweep is read again; one whose read
    // fails is closed and replaced.
    const existing = this.#connections.get(alias);
    if (existing && clientConnectionOpen(existing)) {
      const listing = await readListing(existing, signal);
      if (listing.state === "ok") return { ...listing, client: existing };
      this.#connections.delete(alias);
      await closeQuietly(existing);
      if (signal.aborted) return listing;
    }
    let client: SignerClient;
    try {
      client = await discoveryHooks.connect(alias, endpoint, { ...this.#options, signal });
    } catch (error) {
      const state = connectFailure(error);
      return state === "mismatch" ? { state: "unreachable", keys: [], mismatch: error } : { state, keys: [] };
    }
    const listing = await readListing(client, signal);
    if (listing.state !== "ok") {
      await closeQuietly(client);
      return listing;
    }
    return { ...listing, client };
  }
}

function closedError(): CosignerDiscoveryError {
  return new CosignerDiscoveryError("cosigner discovery: the resolver is closed");
}

/** The caller's signal ended the discovery. */
function signalEnded(): CosignerDiscoveryError {
  const cause = callerAborted();
  return new CosignerDiscoveryError(`cosigner discovery: ${errorText(cause)}`, cause);
}
