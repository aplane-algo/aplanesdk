// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { isScalar, parse as parseYaml, parseDocument } from "yaml";
import type {
  ClientConfig,
  ClientEndpointConfig,
  ClientEndpointRegistry,
} from "./types.js";
import { SignerError } from "./errors.js";

/** Default ports (match apshell/apsigner defaults) */
export const DEFAULT_SSH_PORT = 1127;
/**
 * Endpoint keys earlier builds wrote and nothing reads: the node's SSH server
 * forwards every channel to its own REST listener, the local tunnel port is
 * chosen at connect time, and the client's enrolled SSH key is its only
 * credential, so there is no token file. They are accepted and ignored, as
 * APlane ignores them, so a registry written before they were retired keeps
 * working.
 */
const RETIRED_ENDPOINT_FIELDS = ["signer_port", "local_port", "token_file"] as const;
export const CLIENT_ENDPOINTS_FILE = "endpoints.yaml";
export const DEFAULT_CLIENT_ENDPOINT_NAME = "primary";
export const CLIENT_ENDPOINT_SCHEMA_VERSION = 2;
export const MAX_CLIENT_COSIGNER_ENDPOINTS = 12;

/**
 * Expand ~ in paths to the user's home directory.
 */
export function expandPath(filePath: string): string {
  if (filePath.startsWith("~")) {
    return path.join(os.homedir(), filePath.slice(1));
  }
  return filePath;
}

/**
 * Load client configuration from data_dir/config.yaml.
 *
 * @param dataDir - Path to data directory
 * @returns ClientConfig with values from file, defaults for missing fields
 */
export function loadConfig(dataDir: string): ClientConfig {
  const config: ClientConfig = {
    network: "testnet",
    networksAllowed: [],
    theme: "auto",
  };

  const configPath = path.join(dataDir, "config.yaml");

  if (!fs.existsSync(configPath)) {
    return config;
  }

  try {
    const content = fs.readFileSync(configPath, "utf-8");
    const data = parseYaml(content) || {};
    requireMapping(data, "config.yaml");
    for (const field of ["endpoint", "ssh", "signer_port"]) {
      if (Object.prototype.hasOwnProperty.call(data, field)) {
        throw new SignerError(
          `unsupported client routing in config.yaml: remove "${field}" and configure endpoints.yaml`,
        );
      }
    }
    if (typeof data.network === "string") config.network = data.network;
    if (
      Array.isArray(data.networks_allowed) &&
      data.networks_allowed.every((item) => typeof item === "string")
    ) {
      config.networksAllowed = data.networks_allowed;
    }
    if (typeof data.theme === "string" && data.theme) config.theme = data.theme;
  } catch (error) {
    if (error instanceof SignerError) throw error;
    throw new SignerError(`failed to parse config.yaml: ${errorMessage(error)}`);
  }

  return config;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function requireMapping(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new SignerError(`${label} must be a mapping`);
  }
}

function requireKnownFields(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  const allowedSet = new Set(allowed);
  for (const field of Object.keys(value)) {
    if (!allowedSet.has(field)) {
      throw new SignerError(`${label} contains unknown field "${field}"`);
    }
  }
}

function optionalString(value: unknown, field: string): string {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") {
    throw new SignerError(`${field} must be a string`);
  }
  return value;
}

function resolvePath(filePath: string, dataDir: string): string {
  if (!filePath) return "";
  const expanded = expandPath(filePath);
  return path.isAbsolute(expanded) ? expanded : path.join(dataDir, expanded);
}

function validateAlias(alias: string): void {
  if (!alias || !/^[A-Za-z0-9._-]+$/.test(alias)) {
    throw new SignerError(
      `alias "${alias}" must contain only ASCII letters, digits, '.', '_', or '-'`,
    );
  }
}


function normalizeEndpoint(
  dataDir: string,
  alias: string,
  raw: unknown,
): ClientEndpointConfig {
  requireMapping(raw, `endpoint "${alias}"`);
  requireKnownFields(raw, [
    "role",
    "url",
    "identity_file",
    "known_hosts_path",
    ...RETIRED_ENDPOINT_FIELDS,
  ], `endpoint "${alias}"`);

  const role = optionalString(raw.role, "role").trim();
  if (role !== "signer" && role !== "cosigner") {
    throw new SignerError(
      `endpoint "${alias}": unsupported role "${role}" (expected "signer" or "cosigner")`,
    );
  }
  const endpointUrl = optionalString(raw.url, "url").trim().replace(/\/+$/, "");
  if (!endpointUrl) {
    throw new SignerError(`endpoint "${alias}": url is required`);
  }
  if (endpointUrl === "self") {
    throw new SignerError(
      `endpoint "${alias}": url "self" is not supported; configure an explicit ssh://host[:port] endpoint`,
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(endpointUrl);
  } catch (error) {
    throw new SignerError(`endpoint "${alias}": invalid url: ${errorMessage(error)}`);
  }
  // A node is reached only through its SSH server, which authenticates the
  // client's enrolled key; there is no credential a raw HTTP endpoint could
  // present.
  if (parsed.protocol !== "ssh:") {
    throw new SignerError(
      `endpoint "${alias}": unsupported url scheme "${parsed.protocol.slice(0, -1)}"; a node is reached only through its SSH server (ssh://host[:port])`,
    );
  }
  if (!parsed.hostname) {
    throw new SignerError(`endpoint "${alias}": url host is required`);
  }
  if (parsed.port) {
    const urlPort = Number(parsed.port);
    if (!Number.isInteger(urlPort) || urlPort < 1 || urlPort > 65535) {
      throw new SignerError(`endpoint "${alias}": invalid url port "${parsed.port}"`);
    }
  }

  const identityFile = optionalString(raw.identity_file, "identity_file") || ".ssh/id_ed25519";
  const knownHostsPath = optionalString(raw.known_hosts_path, "known_hosts_path") || ".ssh/known_hosts";

  return {
    role,
    url: endpointUrl,
    identityFile: resolvePath(identityFile, dataDir),
    knownHostsPath: resolvePath(knownHostsPath, dataDir),
  };
}

/** Load and normalize dataDir/endpoints.yaml. */
export function loadClientEndpointRegistry(dataDir: string): ClientEndpointRegistry {
  const registry: ClientEndpointRegistry = {
    schemaVersion: CLIENT_ENDPOINT_SCHEMA_VERSION,
    default: "",
    endpoints: {},
  };
  const endpointsPath = path.join(dataDir, CLIENT_ENDPOINTS_FILE);
  if (!fs.existsSync(endpointsPath)) return registry;

  let raw: unknown;
  let schemaVersionSource = "";
  try {
    const document = parseDocument(fs.readFileSync(endpointsPath, "utf-8"));
    const problem = document.errors[0] ?? document.warnings[0];
    if (problem) throw problem;
    const schemaVersionNode = document.get("schema_version", true);
    if (isScalar(schemaVersionNode)) {
      schemaVersionSource = String(schemaVersionNode.source ?? "");
    }
    raw = document.toJS() ?? {};
  } catch (error) {
    throw new SignerError(`failed to parse ${endpointsPath}: ${errorMessage(error)}`);
  }
  requireMapping(raw, CLIENT_ENDPOINTS_FILE);
  requireKnownFields(raw, ["schema_version", "default", "endpoints"], CLIENT_ENDPOINTS_FILE);
  const schemaVersion = raw.schema_version;
  if (
    schemaVersion !== CLIENT_ENDPOINT_SCHEMA_VERSION
    || (schemaVersionSource !== "" && !/^[+-]?\d+$/.test(schemaVersionSource))
  ) {
    const shown = schemaVersion === undefined ? "0" : schemaVersionSource || String(schemaVersion);
    throw new SignerError(
      `${CLIENT_ENDPOINTS_FILE} schema_version = ${shown}, want ${CLIENT_ENDPOINT_SCHEMA_VERSION}`,
    );
  }
  const endpointsRaw = raw.endpoints ?? {};
  requireMapping(endpointsRaw, `${CLIENT_ENDPOINTS_FILE} endpoints`);
  for (const [alias, endpointRaw] of Object.entries(endpointsRaw)) {
    validateAlias(alias);
    registry.endpoints[alias] = normalizeEndpoint(dataDir, alias, endpointRaw);
  }

  registry.default = optionalString(raw.default, "default").trim();
  if (registry.default) validateAlias(registry.default);
  const signerAliases = Object.entries(registry.endpoints)
    .filter(([, endpoint]) => endpoint.role === "signer")
    .map(([alias]) => alias);
  const cosignerCount = Object.values(registry.endpoints).filter((endpoint) => endpoint.role === "cosigner").length;
  if (cosignerCount > MAX_CLIENT_COSIGNER_ENDPOINTS) {
    throw new SignerError(`${CLIENT_ENDPOINTS_FILE} configures ${cosignerCount} cosigner endpoints; maximum is ${MAX_CLIENT_COSIGNER_ENDPOINTS}; remove or consolidate endpoint profiles`);
  }
  if (signerAliases.length > 1) {
    throw new SignerError(
      `${CLIENT_ENDPOINTS_FILE} may contain at most one "signer" endpoint`,
    );
  }
  if (signerAliases.length === 0) {
    if (registry.default) {
      throw new SignerError(
        `${CLIENT_ENDPOINTS_FILE} default endpoint "${registry.default}" is set but no "signer" endpoint is configured`,
      );
    }
  } else if (registry.default && registry.default !== signerAliases[0]) {
    throw new SignerError(
      `${CLIENT_ENDPOINTS_FILE} default endpoint "${registry.default}" must be the "signer" endpoint "${signerAliases[0]}"`,
    );
  } else {
    registry.default = signerAliases[0];
  }
  return registry;
}

/** Resolve an explicit endpoint alias or the registry's default signer. */
export function resolveClientEndpoint(
  registry: ClientEndpointRegistry,
  alias?: string,
): { alias: string; endpoint: ClientEndpointConfig } {
  const selected = alias || registry.default;
  if (!selected) {
    throw new SignerError(`${CLIENT_ENDPOINTS_FILE} has no default signer endpoint`);
  }
  const endpoint = registry.endpoints[selected];
  if (!endpoint) {
    throw new SignerError(`endpoint alias "${selected}" is not defined`);
  }
  return { alias: selected, endpoint };
}

/** Resolve host and SSH port from an ssh:// endpoint. */
export function clientEndpointSshHostPort(
  endpoint: ClientEndpointConfig,
): { host: string; port: number } {
  const parsed = new URL(endpoint.url);
  if (parsed.protocol !== "ssh:") {
    throw new SignerError(`endpoint "${endpoint.url}" requires ssh://`);
  }
  return {
    host: parsed.hostname.replace(/^\[|\]$/g, ""),
    port: parsed.port ? Number(parsed.port) : DEFAULT_SSH_PORT,
  };
}

/**
 * Resolve data directory from parameter > APCLIENT_DATA env var.
 *
 * @param dataDir - Optional override
 * @returns Resolved and expanded path
 * @throws SignerError when neither parameter nor APCLIENT_DATA is set
 */
export function resolveDataDir(dataDir?: string): string {
  const dir = dataDir || process.env.APCLIENT_DATA;
  if (!dir) {
    throw new SignerError(
      "client data directory not specified: pass dataDir or set APCLIENT_DATA",
    );
  }
  return expandPath(dir);
}
