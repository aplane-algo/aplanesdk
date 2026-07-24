// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as net from "net";
import { isScalar, parse as parseYaml, parseDocument } from "yaml";
import type {
  ClientConfig,
  ClientEndpointConfig,
  ClientEndpointPublishedSentry,
  ClientEndpointRegistry,
} from "./types.js";
import { SignerError } from "./errors.js";

/** Default ports (match apshell/apsigner defaults) */
export const DEFAULT_SSH_PORT = 1127;
export const DEFAULT_SIGNER_PORT = 11270;
export const CLIENT_ENDPOINTS_FILE = "endpoints.yaml";
export const DEFAULT_CLIENT_ENDPOINT_NAME = "primary";

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

function optionalInteger(value: unknown, field: string): number {
  if (value === undefined || value === null) return 0;
  if (!Number.isInteger(value)) {
    throw new SignerError(`${field} must be an integer`);
  }
  return value as number;
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

function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host === "::1") return true;
  return net.isIP(host) === 4 && host.startsWith("127.");
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
    "signer_port",
    "local_port",
    "identity_file",
    "known_hosts_path",
    "token_file",
    "published_sentries",
  ], `endpoint "${alias}"`);

  const role = optionalString(raw.role, "role").trim();
  if (role !== "signer" && role !== "sentry") {
    throw new SignerError(
      `endpoint "${alias}": unsupported role "${role}" (expected "signer" or "sentry")`,
    );
  }
  const endpointUrl = optionalString(raw.url, "url").trim().replace(/\/+$/, "");
  if (!endpointUrl) {
    throw new SignerError(`endpoint "${alias}": url is required`);
  }
  const signerPort = optionalInteger(raw.signer_port, "signer_port");
  const localPort = optionalInteger(raw.local_port, "local_port");
  for (const [field, port] of [["signer_port", signerPort], ["local_port", localPort]] as const) {
    if (port < 0 || port > 65535) {
      throw new SignerError(`endpoint "${alias}": ${field} must be 1-65535 when set`);
    }
  }

  if (endpointUrl !== "self") {
    let parsed: URL;
    try {
      parsed = new URL(endpointUrl);
    } catch (error) {
      throw new SignerError(`endpoint "${alias}": invalid url: ${errorMessage(error)}`);
    }
    if (!["ssh:", "https:", "http:"].includes(parsed.protocol)) {
      throw new SignerError(`endpoint "${alias}": unsupported url scheme "${parsed.protocol.slice(0, -1)}"`);
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
    if (parsed.protocol === "http:" && !isLoopbackHost(parsed.hostname)) {
      throw new SignerError(
        `raw http endpoints must be loopback; use ssh:// or https:// for remote endpoint "${alias}"`,
      );
    }
  }

  let tokenFile = optionalString(raw.token_file, "token_file");
  if (!tokenFile && endpointUrl !== "self") {
    tokenFile = alias === DEFAULT_CLIENT_ENDPOINT_NAME
      ? "aplane.token"
      : path.join("tokens", `${alias}.token`);
  }
  let identityFile = optionalString(raw.identity_file, "identity_file");
  let knownHostsPath = optionalString(raw.known_hosts_path, "known_hosts_path");
  let normalizedSignerPort = signerPort;
  if (endpointUrl.startsWith("ssh://")) {
    normalizedSignerPort ||= DEFAULT_SIGNER_PORT;
    identityFile ||= ".ssh/id_ed25519";
    knownHostsPath ||= ".ssh/known_hosts";
    identityFile = resolvePath(identityFile, dataDir);
    knownHostsPath = resolvePath(knownHostsPath, dataDir);
  }

  let publishedSentries: Record<string, ClientEndpointPublishedSentry> | undefined;
  if (raw.published_sentries !== undefined && raw.published_sentries !== null) {
    requireMapping(raw.published_sentries, `endpoint "${alias}" published_sentries`);
    if (role !== "sentry" && Object.keys(raw.published_sentries).length > 0) {
      throw new SignerError(`endpoint "${alias}": published_sentries are only valid on "sentry" endpoints`);
    }
    publishedSentries = {};
    for (const [publicKey, value] of Object.entries(raw.published_sentries)) {
      requireMapping(value, `published sentry "${publicKey}"`);
      requireKnownFields(value, ["component_key", "key_type", "last_seen_at"], `published sentry "${publicKey}"`);
      if (typeof value.component_key !== "string" || typeof value.key_type !== "string") {
        throw new SignerError(`published sentry "${publicKey}" requires component_key and key_type`);
      }
      const lastSeenAt = optionalString(value.last_seen_at, "last_seen_at").trim();
      publishedSentries[publicKey] = {
        componentKey: value.component_key,
        keyType: value.key_type,
        ...(lastSeenAt ? { lastSeenAt } : {}),
      };
    }
  }

  return {
    role,
    url: endpointUrl,
    signerPort: normalizedSignerPort,
    localPort,
    identityFile,
    knownHostsPath,
    tokenFile: resolvePath(tokenFile, dataDir),
    ...(publishedSentries ? { publishedSentries } : {}),
  };
}

/** Load and normalize dataDir/endpoints.yaml. */
export function loadClientEndpointRegistry(dataDir: string): ClientEndpointRegistry {
  const registry: ClientEndpointRegistry = {
    schemaVersion: 1,
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
  const rawSchemaVersion = raw.schema_version;
  let schemaVersion = rawSchemaVersion;
  if (schemaVersion === undefined || schemaVersion === null || schemaVersion === 0) {
    schemaVersion = 1;
  }
  if (
    typeof schemaVersion !== "number"
    || !Number.isInteger(schemaVersion)
    || (
      typeof rawSchemaVersion === "number"
      && schemaVersionSource !== ""
      && !/^[+-]?\d+$/.test(schemaVersionSource)
    )
    || schemaVersion !== 1
  ) {
    throw new SignerError(`${CLIENT_ENDPOINTS_FILE} schema_version = ${String(schemaVersion)}, want 1`);
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
 * Load authentication token from file.
 *
 * @param tokenPath - Path to aplane.token file
 * @returns Token string
 * @throws SignerError if file doesn't exist
 */
export function loadToken(tokenPath: string): string {
  const expandedPath = expandPath(tokenPath);

  if (!fs.existsSync(expandedPath)) {
    throw new SignerError(`No token found at ${expandedPath}`);
  }

  const token = fs.readFileSync(expandedPath, "utf-8").trim();
  if (!token) {
    throw new SignerError(`Token file ${expandedPath} is empty`);
  }
  return token;
}

/**
 * Load token from the default location in a data directory.
 *
 * @param dataDir - Data directory path (will be expanded)
 * @returns Token string
 * @throws SignerError if token file doesn't exist
 */
export function loadTokenFromDir(dataDir: string): string {
  const expandedDir = expandPath(dataDir);
  const tokenPath = path.join(expandedDir, "aplane.token");
  return loadToken(tokenPath);
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
