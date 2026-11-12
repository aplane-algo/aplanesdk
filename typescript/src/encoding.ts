// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import type { Transaction } from "algosdk";
import { SignerError } from "./errors.js";

/**
 * Convert Uint8Array to hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Convert hex string to Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new SignerError("hex string must have even length");
  }
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new SignerError("invalid hex string");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Encode a transaction for signing.
 *
 * @param txn - algosdk Transaction object
 * @returns Tuple of [txnBytesHex, txnSender] where:
 *   - txnBytesHex = hex(b"TX" + msgpack(txn))
 *   - txnSender = sender address string
 */
export function encodeTransaction(txn: Transaction): [string, string] {
  // algosdk v3 uses toByte() to get the unsigned transaction bytes
  // This returns the raw msgpack without the "TX" prefix
  const msgpackBytes = txn.toByte();

  // Prepend "TX" prefix
  const txPrefix = new Uint8Array([84, 88]); // "TX"
  const txnBytes = new Uint8Array(txPrefix.length + msgpackBytes.length);
  txnBytes.set(txPrefix);
  txnBytes.set(msgpackBytes, txPrefix.length);

  // Get sender address
  const sender = txn.sender.toString();

  return [bytesToHex(txnBytes), sender];
}

/**
 * Encode LogicSig runtime arguments for the signer: each value as hex.
 * args must be a plain object of name to Uint8Array. Anything else is
 * refused, because it would otherwise be sent as different bytes with no
 * error: a string's characters are not its bytes, a number has none, and a
 * Map has no own entries.
 */
export function encodeLsigArgs(
  args: Record<string, Uint8Array>
): Record<string, string> {
  // Told by the internal type, which holds across realms: a Map, a Set and
  // an array are objects but not this.
  if (args === null || typeof args !== "object" || typeTag(args) !== "Object") {
    throw new SignerError(`lsigArgs must be an object of name to Uint8Array, not ${valueKind(args)}`);
  }
  const encoded: Record<string, string> = {};
  for (const [name, value] of Object.entries(args)) {
    if (!isUint8Array(value)) {
      throw new SignerError(`lsigArgs.${name} must be a Uint8Array, not ${valueKind(value)}`);
    }
    encoded[name] = bytesToHex(value);
  }
  return encoded;
}

/**
 * A map of auth address to LogicSig arguments, each entry encoded as
 * encodeLsigArgs does. Every entry is checked, whether or not a position
 * uses it: a Map in place of the object, or of one address's arguments, has
 * no own entries and would otherwise be passed over as empty. An entry that
 * is null or undefined has no arguments.
 */
export function encodeLsigArgsMap(
  map: Record<string, Record<string, Uint8Array>> | undefined | null
): Record<string, Record<string, string>> {
  const encoded: Record<string, Record<string, string>> = {};
  if (map === undefined || map === null) return encoded;
  if (typeof map !== "object" || typeTag(map) !== "Object") {
    throw new SignerError(`lsigArgsMap must be an object of auth address to arguments, not ${valueKind(map)}`);
  }
  for (const [address, args] of Object.entries(map)) {
    if (args === undefined || args === null) continue;
    encoded[address] = encodeLsigArgs(args);
  }
  return encoded;
}

/** The built-in type tag of value, such as "Uint8Array" or "DataView". */
function typeTag(value: unknown): string {
  return Object.prototype.toString.call(value).slice(8, -1);
}

/**
 * Whether value is a Uint8Array, a Node Buffer among them, told by its
 * internal type rather than by instanceof: a Uint8Array from another realm,
 * such as a vm context or a frame, is not an instance of this realm's class.
 * ArrayBuffer.isView reads the internal slot, so an object that only claims
 * the tag is not one. Another typed array or a DataView is not one either.
 */
export function isUint8Array(value: unknown): value is Uint8Array {
  return ArrayBuffer.isView(value) && typeTag(value) === "Uint8Array";
}

/**
 * name with its indefinite article: "an Int8Array", "a Uint8Array". The
 * names it gets begin with a U only as "Uint", which takes "a".
 */
function withArticle(name: string): string {
  return `${/^[AEIO]/i.test(name) ? "an" : "a"} ${name}`;
}

/**
 * What kind of value something is, for an error message: "null", "a
 * string", "an array", "a Uint8Array", "an algosdk Address", "a
 * Transaction", "an object" and so on. A typed array or a DataView is named
 * by its internal type, which holds across realms; an object whose
 * publicKey is 32 bytes is an algosdk Address, from any copy of algosdk;
 * another object is named by its class, or is "an object".
 */
export function valueKind(value: unknown): string {
  if (value === null || value === undefined) return String(value);
  if (Array.isArray(value)) return "an array";
  if (typeof value !== "object") return withArticle(typeof value);
  if (ArrayBuffer.isView(value)) return withArticle(typeTag(value));
  const publicKey = (value as { publicKey?: unknown }).publicKey;
  if (isUint8Array(publicKey) && publicKey.length === 32) return "an algosdk Address";
  const name = (value as { constructor?: { name?: unknown } }).constructor?.name;
  return typeof name === "string" && name !== "" && name !== "Object" ? withArticle(name) : "an object";
}

/**
 * A copy of one signed transaction a caller supplied, as a plain Uint8Array
 * of this realm. Anything else, such as a hex or base64 string, is refused,
 * and label names its position in the error.
 */
export function signedTransactionCopy(value: unknown, label: string): Uint8Array {
  if (!isUint8Array(value)) {
    throw new SignerError(`${label} must be signed transaction bytes (a Uint8Array), not ${valueKind(value)}`);
  }
  return new Uint8Array(value);
}

/** A copy of a signed group that shares no bytes with it. */
export function cloneSignedGroup(group: readonly Uint8Array[]): Uint8Array[] {
  return group.map((entry) => new Uint8Array(entry));
}

/**
 * The signer's hex entries of a signed group as bytes, one per transaction,
 * in order. An empty entry stays empty.
 */
export function signedGroupFromHex(signed: string[]): Uint8Array[] {
  return signed.map((entry, index) => {
    try {
      return hexToBytes(entry);
    } catch (error) {
      throw new SignerError(`signed transaction ${index + 1} is invalid hex: ${error instanceof Error ? error.message : String(error)}`);
    }
  });
}

// bytesToBase64 encodes bytes as base64, using Buffer in Node.js and a chunked
// btoa fallback in the browser. The chunking matters: String.fromCharCode(...big)
// spreads every byte as a function argument and throws on large inputs (e.g. a
// 16-transaction Falcon group is ~50 KB), so the bytes are converted in 32 KB
// blocks instead.
export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}
