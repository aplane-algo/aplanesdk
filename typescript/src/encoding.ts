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
 * Encode LogicSig args for the API request.
 * Converts Uint8Array values to hex strings.
 *
 * @param args - Map of argument name to Uint8Array value
 * @returns Map of argument name to hex-encoded value
 */
export function encodeLsigArgs(
  args: Record<string, Uint8Array>
): Record<string, string> {
  const encoded: Record<string, string> = {};
  for (const [name, value] of Object.entries(args)) {
    encoded[name] = bytesToHex(value);
  }
  return encoded;
}

/**
 * Concatenate signed transactions and convert to base64 for submission.
 *
 * @param signedHexes - Array of hex-encoded signed transactions
 * @returns Base64-encoded concatenated transactions ready for algod
 */
export function concatenateSignedTxns(signedHexes: string[]): string {
  // Calculate total length
  let totalLength = 0;
  const byteArrays: Uint8Array[] = [];
  for (const hex of signedHexes) {
    const bytes = hexToBytes(hex);
    byteArrays.push(bytes);
    totalLength += bytes.length;
  }

  // Concatenate all bytes
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const bytes of byteArrays) {
    combined.set(bytes, offset);
    offset += bytes.length;
  }

  return bytesToBase64(combined);
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
