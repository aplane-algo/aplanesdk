// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { createHash } from "crypto";

/** The domain the Witness Key ID digest is taken under. */
const WITNESS_KEY_ID_DOMAIN = "APLANE_WITNESS_KEY_ID_V1";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 base32, uppercase, without padding. */
function base32NoPadding(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(buffer >> bits) & 31];
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(buffer << (5 - bits)) & 31];
  }
  return out;
}

/** value prefixed by its length as a 4-byte big-endian integer. */
function lengthPrefixed(value: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + value.length);
  new DataView(out.buffer).setUint32(0, value.length, false);
  out.set(value, 4);
  return out;
}

/**
 * The Witness Key ID of a witness key: base32 (uppercase, no padding) of
 * SHA-512/256 over the domain, the key type and the raw public key, each
 * prefixed by its length. 52 characters. The key type is opaque here: the
 * public key's length is not checked against it.
 */
export function witnessKeyId(keyType: string, publicKey: Uint8Array): string {
  const hash = createHash("sha512-256");
  hash.update(lengthPrefixed(new TextEncoder().encode(WITNESS_KEY_ID_DOMAIN)));
  hash.update(lengthPrefixed(new TextEncoder().encode(keyType)));
  hash.update(lengthPrefixed(publicKey));
  return base32NoPadding(new Uint8Array(hash.digest()));
}
