// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import type {
  PreparedGroup,
  PreparedTransaction,
  SignRequest,
} from "./types.js";
import { SignerError } from "./errors.js";
import { encodeLsigArgs, encodeTransaction, bytesToHex } from "./encoding.js";

function base64ToHex(value: string): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(value, "base64").toString("hex");
  }
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytesToHex(bytes);
}

/**
 * Convert one prepared transaction slot to a signer SignRequest entry.
 */
export function preparedTransactionToSignRequest(
  prepared: PreparedTransaction,
): SignRequest {
  if (prepared.signedTransactionBase64) {
    return {
      signed_txn_hex: base64ToHex(prepared.signedTransactionBase64),
    };
  }

  if (!prepared.transaction) {
    throw new SignerError("transaction is required");
  }

  const [txnBytesHex, txnSender] = encodeTransaction(prepared.transaction);
  if (!prepared.authAddress) {
    const request: SignRequest = { txn_bytes_hex: txnBytesHex };
    if (prepared.lsigSize && prepared.lsigSize > 0) {
      request.lsig_size = prepared.lsigSize;
    }
    return request;
  }

  const request: SignRequest = {
    txn_bytes_hex: txnBytesHex,
    auth_address: prepared.authAddress,
    txn_sender: prepared.txnSender || txnSender,
  };
  if (prepared.lsigArgs) {
    request.lsig_args = encodeLsigArgs(prepared.lsigArgs);
  }
  if (prepared.appCallInfo) {
    request.app_call_info = prepared.appCallInfo;
  }
  return request;
}

/**
 * Convert a prepared group to signer SignRequest entries.
 */
export function preparedGroupToSignRequests(group: PreparedGroup): SignRequest[] {
  if (!group.transactions || group.transactions.length === 0) {
    throw new SignerError("prepared group is empty");
  }
  return group.transactions.map((item, index) => {
    try {
      return preparedTransactionToSignRequest(item);
    } catch (error) {
      if (error instanceof Error) {
        throw new SignerError(`prepared transaction ${index}: ${error.message}`);
      }
      throw error;
    }
  });
}
