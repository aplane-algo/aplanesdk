// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import type {
  PreparedGroup,
  PreparedTransaction,
  SignRequest,
} from "./types.js";
import { PQ_SCHEME_FALCON1024, wireLogicSigResources } from "./types.js";
import { SignerError } from "./errors.js";
import { encodeLsigArgs, encodeTransaction, bytesToHex, signedTransactionCopy } from "./encoding.js";

/**
 * A copy of a prepared slot's pre-signed transaction, or undefined when the
 * slot has none: signedTransaction unset, null or empty. A value that is not
 * a Uint8Array, such as a string, is refused, with label naming it.
 */
export function preparedSignedTransaction(
  prepared: PreparedTransaction,
  label = "signedTransaction",
): Uint8Array | undefined {
  const value: unknown = prepared.signedTransaction;
  if (value === undefined || value === null) {
    return undefined;
  }
  const bytes = signedTransactionCopy(value, label);
  return bytes.length === 0 ? undefined : bytes;
}

/**
 * Convert one prepared transaction slot to a signer SignRequest entry.
 */
export function preparedTransactionToSignRequest(
  prepared: PreparedTransaction,
): SignRequest {
  const presigned = preparedSignedTransaction(prepared);
  if (presigned) {
    if (prepared.pqScheme) {
      throw new SignerError("pqScheme is allowed only for foreign transactions");
    }
    const request: SignRequest = {
      signed_txn_hex: bytesToHex(presigned),
    };
    if (prepared.lsigResources) {
      request.lsig_resources = wireLogicSigResources(
        prepared.lsigResources,
        "prepared passthrough lsigResources",
      );
    }
    return request;
  }

  if (!prepared.transaction) {
    throw new SignerError("transaction is required");
  }

  const [txnBytesHex, txnSender] = encodeTransaction(prepared.transaction);
  if (!prepared.authAddress) {
    const request: SignRequest = { txn_bytes_hex: txnBytesHex };
    if (prepared.lsigResources) {
      request.lsig_resources = wireLogicSigResources(
        prepared.lsigResources,
        "prepared foreign lsigResources",
      );
    }
    if (prepared.pqScheme) {
      if (request.lsig_resources) {
        throw new SignerError("foreign transaction cannot specify both pqScheme and lsigResources");
      }
      if (prepared.pqScheme !== PQ_SCHEME_FALCON1024) {
        throw new SignerError(`unsupported pqScheme ${JSON.stringify(prepared.pqScheme)}`);
      }
      request.pq_scheme = prepared.pqScheme;
    }
    return request;
  }

  if (prepared.pqScheme) {
    throw new SignerError("pqScheme is allowed only for foreign transactions");
  }
  if (prepared.lsigResources) {
    throw new SignerError(
      "lsigResources is allowed only for foreign or passthrough transactions",
    );
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
