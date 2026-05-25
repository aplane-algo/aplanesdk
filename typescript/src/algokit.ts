// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import { decodeAddress } from "algosdk";
import type { SignerClient } from "./client.js";
import { SignerError } from "./errors.js";
import { bytesToHex, encodeLsigArgs, hexToBytes } from "./encoding.js";
import type {
  GroupSignResponse,
  KeyInfo,
  LsigArgs,
  SignRequest,
  SignOptions,
} from "./types.js";

export type AlgoKitTransaction = {
  sender?: { toString(): string } | string;
};

export type AlgoKitTransactionSigner = (
  txnGroup: AlgoKitTransaction[],
  indexesToSign: number[],
) => Promise<Uint8Array[]>;

export type AlgoKitAddress = {
  readonly publicKey: Uint8Array;
  toString(): string;
  equals?(other: unknown): boolean;
};

type RequestsSignerClient = Pick<SignerClient, "signRequests" | "listKeys">;

export type AlgoKitTransactionEncoder = (
  txn: AlgoKitTransaction,
) => Uint8Array | Promise<Uint8Array>;

type AlgoKitEncoderModule = {
  encodeTransaction?: AlgoKitTransactionEncoder;
};

export interface ApsignerAccountOptions {
  /** Native APlane signer client. */
  client: RequestsSignerClient;
  /** Sending address exposed to AlgoKit as addr. */
  address: string;
  /** Apsigner key address to authorize the transaction. Defaults to address. */
  authAddress?: string;
  /** Runtime LogicSig args to send with each signed transaction. */
  lsigArgs?: LsigArgs;
  /** Optional factory that returns a caller-owned request ID per sign call. */
  newRequestId?: () => string;
  /** Optional cancellation signal for the /sign request. */
  signal?: AbortSignal;
  /** Override transaction encoding, mostly useful for tests. */
  encodeTransaction?: AlgoKitTransactionEncoder;
  /** Override the object exposed as addr. Defaults to an Algorand-address-compatible object. */
  addressObject?: AlgoKitAddress;
}

export interface ApsignerAccount {
  readonly addr: AlgoKitAddress;
  readonly authAddress: string;
  readonly signer: AlgoKitTransactionSigner;
}

class AlgorandAddressLike implements AlgoKitAddress {
  readonly publicKey: Uint8Array;

  constructor(private readonly value: string) {
    this.publicKey = decodeAddress(value).publicKey;
  }

  toString(): string {
    return this.value;
  }

  equals(other: unknown): boolean {
    if (!other) {
      return false;
    }
    if (typeof other === "string") {
      return other === this.value;
    }
    if (typeof (other as { toString?: unknown }).toString === "function") {
      return (other as { toString(): string }).toString() === this.value;
    }
    return false;
  }
}

async function dynamicImport<T>(specifier: string): Promise<T> {
  const importer = new Function("specifier", "return import(specifier)") as (
    specifier: string,
  ) => Promise<T>;
  return importer(specifier);
}

async function loadAlgoKitEncoder(
  specifier: string,
): Promise<AlgoKitTransactionEncoder | undefined> {
  try {
    const mod = await dynamicImport<AlgoKitEncoderModule>(specifier);
    return typeof mod.encodeTransaction === "function" ? mod.encodeTransaction : undefined;
  } catch {
    return undefined;
  }
}

async function defaultEncodeAlgoKitTransaction(txn: AlgoKitTransaction): Promise<Uint8Array> {
  const encodeTransaction =
    await loadAlgoKitEncoder("@algorandfoundation/algokit-utils/transact")
    ?? await loadAlgoKitEncoder("@algorandfoundation/algokit-transact");
  if (!encodeTransaction) {
    throw new SignerError(
      "AlgoKit transaction encoder not found; install @algorandfoundation/algokit-utils@10 or pass encodeTransaction",
    );
  }
  return encodeTransaction(txn);
}

function txnSender(txn: AlgoKitTransaction): string {
  const sender = txn.sender;
  if (typeof sender === "string") {
    return sender;
  }
  if (sender && typeof sender.toString === "function") {
    return sender.toString();
  }
  throw new SignerError("AlgoKit transaction is missing sender");
}

/**
 * AlgoKit AddressWithTransactionSigner adapter backed by apsigner.
 *
 * The adapter connects AlgoKit clients to APlane's transaction signing functions.
 */
export class ApsignerAlgoKitAccount implements ApsignerAccount {
  readonly addr: AlgoKitAddress;
  readonly authAddress: string;
  readonly signer: AlgoKitTransactionSigner;

  private readonly client: RequestsSignerClient;
  private readonly lsigArgs?: LsigArgs;
  private readonly newRequestId?: () => string;
  private readonly signal?: AbortSignal;
  private readonly encodeTransaction: AlgoKitTransactionEncoder;

  constructor(options: ApsignerAccountOptions) {
    this.client = options.client;
    this.addr = options.addressObject ?? new AlgorandAddressLike(options.address);
    this.authAddress = options.authAddress ?? options.address;
    this.lsigArgs = options.lsigArgs;
    this.newRequestId = options.newRequestId;
    this.signal = options.signal;
    this.encodeTransaction = options.encodeTransaction ?? defaultEncodeAlgoKitTransaction;
    this.signer = async (txnGroup, indexesToSign) => this.sign(txnGroup, indexesToSign);
  }

  private nextRequestId(): string | undefined {
    return this.newRequestId?.();
  }

  private async sign(
    txnGroup: AlgoKitTransaction[],
    indexesToSign: number[],
  ): Promise<Uint8Array[]> {
    if (indexesToSign.length === 0) {
      return [];
    }

    const requests: SignRequest[] = [];
    for (const index of indexesToSign) {
      if (index < 0 || index >= txnGroup.length) {
        throw new SignerError(`index ${index} out of range for ${txnGroup.length} transactions`);
      }
      const txn = txnGroup[index];
      if (!txn) {
        throw new SignerError(`transaction is required at index ${index}`);
      }

      const req: SignRequest = {
        txn_bytes_hex: bytesToHex(await this.encodeTransaction(txn)),
        txn_sender: txnSender(txn),
        auth_address: this.authAddress,
      };
      if (this.lsigArgs) {
        req.lsig_args = encodeLsigArgs(this.lsigArgs);
      }
      requests.push(req);
    }

    const response = await this.client.signRequests(
      requests,
      {
        requestId: this.nextRequestId(),
        signal: this.signal,
      } satisfies SignOptions,
    );

    const signed = response.signed ?? [];
    if (signed.length < indexesToSign.length) {
      throw new SignerError(
        "apsigner returned fewer signed transactions than AlgoKit requested",
      );
    }

    return signed.map((hex) => hexToBytes(hex));
  }
}

export function createApsignerAccount(options: ApsignerAccountOptions): ApsignerAccount {
  return new ApsignerAlgoKitAccount(options);
}

export async function listApsignerAccounts(
  client: RequestsSignerClient,
  options: { refresh?: boolean } = {},
): Promise<ApsignerAccount[]> {
  const keys: KeyInfo[] = await client.listKeys(options.refresh ?? false);
  return keys.map((key) => createApsignerAccount({
    client,
    address: key.address,
    authAddress: key.address,
  }));
}

export type { GroupSignResponse };
