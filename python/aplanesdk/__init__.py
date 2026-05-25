# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""
APlane Python SDK - Transaction signing via apsigner

Data directory: required via data_dir parameter or APCLIENT_DATA env var

Token provisioning:
    from aplanesdk import request_token_to_file
    request_token_to_file()  # operator must approve in apadmin

Usage:
    from aplanesdk import SignerClient, send_raw_transaction

    client = SignerClient.from_env()
    signed_txn = client.sign_transaction(txn)
    txid = send_raw_transaction(algod_client, signed_txn)
    client.close()
"""
from ._version import __version__

from .signer import (
    # Main client
    SignerClient,

    # Submission helpers
    send_raw_transaction,
    assemble_group,

    # Token provisioning
    request_token,
    request_token_to_file,

    # Utility
    load_token,
    load_config,

    # Exceptions
    SignerError,
    AuthenticationError,
    SigningRejectedError,
    SignerUnavailableError,
    KeyNotFoundError,
    KeyDeletionError,
    TokenProvisioningError,
    TransactionRejectedError,
    LogicSigRejectedError,
    InsufficientFundsError,
    InvalidTransactionError,

    # Types
    RuntimeArg,
    SigningArg,
    InputModeInfo,
    KeyInfo,
    SSHConfig,
    ClientConfig,
    CreationParam,
    KeyTypeInfo,
    StatusResponse,
    CancelSignResponse,
    GroupSignResponse,
    ErrorResponse,
    GenerateResult,
)

__all__ = [
    # Main client
    "SignerClient",

    # Submission helpers
    "send_raw_transaction",
    "assemble_group",

    # Token provisioning
    "request_token",
    "request_token_to_file",

    # Utility
    "load_token",
    "load_config",

    # Exceptions
    "SignerError",
    "AuthenticationError",
    "SigningRejectedError",
    "SignerUnavailableError",
    "KeyNotFoundError",
    "KeyDeletionError",
    "TokenProvisioningError",
    "TransactionRejectedError",
    "LogicSigRejectedError",
    "InsufficientFundsError",
    "InvalidTransactionError",

    # Types
    "RuntimeArg",
    "SigningArg",
    "InputModeInfo",
    "KeyInfo",
    "SSHConfig",
    "ClientConfig",
    "CreationParam",
    "KeyTypeInfo",
    "StatusResponse",
    "CancelSignResponse",
    "GroupSignResponse",
    "ErrorResponse",
    "GenerateResult",
]
