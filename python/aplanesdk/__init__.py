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
    sign_guarded_group,
    sign_prepared_guarded_group,

    # Token provisioning
    request_token,
    request_token_to_file,

    # Utility
    load_token,
    load_config,

    # Exceptions
    ERR_CODE_BAD_REQUEST,
    ERR_CODE_UNAUTHORIZED,
    ERR_CODE_FORBIDDEN,
    ERR_CODE_LOCKED,
    ERR_CODE_NOT_FOUND,
    ERR_CODE_INVALID_PASSPHRASE,
    ERR_CODE_UNAVAILABLE,
    ERR_CODE_CACHE_REFRESH,
    ERR_CODE_INTERNAL,
    ERR_CODE_BOUNDED_ADMIN_REQUIRED,
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
    BoundedSignatureArgLayout,
    BoundedAdminOperationInfo,
    BoundedDerivedArgInfo,
    BoundedArgumentPathMask,
    BoundedArgumentSlotInfo,
    BoundedAuthorizationInfo,
    InputModeInfo,
    KeyInfo,
    SSHConfig,
    ClientConfig,
    CreationParam,
    KeyTypeInfo,
    ProtocolVersion,
    StatusResponse,
    CancelSignResponse,
    GroupSignResponse,
    GroupSimulateResponse,
    ErrorResponse,
    GenerateResult,
    ComponentSignRequest,
    ComponentSignature,
    ComponentSignResponse,
    GuardedAssemblyRequest,
    GuardedAssemblyTarget,
    GuardedSimulateRequest,
    GuardedSimulateTarget,
    GuardedSimulateResponse,
    GuardedPassthroughItem,
    GuardedAssemblyResponse,
    SentryReferenceCandidate,
    AdminSyncSentryReferencesRequest,
    SyncedSentryReferenceInfo,
    AdminSyncSentryReferencesResponse,
    GuardedSignTarget,
    GuardedPrimarySignTarget,
    GuardedSignResult,
    PreparedCheck,
    PreparedTransaction,
    PreparedGroup,
    ResolvedAuthAddress,
    COMPONENT_SIGN_ROLE_USER,
    COMPONENT_SIGN_ROLE_SENTRY,
    SIGNING_FLOW_SENTRY1,
    SIGNING_FLOW_BOUNDED1,
    KEY_TYPE_SENTRY_FALCON1024,
    KEY_TYPE_GUARDED_FALCON1024_SENTRY_FALCON1024,
)

__all__ = [
    # Main client
    "SignerClient",

    # Submission helpers
    "send_raw_transaction",
    "assemble_group",
    "sign_guarded_group",
    "sign_prepared_guarded_group",

    # Token provisioning
    "request_token",
    "request_token_to_file",

    # Utility
    "load_token",
    "load_config",

    # Exceptions
    "ERR_CODE_BAD_REQUEST",
    "ERR_CODE_UNAUTHORIZED",
    "ERR_CODE_FORBIDDEN",
    "ERR_CODE_LOCKED",
    "ERR_CODE_NOT_FOUND",
    "ERR_CODE_INVALID_PASSPHRASE",
    "ERR_CODE_UNAVAILABLE",
    "ERR_CODE_CACHE_REFRESH",
    "ERR_CODE_INTERNAL",
    "ERR_CODE_BOUNDED_ADMIN_REQUIRED",
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
    "BoundedSignatureArgLayout",
    "BoundedAdminOperationInfo",
    "BoundedDerivedArgInfo",
    "BoundedArgumentPathMask",
    "BoundedArgumentSlotInfo",
    "BoundedAuthorizationInfo",
    "InputModeInfo",
    "KeyInfo",
    "SSHConfig",
    "ClientConfig",
    "CreationParam",
    "KeyTypeInfo",
    "ProtocolVersion",
    "StatusResponse",
    "CancelSignResponse",
    "GroupSignResponse",
    "GroupSimulateResponse",
    "ErrorResponse",
    "GenerateResult",
    "ComponentSignRequest",
    "ComponentSignature",
    "ComponentSignResponse",
    "GuardedAssemblyRequest",
    "GuardedAssemblyTarget",
    "GuardedSimulateRequest",
    "GuardedSimulateTarget",
    "GuardedSimulateResponse",
    "GuardedPassthroughItem",
    "GuardedAssemblyResponse",
    "SentryReferenceCandidate",
    "AdminSyncSentryReferencesRequest",
    "SyncedSentryReferenceInfo",
    "AdminSyncSentryReferencesResponse",
    "GuardedSignTarget",
    "GuardedPrimarySignTarget",
    "GuardedSignResult",
    "PreparedCheck",
    "PreparedTransaction",
    "PreparedGroup",
    "ResolvedAuthAddress",
    "COMPONENT_SIGN_ROLE_USER",
    "COMPONENT_SIGN_ROLE_SENTRY",
    "SIGNING_FLOW_SENTRY1",
    "SIGNING_FLOW_BOUNDED1",
    "KEY_TYPE_SENTRY_FALCON1024",
    "KEY_TYPE_GUARDED_FALCON1024_SENTRY_FALCON1024",
]
