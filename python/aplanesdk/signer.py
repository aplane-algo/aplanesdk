# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""
APlane Python SDK - Transaction signing via apsigner

Data directory (required via APCLIENT_DATA env var or data_dir parameter):
    <data_dir>/
    ├── aplane.token         # API token (from request_token_to_file)
    ├── config.yaml          # Connection settings
    └── .ssh/
        └── id_ed25519       # SSH key for authentication

Example config.yaml:
    endpoint:
      signer_port: 11270
      ssh:
        host: signer.example.com
        port: 1127
        identity_file: .ssh/id_ed25519

Token Provisioning:
    from aplanesdk import request_token_to_file

    # Request token (operator must approve in apadmin)
    request_token_to_file()  # reads APCLIENT_DATA from environment

Usage:
    from aplanesdk import SignerClient

    client = SignerClient.from_env()  # reads APCLIENT_DATA from environment
    signed_txn = client.sign_transaction(txn)
    client.close()

Data directory is required:
    export APCLIENT_DATA=/path/to/apclient
    # or pass data_dir parameter to from_env()
"""

from __future__ import annotations

import base64
import json
import os
import re
import requests
import secrets
import socket
import time
from dataclasses import asdict, dataclass, is_dataclass
from typing import Optional, Dict, List, Any, Callable

from algosdk import encoding, transaction

import paramiko


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Default ports (match apshell/apsigner defaults)
DEFAULT_SSH_PORT = 1127
DEFAULT_SIGNER_PORT = 11270
HEALTH_TIMEOUT = 3
STATUS_TIMEOUT = 5
INVENTORY_TIMEOUT = 30
MUTATION_TIMEOUT = 60
GROUP_PLAN_TIMEOUT = 60
COMPONENT_SIGN_TIMEOUT = 120
GUARDED_ASSEMBLY_TIMEOUT = 120
SIGN_CANCEL_TIMEOUT = 5
SIGN_APPROVAL_SLACK = 30
DEFAULT_SIGN_REQUEST_TIMEOUT = 360
MAX_DISCOVERED_APPROVAL_WAIT = 30 * 60
APPROVAL_WAIT_REFRESH = 5 * 60
MAX_SIGN_REQUEST_ID_LENGTH = 128
MAX_COMPONENT_GROUP_SIZE = 16

COMPONENT_SIGN_ROLE_USER = "user"
COMPONENT_SIGN_ROLE_SENTRY = "sentry"

KEY_TYPE_SENTRY_ED25519 = "aplane.sentry-ed25519.v1"
KEY_TYPE_SENTRY_FALCON1024 = "aplane.sentry-falcon1024.v1"
KEY_TYPE_GUARDED_FALCON1024_SENTRY_ED25519 = "aplane.falcon1024-sentry-ed25519.v1"
KEY_TYPE_GUARDED_FALCON1024_SENTRY_FALCON1024 = "aplane.falcon1024-sentry-falcon1024.v1"

# Current product identity for token provisioning helpers.
DEFAULT_PRODUCT_IDENTITY = "default"


def _resolve_data_dir(data_dir: Optional[str]) -> str:
    """Resolve client data directory from param > APCLIENT_DATA.

    Raises SignerError when neither is set; the SDK has no implicit default.
    """
    resolved = data_dir or os.environ.get("APCLIENT_DATA")
    if not resolved:
        raise SignerError(
            "client data directory not specified: pass data_dir or set APCLIENT_DATA"
        )
    return os.path.expanduser(resolved)


def _require_current_product_identity(identity: str) -> None:
    """Reject unsupported non-product identities in single-operator helpers."""
    if identity != DEFAULT_PRODUCT_IDENTITY:
        raise SignerError(
            f"unsupported identity: {identity} "
            f"(only {DEFAULT_PRODUCT_IDENTITY!r} is currently supported)"
        )


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------

class SignerError(Exception):
    """Base exception for signer errors"""
    pass


class AuthenticationError(SignerError):
    """Token invalid or missing"""
    pass


class SigningRejectedError(SignerError):
    """Operator rejected the signing request"""
    pass


class SignerUnavailableError(SignerError):
    """Signer not reachable or locked"""
    pass


class KeyNotFoundError(SignerError):
    """Requested auth_address not found in signer"""
    pass


class TokenProvisioningError(SignerError):
    """Token provisioning failed (rejected or no operator)"""
    pass


class KeyDeletionError(SignerError):
    """Key deletion failed (not found or other error)"""
    pass


class TransactionRejectedError(SignerError):
    """Transaction was rejected by the network."""
    def __init__(self, txid: str, reason: str):
        self.txid = txid
        self.reason = reason
        super().__init__(f"Transaction {txid} rejected: {reason}")


class LogicSigRejectedError(TransactionRejectedError):
    """LogicSig program returned false."""
    pass


class InsufficientFundsError(TransactionRejectedError):
    """Account has insufficient funds for the transaction."""
    pass


class InvalidTransactionError(TransactionRejectedError):
    """Transaction is malformed or invalid."""
    pass


# -----------------------------------------------------------------------------
# Types
# -----------------------------------------------------------------------------

@dataclass
class RuntimeArg:
    """Runtime argument specification for a generic LogicSig"""
    name: str
    arg_type: str  # "bytes", "uint64", etc.
    description: str = ""
    label: str = ""
    required: bool = False
    byte_length: int = 0


# /keys exposes key-file-owned signing_args with the same item shape.
SigningArg = RuntimeArg


@dataclass
class KeyInfo:
    """Information about a signing key"""
    address: str
    key_type: str
    public_key_hex: str = ""
    lsig_size: int = 0
    is_generic_lsig: bool = False
    is_component_key: bool = False
    is_spending_account: Optional[bool] = None
    signing_args: Optional[List[SigningArg]] = None  # Key-file args required for LogicSigs
    parameters: Optional[Dict[str, str]] = None
    template_provenance_status: str = ""
    template_provenance_note: str = ""
    template_status: str = ""  # Legacy alias for template_provenance_status
    template_warning: str = ""  # Legacy alias for template_provenance_note


@dataclass
class SSHConfig:
    """SSH tunnel configuration (token is used as SSH username for 2FA)"""
    host: str  # Remote host to SSH to
    port: int = DEFAULT_SSH_PORT
    identity_file: str = ".ssh/id_ed25519"  # Relative to data_dir
    known_hosts_path: str = ".ssh/known_hosts"  # Relative to data_dir
    trust_on_first_use: bool = False  # If true, auto-trust unknown host keys (TOFU)


@dataclass
class ClientConfig:
    """Client configuration loaded from config.yaml"""
    signer_port: int = DEFAULT_SIGNER_PORT
    ssh: Optional[SSHConfig] = None  # Required in config.yaml


@dataclass
class InputModeInfo:
    """Alternate UI input mode for a creation parameter"""
    name: str
    label: str = ""
    transform: str = ""
    byte_length: int = 0
    input_type: str = ""


@dataclass
class CreationParam:
    """Parameter specification for key generation"""
    name: str
    label: str
    description: str = ""
    param_type: str = ""  # "address", "address[]", "uint64", "string", "bytes"
    required: bool = False
    max_length: int = 0
    input_modes: Optional[List[InputModeInfo]] = None
    min_items: int = 0
    max_items: int = 0
    options: Optional[List[str]] = None
    min: Optional[int] = None
    max: Optional[int] = None
    example: str = ""
    placeholder: str = ""
    default: str = ""


@dataclass
class KeyTypeInfo:
    """Information about an available key type"""
    key_type: str
    family: str
    display_name: str = ""
    description: str = ""
    requires_logicsig: bool = False
    mnemonic_word_count: int = 0
    mnemonic_import: bool = False
    mnemonic_scheme: str = ""
    creation_params: Optional[List[CreationParam]] = None
    runtime_args: Optional[List[RuntimeArg]] = None


@dataclass
class StatusResponse:
    """Authenticated signer status from /status"""
    identity_id: str
    state: str
    signer_locked: bool
    ready_for_signing: bool
    key_count: int
    keyset_revision: int
    approval_wait_seconds: int = 0
    node_role: str = ""


@dataclass
class CancelSignResponse:
    """Response from /sign/cancel"""
    success: bool
    state: str = ""
    error: str = ""


@dataclass
class GroupSignResponse:
    """Response from /sign"""
    signed: List[str]
    mutations: Optional[Dict[str, Any]] = None
    error: str = ""


@dataclass
class ComponentSignRequest:
    """Request payload for /sign/component"""
    role: str
    group_bytes_hex: List[str]
    target_indices: List[int]
    request_id: str = ""
    component_key: str = ""


@dataclass
class ComponentSignature:
    """One component signature returned from /sign/component"""
    target_index: int
    signature: str
    signature_scheme: str


@dataclass
class ComponentSignResponse:
    """Response payload from /sign/component"""
    request_id: str
    signatures: List[ComponentSignature]
    component_key: str = ""


@dataclass
class GuardedAssemblyTarget:
    """One guarded-account position for /sign/assemble"""
    target_index: int
    guarded_account: str
    user_signature: str
    sentry_signature: str
    user_source_request_id: str = ""
    sentry_source_request_id: str = ""
    runtime_args: Optional[List[str]] = None


@dataclass
class GuardedPassthroughItem:
    """Already-signed group position for /sign/assemble"""
    target_index: int
    signed_txn_hex: str


@dataclass
class GuardedAssemblyRequest:
    """Request payload for /sign/assemble"""
    group_bytes_hex: List[str]
    request_id: str = ""
    targets: Optional[List[GuardedAssemblyTarget]] = None
    passthrough: Optional[List[GuardedPassthroughItem]] = None


@dataclass
class GuardedAssemblyResponse:
    """Response payload from /sign/assemble"""
    request_id: str
    signed_group: List[str]


@dataclass
class SentryReferenceCandidate:
    """Public sentry metadata synced into the signer reference catalog"""
    endpoint_alias: str
    component_key: str
    key_type: str
    public_key_hex: str
    last_seen_at: str = ""


@dataclass
class AdminSyncSentryReferencesRequest:
    """Request payload for /admin/sentries/sync"""
    candidates: List[SentryReferenceCandidate]


@dataclass
class SyncedSentryReferenceInfo:
    """Signer-local sentry reference after sync"""
    name: str
    source: str
    component_key: str
    key_type: str
    public_key_hex: str
    endpoint_alias: str = ""
    last_seen_at: str = ""
    synced_at: str = ""


@dataclass
class AdminSyncSentryReferencesResponse:
    """Response payload from /admin/sentries/sync"""
    added: int
    updated: int
    removed: int
    count: int
    records: Optional[List[SyncedSentryReferenceInfo]] = None
    error: str = ""


@dataclass
class GuardedSignTarget:
    """One guarded-account slot for the high-level guarded signing helper"""
    target_index: int
    guarded_account: str
    sentry_public_key_hex: str = ""
    sentry_component_key_type: str = ""
    sentry_component_key: str = ""
    runtime_args: Optional[List[str]] = None


@dataclass
class GuardedPrimarySignTarget:
    """One non-guarded slot signed by the primary/user signer before assembly"""
    target_index: int
    auth_address: str
    txn_sender: str = ""
    lsig_args: Optional[Dict[str, str]] = None
    lsig_size: int = 0
    app_call_info: Optional[Dict[str, str]] = None


@dataclass
class GuardedSignResult:
    """Result from sign_guarded_group"""
    signed_group: List[str]
    user_component_responses: List[ComponentSignResponse]
    sentry_component_responses: List[ComponentSignResponse]
    assembly_response: GuardedAssemblyResponse
    primary_sign_response: Optional[GroupSignResponse] = None


@dataclass
class PreparedCheck:
    """SDK-side preflight information collected during intent preparation."""
    name: str
    status: str = ""
    message: str = ""
    data: Optional[Dict[str, Any]] = None


@dataclass
class PreparedTransaction:
    """One prepared transaction slot before apsigner planning/signing."""
    transaction: Optional[transaction.Transaction] = None
    auth_address: Optional[str] = None
    txn_sender: str = ""
    signer_key: Optional[KeyInfo] = None
    lsig_args: Optional[Dict[str, bytes]] = None
    lsig_size: int = 0
    app_call_info: Optional[Dict[str, str]] = None
    signed_transaction_base64: str = ""
    checks: Optional[List[PreparedCheck]] = None

    def to_sign_request(self) -> Dict[str, Any]:
        """Convert this prepared slot to a signer SignRequest entry."""
        if self.signed_transaction_base64:
            try:
                signed_hex = base64.b64decode(
                    self.signed_transaction_base64,
                    validate=True,
                ).hex()
            except Exception as e:
                raise ValueError(
                    f"invalid passthrough transaction: {e}"
                ) from e
            return {"signed_txn_hex": signed_hex}

        if self.transaction is None:
            raise ValueError("transaction is required")

        txn_bytes_hex, txn_sender = encode_transaction(self.transaction)
        if not self.auth_address:
            request: Dict[str, Any] = {"txn_bytes_hex": txn_bytes_hex}
            if self.lsig_size > 0:
                request["lsig_size"] = self.lsig_size
            return request

        request = {
            "txn_bytes_hex": txn_bytes_hex,
            "auth_address": self.auth_address,
            "txn_sender": self.txn_sender or txn_sender,
        }
        if self.lsig_args:
            request["lsig_args"] = {
                name: value.hex()
                for name, value in self.lsig_args.items()
            }
        if self.app_call_info:
            request["app_call_info"] = self.app_call_info
        return request


@dataclass
class PreparedGroup:
    """Ordered group of prepared transaction slots."""
    transactions: List[PreparedTransaction]
    checks: Optional[List[PreparedCheck]] = None

    def to_sign_requests(self) -> List[Dict[str, Any]]:
        """Convert this group to signer SignRequest entries."""
        if not self.transactions:
            raise ValueError("prepared group is empty")
        requests = []
        for index, item in enumerate(self.transactions):
            try:
                requests.append(item.to_sign_request())
            except Exception as e:
                raise ValueError(f"prepared transaction {index}: {e}") from e
        return requests


@dataclass
class ResolvedAuthAddress:
    """Effective signer information for one account."""
    address: str
    auth_address: str
    is_rekeyed: bool
    key_info: KeyInfo


@dataclass
class ErrorResponse:
    """Standard signer HTTP error body for non-2xx responses"""
    error: str


@dataclass
class GenerateResult:
    """Result of key generation"""
    address: str
    key_type: str
    public_key_hex: str = ""
    is_component_key: bool = False
    is_spending_account: Optional[bool] = None
    parameters: Optional[Dict[str, str]] = None


def load_config(data_dir: str) -> ClientConfig:
    """
    Load client configuration from data_dir/config.yaml.

    Args:
        data_dir: Path to data directory

    Returns:
        ClientConfig with values from file, defaults for missing fields
    """
    import yaml

    config_path = os.path.join(data_dir, "config.yaml")
    config = ClientConfig()

    if not os.path.exists(config_path):
        return config

    try:
        with open(config_path, "r") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise SignerError(f"failed to parse config.yaml: {e}") from e

    endpoint_data = data.get("endpoint") or {}
    if not isinstance(endpoint_data, dict):
        raise SignerError("endpoint must be a mapping in config.yaml")

    if "signer_port" in endpoint_data:
        config.signer_port = int(endpoint_data["signer_port"])

    # Parse nested SSH config (if present, SSH tunnel is enabled)
    if "ssh" in endpoint_data and endpoint_data["ssh"]:
        ssh_data = endpoint_data["ssh"]
        if "host" not in ssh_data:
            raise SignerError("endpoint.ssh.host is required when endpoint.ssh block is present")
        config.ssh = SSHConfig(
            host=ssh_data["host"],
            port=ssh_data.get("port", DEFAULT_SSH_PORT),
            identity_file=ssh_data.get("identity_file", ".ssh/id_ed25519"),
            known_hosts_path=ssh_data.get("known_hosts_path", ".ssh/known_hosts"),
            trust_on_first_use=ssh_data.get("trust_on_first_use", False),
        )

    return config


# -----------------------------------------------------------------------------
# Transaction Encoding
# -----------------------------------------------------------------------------

def encode_transaction(txn: transaction.Transaction) -> tuple:
    """
    Encode transaction for signing.

    Returns:
        (txn_bytes_hex, txn_sender) where:
        - txn_bytes_hex = hex(b"TX" + msgpack(txn))
        - txn_sender = advisory display hint; signer authority comes from txn bytes
    """
    # Encode transaction to msgpack (algosdk returns base64 string)
    msgpack_b64 = encoding.msgpack_encode(txn)
    txn_bytes = b"TX" + base64.b64decode(msgpack_b64)

    return txn_bytes.hex(), txn.sender


def _new_sign_request_id() -> str:
    return f"sdk-{secrets.token_hex(16)}"


def _validate_sign_request_id(request_id: str, *, required: bool = False) -> None:
    if not request_id:
        if required:
            raise ValueError("request_id is required")
        return
    if len(request_id) > MAX_SIGN_REQUEST_ID_LENGTH:
        raise ValueError("request_id is too long")
    for ch in request_id:
        if ch.isalnum() or ch in "-_.:":
            continue
        raise ValueError(f"request_id contains invalid character {ch!r}")


def _compact_payload(value: Any) -> Any:
    """Convert dataclass payloads to JSON dictionaries and drop None values."""
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        return {
            key: _compact_payload(item)
            for key, item in value.items()
            if item is not None
        }
    if isinstance(value, list):
        return [_compact_payload(item) for item in value]
    return value


def _validate_component_group_bytes(items: List[str]) -> None:
    if not items:
        raise ValueError("group_bytes_hex is empty")
    if len(items) > MAX_COMPONENT_GROUP_SIZE:
        raise ValueError(
            f"group_bytes_hex length {len(items)} exceeds max {MAX_COMPONENT_GROUP_SIZE}"
        )
    for index, item in enumerate(items):
        if not item:
            raise ValueError(f"group_bytes_hex {index} is empty")


def _validate_component_target_indices(indices: List[int], group_len: int) -> None:
    if not indices:
        raise ValueError("target_indices is empty")
    seen = set()
    for index in indices:
        if not isinstance(index, int) or index < 0 or index >= group_len:
            raise ValueError(f"target_indices {index} out of range")
        if index in seen:
            raise ValueError(f"target_indices contains duplicate {index}")
        seen.add(index)


def _validate_assembly_index(index: int, group_len: int, covered: set) -> None:
    if not isinstance(index, int) or index < 0 or index >= group_len:
        raise ValueError(f"target_index {index} out of range")
    if index in covered:
        raise ValueError(f"duplicate target_index {index}")
    covered.add(index)


def _validate_component_sign_request(data: Dict[str, Any]) -> None:
    _validate_sign_request_id(str(data.get("request_id", "")))
    role = data.get("role", "")
    if role == COMPONENT_SIGN_ROLE_USER:
        if not data.get("component_key"):
            raise ValueError("component_key is required for user role")
    elif role != COMPONENT_SIGN_ROLE_SENTRY:
        raise ValueError(
            f"role must be {COMPONENT_SIGN_ROLE_USER!r} or {COMPONENT_SIGN_ROLE_SENTRY!r}"
        )
    group_bytes_hex = data.get("group_bytes_hex") or []
    target_indices = data.get("target_indices") or []
    _validate_component_group_bytes(group_bytes_hex)
    _validate_component_target_indices(target_indices, len(group_bytes_hex))


def _validate_component_sign_response(data: Dict[str, Any]) -> None:
    request_id = data.get("request_id", "")
    if not request_id:
        raise ValueError("request_id is required")
    _validate_sign_request_id(str(request_id))
    signatures = data.get("signatures") or []
    if not signatures:
        raise ValueError("signatures array is empty")
    seen = set()
    for i, signature in enumerate(signatures, start=1):
        target_index = signature.get("target_index")
        if not isinstance(target_index, int) or target_index < 0:
            raise ValueError(f"signature {i}: target_index must be non-negative")
        if target_index in seen:
            raise ValueError(f"signature {i}: duplicate target_index {target_index}")
        seen.add(target_index)
        if not signature.get("signature"):
            raise ValueError(f"signature {i}: signature is required")
        if not signature.get("signature_scheme"):
            raise ValueError(f"signature {i}: signature_scheme is required")


def _validate_guarded_assembly_request(data: Dict[str, Any]) -> None:
    _validate_sign_request_id(str(data.get("request_id", "")))
    group_bytes_hex = data.get("group_bytes_hex") or []
    targets = data.get("targets") or []
    passthrough = data.get("passthrough") or []
    _validate_component_group_bytes(group_bytes_hex)
    if not targets and not passthrough:
        raise ValueError("targets or passthrough is required")

    covered = set()
    for i, target in enumerate(targets, start=1):
        _validate_assembly_index(target.get("target_index"), len(group_bytes_hex), covered)
        if not target.get("guarded_account"):
            raise ValueError(f"target {i}: guarded_account is required")
        if not target.get("user_signature"):
            raise ValueError(f"target {i}: user_signature is required")
        if not target.get("sentry_signature"):
            raise ValueError(f"target {i}: sentry_signature is required")
        _validate_sign_request_id(str(target.get("user_source_request_id", "")))
        _validate_sign_request_id(str(target.get("sentry_source_request_id", "")))

    for i, item in enumerate(passthrough, start=1):
        _validate_assembly_index(item.get("target_index"), len(group_bytes_hex), covered)
        if not item.get("signed_txn_hex"):
            raise ValueError(f"passthrough {i}: signed_txn_hex is required")

    for index in range(len(group_bytes_hex)):
        if index not in covered:
            raise ValueError(
                f"group position {index} is not covered by targets or passthrough"
            )


def _validate_guarded_assembly_response(data: Dict[str, Any]) -> None:
    request_id = data.get("request_id", "")
    if not request_id:
        raise ValueError("request_id is required")
    _validate_sign_request_id(str(request_id))
    signed_group = data.get("signed_group") or []
    if not signed_group:
        raise ValueError("signed_group is empty")
    for index, signed in enumerate(signed_group):
        if not signed:
            raise ValueError(f"signed_group {index} is empty")


def _extract_auth_address(account_info: Any) -> str:
    if account_info is None:
        return ""
    if isinstance(account_info, str):
        return account_info
    if isinstance(account_info, dict):
        return (
            account_info.get("auth-addr")
            or account_info.get("auth_addr")
            or account_info.get("authAddr")
            or ""
        )
    return (
        getattr(account_info, "auth_addr", "")
        or getattr(account_info, "authAddr", "")
        or getattr(account_info, "auth_address", "")
        or ""
    )


def _find_spendable_key(keys: List[KeyInfo], address: str) -> Optional[KeyInfo]:
    for key in keys:
        if key.address != address:
            continue
        if key.is_spending_account is False:
            continue
        return key
    return None


def _apply_prep_fee(params: Any, fee: Optional[int], use_flat_fee: bool) -> None:
    if fee is None:
        return
    params.fee = fee
    params.flat_fee = use_flat_fee


def _account_amount(account_info: Any) -> int:
    if isinstance(account_info, dict):
        return int(account_info.get("amount", 0))
    return int(getattr(account_info, "amount", 0))


def _account_min_balance(account_info: Any) -> int:
    if isinstance(account_info, dict):
        return int(account_info.get("min-balance") or account_info.get("min_balance") or 0)
    return int(
        getattr(account_info, "min_balance", None)
        or getattr(account_info, "minBalance", 0)
    )


def _account_asset_holding(account_info: Any, asset_id: int) -> Optional[Any]:
    assets = account_info.get("assets", []) if isinstance(account_info, dict) else getattr(account_info, "assets", [])
    for holding in assets or []:
        if isinstance(holding, dict):
            holding_id = holding.get("asset-id") or holding.get("asset_id")
            deleted = holding.get("deleted", False)
        else:
            holding_id = getattr(holding, "asset_id", None) or getattr(holding, "assetId", None)
            deleted = getattr(holding, "deleted", False)
        if int(holding_id or 0) == asset_id and not deleted:
            return holding
    return None


def _asset_holding_amount(holding: Any) -> int:
    if isinstance(holding, dict):
        return int(holding.get("amount", 0))
    return int(getattr(holding, "amount", 0))


# -----------------------------------------------------------------------------
# Signer Client
# -----------------------------------------------------------------------------


def _find_free_port() -> int:
    """Find an available local port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class _SSHTunnel:
    """
    Lightweight SSH local port forward using paramiko directly.

    Replaces sshtunnel dependency. Forwards local_port on 127.0.0.1 to
    remote_host:remote_port through the SSH connection.
    """

    def __init__(
        self,
        ssh_host: str,
        ssh_port: int,
        ssh_username: str,
        ssh_pkey_path: str,
        remote_host: str,
        remote_port: int,
        local_port: int,
        known_hosts_path: str = "",
        trust_on_first_use: bool = False,
    ):
        self._transport: Optional[paramiko.Transport] = None
        self._ssh_client: Optional[paramiko.SSHClient] = None
        self._server_socket: Optional[socket.socket] = None
        self._threads: list = []
        self._running = False

        self._ssh_host = ssh_host
        self._ssh_port = ssh_port
        self._ssh_username = ssh_username
        self._ssh_pkey_path = ssh_pkey_path
        self._remote_host = remote_host
        self._remote_port = remote_port
        self.local_bind_port = local_port
        self._known_hosts_path = known_hosts_path
        self._trust_on_first_use = trust_on_first_use

    def start(self):
        """Establish SSH connection and start local port forward listener."""
        import threading

        if not self._known_hosts_path:
            raise SignerError(
                "known_hosts path is required for SSH host key verification"
            )

        # Load key
        try:
            pkey = paramiko.Ed25519Key.from_private_key_file(self._ssh_pkey_path)
        except paramiko.ssh_exception.SSHException:
            try:
                pkey = paramiko.RSAKey.from_private_key_file(self._ssh_pkey_path)
            except paramiko.ssh_exception.SSHException as e:
                raise SignerError(f"Failed to load SSH key: {e}")

        # Use SSHClient for host key verification (TOFU)
        client = paramiko.SSHClient()

        # Load existing known hosts if available
        if os.path.exists(self._known_hosts_path):
            client.load_host_keys(self._known_hosts_path)

        # Set host key policy based on trust_on_first_use
        if self._trust_on_first_use:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        try:
            client.connect(
                hostname=self._ssh_host,
                port=self._ssh_port,
                username=self._ssh_username,
                pkey=pkey,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.ssh_exception.SSHException as e:
            err_msg = str(e)
            if "not match" in err_msg.lower() or "mismatch" in err_msg.lower():
                raise SignerError(
                    f"SSH host key mismatch for {self._ssh_host}:{self._ssh_port} "
                    f"(possible MITM attack); remove the old key from "
                    f"{self._known_hosts_path} to connect"
                )
            if "not found in known_hosts" in err_msg.lower() or "reject" in err_msg.lower():
                raise SignerError(
                    f"Unknown SSH host key for {self._ssh_host}:{self._ssh_port}; "
                    f"to trust this host, set endpoint.ssh.trust_on_first_use: true in config.yaml, "
                    f"or connect via apshell first to save the host key to "
                    f"{self._known_hosts_path}"
                )
            raise SignerError(f"SSH connection failed: {e}")

        # Save updated known hosts when TOFU is enabled (includes newly added keys)
        if self._trust_on_first_use:
            known_hosts_dir = os.path.dirname(self._known_hosts_path)
            if known_hosts_dir and not os.path.exists(known_hosts_dir):
                os.makedirs(known_hosts_dir, mode=0o700)
            client.save_host_keys(self._known_hosts_path)

        self._ssh_client = client
        self._transport = client.get_transport()

        # Start local listener
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(('127.0.0.1', self.local_bind_port))
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)
        self._running = True

        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()
        self._threads.append(accept_thread)

    def _accept_loop(self):
        """Accept local connections and forward through SSH channel."""
        import threading

        while self._running:
            try:
                client_sock, _ = self._server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                channel = self._transport.open_channel(
                    'direct-tcpip',
                    (self._remote_host, self._remote_port),
                    client_sock.getpeername(),
                )
            except Exception:
                client_sock.close()
                continue

            if channel is None:
                client_sock.close()
                continue

            # Shuttle data in both directions
            t1 = threading.Thread(
                target=self._forward, args=(client_sock, channel), daemon=True
            )
            t2 = threading.Thread(
                target=self._forward, args=(channel, client_sock), daemon=True
            )
            t1.start()
            t2.start()
            self._threads.extend([t1, t2])

    @staticmethod
    def _forward(src, dst):
        """Copy data from src to dst until EOF or error."""
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass
            try:
                src.close()
            except Exception:
                pass

    def stop(self):
        """Tear down the tunnel."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
            self._server_socket = None
        if self._ssh_client:
            try:
                self._ssh_client.close()
            except Exception:
                pass
            self._ssh_client = None
            self._transport = None  # Transport is owned by SSHClient
        elif self._transport:
            try:
                self._transport.close()
            except Exception:
                pass
            self._transport = None


class SignerClient:
    """
    Client for apsigner signing service.

    Use class methods to create:
        # From config (recommended)
        client = SignerClient.from_env()

        # Explicit SSH tunnel
        client = SignerClient.connect_ssh(
            host="signer.example.com",
            token="...",
            ssh_key_path="~/.ssh/id_ed25519"
        )

        # Sign transactions
        signed_txn = client.sign_transaction(txn)

        # Close when done (important for SSH)
        client.close()

    Or use as context manager:
        with SignerClient.connect_ssh(...) as client:
            signed_txn = client.sign_transaction(txn)
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: Optional[int] = None,
        tunnel: Optional[Any] = None
    ):
        """
        Initialize signer client (use class methods instead).

        Args:
            base_url: Internal HTTP endpoint (set automatically by class methods)
            token: Authentication token (from aplane.token)
            timeout: Optional explicit request timeout in seconds. If omitted,
                endpoint-specific defaults are used.
            tunnel: SSH tunnel instance (managed internally)
        """
        if not base_url:
            raise SignerError("base_url is required")
        if not token:
            raise SignerError("token is required")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout if timeout and timeout > 0 else None
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"aplane {token}"
        self._tunnel = tunnel
        self._key_cache: Dict[str, KeyInfo] = {}  # Cache key info by address
        self._key_cache_revision: Optional[int] = None
        self._approval_wait_seconds: Optional[int] = None
        self._approval_wait_fetched_at: Optional[float] = None
        self._approval_wait_known = False

    @classmethod
    def connect_ssh(
        cls,
        host: str,
        token: str,
        ssh_key_path: str,
        ssh_port: int = DEFAULT_SSH_PORT,
        signer_port: int = DEFAULT_SIGNER_PORT,
        timeout: Optional[int] = None,
        known_hosts_path: str = "",
        trust_on_first_use: bool = False,
    ) -> "SignerClient":
        """
        Connect to remote apsigner via SSH tunnel.

        Establishes an SSH tunnel to the remote host and forwards
        the signer port to a local port. Uses 2FA: token (as SSH username)
        + public key authentication.

        Args:
            host: Remote host running apsigner
            token: Authentication token (used for both SSH and HTTP API)
            ssh_key_path: Path to SSH private key (e.g., ~/.ssh/id_ed25519)
            ssh_port: SSH port on remote (default: 1127)
            signer_port: Signer REST port on remote (default: 11270)
            timeout: Optional explicit request timeout in seconds
            known_hosts_path: Path to known_hosts file for host key verification (required)
            trust_on_first_use: If true, auto-trust unknown host keys (default: false)

        Returns:
            SignerClient instance with active SSH tunnel

        Raises:
            SignerError: If paramiko is not installed or known_hosts_path is empty
            SignerUnavailableError: If SSH connection fails
        """
        import os
        ssh_key_path = os.path.expanduser(ssh_key_path)

        # Find a free local port
        local_port = _find_free_port()

        try:
            # Token is used as SSH username for 2FA (token + public key)
            tunnel = _SSHTunnel(
                ssh_host=host,
                ssh_port=ssh_port,
                ssh_username=token,
                ssh_pkey_path=ssh_key_path,
                remote_host='127.0.0.1',
                remote_port=signer_port,
                local_port=local_port,
                known_hosts_path=known_hosts_path,
                trust_on_first_use=trust_on_first_use,
            )
            tunnel.start()
        except SignerError:
            raise
        except Exception as e:
            raise SignerUnavailableError(f"SSH tunnel failed: {e}")

        # Connect through tunnel
        base_url = f"http://127.0.0.1:{tunnel.local_bind_port}"
        client = cls(base_url, token, timeout, tunnel=tunnel)

        # Verify connection
        if not client.health():
            client.close()
            raise SignerUnavailableError(
                f"Connected via SSH but signer not responding on port {signer_port}"
            )

        return client

    @classmethod
    def from_env(
        cls,
        data_dir: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> "SignerClient":
        """
        Connect using config file from data directory.

        Data directory contents:
            - config.yaml: Connection settings
            - aplane.token: Authentication token
            - .ssh/id_ed25519: SSH key for authentication

        Args:
            data_dir: Client data directory. Required unless APCLIENT_DATA
                environment variable is set.
            timeout: Optional explicit request timeout in seconds

        Returns:
            SignerClient instance

        Raises:
            SignerError: if neither data_dir nor APCLIENT_DATA is set

        Example:
            # Reads APCLIENT_DATA from environment
            client = SignerClient.from_env()

            # Or pass explicitly
            client = SignerClient.from_env(data_dir="/custom/path")
        """
        data_dir = _resolve_data_dir(data_dir)

        # Load config from data_dir/config.yaml
        config = load_config(data_dir)

        # Load token from data directory
        token_path = os.path.join(data_dir, "aplane.token")
        if not os.path.exists(token_path):
            raise SignerError(f"No token found at {token_path}")
        token = load_token(token_path)

        # Check if SSH is configured
        if config.ssh:
            # Resolve SSH key path (relative to data_dir)
            ssh_key_path = os.path.join(data_dir, config.ssh.identity_file)
            if not os.path.exists(ssh_key_path):
                raise SignerError(
                    f"SSH configured but key not found at {ssh_key_path}"
                )

            # Resolve known_hosts path (relative to data_dir, or use config override)
            known_hosts_path = os.path.join(data_dir, config.ssh.known_hosts_path)

            return cls.connect_ssh(
                host=config.ssh.host,
                token=token,
                ssh_key_path=ssh_key_path,
                ssh_port=config.ssh.port,
                signer_port=config.signer_port,
                timeout=timeout,
                known_hosts_path=known_hosts_path,
                trust_on_first_use=config.ssh.trust_on_first_use,
            )

        # SSH is required
        raise SignerError(
            "No endpoint.ssh block in config.yaml. "
            "Add endpoint.ssh with host, port, and identity_file."
        )

    def close(self):
        """Close the client and any SSH tunnel."""
        if self._tunnel:
            try:
                self._tunnel.stop()
            except Exception:
                pass
            self._tunnel = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def _timeout_for(self, default_timeout: int) -> int:
        if self.timeout and self.timeout < default_timeout:
            return self.timeout
        return default_timeout

    def health(self) -> bool:
        """Check if signer is healthy and reachable."""
        try:
            resp = self.session.get(
                f"{self.base_url}/health",
                timeout=self._timeout_for(HEALTH_TIMEOUT)
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def get_status(self) -> StatusResponse:
        """
        Fetch authenticated signer status and keyset revision.

        /status is authenticated but does not require unlock. A locked state
        in a 200 response is returned as normal data.
        """
        try:
            resp = self.session.get(
                f"{self.base_url}/status",
                timeout=self._timeout_for(STATUS_TIMEOUT)
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")

        if resp.status_code == 503:
            raise SignerUnavailableError(self._error_message(resp, "Signer unavailable"))

        if resp.status_code != 200:
            raise SignerError(
                self._error_message(
                    resp,
                    f"Failed to get signer status: HTTP {resp.status_code}",
                )
            )

        data = resp.json()
        identity = StatusResponse(
            identity_id=data.get("identity_id", ""),
            node_role=data.get("node_role", ""),
            state=data.get("state", ""),
            signer_locked=data.get("signer_locked", False),
            ready_for_signing=data.get("ready_for_signing", False),
            key_count=data.get("key_count", 0),
            keyset_revision=data.get("keyset_revision", 0),
            approval_wait_seconds=data.get("approval_wait_seconds", 0),
        )
        self._cache_approval_wait(identity.approval_wait_seconds)
        return identity

    def _cache_approval_wait(self, seconds: int) -> None:
        self._approval_wait_seconds = (
            seconds
            if seconds > 0 and seconds <= MAX_DISCOVERED_APPROVAL_WAIT
            else None
        )
        self._approval_wait_fetched_at = time.monotonic()
        self._approval_wait_known = True

    def _cached_approval_wait(self) -> Optional[int]:
        if (
            not self._approval_wait_known
            or not self._approval_wait_seconds
            or self._approval_wait_fetched_at is None
        ):
            return None
        if time.monotonic() - self._approval_wait_fetched_at > APPROVAL_WAIT_REFRESH:
            return None
        return self._approval_wait_seconds

    def _needs_approval_wait_discovery(self) -> bool:
        if not self._approval_wait_known or self._approval_wait_fetched_at is None:
            return True
        return time.monotonic() - self._approval_wait_fetched_at > APPROVAL_WAIT_REFRESH

    def _discover_approval_wait(self) -> None:
        if not self._needs_approval_wait_discovery():
            return
        try:
            self.get_status()
        except SignerError:
            # /status discovery failure must not fail /sign; use fallback.
            pass

    def _sign_request_timeout(self) -> int:
        wait = self._cached_approval_wait()
        default = (
            wait + SIGN_APPROVAL_SLACK
            if wait is not None
            else DEFAULT_SIGN_REQUEST_TIMEOUT
        )
        return self._timeout_for(default)

    def list_keys(self, refresh: bool = False) -> List[KeyInfo]:
        """
        List available signing keys.

        Args:
            refresh: If True, bypass cache and fetch fresh data

        Returns:
            List of KeyInfo with address, key_type, etc.
        """
        if not refresh and self._key_cache:
            return list(self._key_cache.values())

        try:
            resp = self.session.get(
                f"{self.base_url}/keys",
                timeout=self._timeout_for(INVENTORY_TIMEOUT)
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")

        if resp.status_code != 200:
            raise SignerError(
                self._error_message(resp, f"Failed to list keys: HTTP {resp.status_code}")
            )

        data = resp.json()
        self._key_cache.clear()
        self._key_cache_revision = None
        keys = []
        for k in data.get("keys", []):
            # Parse signing_args if present
            signing_args = None
            if k.get("signing_args"):
                signing_args = [
                    RuntimeArg(
                        name=arg["name"],
                        arg_type=arg.get("type", "bytes"),
                        description=arg.get("description", ""),
                        label=arg.get("label", ""),
                        required=arg.get("required", False),
                        byte_length=arg.get("byte_length", 0),
                    )
                    for arg in k["signing_args"]
                ]

            key_info = KeyInfo(
                address=k["address"],
                key_type=k["key_type"],
                public_key_hex=k.get("public_key_hex", ""),
                lsig_size=k.get("lsig_size", 0),
                is_generic_lsig=k.get("is_generic_lsig", False),
                is_component_key=k.get("is_component_key", False),
                is_spending_account=k.get("is_spending_account"),
                signing_args=signing_args,
                parameters=k.get("parameters"),
                template_provenance_status=(
                    k.get("template_provenance_status")
                    or k.get("template_status", "")
                ),
                template_provenance_note=(
                    k.get("template_provenance_note")
                    or k.get("template_warning", "")
                ),
            )
            key_info.template_status = key_info.template_provenance_status
            key_info.template_warning = key_info.template_provenance_note
            keys.append(key_info)
            self._key_cache[key_info.address] = key_info

        return keys

    def list_keys_if_keyset_changed(self) -> List[KeyInfo]:
        """
        Return cached keys when /status.keyset_revision is unchanged.

        This is the SDK-facing cache invalidation contract for preparation
        helpers that need fresh signer inventory before deciding signability.
        """
        status = self.get_status()
        if status.signer_locked:
            raise SignerUnavailableError("signer is locked")
        if (
            self._key_cache
            and self._key_cache_revision is not None
            and self._key_cache_revision == status.keyset_revision
        ):
            return list(self._key_cache.values())

        keys = self.list_keys(refresh=True)
        self._key_cache_revision = status.keyset_revision
        return keys

    def get_key_info(self, address: str) -> Optional[KeyInfo]:
        """
        Get key info for a specific address.

        Args:
            address: The Algorand address to look up

        Returns:
            KeyInfo if found, None otherwise
        """
        if address not in self._key_cache:
            self.list_keys(refresh=True)
        return self._key_cache.get(address)

    def resolve_auth_address(
        self,
        address: str,
        account_info_lookup: Callable[[str], Any],
    ) -> ResolvedAuthAddress:
        """
        Resolve sender -> effective signer and verify signer key ownership.

        account_info_lookup is usually algod_client.account_info. It may return
        a dict/object containing auth-addr/auth_addr/authAddr, or a string auth
        address. Empty auth address means the account signs for itself.
        """
        if account_info_lookup is None:
            raise ValueError("account_info_lookup is required")

        try:
            account_info = account_info_lookup(address)
        except Exception as e:
            raise SignerError(f"failed to query account info: {e}") from e

        auth_addr = _extract_auth_address(account_info)
        signing_addr = address
        if auth_addr and auth_addr != address:
            signing_addr = auth_addr

        key_info = _find_spendable_key(
            self.list_keys_if_keyset_changed(),
            signing_addr,
        )
        if key_info is None:
            if signing_addr == address:
                raise KeyNotFoundError(f"{address} is not available for signing")
            raise KeyNotFoundError(
                f"account is rekeyed to {auth_addr} but that address is not signable"
            )

        return ResolvedAuthAddress(
            address=address,
            auth_address=signing_addr,
            is_rekeyed=signing_addr != address,
            key_info=key_info,
        )

    def prepare_payment(
        self,
        algod_client: Any,
        *,
        sender: str,
        receiver: str,
        amount: int,
        note: Optional[bytes] = None,
        fee: Optional[int] = None,
        use_flat_fee: bool = False,
    ) -> PreparedTransaction:
        """Build a prepared ALGO payment transaction."""
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        if not receiver:
            raise ValueError("receiver is required")

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee, use_flat_fee)

        sender_info = algod_client.account_info(sender)
        txn = transaction.PaymentTxn(
            sender=sender,
            sp=params,
            receiver=receiver,
            amt=amount,
            note=note,
        )
        txn_fee = int(getattr(txn, "fee", 0))
        available = _account_amount(sender_info) - _account_min_balance(sender_info)
        required = amount + txn_fee
        if available < required:
            raise SignerError(
                f"insufficient funds: available {available}, required {required}"
            )

        resolved = self.resolve_auth_address(sender, lambda _: sender_info)
        return PreparedTransaction(
            transaction=txn,
            auth_address=resolved.auth_address,
            signer_key=resolved.key_info,
            checks=[
                PreparedCheck(
                    name="payment_balance",
                    status="ok",
                    data={
                        "amount": amount,
                        "fee": txn_fee,
                        "available": available,
                    },
                )
            ],
        )

    def prepare_asa_transfer(
        self,
        algod_client: Any,
        *,
        sender: str,
        receiver: str,
        asset_id: int,
        amount: int,
        note: Optional[bytes] = None,
        fee: Optional[int] = None,
        use_flat_fee: bool = False,
    ) -> PreparedTransaction:
        """Build a prepared ASA transfer transaction."""
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        if not receiver:
            raise ValueError("receiver is required")
        if not asset_id:
            raise ValueError("asset_id is required")

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee, use_flat_fee)

        sender_info = algod_client.account_info(sender)
        receiver_info = algod_client.account_info(receiver)
        sender_holding = _account_asset_holding(sender_info, asset_id)
        if sender_holding is None:
            raise SignerError(f"sender is not opted into asset {asset_id}")
        sender_amount = _asset_holding_amount(sender_holding)
        if sender_amount < amount:
            raise SignerError(
                f"insufficient asset balance: available {sender_amount}, required {amount}"
            )
        if _account_asset_holding(receiver_info, asset_id) is None:
            raise SignerError(f"receiver is not opted into asset {asset_id}")

        txn = transaction.AssetTransferTxn(
            sender=sender,
            sp=params,
            receiver=receiver,
            amt=amount,
            index=asset_id,
            note=note,
        )

        resolved = self.resolve_auth_address(sender, lambda _: sender_info)
        return PreparedTransaction(
            transaction=txn,
            auth_address=resolved.auth_address,
            signer_key=resolved.key_info,
            checks=[
                PreparedCheck(
                    name="asa_transfer",
                    status="ok",
                    data={"asset_id": asset_id, "amount": amount},
                )
            ],
        )

    def list_key_types(self) -> List[KeyTypeInfo]:
        """
        List available key types supported by the signer.

        Returns:
            List of KeyTypeInfo describing each available key type
        """
        try:
            resp = self.session.get(
                f"{self.base_url}/keytypes",
                timeout=self._timeout_for(INVENTORY_TIMEOUT)
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")

        if resp.status_code != 200:
            raise SignerError(
                self._error_message(
                    resp,
                    f"Failed to list key types: HTTP {resp.status_code}",
                )
            )

        data = resp.json()
        result = []
        for kt in data.get("key_types", []):
            creation_params = None
            if kt.get("creation_params"):
                creation_params = [
                    CreationParam(
                        name=p["name"],
                        label=p.get("label", ""),
                        description=p.get("description", ""),
                        param_type=p.get("type", ""),
                        required=p.get("required", False),
                        max_length=p.get("max_length", 0),
                        input_modes=[
                            InputModeInfo(
                                name=mode["name"],
                                label=mode.get("label", ""),
                                transform=mode.get("transform", ""),
                                byte_length=mode.get("byte_length", 0),
                                input_type=mode.get("input_type", ""),
                            )
                            for mode in p.get("input_modes", [])
                        ] or None,
                        min_items=p.get("min_items", 0),
                        max_items=p.get("max_items", 0),
                        options=p.get("options"),
                        min=p.get("min"),
                        max=p.get("max"),
                        example=p.get("example", ""),
                        placeholder=p.get("placeholder", ""),
                        default=p.get("default", ""),
                    )
                    for p in kt["creation_params"]
                ]

            runtime_args = None
            if kt.get("runtime_args"):
                runtime_args = [
                    RuntimeArg(
                        name=arg["name"],
                        arg_type=arg.get("type", "bytes"),
                        description=arg.get("description", ""),
                        label=arg.get("label", ""),
                        required=arg.get("required", False),
                        byte_length=arg.get("byte_length", 0),
                    )
                    for arg in kt["runtime_args"]
                ]

            result.append(KeyTypeInfo(
                key_type=kt["key_type"],
                family=kt.get("family", ""),
                display_name=kt.get("display_name", ""),
                description=kt.get("description", ""),
                requires_logicsig=kt.get("requires_logicsig", False),
                mnemonic_word_count=kt.get("mnemonic_word_count", 0),
                mnemonic_import=kt.get("mnemonic_import", False),
                mnemonic_scheme=kt.get("mnemonic_scheme", ""),
                creation_params=creation_params,
                runtime_args=runtime_args,
            ))

        return result

    def generate_key(
        self,
        key_type: str,
        parameters: Optional[Dict[str, str]] = None
    ) -> GenerateResult:
        """
        Generate a new key on the signer.

        Args:
            key_type: Type of key to generate (e.g., "ed25519", "aplane.falcon1024.v1")
            parameters: Optional creation parameters (type-specific)

        Returns:
            GenerateResult with address, key_type, and parameters
        """
        body: Dict[str, Any] = {"key_type": key_type}
        if parameters:
            body["parameters"] = parameters

        try:
            resp = self.session.post(
                f"{self.base_url}/admin/generate",
                json=body,
                timeout=self._timeout_for(MUTATION_TIMEOUT)
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")

        if resp.status_code == 403:
            raise SignerUnavailableError("Signer is locked")

        if resp.status_code == 400:
            raise SignerError(self._error_message(resp, "Bad request"))

        if resp.status_code != 200:
            raise SignerError(
                self._error_message(resp, f"Key generation failed: HTTP {resp.status_code}")
            )

        data = resp.json()
        if data.get("error"):
            raise SignerError(data["error"])

        # Invalidate key cache so next list_keys fetches fresh
        self._key_cache.clear()
        self._key_cache_revision = None

        if not data.get("address"):
            raise SignerError("Key generation response missing address")
        if not data.get("key_type"):
            raise SignerError("Key generation response missing key_type")

        return GenerateResult(
            address=data["address"],
            key_type=data["key_type"],
            public_key_hex=data.get("public_key_hex", ""),
            is_component_key=data.get("is_component_key", False),
            is_spending_account=data.get("is_spending_account"),
            parameters=data.get("parameters"),
        )

    def delete_key(self, address: str) -> None:
        """
        Delete a key from the signer.

        Args:
            address: Algorand address of the key to delete
        """
        try:
            resp = self.session.delete(
                f"{self.base_url}/admin/keys",
                params={"address": address},
                timeout=self._timeout_for(MUTATION_TIMEOUT)
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")

        if resp.status_code == 403:
            raise SignerUnavailableError("Signer is locked")

        if resp.status_code == 404:
            raise KeyDeletionError(self._error_message(resp, f"Key not found: {address}"))

        if resp.status_code != 200:
            raise SignerError(
                self._error_message(resp, f"Key deletion failed: HTTP {resp.status_code}")
            )

        data = self._safe_json(resp)
        if data.get("error"):
            raise SignerError(data["error"])

        # Invalidate key cache
        self._key_cache.clear()
        self._key_cache_revision = None

    def _safe_json(self, resp: requests.Response) -> dict:
        """
        Parse JSON response safely.

        Returns the parsed JSON as a dict, or an empty dict if:
        - Response has no content
        - Response content is not valid JSON (e.g., plain text error)

        This prevents JSONDecodeError when the server returns plain text
        error messages instead of JSON.
        """
        if not resp.content:
            return {}
        try:
            return resp.json()
        except json.JSONDecodeError:
            return {}

    def _error_message(self, resp: requests.Response, fallback: str) -> str:
        """Return signer error text from top-level JSON error, text, or fallback."""
        data = self._safe_json(resp)
        error = data.get("error")
        if isinstance(error, str) and error.strip():
            return error
        text = (resp.text or "").strip()
        if text:
            return text
        return fallback

    def cancel_sign_request(self, request_id: str) -> CancelSignResponse:
        """
        Ask apsigner to cancel a live synchronous /sign request.

        Cancellation is idempotent for client behavior. A successful HTTP
        response returns state "canceled" or "not_found".
        """
        _validate_sign_request_id(request_id, required=True)
        try:
            resp = self.session.post(
                f"{self.base_url}/sign/cancel",
                json={"request_id": request_id},
                timeout=self._timeout_for(SIGN_CANCEL_TIMEOUT),
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")

        if resp.status_code != 200:
            raise SignerError(
                self._error_message(resp, f"Sign cancel failed: HTTP {resp.status_code}")
            )

        data = self._safe_json(resp)
        result = CancelSignResponse(
            success=data.get("success", False),
            state=data.get("state", ""),
            error=data.get("error", ""),
        )
        if result.error:
            raise SignerError(result.error)
        return result

    def request_component_sign(
        self,
        request: Any,
    ) -> ComponentSignResponse:
        """
        Send a raw role-specific component signing request to /sign/component.

        This is a low-level building block for guarded-account flows. The SDK
        validates request and response shape but does not assemble transactions.
        """
        request_body = _compact_payload(request)
        if not isinstance(request_body, dict):
            raise ValueError("component sign request must be a mapping or dataclass")
        if not request_body.get("request_id"):
            request_body["request_id"] = _new_sign_request_id()
        try:
            _validate_component_sign_request(request_body)
        except ValueError as e:
            raise ValueError(f"invalid component sign request: {e}") from e

        try:
            resp = self.session.post(
                f"{self.base_url}/sign/component",
                json=request_body,
                timeout=self._timeout_for(COMPONENT_SIGN_TIMEOUT),
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")

        if resp.status_code == 403:
            error = self._error_message(resp, "Component signing request rejected")
            raise SigningRejectedError(error)

        if resp.status_code == 503:
            raise SignerUnavailableError(self._error_message(resp, "Signer unavailable"))

        if resp.status_code != 200:
            raise SignerError(
                self._error_message(
                    resp,
                    f"Component signing failed: HTTP {resp.status_code}",
                )
            )

        data = self._safe_json(resp)
        if data.get("error"):
            raise SignerError(data["error"])
        try:
            _validate_component_sign_response(data)
        except ValueError as e:
            raise SignerError(f"invalid component sign response: {e}") from e

        return ComponentSignResponse(
            request_id=data["request_id"],
            component_key=data.get("component_key", ""),
            signatures=[
                ComponentSignature(
                    target_index=item["target_index"],
                    signature=item["signature"],
                    signature_scheme=item["signature_scheme"],
                )
                for item in data.get("signatures", [])
            ],
        )

    def request_guarded_assemble(
        self,
        request: Any,
    ) -> GuardedAssemblyResponse:
        """
        Send a raw guarded transaction assembly request to /sign/assemble.
        """
        request_body = _compact_payload(request)
        if not isinstance(request_body, dict):
            raise ValueError("guarded assembly request must be a mapping or dataclass")
        if not request_body.get("request_id"):
            request_body["request_id"] = _new_sign_request_id()
        try:
            _validate_guarded_assembly_request(request_body)
        except ValueError as e:
            raise ValueError(f"invalid guarded assembly request: {e}") from e

        try:
            resp = self.session.post(
                f"{self.base_url}/sign/assemble",
                json=request_body,
                timeout=self._timeout_for(GUARDED_ASSEMBLY_TIMEOUT),
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")

        if resp.status_code == 403:
            error = self._error_message(resp, "Guarded assembly request rejected")
            raise SigningRejectedError(error)

        if resp.status_code == 503:
            raise SignerUnavailableError(self._error_message(resp, "Signer unavailable"))

        if resp.status_code != 200:
            raise SignerError(
                self._error_message(
                    resp,
                    f"Guarded assembly failed: HTTP {resp.status_code}",
                )
            )

        data = self._safe_json(resp)
        if data.get("error"):
            raise SignerError(data["error"])
        try:
            _validate_guarded_assembly_response(data)
        except ValueError as e:
            raise SignerError(f"invalid guarded assembly response: {e}") from e

        return GuardedAssemblyResponse(
            request_id=data["request_id"],
            signed_group=data.get("signed_group", []),
        )

    def admin_sync_sentry_references(
        self,
        candidates: List[Any],
    ) -> AdminSyncSentryReferencesResponse:
        """
        Sync public sentry reference candidates into the connected signer.
        """
        request_body = {"candidates": _compact_payload(candidates)}

        try:
            resp = self.session.post(
                f"{self.base_url}/admin/sentries/sync",
                json=request_body,
                timeout=self._timeout_for(MUTATION_TIMEOUT),
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")

        if resp.status_code == 403:
            raise SignerUnavailableError("Signer is locked")

        if resp.status_code != 200:
            raise SignerError(
                self._error_message(
                    resp,
                    f"Sentry reference sync failed: HTTP {resp.status_code}",
                )
            )

        data = self._safe_json(resp)
        if data.get("error"):
            raise SignerError(data["error"])

        raw_records = data.get("records")
        records = None
        if isinstance(raw_records, list):
            records = [
                SyncedSentryReferenceInfo(
                    name=item.get("name", ""),
                    source=item.get("source", ""),
                    endpoint_alias=item.get("endpoint_alias", ""),
                    component_key=item.get("component_key", ""),
                    key_type=item.get("key_type", ""),
                    public_key_hex=item.get("public_key_hex", ""),
                    last_seen_at=item.get("last_seen_at", ""),
                    synced_at=item.get("synced_at", ""),
                )
                for item in raw_records
            ]

        return AdminSyncSentryReferencesResponse(
            added=data.get("added", 0),
            updated=data.get("updated", 0),
            removed=data.get("removed", 0),
            count=data.get("count", 0),
            records=records,
            error=data.get("error", ""),
        )

    def _best_effort_cancel_sign_request(self, request_id: str) -> None:
        try:
            self.cancel_sign_request(request_id)
        except Exception:
            pass

    def _build_sign_request_body(
        self,
        txns: List[Optional[transaction.Transaction]],
        auth_addresses: List[Optional[str]],
        lsig_args_map: Optional[Dict[str, Dict[str, bytes]]] = None,
        passthrough: Optional[Dict[int, str]] = None,
        lsig_sizes: Optional[Dict[int, int]] = None,
        allow_foreign: bool = True,
    ) -> dict:
        """
        Build the JSON request body for /sign and /plan endpoints.

        Args:
            txns: List of transactions
            auth_addresses: Auth address for each transaction
            lsig_args_map: Optional mapping of address -> lsig_args
            passthrough: Optional mapping of group index -> base64-encoded
                pre-signed transaction
            lsig_sizes: Optional mapping of group index -> LSig size hint
                for foreign transactions (no auth_address). This tells the
                signer how much LSig budget to reserve for the foreign party.

        Returns:
            Dict ready for JSON serialization as request body

        Raises:
            ValueError: If a passthrough index is out of range or a
                non-passthrough, non-foreign entry has a missing auth_address.
        """
        # Validate passthrough indices
        if passthrough:
            for idx in passthrough:
                if idx < 0 or idx >= len(txns):
                    raise ValueError(
                        f"passthrough index {idx} out of range for {len(txns)} transactions"
                    )

        # Validate lsig_sizes indices and values
        if lsig_sizes:
            for idx, size in lsig_sizes.items():
                if idx < 0 or idx >= len(txns):
                    raise ValueError(
                        f"lsig_sizes index {idx} out of range for {len(txns)} transactions"
                    )
                if not isinstance(size, int) or size < 0:
                    raise ValueError(
                        f"lsig_sizes[{idx}] must be a non-negative integer, got {size!r}"
                    )

        # Build request array
        sign_requests = []
        for i, (txn, auth_addr) in enumerate(zip(txns, auth_addresses)):
            # Passthrough: include pre-signed transaction as-is
            if passthrough and i in passthrough:
                try:
                    signed_hex = base64.b64decode(passthrough[i], validate=True).hex()
                except Exception as e:
                    raise ValueError(
                        f"invalid base64 in passthrough[{i}]: {e}"
                    ) from e
                sign_requests.append({"signed_txn_hex": signed_hex})
                continue

            # Foreign mode: txn_bytes_hex without auth_address
            if not auth_addr:
                if not allow_foreign:
                    raise SignerError(
                        "foreign entries are only supported on /plan; use "
                        f"plan_group() first, then resubmit slot {i} as passthrough"
                    )
                if txn is None:
                    raise ValueError(
                        f"transaction is required for foreign-mode entry at index {i}"
                    )
                txn_bytes_hex, _ = encode_transaction(txn)
                req: Dict[str, Any] = {"txn_bytes_hex": txn_bytes_hex}
                if lsig_sizes and i in lsig_sizes:
                    req["lsig_size"] = lsig_sizes[i]
                sign_requests.append(req)
                continue

            if txn is None:
                raise ValueError(
                    f"transaction is required for sign-mode entry at index {i}"
                )

            txn_bytes_hex, txn_sender = encode_transaction(txn)

            req = {
                "txn_bytes_hex": txn_bytes_hex,
                "auth_address": auth_addr,
                "txn_sender": txn_sender,
            }

            # Add LogicSig args if provided
            if lsig_args_map and auth_addr in lsig_args_map:
                req["lsig_args"] = {
                    name: value.hex()
                    for name, value in lsig_args_map[auth_addr].items()
                }

            sign_requests.append(req)

        return {"requests": sign_requests}

    def _sign_request(
        self,
        txns: List[Optional[transaction.Transaction]],
        auth_addresses: List[Optional[str]],
        lsig_args_map: Optional[Dict[str, Dict[str, bytes]]] = None,
        passthrough: Optional[Dict[int, str]] = None,
        lsig_sizes: Optional[Dict[int, int]] = None,
        request_id: Optional[str] = None,
    ) -> List[str]:
        """
        Send signing request to the /sign endpoint.

        For pure sign-mode requests (no passthrough), the server handles:
        - Dummy transaction creation for large LogicSigs
        - Fee pooling across the group
        - Group ID computation

        When passthrough entries are present, the caller is responsible for
        pre-assigning group IDs on all transactions. The server cannot mutate
        pre-signed passthrough transactions, so dummy insertion and group ID
        computation are skipped for the entire group.

        Args:
            txns: List of transactions to sign
            auth_addresses: Auth address for each transaction
            lsig_args_map: Optional mapping of address -> lsig_args
            passthrough: Optional mapping of group index -> base64-encoded
                pre-signed transaction. Passthrough transactions are included
                as-is in the group (the server does not re-sign them). Use this
                for multi-party workflows where another signer has already
                signed their transaction. All indices must be in range
                [0, len(txns)).
            lsig_sizes: Optional mapping of group index -> LSig size hint
                for planning foreign transactions.
            request_id: Optional caller-owned /sign request ID. Applications
                can use the same ID with cancel_sign_request() to cancel a
                pending approval from another thread.

        Returns:
            List of base64-encoded signed transactions (includes any dummies
            added by server).

        Raises:
            ValueError: If a passthrough index is out of range or a
                non-passthrough, non-foreign entry has a missing auth_address.
        """
        request_body = self._build_sign_request_body(
            txns, auth_addresses, lsig_args_map, passthrough, lsig_sizes, False
        )
        data = self.sign_requests(request_body["requests"], request_id=request_id)

        # Parse signed transactions (convert hex to base64 for algosdk compatibility)
        signed_hexes = data.signed
        if not signed_hexes:
            raise SignerError("Server returned no signed transactions")

        result = []
        for h in signed_hexes:
            if not h:
                raise SignerError(
                    "Server returned empty signed transaction slot; use /plan "
                    "for foreign or partial groups"
                )
            result.append(base64.b64encode(bytes.fromhex(h)).decode())
        return result

    def sign_requests(
        self,
        sign_entries: List[Dict[str, Any]],
        *,
        request_id: Optional[str] = None,
    ) -> GroupSignResponse:
        """
        Send raw signing request entries to /sign.

        Higher-level helpers build these entries from algosdk transactions;
        adapters can use this method directly when they already own transaction
        encoding.
        """
        if not sign_entries:
            raise ValueError("sign_entries must not be empty")

        if request_id is None:
            request_id = _new_sign_request_id()
        _validate_sign_request_id(request_id, required=True)
        request_body = {
            "request_id": request_id,
            "requests": sign_entries,
        }

        self._discover_approval_wait()

        try:
            resp = self.session.post(
                f"{self.base_url}/sign",
                json=request_body,
                timeout=self._sign_request_timeout()
            )
        except requests.RequestException as e:
            self._best_effort_cancel_sign_request(request_id)
            raise SignerUnavailableError(f"Failed to connect: {e}")

        # Handle errors
        # Note: Use _safe_json() to handle both JSON and plain text error responses
        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")

        if resp.status_code == 400:
            error = self._error_message(resp, "")
            if "not found" in error.lower():
                raise KeyNotFoundError(error)
            raise SignerError(f"Bad request: {error}")

        if resp.status_code == 403:
            error = self._error_message(resp, "Signing request rejected by operator")
            raise SigningRejectedError(error)

        if resp.status_code == 503:
            error = self._error_message(resp, "Signer unavailable")
            raise SignerUnavailableError(error)

        if resp.status_code != 200:
            raise SignerError(
                self._error_message(resp, f"Signing failed: HTTP {resp.status_code}")
            )

        # Parse successful response
        try:
            data = resp.json()
        except json.JSONDecodeError:
            raise SignerError(f"Server returned invalid JSON: {resp.text[:200]}")

        if data.get("error"):
            raise SignerError(data["error"])

        return GroupSignResponse(
            signed=data.get("signed", []),
            mutations=data.get("mutations"),
            error=data.get("error", ""),
        )

    def plan_group(
        self,
        txns: List[Optional[transaction.Transaction]],
        auth_addresses: Optional[List[Optional[str]]] = None,
        lsig_args_map: Optional[Dict[str, Dict[str, bytes]]] = None,
        passthrough: Optional[Dict[int, str]] = None,
        lsig_sizes: Optional[Dict[int, int]] = None,
    ) -> dict:
        """
        Preview group building without signing or approval.

        Sends the same request as sign_transactions() to the /plan endpoint.
        The server performs group building (dummy insertion, fee pooling,
        group ID computation) and returns the planned group as unsigned
        transactions plus a mutation report.

        Use cases:
        - Transaction simulation (feed planned group to algod /simulate)
        - Fee visibility before committing to approval
        - Multi-party signing coordination (use foreign entries with lsig_sizes)
        - Scripting dry-runs and debugging group mutations

        Args:
            txns: List of algosdk Transaction objects. Passthrough indices
                may use None as a placeholder.
            auth_addresses: List of auth addresses (one per txn),
                defaults to each txn's sender. Passthrough and foreign indices
                may be None.
            lsig_args_map: Optional mapping of address -> lsig_args
            passthrough: Optional mapping of group index -> base64-encoded
                pre-signed transaction
            lsig_sizes: Optional mapping of group index -> LSig size hint
                for foreign transactions (auth_address is None).

        Returns:
            Dict with:
            - "transactions": list of TX-prefixed hex-encoded unsigned txns
            - "mutations": dict describing server modifications (or None)

        Raises:
            SignerError: On server errors
            AuthenticationError: On auth failure
            ValueError: On invalid input
        """
        if auth_addresses is None:
            auth_addresses = [txn.sender if txn else None for txn in txns]

        if len(auth_addresses) != len(txns):
            raise ValueError("auth_addresses length must match txns length")

        request_body = self._build_sign_request_body(
            txns, auth_addresses, lsig_args_map, passthrough, lsig_sizes
        )

        try:
            resp = self.session.post(
                f"{self.base_url}/plan",
                json=request_body,
                timeout=self._timeout_for(GROUP_PLAN_TIMEOUT)
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")

        if resp.status_code == 400:
            error = self._error_message(resp, "")
            if "not found" in error.lower():
                raise KeyNotFoundError(error)
            raise SignerError(f"Bad request: {error}")

        if resp.status_code == 403:
            raise SignerError(self._error_message(resp, "Forbidden"))

        if resp.status_code != 200:
            raise SignerError(self._error_message(resp, f"Plan failed: HTTP {resp.status_code}"))

        try:
            data = resp.json()
        except json.JSONDecodeError:
            raise SignerError(f"Server returned invalid JSON: {resp.text[:200]}")

        if data.get("error"):
            raise SignerError(data["error"])

        return data

    def sign_transaction(
        self,
        txn: transaction.Transaction,
        auth_address: Optional[str] = None,
        lsig_args: Optional[Dict[str, bytes]] = None,
        *,
        request_id: Optional[str] = None,
    ) -> str:
        """
        Sign a transaction via apsigner.

        The server automatically handles:
        - Dummy transaction creation for large LogicSigs (e.g., Falcon-1024)
        - Fee pooling (distributes fees across the group)
        - Group ID computation

        Args:
            txn: algosdk Transaction object
            auth_address: Key to sign with (defaults to txn.sender)
            lsig_args: Optional runtime args for generic LogicSigs,
                       e.g., {"preimage": b"secret"}
            request_id: Optional caller-owned /sign request ID. Use the same
                ID with cancel_sign_request() to cancel a pending approval from
                another thread.

        Returns:
            Base64-encoded signed transaction(s), ready for algod_client.send_raw_transaction().
            If dummies were added, returns concatenated group as single base64 string.
        """
        if auth_address is None:
            auth_address = txn.sender

        lsig_args_map = {auth_address: lsig_args} if lsig_args else None

        signed_list = self._sign_request([txn], [auth_address], lsig_args_map, request_id=request_id)

        # Concatenate all signed txns and return as single base64 string
        all_bytes = b"".join(base64.b64decode(s) for s in signed_list)
        return base64.b64encode(all_bytes).decode()

    def sign_transactions(
        self,
        txns: List[Optional[transaction.Transaction]],
        auth_addresses: Optional[List[Optional[str]]] = None,
        lsig_args_map: Optional[Dict[str, Dict[str, bytes]]] = None,
        passthrough: Optional[Dict[int, str]] = None,
        lsig_sizes: Optional[Dict[int, int]] = None,
        *,
        request_id: Optional[str] = None,
    ) -> str:
        """
        Sign multiple transactions as a group.

        Without passthrough, the server automatically handles:
        - Group ID computation (for 2+ transactions)
        - Dummy transaction creation for large LogicSigs
        - Fee pooling across the group

        Note: Without passthrough, transactions should NOT have group IDs
        pre-assigned. The server computes the group ID after adding any
        required dummies.

        When passthrough entries are present, the caller must pre-assign group
        IDs on all transactions before signing. The server cannot mutate
        pre-signed passthrough transactions, so dummy insertion and group ID
        computation are skipped for the entire group.

        Args:
            txns: List of algosdk Transaction objects. Passthrough indices
                may use None as a placeholder since only the pre-signed bytes
                are sent for those positions.
            auth_addresses: List of auth addresses (one per txn),
                           defaults to each txn's sender. Passthrough indices
                           may be None.
            lsig_args_map: Optional mapping of address -> lsig_args.
                           Example: {"HASHLOCK_ADDR...": {"preimage": b"secret"}}
            passthrough: Optional mapping of group index -> base64-encoded
                pre-signed transaction. These transactions are included as-is
                in the group without re-signing. Use for multi-party workflows.
                All indices must be in range [0, len(txns)).
            lsig_sizes: Optional mapping of group index -> LSig size hint
                for planning foreign transactions.
            request_id: Optional caller-owned /sign request ID. Use the same
                ID with cancel_sign_request() to cancel a pending approval from
                another thread.

        Returns:
            Base64-encoded concatenated signed transactions for the entire group,
            ready for algod_client.send_raw_transaction().
        """
        if auth_addresses is None:
            auth_addresses = [txn.sender if txn else None for txn in txns]

        if len(auth_addresses) != len(txns):
            raise ValueError("auth_addresses length must match txns length")

        signed_list = self._sign_request(
            txns, auth_addresses, lsig_args_map, passthrough, lsig_sizes, request_id=request_id
        )

        # Concatenate all signed txns and return as single base64 string
        all_bytes = b"".join(base64.b64decode(s) for s in signed_list)
        return base64.b64encode(all_bytes).decode()

    def sign_transactions_list(
        self,
        txns: List[Optional[transaction.Transaction]],
        auth_addresses: Optional[List[Optional[str]]] = None,
        lsig_args_map: Optional[Dict[str, Dict[str, bytes]]] = None,
        passthrough: Optional[Dict[int, str]] = None,
        lsig_sizes: Optional[Dict[int, int]] = None,
        *,
        request_id: Optional[str] = None,
    ) -> List[str]:
        """
        Sign multiple transactions and return as a list.

        Like sign_transactions() but returns individual base64-encoded signed
        transactions instead of concatenated. Useful when you need to inspect
        or handle transactions individually, especially in multi-party workflows.

        See sign_transactions() for passthrough/foreign semantics and group ID
        requirements.

        Args:
            txns: List of algosdk Transaction objects. Passthrough indices
                may use None as a placeholder.
            auth_addresses: List of auth addresses (one per txn).
                Passthrough indices may be None.
            lsig_args_map: Optional mapping of address -> lsig_args
            passthrough: Optional mapping of group index -> base64-encoded
                pre-signed transaction. These transactions are included as-is
                in the group without re-signing. Use for multi-party workflows.
                All indices must be in range [0, len(txns)).
            lsig_sizes: Optional mapping of group index -> LSig size hint
                for planning foreign transactions.
            request_id: Optional caller-owned /sign request ID. Use the same
                ID with cancel_sign_request() to cancel a pending approval from
                another thread.

        Returns:
            List of base64-encoded signed transactions (includes any dummies).
        """
        if auth_addresses is None:
            auth_addresses = [txn.sender if txn else None for txn in txns]

        if len(auth_addresses) != len(txns):
            raise ValueError("auth_addresses length must match txns length")

        return self._sign_request(
            txns, auth_addresses, lsig_args_map, passthrough, lsig_sizes, request_id=request_id
        )


def _component_signatures_by_index(
    response: ComponentSignResponse,
) -> Dict[int, Dict[str, str]]:
    return {
        item.target_index: {
            "signature": item.signature,
            "request_id": response.request_id,
        }
        for item in response.signatures
    }


def _resolve_sentry_for_target(
    target: Dict[str, Any],
    sentry_client: Optional[SignerClient],
    sentry_component_key: str,
    sentry_resolver: Optional[Any],
) -> tuple:
    if sentry_resolver is not None:
        resolved = sentry_resolver(target)
        if isinstance(resolved, dict):
            client = resolved.get("client")
            component_key = resolved.get("component_key", "")
        else:
            client, component_key = resolved
        if client is None:
            raise SignerError("sentry resolver returned no client")
        return client, component_key or ""
    if sentry_client is None:
        raise SignerError("sentry_client or sentry_resolver is required")
    return sentry_client, target.get("sentry_component_key") or sentry_component_key


def _request_primary_guarded_passthrough(
    user_client: SignerClient,
    group_bytes_hex: List[str],
    guarded_indices: set,
    primary_targets: List[Dict[str, Any]],
) -> tuple:
    primary_by_index: Dict[int, Dict[str, Any]] = {}
    for target in primary_targets:
        index = target.get("target_index")
        if not isinstance(index, int) or index < 0 or index >= len(group_bytes_hex):
            raise ValueError(f"primary target {index} out of range")
        if index in guarded_indices:
            raise ValueError(f"primary target {index} overlaps guarded target")
        if index in primary_by_index:
            raise ValueError(f"duplicate primary target index {index}")
        if not target.get("auth_address"):
            raise ValueError(f"primary target {index} missing auth_address")
        primary_by_index[index] = target

    requests = []
    for index, txn_hex in enumerate(group_bytes_hex):
        target = primary_by_index.get(index)
        if target:
            request = {
                "txn_bytes_hex": txn_hex,
                "auth_address": target["auth_address"],
            }
            if target.get("txn_sender"):
                request["txn_sender"] = target["txn_sender"]
            if target.get("lsig_args"):
                request["lsig_args"] = target["lsig_args"]
            if target.get("lsig_size"):
                request["lsig_size"] = target["lsig_size"]
            if target.get("app_call_info"):
                request["app_call_info"] = target["app_call_info"]
            requests.append(request)
        else:
            requests.append({"txn_bytes_hex": txn_hex})

    response = user_client.sign_requests(requests)
    passthrough = []
    for index in sorted(primary_by_index):
        if index >= len(response.signed) or not response.signed[index]:
            raise SignerError(
                f"primary signer returned no signed transaction for target {index}"
            )
        passthrough.append(
            GuardedPassthroughItem(
                target_index=index,
                signed_txn_hex=response.signed[index],
            )
        )
    return response, passthrough


def sign_guarded_group(
    *,
    user_client: SignerClient,
    group_bytes_hex: List[str],
    guarded_targets: List[Any],
    sentry_client: Optional[SignerClient] = None,
    sentry_resolver: Optional[Any] = None,
    sentry_component_key: str = "",
    primary_targets: Optional[List[Any]] = None,
    passthrough: Optional[List[Any]] = None,
    assembly_request_id: str = "",
) -> GuardedSignResult:
    """
    Sign and assemble a guarded group using explicit signer clients.

    The helper expects canonical TX-prefixed group bytes. Planning and endpoint
    discovery stay caller-owned.
    """
    if user_client is None:
        raise SignerError("user_client is required")
    _validate_component_group_bytes(group_bytes_hex)
    targets = [_compact_payload(target) for target in guarded_targets]
    if not targets:
        raise ValueError("at least one guarded target is required")
    targets.sort(key=lambda item: item["target_index"])

    guarded_indices = set()
    user_groups: Dict[str, List[int]] = {}
    for target in targets:
        index = target.get("target_index")
        if not isinstance(index, int) or index < 0 or index >= len(group_bytes_hex):
            raise ValueError(f"guarded target {index} out of range")
        if index in guarded_indices:
            raise ValueError(f"duplicate guarded target index {index}")
        if not target.get("guarded_account"):
            raise ValueError(f"guarded target {index} missing guarded_account")
        guarded_indices.add(index)
        user_groups.setdefault(target["guarded_account"], []).append(index)

    user_component_responses = []
    user_signatures: Dict[int, Dict[str, str]] = {}
    for guarded_account in sorted(user_groups):
        response = user_client.request_component_sign(ComponentSignRequest(
            role=COMPONENT_SIGN_ROLE_USER,
            component_key=guarded_account,
            group_bytes_hex=group_bytes_hex,
            target_indices=sorted(user_groups[guarded_account]),
        ))
        user_component_responses.append(response)
        user_signatures.update(_component_signatures_by_index(response))

    sentry_groups: Dict[tuple, Dict[str, Any]] = {}
    for target in targets:
        client, component_key = _resolve_sentry_for_target(
            target, sentry_client, sentry_component_key, sentry_resolver
        )
        key = (id(client), component_key)
        if key not in sentry_groups:
            sentry_groups[key] = {
                "client": client,
                "component_key": component_key,
                "indices": [],
            }
        sentry_groups[key]["indices"].append(target["target_index"])

    sentry_component_responses = []
    sentry_signatures: Dict[int, Dict[str, str]] = {}
    for group in sentry_groups.values():
        response = group["client"].request_component_sign(ComponentSignRequest(
            role=COMPONENT_SIGN_ROLE_SENTRY,
            component_key=group["component_key"],
            group_bytes_hex=group_bytes_hex,
            target_indices=sorted(group["indices"]),
        ))
        sentry_component_responses.append(response)
        sentry_signatures.update(_component_signatures_by_index(response))

    primary_sign_response = None
    assembly_passthrough = [
        item if isinstance(item, GuardedPassthroughItem)
        else GuardedPassthroughItem(**_compact_payload(item))
        for item in (passthrough or [])
    ]
    if primary_targets:
        primary_sign_response, primary_passthrough = _request_primary_guarded_passthrough(
            user_client,
            group_bytes_hex,
            guarded_indices,
            [_compact_payload(target) for target in primary_targets],
        )
        assembly_passthrough.extend(primary_passthrough)

    assembly_targets = []
    for target in targets:
        index = target["target_index"]
        if index not in user_signatures:
            raise SignerError(f"missing user component signature for target {index}")
        if index not in sentry_signatures:
            raise SignerError(f"missing sentry component signature for target {index}")
        assembly_targets.append(GuardedAssemblyTarget(
            target_index=index,
            guarded_account=target["guarded_account"],
            user_signature=user_signatures[index]["signature"],
            user_source_request_id=user_signatures[index]["request_id"],
            sentry_signature=sentry_signatures[index]["signature"],
            sentry_source_request_id=sentry_signatures[index]["request_id"],
            runtime_args=target.get("runtime_args"),
        ))

    assembly_response = user_client.request_guarded_assemble(GuardedAssemblyRequest(
        request_id=assembly_request_id,
        group_bytes_hex=group_bytes_hex,
        targets=assembly_targets,
        passthrough=assembly_passthrough,
    ))
    return GuardedSignResult(
        signed_group=assembly_response.signed_group,
        user_component_responses=user_component_responses,
        sentry_component_responses=sentry_component_responses,
        primary_sign_response=primary_sign_response,
        assembly_response=assembly_response,
    )


def assemble_group(signed_lists: List[List[str]]) -> str:
    """
    Merge multi-party signed outputs into one complete group.

    Each signer produces a list of base64-encoded signed transactions,
    with empty strings ("") for slots they didn't sign (foreign entries).
    This function merges them so each slot has exactly one non-empty entry.

    Args:
        signed_lists: List of signed transaction lists from different signers.
            Each list must have the same length. For each index, exactly one
            list should have a non-empty entry.

    Returns:
        Base64-encoded concatenated signed transactions, ready for
        algod_client.send_raw_transaction().

    Raises:
        ValueError: If lists have different lengths, if a slot has no
            signed entry, or if multiple signers signed the same slot.

    Example:
        # Alice signs her txns, gets "" for Bob's slots
        alice_signed = alice_client.sign_transactions_list(...)
        # Bob signs his txns, gets "" for Alice's slots
        bob_signed = bob_client.sign_transactions_list(...)
        # Merge and submit
        combined = assemble_group([alice_signed, bob_signed])
        send_raw_transaction(algod_client, combined)
    """
    if not signed_lists:
        raise ValueError("signed_lists must not be empty")

    group_len = len(signed_lists[0])
    for i, sl in enumerate(signed_lists):
        if len(sl) != group_len:
            raise ValueError(
                f"signed_lists[{i}] has {len(sl)} entries, expected {group_len}"
            )

    merged = []
    for idx in range(group_len):
        entries = [sl[idx] for sl in signed_lists if sl[idx]]
        if len(entries) == 0:
            raise ValueError(f"slot {idx}: no signer provided a signed transaction")
        if len(entries) > 1:
            raise ValueError(f"slot {idx}: multiple signers provided a signed transaction")
        merged.append(entries[0])

    all_bytes = b"".join(base64.b64decode(s) for s in merged)
    return base64.b64encode(all_bytes).decode()


def send_raw_transaction(algod_client, signed_txn: str) -> str:
    """
    Submit a signed transaction to the network with clean error handling.

    Args:
        algod_client: algosdk AlgodClient instance
        signed_txn: Base64-encoded string from sign_transaction()

    Returns:
        Transaction ID

    Raises:
        LogicSigRejectedError: If a LogicSig program returned false
        InsufficientFundsError: If account has insufficient funds
        InvalidTransactionError: If transaction is malformed
        TransactionRejectedError: For other rejection reasons

    Note:
        You can also use algod_client.send_raw_transaction(signed_txn) directly
        if you don't need the clean error types.
    """
    from algosdk.error import AlgodHTTPError

    try:
        return algod_client.send_raw_transaction(signed_txn)
    except AlgodHTTPError as e:
        raise _parse_algod_error(e) from e


def _parse_algod_error(e: Exception) -> Exception:
    """
    Parse algod HTTP error into a clean aplane exception.

    Extracts the transaction ID and meaningful error reason from verbose
    algod error messages that include full struct dumps.
    """
    msg = str(e)

    # Try to extract transaction ID (appears before the colon in many errors)
    # Format: "TransactionPool.Remember: transaction XXXXX: error details"
    txid = "unknown"
    txid_match = re.search(r'transaction ([A-Z0-9]{52}):', msg)
    if txid_match:
        txid = txid_match.group(1)

    # LogicSig rejection
    if "rejected by logic" in msg.lower():
        return LogicSigRejectedError(txid, "LogicSig program returned false")

    # Insufficient funds / overspend
    if "overspend" in msg.lower() or "insufficient funds" in msg.lower():
        # Try to extract balance info if present
        balance_match = re.search(r'tried to spend \{(\d+)\}', msg)
        if balance_match:
            return InsufficientFundsError(
                txid, f"insufficient funds (tried to spend {balance_match.group(1)} microAlgos)"
            )
        return InsufficientFundsError(txid, "insufficient funds")

    # LogicSig pool budget exceeded
    if "logicsigs" in msg.lower() and "pool" in msg.lower():
        pool_match = re.search(r'had (\d+) bytes.*pool of (\d+) bytes', msg)
        if pool_match:
            return InvalidTransactionError(
                txid,
                f"LogicSig too large ({pool_match.group(1)} bytes exceeds {pool_match.group(2)} byte pool). "
                "Fee pooling should be automatic - ensure you're using sign_transaction() or sign_transactions()."
            )
        return InvalidTransactionError(txid, "LogicSig exceeds pool budget - fee pooling should be automatic via sign_transaction()")

    # Invalid group ID
    if "group" in msg.lower() and ("invalid" in msg.lower() or "mismatch" in msg.lower()):
        return InvalidTransactionError(txid, "invalid or mismatched group ID")

    # Fee too low
    if "fee" in msg.lower() and ("too small" in msg.lower() or "below" in msg.lower()):
        return InvalidTransactionError(txid, "transaction fee too low")

    # Round range errors
    if "round" in msg.lower() and ("past" in msg.lower() or "future" in msg.lower() or "invalid" in msg.lower()):
        return InvalidTransactionError(txid, "transaction round range invalid (expired or too far in future)")

    # Generic rejection - extract a cleaner message if possible
    # Look for the last meaningful phrase after struct dumps
    reason_match = re.search(r'\}: (.+?)(?:\s*$|\s*\{)', msg)
    if reason_match:
        reason = reason_match.group(1).strip()
        if reason:
            return TransactionRejectedError(txid, reason)

    # Fallback: return generic error with truncated message
    truncated = msg[:200] + "..." if len(msg) > 200 else msg
    return TransactionRejectedError(txid, truncated)


# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------

def load_token(path: str) -> str:
    """
    Load authentication token from file.

    Args:
        path: Path to aplane.token file

    Returns:
        Token string
    """
    with open(path, "r") as f:
        return f.read().strip()


def request_token(
    host: str,
    ssh_key_path: str,
    ssh_port: int = DEFAULT_SSH_PORT,
    identity: str = DEFAULT_PRODUCT_IDENTITY,
    known_hosts_path: Optional[str] = None,
    auto_add_host: bool = False,
) -> str:
    """
    Request an API token from apsigner via SSH.

    This connects to the signer's SSH server and requests a token.
    An operator (apadmin) must approve the request on the server side.

    The SSH key fingerprint is shown to the operator for verification.

    Args:
        host: Signer host (e.g., "signer.example.com" or "localhost")
        ssh_key_path: Path to SSH private key (e.g., "~/.ssh/id_ed25519")
        ssh_port: SSH port on remote (default: 1127)
        identity: Identity ID for the token (default: current product identity).
                  Non-product identities are rejected in the current single-operator mode.
        known_hosts_path: Path to known_hosts file (default: ~/.ssh/known_hosts)
        auto_add_host: If True, automatically trust unknown hosts (TOFU).
                       If False (default), prompt user for confirmation.

    Returns:
        The provisioned token string

    Raises:
        SignerError: If paramiko is not installed
        TokenProvisioningError: If provisioning fails (rejected, no operator, etc.)

    Example:
        # Request token interactively (prompts for host key confirmation)
        token = request_token(
            host="signer.example.com",
            ssh_key_path="~/.ssh/id_ed25519"
        )

        # Save to file
        with open("~/aplane/apclient/aplane.token", "w") as f:
            f.write(token)
    """
    _require_current_product_identity(identity)

    ssh_key_path = os.path.expanduser(ssh_key_path)
    if not os.path.exists(ssh_key_path):
        raise SignerError(f"SSH key not found: {ssh_key_path}")

    # Load the private key
    try:
        pkey = paramiko.Ed25519Key.from_private_key_file(ssh_key_path)
    except paramiko.ssh_exception.SSHException:
        # Try RSA if Ed25519 fails
        try:
            pkey = paramiko.RSAKey.from_private_key_file(ssh_key_path)
        except paramiko.ssh_exception.SSHException as e:
            raise SignerError(f"Failed to load SSH key: {e}")

    # Set up host key policy
    if known_hosts_path:
        known_hosts_path = os.path.expanduser(known_hosts_path)
    else:
        known_hosts_path = os.path.expanduser("~/.ssh/known_hosts")

    client = paramiko.SSHClient()

    # Load known hosts if file exists
    if os.path.exists(known_hosts_path):
        client.load_host_keys(known_hosts_path)

    if auto_add_host:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(_InteractiveHostKeyPolicy(known_hosts_path))

    # Connect with special username for token provisioning
    username = f"request-token:{identity}"

    try:
        client.connect(
            hostname=host,
            port=ssh_port,
            username=username,
            pkey=pkey,
            look_for_keys=False,
            allow_agent=False,
            timeout=30,
        )
    except paramiko.ssh_exception.AuthenticationException as e:
        raise TokenProvisioningError(f"SSH authentication failed: {e}")
    except paramiko.ssh_exception.SSHException as e:
        raise TokenProvisioningError(f"SSH connection failed: {e}")
    except Exception as e:
        raise TokenProvisioningError(f"Connection failed: {e}")

    try:
        # Execute the provisioning command
        # This blocks until operator approves or rejects
        stdin, stdout, stderr = client.exec_command("provision", timeout=300)

        # Wait for command to complete
        exit_status = stdout.channel.recv_exit_status()

        if exit_status != 0:
            error_msg = stderr.read().decode().strip()
            if not error_msg:
                error_msg = stdout.read().decode().strip()
            raise TokenProvisioningError(error_msg or "Token provisioning rejected")

        # Read the token from stdout
        token = stdout.read().decode().strip()
        if not token:
            raise TokenProvisioningError("Empty token received")

        return token

    finally:
        client.close()


class _InteractiveHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Host key policy that prompts user for confirmation (TOFU)."""

    def __init__(self, known_hosts_path: str):
        self.known_hosts_path = known_hosts_path

    def missing_host_key(self, client, hostname, key):
        fingerprint = key.get_fingerprint().hex()
        fingerprint_formatted = ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        key_type = key.get_name()

        print(f"\nUnknown host: {hostname}")
        print(f"Host key ({key_type}): {fingerprint_formatted}")
        response = input("Do you want to trust this server? [y/N]: ").strip().lower()

        if response not in ("y", "yes"):
            raise TokenProvisioningError("Host key rejected by user")

        # Save to known_hosts
        try:
            # Ensure directory exists
            known_hosts_dir = os.path.dirname(self.known_hosts_path)
            if known_hosts_dir and not os.path.exists(known_hosts_dir):
                os.makedirs(known_hosts_dir, mode=0o700)

            # Add key to known_hosts
            host_keys = paramiko.HostKeys()
            if os.path.exists(self.known_hosts_path):
                host_keys.load(self.known_hosts_path)
            host_keys.add(hostname, key.get_name(), key)
            host_keys.save(self.known_hosts_path)
            print(f"Host key saved to {self.known_hosts_path}")
        except Exception as e:
            print(f"Warning: Could not save host key: {e}")


def request_token_to_file(
    data_dir: Optional[str] = None,
    host: Optional[str] = None,
    ssh_port: Optional[int] = None,
    identity: str = DEFAULT_PRODUCT_IDENTITY,
    auto_add_host: bool = False,
) -> str:
    """
    Request a token and save it to the data directory.

    Convenience function that:
    1. Loads SSH key from config's identity_file
    2. Uses config's known_hosts_path for host verification
    3. Saves the token to data_dir/aplane.token

    Args:
        data_dir: Client data directory. Required unless APCLIENT_DATA env var is set.
        host: Signer host (default: from config.yaml endpoint.ssh.host)
        ssh_port: SSH port (default: from config.yaml endpoint.ssh.port or 1127)
        identity: Identity ID for the token (default: current product identity).
                  Non-product identities are rejected in the current single-operator mode.
        auto_add_host: If True, automatically trust unknown hosts

    Returns:
        Path to the saved token file

    Raises:
        SignerError: If data dir not resolvable or SSH key not found
        TokenProvisioningError: If provisioning fails

    Example:
        # Reads APCLIENT_DATA from environment
        request_token_to_file()

        # Or with explicit parameters
        request_token_to_file(data_dir="/custom/path", host="signer.example.com")

        # Now you can use SignerClient.from_env()
        client = SignerClient.from_env()
    """
    data_dir = _resolve_data_dir(data_dir)

    # Load config to get host/port if not specified
    config = load_config(data_dir)
    if host is None:
        if config.ssh is None:
            raise SignerError(
                "No host specified and no endpoint.ssh.host in config.yaml. "
                "Pass host parameter or add endpoint.ssh block to config.yaml."
            )
        host = config.ssh.host
    if ssh_port is None:
        ssh_port = config.ssh.port if config.ssh else DEFAULT_SSH_PORT

    # Use paths from config, or defaults
    if config.ssh:
        ssh_key_path = os.path.join(data_dir, config.ssh.identity_file)
        known_hosts_path = os.path.join(data_dir, config.ssh.known_hosts_path)
    else:
        ssh_key_path = os.path.join(data_dir, ".ssh", "id_ed25519")
        known_hosts_path = os.path.join(data_dir, ".ssh", "known_hosts")
    token_path = os.path.join(data_dir, "aplane.token")

    if not os.path.exists(ssh_key_path):
        raise SignerError(
            f"SSH key not found at {ssh_key_path}\n"
            "Create one with: ssh-keygen -t ed25519 -f " + ssh_key_path
        )

    print(f"Requesting token from {host} (SSH port: {ssh_port})...")
    print("This requires an operator (apadmin) to approve on the server.")
    print("Waiting for operator approval...")

    token = request_token(
        host=host,
        ssh_key_path=ssh_key_path,
        ssh_port=ssh_port,
        identity=identity,
        known_hosts_path=known_hosts_path,
        auto_add_host=auto_add_host,
    )

    # Save token with secure permissions
    fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token)

    print(f"✓ Token saved to {token_path}")
    return token_path
