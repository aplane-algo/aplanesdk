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
import copy
import json
import os
import re
import requests
import secrets
import socket
import threading
import time
from dataclasses import asdict, dataclass, is_dataclass
from typing import Optional, Dict, List, Any, Callable

from algosdk import abi, encoding, transaction
from algosdk.v2client import models

import paramiko

from ._ssh_tokenproof import IDENTITY as SSH_TOKEN_PROOF_IDENTITY
from ._ssh_tokenproof import TokenProofClient


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
APP_CALL_MAX_APP_ARGS = 16
APP_CALL_METHOD_ARGS_TUPLE_THRESHOLD = APP_CALL_MAX_APP_ARGS - 2
GUARDED_LSIG_BUDGET_BYTES = 1000
GUARDED_MAX_GROUP_SIZE = 16
GUARDED_DEFAULT_MIN_FEE = 1000
GUARDED_DUMMY_PROGRAM = bytes.fromhex("033120320312")

COMPONENT_SIGN_ROLE_USER = "user"
COMPONENT_SIGN_ROLE_SENTRY = "sentry"

# Signing choreography label for the sentry co-signed component flow (one
# user plus one sentry component signature per target, assembled via
# /sign/assemble). Signer inventory labels guarded keys with this flow;
# clients route on the label and must fail fast on flow labels they do not
# implement. An empty signing_flow means the ordinary /sign path.
SIGNING_FLOW_SENTRY1 = "sentry1"
SIGNING_FLOW_BOUNDED1 = "bounded1"
SIGNING_FLOW_BOUNDED_SENTRY1 = "bounded-sentry1"

KEY_TYPE_WITNESS_FALCON1024 = "aplane.witness-falcon1024.v1"
KEY_TYPE_GUARDED_FALCON1024_SENTRY1024 = "aplane.falcon1024-sentry1024.v1"

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

# Stable machine-readable error codes carried in ErrorResponse.code.
# These mirror the signer wire contract (pkg/signerapi/error_codes.go in the
# aplane repo). An empty code means the signer predates code support.
ERR_CODE_BAD_REQUEST = "bad_request"
ERR_CODE_UNAUTHORIZED = "unauthorized"
ERR_CODE_FORBIDDEN = "forbidden"
ERR_CODE_LOCKED = "locked"
ERR_CODE_NOT_FOUND = "not_found"
ERR_CODE_INVALID_PASSPHRASE = "invalid_passphrase"
ERR_CODE_UNAVAILABLE = "unavailable"
ERR_CODE_CACHE_REFRESH = "cache_refresh"
ERR_CODE_INTERNAL = "internal"
ERR_CODE_BOUNDED_ADMIN_REQUIRED = "bounded_admin_required"
ERR_CODE_BOUNDED_SENTRY_REQUIRED = "bounded_sentry_required"


class SignerError(Exception):
    """Base exception for signer errors.

    ``code`` carries the stable machine-readable wire error code from the
    signer when one was provided (see ERR_CODE_* constants); branch on it
    instead of matching message text. Empty when the signer predates wire
    error codes or the error was raised client-side.
    """

    def __init__(self, *args, code: str = ""):
        super().__init__(*args)
        self.code = code


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
    max_size: int = 0


# /keys exposes key-file-owned signing_args with the same item shape.
SigningArg = RuntimeArg


@dataclass
class BoundedSignatureArgLayout:
    count: int
    max_sizes: List[int]


@dataclass
class BoundedAdminOperationInfo:
    kind: str
    authorization: str
    policy_gate: str


@dataclass
class BoundedDerivedArgInfo:
    name: str
    kind: str
    parameter: str
    max_size: int


@dataclass
class BoundedArgumentPathMask:
    spend: str
    spending_rekey: str
    admin_rekey: str


@dataclass
class BoundedArgumentSlotInfo:
    index: int
    name: str
    source: str
    max_size: int
    paths: BoundedArgumentPathMask


@dataclass
class BoundedSentryAuthorizationInfo:
    """Public sentry authority embedded in a bounded account."""
    contract: str
    component_key_type: str
    public_key_hex: str = ""
    component_key_id: str = ""
    signature_max_size: int = 0
    required_on: Optional[List[str]] = None


@dataclass
class BoundedAuthorizationInfo:
    contract: str
    base_signature_arg_layout: BoundedSignatureArgLayout
    spend_effects: List[str]
    max_fee: int
    admin_operations: List[BoundedAdminOperationInfo]
    runtime_args: List[RuntimeArg]
    derived_args: List[BoundedDerivedArgInfo]
    argument_layout: List[BoundedArgumentSlotInfo]
    layer3_policy: str
    sentry: Optional[BoundedSentryAuthorizationInfo] = None
    admin_key_id: str = ""
    program_binding: str = ""
    post_signing_lsig_size: int = 0  # Admin-inclusive bounded size


@dataclass
class KeyInfo:
    """Information about a signing key"""
    address: str
    key_type: str
    public_key_hex: str = ""
    signing_flow: str = ""  # Signing choreography label (e.g. "sentry1"); empty = plain /sign
    sentry_component_key_type: str = ""  # Sentry component key type for signing flow "sentry1"
    lsig_size: int = 0  # Spend-path size for bounded1
    is_generic_lsig: bool = False
    is_witness_key: bool = False
    bounded_authorization: Optional[BoundedAuthorizationInfo] = None
    is_spending_account: Optional[bool] = None
    signing_args: Optional[List[SigningArg]] = None  # Key-file args required for LogicSigs
    parameters: Optional[Dict[str, str]] = None
    template_provenance_status: str = ""
    template_provenance_note: str = ""
    template_status: str = ""  # Legacy alias for template_provenance_status
    template_warning: str = ""  # Legacy alias for template_provenance_note


@dataclass
class SSHConfig:
    """SSH tunnel configuration for public-key plus mutual token-proof auth."""
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
    signing_flow: str = ""  # Signing choreography label (e.g. "sentry1"); empty = plain /sign
    sentry_component_key_type: str = ""  # Sentry component key type for signing flow "sentry1"
    bounded_authorization: Optional[BoundedAuthorizationInfo] = None
    creation_params: Optional[List[CreationParam]] = None
    runtime_args: Optional[List[RuntimeArg]] = None


@dataclass
class ProtocolVersion:
    """Signer wire-protocol version."""
    major: int = 0
    minor: int = 0


@dataclass
class StatusResponse:
    """Authenticated signer status from /status"""
    identity_id: str
    state: str
    signer_locked: bool
    ready_for_signing: bool
    key_count: int
    keyset_revision: int
    protocol_version: Optional[ProtocolVersion] = None
    build_version: str = ""
    approval_wait_seconds: int = 0
    node_role: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.protocol_version, dict):
            self.protocol_version = ProtocolVersion(**self.protocol_version)


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
class SimulationResult:
    """Result of ordinary signing followed by client-side algod simulation."""
    tx_ids: List[str]
    transactions: List[str]
    signed_group: List[str]
    response: Dict[str, Any]
    mutations: Optional[Dict[str, Any]] = None
    failed: bool = False


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
class BoundedComponentRequest:
    """Request payload for /sign/bounded-component."""
    requests: List[Dict[str, Any]]
    request_id: str = ""


@dataclass
class BoundedBaseComponent:
    """One user-signer contribution to bounded assembly."""
    target_index: int
    bounded_account: str
    base_signatures: List[str]
    assembly_receipt: str
    signature_scheme: str
    runtime_args: Optional[Dict[str, str]] = None


@dataclass
class BoundedComponentResponse:
    """Response payload from /sign/bounded-component."""
    request_id: str
    transactions: List[str]
    components: List[BoundedBaseComponent]
    mutations: Optional[Dict[str, Any]] = None


@dataclass
class BoundedAssemblyTarget:
    """One source-bound bounded-sentry assembly target."""
    target_index: int
    bounded_account: str
    base_signatures: List[str]
    assembly_receipt: str
    sentry_signature: str
    runtime_args: Optional[Dict[str, str]] = None
    base_source_request_id: str = ""
    sentry_source_request_id: str = ""


@dataclass
class BoundedAssemblyRequest:
    """Request payload for /sign/bounded-assemble."""
    group_bytes_hex: List[str]
    targets: List[BoundedAssemblyTarget]
    request_id: str = ""
    passthrough: Optional[List[GuardedPassthroughItem]] = None


@dataclass
class BoundedAssemblyResponse:
    """Response payload from /sign/bounded-assemble."""
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
    assembly_response: Optional[GuardedAssemblyResponse]
    primary_sign_response: Optional[GroupSignResponse] = None
    bounded_component_response: Optional[BoundedComponentResponse] = None
    bounded_assembly_response: Optional[BoundedAssemblyResponse] = None


@dataclass
class GuardedSimulationResult:
    """Complete guarded signing result and client-side simulation result."""
    signing: GuardedSignResult
    simulation: SimulationResult


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
    """Standard signer HTTP error body for non-2xx responses.

    ``code`` carries a stable machine-readable classification (see the
    ERR_CODE_* constants); branch on ``code``, never on ``error`` message
    text. Empty when the signer predates wire error codes.
    """
    error: str
    code: str = ""


@dataclass
class GenerateResult:
    """Result of key generation"""
    address: str
    key_type: str
    public_key_hex: str = ""
    is_witness_key: bool = False
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


def _simulate_signed_group(
    algod_client: Any,
    signed_group: List[str],
    mutations: Optional[Dict[str, Any]] = None,
) -> SimulationResult:
    if algod_client is None:
        raise ValueError("algod_client is required")
    if not signed_group:
        raise SignerError("signed group is empty")

    signed_transactions = []
    for index, signed_hex in enumerate(signed_group, start=1):
        if not signed_hex:
            raise SignerError(f"signed group position {index} is empty")
        try:
            signed_bytes = bytes.fromhex(signed_hex)
            signed = encoding.msgpack_decode(
                base64.b64encode(signed_bytes).decode()
            )
        except Exception as e:
            raise SignerError(
                f"signed group position {index} is invalid: {e}"
            ) from e
        if not hasattr(signed, "transaction"):
            raise SignerError(
                f"signed group position {index} does not contain a signed transaction"
            )
        signed_transactions.append(signed)

    def simulation_request(trace: bool) -> models.SimulateRequest:
        return models.SimulateRequest(
            txn_groups=[models.SimulateRequestTransactionGroup(
                txns=signed_transactions
            )],
            allow_empty_signatures=False,
            allow_more_logs=trace,
            exec_trace_config=(
                models.SimulateTraceConfig(enable=True, state_change=True)
                if trace else None
            ),
        )

    try:
        response = algod_client.simulate_transactions(simulation_request(True))
    except Exception:
        try:
            response = algod_client.simulate_transactions(simulation_request(False))
        except Exception as e:
            raise SignerError(f"simulation API call failed: {e}") from e

    if not isinstance(response, dict):
        raise SignerError("simulation API returned an invalid response")
    groups = response.get("txn-groups") or response.get("txn_groups") or []
    failure = ""
    if groups:
        failure = groups[0].get("failure-message") or groups[0].get(
            "failure_message", ""
        )

    return SimulationResult(
        tx_ids=[signed.get_txid() for signed in signed_transactions],
        transactions=[
            encode_transaction(signed.transaction)[0]
            for signed in signed_transactions
        ],
        signed_group=list(signed_group),
        mutations=mutations,
        response=response,
        failed=bool(failure),
    )


def _validate_group_sign_response(
    sign_entries: List[Dict[str, Any]], signed: List[str]
) -> None:
    """Reject truncated or partially empty /sign responses.

    A malformed signer reply must never submit an incomplete group. The
    server may append signed dummy transactions after the request slots, and
    foreign-mode slots are returned empty by design.
    """
    if len(signed) < len(sign_entries):
        raise SignerError(
            f"Server returned {len(signed)} signed transaction(s), "
            f"want at least {len(sign_entries)}"
        )
    for index, entry in enumerate(sign_entries):
        foreign = (
            bool(entry.get("txn_bytes_hex"))
            and not entry.get("auth_address")
            and not entry.get("signed_txn_hex")
        )
        if foreign:
            continue
        if not signed[index]:
            raise SignerError(
                f"Server returned no signature for position {index + 1}"
            )
    for index in range(len(sign_entries), len(signed)):
        if not signed[index]:
            raise SignerError(
                f"Server returned empty dummy transaction at position {index + 1}"
            )


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


def _parse_bounded_authorization(data: Any) -> Optional[BoundedAuthorizationInfo]:
    if not isinstance(data, dict):
        return None
    layout = data.get("base_signature_arg_layout") or {}
    operations = data.get("admin_operations") or []
    runtime_args = data.get("runtime_args") or []
    derived_args = data.get("derived_args") or []
    argument_layout = data.get("argument_layout") or []
    sentry = data.get("sentry")
    return BoundedAuthorizationInfo(
        contract=data.get("contract", ""),
        base_signature_arg_layout=BoundedSignatureArgLayout(
            count=layout.get("count", 0), max_sizes=list(layout.get("max_sizes") or [])
        ),
        spend_effects=list(data.get("spend_effects") or []),
        max_fee=data.get("max_fee", 0),
        admin_operations=[
            BoundedAdminOperationInfo(
                kind=item.get("kind", ""),
                authorization=item.get("authorization", ""),
                policy_gate=item.get("policy_gate", ""),
            )
            for item in operations
        ],
        runtime_args=[
            RuntimeArg(
                name=item.get("name", ""),
                arg_type=item.get("type", "bytes"),
                description=item.get("description", ""),
                label=item.get("label", ""),
                required=item.get("required", False),
                byte_length=item.get("byte_length", 0),
                max_size=item.get("max_size", 0),
            )
            for item in runtime_args
        ],
        derived_args=[
            BoundedDerivedArgInfo(
                name=item.get("name", ""),
                kind=item.get("kind", ""),
                parameter=item.get("parameter", ""),
                max_size=item.get("max_size", 0),
            )
            for item in derived_args
        ],
        argument_layout=[
            BoundedArgumentSlotInfo(
                index=item.get("index", 0),
                name=item.get("name", ""),
                source=item.get("source", ""),
                max_size=item.get("max_size", 0),
                paths=BoundedArgumentPathMask(
                    spend=(item.get("paths") or {}).get("spend", ""),
                    spending_rekey=(item.get("paths") or {}).get("spending_rekey", ""),
                    admin_rekey=(item.get("paths") or {}).get("admin_rekey", ""),
                ),
            )
            for item in argument_layout
        ],
        layer3_policy=data.get("layer3_policy", ""),
        sentry=(
            BoundedSentryAuthorizationInfo(
                contract=sentry.get("contract", ""),
                component_key_type=sentry.get("component_key_type", ""),
                public_key_hex=sentry.get("public_key_hex", ""),
                component_key_id=sentry.get("component_key_id", ""),
                signature_max_size=sentry.get("signature_max_size", 0),
                required_on=list(sentry.get("required_on") or []),
            )
            if isinstance(sentry, dict)
            else None
        ),
        admin_key_id=data.get("admin_key_id", ""),
        program_binding=data.get("program_binding", ""),
        post_signing_lsig_size=data.get("post_signing_lsig_size", 0),
    )


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


def _validate_bounded_component_request(data: Dict[str, Any]) -> None:
    _validate_sign_request_id(str(data.get("request_id", "")))
    requests_data = data.get("requests") or []
    if not requests_data:
        raise ValueError("requests array is empty")
    sign_count = 0
    foreign_count = 0
    for index, item in enumerate(requests_data, start=1):
        has_auth = bool(item.get("auth_address"))
        has_txn = bool(item.get("txn_bytes_hex"))
        has_passthrough = bool(item.get("signed_txn_hex"))
        if has_passthrough and (has_auth or has_txn):
            raise ValueError(f"transaction {index}: sign and passthrough fields cannot be mixed")
        if has_passthrough:
            raise ValueError(
                "bounded-component does not accept signed passthrough entries"
            )
        elif has_auth and has_txn:
            sign_count += 1
        elif has_txn:
            foreign_count += 1
        else:
            raise ValueError(f"transaction {index}: unsupported request mode")
    if sign_count == 0 and foreign_count:
        raise ValueError("no signable transactions")


def _validate_bounded_component_response(data: Dict[str, Any]) -> None:
    request_id = data.get("request_id", "")
    _validate_sign_request_id(str(request_id), required=True)
    transactions = data.get("transactions") or []
    components = data.get("components") or []
    if not transactions or not components:
        raise ValueError("transactions and components are required")
    seen = set()
    for index, component in enumerate(components, start=1):
        target = component.get("target_index")
        if (
            not isinstance(target, int)
            or target < 0
            or target >= len(transactions)
            or target in seen
        ):
            raise ValueError(f"component {index} has invalid or duplicate target_index")
        seen.add(target)
        if (
            not component.get("bounded_account")
            or not component.get("base_signatures")
            or not component.get("assembly_receipt")
            or not component.get("signature_scheme")
        ):
            raise ValueError(f"component {index} is incomplete")


def _validate_bounded_assembly_request(data: Dict[str, Any]) -> None:
    _validate_sign_request_id(str(data.get("request_id", "")))
    group_bytes_hex = data.get("group_bytes_hex") or []
    targets = data.get("targets") or []
    passthrough = data.get("passthrough") or []
    _validate_component_group_bytes(group_bytes_hex)
    if not targets:
        raise ValueError("targets array is empty")
    covered: set[int] = set()
    for index, target in enumerate(targets, start=1):
        _validate_assembly_index(target.get("target_index"), len(group_bytes_hex), covered)
        if (
            not target.get("bounded_account")
            or not target.get("base_signatures")
            or not target.get("assembly_receipt")
            or not target.get("sentry_signature")
        ):
            raise ValueError(
                f"target {index}: bounded_account, base_signatures, "
                "assembly_receipt, and sentry_signature are required"
            )
    for index, item in enumerate(passthrough, start=1):
        _validate_assembly_index(item.get("target_index"), len(group_bytes_hex), covered)
        if not item.get("signed_txn_hex"):
            raise ValueError(f"passthrough {index}: signed_txn_hex is required")
    for index in range(len(group_bytes_hex)):
        if index not in covered:
            raise ValueError(f"group position {index} is not covered by targets or passthrough")


def _validate_bounded_assembly_response(data: Dict[str, Any]) -> None:
    _validate_guarded_assembly_response(data)


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
    # No fee-per-byte mode: fee is always flat microAlgos, so a set fee can
    # never be silently reinterpreted as EstimateSize*fee. None means unset
    # (keep the suggested fee); an explicit int (including 0, used for fee
    # pooling) is applied as a flat fee. use_flat_fee is accepted for signature
    # compatibility but no longer selects a per-byte fee.
    _ = use_flat_fee
    if fee is None:
        return
    params.fee = fee
    params.flat_fee = True


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


def _account_list(account_info: Any, *names: str) -> List[Any]:
    if isinstance(account_info, dict):
        for name in names:
            value = account_info.get(name)
            if value:
                return list(value)
        return []
    for name in names:
        value = getattr(account_info, name, None)
        if value:
            return list(value)
    return []


def _account_int(account_info: Any, *names: str) -> int:
    if isinstance(account_info, dict):
        for name in names:
            value = account_info.get(name)
            if value is not None:
                return int(value)
        return 0
    for name in names:
        value = getattr(account_info, name, None)
        if value is not None:
            return int(value)
    return 0


def _account_status(account_info: Any) -> str:
    if isinstance(account_info, dict):
        return str(account_info.get("status", ""))
    return str(getattr(account_info, "status", ""))


def _asa_opt_in_checks(account_info: Any, asset_id: int, fee: int) -> List[PreparedCheck]:
    if _account_asset_holding(account_info, asset_id) is not None:
        raise SignerError(f"sender is already opted into asset {asset_id}")
    if _account_amount(account_info) < fee:
        raise SignerError(
            f"insufficient funds for opt-in fee: balance {_account_amount(account_info)}, fee {fee}"
        )
    return [
        PreparedCheck(
            name="asa_opt_in",
            status="ok",
            data={"asset_id": asset_id, "fee": fee},
        )
    ]


def _asa_opt_out_checks(sender_info: Any, close_info: Any, asset_id: int, close_to: str) -> List[PreparedCheck]:
    holding = _account_asset_holding(sender_info, asset_id)
    if holding is None:
        raise SignerError(f"sender is not opted into asset {asset_id}")
    if _account_asset_holding(close_info, asset_id) is None:
        raise SignerError(f"close_to is not opted into asset {asset_id}")
    return [
        PreparedCheck(
            name="asa_opt_out",
            status="ok",
            data={
                "asset_id": asset_id,
                "balance": _asset_holding_amount(holding),
                "close_to": close_to,
            },
        )
    ]


def _account_close_checks(account_info: Any, fee: int) -> List[PreparedCheck]:
    if _account_status(account_info).lower() == "online":
        raise SignerError("cannot close an online account")
    if (
        _account_list(account_info, "assets")
        or _account_int(account_info, "total-assets-opted-in", "total_assets_opted_in", "totalAssetsOptedIn") > 0
    ):
        raise SignerError("cannot close account with ASA holdings")
    if (
        _account_list(account_info, "created-assets", "created_assets", "createdAssets")
        or _account_int(account_info, "total-created-assets", "total_created_assets", "totalCreatedAssets") > 0
    ):
        raise SignerError("cannot close account with created assets")
    if (
        _account_list(account_info, "apps-local-state", "apps_local_state", "appsLocalState")
        or _account_int(account_info, "total-apps-opted-in", "total_apps_opted_in", "totalAppsOptedIn") > 0
    ):
        raise SignerError("cannot close account with app opt-ins")
    if (
        _account_list(account_info, "created-apps", "created_apps", "createdApps")
        or _account_int(account_info, "total-created-apps", "total_created_apps", "totalCreatedApps") > 0
    ):
        raise SignerError("cannot close account with created apps")
    if _account_amount(account_info) < fee:
        raise SignerError(
            f"insufficient funds for close fee: balance {_account_amount(account_info)}, fee {fee}"
        )
    return [
        PreparedCheck(
            name="account_close",
            status="ok",
            data={
                "balance": _account_amount(account_info),
                "min_balance": _account_min_balance(account_info),
                "fee": fee,
            },
        )
    ]


def _rekey_checks(target_info: Any, rekey_to: str) -> List[PreparedCheck]:
    auth_addr = _extract_auth_address(target_info)
    if auth_addr and auth_addr != rekey_to:
        raise SignerError(f"rekey target is itself rekeyed to {auth_addr}")
    return [
        PreparedCheck(
            name="rekey",
            status="ok",
            data={"rekey_to": rekey_to},
        )
    ]


def _validate_keyreg_params(
    *,
    nonpart: bool,
    votekey: Optional[str],
    selkey: Optional[str],
    votefst: Optional[int],
    votelst: Optional[int],
    votekd: Optional[int],
) -> None:
    if nonpart:
        return
    if not votekey:
        raise ValueError("votekey is required")
    if not selkey:
        raise ValueError("selkey is required")
    if not votefst:
        raise ValueError("votefst is required")
    if not votelst:
        raise ValueError("votelst is required")
    if votelst < votefst:
        raise ValueError("votelst must be greater than or equal to votefst")
    if not votekd:
        raise ValueError("votekd is required")


def _validate_payment_group(transactions: List[PreparedTransaction]) -> PreparedCheck:
    totals: Dict[str, Dict[str, int]] = {}
    for item in transactions:
        if item.transaction is None:
            raise ValueError("payment group transaction is required")
        sender = item.transaction.sender
        total = totals.setdefault(sender, {"available": 0, "required": 0})
        amount = int(getattr(item.transaction, "amt", getattr(item.transaction, "amount", 0)))
        fee = int(getattr(item.transaction, "fee", 0))
        total["required"] += amount + fee
        for check in item.checks or []:
            if check.name == "payment_balance" and check.data:
                total["available"] = int(check.data.get("available", 0))
    for sender, total in totals.items():
        if total["available"] < total["required"]:
            raise SignerError(
                f"payment group insufficient funds for {sender}: "
                f"available {total['available']}, required {total['required']}"
            )
    return PreparedCheck(
        name="payment_group_balance",
        status="ok",
        data={"sender_count": len(totals)},
    )


def _validate_asa_transfer_group(transactions: List[PreparedTransaction]) -> PreparedCheck:
    totals: Dict[str, Dict[str, int]] = {}
    for item in transactions:
        if item.transaction is None:
            raise ValueError("ASA transfer group transaction is required")
        sender = item.transaction.sender
        asset_id = int(item.transaction.index)
        key = f"{sender}:{asset_id}"
        total = totals.setdefault(key, {"balance": 0, "amount": 0})
        total["amount"] += int(item.transaction.amount)
        for check in item.checks or []:
            if check.name == "asa_transfer" and check.data:
                total["balance"] = int(check.data.get("balance", 0))
    for key, total in totals.items():
        if total["balance"] < total["amount"]:
            raise SignerError(
                f"ASA transfer group insufficient asset balance for {key}: "
                f"available {total['balance']}, required {total['amount']}"
            )
    return PreparedCheck(
        name="asa_transfer_group_balance",
        status="ok",
        data={"holding_count": len(totals)},
    )


def _app_call_checks(
    app_id: int,
    on_complete: Any,
    app_args: Optional[List[bytes]],
    accounts: Optional[List[str]],
    foreign_apps: Optional[List[int]],
    foreign_assets: Optional[List[int]],
    boxes: Optional[List[Any]],
    app_call_info: Dict[str, str],
) -> List[PreparedCheck]:
    data: Dict[str, Any] = {
        "app_id": app_id,
        "on_completion": int(on_complete),
        "args": len(app_args or []),
        "accounts": len(accounts or []),
        "foreign_apps": len(foreign_apps or []),
        "foreign_assets": len(foreign_assets or []),
        "boxes": len(boxes or []),
        "mode": app_call_info.get("mode"),
    }
    if app_call_info.get("method"):
        data["method"] = app_call_info["method"]
    return [PreparedCheck(name="app_call", status="ok", data=data)]


def _encode_abi_method_args(
    method: abi.Method,
    args: List[Any],
    sender: str,
    app_id: int,
    accounts: Optional[List[str]],
    foreign_apps: Optional[List[int]],
    foreign_assets: Optional[List[int]],
) -> tuple[List[bytes], List[str], List[int], List[int]]:
    if len(args) != len(method.args):
        raise ValueError(
            f"incorrect number of ABI arguments: got {len(args)}, want {len(method.args)}"
        )

    basic_arg_types: List[Any] = []
    basic_arg_values: List[Any] = []
    ref_arg_types: List[str] = []
    ref_arg_values: List[Any] = []
    ref_arg_index_to_basic_arg_index: Dict[int, int] = {}

    transaction_types = {"txn", "pay", "keyreg", "acfg", "axfer", "afrz", "appl"}
    reference_types = {"account", "application", "asset"}

    for index, method_arg in enumerate(method.args):
        arg_type = method_arg.type
        arg_value = args[index]
        if isinstance(arg_type, str) and arg_type in transaction_types:
            raise ValueError("ABI transaction arguments are not supported by prepare_abi_app_call")
        if isinstance(arg_type, str) and arg_type in reference_types:
            ref_arg_index_to_basic_arg_index[len(ref_arg_types)] = len(basic_arg_types)
            ref_arg_types.append(arg_type)
            ref_arg_values.append(arg_value)
            abi_type = abi.ABIType.from_string("uint8")
        elif isinstance(arg_type, str):
            abi_type = abi.ABIType.from_string(arg_type)
        else:
            abi_type = arg_type

        basic_arg_types.append(abi_type)
        basic_arg_values.append(arg_value)

    resolved_accounts = list(accounts or [])
    resolved_apps = list(foreign_apps or [])
    resolved_assets = list(foreign_assets or [])
    ref_indexes = _resolve_abi_reference_args(
        sender,
        app_id,
        ref_arg_types,
        ref_arg_values,
        resolved_accounts,
        resolved_apps,
        resolved_assets,
    )
    for ref_index, resolved in enumerate(ref_indexes):
        if resolved > 255:
            raise ValueError(f"ABI reference index {resolved} exceeds uint8")
        basic_arg_values[ref_arg_index_to_basic_arg_index[ref_index]] = resolved

    if len(basic_arg_values) > APP_CALL_MAX_APP_ARGS - 1:
        tuple_types = basic_arg_types[APP_CALL_METHOD_ARGS_TUPLE_THRESHOLD:]
        tuple_values = basic_arg_values[APP_CALL_METHOD_ARGS_TUPLE_THRESHOLD:]
        tuple_type = abi.ABIType.from_string(
            "(" + ",".join(str(arg_type) for arg_type in tuple_types) + ")"
        )
        basic_arg_types = basic_arg_types[:APP_CALL_METHOD_ARGS_TUPLE_THRESHOLD]
        basic_arg_values = basic_arg_values[:APP_CALL_METHOD_ARGS_TUPLE_THRESHOLD]
        basic_arg_types.append(tuple_type)
        basic_arg_values.append(tuple_values)

    encoded_args = [method.get_selector()]
    for arg_type, arg_value in zip(basic_arg_types, basic_arg_values):
        encoded_args.append(arg_type.encode(arg_value))

    return encoded_args, resolved_accounts, resolved_apps, resolved_assets


def _resolve_abi_reference_args(
    sender: str,
    app_id: int,
    arg_types: List[str],
    values: List[Any],
    accounts: List[str],
    apps: List[int],
    assets: List[int],
) -> List[int]:
    resolved: List[int] = []
    for arg_type, value in zip(arg_types, values):
        if arg_type == "account":
            address = _marshal_abi_address(value)
            if address == sender:
                resolved.append(0)
            elif address in accounts:
                resolved.append(accounts.index(address) + 1)
            else:
                accounts.append(address)
                resolved.append(len(accounts))
        elif arg_type == "application":
            ref_app_id = int(value)
            if ref_app_id == app_id:
                resolved.append(0)
            elif ref_app_id in apps:
                resolved.append(apps.index(ref_app_id) + 1)
            else:
                apps.append(ref_app_id)
                resolved.append(len(apps))
        elif arg_type == "asset":
            asset_id = int(value)
            if asset_id in assets:
                resolved.append(assets.index(asset_id))
            else:
                assets.append(asset_id)
                resolved.append(len(assets) - 1)
        else:
            raise ValueError(f"unknown reference type: {arg_type}")
    return resolved


def _marshal_abi_address(value: Any) -> str:
    if isinstance(value, str):
        encoding.decode_address(value)
        return value
    if isinstance(value, bytes):
        if len(value) != 32:
            raise ValueError("decoded value is not a 32-byte address")
        return encoding.encode_address(value)
    raise ValueError("account reference arguments must be Algorand addresses")


# -----------------------------------------------------------------------------
# Signer Client
# -----------------------------------------------------------------------------


def _find_free_port() -> int:
    """Find an available local port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _continue_keyboard_interactive_auth(
    transport: paramiko.Transport,
    username: str,
    handler: Callable[[str, str, list[tuple[str, bool]]], list[str]],
) -> list[str]:
    """Continue partial auth without sending a second SSH service request."""
    auth_handler = transport.auth_handler
    if auth_handler is None:
        raise paramiko.SSHException("SSH authentication handler is unavailable")

    # Paramiko's public auth_interactive() creates a new AuthHandler, which
    # sends another ssh-userauth service request. After partial success the SSH
    # protocol requires the next USERAUTH_REQUEST on the existing service.
    event = threading.Event()
    with transport.lock:
        transport.saved_exception = None
        auth_handler.auth_event = event
        auth_handler.auth_method = "keyboard-interactive"
        auth_handler.username = username
        auth_handler.interactive_handler = handler
        auth_handler.submethods = ""

        request = paramiko.Message()
        request.add_byte(paramiko.common.cMSG_USERAUTH_REQUEST)
        request.add_string(username)
        request.add_string("ssh-connection")
        request.add_string("keyboard-interactive")
        request.add_string("")  # language tag
        request.add_string("")  # submethods
        transport._send_message(request)

    return auth_handler.wait_for_response(event)


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
        token: str,
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
        self._token = token
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

        sock: Optional[socket.socket] = None
        transport: Optional[paramiko.Transport] = None
        proof: Optional[TokenProofClient] = None
        try:
            sock = socket.create_connection((self._ssh_host, self._ssh_port))
            transport = paramiko.Transport(sock)
            transport.start_client()
            server_key = transport.get_remote_server_key()
            self._verify_host_key(server_key)

            proof = TokenProofClient(self._token)
            proof.capture_host_key(server_key.asbytes())
            methods = transport.auth_publickey(SSH_TOKEN_PROOF_IDENTITY, pkey)
            if transport.is_authenticated() or "keyboard-interactive" not in methods:
                raise SignerError(
                    "SSH server did not require token proof after public-key authentication"
                )
            _continue_keyboard_interactive_auth(
                transport, SSH_TOKEN_PROOF_IDENTITY, proof.challenge
            )
            if not transport.is_authenticated() or not proof.server_verified:
                raise SignerError("SSH token proof authentication did not complete")
        except SignerError:
            if transport:
                transport.close()
            elif sock:
                sock.close()
            raise
        except paramiko.ssh_exception.SSHException as e:
            if transport:
                transport.close()
            elif sock:
                sock.close()
            raise SignerError(f"SSH connection failed: {e}")
        except Exception:
            if transport:
                transport.close()
            elif sock:
                sock.close()
            raise
        finally:
            if proof is not None:
                proof.clear()

        self._transport = transport

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

    def _verify_host_key(self, server_key: paramiko.PKey) -> None:
        """Verify or persist the negotiated key before authentication."""
        host_entry = (
            self._ssh_host
            if self._ssh_port == 22
            else f"[{self._ssh_host}]:{self._ssh_port}"
        )
        host_keys = paramiko.HostKeys()
        if os.path.exists(self._known_hosts_path):
            host_keys.load(self._known_hosts_path)
        known = host_keys.lookup(host_entry)
        if known is not None:
            expected = known.get(server_key.get_name())
            if expected is None or expected != server_key:
                raise SignerError(
                    f"SSH host key mismatch for {self._ssh_host}:{self._ssh_port} "
                    f"(possible MITM attack); remove the old key from "
                    f"{self._known_hosts_path} to connect"
                )
            return

        if not self._trust_on_first_use:
            raise SignerError(
                f"Unknown SSH host key for {self._ssh_host}:{self._ssh_port}; "
                f"to trust this host, set endpoint.ssh.trust_on_first_use: true in config.yaml, "
                f"or connect via apshell first to save the host key to "
                f"{self._known_hosts_path}"
            )

        known_hosts_dir = os.path.dirname(self._known_hosts_path)
        if known_hosts_dir:
            os.makedirs(known_hosts_dir, mode=0o700, exist_ok=True)
        host_keys.add(host_entry, server_key.get_name(), server_key)
        host_keys.save(self._known_hosts_path)
        os.chmod(self._known_hosts_path, 0o600)

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
        the signer port to a local port. Uses public-key authentication plus a
        host-key-bound token proof.

        Args:
            host: Remote host running apsigner
            token: Authentication token (proven during SSH auth and used by the HTTP API)
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
            tunnel = _SSHTunnel(
                ssh_host=host,
                ssh_port=ssh_port,
                token=token,
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
            raise self._signer_http_error(
                resp,
                f"Failed to get signer status: HTTP {resp.status_code}",
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
            protocol_version=data.get("protocol_version"),
            build_version=data.get("build_version", ""),
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
            raise self._signer_http_error(resp, f"Failed to list keys: HTTP {resp.status_code}")

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
                        max_size=arg.get("max_size", 0),
                    )
                    for arg in k["signing_args"]
                ]

            key_info = KeyInfo(
                address=k["address"],
                key_type=k["key_type"],
                public_key_hex=k.get("public_key_hex", ""),
                signing_flow=k.get("signing_flow", ""),
                sentry_component_key_type=k.get("sentry_component_key_type", ""),
                lsig_size=k.get("lsig_size", 0),
                is_generic_lsig=k.get("is_generic_lsig", False),
                is_witness_key=k.get("is_witness_key", False),
                bounded_authorization=_parse_bounded_authorization(k.get("bounded_authorization")),
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
                    data={
                        "asset_id": asset_id,
                        "amount": amount,
                        "balance": sender_amount,
                    },
                )
            ],
        )

    def prepare_asa_opt_in(
        self,
        algod_client: Any,
        *,
        sender: str,
        asset_id: int,
        note: Optional[bytes] = None,
        fee: Optional[int] = None,
        use_flat_fee: bool = False,
    ) -> PreparedTransaction:
        """Build a prepared ASA opt-in transaction."""
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        if not asset_id:
            raise ValueError("asset_id is required")

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee, use_flat_fee)

        sender_info = algod_client.account_info(sender)
        checks = _asa_opt_in_checks(sender_info, asset_id, int(getattr(params, "fee", 0)))
        txn = transaction.AssetTransferTxn(
            sender=sender,
            sp=params,
            receiver=sender,
            amt=0,
            index=asset_id,
            note=note,
        )
        resolved = self.resolve_auth_address(sender, lambda _: sender_info)
        return PreparedTransaction(
            transaction=txn,
            auth_address=resolved.auth_address,
            signer_key=resolved.key_info,
            checks=checks,
        )

    def prepare_asa_opt_out(
        self,
        algod_client: Any,
        *,
        sender: str,
        asset_id: int,
        close_to: str,
        note: Optional[bytes] = None,
        fee: Optional[int] = None,
        use_flat_fee: bool = False,
    ) -> PreparedTransaction:
        """Build a prepared ASA opt-out transaction."""
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        if not close_to:
            raise ValueError("close_to is required")
        if sender == close_to:
            raise ValueError("close_to must differ from sender")
        if not asset_id:
            raise ValueError("asset_id is required")

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee, use_flat_fee)

        sender_info = algod_client.account_info(sender)
        close_info = algod_client.account_info(close_to)
        checks = _asa_opt_out_checks(sender_info, close_info, asset_id, close_to)
        txn = transaction.AssetTransferTxn(
            sender=sender,
            sp=params,
            receiver=sender,
            amt=0,
            index=asset_id,
            close_assets_to=close_to,
            note=note,
        )
        resolved = self.resolve_auth_address(sender, lambda _: sender_info)
        return PreparedTransaction(
            transaction=txn,
            auth_address=resolved.auth_address,
            signer_key=resolved.key_info,
            checks=checks,
        )

    def prepare_account_close(
        self,
        algod_client: Any,
        *,
        sender: str,
        close_to: str,
        note: Optional[bytes] = None,
        fee: Optional[int] = None,
        use_flat_fee: bool = False,
    ) -> PreparedTransaction:
        """Build a prepared account close transaction."""
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        if not close_to:
            raise ValueError("close_to is required")
        if sender == close_to:
            raise ValueError("close_to must differ from sender")

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee, use_flat_fee)

        sender_info = algod_client.account_info(sender)
        checks = _account_close_checks(sender_info, int(getattr(params, "fee", 0)))
        txn = transaction.PaymentTxn(
            sender=sender,
            sp=params,
            receiver=close_to,
            amt=0,
            close_remainder_to=close_to,
            note=note,
        )
        resolved = self.resolve_auth_address(sender, lambda _: sender_info)
        return PreparedTransaction(
            transaction=txn,
            auth_address=resolved.auth_address,
            signer_key=resolved.key_info,
            checks=checks,
        )

    def prepare_rekey(
        self,
        algod_client: Any,
        *,
        sender: str,
        rekey_to: str,
        note: Optional[bytes] = None,
        fee: Optional[int] = None,
        use_flat_fee: bool = False,
    ) -> PreparedTransaction:
        """Build a prepared self-payment rekey transaction."""
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        if not rekey_to:
            raise ValueError("rekey_to is required")

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee, use_flat_fee)

        sender_info = algod_client.account_info(sender)
        target_info = {"address": rekey_to}
        if rekey_to != sender:
            target_info = algod_client.account_info(rekey_to)
        checks = _rekey_checks(target_info, rekey_to)
        txn = transaction.PaymentTxn(
            sender=sender,
            sp=params,
            receiver=sender,
            amt=0,
            note=note,
            rekey_to=rekey_to,
        )
        resolved = self.resolve_auth_address(sender, lambda _: sender_info)
        return PreparedTransaction(
            transaction=txn,
            auth_address=resolved.auth_address,
            signer_key=resolved.key_info,
            checks=checks,
        )

    def prepare_keyreg(
        self,
        algod_client: Any,
        *,
        sender: str,
        votekey: Optional[str] = None,
        selkey: Optional[str] = None,
        votefst: Optional[int] = None,
        votelst: Optional[int] = None,
        votekd: Optional[int] = None,
        sprfkey: Optional[str] = None,
        nonpart: bool = False,
        note: Optional[bytes] = None,
        fee: Optional[int] = None,
        use_flat_fee: bool = False,
    ) -> PreparedTransaction:
        """Build a prepared key registration transaction."""
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        _validate_keyreg_params(
            nonpart=nonpart,
            votekey=votekey,
            selkey=selkey,
            votefst=votefst,
            votelst=votelst,
            votekd=votekd,
        )

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee, use_flat_fee)

        sender_info = algod_client.account_info(sender)
        txn = transaction.KeyregTxn(
            sender=sender,
            sp=params,
            votekey=votekey,
            selkey=selkey,
            votefst=votefst,
            votelst=votelst,
            votekd=votekd,
            sprfkey=sprfkey,
            nonpart=nonpart,
            note=note,
        )
        resolved = self.resolve_auth_address(sender, lambda _: sender_info)
        return PreparedTransaction(
            transaction=txn,
            auth_address=resolved.auth_address,
            signer_key=resolved.key_info,
            checks=[
                PreparedCheck(
                    name="keyreg",
                    status="ok",
                    data={
                        "nonparticipation": nonpart,
                        "vote_first": votefst or 0,
                        "vote_last": votelst or 0,
                        "vote_key_dilution": votekd or 0,
                    },
                )
            ],
        )

    def prepare_app_call(
        self,
        algod_client: Any,
        *,
        sender: str,
        app_id: int,
        on_complete: Any = transaction.OnComplete.NoOpOC,
        app_args: Optional[List[bytes]] = None,
        accounts: Optional[List[str]] = None,
        foreign_apps: Optional[List[int]] = None,
        foreign_assets: Optional[List[int]] = None,
        boxes: Optional[List[Any]] = None,
        approval_program: Optional[bytes] = None,
        clear_program: Optional[bytes] = None,
        local_schema: Optional[transaction.StateSchema] = None,
        global_schema: Optional[transaction.StateSchema] = None,
        note: Optional[bytes] = None,
        fee: Optional[int] = None,
        use_flat_fee: bool = False,
    ) -> PreparedTransaction:
        """Build a prepared raw app-call transaction."""
        return self._prepare_app_call(
            algod_client,
            sender=sender,
            app_id=app_id,
            on_complete=on_complete,
            app_args=app_args,
            accounts=accounts,
            foreign_apps=foreign_apps,
            foreign_assets=foreign_assets,
            boxes=boxes,
            approval_program=approval_program,
            clear_program=clear_program,
            local_schema=local_schema,
            global_schema=global_schema,
            note=note,
            fee=fee,
            use_flat_fee=use_flat_fee,
            app_call_info={"mode": "raw"},
        )

    def prepare_abi_app_call(
        self,
        algod_client: Any,
        *,
        sender: str,
        app_id: int,
        method_signature: str,
        args: Optional[List[Any]] = None,
        on_complete: Any = transaction.OnComplete.NoOpOC,
        accounts: Optional[List[str]] = None,
        foreign_apps: Optional[List[int]] = None,
        foreign_assets: Optional[List[int]] = None,
        boxes: Optional[List[Any]] = None,
        approval_program: Optional[bytes] = None,
        clear_program: Optional[bytes] = None,
        local_schema: Optional[transaction.StateSchema] = None,
        global_schema: Optional[transaction.StateSchema] = None,
        note: Optional[bytes] = None,
        fee: Optional[int] = None,
        use_flat_fee: bool = False,
    ) -> PreparedTransaction:
        """Build a prepared ABI method-call transaction."""
        if not method_signature:
            raise ValueError("method_signature is required")
        method = abi.Method.from_signature(method_signature)
        app_args, resolved_accounts, resolved_apps, resolved_assets = _encode_abi_method_args(
            method,
            list(args or []),
            sender,
            app_id,
            accounts,
            foreign_apps,
            foreign_assets,
        )
        return self._prepare_app_call(
            algod_client,
            sender=sender,
            app_id=app_id,
            on_complete=on_complete,
            app_args=app_args,
            accounts=resolved_accounts,
            foreign_apps=resolved_apps,
            foreign_assets=resolved_assets,
            boxes=boxes,
            approval_program=approval_program,
            clear_program=clear_program,
            local_schema=local_schema,
            global_schema=global_schema,
            note=note,
            fee=fee,
            use_flat_fee=use_flat_fee,
            app_call_info={"mode": "abi", "method": method.get_signature()},
        )

    def _prepare_app_call(
        self,
        algod_client: Any,
        *,
        sender: str,
        app_id: int,
        on_complete: Any,
        app_args: Optional[List[bytes]],
        accounts: Optional[List[str]],
        foreign_apps: Optional[List[int]],
        foreign_assets: Optional[List[int]],
        boxes: Optional[List[Any]],
        approval_program: Optional[bytes],
        clear_program: Optional[bytes],
        local_schema: Optional[transaction.StateSchema],
        global_schema: Optional[transaction.StateSchema],
        note: Optional[bytes],
        fee: Optional[int],
        use_flat_fee: bool,
        app_call_info: Dict[str, str],
    ) -> PreparedTransaction:
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        if not app_id:
            raise ValueError("app_id is required")
        if int(on_complete) < 0 or int(on_complete) > int(transaction.OnComplete.DeleteApplicationOC):
            raise ValueError(f"invalid on_complete: {on_complete}")

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee, use_flat_fee)

        sender_info = algod_client.account_info(sender)
        txn = transaction.ApplicationCallTxn(
            sender=sender,
            sp=params,
            index=app_id,
            on_complete=on_complete,
            app_args=app_args,
            accounts=accounts,
            foreign_apps=foreign_apps,
            foreign_assets=foreign_assets,
            note=note,
            boxes=boxes,
            approval_program=approval_program,
            clear_program=clear_program,
            local_schema=local_schema,
            global_schema=global_schema,
        )

        resolved = self.resolve_auth_address(sender, lambda _: sender_info)
        return PreparedTransaction(
            transaction=txn,
            auth_address=resolved.auth_address,
            signer_key=resolved.key_info,
            app_call_info=app_call_info,
            checks=_app_call_checks(
                app_id,
                on_complete,
                app_args,
                accounts,
                foreign_apps,
                foreign_assets,
                boxes,
                app_call_info,
            ),
        )

    def prepare_app_deploy(
        self,
        algod_client: Any,
        *,
        sender: str,
        approval_program: bytes,
        clear_program: bytes,
        global_schema: Optional[transaction.StateSchema] = None,
        local_schema: Optional[transaction.StateSchema] = None,
        extra_pages: int = 0,
        app_args: Optional[List[bytes]] = None,
        accounts: Optional[List[str]] = None,
        foreign_apps: Optional[List[int]] = None,
        foreign_assets: Optional[List[int]] = None,
        boxes: Optional[List[Any]] = None,
        opt_in: bool = False,
        note: Optional[bytes] = None,
        fee: Optional[int] = None,
        use_flat_fee: bool = False,
    ) -> PreparedTransaction:
        """Build a prepared application create transaction."""
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        if not approval_program:
            raise ValueError("approval_program is required")
        if not clear_program:
            raise ValueError("clear_program is required")

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee, use_flat_fee)

        sender_info = algod_client.account_info(sender)
        txn = transaction.ApplicationCreateTxn(
            sender=sender,
            sp=params,
            on_complete=transaction.OnComplete.OptInOC if opt_in else transaction.OnComplete.NoOpOC,
            approval_program=approval_program,
            clear_program=clear_program,
            global_schema=global_schema or transaction.StateSchema(0, 0),
            local_schema=local_schema or transaction.StateSchema(0, 0),
            app_args=app_args,
            accounts=accounts,
            foreign_apps=foreign_apps,
            foreign_assets=foreign_assets,
            note=note,
            extra_pages=extra_pages,
            boxes=boxes,
        )
        resolved = self.resolve_auth_address(sender, lambda _: sender_info)
        return PreparedTransaction(
            transaction=txn,
            auth_address=resolved.auth_address,
            signer_key=resolved.key_info,
            app_call_info={"mode": "raw"},
            checks=[
                PreparedCheck(
                    name="app_deploy",
                    status="ok",
                    data={
                        "extra_pages": extra_pages,
                        "approval_program_len": len(approval_program),
                        "clear_program_len": len(clear_program),
                        "opt_in": opt_in,
                    },
                )
            ],
        )

    def prepare_sweep_group(
        self,
        algod_client: Any,
        *,
        asa_transfers: Optional[List[Dict[str, Any]]] = None,
        payments: Optional[List[Dict[str, Any]]] = None,
    ) -> PreparedGroup:
        """Build a sweep group from normalized ASA transfers and payments."""
        asa_transfers = asa_transfers or []
        payments = payments or []
        if not asa_transfers and not payments:
            raise ValueError("sweep group must not be empty")
        prepared: List[PreparedTransaction] = []
        for index, transfer in enumerate(asa_transfers):
            try:
                prepared.append(self.prepare_asa_transfer(algod_client, **transfer))
            except Exception as e:
                raise SignerError(f"ASA transfer {index}: {e}") from e
        for index, payment in enumerate(payments):
            try:
                prepared.append(self.prepare_payment(algod_client, **payment))
            except Exception as e:
                raise SignerError(f"payment {index}: {e}") from e

        checks = [
            PreparedCheck(
                name="sweep_group",
                status="ok",
                data={
                    "asa_transfer_count": len(asa_transfers),
                    "payment_count": len(payments),
                },
            )
        ]
        if asa_transfers:
            checks.append(_validate_asa_transfer_group(prepared[:len(asa_transfers)]))
        if payments:
            checks.append(_validate_payment_group(prepared[len(asa_transfers):]))
        return PreparedGroup(prepared, checks=checks)

    def prepare_payment_group(
        self,
        algod_client: Any,
        payments: List[Dict[str, Any]],
    ) -> PreparedGroup:
        """Build an ordered group of prepared ALGO payment transactions."""
        if not payments:
            raise ValueError("payments must not be empty")
        prepared = []
        for index, payment in enumerate(payments):
            try:
                prepared.append(self.prepare_payment(algod_client, **payment))
            except Exception as e:
                raise SignerError(f"payment {index}: {e}") from e
        group_checks = [
            PreparedCheck(
                name="payment_group",
                status="ok",
                data={"count": len(payments)},
            ),
            _validate_payment_group(prepared),
        ]
        return PreparedGroup(
            prepared,
            checks=group_checks,
        )

    def prepare_asa_transfer_group(
        self,
        algod_client: Any,
        transfers: List[Dict[str, Any]],
    ) -> PreparedGroup:
        """Build an ordered group of prepared ASA transfer transactions."""
        if not transfers:
            raise ValueError("transfers must not be empty")
        prepared = []
        for index, transfer in enumerate(transfers):
            try:
                prepared.append(self.prepare_asa_transfer(algod_client, **transfer))
            except Exception as e:
                raise SignerError(f"ASA transfer {index}: {e}") from e
        group_checks = [
            PreparedCheck(
                name="asa_transfer_group",
                status="ok",
                data={"count": len(transfers)},
            ),
            _validate_asa_transfer_group(prepared),
        ]
        return PreparedGroup(
            prepared,
            checks=group_checks,
        )

    def prepare_payment_app_call_group(
        self,
        payment: PreparedTransaction,
        app_call: PreparedTransaction,
    ) -> PreparedGroup:
        """Return the payment-first group shape for payment plus app-call."""
        if payment.transaction is None:
            raise ValueError("payment transaction is required")
        if app_call.transaction is None:
            raise ValueError("app call transaction is required")
        return PreparedGroup(
            [payment, app_call],
            checks=[
                PreparedCheck(
                    name="payment_app_call_order",
                    status="ok",
                    data={"payment_index": 0, "app_call_index": 1},
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
            raise self._signer_http_error(
                resp,
                f"Failed to list key types: HTTP {resp.status_code}",
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
                        max_size=arg.get("max_size", 0),
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
                signing_flow=kt.get("signing_flow", ""),
                sentry_component_key_type=kt.get("sentry_component_key_type", ""),
                bounded_authorization=_parse_bounded_authorization(kt.get("bounded_authorization")),
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
            raise self._forbidden_locked_error(resp)

        if resp.status_code == 400:
            raise self._signer_http_error(resp, "Bad request")

        if resp.status_code != 200:
            raise self._signer_http_error(resp, f"Key generation failed: HTTP {resp.status_code}")

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
            is_witness_key=data.get("is_witness_key", False),
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
            raise self._forbidden_locked_error(resp)

        if resp.status_code == 404:
            raise KeyDeletionError(self._error_message(resp, f"Key not found: {address}"))

        if resp.status_code != 200:
            raise self._signer_http_error(resp, f"Key deletion failed: HTTP {resp.status_code}")

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
        _, message = self._error_parts(resp, fallback)
        return message

    def _error_parts(self, resp: requests.Response, fallback: str) -> tuple[str, str]:
        """Return (code, message) for a non-2xx signer response.

        ``code`` is the stable machine-readable wire error code, empty when
        the signer predates code support.
        """
        data = self._safe_json(resp)
        error = data.get("error")
        if isinstance(error, str) and error.strip():
            code = data.get("code")
            return (code if isinstance(code, str) else "", error)
        text = (resp.text or "").strip()
        if text:
            return ("", text)
        return ("", fallback)

    def _signer_http_error(self, resp: requests.Response, fallback: str) -> SignerError:
        """Build a SignerError carrying the stable wire error code."""
        code, message = self._error_parts(resp, fallback)
        return SignerError(message, code=code)

    def _bad_request_error(self, resp: requests.Response) -> SignerError:
        """Classify a 400 at signing/planning endpoints.

        The wire code is authoritative: not_found maps to KeyNotFoundError.
        Pre-code signers send no code and keep the legacy message-text
        mapping.
        """
        code, message = self._error_parts(resp, "Bad request")
        if code == ERR_CODE_NOT_FOUND or (code == "" and "not found" in message.lower()):
            return KeyNotFoundError(message, code=code)
        return SignerError(f"Bad request: {message}", code=code)

    def _forbidden_locked_error(self, resp: requests.Response) -> SignerError:
        """Classify a 403 at endpoints that historically reported locked.

        The wire code distinguishes a genuinely locked signer from other
        forbidden conditions; pre-code signers send no code and keep the
        legacy locked mapping.
        """
        code, message = self._error_parts(resp, "Signer is locked")
        if code in ("", ERR_CODE_LOCKED):
            return SignerUnavailableError("Signer is locked", code=code)
        return SignerError(message, code=code)

    def _forbidden_rejected_error(self, resp: requests.Response, fallback: str) -> SignerError:
        """Classify a 403 at endpoints that historically reported rejection.

        A locked code maps to the locked error; forbidden (or no code, for
        pre-code signers) keeps the rejection error.
        """
        code, message = self._error_parts(resp, fallback)
        if code == ERR_CODE_LOCKED:
            return SignerUnavailableError("Signer is locked", code=code)
        if code in ("", ERR_CODE_FORBIDDEN):
            return SigningRejectedError(message, code=code)
        return SignerError(message, code=code)

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
            raise self._signer_http_error(resp, f"Sign cancel failed: HTTP {resp.status_code}")

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

        # User-role component signing runs the signer-domain approval gates
        # and can block on a manual approval decision, so it needs the same
        # approval-aware deadline as /sign. Sentry-role requests are
        # deterministic and keep the short component deadline.
        timeout = self._timeout_for(COMPONENT_SIGN_TIMEOUT)
        if request_body.get("role") == COMPONENT_SIGN_ROLE_USER:
            self._discover_approval_wait()
            timeout = max(timeout, self._sign_request_timeout())

        try:
            resp = self.session.post(
                f"{self.base_url}/sign/component",
                json=request_body,
                timeout=timeout,
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")

        if resp.status_code == 403:
            raise self._forbidden_rejected_error(resp, "Component signing request rejected")

        if resp.status_code == 503:
            raise SignerUnavailableError(self._error_message(resp, "Signer unavailable"))

        if resp.status_code != 200:
            raise self._signer_http_error(
                resp,
                f"Component signing failed: HTTP {resp.status_code}",
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
            raise self._forbidden_rejected_error(resp, "Guarded assembly request rejected")

        if resp.status_code == 503:
            raise SignerUnavailableError(self._error_message(resp, "Signer unavailable"))

        if resp.status_code != 200:
            raise self._signer_http_error(
                resp,
                f"Guarded assembly failed: HTTP {resp.status_code}",
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

    def request_bounded_component(
        self,
        request: Any,
    ) -> BoundedComponentResponse:
        """Request approved bounded base components from the user signer."""
        request_body = _compact_payload(request)
        if not isinstance(request_body, dict):
            raise ValueError("bounded component request must be a mapping or dataclass")
        if not request_body.get("request_id"):
            request_body["request_id"] = _new_sign_request_id()
        try:
            _validate_bounded_component_request(request_body)
        except ValueError as e:
            raise ValueError(f"invalid bounded component request: {e}") from e

        self._discover_approval_wait()
        try:
            resp = self.session.post(
                f"{self.base_url}/sign/bounded-component",
                json=request_body,
                timeout=self._sign_request_timeout(),
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")
        if resp.status_code == 403:
            raise self._forbidden_rejected_error(resp, "Bounded component signing request rejected")
        if resp.status_code == 503:
            raise SignerUnavailableError(self._error_message(resp, "Signer unavailable"))
        if resp.status_code != 200:
            raise self._signer_http_error(
                resp,
                f"Bounded component signing failed: HTTP {resp.status_code}",
            )

        data = self._safe_json(resp)
        if data.get("error"):
            raise SignerError(data["error"])
        try:
            _validate_bounded_component_response(data)
        except ValueError as e:
            raise SignerError(f"invalid bounded component response: {e}") from e
        if data["request_id"] != request_body["request_id"]:
            raise SignerError("bounded component response request_id does not match request")
        return BoundedComponentResponse(
            request_id=data["request_id"],
            transactions=list(data.get("transactions") or []),
            components=[
                BoundedBaseComponent(
                    target_index=item["target_index"],
                    bounded_account=item["bounded_account"],
                    base_signatures=list(item.get("base_signatures") or []),
                    runtime_args=dict(item.get("runtime_args") or {}) or None,
                    assembly_receipt=item["assembly_receipt"],
                    signature_scheme=item["signature_scheme"],
                )
                for item in data.get("components", [])
            ],
            mutations=data.get("mutations"),
        )

    def request_bounded_assemble(
        self,
        request: Any,
    ) -> BoundedAssemblyResponse:
        """Send source-bound bounded-sentry material to the user signer."""
        request_body = _compact_payload(request)
        if not isinstance(request_body, dict):
            raise ValueError("bounded assembly request must be a mapping or dataclass")
        if not request_body.get("request_id"):
            request_body["request_id"] = _new_sign_request_id()
        try:
            _validate_bounded_assembly_request(request_body)
        except ValueError as e:
            raise ValueError(f"invalid bounded assembly request: {e}") from e

        try:
            resp = self.session.post(
                f"{self.base_url}/sign/bounded-assemble",
                json=request_body,
                timeout=self._timeout_for(GUARDED_ASSEMBLY_TIMEOUT),
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing token")
        if resp.status_code == 403:
            raise self._forbidden_rejected_error(resp, "Bounded assembly request rejected")
        if resp.status_code == 503:
            raise SignerUnavailableError(self._error_message(resp, "Signer unavailable"))
        if resp.status_code != 200:
            raise self._signer_http_error(resp, f"Bounded assembly failed: HTTP {resp.status_code}")

        data = self._safe_json(resp)
        if data.get("error"):
            raise SignerError(data["error"])
        try:
            _validate_bounded_assembly_response(data)
        except ValueError as e:
            raise SignerError(f"invalid bounded assembly response: {e}") from e
        if data["request_id"] != request_body["request_id"]:
            raise SignerError("bounded assembly response request_id does not match request")
        return BoundedAssemblyResponse(
            request_id=data["request_id"],
            signed_group=list(data.get("signed_group") or []),
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
            raise self._forbidden_locked_error(resp)

        if resp.status_code != 200:
            raise self._signer_http_error(
                resp,
                f"Sentry reference sync failed: HTTP {resp.status_code}",
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
            raise self._bad_request_error(resp)

        if resp.status_code == 403:
            raise self._forbidden_rejected_error(resp, "Signing request rejected by operator")

        if resp.status_code == 503:
            error = self._error_message(resp, "Signer unavailable")
            raise SignerUnavailableError(error)

        if resp.status_code != 200:
            raise self._signer_http_error(resp, f"Signing failed: HTTP {resp.status_code}")

        # Parse successful response
        try:
            data = resp.json()
        except json.JSONDecodeError:
            raise SignerError(f"Server returned invalid JSON: {resp.text[:200]}")

        if data.get("error"):
            raise SignerError(data["error"])

        signed = data.get("signed", [])
        _validate_group_sign_response(sign_entries, signed)

        return GroupSignResponse(
            signed=signed,
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
            raise self._bad_request_error(resp)

        if resp.status_code == 403:
            raise self._signer_http_error(resp, "Forbidden")

        if resp.status_code != 200:
            raise self._signer_http_error(resp, f"Plan failed: HTTP {resp.status_code}")

        try:
            data = resp.json()
        except json.JSONDecodeError:
            raise SignerError(f"Server returned invalid JSON: {resp.text[:200]}")

        if data.get("error"):
            raise SignerError(data["error"])

        return data

    def simulate_prepared_group(
        self,
        algod_client: Any,
        prepared_group: PreparedGroup,
        *,
        request_id: Optional[str] = None,
    ) -> SimulationResult:
        """Sign normally, then simulate the exact group through client algod."""
        if algod_client is None:
            raise ValueError("algod_client is required")
        response = self.sign_requests(
            prepared_group.to_sign_requests(), request_id=request_id
        )
        foreign_count = int((response.mutations or {}).get("foreign_count", 0))
        if foreign_count:
            raise SignerError(
                "signed simulation requires a complete group; signer returned "
                f"{foreign_count} foreign transaction(s)"
            )
        return _simulate_signed_group(
            algod_client, response.signed, response.mutations
        )

    def simulate_prepared_transaction(
        self,
        algod_client: Any,
        prepared: PreparedTransaction,
        *,
        request_id: Optional[str] = None,
    ) -> SimulationResult:
        """Sign and simulate one prepared transaction."""
        return self.simulate_prepared_group(
            algod_client,
            PreparedGroup([prepared]),
            request_id=request_id,
        )

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


def _guarded_dummies_needed(total_lsig_bytes: int, txn_count: int) -> int:
    current_budget = txn_count * GUARDED_LSIG_BUDGET_BYTES
    if total_lsig_bytes <= current_budget:
        return 0
    extra_budget = total_lsig_bytes - current_budget
    return (extra_budget + GUARDED_LSIG_BUDGET_BYTES - 1) // GUARDED_LSIG_BUDGET_BYTES


def _apply_guarded_dummy_fees(
    txns: List[transaction.Transaction],
    lsig_indices: List[int],
    dummy_count: int,
    min_fee: int,
) -> None:
    total_fees = dummy_count * min_fee
    if not lsig_indices:
        if not txns:
            raise ValueError("no transactions to apply dummy fees to")
        txns[0].fee = int(getattr(txns[0], "fee", 0)) + total_fees
        return

    fee_per_lsig = total_fees // len(lsig_indices)
    remainder = total_fees % len(lsig_indices)
    for offset, index in enumerate(lsig_indices):
        extra = fee_per_lsig + (remainder if offset == 0 else 0)
        txns[index].fee = int(getattr(txns[index], "fee", 0)) + extra


def _create_guarded_dummies(first_txn: transaction.Transaction, count: int) -> List[transaction.Transaction]:
    if count == 0:
        return []
    # The dummies must share the real transactions' network. A missing genesis
    # hash would silently build dummies for the wrong (empty) network, so fail
    # loudly instead of defaulting to "".
    genesis_hash = getattr(first_txn, "genesis_hash", None)
    if not genesis_hash:
        raise SignerError("cannot build guarded dummy transactions: first transaction has no genesis hash")
    dummy_account = transaction.LogicSigAccount(GUARDED_DUMMY_PROGRAM)
    dummy_address = dummy_account.address()
    params = transaction.SuggestedParams(
        int(getattr(first_txn, "fee", GUARDED_DEFAULT_MIN_FEE)),
        int(getattr(first_txn, "first_valid_round", 0)),
        int(getattr(first_txn, "last_valid_round", 0)),
        genesis_hash,
        getattr(first_txn, "genesis_id", None),
        flat_fee=True,
    )
    dummies = []
    for index in range(count):
        txn = transaction.PaymentTxn(
            dummy_address,
            params,
            dummy_address,
            0,
            note=bytes([index]),
        )
        txn.fee = 0
        dummies.append(txn)
    return dummies


def _sign_guarded_dummies(
    dummies: List[transaction.Transaction],
    start_index: int,
) -> List[GuardedPassthroughItem]:
    _validate_guarded_dummies(dummies)
    dummy_account = transaction.LogicSigAccount(GUARDED_DUMMY_PROGRAM)
    passthrough = []
    for offset, txn in enumerate(dummies):
        signed = transaction.LogicSigTransaction(txn, dummy_account)
        signed_hex = base64.b64decode(encoding.msgpack_encode(signed)).hex()
        passthrough.append(GuardedPassthroughItem(
            target_index=start_index + offset,
            signed_txn_hex=signed_hex,
        ))
    return passthrough


def _validate_guarded_dummies(dummies: List[transaction.Transaction]) -> None:
    dummy_address = transaction.LogicSigAccount(GUARDED_DUMMY_PROGRAM).address()
    for index, txn in enumerate(dummies):
        if (
            not isinstance(txn, transaction.PaymentTxn)
            or txn.sender != dummy_address
            or txn.receiver != dummy_address
            or txn.amt != 0
            or txn.fee != 0
            or txn.note != bytes([index])
            or txn.rekey_to is not None
            or txn.close_remainder_to is not None
        ):
            raise SignerError(
                f"signer-appended transaction {index} is not a canonical "
                "guarded budget dummy"
            )


def _encode_guarded_lsig_args(args: Optional[Dict[str, bytes]]) -> Optional[Dict[str, str]]:
    if not args:
        return None
    return {name: value.hex() for name, value in args.items()}


def _build_prepared_guarded_sign_inputs(
    user_client: SignerClient,
    prepared_group: PreparedGroup,
    sentry_client: Optional[SignerClient],
    sentry_resolver: Optional[Any],
    sentry_component_key: str,
    assembly_request_id: str,
    min_fee: int,
) -> Dict[str, Any]:
    if user_client is None:
        raise SignerError("user_client is required")
    prepared = prepared_group.transactions
    if not prepared:
        raise ValueError("prepared group is empty")

    txns = []
    guarded_targets = []
    primary_targets = []
    lsig_indices = []
    total_lsig_bytes = 0

    for index, item in enumerate(prepared):
        if item.signed_transaction_base64:
            raise ValueError(
                f"prepared transaction {index}: passthrough entries are not supported in prepared guarded groups"
            )
        if item.transaction is None:
            raise ValueError(f"prepared transaction {index}: transaction is required")
        txns.append(copy.deepcopy(item.transaction))

        key = item.signer_key
        if key is None and item.auth_address:
            key = user_client.get_key_info(item.auth_address)
        if key is None:
            raise ValueError(f"prepared transaction {index}: signer key metadata is required")

        lsig_size = item.lsig_size
        if key.lsig_size > 0:
            lsig_size = key.lsig_size
        if lsig_size > 0:
            total_lsig_bytes += lsig_size
            lsig_indices.append(index)

        if key.signing_flow:
            if key.signing_flow == SIGNING_FLOW_BOUNDED1:
                pass
            elif key.signing_flow != SIGNING_FLOW_SENTRY1:
                raise ValueError(
                    f"prepared transaction {index}: signer key requires signing flow "
                    f"{key.signing_flow!r}, which this SDK does not support; upgrade the SDK"
                )
            if key.signing_flow == SIGNING_FLOW_BOUNDED1:
                if not item.auth_address:
                    raise ValueError(f"prepared transaction {index}: primary auth address is required")
                primary_targets.append(GuardedPrimarySignTarget(
                    target_index=index,
                    auth_address=item.auth_address,
                    txn_sender=item.txn_sender,
                    lsig_args=_encode_guarded_lsig_args(item.lsig_args),
                    lsig_size=lsig_size,
                    app_call_info=item.app_call_info,
                ))
                continue
            if not item.auth_address:
                raise ValueError(f"prepared transaction {index}: guarded auth address is required")
            guarded_targets.append(GuardedSignTarget(
                target_index=index,
                guarded_account=item.auth_address,
                sentry_public_key_hex=(key.parameters or {}).get("sentry_public_key", ""),
                sentry_component_key_type=key.sentry_component_key_type,
            ))
            continue

        if not item.auth_address:
            raise ValueError(f"prepared transaction {index}: primary auth address is required")
        primary_targets.append(GuardedPrimarySignTarget(
            target_index=index,
            auth_address=item.auth_address,
            txn_sender=item.txn_sender,
            lsig_args=_encode_guarded_lsig_args(item.lsig_args),
            lsig_size=lsig_size,
            app_call_info=item.app_call_info,
        ))

    if not guarded_targets:
        raise ValueError("prepared group has no guarded targets")

    dummy_count = _guarded_dummies_needed(total_lsig_bytes, len(txns))
    if len(txns) + dummy_count > GUARDED_MAX_GROUP_SIZE:
        raise ValueError(
            f"group would be {len(txns) + dummy_count} transactions (max {GUARDED_MAX_GROUP_SIZE}) "
            f"- cannot add {dummy_count} dummies for LSig budget"
        )
    if dummy_count > 0:
        _apply_guarded_dummy_fees(txns, lsig_indices, dummy_count, min_fee or GUARDED_DEFAULT_MIN_FEE)

    dummies = _create_guarded_dummies(txns[0], dummy_count)
    all_txns = txns + dummies
    if len(all_txns) > 1:
        for txn in all_txns:
            txn.group = None
        transaction.assign_group_id(all_txns)

    dummy_passthrough = _sign_guarded_dummies(all_txns[len(txns):], len(txns))
    group_bytes_hex = [encode_transaction(txn)[0] for txn in all_txns]
    return {
        "user_client": user_client,
        "group_bytes_hex": group_bytes_hex,
        "guarded_targets": guarded_targets,
        "sentry_client": sentry_client,
        "sentry_resolver": sentry_resolver,
        "sentry_component_key": sentry_component_key,
        "primary_targets": primary_targets,
        "passthrough": dummy_passthrough,
        "assembly_request_id": assembly_request_id,
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
        _verify_signed_transaction_matches_canonical(
            "primary passthrough",
            index,
            response.signed[index],
            group_bytes_hex[index],
        )
        passthrough.append(
            GuardedPassthroughItem(
                target_index=index,
                signed_txn_hex=response.signed[index],
            )
        )
    return response, passthrough


def _prepared_sentry_flow_kinds(
    user_client: SignerClient,
    prepared_group: PreparedGroup,
) -> tuple:
    bounded_sentry = False
    legacy_guarded = False
    for index, item in enumerate(prepared_group.transactions):
        key = item.signer_key
        if key is None and item.auth_address:
            try:
                key = user_client.get_key_info(item.auth_address)
            except SignerError:
                raise
            except Exception as e:
                raise SignerError(
                    f"prepared transaction {index}: resolve signer key: {e}"
                ) from e
        if key is None:
            continue
        if key.signing_flow == SIGNING_FLOW_BOUNDED_SENTRY1:
            bounded_sentry = True
        elif key.signing_flow == SIGNING_FLOW_SENTRY1:
            legacy_guarded = True
    return bounded_sentry, legacy_guarded


def _decode_canonical_group(group_bytes_hex: List[str]) -> List[transaction.Transaction]:
    result = []
    for index, encoded in enumerate(group_bytes_hex):
        try:
            raw = bytes.fromhex(encoded)
        except ValueError as e:
            raise SignerError(f"transaction {index} is invalid hex: {e}") from e
        if len(raw) < 3 or raw[:2] != b"TX":
            raise SignerError(f"transaction {index} is missing TX prefix")
        try:
            decoded = encoding.msgpack_decode(base64.b64encode(raw[2:]).decode())
        except Exception as e:
            raise SignerError(f"transaction {index} is invalid: {e}") from e
        if not isinstance(decoded, transaction.Transaction):
            raise SignerError(f"transaction {index} did not decode as a transaction")
        result.append(decoded)
    return result


def _bounded_mutation_int(mutations: Dict[str, Any], name: str) -> int:
    value = mutations.get(name, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SignerError(f"bounded mutation {name} must be a non-negative integer")
    return value


def _validate_bounded_component_plan(
    original: List[transaction.Transaction],
    planned: List[transaction.Transaction],
    mutations: Optional[Dict[str, Any]],
) -> None:
    if len(planned) < len(original):
        raise SignerError(
            f"signer returned {len(planned)} bounded group positions, "
            f"want at least {len(original)}"
        )
    appended = len(planned) - len(original)
    if mutations is not None and not isinstance(mutations, dict):
        raise SignerError("bounded mutation report must be a mapping")
    if mutations is None:
        if appended:
            raise SignerError(
                f"signer appended {appended} bounded group positions without "
                "a mutation report"
            )
    else:
        original_count = _bounded_mutation_int(mutations, "original_count")
        final_count = _bounded_mutation_int(mutations, "final_count")
        dummies_added = _bounded_mutation_int(mutations, "dummies_added")
        if original_count != len(original):
            raise SignerError(
                f"bounded mutation original_count {original_count} does not "
                f"match request count {len(original)}"
            )
        if final_count != len(planned):
            raise SignerError(
                f"bounded mutation final_count {final_count} does not match "
                f"returned count {len(planned)}"
            )
        if dummies_added != appended:
            raise SignerError(
                f"bounded mutation dummies_added {dummies_added} does not "
                f"match appended count {appended}"
            )

    fee_modified = set()
    if mutations is not None:
        group_id_changed = mutations.get("group_id_changed", False)
        if not isinstance(group_id_changed, bool):
            raise SignerError("bounded mutation group_id_changed must be a boolean")
        raw_fee_modified = mutations.get("fees_modified") or []
        if not isinstance(raw_fee_modified, list):
            raise SignerError("bounded mutation fees_modified must be a list")
        for index in raw_fee_modified:
            if (
                isinstance(index, bool)
                or not isinstance(index, int)
                or index < 0
                or index >= len(original)
            ):
                raise SignerError(
                    f"bounded mutation fee index {index!r} is outside "
                    "original positions"
                )
            if index in fee_modified:
                raise SignerError(
                    f"bounded mutation fee index {index} is duplicated"
                )
            fee_modified.add(index)

    total_fee_delta = 0
    for index, (original_txn, planned_txn) in enumerate(zip(original, planned)):
        expected = copy.deepcopy(original_txn)
        if mutations is not None and mutations.get("group_id_changed") is True:
            expected.group = planned_txn.group
        if index in fee_modified:
            if planned_txn.fee < expected.fee:
                raise SignerError(
                    f"bounded mutation decreased fee at original position {index}"
                )
            total_fee_delta += planned_txn.fee - expected.fee
            expected.fee = planned_txn.fee
        expected_hex, _ = encode_transaction(expected)
        planned_hex, _ = encode_transaction(planned_txn)
        if expected_hex != planned_hex:
            raise SignerError(
                f"signer changed unreported fields at bounded original "
                f"position {index}"
            )
    if mutations is not None:
        reported_delta = _bounded_mutation_int(mutations, "total_fees_delta")
        if reported_delta != total_fee_delta:
            raise SignerError(
                f"bounded mutation total_fees_delta {reported_delta} does not "
                f"match observed delta {total_fee_delta}"
            )
    _validate_guarded_dummies(planned[len(original):])


def _verify_bounded_assembled_group(
    group_bytes_hex: List[str], signed_group: List[str]
) -> None:
    if len(signed_group) != len(group_bytes_hex):
        raise SignerError(
            f"assembled group has {len(signed_group)} transaction(s), "
            f"want {len(group_bytes_hex)}"
        )
    for index, (signed_hex, canonical_hex) in enumerate(
        zip(signed_group, group_bytes_hex)
    ):
        _verify_signed_transaction_matches_canonical(
            "assembled transaction", index, signed_hex, canonical_hex
        )


def _verify_signed_transaction_matches_canonical(
    label: str,
    index: int,
    signed_hex: str,
    canonical_hex: str,
) -> None:
    try:
        signed_bytes = bytes.fromhex(signed_hex)
    except ValueError as e:
        raise SignerError(f"{label} {index}: invalid hex: {e}") from e
    try:
        decoded = encoding.msgpack_decode(base64.b64encode(signed_bytes).decode())
    except Exception as e:
        raise SignerError(f"{label} {index}: decode failed: {e}") from e
    if not isinstance(
        decoded,
        (
            transaction.SignedTransaction,
            transaction.LogicSigTransaction,
            transaction.MultisigTransaction,
        ),
    ):
        raise SignerError(f"{label} {index} did not decode as a signed transaction")
    encoded, _ = encode_transaction(decoded.transaction)
    if encoded != canonical_hex.lower():
        raise SignerError(
            f"{label} {index} does not match the submitted canonical bytes"
        )


def _bounded_sentry_public_key(key: KeyInfo) -> str:
    if key.bounded_authorization and key.bounded_authorization.sentry:
        if key.bounded_authorization.sentry.public_key_hex:
            return key.bounded_authorization.sentry.public_key_hex
    return (key.parameters or {}).get("sentry_public_key", "")


def _bounded_sentry_component_key_type(key: KeyInfo) -> str:
    if key.sentry_component_key_type:
        return key.sentry_component_key_type
    if key.bounded_authorization and key.bounded_authorization.sentry:
        return key.bounded_authorization.sentry.component_key_type
    return ""


def _request_bounded_primary_passthrough(
    user_client: SignerClient,
    group_bytes_hex: List[str],
    original_count: int,
    bounded_indices: set,
    target_lsig_sizes: Dict[int, int],
    primary_targets: List[Dict[str, Any]],
) -> tuple:
    if not primary_targets:
        return None, []
    primary_by_index = {target["target_index"]: target for target in primary_targets}
    requests_data = []
    for index, txn_hex in enumerate(group_bytes_hex):
        if index >= original_count:
            requests_data.append({"txn_bytes_hex": txn_hex})
        elif index in bounded_indices:
            request: Dict[str, Any] = {"txn_bytes_hex": txn_hex}
            if target_lsig_sizes.get(index):
                request["lsig_size"] = target_lsig_sizes[index]
            requests_data.append(request)
        else:
            target = primary_by_index.get(index)
            if target is None:
                raise ValueError(f"group position {index} has no bounded or primary target")
            request = {
                "txn_bytes_hex": txn_hex,
                "auth_address": target["auth_address"],
            }
            for field in ("txn_sender", "lsig_args", "lsig_size", "app_call_info"):
                if target.get(field):
                    request[field] = target[field]
            requests_data.append(request)
    response = user_client.sign_requests(requests_data)
    passthrough = []
    for index in sorted(primary_by_index):
        if index >= len(response.signed) or not response.signed[index]:
            raise SignerError(
                f"primary signer returned no signed transaction for target {index}"
            )
        _verify_signed_transaction_matches_canonical(
            "primary passthrough",
            index,
            response.signed[index],
            group_bytes_hex[index],
        )
        passthrough.append(GuardedPassthroughItem(
            target_index=index,
            signed_txn_hex=response.signed[index],
        ))
    return response, passthrough


def sign_prepared_bounded_sentry_group(
    *,
    user_client: SignerClient,
    prepared_group: PreparedGroup,
    sentry_client: Optional[SignerClient] = None,
    sentry_resolver: Optional[Any] = None,
    sentry_component_key: str = "",
    assembly_request_id: str = "",
    min_fee: int = GUARDED_DEFAULT_MIN_FEE,
) -> GuardedSignResult:
    """Sign a prepared bounded-sentry1 group using the user-first flow."""
    del min_fee  # Planning, dummy insertion, and fee pooling are signer-owned.
    if user_client is None:
        raise SignerError("user_client is required")
    prepared = prepared_group.transactions
    if not prepared:
        raise ValueError("prepared group is empty")

    requests_data: List[Dict[str, Any]] = []
    targets: List[Dict[str, Any]] = []
    primary_targets: List[Dict[str, Any]] = []
    target_lsig_sizes: Dict[int, int] = {}
    for index, item in enumerate(prepared):
        if item.signed_transaction_base64:
            raise ValueError(
                f"prepared transaction {index}: passthrough entries are not "
                "supported in prepared bounded-sentry groups"
            )
        if item.transaction is None:
            raise ValueError(f"prepared transaction {index}: transaction is required")
        key = item.signer_key
        if key is None and item.auth_address:
            key = user_client.get_key_info(item.auth_address)
        if key is None:
            raise ValueError(
                f"prepared transaction {index}: signer key metadata is required"
            )
        lsig_size = key.lsig_size or item.lsig_size
        if key.signing_flow == SIGNING_FLOW_BOUNDED_SENTRY1:
            if not item.auth_address:
                raise ValueError(
                    f"prepared transaction {index}: bounded auth address is required"
                )
            requests_data.append(item.to_sign_request())
            target_lsig_sizes[index] = lsig_size
            targets.append({
                "target_index": index,
                "guarded_account": item.auth_address,
                "sentry_public_key_hex": _bounded_sentry_public_key(key),
                "sentry_component_key_type": _bounded_sentry_component_key_type(key),
            })
            continue
        if key.signing_flow == SIGNING_FLOW_SENTRY1:
            raise ValueError("cannot mix sentry1 and bounded-sentry1 targets in one group")
        if key.signing_flow not in ("", SIGNING_FLOW_BOUNDED1):
            raise ValueError(
                f"prepared transaction {index}: signer key requires signing flow "
                f"{key.signing_flow!r}, which this SDK does not support; upgrade the SDK"
            )
        if not item.auth_address:
            raise ValueError(
                f"prepared transaction {index}: primary auth address is required"
            )
        txn_hex, _ = encode_transaction(item.transaction)
        request = {"txn_bytes_hex": txn_hex}
        if lsig_size:
            request["lsig_size"] = lsig_size
        requests_data.append(request)
        primary_targets.append({
            "target_index": index,
            "auth_address": item.auth_address,
            "txn_sender": item.txn_sender,
            "lsig_args": _encode_guarded_lsig_args(item.lsig_args),
            "lsig_size": lsig_size,
            "app_call_info": item.app_call_info,
        })
    if not targets:
        raise ValueError("prepared group has no bounded-sentry targets")

    component_response = user_client.request_bounded_component(
        BoundedComponentRequest(requests=requests_data)
    )
    planned = _decode_canonical_group(component_response.transactions)
    if len(planned) < len(prepared):
        raise SignerError(
            f"signer returned {len(planned)} bounded group positions, "
            f"want at least {len(prepared)}"
        )
    _validate_bounded_component_plan(
        [item.transaction for item in prepared],
        planned,
        component_response.mutations,
    )
    target_by_index = {target["target_index"]: target for target in targets}
    components: Dict[int, BoundedBaseComponent] = {}
    for component in component_response.components:
        target = target_by_index.get(component.target_index)
        if target is None or component.bounded_account != target["guarded_account"]:
            raise SignerError(
                f"signer returned unexpected bounded component target "
                f"{component.target_index}"
            )
        if component.target_index in components:
            raise SignerError(
                f"signer returned duplicate bounded component target "
                f"{component.target_index}"
            )
        components[component.target_index] = component
    for target in targets:
        if target["target_index"] not in components:
            raise SignerError(
                f"signer returned no bounded component for target index "
                f"{target['target_index']}"
            )

    sentry_groups: Dict[tuple, Dict[str, Any]] = {}
    for target in targets:
        client, component_key = _resolve_sentry_for_target(
            target, sentry_client, sentry_component_key, sentry_resolver
        )
        group_key = (id(client), component_key)
        sentry_groups.setdefault(group_key, {
            "client": client, "component_key": component_key, "indices": [],
        })["indices"].append(target["target_index"])
    sentry_component_responses = []
    sentry_signatures: Dict[int, Dict[str, str]] = {}
    for group in sentry_groups.values():
        response = group["client"].request_component_sign(ComponentSignRequest(
            role=COMPONENT_SIGN_ROLE_SENTRY,
            component_key=group["component_key"],
            group_bytes_hex=component_response.transactions,
            target_indices=sorted(group["indices"]),
        ))
        sentry_component_responses.append(response)
        sentry_signatures.update(_component_signatures_by_index(response))

    primary_response, passthrough = _request_bounded_primary_passthrough(
        user_client,
        component_response.transactions,
        len(prepared),
        set(target_by_index),
        target_lsig_sizes,
        primary_targets,
    )
    passthrough.extend(_sign_guarded_dummies(planned[len(prepared):], len(prepared)))
    assembly_targets: List[BoundedAssemblyTarget] = []
    for target in targets:
        index = target["target_index"]
        sentry = sentry_signatures.get(index)
        if sentry is None:
            raise SignerError(f"missing sentry component signature for target {index}")
        component = components[index]
        assembly_targets.append(BoundedAssemblyTarget(
            target_index=index,
            bounded_account=component.bounded_account,
            base_signatures=list(component.base_signatures),
            runtime_args=dict(component.runtime_args or {}) or None,
            assembly_receipt=component.assembly_receipt,
            base_source_request_id=component_response.request_id,
            sentry_signature=sentry["signature"],
            sentry_source_request_id=sentry["request_id"],
        ))
    assembly_response = user_client.request_bounded_assemble(
        BoundedAssemblyRequest(
            request_id=assembly_request_id,
            group_bytes_hex=list(component_response.transactions),
            targets=assembly_targets,
            passthrough=passthrough,
        )
    )
    _verify_bounded_assembled_group(
        component_response.transactions, assembly_response.signed_group
    )
    return GuardedSignResult(
        signed_group=list(assembly_response.signed_group),
        user_component_responses=[],
        sentry_component_responses=sentry_component_responses,
        primary_sign_response=primary_response,
        assembly_response=None,
        bounded_component_response=component_response,
        bounded_assembly_response=assembly_response,
    )


def sign_prepared_guarded_group(
    *,
    user_client: SignerClient,
    prepared_group: PreparedGroup,
    sentry_client: Optional[SignerClient] = None,
    sentry_resolver: Optional[Any] = None,
    sentry_component_key: str = "",
    assembly_request_id: str = "",
    min_fee: int = GUARDED_DEFAULT_MIN_FEE,
) -> GuardedSignResult:
    """
    Canonicalize a prepared group locally, classify guarded and primary slots,
    then sign and assemble it through guarded component endpoints.

    This mirrors apshell's guarded client-side prep path and avoids sending an
    all-guarded group to /plan or /sign as all-foreign requests.
    """
    has_bounded_sentry, has_legacy_guarded = _prepared_sentry_flow_kinds(
        user_client, prepared_group
    )
    if has_bounded_sentry:
        if has_legacy_guarded:
            raise ValueError("cannot mix sentry1 and bounded-sentry1 targets in one group")
        return sign_prepared_bounded_sentry_group(
            user_client=user_client,
            prepared_group=prepared_group,
            sentry_client=sentry_client,
            sentry_resolver=sentry_resolver,
            sentry_component_key=sentry_component_key,
            assembly_request_id=assembly_request_id,
            min_fee=min_fee,
        )
    inputs = _build_prepared_guarded_sign_inputs(
        user_client,
        prepared_group,
        sentry_client,
        sentry_resolver,
        sentry_component_key,
        assembly_request_id,
        min_fee,
    )
    return sign_guarded_group(**inputs)


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


def simulate_guarded_group(
    algod_client: Any,
    **sign_options: Any,
) -> GuardedSimulationResult:
    """Run ordinary guarded signing, then simulate through client algod."""
    if algod_client is None:
        raise ValueError("algod_client is required")
    signing = sign_guarded_group(**sign_options)
    return GuardedSimulationResult(
        signing=signing,
        simulation=_simulate_signed_group(algod_client, signing.signed_group),
    )


def simulate_prepared_guarded_group(
    algod_client: Any,
    **sign_options: Any,
) -> GuardedSimulationResult:
    """Prepare and sign a guarded group, then simulate through client algod."""
    if algod_client is None:
        raise ValueError("algod_client is required")
    signing = sign_prepared_guarded_group(**sign_options)
    return GuardedSimulationResult(
        signing=signing,
        simulation=_simulate_signed_group(algod_client, signing.signed_group),
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
