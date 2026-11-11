# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""
APlane Python SDK - Transaction signing via apsigner

Data directory (required via APCLIENT_DATA env var or data_dir parameter):
    <data_dir>/
    ├── endpoints.yaml       # Signer and cosigner routing
    └── .ssh/
        └── id_ed25519       # SSH key: the client's credential

Example endpoints.yaml:
    schema_version: 2
    endpoints:
      primary:
        role: signer
        url: ssh://signer.example.com:1127

Enrollment (once per client key; the request is queued for the operator to
approve later in apadmin, then connect):
    from aplanesdk import request_enrollment_from_env

    result = request_enrollment_from_env(label="ci-runner")  # reads APCLIENT_DATA

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
import hashlib
import json
import math
import operator
import os
import re
import requests
import secrets
import socket
import threading
import time
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from typing import Optional, Dict, List, Any, Callable, cast
from urllib.parse import urlparse

from algosdk import abi, constants, encoding, transaction
from algosdk import error as algosdk_error
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from algosdk.v2client import models

import paramiko

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Default ports (match apshell/apsigner defaults)
DEFAULT_SSH_PORT = 1127
# SSH usernames the signer's SSH server recognizes: SSH_USERNAME for API
# connections authenticated by an enrolled key, SSH_ENROLLMENT_USERNAME for a
# enroll session.
SSH_USERNAME = "aplane"
SSH_ENROLLMENT_USERNAME = "enroll"
# The exec command an enroll session runs, and the longest display
# label the signer accepts with it.
SSH_ENROLLMENT_COMMAND = "enroll"
MAX_ENROLLMENT_LABEL_BYTES = 64
# Endpoint keys earlier builds wrote and nothing reads: the node's SSH server
# forwards every channel to its own REST listener, the local tunnel port is
# chosen at connect time, and the client's enrolled SSH key is its only
# credential, so there is no token file. They are accepted and ignored, as
# APlane ignores them, so a registry written before they were retired keeps
# working.
_RETIRED_ENDPOINT_FIELDS = ("signer_port", "local_port", "token_file")
DEFAULT_SSH_SETUP_TIMEOUT = 60.0
CLIENT_ENDPOINTS_FILE = "endpoints.yaml"
CLIENT_ENDPOINT_SCHEMA_VERSION = 2

# Client SSH keys the signer accepts and this SDK can load from a file. The
# signer also accepts hardware-backed sk- keys, which paramiko cannot use from
# a key file. RSA and DSA keys are refused by the signer before signature
# verification, so they are rejected here with a clear message instead.
CLIENT_SSH_KEY_REQUIREMENT = "Ed25519 or ECDSA (P-256/384/521)"
DEFAULT_CLIENT_ENDPOINT_NAME = "primary"
HEALTH_TIMEOUT = 3
STATUS_TIMEOUT = 5
INVENTORY_TIMEOUT = 30
MUTATION_TIMEOUT = 60
GROUP_PLAN_TIMEOUT = 60
COMPONENT_SIGN_TIMEOUT = 120
COSIGNED_ASSEMBLY_TIMEOUT = 120
SIGN_CANCEL_TIMEOUT = 5
SIGN_APPROVAL_SLACK = 30
DEFAULT_SIGN_REQUEST_TIMEOUT = 360
MAX_DISCOVERED_APPROVAL_WAIT = 30 * 60
APPROVAL_WAIT_REFRESH = 5 * 60
MAX_SIGN_REQUEST_ID_LENGTH = 128
MAX_COMPONENT_GROUP_SIZE = 16
APP_CALL_MAX_APP_ARGS = 16
APP_CALL_METHOD_ARGS_TUPLE_THRESHOLD = APP_CALL_MAX_APP_ARGS - 2
COSIGNED_DUMMY_PROGRAM = bytes.fromhex("033120320312")
PQ_SCHEME_FALCON1024 = "f1"

AUTHORIZATION_KIND_ED25519 = "ed25519"
AUTHORIZATION_KIND_NATIVE_PQ = "native_pq"
AUTHORIZATION_KIND_LOGIC_SIG = "logic_sig"

# Signing choreography labels name a frozen client flow. Clients route on
# signing_flow and must fail fast on labels they do not implement; an empty
# signing_flow means the ordinary /sign path.
#
# The transaction-aware LogicSig choreography: the signer classifies and signs
# a bounded account without a cosigner on the ordinary /sign path.
SIGNING_FLOW_BOUNDED1 = "bounded1"
# The cosigned account choreography: a target may be a spend or a rekey, and each
# base component names the path the signer classified. A listed rekey takes no
# cosigner component. It replaces bounded-cosigner1, which carried spends only.
SIGNING_FLOW_COSIGNED1 = "cosigned1"

# Bounded authorization contracts this SDK signs for: a bounded host, with a
# fee ceiling, and a plain host, which has none.
BOUNDED_CONTRACT_BOUNDED2 = "bounded2"
BOUNDED_CONTRACT_PLAIN1 = "plain1"
# Rotating account choreography (/sign/rotating/prepare then
# /sign/rotating/sign), in which the signer rekeys the account to a fresh
# stage on every spend. This SDK does not implement it; keys labelled with
# it must be signed through apshell.
SIGNING_FLOW_ROTATING1 = "rotating1"

KEY_TYPE_WITNESS_FALCON1024 = "aplane.witness-falcon1024.v1"


def _resolve_data_dir(data_dir: Optional[str]) -> str:
    """Resolve client data directory from param > APCLIENT_DATA.

    Raises SignerError when neither is set; the SDK has no implicit default.
    """
    resolved = data_dir or os.environ.get("APCLIENT_DATA")
    if not resolved:
        raise SignerError("client data directory not specified: pass data_dir or set APCLIENT_DATA")
    return os.path.expanduser(resolved)


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------

# Stable machine-readable error codes carried in ErrorResponse.code.
# These mirror the signer wire contract (pkg/signerapi/error_codes.go in the
# aplane repo). Every apsigner error response carries a non-empty code.
ERR_CODE_BAD_REQUEST = "bad_request"
ERR_CODE_UNAUTHORIZED = "unauthorized"
ERR_CODE_FORBIDDEN = "forbidden"
ERR_CODE_LOCKED = "locked"
ERR_CODE_NOT_FOUND = "not_found"
ERR_CODE_INVALID_PASSPHRASE = "invalid_passphrase"
ERR_CODE_UNAVAILABLE = "unavailable"
ERR_CODE_CACHE_REFRESH = "cache_refresh"
ERR_CODE_INTERNAL = "internal"
ERR_CODE_BOUNDED_COSIGNER_REQUIRED = "bounded_cosigner_required"
# The account refuses every rekey but one to an address on its rekey-to list,
# and the target is not on it.
ERR_CODE_BOUNDED_REKEY_TARGET_NOT_LISTED = "bounded_rekey_target_not_listed"
# A rotating account (rotating1) was sent to an ordinary signing endpoint.
ERR_CODE_ROTATING_SIGNING_REQUIRED = "rotating_signing_required"
# 409, temporary: the signer has not yet found the account's live stage.
ERR_CODE_ROTATING_STAGE_UNPROVEN = "rotating_stage_unproven"
# 409: the account's authorizer moved between prepare and sign; nothing was signed.
ERR_CODE_ROTATING_STAGE_CHANGED = "rotating_stage_changed"


class SignerError(Exception):
    """Base exception for signer errors.

    ``code`` carries the stable machine-readable wire error code from the
    signer when one was provided (see ERR_CODE_* constants); branch on it
    instead of matching message text. Empty when the error was raised
    client-side or the response body was not a JSON error envelope.
    """

    def __init__(self, *args, code: str = ""):
        super().__init__(*args)
        self.code = code


class MaxFeeIncreaseError(SignerError):
    """The signer raised fees by more than the client's max fee increase.

    Attributes:
        raised: total the signer added across the request's positions, in microAlgos
        limit: the ceiling the call was held to, in microAlgos
    """

    def __init__(self, raised: int, limit: int, prefix: str = ""):
        super().__init__(
            f"{prefix}signer raised fees by {raised} microAlgos, more than the "
            f"max fee increase {limit} set on this client"
        )
        self.raised = raised
        self.limit = limit
        self.prefix = prefix

    def __reduce__(self) -> tuple:
        # Exceptions pickle and copy by calling the class with the message
        # alone; this one is built from its amounts.
        return (self.__class__, (self.raised, self.limit, self.prefix))


def _verification_error(prefix: str, error: Exception) -> SignerError:
    """Word a failed check of a signer result.

    A refusal by one of the checks is a SignerError and is passed on as it
    reads, a ceiling refusal keeping its type. Anything else is a fault in the
    checking itself, and says so by naming the exception, so an SDK defect is
    not reported as the signer having sent something wrong.
    """
    if isinstance(error, MaxFeeIncreaseError):
        return MaxFeeIncreaseError(error.raised, error.limit, prefix)
    if isinstance(error, SignerError):
        return SignerError(f"{prefix}{error}")
    return SignerError(
        f"{prefix}the check itself failed with {type(error).__name__}: {error}"
    )


class AuthenticationError(SignerError):
    """The signer refused the request as unauthenticated (HTTP 401): the
    connection did not arrive through an enrolled SSH key."""

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


class EnrollmentError(SignerError):
    """Enrollment of the client key failed (rejected by the operator, no
    operator connected, or the signer could not record the key)."""

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

    def __reduce__(self) -> tuple:
        # Exceptions pickle and copy by calling the class with the message
        # alone; this one is built from its transaction ID and reason.
        return (self.__class__, (self.txid, self.reason))


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
class BoundedDerivedArgInfo:
    name: str
    kind: str
    parameter: str
    max_size: int


@dataclass
class BoundedArgumentPathMask:
    spend: str
    spending_rekey: str
    listed_rekey: str = ""


@dataclass
class BoundedRekeyListInfo:
    """A bounded account's rekey-to list. The entries are never published."""

    contract: str
    depth: int
    root_hex: str = ""


@dataclass
class BoundedArgumentSlotInfo:
    index: int
    name: str
    source: str
    max_size: int
    paths: BoundedArgumentPathMask


@dataclass
class BoundedCosignerAuthorizationInfo:
    """Public cosigner authority embedded in a bounded account."""

    contract: str
    component_key_type: str
    public_key_hex: str = ""
    component_key_id: str = ""
    signature_max_size: int = 0
    required_on: Optional[List[str]] = None


@dataclass
class LogicSigResourceUsage:
    """Independent program, argument, and opcode demand for one path."""

    program_bytes: int
    argument_bytes: int
    max_opcode_cost: int


@dataclass
class LogicSigResourceProfile:
    """Closed LogicSig resource paths published by signer inventory."""

    default: Optional[LogicSigResourceUsage] = None
    spend: Optional[LogicSigResourceUsage] = None
    spending_rekey: Optional[LogicSigResourceUsage] = None
    # A rekey on an account with a rekey-to list takes this path.
    listed_rekey: Optional[LogicSigResourceUsage] = None


@dataclass
class BoundedAuthorizationInfo:
    contract: str
    base_signature_arg_layout: BoundedSignatureArgLayout
    spend_effects: List[str]
    max_fee: Optional[int]  # None on a plain host, which has no fee ceiling
    rekey: str  # "refused" or "spending_key"
    runtime_args: List[RuntimeArg]
    derived_args: List[BoundedDerivedArgInfo]
    argument_layout: List[BoundedArgumentSlotInfo]
    layer3_policy: str
    cosigner: Optional[BoundedCosignerAuthorizationInfo] = None
    # With rekey "refused": "only these", a rekey may go only to a listed address.
    rekey_list: Optional[BoundedRekeyListInfo] = None


@dataclass
class KeyInfo:
    """Information about a signing key"""

    address: str
    key_type: str
    public_key_hex: str = ""
    # Account authorization envelope; empty when the signer does not report it
    # or the key is not a spending account. Never infer ed25519 from empty.
    authorization_kind: str = ""
    signing_flow: str = ""  # Signing choreography label (e.g. "cosigned1"); empty = plain /sign
    cosigner_component_key_type: str = ""  # Cosigner component key type for signing flow "cosigned1"
    logic_sig_resources: Optional[LogicSigResourceProfile] = None
    is_generic_lsig: bool = False
    is_witness_key: bool = False
    bounded_authorization: Optional[BoundedAuthorizationInfo] = None
    is_spending_account: Optional[bool] = None
    signing_args: Optional[List[SigningArg]] = None  # Key-file args required for LogicSigs
    parameters: Optional[Dict[str, str]] = None
    template_provenance_status: str = ""
    template_provenance_note: str = ""


@dataclass
class ClientConfig:
    """Non-routing client configuration loaded from config.yaml."""

    network: str = "testnet"
    networks_allowed: List[str] = field(default_factory=list)
    theme: str = "auto"

    def is_network_allowed(self, network: str) -> bool:
        """Whether config permits the network; an empty allowlist permits all."""
        return not self.networks_allowed or network in self.networks_allowed


@dataclass
class ClientEndpointConfig:
    """One signer or cosigner connection profile from endpoints.yaml. The
    client's SSH key (identity_file) is its credential; there is no token."""

    role: str
    url: str
    identity_file: str = ""
    known_hosts_path: str = ""


@dataclass
class EnrollmentResult:
    """The signer's answer to an enrollment request.

    ``fingerprint`` is the SHA256 fingerprint of the client key the request
    was made with (it equals the key the client authenticated with).
    ``pending`` is True when the request was queued for the operator to
    approve later in apadmin (the normal outcome), False when the key was
    already enrolled.
    """

    fingerprint: str
    pending: bool


@dataclass
class ClientEndpointRegistry:
    """Normalized client-local endpoint registry."""

    schema_version: int = CLIENT_ENDPOINT_SCHEMA_VERSION
    default: str = ""
    endpoints: Dict[str, ClientEndpointConfig] = field(default_factory=dict)


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
    authorization_kind: str = ""
    requires_logicsig: bool = False
    mnemonic_word_count: int = 0
    mnemonic_import: bool = False
    mnemonic_scheme: str = ""
    signing_flow: str = ""  # Signing choreography label (e.g. "cosigned1"); empty = plain /sign
    cosigner_component_key_type: str = ""  # Cosigner component key type for signing flow "cosigned1"
    per_key_contract: bool = False  # Each account selects its own contract; route by /keys
    # The boundary file grammar a per-key type's requests take ("aplane.boundary.v1"),
    # or "" for one that takes none, such as a plain host.
    boundary_schema: str = ""
    bounded_authorization: Optional[BoundedAuthorizationInfo] = None
    creation_params: Optional[List[CreationParam]] = None
    runtime_args: Optional[List[RuntimeArg]] = None


def _declared_fields(cls: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only the fields the dataclass declares, so a field added by a newer
    signer does not make decoding fail."""
    names = {f.name for f in fields(cls)}
    return {key: value for key, value in data.items() if key in names}


@dataclass
class ProtocolVersion:
    """Signer wire-protocol version."""

    major: int = 0
    minor: int = 0


@dataclass
class RotatingRecoveryStatus:
    """A rotating account's stage recovery: the active grant, why the last
    one stopped, and the per-unlock automatic allowance. Wire shape only;
    recovery is an operator action."""

    active: bool = False
    kind: str = ""
    grant_id: int = 0
    stages_charged: int = 0
    max_stages: int = 0
    active_seconds: int = 0
    hint: Optional[int] = None
    found_stage: Optional[int] = None
    stopped: str = ""
    stopped_kind: str = ""
    stopped_grant_id: int = 0
    stopped_stage: Optional[int] = None
    allowance_spent: int = 0
    allowance_max: int = 0
    suppressed_authorizer: str = ""


@dataclass
class RotatingAccountStatus:
    """One rotating account's view from the signer's last background pass
    (/status ``rotating[]``). Classification is "stage", "held_key",
    "unknown" or "unobserved"."""

    account: str
    classification: str = ""
    authorizer: str = ""
    round: int = 0
    stage: Optional[int] = None
    cached_entries: int = 0
    # Empty when the signer did not report readiness.
    preparation: str = ""
    recovery: Optional[RotatingRecoveryStatus] = None

    def __post_init__(self) -> None:
        if isinstance(self.recovery, dict):
            self.recovery = RotatingRecoveryStatus(
                **_declared_fields(RotatingRecoveryStatus, self.recovery)
            )


@dataclass
class RotatingRecoverRequest:
    """Request payload for POST /admin/rotating/recover: start ("start",
    with an optional stage hint, window, stage budget and timeout) or cancel
    ("cancel") a bounded search for a rotating account's live stage. Wire
    shape only."""

    account: str
    action: str
    stage: Optional[int] = None
    window: int = 0
    max_stages: int = 0
    timeout_seconds: int = 0


@dataclass
class RotatingRecoverResponse:
    """Response payload for POST /admin/rotating/recover."""

    account: str
    action: str
    recovery: RotatingRecoveryStatus
    grant_id: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.recovery, dict):
            self.recovery = RotatingRecoveryStatus(
                **_declared_fields(RotatingRecoveryStatus, self.recovery)
            )


@dataclass
class StatusResponse:
    """Authenticated signer status from /status"""

    state: str
    signer_locked: bool
    ready_for_signing: bool
    key_count: int
    keyset_revision: int
    protocol_version: Optional[ProtocolVersion] = None
    build_version: str = ""
    approval_wait_seconds: int = 0
    node_role: str = ""
    warnings: List[str] = field(default_factory=list)
    # Informational lines that need no action, such as a rotating account's
    # release still in flight.
    notes: List[str] = field(default_factory=list)
    # Each rotating account's view from the signer's last background pass.
    rotating: List[RotatingAccountStatus] = field(default_factory=list)

    def __post_init__(self) -> None:
        if isinstance(self.protocol_version, dict):
            self.protocol_version = ProtocolVersion(
                **_declared_fields(ProtocolVersion, self.protocol_version)
            )
        self.rotating = [
            (
                RotatingAccountStatus(**_declared_fields(RotatingAccountStatus, entry))
                if isinstance(entry, dict)
                else entry
            )
            for entry in self.rotating
        ]


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


COMPONENT_TARGET_KIND_COSIGNER = "cosigner"
COMPONENT_TARGET_KIND_BOUNDED_BASE = "bounded-base"
# Bounded-base component paths: the path the signer classified a target on. A
# listed rekey takes no cosigner component; every other path does.
COMPONENT_PATH_SPEND = "spend"
COMPONENT_PATH_SPENDING_REKEY = "spending_rekey"
COMPONENT_PATH_LISTED_REKEY = "listed_rekey"
COMPONENT_PATHS = (COMPONENT_PATH_SPEND, COMPONENT_PATH_SPENDING_REKEY, COMPONENT_PATH_LISTED_REKEY)


def component_needs_cosigner(component: Dict[str, Any]) -> bool:
    """Whether a bounded-base component's path takes a cosigner component."""
    return component.get("path") != COMPONENT_PATH_LISTED_REKEY


@dataclass
class ComponentRequest:
    """Discriminated frozen-group request for /sign/component."""

    group_bytes_hex: List[str]
    targets: List[Dict[str, Any]]
    request_id: str = ""
    contextual_positions: Optional[List[Dict[str, Any]]] = None
    dummy_positions: Optional[List[Dict[str, int]]] = None


@dataclass
class ComponentResponse:
    """Kind-tagged components returned from /sign/component."""

    request_id: str
    components: List[Dict[str, Any]]


ASSEMBLY_TARGET_KIND_BOUNDED_COSIGNER = "bounded-cosigner"


@dataclass
class AssemblyTarget:
    """One discriminated target for /sign/assemble."""

    target_index: int
    kind: str
    auth_address: str
    # Required on every bounded-cosigner target except a listed rekey, which
    # takes none.
    cosigner_signature: str = ""
    base_signatures: Optional[List[str]] = None
    bounded_runtime_args: Optional[Dict[str, str]] = None
    assembly_receipt: str = ""
    base_source_request_id: str = ""
    cosigner_source_request_id: str = ""


@dataclass
class AssemblyRequest:
    """Shared request payload for /sign/assemble."""

    group_bytes_hex: List[str]
    request_id: str = ""
    targets: Optional[List[AssemblyTarget]] = None
    passthrough: Optional[List["CosignedPassthroughItem"]] = None


@dataclass
class AssemblyResponse:
    """Shared response payload from /sign/assemble."""

    request_id: str
    signed_group: List[str]


@dataclass
class RotatingPrepareRequest:
    """Request payload for /sign/rotating/prepare: one unsigned, ungrouped,
    TX-prefixed transaction from a rotating account. The SDK carries the wire
    shape only; it does not drive the rotating flow."""

    account: str
    txn_bytes_hex: str
    request_id: str = ""


@dataclass
class RotatingPrepareResponse:
    """The exact unsigned group the signer will sign. ``mutations`` is the
    wire mutation report (snake_case keys), when present."""

    account: str
    stage: int
    target: int
    rekey_to: str
    transactions: List[str]
    mutations: Optional[Dict[str, Any]] = None


@dataclass
class RotatingSignRequest:
    """Request payload for /sign/rotating/sign.

    ``app_call_info`` is optional app-call metadata for the approval prompt,
    as on /sign. The signer checks it against the spend's bytes when
    rendering the prompt and does not sign it.
    """

    account: str
    transactions: List[str]
    request_id: str = ""
    app_call_info: Optional[Dict[str, str]] = None


@dataclass
class RotatingSignResponse:
    """Response payload from /sign/rotating/sign."""

    signed: List[str]
    stage: int
    target: int
    txid: str
    group_id: str


@dataclass
class CosignedPassthroughAuthorization:
    """Authorization shape used to budget a cosigned passthrough slot."""

    logic_sig_resources: Optional[LogicSigResourceUsage] = None
    pq_scheme: str = ""


@dataclass
class CosignedPassthroughItem:
    """Already-signed group position for /sign/assemble."""

    target_index: int
    signed_txn_hex: str
    authorization: Optional[CosignedPassthroughAuthorization] = None


@dataclass
class CosignedSignResult:
    """Result from sign_prepared_cosigned_group"""

    signed_group: List[str]
    cosigner_component_responses: List[ComponentResponse]
    primary_sign_response: Optional[GroupSignResponse] = None
    bounded_component_response: Optional[ComponentResponse] = None
    bounded_assembly_response: Optional[AssemblyResponse] = None
    # The plan's mutation report, checked against the prepared group: what
    # the signer added to it (fees, group ID, dummies). None when it changed
    # nothing.
    plan_mutations: Optional[Dict[str, Any]] = None


@dataclass
class CosignedSimulationResult:
    """Complete cosigned signing result and client-side simulation result."""

    signing: CosignedSignResult
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
    lsig_resources: Optional[LogicSigResourceUsage] = None
    pq_scheme: str = ""
    app_call_info: Optional[Dict[str, str]] = None
    signed_transaction_base64: str = ""
    checks: Optional[List[PreparedCheck]] = None

    def to_sign_request(self) -> Dict[str, Any]:
        """Convert this prepared slot to a signer SignRequest entry."""
        if self.signed_transaction_base64:
            if self.pq_scheme:
                raise ValueError("pq_scheme is allowed only for foreign transactions")
            try:
                signed_hex = base64.b64decode(
                    self.signed_transaction_base64,
                    validate=True,
                ).hex()
            except Exception as e:
                raise ValueError(f"invalid passthrough transaction: {e}") from e
            request = {"signed_txn_hex": signed_hex}
            if self.lsig_resources is not None:
                request["lsig_resources"] = _wire_lsig_resources(self.lsig_resources)
            return request

        if self.transaction is None:
            raise ValueError("transaction is required")

        txn_bytes_hex, txn_sender = encode_transaction(self.transaction)
        if not self.auth_address:
            request: Dict[str, Any] = {"txn_bytes_hex": txn_bytes_hex}
            if self.lsig_resources is not None:
                request["lsig_resources"] = _wire_lsig_resources(self.lsig_resources)
            if self.pq_scheme:
                if self.lsig_resources is not None:
                    raise ValueError(
                        "foreign transaction cannot specify both pq_scheme and lsig_resources"
                    )
                if self.pq_scheme != PQ_SCHEME_FALCON1024:
                    raise ValueError(f"unsupported pq_scheme {self.pq_scheme!r}")
                request["pq_scheme"] = self.pq_scheme
            return request

        if self.pq_scheme:
            raise ValueError("pq_scheme is allowed only for foreign transactions")
        if self.lsig_resources is not None:
            raise ValueError(
                "lsig_resources is allowed only for foreign or passthrough transactions"
            )

        request = {
            "txn_bytes_hex": txn_bytes_hex,
            "auth_address": self.auth_address,
            "txn_sender": self.txn_sender or txn_sender,
        }
        if self.lsig_args:
            request["lsig_args"] = {name: value.hex() for name, value in self.lsig_args.items()}
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
    text. Every apsigner error response sets it.
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

    if not isinstance(data, dict):
        raise SignerError("config.yaml must be a mapping")
    for field in ("endpoint", "ssh", "signer_port"):
        if field in data:
            raise SignerError(
                f'unsupported client routing in config.yaml: remove "{field}" '
                "and configure endpoints.yaml"
            )
    if isinstance(data.get("network"), str):
        config.network = data["network"]
    if isinstance(data.get("networks_allowed"), list) and all(
        isinstance(item, str) for item in data["networks_allowed"]
    ):
        config.networks_allowed = data["networks_allowed"]
    if isinstance(data.get("theme"), str) and data["theme"]:
        config.theme = data["theme"]
    if config.networks_allowed and config.network not in config.networks_allowed:
        raise SignerError(
            f"network {config.network!r} is not in networks_allowed {config.networks_allowed}"
        )

    return config


def _require_mapping(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise SignerError(f"{label} must be a mapping")
    return cast(Dict[str, Any], value)


def _require_known_fields(value: Dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        field = sorted(str(item) for item in unknown)[0]
        raise SignerError(f'{label} contains unknown field "{field}"')


def _optional_string(value: Any, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise SignerError(f"{field} must be a string")
    return value


def _resolve_path(file_path: str, data_dir: str) -> str:
    if not file_path:
        return ""
    expanded = os.path.expanduser(file_path)
    return expanded if os.path.isabs(expanded) else os.path.join(data_dir, expanded)


def _validate_endpoint_alias(alias: str) -> None:
    if not alias or re.fullmatch(r"[A-Za-z0-9._-]+", alias) is None:
        raise SignerError(
            f"alias \"{alias}\" must contain only ASCII letters, digits, '.', '_', or '-'"
        )


def _normalize_client_endpoint(
    data_dir: str, alias: str, raw_value: Any
) -> ClientEndpointConfig:
    raw = _require_mapping(raw_value, f'endpoint "{alias}"')
    _require_known_fields(
        raw,
        {
            "role",
            "url",
            "identity_file",
            "known_hosts_path",
            *_RETIRED_ENDPOINT_FIELDS,
        },
        f'endpoint "{alias}"',
    )
    role = _optional_string(raw.get("role"), "role").strip()
    if role not in ("signer", "cosigner"):
        raise SignerError(
            f'endpoint "{alias}": unsupported role "{role}" ' '(expected "signer" or "cosigner")'
        )
    endpoint_url = _optional_string(raw.get("url"), "url").strip().rstrip("/")
    if not endpoint_url:
        raise SignerError(f'endpoint "{alias}": url is required')

    if endpoint_url == "self":
        raise SignerError(
            f'endpoint "{alias}": url "self" is not supported; configure an explicit '
            "ssh://host[:port] endpoint"
        )

    try:
        parsed = urlparse(endpoint_url)
        parsed_port = parsed.port
    except ValueError as exc:
        raise SignerError(f'endpoint "{alias}": invalid url: {exc}') from exc
    # A node is reached only through its SSH server, which authenticates the
    # client's enrolled key; there is no credential a raw HTTP endpoint could
    # present.
    if parsed.scheme != "ssh":
        raise SignerError(
            f'endpoint "{alias}": unsupported url scheme "{parsed.scheme}"; '
            "a node is reached only through its SSH server (ssh://host[:port])"
        )
    if not parsed.hostname:
        raise SignerError(f'endpoint "{alias}": url host is required')
    if parsed_port is not None and not 1 <= parsed_port <= 65535:
        raise SignerError(f'endpoint "{alias}": invalid url port "{parsed_port}"')

    identity_file = _optional_string(raw.get("identity_file"), "identity_file")
    known_hosts_path = _optional_string(raw.get("known_hosts_path"), "known_hosts_path")
    identity_file = identity_file or ".ssh/id_ed25519"
    known_hosts_path = known_hosts_path or ".ssh/known_hosts"

    return ClientEndpointConfig(
        role=role,
        url=endpoint_url,
        identity_file=_resolve_path(identity_file, data_dir),
        known_hosts_path=_resolve_path(known_hosts_path, data_dir),
    )


def load_client_endpoint_registry(data_dir: str) -> ClientEndpointRegistry:
    """Load and normalize data_dir/endpoints.yaml."""
    registry = ClientEndpointRegistry()
    endpoints_path = os.path.join(data_dir, CLIENT_ENDPOINTS_FILE)
    if not os.path.exists(endpoints_path):
        return registry

    import yaml

    try:
        with open(endpoints_path, "r") as handle:
            raw_value = yaml.safe_load(handle) or {}
    except yaml.YAMLError as exc:
        raise SignerError(f"failed to parse {endpoints_path}: {exc}") from exc
    raw = _require_mapping(raw_value, CLIENT_ENDPOINTS_FILE)
    _require_known_fields(raw, {"schema_version", "default", "endpoints"}, CLIENT_ENDPOINTS_FILE)
    schema_version = raw.get("schema_version", 0)
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != CLIENT_ENDPOINT_SCHEMA_VERSION
    ):
        raise SignerError(
            f"{CLIENT_ENDPOINTS_FILE} schema_version = {schema_version}, "
            f"want {CLIENT_ENDPOINT_SCHEMA_VERSION}"
        )
    registry.schema_version = CLIENT_ENDPOINT_SCHEMA_VERSION
    endpoints_value = raw.get("endpoints")
    if endpoints_value is None:
        endpoints_value = {}
    endpoints_raw = _require_mapping(endpoints_value, f"{CLIENT_ENDPOINTS_FILE} endpoints")
    for raw_alias, endpoint_raw in endpoints_raw.items():
        if not isinstance(raw_alias, str):
            raise SignerError("endpoint aliases must be strings")
        _validate_endpoint_alias(raw_alias)
        registry.endpoints[raw_alias] = _normalize_client_endpoint(
            data_dir, raw_alias, endpoint_raw
        )

    cosigner_count = sum(
        endpoint.role == "cosigner" for endpoint in registry.endpoints.values()
    )
    if cosigner_count > 12:
        raise SignerError(
            f"{CLIENT_ENDPOINTS_FILE} configures {cosigner_count} cosigner endpoints; "
            "maximum is 12; remove or consolidate endpoint profiles"
        )

    default = _optional_string(raw.get("default"), "default")
    registry.default = default.strip()
    if registry.default:
        _validate_endpoint_alias(registry.default)
    signer_aliases = [
        alias for alias, endpoint in registry.endpoints.items() if endpoint.role == "signer"
    ]
    if len(signer_aliases) > 1:
        raise SignerError(f'{CLIENT_ENDPOINTS_FILE} may contain at most one "signer" endpoint')
    if not signer_aliases:
        if registry.default:
            raise SignerError(
                f'{CLIENT_ENDPOINTS_FILE} default endpoint "{registry.default}" '
                'is set but no "signer" endpoint is configured'
            )
    elif registry.default and registry.default != signer_aliases[0]:
        raise SignerError(
            f'{CLIENT_ENDPOINTS_FILE} default endpoint "{registry.default}" must be '
            f'the "signer" endpoint "{signer_aliases[0]}"'
        )
    else:
        registry.default = signer_aliases[0]
    return registry


def resolve_client_endpoint(
    registry: ClientEndpointRegistry, alias: Optional[str] = None
) -> tuple[str, ClientEndpointConfig]:
    """Resolve an explicit endpoint alias or the registry's default signer."""
    selected = alias or registry.default
    if not selected:
        raise SignerError(f"{CLIENT_ENDPOINTS_FILE} has no default signer endpoint")
    if selected not in registry.endpoints:
        raise SignerError(f'endpoint alias "{selected}" is not defined')
    return selected, registry.endpoints[selected]


def client_endpoint_ssh_host_port(
    endpoint: ClientEndpointConfig,
) -> tuple[str, int]:
    """Resolve host and SSH port from an ssh:// endpoint."""
    parsed = urlparse(endpoint.url)
    if parsed.scheme != "ssh":
        raise SignerError(f'endpoint "{endpoint.url}" requires ssh://')
    return parsed.hostname or "", parsed.port or DEFAULT_SSH_PORT


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
            signed_bytes = _strict_hex(signed_hex)
        except ValueError as e:
            raise SignerError(f"signed group position {index} is invalid hex: {e}") from e
        # The raw hex is what gets submitted and the decoded value is what gets
        # simulated, so the two must be the same transaction exactly.
        try:
            signed = _decode_canonical_signed_txn(signed_bytes)
        except SignerError as e:
            raise SignerError(f"signed group position {index}: {e}") from e
        signed_transactions.append(signed)

    def simulation_request(trace: bool) -> models.SimulateRequest:
        return models.SimulateRequest(
            txn_groups=[models.SimulateRequestTransactionGroup(txns=signed_transactions)],
            allow_empty_signatures=False,
            allow_more_logs=trace,
            exec_trace_config=(
                models.SimulateTraceConfig(enable=True, state_change=True) if trace else None
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
        failure = groups[0].get("failure-message") or groups[0].get("failure_message", "")

    return SimulationResult(
        tx_ids=[signed.get_txid() for signed in signed_transactions],
        transactions=[encode_transaction(signed.transaction)[0] for signed in signed_transactions],
        signed_group=list(signed_group),
        mutations=mutations,
        response=response,
        failed=bool(failure),
    )


_SIGNED_TRANSACTION_TYPES = (
    transaction.SignedTransaction,
    transaction.LogicSigTransaction,
    transaction.MultisigTransaction,
    # A native post-quantum signature, such as native Falcon.
    transaction.PQSignedTransaction,
)

_UINT64_MAX = (1 << 64) - 1


@dataclass
class _RequestSlot:
    """One decoded /sign or /plan request entry."""

    mode: str
    txn: transaction.Transaction
    signed_bytes: Optional[bytes] = None
    # The address a sign position asked the signer to sign with.
    auth: Optional[str] = None
    # The auth address a passthrough's signed bytes carry, if any.
    signer: Optional[str] = None


def _sign_slot(txn: transaction.Transaction, auth_address: Any) -> _RequestSlot:
    """The slot of a sign-mode position.

    The auth address must be a real address: the returned authorization is
    checked against it.
    """
    if not isinstance(auth_address, str) or not encoding.is_valid_address(auth_address):
        raise ValueError(f"auth_address {auth_address!r} is not a valid address")
    return _RequestSlot("sign", txn, auth=auth_address)


def _decode_passthrough_slot(raw: bytes) -> _RequestSlot:
    """Decode a passthrough's signed bytes, strictly."""
    signed = _decode_canonical_signed_txn(raw)
    signer = getattr(signed, "authorizing_address", None) or getattr(signed, "auth_addr", None)
    return _RequestSlot("passthrough", signed.transaction, raw, signer=signer or None)


def _validate_authorization(signed: Any, auth: str) -> None:
    """Require a signed position's one authorization to be the auth address's.

    A response that signs the right transaction with the wrong key, or with no
    key at all, is as unusable as one that signs the wrong transaction.

    - Ed25519 signature: must verify over the transaction under the auth
      address.
    - LogicSig: a plain LogicSig (a program and its args, not one delegated by
      a signature) whose program address is the auth address.
    - Post-quantum proof: native Falcon-1024 with its public key and signature
      present, whose derived account address is the auth address. The Falcon
      signature itself is not verified.
    - Multisig: refused. The signer never returns one for a position it signs.

    The signer field (``sgnr``) must name the auth address when that differs
    from the sender, and must be absent when they are the same. A wrapper with
    no authorization, or with more than one, never reaches here: it does not
    decode as a canonical signed transaction.
    """
    txn = signed.transaction
    if isinstance(signed, transaction.MultisigTransaction):
        raise SignerError(
            "carries a multisig, which the signer does not return for a position it signs"
        )
    named = getattr(signed, "authorizing_address", None) or getattr(signed, "auth_addr", None)
    want = auth if auth != txn.sender else None
    if (named or None) != want:
        if want is None:
            raise SignerError(f"names signer {named}, but the sender signs for itself")
        if not named:
            raise SignerError(f"does not name its signer {auth}, which is not the sender")
        raise SignerError(f"names signer {named}, not the requested auth address {auth}")

    if isinstance(signed, transaction.SignedTransaction):
        signature = base64.b64decode(signed.signature or "")
        if len(signature) != 64:
            raise SignerError(f"signature is {len(signature)} bytes, not 64")
        message = bytes.fromhex(encode_transaction(txn)[0])
        try:
            VerifyKey(encoding.decode_address(auth)).verify(message, signature)
        except BadSignatureError as e:
            # Only the library's own verdict reads as a failed verification.
            # Anything else that goes wrong here is not the signer's doing and
            # is left for the caller to report as what it is.
            raise SignerError(
                f"signature does not verify under the requested auth address {auth}"
            ) from e
    elif isinstance(signed, transaction.LogicSigTransaction):
        lsig = signed.lsig
        if not lsig.logic:
            raise SignerError("LogicSig has no program")
        if lsig.sig or lsig.msig or lsig.lmsig or getattr(lsig, "pqsig", None):
            raise SignerError(
                "LogicSig is delegated by a signature, which the signer does not "
                "return for a position it signs"
            )
        program = lsig.address()
        if program != auth:
            raise SignerError(
                f"LogicSig program address {program} is not the requested auth address {auth}"
            )
    elif isinstance(signed, transaction.PQSignedTransaction):
        proof = signed.pqsig
        if proof.scheme != PQ_SCHEME_FALCON1024.encode():
            raise SignerError(
                f"post-quantum scheme {proof.scheme!r} is not {PQ_SCHEME_FALCON1024!r}"
            )
        if not proof.public_key or not proof.signature:
            raise SignerError("post-quantum authorization is missing its public key or signature")
        try:
            derived = encoding.address_from_pq_sig(proof)
        except (
            algosdk_error.InvalidPQSaltError,
            algosdk_error.PQSchemeLengthError,
            algosdk_error.NoCanonicalSaltError,
        ) as e:
            raise SignerError(f"post-quantum key's address cannot be derived: {e}") from e
        if derived != auth:
            raise SignerError(
                f"post-quantum key's address {derived} is not the requested auth address {auth}"
            )
    else:
        raise SignerError("carries no authorization")


_HEX = re.compile(r"(?:[0-9a-fA-F]{2})*")


def _strict_hex(value: Any) -> bytes:
    """Decode a hex string that holds hex digits and nothing else.

    bytes.fromhex skips ASCII whitespace, so it would accept strings the Go
    and TypeScript SDKs refuse.
    """
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise ValueError("not a hex string")
    return bytes.fromhex(value)


def _decode_canonical_txn(raw: bytes) -> transaction.Transaction:
    """Decode TX-prefixed unsigned transaction bytes, requiring the canonical encoding."""
    if len(raw) < 3 or raw[:2] != b"TX":
        raise SignerError("missing TX prefix")
    try:
        decoded = encoding.msgpack_decode(base64.b64encode(raw[2:]).decode())
    except Exception as e:
        raise SignerError(f"invalid msgpack: {e}") from e
    if not isinstance(decoded, transaction.Transaction):
        raise SignerError("did not decode as a transaction")
    if raw.hex() != encode_transaction(decoded)[0]:
        raise SignerError("bytes are not canonical")
    return decoded


def _decode_canonical_signed_txn(raw: bytes) -> Any:
    """Decode signed transaction bytes, requiring the canonical encoding.

    Comparing only the inner transaction would let a non-canonical wrapper, or
    fields the decoder drops, through to submission unnoticed.
    """
    if not raw:
        raise SignerError("empty signed transaction")
    try:
        decoded = encoding.msgpack_decode(base64.b64encode(raw).decode())
    except Exception as e:
        raise SignerError(f"invalid msgpack: {e}") from e
    if not isinstance(decoded, _SIGNED_TRANSACTION_TYPES):
        raise SignerError("did not decode as a signed transaction")
    if raw != base64.b64decode(encoding.msgpack_encode(decoded)):
        raise SignerError("bytes are not a canonical signed transaction")
    return decoded


def _group_id_bytes(txn: transaction.Transaction) -> Optional[bytes]:
    value = getattr(txn, "group", None)
    if value is None:
        return None
    try:
        encoded = bytes(value)
    except (TypeError, ValueError) as e:
        raise SignerError("transaction has invalid group ID") from e
    if not encoded or encoded == bytes(32):
        return None
    if len(encoded) != 32:
        raise SignerError("transaction has invalid group ID")
    return encoded


def _decode_request_slots(sign_entries: List[Dict[str, Any]]) -> List[_RequestSlot]:
    """Decode every request entry before it is sent to the signer.

    Malformed request bytes raise SignerError, as the signer's own refusal of
    them would.
    """
    slots = []
    for index, entry in enumerate(sign_entries, start=1):
        mode = _sign_request_mode(entry)
        if mode == "passthrough":
            try:
                raw = _strict_hex(entry["signed_txn_hex"])
            except (TypeError, ValueError) as e:
                raise SignerError(
                    f"transaction {index}: signed_txn_hex is invalid hex: {e}"
                ) from e
            try:
                slots.append(_decode_passthrough_slot(raw))
            except SignerError as e:
                raise SignerError(f"transaction {index}: passthrough transaction: {e}") from e
            continue
        try:
            raw = _strict_hex(entry["txn_bytes_hex"])
        except (TypeError, ValueError) as e:
            raise SignerError(f"transaction {index}: txn_bytes_hex is invalid hex: {e}") from e
        try:
            txn = _decode_canonical_txn(raw)
        except SignerError as e:
            raise SignerError(f"transaction {index}: txn_bytes_hex: {e}") from e
        if mode == "foreign":
            slots.append(_RequestSlot(mode, txn))
            continue
        try:
            slots.append(_sign_slot(txn, entry.get("auth_address")))
        except ValueError as e:
            raise SignerError(f"transaction {index}: {e}") from e
    return slots


def _mutation_int(mutations: Dict[str, Any], name: str) -> int:
    value = mutations.get(name, 0)
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int):
        raise SignerError(f"mutation {name} must be an integer")
    return cast(int, value)


def _validate_canonical_group_id(txns: List[transaction.Transaction]) -> Optional[bytes]:
    """Require a multi-transaction group to carry the group ID computed over itself."""
    if len(txns) < 2:
        return None
    cleared = copy.deepcopy(txns)
    for txn in cleared:
        txn.group = None
    try:
        want = transaction.calculate_group_id(cleared)
    except Exception as e:
        raise SignerError(f"compute canonical returned group ID: {e}") from e
    for index, txn in enumerate(txns, start=1):
        if _group_id_bytes(txn) != want:
            raise SignerError(f"returned transaction {index} does not carry the canonical group ID")
    return cast(bytes, want)


def _canonical_dummy_txn(
    first_original: transaction.Transaction,
    group_id: Optional[bytes],
    index: int,
) -> transaction.Transaction:
    """Rebuild the index'th resource dummy the signer's planner appends.

    A zero-fee, zero-amount self-payment from the dummy address with the index
    as its one-byte note, on the first original transaction's validity window
    and genesis, in the group.
    """
    dummy_address = transaction.LogicSigAccount(COSIGNED_DUMMY_PROGRAM).address()
    params = transaction.SuggestedParams(
        fee=0,
        first=first_original.first_valid_round,
        last=first_original.last_valid_round,
        gh=first_original.genesis_hash,
        gen=first_original.genesis_id,
        flat_fee=True,
    )
    dummy = transaction.PaymentTxn(dummy_address, params, dummy_address, 0, note=bytes([index]))
    dummy.fee = 0
    dummy.group = group_id
    return dummy


def _validate_canonical_dummies(
    first_original: transaction.Transaction,
    group_id: Optional[bytes],
    appended: List[transaction.Transaction],
) -> None:
    """Require every appended transaction to be the canonical resource dummy."""
    for index, txn in enumerate(appended):
        want = _canonical_dummy_txn(first_original, group_id, index)
        if encode_transaction(want)[0] != encode_transaction(txn)[0]:
            raise SignerError(
                f"appended transaction {index + 1} is not the canonical resource dummy"
            )


def _sign_canonical_dummy(txn: transaction.Transaction) -> bytes:
    """Sign a resource dummy with the dummy LogicSig, its only valid authorization."""
    dummy_account = transaction.LogicSigAccount(COSIGNED_DUMMY_PROGRAM)
    signed = transaction.LogicSigTransaction(txn, dummy_account)
    return base64.b64decode(encoding.msgpack_encode(signed))


def _check_max_fee_increase(value: Any) -> Optional[int]:
    """Validate a max fee increase setting: None, or a non-negative integer.

    Any integral type is accepted (anything with ``__index__``, such as a
    numpy integer). A bool or a float is not.
    """
    if value is None:
        return None
    error = SignerError("max_fee_increase must be a non-negative integer of microAlgos, or None")
    if isinstance(value, bool):
        raise error
    try:
        limit = operator.index(value)
    except TypeError:
        raise error from None
    if limit < 0:
        raise error
    return limit


def _validate_group_mutations(
    slots: List[_RequestSlot],
    returned: List[Optional[transaction.Transaction]],
    mutations: Optional[Dict[str, Any]],
    max_fee_increase: Optional[int],
) -> None:
    """Check a /sign or /plan result against the request.

    The signer may raise the fees it reports on positions it signs, assign a
    canonical group ID, and append reported canonical resource dummies. It may
    not alter any other transaction field.

    ``returned`` holds the transaction observed at each final position. None is
    a foreign position /sign returned empty: nothing was observed, and the
    position is taken as the request's transaction in the final group.

    ``max_fee_increase`` is the caller's ceiling on the total fee the signer may
    add across the request's positions, or None for no ceiling; it has no
    default, so a caller cannot leave the check out by omission. The report's
    own total cannot serve: it is written by the party being checked. An
    appended dummy carries a zero fee of its own, and the signer charges its
    base fee to an original position, so the total over original positions is
    the whole increase, dummies included.
    """
    if len(returned) < len(slots):
        raise SignerError(
            f"signer returned {len(returned)} transaction(s), want at least {len(slots)}"
        )
    if len(returned) > constants.tx_group_limit:
        raise SignerError(
            f"signer returned {len(returned)} transaction(s), more than the maximum "
            f"group size {constants.tx_group_limit}"
        )
    appended = len(returned) - len(slots)
    passthrough_count = sum(1 for slot in slots if slot.mode == "passthrough")
    foreign_count = sum(1 for slot in slots if slot.mode == "foreign")

    if mutations is not None and not isinstance(mutations, dict):
        raise SignerError("mutation report must be a mapping")
    report: Dict[str, Any] = mutations or {}
    group_id_changed = report.get("group_id_changed") or False
    if not isinstance(group_id_changed, bool):
        raise SignerError("mutation group_id_changed must be a boolean")
    if mutations is None:
        if appended:
            raise SignerError(
                f"signer appended {appended} transaction(s) without a mutation report"
            )
    else:
        original_count = _mutation_int(report, "original_count")
        final_count = _mutation_int(report, "final_count")
        dummies_added = _mutation_int(report, "dummies_added")
        if original_count != len(slots):
            raise SignerError(
                f"mutation original_count {original_count} does not match "
                f"request count {len(slots)}"
            )
        if final_count != len(returned):
            raise SignerError(
                f"mutation final_count {final_count} does not match "
                f"returned count {len(returned)}"
            )
        if dummies_added != appended:
            raise SignerError(
                f"mutation dummies_added {dummies_added} does not match "
                f"appended count {appended}"
            )
        if _mutation_int(report, "total_fees_delta") < 0:
            raise SignerError("mutation total_fees_delta must not be negative")
        if appended and not group_id_changed:
            raise SignerError("mutation appended dummies without reporting a group ID change")
        if len(returned) == 1 and group_id_changed:
            raise SignerError("mutation reported a group ID change for a single transaction")
    reported_passthrough = _mutation_int(report, "passthrough_count")
    if reported_passthrough != passthrough_count:
        raise SignerError(
            f"mutation passthrough_count {reported_passthrough} does not match the "
            f"{passthrough_count} passthrough transaction(s) requested"
        )
    reported_foreign = _mutation_int(report, "foreign_count")
    if reported_foreign != foreign_count:
        raise SignerError(
            f"mutation foreign_count {reported_foreign} does not match the "
            f"{foreign_count} foreign transaction(s) requested"
        )

    fee_modified = set()
    raw_fee_modified = report.get("fees_modified") or []
    if not isinstance(raw_fee_modified, list):
        raise SignerError("mutation fees_modified must be a list")
    for index in raw_fee_modified:
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or index < 0
            or index >= len(slots)
        ):
            raise SignerError(f"mutation fee index {index!r} is outside original positions")
        if index in fee_modified:
            raise SignerError(f"mutation fee index {index} is duplicated")
        if slots[index].mode != "sign":
            raise SignerError(
                f"mutation fee index {index} is a {slots[index].mode} position, "
                "whose fee the signer cannot change"
            )
        fee_modified.add(index)

    # A request that already carries a group ID is immutable to the signer:
    # its planner raises no fee on it, appends no dummy to it and never
    # regroups it, whatever the modes of its positions. A response that reports
    # any of these could not be submitted, because positions the signer did
    # not return stay bound to the original group.
    if any(_group_id_bytes(slot.txn) is not None for slot in slots):
        if group_id_changed:
            raise SignerError(
                "signer reported a group ID change for a request that was already grouped"
            )
        if fee_modified:
            raise SignerError(
                "signer reported a fee change for a request that was already grouped"
            )
        if appended:
            raise SignerError(
                f"signer appended {appended} transaction(s) to a request that was already grouped"
            )

    assigned: Optional[bytes] = None
    if group_id_changed:
        observed = next((txn for txn in returned if txn is not None), None)
        if observed is None:
            raise SignerError(
                "signer reported a group ID change but returned no transaction that carries it"
            )
        assigned = _group_id_bytes(observed)

    final: List[transaction.Transaction] = []
    total_fee_delta = 0
    for index, slot in enumerate(slots):
        want = copy.deepcopy(slot.txn)
        if group_id_changed:
            want.group = assigned
        got = returned[index]
        if got is None:
            final.append(want)
            continue
        if index in fee_modified:
            if got.fee <= want.fee:
                raise SignerError(
                    f"reported fee mutation at original position {index + 1} "
                    "did not increase the fee"
                )
            total_fee_delta += got.fee - want.fee
            if total_fee_delta > _UINT64_MAX:
                raise SignerError("observed fee delta overflows uint64")
            want.fee = got.fee
        if encode_transaction(want)[0] != encode_transaction(got)[0]:
            raise SignerError(f"signer changed unreported fields at original position {index + 1}")
        final.append(got)
    reported_delta = _mutation_int(report, "total_fees_delta")
    if reported_delta != total_fee_delta:
        raise SignerError(
            f"mutation total_fees_delta {reported_delta} does not match "
            f"observed delta {total_fee_delta}"
        )
    if max_fee_increase is not None and total_fee_delta > max_fee_increase:
        raise MaxFeeIncreaseError(total_fee_delta, max_fee_increase)
    for index in range(len(slots), len(returned)):
        extra = returned[index]
        if extra is None:
            raise SignerError(f"signer returned no transaction at appended position {index + 1}")
        final.append(extra)

    group_id = _validate_canonical_group_id(final)
    if appended:
        _validate_canonical_dummies(slots[0].txn, group_id, final[len(slots) :])


def _validate_sign_response(
    slots: List[_RequestSlot],
    signed: Any,
    mutations: Optional[Dict[str, Any]],
    max_fee_increase: Optional[int],
) -> None:
    """Check a /sign response against the request before anyone can submit it.

    Sign positions must carry the requested transaction, changed only as the
    mutation report states. Passthrough positions must come back byte for
    byte, foreign positions stay empty, and every appended position must be
    the canonical signed resource dummy.
    """
    if not isinstance(signed, list) or any(not isinstance(item, str) for item in signed):
        raise SignerError("signer returned a malformed signed list")
    if len(signed) < len(slots):
        raise SignerError(
            f"signer returned {len(signed)} signed transaction(s), want at least {len(slots)}"
        )
    returned: List[Optional[transaction.Transaction]] = []
    signed_bytes: List[bytes] = []
    for index, signed_hex in enumerate(signed):
        slot = slots[index] if index < len(slots) else None
        if slot is not None and slot.mode == "foreign":
            if signed_hex:
                raise SignerError(
                    f"signer returned a signed transaction for foreign position {index + 1}"
                )
            returned.append(None)
            signed_bytes.append(b"")
            continue
        if not signed_hex:
            if slot is None:
                raise SignerError(
                    f"signer returned empty dummy transaction at position {index + 1}"
                )
            raise SignerError(f"signer returned no signature for position {index + 1}")
        try:
            raw = _strict_hex(signed_hex)
        except ValueError as e:
            raise SignerError(f"signed transaction {index + 1} is invalid hex: {e}") from e
        signed_bytes.append(raw)
        if slot is not None and slot.mode == "passthrough":
            if raw != slot.signed_bytes:
                raise SignerError(f"signer changed passthrough transaction {index + 1}")
            returned.append(slot.txn)
            continue
        try:
            decoded = _decode_canonical_signed_txn(raw)
        except SignerError as e:
            raise SignerError(f"signed transaction {index + 1}: {e}") from e
        if slot is not None:
            try:
                _validate_authorization(decoded, cast(str, slot.auth))
            except SignerError as e:
                raise SignerError(f"signed transaction {index + 1} {e}") from e
        returned.append(decoded.transaction)
    _validate_group_mutations(slots, returned, mutations, max_fee_increase)
    for index in range(len(slots), len(signed)):
        dummy = cast(transaction.Transaction, returned[index])
        if _sign_canonical_dummy(dummy) != signed_bytes[index]:
            raise SignerError(
                f"appended transaction {index - len(slots) + 1} does not carry the "
                "canonical resource dummy authorization"
            )


def _validate_plan_response(
    slots: List[_RequestSlot],
    transactions: Any,
    mutations: Optional[Dict[str, Any]],
    max_fee_increase: Optional[int],
) -> None:
    """Check a /plan response against the request.

    A plan result is the final group as unsigned transactions, so every
    position is observed, foreign ones included.
    """
    if transactions is None:
        transactions = []
    if not isinstance(transactions, list) or any(
        not isinstance(item, str) for item in transactions
    ):
        raise SignerError("signer returned a malformed planned transaction list")
    if len(transactions) < len(slots):
        raise SignerError(
            f"signer returned {len(transactions)} planned transaction(s), "
            f"want at least {len(slots)}"
        )
    returned: List[Optional[transaction.Transaction]] = []
    for index, txn_hex in enumerate(transactions, start=1):
        try:
            raw = _strict_hex(txn_hex)
        except ValueError as e:
            raise SignerError(f"planned transaction {index} is invalid hex: {e}") from e
        try:
            returned.append(_decode_canonical_txn(raw))
        except SignerError as e:
            raise SignerError(f"planned transaction {index}: {e}") from e
    _validate_group_mutations(slots, returned, mutations, max_fee_increase)


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
        return {key: _compact_payload(item) for key, item in value.items() if item is not None}
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


def _validate_assembly_index(index: int, group_len: int, covered: set) -> None:
    if not isinstance(index, int) or index < 0 or index >= group_len:
        raise ValueError(f"target_index {index} out of range")
    if index in covered:
        raise ValueError(f"duplicate target_index {index}")
    covered.add(index)


def _wire_lsig_resources(resources: LogicSigResourceUsage) -> Dict[str, int]:
    _validate_lsig_resources(resources, "lsig_resources")
    return {
        "program_bytes": resources.program_bytes,
        "argument_bytes": resources.argument_bytes,
        "max_opcode_cost": resources.max_opcode_cost,
    }


def _validate_lsig_resources(resources: LogicSigResourceUsage, label: str) -> None:
    if not (
        type(resources.program_bytes) is int
        and 0 < resources.program_bytes <= 16_000
        and type(resources.argument_bytes) is int
        and resources.argument_bytes >= 0
        and type(resources.max_opcode_cost) is int
        and 0 < resources.max_opcode_cost <= 320_000
    ):
        raise ValueError(f"{label} LogicSig resources are invalid")


def _require_lsig_resources(resources: Any, label: str) -> LogicSigResourceUsage:
    if resources is None:
        raise ValueError(f"{label} LogicSig resources are unavailable")
    if isinstance(resources, LogicSigResourceUsage):
        normalized = LogicSigResourceUsage(**vars(resources))
    elif isinstance(resources, dict):
        expected = {"program_bytes", "argument_bytes", "max_opcode_cost"}
        if set(resources) != expected:
            raise ValueError(f"{label} LogicSig resources are invalid")
        normalized = LogicSigResourceUsage(
            program_bytes=resources["program_bytes"],
            argument_bytes=resources["argument_bytes"],
            max_opcode_cost=resources["max_opcode_cost"],
        )
    else:
        raise ValueError(f"{label} LogicSig resources are invalid")
    _validate_lsig_resources(normalized, label)
    return normalized


def _cosigned_dummy_lsig_resources() -> LogicSigResourceUsage:
    """Return apsigner's canonical dummy LogicSig resource declaration.

    /plan and /sign must see these exact values to keep fee planning
    idempotent across the cosigned assembly choreography.
    """
    return LogicSigResourceUsage(
        program_bytes=len(COSIGNED_DUMMY_PROGRAM),
        argument_bytes=0,
        max_opcode_cost=1,
    )


def _normalize_cosigned_passthrough_authorization(
    authorization: Any,
) -> Optional[CosignedPassthroughAuthorization]:
    """Return a fully typed authorization built from a dict or an instance.

    A caller may construct CosignedPassthroughAuthorization directly and still
    set logic_sig_resources to a plain dict. Normalizing both shapes here keeps
    every downstream consumer working on LogicSigResourceUsage, so invalid
    input raises ValueError instead of AttributeError at the point of use.
    """
    if authorization is None:
        return None
    if isinstance(authorization, CosignedPassthroughAuthorization):
        resources = authorization.logic_sig_resources
        pq_scheme = authorization.pq_scheme
    elif isinstance(authorization, dict):
        expected = {"logic_sig_resources", "pq_scheme"}
        if not set(authorization).issubset(expected):
            raise ValueError("cosigned passthrough authorization has unknown fields")
        resources = authorization.get("logic_sig_resources")
        pq_scheme = authorization.get("pq_scheme", "")
    else:
        raise ValueError("cosigned passthrough authorization must be an object")
    return CosignedPassthroughAuthorization(
        logic_sig_resources=(
            _require_lsig_resources(resources, "cosigned passthrough authorization")
            if resources is not None
            else None
        ),
        pq_scheme=pq_scheme,
    )


def _sign_request_mode(entry: Dict[str, Any]) -> str:
    has_passthrough = bool(entry.get("signed_txn_hex"))
    has_txn = bool(entry.get("txn_bytes_hex"))
    has_auth = bool(entry.get("auth_address"))
    if has_passthrough and (has_txn or has_auth):
        raise ValueError(
            "cannot specify both sign fields (auth_address/txn_bytes_hex) "
            "and passthrough field (signed_txn_hex)"
        )
    if has_passthrough:
        return "passthrough"
    if has_txn and has_auth:
        return "sign"
    if has_txn:
        return "foreign"
    if has_auth:
        raise ValueError("txn_bytes_hex is required for sign mode")
    raise ValueError(
        "must specify either sign fields (auth_address + txn_bytes_hex), "
        "foreign fields (txn_bytes_hex), or passthrough field (signed_txn_hex)"
    )


def _validate_sign_entries(sign_entries: List[Dict[str, Any]]) -> None:
    if not sign_entries:
        raise ValueError("sign_entries must not be empty")
    sign_count = 0
    passthrough_count = 0
    foreign_count = 0
    for index, entry in enumerate(sign_entries):
        try:
            if not isinstance(entry, dict):
                raise ValueError("sign entry must be a mapping")
            mode = _sign_request_mode(entry)
            pq_scheme = entry.get("pq_scheme")
            resources = entry.get("lsig_resources")
            if pq_scheme and mode != "foreign":
                raise ValueError("pq_scheme is allowed only for foreign transactions")
            if pq_scheme and pq_scheme != PQ_SCHEME_FALCON1024:
                raise ValueError(f"unsupported pq_scheme {pq_scheme!r}")
            if resources is not None and mode not in ("foreign", "passthrough"):
                raise ValueError(
                    "lsig_resources is allowed only for foreign or passthrough transactions"
                )
            if pq_scheme and resources is not None:
                raise ValueError(
                    "foreign transaction cannot specify both pq_scheme and lsig_resources"
                )
            if resources is not None:
                _require_lsig_resources(resources, "lsig_resources")
            if mode == "sign":
                sign_count += 1
            elif mode == "passthrough":
                passthrough_count += 1
            else:
                foreign_count += 1
        except ValueError as e:
            raise ValueError(f"transaction {index + 1}: {e}") from e
    if passthrough_count and foreign_count:
        raise ValueError("cannot mix passthrough and foreign transactions in one request")
    if sign_count == 0 and foreign_count:
        raise ValueError(
            "no signable transactions: all entries are foreign. Build and submit "
            "this group locally instead of using apsigner"
        )


def _parse_lsig_resource_usage(data: Any) -> Optional[LogicSigResourceUsage]:
    if not isinstance(data, dict):
        return None

    def number(name: str) -> int:
        # A missing field keeps its default. A value that is not an integer
        # is a malformed payload, not a number to be converted.
        value = data.get(name, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise SignerError(
                f"signer reported LogicSig resources with a non-integer {name}: {value!r}"
            )
        return cast(int, value)

    return LogicSigResourceUsage(
        program_bytes=number("program_bytes"),
        argument_bytes=number("argument_bytes"),
        max_opcode_cost=number("max_opcode_cost"),
    )


def _parse_lsig_resource_profile(data: Any) -> Optional[LogicSigResourceProfile]:
    if not isinstance(data, dict):
        return None
    return LogicSigResourceProfile(
        default=_parse_lsig_resource_usage(data.get("default")),
        spend=_parse_lsig_resource_usage(data.get("spend")),
        spending_rekey=_parse_lsig_resource_usage(data.get("spending_rekey")),
        listed_rekey=_parse_lsig_resource_usage(data.get("listed_rekey")),
    )


def _selected_prepared_resources(
    key: Optional[KeyInfo], txn: Optional[transaction.Transaction]
) -> Optional[LogicSigResourceUsage]:
    if not key or not key.logic_sig_resources:
        return None
    profile = key.logic_sig_resources
    selected = profile.spend or profile.default
    if key.bounded_authorization and txn is not None and txn.rekey_to is not None:
        bounded = key.bounded_authorization
        if bounded.rekey_list is not None and bounded.rekey == "refused":
            # Only these addresses: the signer checks the target and adds the proof.
            selected = profile.listed_rekey
        elif bounded.rekey == "spending_key":
            # With a list too (plus cosigned) the signer moves a listed target to
            # the listed path, and its base component says so.
            selected = profile.spending_rekey
        elif bounded.rekey == "refused":
            raise ValueError("the account refuses rekeys")
        else:
            raise ValueError("bounded rekey authorization metadata is unavailable")
    return LogicSigResourceUsage(**vars(selected)) if selected else None


def _component_path_resources(
    key: Optional[KeyInfo], path: str, label: str
) -> LogicSigResourceUsage:
    """The key's LogicSig resources for the path a base component named."""
    profile = key.logic_sig_resources if key else None
    selected = None
    if profile is not None:
        selected = {
            COMPONENT_PATH_SPEND: profile.spend,
            COMPONENT_PATH_SPENDING_REKEY: profile.spending_rekey,
            COMPONENT_PATH_LISTED_REKEY: profile.listed_rekey,
        }.get(path)
    if selected is None:
        raise SignerError(f"{label}: signer key publishes no LogicSig resources for path {path!r}")
    return LogicSigResourceUsage(**vars(selected))


def _prepared_sign_request(item: "PreparedTransaction", index: int) -> Dict[str, Any]:
    """A prepared slot's SignRequest entry, with its index on any error."""
    try:
        return item.to_sign_request()
    except ValueError as e:
        raise ValueError(f"prepared transaction {index}: {e}") from e


def _parse_bounded_authorization(data: Any) -> Optional[BoundedAuthorizationInfo]:
    if not isinstance(data, dict):
        return None
    # A plain host has no fee ceiling, so max_fee may be absent; signing checks
    # that the contract agrees (_bounded_fee_ceiling).
    max_fee = data.get("max_fee")
    if max_fee is not None and (
        isinstance(max_fee, bool) or not isinstance(max_fee, int) or max_fee < 0
    ):
        raise SignerError("invalid bounded_authorization: max_fee must be a non-negative integer")
    layout = data.get("base_signature_arg_layout") or {}
    runtime_args = data.get("runtime_args") or []
    derived_args = data.get("derived_args") or []
    argument_layout = data.get("argument_layout") or []
    cosigner = data.get("cosigner")
    rekey_list = data.get("rekey_list")
    return BoundedAuthorizationInfo(
        contract=data.get("contract", ""),
        base_signature_arg_layout=BoundedSignatureArgLayout(
            count=layout.get("count", 0), max_sizes=list(layout.get("max_sizes") or [])
        ),
        spend_effects=list(data.get("spend_effects") or []),
        max_fee=max_fee,
        rekey=data.get("rekey", ""),
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
                    listed_rekey=(item.get("paths") or {}).get("listed_rekey", ""),
                ),
            )
            for item in argument_layout
        ],
        layer3_policy=data.get("layer3_policy", ""),
        cosigner=(
            BoundedCosignerAuthorizationInfo(
                contract=cosigner.get("contract", ""),
                component_key_type=cosigner.get("component_key_type", ""),
                public_key_hex=cosigner.get("public_key_hex", ""),
                component_key_id=cosigner.get("component_key_id", ""),
                signature_max_size=cosigner.get("signature_max_size", 0),
                required_on=list(cosigner.get("required_on") or []),
            )
            if isinstance(cosigner, dict)
            else None
        ),
        rekey_list=(
            BoundedRekeyListInfo(
                contract=rekey_list.get("contract", ""),
                depth=rekey_list.get("depth", 0),
                root_hex=rekey_list.get("root", ""),
            )
            if isinstance(rekey_list, dict)
            else None
        ),
    )


def _validate_assembly_request(data: Dict[str, Any]) -> None:
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
        if not target.get("auth_address"):
            raise ValueError(f"target {i}: auth_address is required")
        if not target.get("cosigner_signature") and target.get("cosigner_source_request_id"):
            raise ValueError(f"target {i}: cosigner_source_request_id needs a cosigner_signature")
        kind = target.get("kind")
        if kind == ASSEMBLY_TARGET_KIND_BOUNDED_COSIGNER:
            if not target.get("base_signatures") or not target.get("assembly_receipt"):
                raise ValueError(f"target {i}: base_signatures and assembly_receipt are required for bounded-cosigner target")
            _validate_sign_request_id(str(target.get("base_source_request_id", "")))
        else:
            raise ValueError(f"target {i}: invalid kind")
        _validate_sign_request_id(str(target.get("cosigner_source_request_id", "")))

    for i, item in enumerate(passthrough, start=1):
        _validate_assembly_index(item.get("target_index"), len(group_bytes_hex), covered)
        if not item.get("signed_txn_hex"):
            raise ValueError(f"passthrough {i}: signed_txn_hex is required")

    for index in range(len(group_bytes_hex)):
        if index not in covered:
            raise ValueError(f"group position {index} is not covered by targets or passthrough")


def _validate_assembly_response(data: Dict[str, Any]) -> None:
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
    group = data.get("group_bytes_hex") or []
    targets = data.get("targets") or []
    context = data.get("contextual_positions") or []
    dummies = data.get("dummy_positions") or []
    _validate_component_group_bytes(group)
    if not targets or len(dummies) > len(group):
        raise ValueError("targets are required and dummy_positions cannot exceed group length")
    original_count = len(group) - len(dummies)
    covered = set()
    for index, target in enumerate(targets, start=1):
        target_index = target.get("target_index")
        if (not isinstance(target_index, int) or target_index < 0
                or target_index >= original_count or target_index in covered):
            raise ValueError(f"target {index} has invalid, duplicate, or overlapping target_index")
        covered.add(target_index)
        if not target.get("auth_address"):
            raise ValueError(f"target {index}: auth_address is required")
    for index, position in enumerate(context, start=1):
        target_index = position.get("target_index")
        if (not isinstance(target_index, int) or target_index < 0
                or target_index >= original_count or target_index in covered):
            raise ValueError(f"contextual position {index} has invalid, duplicate, or overlapping target_index")
        covered.add(target_index)
        resources = position.get("lsig_resources")
        pq_scheme = position.get("pq_scheme", "")
        # With auth_address the position is the signer's own, which the signer
        # sizes from its records: it takes no hint.
        if position.get("auth_address") and (resources is not None or pq_scheme):
            raise ValueError(
                f"contextual position {index}: lsig_resources and pq_scheme "
                "are allowed only without auth_address"
            )
        if not position.get("auth_address") and position.get("lsig_args"):
            raise ValueError(f"contextual position {index}: lsig_args requires auth_address")
        if resources is not None and pq_scheme:
            raise ValueError(
                f"contextual position {index} cannot specify both lsig_resources and pq_scheme"
            )
        if resources is not None:
            _require_lsig_resources(resources, f"contextual position {index}")
        if pq_scheme and pq_scheme != PQ_SCHEME_FALCON1024:
            raise ValueError(
                f"contextual position {index} has unsupported pq_scheme {pq_scheme!r}"
            )
    for index in range(original_count):
        if index not in covered:
            raise ValueError(f"original group position {index} is not covered")
    for offset, dummy in enumerate(dummies):
        if dummy.get("target_index") != original_count + offset:
            raise ValueError(f"dummy position {offset + 1} is not in the contiguous suffix")


def _validate_component_request(data: Dict[str, Any]) -> None:
    _validate_sign_request_id(str(data.get("request_id", "")))
    group = data.get("group_bytes_hex") or []
    targets = data.get("targets") or []
    context = data.get("contextual_positions") or []
    dummies = data.get("dummy_positions") or []
    _validate_component_group_bytes(group)
    if not targets or len(dummies) > len(group):
        raise ValueError("targets are required and dummy_positions cannot exceed group length")
    original_count = len(group) - len(dummies)
    covered = set()
    kind = targets[0].get("kind")
    for index, target in enumerate(targets, start=1):
        target_index = target.get("target_index")
        if (not isinstance(target_index, int) or target_index < 0
                or target_index >= original_count or target_index in covered):
            raise ValueError(f"target {index} has invalid, duplicate, or overlapping target_index")
        covered.add(target_index)
        if target.get("kind") != kind:
            raise ValueError("mixed component target kinds are not supported")
        if kind == COMPONENT_TARGET_KIND_COSIGNER:
            if target.get("auth_address") or target.get("lsig_args"):
                raise ValueError(f"target {index}: cosigner target forbids auth_address and lsig_args")
            if index > 1 and target.get("component_key") != targets[0].get("component_key"):
                raise ValueError("cosigner targets must share one component_key")
        elif kind == COMPONENT_TARGET_KIND_BOUNDED_BASE:
            if not target.get("auth_address") or target.get("component_key"):
                raise ValueError(f"target {index}: bounded-base target requires auth_address and forbids component_key")
        else:
            raise ValueError(f"target {index}: unsupported component kind {kind!r}")
    # auth_address marks one of the signer's own accounts. Only a bounded-base
    # request sizes the group, so only it takes the field.
    if kind != COMPONENT_TARGET_KIND_BOUNDED_BASE:
        for index, position in enumerate(context, start=1):
            if position.get("auth_address") or position.get("lsig_args"):
                raise ValueError(
                    f"contextual position {index}: auth_address and lsig_args "
                    "are allowed only on a bounded-base request"
                )
    probe = {
        "request_id": data.get("request_id", ""),
        "group_bytes_hex": group,
        "targets": [{
            "target_index": target.get("target_index"),
            "auth_address": target.get("auth_address") or "target",
        } for target in targets],
        "contextual_positions": context,
        "dummy_positions": dummies,
    }
    _validate_bounded_component_request(probe)


def _validate_component_response(
    data: Dict[str, Any], request: Optional[Dict[str, Any]] = None
) -> None:
    _validate_sign_request_id(str(data.get("request_id", "")))
    if not data.get("request_id") or not data.get("components"):
        raise ValueError("request_id and components are required")
    seen = set()
    for index, component in enumerate(data["components"], start=1):
        target_index = component.get("target_index")
        if not isinstance(target_index, int) or target_index < 0 or target_index in seen:
            raise ValueError(f"component {index} has invalid or duplicate target_index")
        if request is not None and target_index >= len(request.get("group_bytes_hex") or []):
            raise ValueError(f"component {index} target_index is outside the frozen group")
        seen.add(target_index)
        kind = component.get("kind")
        if kind == COMPONENT_TARGET_KIND_COSIGNER:
            if (not component.get("signature") or not component.get("signature_scheme")
                    or component.get("base_signatures") or component.get("assembly_receipt")
                    or component.get("path")):
                raise ValueError(f"component {index} has invalid signature material")
        elif kind == COMPONENT_TARGET_KIND_BOUNDED_BASE:
            if (not component.get("auth_address") or not component.get("base_signatures")
                    or not component.get("assembly_receipt")
                    or not component.get("signature_scheme") or component.get("signature")):
                raise ValueError(f"component {index} has invalid bounded-base material")
            if component.get("path") not in COMPONENT_PATHS:
                raise ValueError(f"component {index} has unknown bounded path {component.get('path')!r}")
        else:
            raise ValueError(f"component {index} has unsupported kind")


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


_UINT64_LIMIT = 1 << 64


def _require_uint(value: Any, name: str, *, positive: bool = False) -> int:
    """Require a plain integer for an ID, an amount or a fee.

    py-algorand-sdk converts what it is given with int(), so 123.9 would
    become 123 and "123" would be accepted. A float, a string or a bool is a
    mistake in the caller, not a number to be rounded.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer, not {type(value).__name__}")
    if value < 0 or value >= _UINT64_LIMIT or (positive and value == 0):
        bound = "a positive integer" if positive else "a non-negative integer"
        raise ValueError(f"{name} must be {bound} below 2**64")
    return cast(int, value)


def _apply_prep_fee(params: Any, fee: Optional[int]) -> None:
    # No fee-per-byte mode: fee is always flat microAlgos, so a set fee can
    # never be silently reinterpreted as EstimateSize*fee. None means unset
    # (keep the suggested fee); an explicit int (including 0, used for fee
    # pooling) is applied as a flat fee.
    if fee is None:
        return
    _require_uint(fee, "fee")
    params.fee = fee
    params.flat_fee = True


def _load_client_ssh_key(path: str) -> Any:
    """Load an SSH client identity the signer accepts (Ed25519 or ECDSA)."""
    errors = []
    for key_class in (paramiko.Ed25519Key, paramiko.ECDSAKey):
        try:
            return key_class.from_private_key_file(path)
        except paramiko.ssh_exception.PasswordRequiredException as e:
            raise SignerError(f"SSH key {path} is encrypted; use an unencrypted key: {e}") from e
        except (paramiko.ssh_exception.SSHException, ValueError) as e:
            errors.append(e)
    raise SignerError(
        f"Failed to load SSH key {path}: not an {CLIENT_SSH_KEY_REQUIREMENT} private key; "
        f"the signer does not accept other key types ({errors[-1]})"
    )


def _account_amount(account_info: Any) -> int:
    if isinstance(account_info, dict):
        return int(account_info.get("amount", 0))
    return int(getattr(account_info, "amount", 0))


def _account_min_balance(account_info: Any) -> int:
    if isinstance(account_info, dict):
        return int(account_info.get("min-balance") or account_info.get("min_balance") or 0)
    return int(getattr(account_info, "min_balance", None) or getattr(account_info, "minBalance", 0))


def _account_asset_holding(account_info: Any, asset_id: int) -> Optional[Any]:
    assets = (
        account_info.get("assets", [])
        if isinstance(account_info, dict)
        else getattr(account_info, "assets", [])
    )
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


def _asa_opt_out_checks(
    sender_info: Any, close_info: Any, asset_id: int, close_to: str
) -> List[PreparedCheck]:
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
        or _account_int(
            account_info, "total-assets-opted-in", "total_assets_opted_in", "totalAssetsOptedIn"
        )
        > 0
    ):
        raise SignerError("cannot close account with ASA holdings")
    if (
        _account_list(account_info, "created-assets", "created_assets", "createdAssets")
        or _account_int(
            account_info, "total-created-assets", "total_created_assets", "totalCreatedAssets"
        )
        > 0
    ):
        raise SignerError("cannot close account with created assets")
    if (
        _account_list(account_info, "apps-local-state", "apps_local_state", "appsLocalState")
        or _account_int(
            account_info, "total-apps-opted-in", "total_apps_opted_in", "totalAppsOptedIn"
        )
        > 0
    ):
        raise SignerError("cannot close account with app opt-ins")
    if (
        _account_list(account_info, "created-apps", "created_apps", "createdApps")
        or _account_int(
            account_info, "total-created-apps", "total_created_apps", "totalCreatedApps"
        )
        > 0
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


def _rekey_target_flow_check(rekey_to: str, flow: str) -> None:
    """Refuse a rekey to a signer key whose signing flow cannot authorize
    another account.

    A rotating account's address is its stage 0 program, which authorizes
    only the account itself, and the signer refuses that rekey; any flow this
    SDK does not know is refused too, so a future flow fails closed here
    rather than at the signer.
    """
    if flow in ("", SIGNING_FLOW_BOUNDED1, SIGNING_FLOW_COSIGNED1):
        return
    if flow == SIGNING_FLOW_ROTATING1:
        raise SignerError(
            f"cannot rekey to {rekey_to}: it is a rotating account, and its address is a "
            "one-time stage key; an account rekeyed to it would be stuck on that stage, "
            "and every signature would reuse that key"
        )
    raise SignerError(
        f"cannot rekey to {rekey_to}: it uses signing flow {flow!r}, which this SDK cannot use as "
        "another account's authorizer"
    )


# The protocol's minimum keyreg fee for an account to become eligible for
# consensus incentives: GoOnlineFee, 2 ALGO since consensus v40. The ledger
# grants eligibility only where payouts are enabled, as on MainNet, TestNet and
# a current LocalNet; algod doesn't report either value.
_INCENTIVE_ELIGIBILITY_FEE = 2_000_000


def _validate_keyreg_params(
    *,
    mode: str,
    votekey: Optional[str],
    selkey: Optional[str],
    votefst: Optional[int],
    votelst: Optional[int],
    votekd: Optional[int],
    sprfkey: Optional[str],
    incentive_eligible: bool,
) -> None:
    if not mode:
        raise ValueError('mode is required: "online" or "offline"')
    if mode == "offline":
        if incentive_eligible:
            raise ValueError("incentive eligibility needs an online keyreg")
        for name, value in (
            ("votekey", votekey),
            ("selkey", selkey),
            ("sprfkey", sprfkey),
            ("votefst", votefst),
            ("votelst", votelst),
            ("votekd", votekd),
        ):
            # Like Go, 0 and an empty key count as unset.
            if value:
                raise ValueError(
                    "an offline keyreg takes no participation keys or vote rounds, "
                    f"but {name} is set"
                )
        return
    if mode != "online":
        raise ValueError(f'mode {mode!r} is not "online" or "offline"')
    if not votekey:
        raise ValueError("votekey is required")
    if not selkey:
        raise ValueError("selkey is required")
    # The network refuses an online keyreg without a state proof key.
    if not sprfkey:
        raise ValueError("sprfkey is required")
    if not votefst:
        raise ValueError("votefst is required")
    if not votelst:
        raise ValueError("votelst is required")
    if votelst < votefst:
        raise ValueError("votelst must be greater than or equal to votefst")
    if not votekd:
        raise ValueError("votekd is required")


def _account_incentive_eligible(account_info: Any) -> bool:
    if isinstance(account_info, dict):
        return bool(
            account_info.get("incentive-eligible") or account_info.get("incentive_eligible")
        )
    return bool(
        getattr(account_info, "incentive_eligible", None)
        or getattr(account_info, "incentiveEligible", False)
    )


def _validate_payment_group(
    transactions: List[PreparedTransaction],
    other_positions: Optional[List[PreparedTransaction]] = None,
) -> PreparedCheck:
    """Check each paying sender can cover its payments and every fee it pays.

    ``other_positions`` are the group's non-payment positions. They move no
    ALGO, but a sender that also pays from this group pays their fees too.
    """
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
    for item in other_positions or []:
        if item.transaction is None:
            raise ValueError("group transaction is required")
        if item.transaction.sender in totals:
            totals[item.transaction.sender]["required"] += int(
                getattr(item.transaction, "fee", 0)
            )
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
        s.bind(("127.0.0.1", 0))
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
        ssh_pkey_path: str,
        remote_host: str,
        remote_port: int,
        local_port: int,
        known_hosts_path: str = "",
        trust_on_first_use: bool = False,
        setup_timeout: float = DEFAULT_SSH_SETUP_TIMEOUT,
    ):
        self._transport: Optional[paramiko.Transport] = None
        self._ssh_client: Optional[paramiko.SSHClient] = None
        self._server_socket: Optional[socket.socket] = None
        self._threads: list = []
        self._running = False

        self._ssh_host = ssh_host
        self._ssh_port = ssh_port
        self._ssh_pkey_path = ssh_pkey_path
        self._remote_host = remote_host
        self._remote_port = remote_port
        self.local_bind_port = local_port
        self._known_hosts_path = known_hosts_path
        self._trust_on_first_use = trust_on_first_use
        if (
            not isinstance(setup_timeout, (int, float))
            or not math.isfinite(setup_timeout)
            or setup_timeout <= 0
        ):
            raise SignerError("SSH setup timeout must be positive")
        self._setup_timeout = float(setup_timeout)

    def start(self):
        """Establish SSH connection and start local port forward listener."""
        import threading

        if not self._known_hosts_path:
            raise SignerError("known_hosts path is required for SSH host key verification")

        pkey = _load_client_ssh_key(self._ssh_pkey_path)

        sock: Optional[socket.socket] = None
        transport: Optional[paramiko.Transport] = None
        transport_socket_timeout: Optional[float] = None
        timeout_timer: Optional[threading.Timer] = None
        setup_timed_out = threading.Event()
        setup_lock = threading.Lock()
        setup_complete = False
        deadline = time.monotonic() + self._setup_timeout

        def remaining_setup_time() -> float:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("SSH setup deadline exceeded")
            return remaining

        def expire_setup() -> None:
            with setup_lock:
                if setup_complete:
                    return
                setup_timed_out.set()
                if sock is not None:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    sock.close()

        try:
            sock = socket.create_connection(
                (self._ssh_host, self._ssh_port), timeout=remaining_setup_time()
            )
            sock.settimeout(remaining_setup_time())
            timeout_timer = threading.Timer(remaining_setup_time(), expire_setup)
            timeout_timer.daemon = True
            timeout_timer.start()
            transport = paramiko.Transport(sock)
            transport_socket_timeout = sock.gettimeout()
            transport.start_client(timeout=remaining_setup_time())
            server_key = transport.get_remote_server_key()
            self._verify_host_key(server_key)

            # The enrolled key is the only credential: public-key
            # authentication under the fixed client username, nothing else.
            sock.settimeout(remaining_setup_time())
            transport.auth_publickey(SSH_USERNAME, pkey)
            if not transport.is_authenticated():
                raise SignerError("SSH public-key authentication did not complete")
            with setup_lock:
                if setup_timed_out.is_set() or time.monotonic() >= deadline:
                    raise TimeoutError("SSH setup deadline exceeded")
                setup_complete = True
            timeout_timer.cancel()
            sock.settimeout(transport_socket_timeout)
        except Exception as exc:
            if timeout_timer is not None:
                timeout_timer.cancel()
            if transport:
                transport.close()
            elif sock:
                sock.close()
            if (
                setup_timed_out.is_set()
                or isinstance(exc, (TimeoutError, socket.timeout))
                or time.monotonic() >= deadline
            ):
                raise SignerError(
                    f"SSH setup timed out after {self._setup_timeout:g} seconds"
                ) from exc
            if isinstance(exc, SignerError):
                raise
            if isinstance(exc, paramiko.ssh_exception.AuthenticationException):
                # The signer refuses unsupported key types before verifying a
                # signature, so a refused supported key is one it has not
                # enrolled (or has revoked).
                raise AuthenticationError(
                    f"SSH authentication failed: {exc}: the client's SSH key is not "
                    f"enrolled at the signer, or was revoked (the signer accepts "
                    f"{CLIENT_SSH_KEY_REQUIREMENT} client keys); enroll it with "
                    "request_enrollment or apshell enroll"
                ) from exc
            if isinstance(exc, paramiko.ssh_exception.SSHException):
                raise SignerError(f"SSH connection failed: {exc}") from exc
            raise
        finally:
            if timeout_timer is not None:
                timeout_timer.cancel()

        self._transport = transport

        # Start local listener
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(("127.0.0.1", self.local_bind_port))
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)
        self._running = True

        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()
        self._threads.append(accept_thread)

    def _verify_host_key(self, server_key: paramiko.PKey) -> None:
        """Verify or persist the negotiated key before authentication."""
        host_entry = (
            self._ssh_host if self._ssh_port == 22 else f"[{self._ssh_host}]:{self._ssh_port}"
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
                f"pass trust_on_first_use=True for explicit first-use trust, "
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
                    "direct-tcpip",
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
            t1 = threading.Thread(target=self._forward, args=(client_sock, channel), daemon=True)
            t2 = threading.Thread(target=self._forward, args=(channel, client_sock), daemon=True)
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

        # Explicit SSH tunnel, authenticated by the enrolled client key
        client = SignerClient.connect_ssh(
            host="signer.example.com",
            ssh_key_path="~/aplane/apclient/.ssh/id_ed25519",
            known_hosts_path="~/aplane/apclient/.ssh/known_hosts",
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
        timeout: Optional[int] = None,
        tunnel: Optional[Any] = None,
        max_fee_increase: Optional[int] = None,
    ):
        """
        Initialize signer client (use class methods instead).

        base_url is the local end of an SSH tunnel to the signer, which
        authenticates the tunnel by the client's enrolled key; the client
        itself carries no credential.

        Args:
            base_url: Internal HTTP endpoint (set automatically by class methods)
            timeout: Optional explicit request timeout in seconds. If omitted,
                endpoint-specific defaults are used.
            tunnel: SSH tunnel instance (managed internally)
            max_fee_increase: Optional ceiling, in microAlgos, on the total fee
                the signer may add to a request. Every sign, plan and simulate
                call through this client fails and returns nothing when the
                signer's fee raises across the request's positions add up to
                more than this. On a sign or simulate call the signer has
                already answered by then; its signature is discarded. Each request is
                held to the ceiling in force when it started. Any integral
                value is accepted. Zero means the signer may not raise
                any fee. There is no default: None accepts a reported raise of
                any size. Also settable as the ``max_fee_increase`` attribute.
        """
        if not base_url:
            raise SignerError("base_url is required")
        self.max_fee_increase = max_fee_increase
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout if timeout and timeout > 0 else None
        self.session = requests.Session()
        self._tunnel = tunnel
        self._key_cache: Dict[str, KeyInfo] = {}  # Cache key info by address
        self._key_cache_revision: Optional[int] = None
        self._approval_wait_seconds: Optional[int] = None
        self._approval_wait_fetched_at: Optional[float] = None
        self._approval_wait_known = False

    @property
    def max_fee_increase(self) -> Optional[int]:
        """Ceiling, in microAlgos, on the signer's total fee increase; None is unbounded."""
        return self._max_fee_increase

    @max_fee_increase.setter
    def max_fee_increase(self, value: Optional[int]) -> None:
        self._max_fee_increase = _check_max_fee_increase(value)

    @classmethod
    def connect_ssh(
        cls,
        host: str,
        ssh_key_path: str,
        ssh_port: int = DEFAULT_SSH_PORT,
        timeout: Optional[int] = None,
        known_hosts_path: str = "",
        trust_on_first_use: bool = False,
        local_port: int = 0,
        ssh_setup_timeout: float = DEFAULT_SSH_SETUP_TIMEOUT,
        max_fee_increase: Optional[int] = None,
    ) -> "SignerClient":
        """
        Connect to remote apsigner via SSH tunnel.

        Establishes an SSH tunnel to the remote host and forwards the
        signer's REST listener to a local port. The enrolled client key is the
        only credential; a key the signer has not enrolled fails the handshake
        with AuthenticationError (enroll it with request_enrollment first).

        Args:
            host: Remote host running apsigner
            ssh_key_path: Path to the APlane client SSH private key
            ssh_port: SSH port on remote (default: 1127)
            timeout: Optional explicit request timeout in seconds
            known_hosts_path: Path to known_hosts file for host key verification (required)
            trust_on_first_use: If true, auto-trust unknown host keys (default: false)
            local_port: Local tunnel port (default: choose a free one). There is no
                remote REST port argument: the signer's SSH server forwards every
                channel to its own REST listener.
            ssh_setup_timeout: Maximum seconds for TCP connection and SSH authentication
            max_fee_increase: Optional ceiling, in microAlgos, on the total fee
                the signer may add to a request (see SignerClient). No default.

        Returns:
            SignerClient instance with active SSH tunnel

        Raises:
            SignerError: If paramiko is not installed or known_hosts_path is empty
            SignerUnavailableError: If SSH connection fails
        """
        import os

        # Checked here so a bad value is refused before any connection is
        # attempted; the constructor is the one place that sets it.
        fee_ceiling = _check_max_fee_increase(max_fee_increase)
        ssh_key_path = os.path.expanduser(ssh_key_path)
        known_hosts_path = os.path.expanduser(known_hosts_path)

        # Find a free local port unless the endpoint pins one.
        local_port = local_port or _find_free_port()

        try:
            tunnel = _SSHTunnel(
                ssh_host=host,
                ssh_port=ssh_port,
                ssh_pkey_path=ssh_key_path,
                # The server checks only that the destination is loopback and
                # forwards to its own REST listener, so the port is nominal.
                remote_host="127.0.0.1",
                remote_port=11270,
                local_port=local_port,
                known_hosts_path=known_hosts_path,
                trust_on_first_use=trust_on_first_use,
                setup_timeout=ssh_setup_timeout,
            )
            tunnel.start()
        except SignerError:
            raise
        except Exception as e:
            raise SignerUnavailableError(f"SSH tunnel failed: {e}")

        # Connect through tunnel
        base_url = f"http://127.0.0.1:{tunnel.local_bind_port}"
        client = cls(base_url, timeout, tunnel=tunnel, max_fee_increase=fee_ceiling)

        # Verify connection
        if not client.health():
            client.close()
            raise SignerUnavailableError(
                "Connected via SSH but signer not responding"
            )

        return client

    @classmethod
    def from_env(
        cls,
        data_dir: Optional[str] = None,
        timeout: Optional[int] = None,
        endpoint: Optional[str] = None,
        trust_on_first_use: bool = False,
        ssh_setup_timeout: float = DEFAULT_SSH_SETUP_TIMEOUT,
        max_fee_increase: Optional[int] = None,
    ) -> "SignerClient":
        """
        Connect using the endpoint registry from a data directory.

        Data directory contents:
            - endpoints.yaml: Signer and cosigner routing
            - .ssh/id_ed25519: SSH key, the client's credential

        Args:
            data_dir: Client data directory. Required unless APCLIENT_DATA
                environment variable is set.
            timeout: Optional explicit request timeout in seconds
            endpoint: Optional signer or cosigner endpoint alias
            trust_on_first_use: Explicitly trust an unknown SSH host key
            ssh_setup_timeout: Maximum seconds for TCP connection and SSH authentication
            max_fee_increase: Optional ceiling, in microAlgos, on the total fee
                the signer may add to a request (see SignerClient). No default.

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

        load_config(data_dir)
        registry = load_client_endpoint_registry(data_dir)
        _, selected = resolve_client_endpoint(registry, endpoint)

        host, ssh_port = client_endpoint_ssh_host_port(selected)
        if not os.path.exists(selected.identity_file):
            raise SignerError(f"SSH key not found at {selected.identity_file}")
        return cls.connect_ssh(
            host=host,
            ssh_key_path=selected.identity_file,
            ssh_port=ssh_port,
            timeout=timeout,
            known_hosts_path=selected.known_hosts_path,
            trust_on_first_use=trust_on_first_use,
            ssh_setup_timeout=ssh_setup_timeout,
            max_fee_increase=max_fee_increase,
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
                f"{self.base_url}/health", timeout=self._timeout_for(HEALTH_TIMEOUT)
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
                f"{self.base_url}/status", timeout=self._timeout_for(STATUS_TIMEOUT)
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Not authenticated: connect through an enrolled SSH key")

        if resp.status_code == 503:
            raise SignerUnavailableError(self._error_message(resp, "Signer unavailable"))

        if resp.status_code != 200:
            raise self._signer_http_error(
                resp,
                f"Failed to get signer status: HTTP {resp.status_code}",
            )

        data = resp.json()
        raw_warnings = data.get("warnings")
        raw_notes = data.get("notes")
        raw_rotating = data.get("rotating")
        status = StatusResponse(
            node_role=data.get("node_role", ""),
            state=data.get("state", ""),
            signer_locked=data.get("signer_locked", False),
            ready_for_signing=data.get("ready_for_signing", False),
            key_count=data.get("key_count", 0),
            keyset_revision=data.get("keyset_revision", 0),
            protocol_version=data.get("protocol_version"),
            build_version=data.get("build_version", ""),
            approval_wait_seconds=data.get("approval_wait_seconds") or 0,
            warnings=(
                [warning for warning in raw_warnings if isinstance(warning, str)]
                if isinstance(raw_warnings, list)
                else []
            ),
            notes=(
                [note for note in raw_notes if isinstance(note, str)]
                if isinstance(raw_notes, list)
                else []
            ),
            rotating=(
                [
                    entry
                    for entry in raw_rotating
                    if isinstance(entry, dict) and isinstance(entry.get("account"), str)
                ]
                if isinstance(raw_rotating, list)
                else []
            ),
        )
        self._cache_approval_wait(status.approval_wait_seconds)
        return status

    def _cache_approval_wait(self, seconds: int) -> None:
        self._approval_wait_seconds = (
            seconds if seconds > 0 and seconds <= MAX_DISCOVERED_APPROVAL_WAIT else None
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
        default = wait + SIGN_APPROVAL_SLACK if wait is not None else DEFAULT_SIGN_REQUEST_TIMEOUT
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
                f"{self.base_url}/keys", timeout=self._timeout_for(INVENTORY_TIMEOUT)
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Not authenticated: connect through an enrolled SSH key")

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
                authorization_kind=k.get("authorization_kind", ""),
                signing_flow=k.get("signing_flow", ""),
                cosigner_component_key_type=k.get("cosigner_component_key_type", ""),
                logic_sig_resources=_parse_lsig_resource_profile(k.get("logic_sig_resources")),
                is_generic_lsig=k.get("is_generic_lsig", False),
                is_witness_key=k.get("is_witness_key", False),
                bounded_authorization=_parse_bounded_authorization(k.get("bounded_authorization")),
                is_spending_account=k.get("is_spending_account"),
                signing_args=signing_args,
                parameters=k.get("parameters"),
                template_provenance_status=k.get("template_provenance_status", ""),
                template_provenance_note=k.get("template_provenance_note", ""),
            )
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
    ) -> PreparedTransaction:
        """Build a prepared ALGO payment transaction.

        ``amount`` and ``fee`` are in microAlgos. A set ``fee`` is the flat fee
        the transaction pays.
        """
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        if not receiver:
            raise ValueError("receiver is required")
        _require_uint(amount, "amount")

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee)

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
            raise SignerError(f"insufficient funds: available {available}, required {required}")

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
    ) -> PreparedTransaction:
        """Build a prepared ASA transfer transaction.

        ``amount`` is in the asset's base units, not adjusted for its
        decimals. ``fee`` is in microAlgos.
        """
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        if not receiver:
            raise ValueError("receiver is required")
        if asset_id is None:
            raise ValueError("asset_id is required")
        _require_uint(asset_id, "asset_id", positive=True)
        _require_uint(amount, "amount")

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee)

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
    ) -> PreparedTransaction:
        """Build a prepared ASA opt-in transaction."""
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        if asset_id is None:
            raise ValueError("asset_id is required")
        _require_uint(asset_id, "asset_id", positive=True)

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee)

        sender_info = algod_client.account_info(sender)
        txn = transaction.AssetTransferTxn(
            sender=sender,
            sp=params,
            receiver=sender,
            amt=0,
            index=asset_id,
            note=note,
        )
        # The balance is checked against the fee the built transaction pays.
        # The suggested fee is per byte, usually zero, and would check nothing.
        checks = _asa_opt_in_checks(sender_info, asset_id, int(txn.fee))
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
        if asset_id is None:
            raise ValueError("asset_id is required")
        _require_uint(asset_id, "asset_id", positive=True)

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee)

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
        _apply_prep_fee(params, fee)

        sender_info = algod_client.account_info(sender)
        txn = transaction.PaymentTxn(
            sender=sender,
            sp=params,
            receiver=close_to,
            amt=0,
            close_remainder_to=close_to,
            note=note,
        )
        # Checked against the fee the built transaction pays, not the
        # suggested per-byte fee.
        checks = _account_close_checks(sender_info, int(txn.fee))
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
    ) -> PreparedTransaction:
        """Build a prepared self-payment rekey transaction."""
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        if not rekey_to:
            raise ValueError("rekey_to is required")

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee)

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
        # Resolution just refreshed the inventory, so the cache answers for
        # the target without another round trip.
        target = None if rekey_to == sender else self._key_cache.get(rekey_to)
        if target is not None:
            _rekey_target_flow_check(rekey_to, target.signing_flow)
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
        mode: str,
        votekey: Optional[str] = None,
        selkey: Optional[str] = None,
        votefst: Optional[int] = None,
        votelst: Optional[int] = None,
        votekd: Optional[int] = None,
        sprfkey: Optional[str] = None,
        incentive_eligible: bool = False,
        note: Optional[bytes] = None,
        fee: Optional[int] = None,
    ) -> PreparedTransaction:
        """Build a prepared key registration transaction.

        ``mode`` is required. An ``"online"`` registration needs the vote,
        selection and state proof keys, the vote rounds and the key dilution;
        an ``"offline"`` one takes none of them and takes the account offline,
        which can register keys again later. A nonparticipating registration, which can never be
        undone, isn't offered, and apsigner refuses one.

        ``incentive_eligible`` asks for consensus incentive eligibility, on an
        online registration only. Unless the account is already eligible, the
        fee is raised to the 2 ALGO the protocol requires; an explicit lower
        ``fee`` is refused. An eligible account stays eligible and pays no
        extra fee.
        """
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        _validate_keyreg_params(
            mode=mode,
            votekey=votekey,
            selkey=selkey,
            votefst=votefst,
            votelst=votelst,
            votekd=votekd,
            sprfkey=sprfkey,
            incentive_eligible=incentive_eligible,
        )

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee)

        sender_info = algod_client.account_info(sender)
        txn: transaction.KeyregTxn
        if mode == "offline":
            # A keyless registration; nonpart is never set.
            txn = transaction.KeyregOfflineTxn(sender=sender, sp=params, note=note)
        else:
            txn = transaction.KeyregTxn(
                sender=sender,
                sp=params,
                votekey=votekey,
                selkey=selkey,
                votefst=votefst,
                votelst=votelst,
                votekd=votekd,
                sprfkey=sprfkey,
                note=note,
            )
        charge_incentive_fee = incentive_eligible and not _account_incentive_eligible(sender_info)
        if charge_incentive_fee and txn.fee < _INCENTIVE_ELIGIBILITY_FEE:
            if fee is not None:
                raise SignerError(
                    "incentive eligibility needs a keyreg fee of at least "
                    f"{_INCENTIVE_ELIGIBILITY_FEE} microAlgos, but fee is set to {fee}"
                )
            txn.fee = _INCENTIVE_ELIGIBILITY_FEE
        available = max(_account_amount(sender_info) - _account_min_balance(sender_info), 0)
        if available < txn.fee:
            raise SignerError(
                f"insufficient funds for keyreg fee: available {available}, fee {txn.fee}"
            )

        message = ""
        if charge_incentive_fee:
            message = "the 2 ALGO incentive eligibility fee is included"
        elif incentive_eligible:
            message = (
                "the account is already incentive eligible and stays eligible, "
                "so no 2 ALGO fee is added"
            )
        data: Dict[str, Any] = {"mode": mode}
        if mode == "online":
            data.update(
                vote_first=votefst or 0,
                vote_last=votelst or 0,
                vote_key_dilution=votekd or 0,
                incentive_eligible=incentive_eligible,
                incentive_fee_charged=charge_incentive_fee,
            )
        resolved = self.resolve_auth_address(sender, lambda _: sender_info)
        return PreparedTransaction(
            transaction=txn,
            auth_address=resolved.auth_address,
            signer_key=resolved.key_info,
            checks=[PreparedCheck(name="keyreg", status="ok", message=message, data=data)],
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
        app_call_info: Dict[str, str],
    ) -> PreparedTransaction:
        if algod_client is None:
            raise ValueError("algod_client is required")
        if not sender:
            raise ValueError("sender is required")
        if app_id is None:
            raise ValueError("app_id is required")
        _require_uint(app_id, "app_id", positive=True)
        for name, references in (("foreign_apps", foreign_apps), ("foreign_assets", foreign_assets)):
            for position, reference in enumerate(references or []):
                _require_uint(reference, f"{name}[{position}]", positive=True)
        if int(on_complete) < 0 or int(on_complete) > int(
            transaction.OnComplete.DeleteApplicationOC
        ):
            raise ValueError(f"invalid on_complete: {on_complete}")

        params = algod_client.suggested_params()
        _apply_prep_fee(params, fee)

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
        _apply_prep_fee(params, fee)

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
            checks.append(_validate_asa_transfer_group(prepared[: len(asa_transfers)]))
        if payments:
            checks.append(
                _validate_payment_group(
                    prepared[len(asa_transfers) :], prepared[: len(asa_transfers)]
                )
            )
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
                f"{self.base_url}/keytypes", timeout=self._timeout_for(INVENTORY_TIMEOUT)
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Not authenticated: connect through an enrolled SSH key")

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
                        ]
                        or None,
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

            result.append(
                KeyTypeInfo(
                    key_type=kt["key_type"],
                    family=kt.get("family", ""),
                    display_name=kt.get("display_name", ""),
                    description=kt.get("description", ""),
                    authorization_kind=kt.get("authorization_kind", ""),
                    requires_logicsig=kt.get("requires_logicsig", False),
                    mnemonic_word_count=kt.get("mnemonic_word_count", 0),
                    mnemonic_import=kt.get("mnemonic_import", False),
                    mnemonic_scheme=kt.get("mnemonic_scheme", ""),
                    signing_flow=kt.get("signing_flow", ""),
                    cosigner_component_key_type=kt.get("cosigner_component_key_type", ""),
                    per_key_contract=kt.get("per_key_contract", False),
                    boundary_schema=kt.get("boundary_schema", ""),
                    bounded_authorization=_parse_bounded_authorization(
                        kt.get("bounded_authorization")
                    ),
                    creation_params=creation_params,
                    runtime_args=runtime_args,
                )
            )

        return result

    def generate_key(
        self, key_type: str, parameters: Optional[Dict[str, str]] = None
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
                timeout=self._timeout_for(MUTATION_TIMEOUT),
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Not authenticated: connect through an enrolled SSH key")

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
                timeout=self._timeout_for(MUTATION_TIMEOUT),
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Not authenticated: connect through an enrolled SSH key")

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
        the body is not a JSON error envelope.
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

        Only the not_found wire code maps to KeyNotFoundError; message text is
        never inspected.
        """
        code, message = self._error_parts(resp, "Bad request")
        if code == ERR_CODE_NOT_FOUND:
            return KeyNotFoundError(message, code=code)
        return SignerError(f"Bad request: {message}", code=code)

    def _forbidden_locked_error(self, resp: requests.Response) -> SignerError:
        """Classify a 403 at endpoints that report a locked signer.

        Only the locked wire code maps to the locked error; any other code,
        including an empty one, is a generic SignerError.
        """
        code, message = self._error_parts(resp, "Forbidden")
        if code == ERR_CODE_LOCKED:
            return SignerUnavailableError("Signer is locked", code=code)
        return SignerError(message, code=code)

    def _forbidden_rejected_error(self, resp: requests.Response, fallback: str) -> SignerError:
        """Classify a 403 at endpoints that report a rejected request.

        A locked code maps to the locked error and a forbidden code to the
        rejection error; any other code, including an empty one, is a
        generic SignerError.
        """
        code, message = self._error_parts(resp, fallback)
        if code == ERR_CODE_LOCKED:
            return SignerUnavailableError("Signer is locked", code=code)
        if code == ERR_CODE_FORBIDDEN:
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
            raise AuthenticationError("Not authenticated: connect through an enrolled SSH key")

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

    def request_components(self, request: Any) -> ComponentResponse:
        request_body = _compact_payload(request)
        if not isinstance(request_body, dict):
            raise ValueError("component request must be a mapping or dataclass")
        if not request_body.get("request_id"):
            request_body["request_id"] = _new_sign_request_id()
        try:
            _validate_component_request(request_body)
        except ValueError as e:
            raise ValueError(f"invalid component request: {e}") from e
        kind = request_body["targets"][0]["kind"]
        timeout = self._timeout_for(COMPONENT_SIGN_TIMEOUT)
        if kind != COMPONENT_TARGET_KIND_COSIGNER:
            self._discover_approval_wait()
            timeout = max(timeout, self._sign_request_timeout())
        try:
            resp = self.session.post(
                f"{self.base_url}/sign/component",
                json=request_body,
                timeout=timeout,
            )
        except requests.RequestException as e:
            if kind != COMPONENT_TARGET_KIND_COSIGNER:
                self._best_effort_cancel_sign_request(request_body["request_id"])
            raise SignerUnavailableError(f"Failed to connect: {e}")
        if resp.status_code == 401:
            raise AuthenticationError("Not authenticated: connect through an enrolled SSH key")
        if resp.status_code == 403:
            raise self._forbidden_rejected_error(resp, "Component signing request rejected")
        if resp.status_code == 503:
            raise SignerUnavailableError(self._error_message(resp, "Signer unavailable"))
        if resp.status_code == 400:
            raise self._bad_request_error(resp)
        if resp.status_code != 200:
            raise self._signer_http_error(resp, f"Component signing failed: HTTP {resp.status_code}")
        data = self._safe_json(resp)
        if data.get("error"):
            raise SignerError(data["error"])
        try:
            _validate_component_response(data, request_body)
        except ValueError as e:
            raise SignerError(f"invalid component response: {e}") from e
        if data["request_id"] != request_body["request_id"]:
            raise SignerError("component response request_id does not match request")
        expected = {
            target["target_index"]: target["kind"]
            for target in request_body["targets"]
        }
        actual = {
            component["target_index"]: component["kind"]
            for component in data["components"]
        }
        if actual != expected:
            raise SignerError("component response target indices or kinds do not match request")
        return ComponentResponse(request_id=data["request_id"], components=list(data["components"]))

    def request_assemble(
        self,
        request: Any,
    ) -> AssemblyResponse:
        """
        Send a discriminated transaction assembly request to /sign/assemble.
        """
        request_body = _compact_payload(request)
        if not isinstance(request_body, dict):
            raise ValueError("assembly request must be a mapping or dataclass")
        if request_body.get("passthrough"):
            request_body["passthrough"] = [
                {
                    "target_index": item["target_index"],
                    "signed_txn_hex": item["signed_txn_hex"],
                }
                for item in request_body["passthrough"]
            ]
        if not request_body.get("request_id"):
            request_body["request_id"] = _new_sign_request_id()
        try:
            _validate_assembly_request(request_body)
        except ValueError as e:
            raise ValueError(f"invalid assembly request: {e}") from e

        try:
            resp = self.session.post(
                f"{self.base_url}/sign/assemble",
                json=request_body,
                timeout=self._timeout_for(COSIGNED_ASSEMBLY_TIMEOUT),
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Not authenticated: connect through an enrolled SSH key")

        if resp.status_code == 403:
            raise self._forbidden_rejected_error(resp, "Assembly request rejected")

        if resp.status_code == 503:
            raise SignerUnavailableError(self._error_message(resp, "Signer unavailable"))

        if resp.status_code != 200:
            raise self._signer_http_error(
                resp,
                f"Assembly failed: HTTP {resp.status_code}",
            )

        data = self._safe_json(resp)
        if data.get("error"):
            raise SignerError(data["error"])
        try:
            _validate_assembly_response(data)
        except ValueError as e:
            raise SignerError(f"invalid assembly response: {e}") from e
        if data["request_id"] != request_body["request_id"]:
            raise SignerError("assembly response request_id does not match request")

        return AssemblyResponse(
            request_id=data["request_id"],
            signed_group=data.get("signed_group", []),
        )

    def _best_effort_cancel_sign_request(self, request_id: str) -> None:
        try:
            self.cancel_sign_request(request_id)
        except Exception:
            pass

    def _build_sign_requests(
        self,
        txns: List[Optional[transaction.Transaction]],
        auth_addresses: List[Optional[str]],
        lsig_args_map: Optional[Dict[str, Dict[str, bytes]]] = None,
        passthrough: Optional[Dict[int, str]] = None,
        lsig_resources: Optional[Dict[int, LogicSigResourceUsage]] = None,
        allow_foreign: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Build the request entries for /sign and /plan.

        It refuses early what the signer could not use (an auth address that
        is not an address, a passthrough that is not a canonical signed
        transaction) and matches the LogicSig args against the positions. What
        it decodes to do that goes no further: the slots a response is checked
        against are decoded from the entries actually sent.

        Args:
            txns: List of transactions
            auth_addresses: Auth address for each transaction
            lsig_args_map: Optional mapping of address -> lsig_args
            passthrough: Optional mapping of group index -> base64-encoded
                pre-signed transaction
            lsig_resources: Optional mapping of group index -> independent
                LogicSig program-byte, argument-byte, and opcode-cost demand
                for foreign or passthrough transactions.

        Returns:
            The request entries, ready to send

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

        # Validate lsig_resources indices and values
        if lsig_resources:
            for idx, resources in lsig_resources.items():
                if idx < 0 or idx >= len(txns):
                    raise ValueError(
                        f"lsig_resources index {idx} out of range for {len(txns)} transactions"
                    )
                if not isinstance(resources, LogicSigResourceUsage) or not (
                    0 < resources.program_bytes <= 16_000
                    and resources.argument_bytes >= 0
                    and 0 < resources.max_opcode_cost <= 320_000
                ):
                    raise ValueError(
                        f"lsig_resources[{idx}] is invalid"
                    )

        # Build request array
        sign_requests: List[Dict[str, Any]] = []
        matched_lsig_args: set = set()
        for i, (txn, auth_addr) in enumerate(zip(txns, auth_addresses)):
            # Passthrough: include pre-signed transaction as-is
            if passthrough and i in passthrough:
                try:
                    signed_bytes = base64.b64decode(passthrough[i], validate=True)
                except Exception as e:
                    raise ValueError(f"invalid base64 in passthrough[{i}]: {e}") from e
                try:
                    slot = _decode_passthrough_slot(signed_bytes)
                except SignerError as e:
                    raise ValueError(f"invalid passthrough[{i}]: {e}") from e
                # A passthrough position's authorizer is whoever signed it:
                # the signer its bytes name, or the sender when they name
                # none. An auth address given for the position counts too.
                # The sender of a rekeyed account is not its authorizer.
                if auth_addr:
                    matched_lsig_args.add(auth_addr)
                matched_lsig_args.add(slot.signer or slot.txn.sender)
                request = {"signed_txn_hex": signed_bytes.hex()}
                if lsig_resources and i in lsig_resources:
                    request["lsig_resources"] = _wire_lsig_resources(
                        lsig_resources[i]
                    )
                sign_requests.append(request)
                continue

            # A sign or foreign position matches its auth address, or its
            # sender when none is given.
            if auth_addr:
                matched_lsig_args.add(auth_addr)
            elif txn is not None:
                matched_lsig_args.add(txn.sender)

            if auth_addr and lsig_resources and i in lsig_resources:
                raise ValueError(
                    f"lsig_resources[{i}] is allowed only for foreign or passthrough transactions"
                )

            # Foreign mode: txn_bytes_hex without auth_address
            if not auth_addr:
                if not allow_foreign:
                    raise SignerError(
                        "foreign entries are only supported on /plan; use "
                        f"plan_group() first, then resubmit slot {i} as passthrough"
                    )
                if txn is None:
                    raise ValueError(f"transaction is required for foreign-mode entry at index {i}")
                txn_bytes_hex, _ = encode_transaction(txn)
                req: Dict[str, Any] = {"txn_bytes_hex": txn_bytes_hex}
                if lsig_resources and i in lsig_resources:
                    req["lsig_resources"] = _wire_lsig_resources(lsig_resources[i])
                sign_requests.append(req)
                continue

            if txn is None:
                raise ValueError(f"transaction is required for sign-mode entry at index {i}")
            try:
                _sign_slot(txn, auth_addr)
            except ValueError as e:
                raise ValueError(f"transaction {i + 1}: {e}") from e

            txn_bytes_hex, txn_sender = encode_transaction(txn)

            req = {
                "txn_bytes_hex": txn_bytes_hex,
                "auth_address": auth_addr,
                "txn_sender": txn_sender,
            }

            # Add LogicSig args if provided
            if lsig_args_map and lsig_args_map.get(auth_addr):
                req["lsig_args"] = {
                    name: value.hex() for name, value in lsig_args_map[auth_addr].items()
                }

            sign_requests.append(req)

        # Args keyed under an address that authorizes no position are a
        # mistake, and dropping them would sign without them; an optional arg
        # left out can select a different authorization branch. A position's
        # authorizer is its auth address, never its sender when the two
        # differ. A key that is the authorizer of a passthrough or foreign
        # position is fine: the same map can serve several calls over one
        # group. An entry with no args is ignored.
        unmatched = sorted(
            repr(address)
            for address, args in (lsig_args_map or {}).items()
            if args and address not in matched_lsig_args
        )
        if unmatched:
            raise ValueError(
                "lsig args are keyed by auth address, and no transaction in the "
                f"request has auth address {', '.join(unmatched)}"
            )

        return sign_requests

    def _sign_request(
        self,
        txns: List[Optional[transaction.Transaction]],
        auth_addresses: List[Optional[str]],
        lsig_args_map: Optional[Dict[str, Dict[str, bytes]]] = None,
        passthrough: Optional[Dict[int, str]] = None,
        lsig_resources: Optional[Dict[int, LogicSigResourceUsage]] = None,
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
            lsig_resources: Optional mapping of group index -> independent
                LogicSig resource demand for foreign or passthrough transactions.
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
        entries = self._build_sign_requests(
            txns, auth_addresses, lsig_args_map, passthrough, lsig_resources, False
        )
        data = self.sign_requests(entries, request_id=request_id)

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
        if request_id is None:
            request_id = _new_sign_request_id()
        _validate_sign_request_id(request_id, required=True)
        _validate_sign_entries(sign_entries)
        # The slots the response is checked against are decoded here, from the
        # very entries that are sent.
        try:
            slots = _decode_request_slots(sign_entries)
        except SignerError as e:
            raise SignerError(f"invalid sign request: {e}") from e
        # The request is held to the ceiling in force now, whatever is set on
        # the client while the signer waits for approval.
        max_fee_increase = self.max_fee_increase
        request_body = {
            "request_id": request_id,
            "requests": sign_entries,
        }

        self._discover_approval_wait()

        try:
            resp = self.session.post(
                f"{self.base_url}/sign", json=request_body, timeout=self._sign_request_timeout()
            )
        except requests.RequestException as e:
            self._best_effort_cancel_sign_request(request_id)
            raise SignerUnavailableError(f"Failed to connect: {e}")

        # Handle errors
        # Note: Use _safe_json() to handle both JSON and plain text error responses
        if resp.status_code == 401:
            raise AuthenticationError("Not authenticated: connect through an enrolled SSH key")

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

        signed = data.get("signed") or []
        mutations = data.get("mutations")
        # Every sign path goes through here, so a truncated, altered or padded
        # group can never be returned for submission or simulation.
        try:
            _validate_sign_response(slots, signed, mutations, max_fee_increase)
        except Exception as e:
            raise _verification_error("verify signer response: ", e) from e

        return GroupSignResponse(
            signed=signed,
            mutations=mutations,
            error=data.get("error", ""),
        )

    def plan_group(
        self,
        txns: List[Optional[transaction.Transaction]],
        auth_addresses: Optional[List[Optional[str]]] = None,
        lsig_args_map: Optional[Dict[str, Dict[str, bytes]]] = None,
        passthrough: Optional[Dict[int, str]] = None,
        lsig_resources: Optional[Dict[int, LogicSigResourceUsage]] = None,
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
        - Multi-party signing coordination (use foreign entries with lsig_resources)
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
            lsig_resources: Optional mapping of group index -> independent
                LogicSig resource demand for foreign transactions
                (auth_address is None).

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

        entries = self._build_sign_requests(
            txns, auth_addresses, lsig_args_map, passthrough, lsig_resources
        )

        return self.plan_requests(entries)

    def plan_requests(self, sign_entries: List[Dict[str, Any]]) -> dict:
        """Preview raw per-slot signer requests without address-keyed rebuilding."""
        _validate_sign_entries(sign_entries)
        try:
            slots = _decode_request_slots(sign_entries)
        except SignerError as e:
            raise SignerError(f"invalid plan request: {e}") from e
        max_fee_increase = self.max_fee_increase
        request_body = {"requests": sign_entries}

        try:
            resp = self.session.post(
                f"{self.base_url}/plan",
                json=request_body,
                timeout=self._timeout_for(GROUP_PLAN_TIMEOUT),
            )
        except requests.RequestException as e:
            raise SignerUnavailableError(f"Failed to connect: {e}")

        if resp.status_code == 401:
            raise AuthenticationError("Not authenticated: connect through an enrolled SSH key")

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

        try:
            _validate_plan_response(
                slots, data.get("transactions"), data.get("mutations"), max_fee_increase
            )
        except Exception as e:
            raise _verification_error("verify signer plan: ", e) from e

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
        response = self.sign_requests(prepared_group.to_sign_requests(), request_id=request_id)
        foreign_count = int((response.mutations or {}).get("foreign_count", 0))
        if foreign_count:
            raise SignerError(
                "signed simulation requires a complete group; signer returned "
                f"{foreign_count} foreign transaction(s)"
            )
        return _simulate_signed_group(algod_client, response.signed, response.mutations)

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
        if not auth_address:
            auth_address = txn.sender

        lsig_args_map = {auth_address: lsig_args} if lsig_args else None

        signed_list = self._sign_request(
            [txn], [auth_address], lsig_args_map, request_id=request_id
        )

        # Concatenate all signed txns and return as single base64 string
        all_bytes = b"".join(base64.b64decode(s) for s in signed_list)
        return base64.b64encode(all_bytes).decode()

    def sign_transactions(
        self,
        txns: List[Optional[transaction.Transaction]],
        auth_addresses: Optional[List[Optional[str]]] = None,
        lsig_args_map: Optional[Dict[str, Dict[str, bytes]]] = None,
        passthrough: Optional[Dict[int, str]] = None,
        lsig_resources: Optional[Dict[int, LogicSigResourceUsage]] = None,
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
            lsig_resources: Optional mapping of group index -> independent
                LogicSig resource demand for foreign or passthrough transactions.
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
            txns, auth_addresses, lsig_args_map, passthrough, lsig_resources, request_id=request_id
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
        lsig_resources: Optional[Dict[int, LogicSigResourceUsage]] = None,
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
            lsig_resources: Optional mapping of group index -> independent
                LogicSig resource demand for planning foreign transactions.
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
            txns, auth_addresses, lsig_args_map, passthrough, lsig_resources, request_id=request_id
        )


def _component_signatures_by_index(
    response: ComponentResponse,
    schemes: Dict[int, str],
) -> Dict[int, Dict[str, str]]:
    """The cosigner signatures by target index. request_components has checked
    the response covers exactly the requested targets as cosigner components;
    each signature must also be in the scheme the account names for its
    cosigner."""
    signatures = {}
    for item in response.components:
        index = item["target_index"]
        want = schemes.get(index, "")
        if want and item.get("signature_scheme") != want:
            raise SignerError(
                f"cosigner signature for target {index} used scheme "
                f"{item.get('signature_scheme')!r}, want {want!r}"
            )
        signatures[index] = {"signature": item["signature"], "request_id": response.request_id}
    return signatures


def _component_request_for_indices(
    group_bytes_hex: List[str],
    indices: List[int],
    component_key: str,
    dummy_positions: Optional[List[int]] = None,
    app_call_info: Optional[Dict[int, Optional[Dict[str, str]]]] = None,
) -> ComponentRequest:
    dummy_positions = list(dummy_positions or [])
    app_call_info = dict(app_call_info or {})
    target_set = set(indices)
    targets = []
    for index in indices:
        target: Dict[str, Any] = {
            "target_index": index,
            "kind": COMPONENT_TARGET_KIND_COSIGNER,
            "component_key": component_key,
        }
        if app_call_info.get(index):
            target["app_call_info"] = app_call_info[index]
        targets.append(target)
    return ComponentRequest(
        group_bytes_hex=list(group_bytes_hex),
        targets=targets,
        contextual_positions=[
            {"target_index": index, "app_call_info": app_call_info.get(index)}
            for index in range(len(group_bytes_hex) - len(dummy_positions))
            if index not in target_set
        ] or None,
        dummy_positions=[{"target_index": index} for index in dummy_positions] or None,
    )


def _sign_cosigned_dummies(
    first_original: transaction.Transaction,
    group_id: Optional[bytes],
    dummies: List[transaction.Transaction],
    start_index: int,
) -> List[CosignedPassthroughItem]:
    """Sign the resource dummies a plan appended, after checking each is canonical."""
    _validate_canonical_dummies(first_original, group_id, dummies)
    passthrough = []
    for offset, txn in enumerate(dummies):
        signed_hex = _sign_canonical_dummy(txn).hex()
        passthrough.append(
            CosignedPassthroughItem(
                target_index=start_index + offset,
                signed_txn_hex=signed_hex,
                authorization=CosignedPassthroughAuthorization(
                    logic_sig_resources=_cosigned_dummy_lsig_resources()
                ),
            )
        )
    return passthrough


def _encode_cosigned_lsig_args(args: Optional[Dict[str, bytes]]) -> Optional[Dict[str, str]]:
    if not args:
        return None
    return {name: value.hex() for name, value in args.items()}


def _resolve_cosigner_for_target(
    target: Dict[str, Any],
    cosigner_client: Optional[SignerClient],
    cosigner_component_key: str,
    cosigner_resolver: Optional[Any],
) -> tuple:
    if cosigner_resolver is not None:
        resolved = cosigner_resolver(target)
        if isinstance(resolved, dict):
            client = resolved.get("client")
            component_key = resolved.get("component_key", "")
        else:
            client, component_key = resolved
        if client is None:
            raise SignerError("cosigner resolver returned no client")
        return client, component_key or ""
    if cosigner_client is None:
        raise SignerError("cosigner_client or cosigner_resolver is required")
    return cosigner_client, cosigner_component_key


def _decode_canonical_group(group_bytes_hex: List[str]) -> List[transaction.Transaction]:
    if not group_bytes_hex:
        raise SignerError("canonical group is empty")
    if len(group_bytes_hex) > constants.tx_group_limit:
        raise SignerError(
            f"canonical group size {len(group_bytes_hex)} exceeds max "
            f"{constants.tx_group_limit}"
        )
    result = []
    for index, encoded in enumerate(group_bytes_hex):
        try:
            raw = _strict_hex(encoded)
        except ValueError as e:
            raise SignerError(f"transaction {index} is invalid hex: {e}") from e
        try:
            result.append(_decode_canonical_txn(raw))
        except SignerError as e:
            raise SignerError(f"transaction {index}: {e}") from e

    if len(result) == 1:
        if _group_id_bytes(result[0]) is not None:
            raise SignerError("singleton transaction must not have a group ID")
        return result
    _validate_canonical_group_id(result)
    return result


def _bounded_fee_ceiling(info: BoundedAuthorizationInfo) -> Optional[int]:
    """Return an account's on-chain fee ceiling, or None for a plain host.

    A bounded host must advertise one; a plain host never has one; a contract
    this SDK does not know fails closed.
    """
    if info.contract == BOUNDED_CONTRACT_BOUNDED2:
        if info.max_fee is None:
            raise SignerError(f"bounded authorization {info.contract} has no max_fee")
        return info.max_fee
    if info.contract == BOUNDED_CONTRACT_PLAIN1:
        if info.max_fee is not None:
            raise SignerError(
                f"bounded authorization {info.contract} has a max_fee, which a plain host never has"
            )
        return None
    raise SignerError(
        f"bounded authorization contract {info.contract!r} is not supported by this SDK; upgrade it"
    )


def _validate_bounded_target_fees(
    planned: List[transaction.Transaction],
    max_fees: Dict[int, int],
) -> None:
    for index, max_fee in max_fees.items():
        if index < 0 or index >= len(planned):
            raise SignerError(f"bounded target index {index} is outside planned group")
        if isinstance(max_fee, bool) or not isinstance(max_fee, int) or max_fee < 0:
            raise SignerError(f"bounded target {index} has invalid advertised max_fee")
        fee = planned[index].fee
        if fee > max_fee:
            raise SignerError(
                f"bounded target {index} fee {fee} exceeds advertised " f"max_fee {max_fee}"
            )


def _verify_bounded_assembled_group(group_bytes_hex: List[str], signed_group: List[str]) -> None:
    if len(signed_group) != len(group_bytes_hex):
        raise SignerError(
            f"assembled group has {len(signed_group)} transaction(s), "
            f"want {len(group_bytes_hex)}"
        )
    for index, (signed_hex, canonical_hex) in enumerate(zip(signed_group, group_bytes_hex)):
        _verify_signed_transaction_matches_canonical(
            "assembled transaction", index, signed_hex, canonical_hex
        )


def _verify_signed_transaction_matches_canonical(
    label: str,
    index: int,
    signed_hex: str,
    canonical_hex: str,
) -> None:
    """Require a signed slot to sign exactly the canonical bytes at its position.

    The signed bytes must themselves be canonical, with nothing after the
    signed transaction.
    """
    try:
        signed_bytes = _strict_hex(signed_hex)
    except ValueError as e:
        raise SignerError(f"{label} {index}: invalid hex: {e}") from e
    try:
        decoded = _decode_canonical_signed_txn(signed_bytes)
    except SignerError as e:
        raise SignerError(f"{label} {index}: {e}") from e
    encoded, _ = encode_transaction(decoded.transaction)
    if encoded != canonical_hex.lower():
        raise SignerError(f"{label} {index} does not match the submitted canonical bytes")


def _bounded_cosigner_public_key(key: KeyInfo) -> str:
    if key.bounded_authorization and key.bounded_authorization.cosigner:
        if key.bounded_authorization.cosigner.public_key_hex:
            return key.bounded_authorization.cosigner.public_key_hex
    return (key.parameters or {}).get("cosigner_public_key", "")


def _bounded_cosigner_component_key_type(key: KeyInfo) -> str:
    if key.cosigner_component_key_type:
        return key.cosigner_component_key_type
    if key.bounded_authorization and key.bounded_authorization.cosigner:
        return key.bounded_authorization.cosigner.component_key_type
    return ""


def _request_bounded_primary_passthrough(
    user_client: SignerClient,
    group_bytes_hex: List[str],
    original_count: int,
    bounded_indices: set,
    target_resources: Dict[int, Optional[LogicSigResourceUsage]],
    primary_targets: List[Dict[str, Any]],
) -> tuple:
    if not primary_targets:
        return None, []
    primary_by_index = {target["target_index"]: target for target in primary_targets}
    requests_data = []
    for index, txn_hex in enumerate(group_bytes_hex):
        if index >= original_count:
            requests_data.append(
                {
                    "txn_bytes_hex": txn_hex,
                    "lsig_resources": _wire_lsig_resources(
                        _cosigned_dummy_lsig_resources()
                    ),
                }
            )
        elif index in bounded_indices:
            resources = _require_lsig_resources(
                target_resources.get(index),
                f"bounded target {index}",
            )
            requests_data.append(
                {
                    "txn_bytes_hex": txn_hex,
                    "lsig_resources": _wire_lsig_resources(resources),
                }
            )
        else:
            target = primary_by_index.get(index)
            if target is None:
                raise ValueError(f"group position {index} has no bounded or primary target")
            request = {
                "txn_bytes_hex": txn_hex,
                "auth_address": target["auth_address"],
            }
            for field in ("txn_sender", "lsig_args", "app_call_info"):
                if target.get(field):
                    request[field] = target[field]
            requests_data.append(request)
    response = user_client.sign_requests(requests_data)
    passthrough = []
    for index in sorted(primary_by_index):
        if index >= len(response.signed) or not response.signed[index]:
            raise SignerError(f"primary signer returned no signed transaction for target {index}")
        _verify_signed_transaction_matches_canonical(
            "primary passthrough",
            index,
            response.signed[index],
            group_bytes_hex[index],
        )
        passthrough.append(
            CosignedPassthroughItem(
                target_index=index,
                signed_txn_hex=response.signed[index],
            )
        )
    return response, passthrough


def sign_prepared_cosigned_group(
    *,
    user_client: SignerClient,
    prepared_group: PreparedGroup,
    cosigner_client: Optional[SignerClient] = None,
    cosigner_resolver: Optional[Any] = None,
    cosigner_component_key: str = "",
    assembly_request_id: str = "",
) -> CosignedSignResult:
    """
    Canonicalize a prepared group locally, classify cosigned and primary slots,
    then sign and assemble it through cosigned component endpoints (cosigned1).

    The signer /plan endpoint owns canonical group sizing, dummy insertion,
    and authorization-fee pooling before component signatures are collected.
    The cosigner is asked only for targets whose base component needs it: a
    listed rekey takes none, and assembles without a cosigner signature.
    """
    if user_client is None:
        raise SignerError("user_client is required")
    prepared = prepared_group.transactions
    if not prepared:
        raise ValueError("prepared group is empty")

    requests_data: List[Dict[str, Any]] = []
    targets: List[Dict[str, Any]] = []
    primary_targets: List[Dict[str, Any]] = []
    target_resources: Dict[int, Optional[LogicSigResourceUsage]] = {}
    target_keys: Dict[int, KeyInfo] = {}
    target_max_fees: Dict[int, int] = {}
    for index, item in enumerate(prepared):
        if item.signed_transaction_base64:
            raise ValueError(
                f"prepared transaction {index}: passthrough entries are not "
                "supported in prepared bounded-cosigner groups"
            )
        if item.transaction is None:
            raise ValueError(f"prepared transaction {index}: transaction is required")
        key = item.signer_key
        if key is not None and key.address != item.auth_address:
            # The key's flow, resources and fee ceiling decide how the
            # position is signed, so it must be the key that signs it.
            raise ValueError(
                f"prepared transaction {index}: signer key is for {key.address}, "
                f"not the position's auth address {item.auth_address}"
            )
        if key is None and item.auth_address:
            key = user_client.get_key_info(item.auth_address)
        if key is None:
            raise ValueError(f"prepared transaction {index}: signer key metadata is required")
        if key.signing_flow == SIGNING_FLOW_COSIGNED1:
            if not item.auth_address:
                raise ValueError(f"prepared transaction {index}: bounded auth address is required")
            resources = _require_lsig_resources(
                _selected_prepared_resources(key, item.transaction),
                f"prepared transaction {index}: bounded",
            )
            requests_data.append(_prepared_sign_request(item, index))
            target_resources[index] = resources
            target_keys[index] = key
            if key.bounded_authorization is None:
                raise ValueError(
                    f"prepared transaction {index}: bounded authorization " "metadata is required"
                )
            ceiling = _bounded_fee_ceiling(key.bounded_authorization)
            if ceiling is not None:
                target_max_fees[index] = ceiling
            targets.append(
                {
                    "target_index": index,
                    "cosigned_account": item.auth_address,
                    "cosigner_public_key_hex": _bounded_cosigner_public_key(key),
                    "cosigner_component_key_type": _bounded_cosigner_component_key_type(key),
                    "logic_sig_resources": resources,
                    "app_call_info": item.app_call_info,
                }
            )
            continue
        if key.signing_flow not in ("", SIGNING_FLOW_BOUNDED1):
            raise ValueError(
                f"prepared transaction {index}: signer key requires signing flow "
                f"{key.signing_flow!r}, which this SDK does not support; upgrade the SDK"
            )
        if not item.auth_address:
            raise ValueError(f"prepared transaction {index}: primary auth address is required")
        # The signer holds this position's key, so it is sent as the signer's
        # own: in sign mode on /plan, and as a contextual position with
        # auth_address on /sign/component. The signer sizes it from its records
        # in both and can put the group's authorization charge on it. Sent as
        # foreign with a size hint, it was immutable, and the cosigned targets
        # paid its charge.
        requests_data.append(_prepared_sign_request(item, index))
        primary_targets.append(
            {
                "target_index": index,
                "auth_address": item.auth_address,
                "txn_sender": item.txn_sender,
                "lsig_args": _encode_cosigned_lsig_args(item.lsig_args),
                "app_call_info": item.app_call_info,
            }
        )
    if not targets:
        raise ValueError("prepared group has no bounded-cosigner targets")

    plan_response = user_client.plan_requests(requests_data)
    frozen_group = list(plan_response.get("transactions") or [])
    planned = _decode_canonical_group(frozen_group)
    if len(planned) < len(prepared):
        raise SignerError(
            f"signer returned {len(planned)} bounded group positions, "
            f"want at least {len(prepared)}"
        )
    # plan_requests has already checked the plan against the requests: only
    # reported fee raises and group assignment on original positions, and
    # canonical resource dummies after them.
    _validate_bounded_target_fees(planned, target_max_fees)
    target_indices = {target["target_index"] for target in targets}
    component_targets = []
    contextual_positions = []
    for index, request in enumerate(requests_data):
        if index in target_indices:
            component_targets.append(
                {
                    "target_index": index,
                    "kind": COMPONENT_TARGET_KIND_BOUNDED_BASE,
                    "auth_address": request["auth_address"],
                    "lsig_args": request.get("lsig_args"),
                    "app_call_info": request.get("app_call_info"),
                }
            )
        else:
            position = {
                "target_index": index,
                "auth_address": request["auth_address"],
                "app_call_info": request.get("app_call_info"),
            }
            if request.get("lsig_args"):
                position["lsig_args"] = request["lsig_args"]
            contextual_positions.append(position)
    component_response = user_client.request_components(
        ComponentRequest(
            group_bytes_hex=frozen_group,
            targets=component_targets,
            contextual_positions=contextual_positions or None,
            dummy_positions=[
                {"target_index": index}
                for index in range(len(prepared), len(frozen_group))
            ] or None,
        )
    )
    target_by_index = {target["target_index"]: target for target in targets}
    components: Dict[int, Dict[str, Any]] = {}
    for component in component_response.components:
        target = target_by_index.get(component["target_index"])
        if (target is None or component.get("kind") != COMPONENT_TARGET_KIND_BOUNDED_BASE
                or component.get("auth_address") != target["cosigned_account"]):
            raise SignerError(
                f"signer returned unexpected bounded component target " f"{component['target_index']}"
            )
        if component["target_index"] in components:
            raise SignerError(
                f"signer returned duplicate bounded component target " f"{component['target_index']}"
            )
        components[component["target_index"]] = component
    for target in targets:
        if target["target_index"] not in components:
            raise SignerError(
                f"signer returned no bounded component for target index "
                f"{target['target_index']}"
            )
        # Budget the position on the path the signer named, which only the
        # signer can choose: whether a rekey target is listed is not public.
        target_resources[target["target_index"]] = _component_path_resources(
            target_keys[target["target_index"]],
            components[target["target_index"]].get("path", ""),
            f"prepared transaction {target['target_index']}",
        )

    primary_response, passthrough = _request_bounded_primary_passthrough(
        user_client,
        frozen_group,
        len(prepared),
        set(target_by_index),
        target_resources,
        primary_targets,
    )
    # The user side is complete, including ordinary primary positions. Only
    # now may the SDK disclose the frozen group to the cosigner endpoint, and
    # only for the targets that need it: a listed rekey takes no cosigner.
    cosigner_groups: Dict[tuple, Dict[str, Any]] = {}
    for target in targets:
        if not component_needs_cosigner(components[target["target_index"]]):
            continue
        client, component_key = _resolve_cosigner_for_target(
            target, cosigner_client, cosigner_component_key, cosigner_resolver
        )
        group_key = (id(client), component_key)
        cosigner_groups.setdefault(
            group_key,
            {
                "client": client,
                "component_key": component_key,
                "indices": [],
            },
        )["indices"].append(target["target_index"])
    cosigner_component_responses = []
    cosigner_signatures: Dict[int, Dict[str, str]] = {}
    for group in cosigner_groups.values():
        response = group["client"].request_components(
            _component_request_for_indices(
                frozen_group,
                sorted(group["indices"]),
                group["component_key"],
                list(range(len(prepared), len(frozen_group))),
                {
                    index: request.get("app_call_info")
                    for index, request in enumerate(requests_data)
                },
            )
        )
        cosigner_component_responses.append(response)
        cosigner_signatures.update(_component_signatures_by_index(
            response,
            {target["target_index"]: target.get("cosigner_component_key_type") or "" for target in targets},
        ))

    passthrough.extend(
        _sign_cosigned_dummies(
            cast(transaction.Transaction, prepared[0].transaction),
            _group_id_bytes(planned[0]),
            planned[len(prepared) :],
            len(prepared),
        )
    )
    assembly_targets: List[AssemblyTarget] = []
    for target in targets:
        index = target["target_index"]
        component = components[index]
        cosigner = {"signature": "", "request_id": ""}
        if component_needs_cosigner(component):
            found = cosigner_signatures.get(index)
            if found is None:
                raise SignerError(f"missing cosigner component signature for target {index}")
            cosigner = found
        assembly_targets.append(
            AssemblyTarget(
                target_index=index,
                kind=ASSEMBLY_TARGET_KIND_BOUNDED_COSIGNER,
                auth_address=component["auth_address"],
                base_signatures=list(component.get("base_signatures") or []),
                bounded_runtime_args=dict(component.get("runtime_args") or {}) or None,
                assembly_receipt=component["assembly_receipt"],
                base_source_request_id=component_response.request_id,
                cosigner_signature=cosigner["signature"],
                cosigner_source_request_id=cosigner["request_id"],
            )
        )
    assembly_response = user_client.request_assemble(
        AssemblyRequest(
            request_id=assembly_request_id,
            group_bytes_hex=list(frozen_group),
            targets=assembly_targets,
            passthrough=passthrough,
        )
    )
    _verify_bounded_assembled_group(frozen_group, assembly_response.signed_group)
    return CosignedSignResult(
        signed_group=list(assembly_response.signed_group),
        cosigner_component_responses=cosigner_component_responses,
        primary_sign_response=primary_response,
        bounded_component_response=component_response,
        bounded_assembly_response=assembly_response,
        plan_mutations=plan_response.get("mutations"),
    )


def simulate_prepared_cosigned_group(
    algod_client: Any,
    **sign_options: Any,
) -> CosignedSimulationResult:
    """Prepare and sign a cosigned group, then simulate through client algod."""
    if algod_client is None:
        raise ValueError("algod_client is required")
    signing = sign_prepared_cosigned_group(**sign_options)
    return CosignedSimulationResult(
        signing=signing,
        simulation=_simulate_signed_group(algod_client, signing.signed_group),
    )


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
    txid_match = re.search(r"transaction ([A-Z0-9]{52}):", msg)
    if txid_match:
        txid = txid_match.group(1)

    # LogicSig rejection
    if "rejected by logic" in msg.lower():
        return LogicSigRejectedError(txid, "LogicSig program returned false")

    # Insufficient funds / overspend
    if "overspend" in msg.lower() or "insufficient funds" in msg.lower():
        # Try to extract balance info if present
        balance_match = re.search(r"tried to spend \{(\d+)\}", msg)
        if balance_match:
            return InsufficientFundsError(
                txid, f"insufficient funds (tried to spend {balance_match.group(1)} microAlgos)"
            )
        return InsufficientFundsError(txid, "insufficient funds")

    # LogicSig pool budget exceeded
    if "logicsigs" in msg.lower() and "pool" in msg.lower():
        pool_match = re.search(r"had (\d+) bytes.*pool of (\d+) bytes", msg)
        if pool_match:
            return InvalidTransactionError(
                txid,
                f"LogicSig too large ({pool_match.group(1)} bytes exceeds {pool_match.group(2)} byte pool). "
                "Fee pooling should be automatic - ensure you're using sign_transaction() or sign_transactions().",
            )
        return InvalidTransactionError(
            txid,
            "LogicSig exceeds pool budget - fee pooling should be automatic via sign_transaction()",
        )

    # Invalid group ID
    if "group" in msg.lower() and ("invalid" in msg.lower() or "mismatch" in msg.lower()):
        return InvalidTransactionError(txid, "invalid or mismatched group ID")

    # Fee too low
    if "fee" in msg.lower() and ("too small" in msg.lower() or "below" in msg.lower()):
        return InvalidTransactionError(txid, "transaction fee too low")

    # Round range errors
    if "round" in msg.lower() and (
        "past" in msg.lower() or "future" in msg.lower() or "invalid" in msg.lower()
    ):
        return InvalidTransactionError(
            txid, "transaction round range invalid (expired or too far in future)"
        )

    # Generic rejection - extract a cleaner message if possible
    # Look for the last meaningful phrase after struct dumps
    reason_match = re.search(r"\}: (.+?)(?:\s*$|\s*\{)", msg)
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


def _ssh_fingerprint_sha256(pkey: Any) -> str:
    """SHA256 fingerprint of an SSH public key, as OpenSSH prints it."""
    digest = base64.b64encode(hashlib.sha256(pkey.asbytes()).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def _validate_enrollment_label(label: str) -> None:
    """Enforce the signer's label rules locally so a bad label fails before
    any network activity: printable, single line, at most 64 bytes, no
    leading or trailing whitespace."""
    if not isinstance(label, str):
        raise TypeError("label must be a str")
    if label == "":
        return
    if len(label.encode("utf-8")) > MAX_ENROLLMENT_LABEL_BYTES:
        raise SignerError(f"enrollment label must be at most {MAX_ENROLLMENT_LABEL_BYTES} bytes")
    if label.strip() != label:
        raise SignerError("enrollment label must not start or end with whitespace")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in label):
        raise SignerError("enrollment label must be printable and single-line")


def request_enrollment(
    host: str,
    ssh_key_path: str,
    ssh_port: int = DEFAULT_SSH_PORT,
    *,
    known_hosts_path: str,
    label: str = "",
    auto_add_host: bool = False,
    setup_timeout: float = DEFAULT_SSH_SETUP_TIMEOUT,
) -> EnrollmentResult:
    """
    Ask the signer to enroll this client's SSH key, so the key can open API
    connections.

    This opens an enroll SSH session, which answers at once: the
    request is queued for the operator to approve later in apadmin
    (``pending=True``, the normal outcome), or the key is already enrolled.
    Nothing waits for the operator and nothing is stored on the client: the
    key is its credential, and the client learns the outcome by connecting
    after approval (an unenrolled key still fails the handshake). The key's
    fingerprint is shown to the operator for verification.

    Args:
        host: Signer host (e.g., "signer.example.com" or "localhost")
        ssh_key_path: Path to the APlane client SSH private key
        ssh_port: SSH port on remote (default: 1127)
        known_hosts_path: Path to the APlane client known_hosts file (required)
        label: Optional display label shown to the operator (printable,
            single line, at most 64 bytes)
        auto_add_host: If True, automatically trust unknown hosts (TOFU).
                       If False (default), prompt user for confirmation.
        setup_timeout: Maximum seconds for TCP connection and SSH authentication.

    Returns:
        EnrollmentResult with the key's SHA256 fingerprint and whether
        approval is pending

    Raises:
        SignerError: If the key cannot be loaded or the label is invalid
        EnrollmentError: If the signer refuses the request (queue full, etc.)

    Example:
        result = request_enrollment(
            host="signer.example.com",
            ssh_key_path="~/aplane/apclient/.ssh/id_ed25519",
            known_hosts_path="~/aplane/apclient/.ssh/known_hosts",
            label="ci-runner",
        )
    """
    if not isinstance(auto_add_host, bool):
        raise TypeError("auto_add_host must be a bool")
    if not known_hosts_path:
        raise SignerError("known_hosts_path is required for SSH host key verification")
    _validate_enrollment_label(label)

    ssh_key_path = os.path.expanduser(ssh_key_path)
    if not os.path.exists(ssh_key_path):
        raise SignerError(f"SSH key not found: {ssh_key_path}")

    pkey = _load_client_ssh_key(ssh_key_path)
    client_fingerprint = _ssh_fingerprint_sha256(pkey)

    # Set up host key policy
    known_hosts_path = os.path.expanduser(known_hosts_path)

    client = paramiko.SSHClient()

    # Load known hosts if file exists
    if os.path.exists(known_hosts_path):
        client.load_host_keys(known_hosts_path)

    if (
        not isinstance(setup_timeout, (int, float))
        or not math.isfinite(setup_timeout)
        or setup_timeout <= 0
    ):
        raise TypeError("setup_timeout must be a positive number")

    setup_timeout = float(setup_timeout)
    deadline = time.monotonic() + setup_timeout
    sock: Optional[socket.socket] = None
    timeout_timer: Optional[threading.Timer] = None
    setup_timed_out = threading.Event()
    setup_lock = threading.Lock()
    setup_complete = False

    def remaining_setup_time() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("SSH setup deadline exceeded")
        return remaining

    def expire_setup() -> None:
        with setup_lock:
            if setup_complete:
                return
            setup_timed_out.set()
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()

    # Operator think time at the first-use host-key prompt is not setup time:
    # stop the clock while the prompt waits and resume with what was left.
    def pause_setup_deadline() -> float:
        with setup_lock:
            if timeout_timer is not None:
                timeout_timer.cancel()
            return deadline - time.monotonic()

    def resume_setup_deadline(remaining: float) -> None:
        nonlocal deadline, timeout_timer
        with setup_lock:
            if setup_complete or setup_timed_out.is_set():
                return
            remaining = max(remaining, 0.0)
            deadline = time.monotonic() + remaining
            timeout_timer = threading.Timer(remaining, expire_setup)
            timeout_timer.daemon = True
            timeout_timer.start()

    if auto_add_host:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(
            _InteractiveHostKeyPolicy(
                known_hosts_path,
                pause_deadline=pause_setup_deadline,
                resume_deadline=resume_setup_deadline,
            )
        )

    try:
        sock = socket.create_connection((host, ssh_port), timeout=remaining_setup_time())
        sock.settimeout(remaining_setup_time())
        timeout_timer = threading.Timer(remaining_setup_time(), expire_setup)
        timeout_timer.daemon = True
        timeout_timer.start()
        client.connect(
            hostname=host,
            port=ssh_port,
            username=SSH_ENROLLMENT_USERNAME,
            pkey=pkey,
            look_for_keys=False,
            allow_agent=False,
            sock=sock,
            timeout=remaining_setup_time(),
            banner_timeout=remaining_setup_time(),
            auth_timeout=remaining_setup_time(),
        )
        with setup_lock:
            if setup_timed_out.is_set() or time.monotonic() >= deadline:
                raise TimeoutError("SSH setup deadline exceeded")
            setup_complete = True
        timeout_timer.cancel()
    except paramiko.ssh_exception.AuthenticationException as e:
        client.close()
        if setup_timed_out.is_set() or time.monotonic() >= deadline:
            raise EnrollmentError(
                f"SSH setup timed out after {setup_timeout:g} seconds"
            ) from e
        # The enrollment username accepts any key of a supported type, so a
        # refusal here is a key-type problem, not enrollment.
        raise EnrollmentError(
            f"SSH authentication failed: {e} "
            f"(the signer accepts {CLIENT_SSH_KEY_REQUIREMENT} client keys)"
        )
    except paramiko.ssh_exception.SSHException as e:
        client.close()
        if setup_timed_out.is_set() or time.monotonic() >= deadline:
            raise EnrollmentError(
                f"SSH setup timed out after {setup_timeout:g} seconds"
            ) from e
        raise EnrollmentError(f"SSH connection failed: {e}")
    except Exception as e:
        client.close()
        if (
            setup_timed_out.is_set()
            or isinstance(e, (TimeoutError, socket.timeout))
            or time.monotonic() >= deadline
        ):
            raise EnrollmentError(
                f"SSH setup timed out after {setup_timeout:g} seconds"
            ) from e
        raise EnrollmentError(f"Connection failed: {e}")
    finally:
        if timeout_timer is not None:
            timeout_timer.cancel()

    command = f"{SSH_ENROLLMENT_COMMAND} {label}" if label else SSH_ENROLLMENT_COMMAND
    try:
        # Run the enrollment command; the signer answers at once.
        stdin, stdout, stderr = client.exec_command(command, timeout=300)

        # Wait for command to complete
        exit_status = stdout.channel.recv_exit_status()

        if exit_status != 0:
            error_msg = stderr.read().decode().strip()
            if not error_msg:
                error_msg = stdout.read().decode().strip()
            if error_msg.startswith("ERROR: "):
                error_msg = error_msg[len("ERROR: "):]
            raise EnrollmentError(error_msg or "Enrollment rejected")

        return _parse_enrollment_reply(stdout.read().decode().strip(), client_fingerprint)

    finally:
        client.close()


def _parse_enrollment_reply(reply: str, client_fingerprint: str) -> EnrollmentResult:
    """Parse the signer's answer: ``pending <fingerprint>`` when the request
    was queued for the operator, ``enrolled <fingerprint>`` when the key was
    already enrolled. The fingerprint must be the key this client
    authenticated with."""
    if reply.startswith("pending "):
        result = EnrollmentResult(fingerprint=reply[len("pending "):], pending=True)
    elif reply.startswith("enrolled "):
        result = EnrollmentResult(fingerprint=reply[len("enrolled "):], pending=False)
    else:
        raise EnrollmentError(f"Unexpected enrollment response: {reply!r}")
    if not result.fingerprint:
        raise EnrollmentError(f"Unexpected enrollment response: {reply!r}")
    if result.fingerprint != client_fingerprint:
        raise EnrollmentError(
            f"Signer answered for {result.fingerprint}, but this client authenticated "
            f"with {client_fingerprint}"
        )
    return result


class _InteractiveHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Host key policy that prompts user for confirmation (TOFU)."""

    def __init__(
        self,
        known_hosts_path: str,
        pause_deadline: Optional[Callable[[], float]] = None,
        resume_deadline: Optional[Callable[[float], None]] = None,
    ):
        self.known_hosts_path = known_hosts_path
        self._pause_deadline = pause_deadline
        self._resume_deadline = resume_deadline

    def missing_host_key(self, client, hostname, key):
        fingerprint = key.get_fingerprint().hex()
        fingerprint_formatted = ":".join(
            fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2)
        )
        key_type = key.get_name()

        print(f"\nUnknown host: {hostname}")
        print(f"Host key ({key_type}): {fingerprint_formatted}")
        remaining = self._pause_deadline() if self._pause_deadline is not None else None
        try:
            response = input("Do you want to trust this server? [y/N]: ").strip().lower()
        finally:
            if self._resume_deadline is not None and remaining is not None:
                self._resume_deadline(remaining)

        if response not in ("y", "yes"):
            raise EnrollmentError("Host key rejected by user")

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


def request_enrollment_from_env(
    data_dir: Optional[str] = None,
    endpoint: Optional[str] = None,
    *,
    label: str = "",
    auto_add_host: bool = False,
    setup_timeout: float = DEFAULT_SSH_SETUP_TIMEOUT,
) -> EnrollmentResult:
    """
    Ask the endpoint selected from the data directory's endpoints.yaml (the
    default signer, or ``endpoint``) to enroll the client key configured for
    it. See request_enrollment for the result; nothing is stored.

    Args:
        data_dir: Client data directory. Required unless APCLIENT_DATA env var is set.
        endpoint: Endpoint alias (default: the registry's signer endpoint)
        label: Optional display label shown to the operator
        auto_add_host: If True, automatically trust unknown hosts
        setup_timeout: Maximum seconds for TCP connection and SSH authentication

    Returns:
        EnrollmentResult with the key's SHA256 fingerprint and whether
        approval is pending

    Raises:
        SignerError: If data dir not resolvable or SSH key not found
        EnrollmentError: If the signer refuses the request

    Example:
        # Reads APCLIENT_DATA from environment
        result = request_enrollment_from_env(label="ci-runner")

        # Or with explicit parameters
        request_enrollment_from_env(data_dir="/custom/path", endpoint="cosigner.qa")

        # Once the operator has approved in apadmin:
        client = SignerClient.from_env()
    """
    if not isinstance(auto_add_host, bool):
        raise TypeError("auto_add_host must be a bool")

    data_dir = _resolve_data_dir(data_dir)

    load_config(data_dir)
    registry = load_client_endpoint_registry(data_dir)
    _, selected = resolve_client_endpoint(registry, endpoint)
    host, ssh_port = client_endpoint_ssh_host_port(selected)
    ssh_key_path = selected.identity_file
    known_hosts_path = selected.known_hosts_path

    if not os.path.exists(ssh_key_path):
        raise SignerError(
            f"SSH key not found at {ssh_key_path}\n"
            "Create one with: ssh-keygen -t ed25519 -f " + ssh_key_path
        )

    print(f"Requesting enrollment at {host} (SSH port: {ssh_port})...")

    result = request_enrollment(
        host=host,
        ssh_key_path=ssh_key_path,
        ssh_port=ssh_port,
        known_hosts_path=known_hosts_path,
        label=label,
        auto_add_host=auto_add_host,
        setup_timeout=setup_timeout,
    )

    if result.pending:
        print(f"✓ Client key {result.fingerprint} queued; have the operator approve it in apadmin")
    else:
        print(f"✓ Client key {result.fingerprint} is already enrolled at {host}")
    return result
