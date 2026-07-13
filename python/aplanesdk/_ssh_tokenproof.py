# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Client side of the APlane SSH mutual token-proof protocol."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
from typing import Any

DOMAIN = "aplane-ssh-token-proof-v1"
IDENTITY = "default"
NONCE_SIZE = 32
MAX_MESSAGE_SIZE = 1024


def _field(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def encode_transcript(
    identity: str,
    host_key_hash: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
) -> bytes:
    if (
        not identity
        or len(identity.encode()) > 128
        or len(host_key_hash) != 32
        or len(client_nonce) != NONCE_SIZE
        or len(server_nonce) != NONCE_SIZE
    ):
        raise ValueError("invalid SSH token proof transcript")
    return b"".join(
        _field(value)
        for value in (
            DOMAIN.encode(),
            identity.encode(),
            host_key_hash,
            client_nonce,
            server_nonce,
        )
    )


def compute_proof(token: str, role: str, transcript: bytes) -> bytes:
    if not token or role not in ("server", "client") or not transcript:
        raise ValueError("invalid SSH token proof input")
    message = _field(role.encode()) + _field(transcript)
    return hmac.new(token.encode(), message, hashlib.sha256).digest()


def encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_bytes(value: Any, size: int) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise ValueError("token proof value is not canonical base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("token proof value is not canonical base64url") from exc
    if len(decoded) != size or encode_bytes(decoded) != value:
        raise ValueError(f"token proof value must encode {size} bytes")
    return decoded


def parse_message(value: str, required: set[str]) -> dict[str, Any]:
    if not value or len(value.encode()) > MAX_MESSAGE_SIZE:
        raise ValueError("invalid token proof message size")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate token proof field {key!r}")
            result[key] = item
        return result

    try:
        message = json.loads(value, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("invalid token proof JSON") from exc
    if not isinstance(message, dict) or set(message) != required:
        raise ValueError("unexpected token proof fields")
    return message


class TokenProofClient:
    def __init__(self, token: str):
        self._token = token
        self._host_hash = b""
        self._client_nonce = b""
        self._round = 0
        self._verified = False

    def capture_host_key(self, key_blob: bytes) -> None:
        host_hash = hashlib.sha256(key_blob).digest()
        if self._host_hash and not hmac.compare_digest(self._host_hash, host_hash):
            raise ValueError("SSH host key changed during authentication")
        self._host_hash = host_hash

    def challenge(
        self,
        title: str,
        instructions: str,
        prompts: list[tuple[str, bool]],
    ) -> list[str]:
        if (
            title != DOMAIN
            or instructions != ""
            or len(prompts) != 1
            or prompts[0][1]
            or len(self._host_hash) != 32
        ):
            raise ValueError("unexpected SSH token proof challenge shape")

        question = prompts[0][0]
        if self._round == 0:
            message = parse_message(question, {"version", "step"})
            if (
                type(message["version"]) is not int
                or message["version"] != 1
                or message["step"] != "client_nonce"
            ):
                raise ValueError("unexpected token proof client-nonce question")
            self._client_nonce = secrets.token_bytes(NONCE_SIZE)
            self._round = 1
            return [
                json.dumps(
                    {"client_nonce": encode_bytes(self._client_nonce)}, separators=(",", ":")
                )
            ]

        if self._round == 1:
            message = parse_message(question, {"version", "step", "server_nonce", "proof"})
            if (
                type(message["version"]) is not int
                or message["version"] != 1
                or message["step"] != "server_proof"
            ):
                raise ValueError("unexpected token proof server-proof question")
            server_nonce = decode_bytes(message["server_nonce"], NONCE_SIZE)
            server_proof = decode_bytes(message["proof"], hashlib.sha256().digest_size)
            transcript = encode_transcript(
                IDENTITY, self._host_hash, self._client_nonce, server_nonce
            )
            expected = compute_proof(self._token, "server", transcript)
            if not hmac.compare_digest(expected, server_proof):
                raise ValueError("SSH server token proof is invalid")
            client_proof = compute_proof(self._token, "client", transcript)
            self._round = 2
            self._verified = True
            return [json.dumps({"client_proof": encode_bytes(client_proof)}, separators=(",", ":"))]

        raise ValueError("unexpected additional SSH token proof challenge")

    @property
    def server_verified(self) -> bool:
        return self._verified and self._round == 2

    def clear(self) -> None:
        """Release proof-only state after an authentication attempt."""
        self._token = ""
        self._host_hash = b""
        self._client_nonce = b""
        self._round = -1
        self._verified = False
