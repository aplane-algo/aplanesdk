# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""AlgoKit Utils adapter for apsigner-backed transaction signing."""

from collections.abc import Callable, Sequence
from secrets import token_hex
from threading import Lock
from typing import Any, Optional, Protocol

from .signer import CancelSignResponse, GroupSignResponse, KeyInfo, SignerError


class _GroupSignerClient(Protocol):
    def sign_requests(
        self,
        sign_entries: list[dict[str, Any]],
        *,
        request_id: Optional[str] = None,
    ) -> GroupSignResponse: ...

    def list_keys(self, refresh: bool = False) -> list[KeyInfo]: ...

    def cancel_sign_request(self, request_id: str) -> CancelSignResponse: ...


TransactionEncoder = Callable[[Any], bytes]
RequestIDFactory = Callable[[], str]


def _default_request_id() -> str:
    return f"sdk-{token_hex(16)}"


def _default_encode_transaction(txn: Any) -> bytes:
    try:
        from algokit_transact.codec.transaction import encode_transaction
    except ImportError as exc:
        raise SignerError(
            "algokit_transact is not importable; install algokit-utils >= 5.0.0b1 "
            "or pass an explicit encode_transaction"
        ) from exc
    return encode_transaction(txn)


def _txn_sender(txn: Any) -> str:
    sender = getattr(txn, "sender", None)
    if sender is None:
        raise SignerError("AlgoKit transaction is missing sender")
    return str(sender)


class ApsignerAccount:
    """
    AlgoKit AddressWithTransactionSigner adapter backed by apsigner.

    The adapter connects AlgoKit clients to APlane's transaction signing
    functions.
    """

    def __init__(
        self,
        client: _GroupSignerClient,
        address: str,
        *,
        auth_address: Optional[str] = None,
        lsig_args: Optional[dict[str, bytes]] = None,
        new_request_id: Optional[RequestIDFactory] = None,
        encode_transaction: Optional[TransactionEncoder] = None,
    ) -> None:
        self._client = client
        self._addr = address
        self.auth_address = auth_address or address
        self._lsig_args = lsig_args
        self._new_request_id = new_request_id or _default_request_id
        self._encode_transaction = encode_transaction or _default_encode_transaction
        self._current_request_id: Optional[str] = None
        self._lock = Lock()

    @property
    def addr(self) -> str:
        return self._addr

    @property
    def signer(self) -> Callable[[Sequence[Any], Sequence[int]], list[bytes]]:
        return self._sign

    def _begin_sign(self) -> str:
        request_id = self._new_request_id()
        with self._lock:
            if self._current_request_id is not None:
                raise RuntimeError("ApsignerAccount already has an in-flight signing request")
            self._current_request_id = request_id
        return request_id

    def _end_sign(self, request_id: str) -> None:
        with self._lock:
            if self._current_request_id == request_id:
                self._current_request_id = None

    def cancel(self) -> None:
        """
        Best-effort cancellation for the current synchronous AlgoKit sign call.

        AlgoKit's Python signer callback has no cancellation parameter, so
        applications that need user cancellation can call this from another
        thread while the signer is waiting for operator approval.
        """
        with self._lock:
            request_id = self._current_request_id
        if request_id is None:
            return
        try:
            self._client.cancel_sign_request(request_id)
        except (SignerError, OSError):
            # Best-effort: backend errors and transport failures are tolerated,
            # but programming errors (TypeError, AttributeError, ...) propagate.
            pass

    def _sign(self, txn_group: Sequence[Any], indexes_to_sign: Sequence[int]) -> list[bytes]:
        if not indexes_to_sign:
            return []

        request_id = self._begin_sign()
        try:
            requests: list[dict[str, Any]] = []
            for index in indexes_to_sign:
                if index < 0 or index >= len(txn_group):
                    raise SignerError(
                        f"index {index} out of range for {len(txn_group)} transactions"
                    )

                txn = txn_group[index]
                if txn is None:
                    raise SignerError(f"transaction is required at index {index}")

                req = {
                    "txn_bytes_hex": self._encode_transaction(txn).hex(),
                    "txn_sender": _txn_sender(txn),
                    "auth_address": self.auth_address,
                }
                if self._lsig_args:
                    req["lsig_args"] = {
                        name: value.hex()
                        for name, value in self._lsig_args.items()
                    }
                requests.append(req)

            result = self._client.sign_requests(requests, request_id=request_id)

            if len(result.signed) < len(indexes_to_sign):
                raise SignerError(
                    "apsigner returned fewer signed transactions than AlgoKit requested"
                )

            return [bytes.fromhex(item) for item in result.signed]
        finally:
            self._end_sign(request_id)


def create_apsigner_account(
    client: _GroupSignerClient,
    address: str,
    **kwargs: Any,
) -> ApsignerAccount:
    return ApsignerAccount(client, address, **kwargs)


def list_apsigner_accounts(
    client: _GroupSignerClient,
    *,
    refresh: bool = False,
) -> list[ApsignerAccount]:
    return [
        ApsignerAccount(client, key.address, auth_address=key.address)
        for key in client.list_keys(refresh=refresh)
    ]
