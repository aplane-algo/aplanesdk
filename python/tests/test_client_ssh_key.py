# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""Client SSH key loading matches the key types the signer accepts."""

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from aplanesdk.signer import CLIENT_SSH_KEY_REQUIREMENT, SignerError, _load_client_ssh_key


def _write_openssh_key(tmp_path, private_key, name, password=None):
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    data = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        encryption,
    )
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_loads_ed25519_key(tmp_path):
    path = _write_openssh_key(tmp_path, ed25519.Ed25519PrivateKey.generate(), "id_ed25519")
    assert isinstance(_load_client_ssh_key(path), paramiko.Ed25519Key)


@pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
def test_loads_ecdsa_key(tmp_path, curve):
    path = _write_openssh_key(tmp_path, ec.generate_private_key(curve), "id_ecdsa")
    assert isinstance(_load_client_ssh_key(path), paramiko.ECDSAKey)


def test_refuses_rsa_key_with_accepted_types(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    path = _write_openssh_key(tmp_path, key, "id_rsa")
    with pytest.raises(SignerError) as excinfo:
        _load_client_ssh_key(path)
    assert CLIENT_SSH_KEY_REQUIREMENT in str(excinfo.value)


def test_reports_encrypted_key(tmp_path):
    path = _write_openssh_key(
        tmp_path, ed25519.Ed25519PrivateKey.generate(), "id_ed25519", password=b"secret"
    )
    with pytest.raises(SignerError, match="encrypted"):
        _load_client_ssh_key(path)
