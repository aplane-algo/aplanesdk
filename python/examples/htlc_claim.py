#!/usr/bin/env python3
"""
Hashlock claim example - demonstrates generic LogicSig with runtime arguments.

This example shows how to claim funds from a hashlock LogicSig by providing
the preimage that hashes to the stored hash. The argument travels with the
prepared transaction, and send_prepared signs, submits and confirms it as it
does any other.

Setup:
    1. Create data directory: mkdir -p ~/aplane/apclient/.ssh
    2. Generate APlane SSH key: ssh-keygen -t ed25519 -f ~/aplane/apclient/.ssh/id_ed25519 -N ''
    3. Enroll it at the signer: run apshell enroll and approve in apadmin
    4. Create endpoints.yaml (see below)
    5. Set env: export APCLIENT_DATA=~/aplane/apclient

Example endpoints.yaml (SSH tunnel):
    schema_version: 2
    endpoints:
      primary:
        role: signer
        url: ssh://192.168.86.73:1127
        identity_file: .ssh/id_ed25519

Prerequisites:
    - A hashlock key must exist in the signer's keystore
    - The hashlock address must have funds to claim
    - You must know the preimage that hashes to the stored hash
"""

from algosdk.v2client import algod
from aplanesdk import SignerClient, SignOutcomeUnknownError, SubmissionUncertainError

# The hashlock address (must exist in apsigner keystore)
HASHLOCK_ADDRESS = "HASHLOCKEXAMPLE7777777777777777777777777777777777777777"

# The recipient address (where funds will be sent)
RECIPIENT = "RECIPIENTEXAMPLE777777777777777777777777777777777777777"

# The secret preimage (must hash to the stored hash)
# For SHA256: hashlib.sha256(PREIMAGE).digest() == stored_hash
PREIMAGE = b"my_secret_preimage_32_bytes_long"


def main():
    # Connect using config from $APCLIENT_DATA
    with SignerClient.from_env() as signer:
        algod_client = algod.AlgodClient("a" * 64, "http://localhost:4001")

        # Discover required arguments for this LogicSig
        key_info = signer.get_key_info(HASHLOCK_ADDRESS)
        if key_info and key_info.signing_args:
            print("Required arguments for this LogicSig:")
            for arg in key_info.signing_args:
                print(f"  - {arg.name}: {arg.arg_type} ({arg.description})")

        # Build claim transaction (send all funds to recipient)
        prepared = signer.prepare_account_close(
            algod_client, sender=HASHLOCK_ADDRESS, close_to=RECIPIENT
        )
        # Sign with the preimage argument
        prepared.lsig_args = {"preimage": PREIMAGE}

        print("Sending hashlock claim with preimage...")
        try:
            result = signer.send_prepared(algod_client, prepared)
        except (SubmissionUncertainError, SignOutcomeUnknownError) as error:
            # A group that was signed, or a signature that may have been
            # released: never build a replacement until the outcome is
            # known, because both could execute. The node says where it
            # stands.
            print_outcome(signer, algod_client, error)
            raise

        print(f"Confirmed {result.tx_ids[0]} in round {result.confirmed_round}")
        print("Hashlock claimed successfully!")


def print_outcome(signer, algod_client, error):
    """Print an uncertain outcome and where the node says it stands. It signs
    and submits nothing. When the node cannot be asked, the error still
    stands, and is raised next as it was."""
    if isinstance(error, SubmissionUncertainError):
        print(f"Outcome unknown for {', '.join(error.tx_ids)} ({error.stage}): {error}")
    else:
        print(f"Sign outcome unknown (request {error.request_id or 'unnamed'}): {error}")
    try:
        report = signer.resolve_outcome(algod_client, error)
    except Exception as check_error:
        print(
            f"Could not check the outcome ({check_error}); look the transaction up "
            "before sending again."
        )
        return
    print(f"{report.state}: {report.advice}")


if __name__ == "__main__":
    main()
