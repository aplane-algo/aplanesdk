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

from algosdk import transaction
from algosdk.v2client import algod
from aplanesdk import SignerClient, SignOutcomeUnknownError, SubmissionError

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
        except SubmissionError as error:
            # The group was signed, and algosdk's submit call or its
            # confirmation wait failed; error.error is algosdk's error. The
            # group may be on the network. Never build a replacement until
            # its outcome is known: both could execute.
            confirmed_round = follow_group(algod_client, error)
            if not confirmed_round:
                raise
            print(f"Confirmed {error.tx_ids[0]} in round {confirmed_round}")
            return
        except SignOutcomeUnknownError as error:
            # Nothing was submitted, but the signer may have released a
            # signature this call never received. Do not build a replacement
            # until round error.last_valid has passed; after it, nothing
            # signed by that request can execute.
            print(f"Sign outcome unknown (request {error.request_id or 'unnamed'}): {error}")
            raise

        print(f"Confirmed {result.tx_ids[0]} in round {result.confirmed_round}")
        print("Hashlock claimed successfully!")


def follow_group(algod_client, error):
    """Follow a signed group after a SubmissionError. When algosdk's submit
    call did not return success (error.submitted is False), the node may or
    may not have the group: say so and return 0. The caller then submits the
    same signed_group again with submit_signed_group, which cannot pay
    twice. When it did return success, wait with algosdk on the first
    transaction (a group confirms as a whole) until the group's last valid
    round, and for at least 1 round. Returns the round it confirmed in, or 0
    when the wait ended without seeing it, which means only that the wait
    ended. Once the last valid round has passed, neither a node's "not found"
    nor a refusal proves that the group never confirmed, so check an indexer
    before building a replacement."""
    print(f"Signed group {', '.join(error.tx_ids)}: {error}")
    if not error.submitted:
        print(
            "The submit call did not return success, so the node may or may not have the "
            "group. Submit the same signed_group again with submit_signed_group."
        )
        return 0
    try:
        current = algod_client.status()["last-round"]
        # At least 1 round: algosdk reads 0 as 1000.
        info = transaction.wait_for_confirmation(
            algod_client, error.tx_ids[0], max(error.last_valid - current, 1)
        )
    except Exception as follow_error:
        print(f"Still unknown ({follow_error}); check an indexer before building a replacement.")
        return 0
    return info["confirmed-round"]


if __name__ == "__main__":
    main()
