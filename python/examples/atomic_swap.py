#!/usr/bin/env python3
"""
Atomic swap example - exchange ALGO between two accounts in a single group.

This demonstrates signing a transaction group where both parties must sign.
Works with any combination of key types (Ed25519, Falcon, etc.), and with a
cosigned account. A rotating account cannot take part: it sends one
transaction alone, and the signer forms its group.

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

Important:
    - Do NOT pre-assign group IDs with assign_group_id()
    - The server computes the group ID after adding any required dummy transactions
    - send_prepared submits exactly the group the signer returned, after checking it
"""

from algosdk.v2client import algod
from aplanesdk import SignerClient, SignOutcomeUnknownError, SubmissionUncertainError

# Swap parameters (replace with your actual addresses)
ALICE = "ALICEED255EXAMPLE777777777777777777777777777777777777777777"  # Ed25519 account
BOB = "BOBFALCONEXAMPLE7777777777777777777777777777777777777777777"    # Falcon account
SWAP_AMOUNT = 100000  # 0.1 ALGO in microAlgos


def main():
    # Connect using config from $APCLIENT_DATA
    with SignerClient.from_env() as signer:
        algod_client = algod.AlgodClient("a" * 64, "http://localhost:4001")

        # Build both payments, ungrouped, each naming the key that signs it
        # (a rekeyed account's authorizer included).
        group = signer.prepare_payment_group(
            algod_client,
            [
                {"sender": ALICE, "receiver": BOB, "amount": SWAP_AMOUNT},
                {"sender": BOB, "receiver": ALICE, "amount": SWAP_AMOUNT},
            ],
        )

        # Sign the group (server handles grouping and dummies for Falcon),
        # then submit and confirm it.
        print(f"Sending atomic swap: {ALICE[:8]}... <-> {BOB[:8]}...")
        try:
            result = signer.send_prepared(algod_client, group)
        except (SubmissionUncertainError, SignOutcomeUnknownError) as error:
            # A group that was signed, or a signature that may have been
            # released: never build a replacement until the outcome is
            # known, because both could execute. The node says where it
            # stands.
            report = signer.resolve_outcome(algod_client, error)
            print(f"Outcome unknown ({report.state}): {report.advice}")
            raise

        print(f"Confirmed group {result.group_id} in round {result.confirmed_round}")
        print("Atomic swap complete!")


if __name__ == "__main__":
    main()
