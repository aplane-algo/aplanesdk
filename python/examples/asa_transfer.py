#!/usr/bin/env python3
"""
ASA (Algorand Standard Asset) transfer example.

Works with any key type (Ed25519, Falcon, etc.), and for a rekeyed sender:
prepare_asa_transfer finds the key that signs, and send_prepared signs
through the flow that key needs, checks the signed result, submits it and
waits for confirmation. The server automatically handles fee pooling for
large LogicSigs.

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
"""

from algosdk.v2client import algod
from aplanesdk import SignerClient, SignOutcomeUnknownError, SubmissionUncertainError

# Transaction parameters (replace with your actual addresses)
SENDER = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777"
RECEIVER = "RECEIVEREXAMPLE777777777777777777777777777777777777777777"
ASSET_ID = 10458941  # replace with an ASA that exists on your LocalNet
AMOUNT = 1  # Amount in base units


def main():
    # Connect using config from $APCLIENT_DATA
    with SignerClient.from_env() as signer:
        algod_client = algod.AlgodClient("a" * 64, "http://localhost:4001")

        # Build the ASA transfer. The receiver must have opted in to the
        # asset; the helper checks that, and the sender's balance, first.
        prepared = signer.prepare_asa_transfer(
            algod_client, sender=SENDER, receiver=RECEIVER, asset_id=ASSET_ID, amount=AMOUNT
        )

        print(f"Sending ASA transfer from {SENDER[:12]}...")
        try:
            result = signer.send_prepared(algod_client, prepared)
        except (SubmissionUncertainError, SignOutcomeUnknownError) as error:
            # A group that was signed, or a signature that may have been
            # released: never build a replacement until the outcome is
            # known, because both could execute. The node says where it
            # stands.
            report = signer.resolve_outcome(algod_client, error)
            print(f"Outcome unknown ({report.state}): {report.advice}")
            raise

        # The signer may raise the fee, so the ID comes from the signed group.
        print(f"Confirmed {result.tx_ids[0]} in round {result.confirmed_round}")


if __name__ == "__main__":
    main()
