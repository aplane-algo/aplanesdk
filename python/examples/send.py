#!/usr/bin/env python3
"""
Send a payment from any account the signer holds.

send_payment builds the payment, signs it through the flow the sender's key
needs, checks the signed result, submits it and waits for confirmation. The
same call works for an Ed25519, native Falcon, LogicSig, bounded or rotating
account, and for a rekeyed sender. A cosigned account also needs its cosigner:
pass cosigner_client and cosigner_component_key.

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
from aplanesdk import SignerClient, SubmissionUncertainError

# The account to pay from (the signer must hold its key) and the account to
# pay. Replace both.
SENDER = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777"
RECEIVER = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777"


def main():
    # Connect using config from $APCLIENT_DATA
    with SignerClient.from_env() as signer:
        algod_client = algod.AlgodClient("a" * 64, "http://localhost:4001")

        try:
            # 1 ALGO, in microAlgos.
            result = signer.send_payment(
                algod_client, sender=SENDER, receiver=RECEIVER, amount=1_000_000
            )
        except SubmissionUncertainError as error:
            # A group that was signed keeps its bytes and IDs in the error.
            # Never send again until its outcome is known: both could execute.
            print(f"Outcome unknown for {error.tx_ids} ({error.stage}); look it up before sending again")
            raise

        # The signer may raise the fee or add transactions, so the ID comes
        # from the signed group, not from the payment as it was built.
        print(
            f"Confirmed {result.tx_ids[0]} in round {result.confirmed_round}, "
            f"fee {result.fees[0]} microAlgos"
        )
        if result.rotating is not None:
            print(f"Rotated from stage {result.rotating.stage} to stage {result.rotating.target}")


if __name__ == "__main__":
    main()
