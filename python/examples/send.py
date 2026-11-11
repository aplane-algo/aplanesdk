#!/usr/bin/env python3
"""
Send a payment from any account the signer holds.

send_payment builds the payment, signs it through the flow the sender's key
needs, checks the signed result, submits it and waits for confirmation. The
same call works for an Ed25519, native Falcon, LogicSig, bounded, cosigned or
rotating account, and for a rekeyed sender. A cosigned account needs nothing
extra when endpoints.yaml lists its cosigner (a role: cosigner endpoint, as
below): the SDK finds the cosigner there.

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
      # Only for a cosigned account: the node holding its cosigner.
      cosigner:
        role: cosigner
        url: ssh://192.168.86.74:1127
"""

from algosdk.v2client import algod
from aplanesdk import SignerClient, SignOutcomeUnknownError, SubmissionUncertainError

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
            # The node says where it stands.
            print_outcome(signer, algod_client, error)
            raise
        except SignOutcomeUnknownError as error:
            # The signer may have released a signature this call never saw.
            # Do NOT build and sign a replacement while it can still execute
            # (until error.last_valid): both could. A rotating account's
            # prepared group, in error.rotating, can be signed again with
            # signer.sign_prepared_rotating.
            print_outcome(signer, algod_client, error)
            raise

        # The signer may raise the fee or add transactions, so the ID comes
        # from the signed group, not from the payment as it was built.
        print(
            f"Confirmed {result.tx_ids[0]} in round {result.confirmed_round}, "
            f"fee {result.fees[0]} microAlgos"
        )
        if result.rotating is not None:
            print(f"Rotated from stage {result.rotating.stage} to stage {result.rotating.target}")


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
