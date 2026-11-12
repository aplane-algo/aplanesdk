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

from algosdk import transaction
from algosdk.v2client import algod
from aplanesdk import SignerClient, SignOutcomeUnknownError, SubmissionError

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
            # signature this call never received. For a rotating account,
            # sign error.rotating again with signer.sign_prepared_rotating:
            # it gives the same transaction IDs, so it cannot pay twice. For
            # any other account, do not build a replacement until round
            # error.last_valid has passed; after it, nothing signed by that
            # request can execute.
            print(f"Sign outcome unknown (request {error.request_id or 'unnamed'}): {error}")
            raise

        # The signer may raise the fee or add transactions, so the ID comes
        # from the signed group, not from the payment as it was built.
        print(
            f"Confirmed {result.tx_ids[0]} in round {result.confirmed_round}, "
            f"fee {result.fees[0]} microAlgos"
        )
        if result.rotating is not None:
            print(f"Rotated from stage {result.rotating.stage} to stage {result.rotating.target}")


def follow_group(algod_client, error):
    """Follow a signed group after a SubmissionError. When algosdk's submit
    call did not return success (error.submitted is False), say what to do
    and return 0: if error.error is algod's HTTP 400 the node answered, so
    read its reason; otherwise it may or may not have the group, so look the
    first transaction up and then submit the same signed_group again with
    submit_signed_group, which cannot pay twice. When it did return success,
    wait with algosdk on the first transaction (a group confirms as a whole)
    for at most 10 more rounds and not past the group's last valid round, at
    least 1. Returns the round it confirmed in, or 0 when the wait ended
    without seeing it, which means only that the wait ended. A caller may
    wait up to the last valid round. Once the last valid round has
    passed, neither a node's "not found" nor a refusal proves that the group
    never confirmed, so check an indexer before building a replacement.
    Whenever it returns 0 it prints what acting on that advice needs."""
    print(f"Signed group {', '.join(error.tx_ids)}: {error}")
    if not error.submitted:
        print(
            "The submit call did not return success. If the cause is algod's HTTP 400, the "
            "node answered: read its reason. Otherwise it may or may not have the group: look "
            "up the first transaction, then submit the same signed_group again with "
            "submit_signed_group."
        )
        print_group(error)
        return 0
    try:
        current = algod_client.status()["last-round"]
        # At most 10 rounds, so the example never blocks for long, and at
        # least 1: algosdk reads 0 as 1000.
        rounds = max(min(error.last_valid - current, 10), 1)
        info = transaction.wait_for_confirmation(algod_client, error.tx_ids[0], rounds)
    except Exception as follow_error:
        print(
            f"Still unknown ({follow_error}); after round {error.last_valid}, check an indexer "
            "before building a replacement."
        )
        print_group(error)
        return 0
    return info["confirmed-round"]


def print_group(error):
    """Print what acting on a SubmissionError needs: every entry of the
    signed group, each signed transaction as hex, the transaction IDs and the
    last valid round. submit_signed_group takes the entries as bytes:
    [bytes.fromhex(line) for line in the printed lines]."""
    print("Signed group, one signed transaction per line, as hex:")
    for entry in error.signed_group:
        print(f"  {entry.hex()}")
    print(f"Transaction IDs: {', '.join(error.tx_ids)}")
    print(f"Last valid round: {error.last_valid}")


if __name__ == "__main__":
    main()
