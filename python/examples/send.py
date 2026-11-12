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
            # The signed group may be on the network. Never build a
            # replacement until its outcome is known: both could execute.
            confirmed_round = wait_for_group(algod_client, error)
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


def wait_for_group(algod_client, error):
    """Wait with algosdk for a signed group whose outcome is unknown, until
    its last valid round. A group confirms as a whole, so its first
    transaction is followed. Returns the round it confirmed in, or 0 when the
    wait ended without seeing it, which means only that the wait ended. Once
    the last valid round has passed, a node's "not found" is not proof that
    the group never confirmed, so check an indexer before building a
    replacement. (A send given a timeout can also end with stage "unsent":
    the node never had the group, so submit it with submit_signed_group
    instead of waiting.)"""
    print(f"Outcome unknown for {', '.join(error.tx_ids)} ({error.stage}): {error}")
    try:
        current = algod_client.status()["last-round"]
        # At least 1 round: algosdk reads 0 as 1000.
        info = transaction.wait_for_confirmation(
            algod_client, error.tx_ids[0], max(error.last_valid - current, 1)
        )
    except Exception as wait_error:
        print(f"Still unknown ({wait_error}); check an indexer before building a replacement.")
        return 0
    return info["confirmed-round"]


if __name__ == "__main__":
    main()
