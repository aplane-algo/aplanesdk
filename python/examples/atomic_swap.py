#!/usr/bin/env python3
"""
Atomic swap example - exchange ALGO between two accounts in a single group.

This demonstrates signing a transaction group where both parties must sign.
Works with any combination of key types (Ed25519, Falcon, etc.).

Setup:
    1. Create data directory: mkdir -p ~/aplane/apclient/.ssh
    2. Copy token: cp /path/to/aplane.token ~/aplane/apclient/
    3. Copy SSH key: cp ~/.ssh/your_key ~/aplane/apclient/.ssh/id_ed25519
    4. Create config.yaml (see below)
    5. Set env: export APCLIENT_DATA=~/aplane/apclient

Example config.yaml (SSH tunnel):
    signer_port: 11270
    ssh:
      host: 192.168.86.73
      port: 1127
      identity_file: .ssh/id_ed25519

Important:
    - Do NOT pre-assign group IDs with assign_group_id()
    - The server computes the group ID after adding any required dummy transactions
    - The return value can be passed directly to send_raw_transaction()
"""

from algosdk import transaction
from algosdk.v2client import algod
from aplanesdk import SignerClient, send_raw_transaction

# Swap parameters (replace with your actual addresses)
ALICE = "ALICEED255EXAMPLE777777777777777777777777777777777777777777"  # Ed25519 account
BOB = "BOBFALCONEXAMPLE7777777777777777777777777777777777777777777"    # Falcon account
SWAP_AMOUNT = 100000  # 0.1 ALGO in microAlgos


def main():
    # Connect using config from $APCLIENT_DATA
    with SignerClient.from_env() as signer:
        algod_client = algod.AlgodClient("", "https://testnet-api.4160.nodely.dev")
        params = algod_client.suggested_params()

        # Build transactions (do NOT call assign_group_id)
        txn_alice_to_bob = transaction.PaymentTxn(
            sender=ALICE,
            receiver=BOB,
            amt=SWAP_AMOUNT,
            sp=params
        )

        txn_bob_to_alice = transaction.PaymentTxn(
            sender=BOB,
            receiver=ALICE,
            amt=SWAP_AMOUNT,
            sp=params
        )

        # Resolve auth addresses (handles rekeyed accounts)
        alice_info = algod_client.account_info(ALICE)
        bob_info = algod_client.account_info(BOB)
        auth_addresses = [
            alice_info.get("auth-addr") or ALICE,
            bob_info.get("auth-addr") or BOB,
        ]

        # Sign the group (server handles grouping and dummies for Falcon)
        print(f"Signing atomic swap: {ALICE[:8]}... <-> {BOB[:8]}...")
        signed = signer.sign_transactions(
            [txn_alice_to_bob, txn_bob_to_alice],
            auth_addresses=auth_addresses,
        )

        # Submit (handles concatenated group bytes from Falcon/LogicSig keys)
        txid = send_raw_transaction(algod_client, signed)
        print(f"Submitted: {txid}")

        # Wait for confirmation
        result = transaction.wait_for_confirmation(algod_client, txid, 4)
        print(f"Confirmed in round {result['confirmed-round']}")
        print("Atomic swap complete!")


if __name__ == "__main__":
    main()
