#!/usr/bin/env python3
"""
Hashlock claim example - demonstrates generic LogicSig with runtime arguments.

This example shows how to claim funds from a hashlock LogicSig by providing
the preimage that hashes to the stored hash.

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

Prerequisites:
    - A hashlock key must exist in the signer's keystore
    - The hashlock address must have funds to claim
    - You must know the preimage that hashes to the stored hash
"""

from algosdk import transaction
from algosdk.v2client import algod
from aplanesdk import SignerClient, send_raw_transaction

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
        algod_client = algod.AlgodClient("", "https://testnet-api.4160.nodely.dev")

        # Discover required arguments for this LogicSig
        key_info = signer.get_key_info(HASHLOCK_ADDRESS)
        if key_info and key_info.signing_args:
            print("Required arguments for this LogicSig:")
            for arg in key_info.signing_args:
                print(f"  - {arg.name}: {arg.arg_type} ({arg.description})")

        # Build claim transaction (send all funds to recipient)
        params = algod_client.suggested_params()
        txn = transaction.PaymentTxn(
            sender=HASHLOCK_ADDRESS,
            receiver=RECIPIENT,
            amt=0,  # Use close_remainder_to to send all funds
            close_remainder_to=RECIPIENT,
            sp=params
        )

        # Sign with the preimage argument
        print("Signing hashlock claim with preimage...")
        signed = signer.sign_transaction(
            txn,
            auth_address=HASHLOCK_ADDRESS,
            lsig_args={"preimage": PREIMAGE},
        )

        # Submit (handles concatenated group bytes from Falcon/LogicSig keys)
        txid = send_raw_transaction(algod_client, signed)
        print(f"Submitted: {txid}")

        # Wait for confirmation
        result = transaction.wait_for_confirmation(algod_client, txid, 4)
        print(f"Confirmed in round {result['confirmed-round']}")
        print("Hashlock claimed successfully!")


if __name__ == "__main__":
    main()
