#!/usr/bin/env python3
"""
Minimal validation transaction example.

Sends a 0 ALGO self-payment to validate that signing works.
Works with any key type (Ed25519, Falcon, etc.).

Setup:
    1. Create data directory: mkdir -p ~/aplane/apclient/.ssh
    2. Copy token: cp /path/to/aplane.token ~/aplane/apclient/
    3. Copy SSH key: cp ~/.ssh/your_key ~/aplane/apclient/.ssh/id_ed25519
    4. Create config.yaml (see below)
    5. Set env: export APCLIENT_DATA=~/aplane/apclient

Example config.yaml (SSH tunnel):
    endpoint:
      signer_port: 11270
      ssh:
        host: 192.168.86.73
        port: 1127
        identity_file: .ssh/id_ed25519
"""

from algosdk import transaction
from algosdk.v2client import algod
from aplanesdk import SignerClient, send_raw_transaction

# The address to validate (must exist in apsigner keystore)
# Replace with your actual address
SENDER = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777"


def main():
    # Connect using config from $APCLIENT_DATA
    with SignerClient.from_env() as signer:
        algod_client = algod.AlgodClient("", "https://testnet-api.4160.nodely.dev")

        # Build 0-ALGO self-send (validation transaction)
        params = algod_client.suggested_params()
        txn = transaction.PaymentTxn(sender=SENDER, sp=params, receiver=SENDER, amt=0)

        # Resolve auth address (handles rekeyed accounts)
        acct_info = algod_client.account_info(SENDER)
        auth_addr = acct_info.get("auth-addr") or None

        # Sign and submit (server handles fee pooling automatically)
        print(f"Signing validation txn for {SENDER[:12]}...")
        signed = signer.sign_transaction(txn, auth_address=auth_addr)

        # Submit (handles concatenated group bytes from Falcon/LogicSig keys)
        txid = send_raw_transaction(algod_client, signed)
        print(f"Submitted: {txid}")

        # Wait for confirmation
        result = transaction.wait_for_confirmation(algod_client, txid, 4)
        print(f"Confirmed in round {result['confirmed-round']}")


if __name__ == "__main__":
    main()
