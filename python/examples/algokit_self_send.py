#!/usr/bin/env python3
"""Minimal AlgoKit Utils example using an apsigner-backed account."""

import os

from algokit_utils import AlgoAmount, AlgorandClient, PaymentParams
from aplanesdk import SignerClient
from aplanesdk.algokit import create_apsigner_account


sender = os.environ["APLANE_ADDRESS"]
algorand = AlgorandClient.testnet()

with SignerClient.from_env() as signer:
    account_info = algorand.account.get_information(sender)
    account = create_apsigner_account(
        signer,
        sender,
        auth_address=account_info.auth_addr or sender,
    )

    txn = algorand.create_transaction.payment(
        PaymentParams(
            sender=account.addr,
            signer=account,
            receiver=account.addr,
            amount=AlgoAmount.from_micro_algo(0),
            validity_window=1000,
        )
    )

    signed_txns = account.signer([txn], [0])
    response = algorand.client.algod.send_raw_transaction(signed_txns)
    print(response.tx_id)
