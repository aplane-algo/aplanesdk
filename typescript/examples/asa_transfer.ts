/**
 * ASA (Algorand Standard Asset) transfer example.
 *
 * Works with any key type (Ed25519, Falcon, etc.).
 * The server automatically handles fee pooling for large LogicSigs.
 *
 * Setup:
 *   1. Create data directory: mkdir -p ~/aplane/apclient/.ssh
 *   2. Copy token: cp /path/to/aplane.token ~/aplane/apclient/
 *   3. Generate APlane SSH key: ssh-keygen -t ed25519 -f ~/aplane/apclient/.ssh/id_ed25519 -N ''
 *   4. Create endpoints.yaml (see below)
 *   5. Set env: export APCLIENT_DATA=~/aplane/apclient
 *
 * Example endpoints.yaml (SSH tunnel):
 *   schema_version: 2
 *   endpoints:
 *     primary:
 *       role: signer
 *       url: ssh://192.168.86.73:1127
 *       identity_file: .ssh/id_ed25519
 * */

import algosdk from "algosdk";
import { SignerClient, sendRawTransaction } from "aplanesdk";

// Transaction parameters (replace with your actual addresses)
const SENDER = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777";
const RECEIVER = "RECEIVEREXAMPLE777777777777777777777777777777777777777777";
const ASSET_ID = 10458941; // replace with an ASA that exists on your LocalNet
const AMOUNT = 1; // Amount in base units

async function main() {
  // Connect using config from $APCLIENT_DATA
  const signer = await SignerClient.fromEnv();

  try {
    const algodClient = new algosdk.Algodv2("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "http://localhost", 4001);

    // Build ASA transfer transaction
    const params = await algodClient.getTransactionParams().do();
    const txn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
      sender: SENDER,
      receiver: RECEIVER,
      amount: AMOUNT,
      assetIndex: ASSET_ID,
      suggestedParams: params,
    });

    // Resolve auth address (handles rekeyed accounts)
    const acctInfo = await algodClient.accountInformation(SENDER).do();
    const authAddr = acctInfo.authAddr?.toString();

    // Sign and submit (server handles fee pooling automatically)
    console.log(`Signing ASA transfer for ${SENDER.slice(0, 12)}...`);
    const signed = await signer.signTransaction(txn, authAddr);

    // Submit (handles concatenated group bytes from Falcon/LogicSig keys)
    const txid = await sendRawTransaction(algodClient, signed);
    console.log(`Submitted: ${txid}`);

    // Wait for confirmation
    const result = await algosdk.waitForConfirmation(algodClient, txid, 4);
    console.log(`Confirmed in round ${result.confirmedRound}`);
  } finally {
    signer.close();
  }
}

main().catch(console.error);
