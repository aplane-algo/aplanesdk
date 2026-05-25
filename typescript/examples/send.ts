/**
 * Minimal validation transaction example.
 *
 * Sends a 0 ALGO self-payment to validate that signing works.
 * Works with any key type (Ed25519, Falcon, etc.).
 *
 * Setup:
 *   1. Create data directory: mkdir -p ~/aplane/apclient/.ssh
 *   2. Copy token: cp /path/to/aplane.token ~/aplane/apclient/
 *   3. Copy SSH key: cp ~/.ssh/your_key ~/aplane/apclient/.ssh/id_ed25519
 *   4. Create config.yaml (see below)
 *   5. Set env: export APCLIENT_DATA=~/aplane/apclient
 *
 * Example config.yaml (SSH tunnel):
 *   signer_port: 11270
 *   ssh:
 *     host: 192.168.86.73
 *     port: 1127
 *     identity_file: .ssh/id_ed25519
 * */

import algosdk from "algosdk";
import { SignerClient, sendRawTransaction } from "aplanesdk";

// The address to validate (must exist in apsigner keystore)
// Replace with your actual address
const SENDER = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777";

async function main() {
  // Connect using config from $APCLIENT_DATA
  const signer = await SignerClient.fromEnv();

  try {
    const algodClient = new algosdk.Algodv2("", "https://testnet-api.4160.nodely.dev", "");

    // Build 0-ALGO self-send (validation transaction)
    const params = await algodClient.getTransactionParams().do();
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: SENDER,
      receiver: SENDER,
      amount: 0,
      suggestedParams: params,
    });

    // Resolve auth address (handles rekeyed accounts)
    const acctInfo = await algodClient.accountInformation(SENDER).do();
    const authAddr = acctInfo.authAddr || undefined;

    // Sign and submit (server handles fee pooling automatically)
    console.log(`Signing validation txn for ${SENDER.slice(0, 12)}...`);
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
