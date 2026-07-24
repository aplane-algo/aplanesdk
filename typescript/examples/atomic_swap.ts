/**
 * Atomic swap example - exchange ALGO between two accounts in a single group.
 *
 * This demonstrates signing a transaction group where both parties must sign.
 * Works with any combination of key types (Ed25519, Falcon, etc.).
 *
 * Setup:
 *   1. Create data directory: mkdir -p ~/aplane/apclient/.ssh
 *   2. Copy token: cp /path/to/aplane.token ~/aplane/apclient/
 *   3. Copy SSH key: cp ~/.ssh/your_key ~/aplane/apclient/.ssh/id_ed25519
 *   4. Create endpoints.yaml (see below)
 *   5. Set env: export APCLIENT_DATA=~/aplane/apclient
 *
 * Example endpoints.yaml (SSH tunnel):
 *   schema_version: 1
 *   endpoints:
 *     primary:
 *       role: signer
 *       url: ssh://192.168.86.73:1127
 *       signer_port: 11270
 *       identity_file: .ssh/id_ed25519
 * *
 * Important:
 *   - Do NOT pre-assign group IDs with assignGroupID()
 *   - The server computes the group ID after adding any required dummy transactions
 *   - The return value can be passed directly to sendRawTransaction()
 */

import algosdk from "algosdk";
import { SignerClient, sendRawTransaction } from "aplanesdk";

// Swap parameters (replace with your actual addresses)
const ALICE = "ALICEED255EXAMPLE777777777777777777777777777777777777777777"; // Ed25519 account
const BOB = "BOBFALCONEXAMPLE7777777777777777777777777777777777777777777"; // Falcon account
const SWAP_AMOUNT = 100000; // 0.1 ALGO in microAlgos

async function main() {
  // Connect using config from $APCLIENT_DATA
  const signer = await SignerClient.fromEnv();

  try {
    const algodClient = new algosdk.Algodv2("", "https://testnet-api.4160.nodely.dev", "");
    const params = await algodClient.getTransactionParams().do();

    // Build transactions (do NOT call assignGroupID)
    const txnAliceToBob = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: ALICE,
      receiver: BOB,
      amount: SWAP_AMOUNT,
      suggestedParams: params,
    });

    const txnBobToAlice = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: BOB,
      receiver: ALICE,
      amount: SWAP_AMOUNT,
      suggestedParams: params,
    });

    // Resolve auth addresses (handles rekeyed accounts)
    const aliceInfo = await algodClient.accountInformation(ALICE).do();
    const bobInfo = await algodClient.accountInformation(BOB).do();
    const authAddresses = [
      aliceInfo.authAddr || ALICE,
      bobInfo.authAddr || BOB,
    ];

    // Sign the group (server handles grouping and dummies for Falcon)
    console.log(`Signing atomic swap: ${ALICE.slice(0, 8)}... <-> ${BOB.slice(0, 8)}...`);
    const signed = await signer.signTransactions(
      [txnAliceToBob, txnBobToAlice],
      authAddresses
    );

    // Submit (handles concatenated group bytes from Falcon/LogicSig keys)
    const txid = await sendRawTransaction(algodClient, signed);
    console.log(`Submitted: ${txid}`);

    // Wait for confirmation
    const result = await algosdk.waitForConfirmation(algodClient, txid, 4);
    console.log(`Confirmed in round ${result.confirmedRound}`);
    console.log("Atomic swap complete!");
  } finally {
    signer.close();
  }
}

main().catch(console.error);
