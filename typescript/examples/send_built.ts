/**
 * Send a payment built with algosdk's own constructor.
 *
 * sendTransactions takes algosdk Transaction objects. For each one it reads
 * the sender's account from the node, names the key that signs for it (the
 * sender, or its auth address when the account is rekeyed), and sends the
 * group through sendPrepared: it signs, checks the signed result, submits it
 * and waits for confirmation. It runs none of the prepare helpers' checks,
 * such as the sender's balance. The call does not modify the transaction
 * objects you pass in. Use the transaction IDs in the result.
 *
 * Setup:
 *   1. Create data directory: mkdir -p ~/aplane/apclient/.ssh
 *   2. Generate APlane SSH key: ssh-keygen -t ed25519 -f ~/aplane/apclient/.ssh/id_ed25519 -N ''
 *   3. Enroll it at the signer: run apshell enroll and approve in apadmin
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
import { SignOutcomeUnknownError, SignerClient, SubmissionError, bytesToHex } from "aplanesdk";

// The account to pay from (the signer must hold its key) and the account to
// pay. Replace both.
const SENDER = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777";
const RECEIVER = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777";

async function main() {
  // Connect using config from $APCLIENT_DATA
  const signer = await SignerClient.fromEnv();
  const algodClient = new algosdk.Algodv2("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "http://localhost", 4001);

  try {
    // Build the payment as in any algosdk program: 1 ALGO, in microAlgos.
    const payment = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: SENDER,
      receiver: RECEIVER,
      amount: 1_000_000,
      suggestedParams: await algodClient.getTransactionParams().do(),
    });

    const result = await signer.sendTransactions(algodClient, [payment]);

    // The signer may raise the fee or add transactions, so the ID comes from
    // the result, not from the payment as it was built.
    console.log(`Confirmed ${result.txIds[0]} in round ${result.confirmedRound}, fee ${result.fees[0]} microAlgos`);
  } catch (error) {
    // Neither of these errors means "send again": a second payment and the
    // first could both execute.
    if (error instanceof SubmissionError) {
      // The group was signed; its bytes and IDs are in the error, and its
      // cause is algosdk's error from the submit call or the wait.
      console.error(error.message);
      console.error(`Transaction IDs: ${error.txIds.join(", ")}`);
      console.error(`Last valid round: ${error.lastValid}`);
      // The entries are bytes; this prints each one as hex, one line per
      // transaction. hexToBytes turns each line back into bytes; the list of
      // them is what submitSignedGroup takes, and algosdk's sendRawTransaction
      // takes it as it is.
      console.error("Signed group, each entry printed as hex msgpack, one per transaction:");
      for (const entry of error.signedGroup) {
        console.error(`  ${bytesToHex(entry)}`);
      }
      console.error(
        "See examples/send.ts for following the group with algosdk's wait, and for when to " +
          "submit the same signed group again with submitSignedGroup.",
      );
    } else if (error instanceof SignOutcomeUnknownError) {
      // The signer may have released a signature that was never received.
      // Nothing was submitted.
      console.error(`Sign outcome unknown (request ${error.requestId || "(no ID)"}): ${error.message}`);
      if (error.rotating) {
        console.error("Sign the same prepared group again with signPreparedRotating(error.rotating).");
      } else {
        console.error(`Do not build a replacement until round ${error.lastValid} has passed.`);
      }
    }
    throw error;
  } finally {
    await signer.close();
  }
}

main().catch(console.error);
