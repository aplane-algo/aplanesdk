/**
 * Send a payment from any account the signer holds.
 *
 * sendPayment builds the payment, signs it through the flow the sender's key
 * needs, checks the signed result, submits it and waits for confirmation. The
 * same call works for an Ed25519, native Falcon, LogicSig, bounded or rotating
 * account, and for a rekeyed sender. A cosigned account needs nothing extra
 * when endpoints.yaml lists its cosigner (an endpoint with role: cosigner);
 * otherwise set cosignerClient and cosignerComponentKey in the options.
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
import { SignOutcomeUnknownError, SignerClient, SubmissionUncertainError } from "aplanesdk";

// The account to pay from (the signer must hold its key) and the account to
// pay. Replace both.
const SENDER = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777";
const RECEIVER = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777";

async function main() {
  // Connect using config from $APCLIENT_DATA
  const signer = await SignerClient.fromEnv();
  const algodClient = new algosdk.Algodv2("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "http://localhost", 4001);

  try {
    // 1 ALGO, in microAlgos.
    const result = await signer.sendPayment(algodClient, {
      sender: SENDER,
      receiver: RECEIVER,
      amount: 1_000_000,
    });

    // The signer may raise the fee or add transactions, so the ID comes from
    // the signed group, not from the payment as it was built.
    console.log(`Confirmed ${result.txIds[0]} in round ${result.confirmedRound}, fee ${result.fees[0]} microAlgos`);
    if (result.rotating) {
      console.log(`Rotated from stage ${result.rotating.stage} to stage ${result.rotating.target}`);
    }
  } catch (error) {
    // Neither of these errors means "send again": a second payment and the
    // first could both execute. Ask the node where things stand instead.
    if (error instanceof SubmissionUncertainError) {
      // The group was signed; its bytes and IDs are in the error.
      const report = await signer.resolveOutcome(algodClient, error);
      console.error(`Outcome of ${error.txIds[0]} is ${report.state}: ${report.advice}`);
    } else if (error instanceof SignOutcomeUnknownError) {
      // The signer may have released a signature that was never submitted.
      const report = await signer.resolveOutcome(algodClient, error);
      console.error(`Sign request ${error.requestId || "(no ID)"} is ${report.state}: ${report.advice}`);
    }
    throw error;
  } finally {
    await signer.close();
  }
}

main().catch(console.error);
