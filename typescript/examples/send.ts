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
import { SignOutcomeUnknownError, SignerClient, SubmissionError } from "aplanesdk";

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
    // first could both execute.
    if (error instanceof SubmissionError) {
      // The group was signed; its bytes and IDs are in the error, and its
      // cause is algosdk's error from the submit call or the wait.
      console.error(error.message);
      if (!error.submitted) {
        console.error(
          "The submit call did not return success; the node may or may not have the group. " +
            "Submit the same signedGroup again with submitSignedGroup.",
        );
      } else if (await waitForGroup(algodClient, error)) {
        return;
      }
    } else if (error instanceof SignOutcomeUnknownError) {
      // The signer may have released a signature that was never received.
      // Nothing was submitted.
      console.error(`Sign outcome unknown (request ${error.requestId || "(no ID)"}): ${error.message}`);
      if (error.rotating) {
        // The same prepared group signs to the same transaction IDs.
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

/**
 * Follow a submitted group with algosdk until its last valid round, and for
 * at least 1 round: given 0, algosdk's wait throws without looking. A group
 * confirms as a whole, so its first ID is enough. A timeout means only that
 * the wait ended.
 */
async function waitForGroup(algodClient: algosdk.Algodv2, error: SubmissionError): Promise<boolean> {
  try {
    const { lastRound } = await algodClient.status().do();
    const rounds = error.lastValid > lastRound ? error.lastValid - lastRound : 1n;
    const info = await algosdk.waitForConfirmation(algodClient, error.txIds[0], Number(rounds));
    console.log(`Confirmed ${error.txIds[0]} in round ${info.confirmedRound}`);
    return true;
  } catch (waitError) {
    const reason = waitError instanceof Error ? waitError.message : String(waitError);
    console.error(
      `Not seen confirmed (${reason}). After round ${error.lastValid}, check an indexer before building a replacement.`,
    );
    return false;
  }
}

main().catch(console.error);
