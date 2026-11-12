/**
 * Atomic swap example - exchange ALGO between two accounts in a single group.
 *
 * This demonstrates signing a transaction group where both parties must sign:
 * either both payments execute or neither does. Works with any combination of
 * key types (Ed25519, Falcon, etc.) the signer holds.
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
 *
 * Important:
 *   - Do NOT pre-assign group IDs with assignGroupID()
 *   - The server computes the group ID after adding any required dummy transactions
 *   - A rotating account cannot take part: it sends one transaction alone, so
 *     sendPrepared refuses such a group with UnsupportedGroupError
 */

import algosdk from "algosdk";
import { SignOutcomeUnknownError, SignerClient, SubmissionUncertainError } from "aplanesdk";

// Swap parameters (replace with your actual addresses)
const ALICE = "ALICEED255EXAMPLE777777777777777777777777777777777777777777"; // Ed25519 account
const BOB = "BOBFALCONEXAMPLE7777777777777777777777777777777777777777777"; // Falcon account
const SWAP_AMOUNT = 100000; // 0.1 ALGO in microAlgos

async function main() {
  // Connect using config from $APCLIENT_DATA
  const signer = await SignerClient.fromEnv();
  const algodClient = new algosdk.Algodv2("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "http://localhost", 4001);

  try {
    // Build both payments, ungrouped. The helper checks each sender's balance
    // and names the key that signs for a rekeyed sender.
    const group = await signer.preparePaymentGroup(algodClient, [
      { sender: ALICE, receiver: BOB, amount: SWAP_AMOUNT },
      { sender: BOB, receiver: ALICE, amount: SWAP_AMOUNT },
    ]);

    // Sign the group (server handles grouping and dummies for Falcon), check
    // it, submit it and wait for confirmation.
    console.log(`Sending atomic swap: ${ALICE.slice(0, 8)}... <-> ${BOB.slice(0, 8)}...`);
    const result = await signer.sendPrepared(algodClient, group);
    console.log(`Confirmed group ${result.groupId} in round ${result.confirmedRound}`);
    console.log("Atomic swap complete!");
  } catch (error) {
    // Neither error means "send again": a second swap and the first could
    // both execute.
    if (error instanceof SubmissionUncertainError) {
      console.error(`Outcome unknown for ${error.txIds.join(", ")} (${error.stage}): ${error.message}`);
      if (await waitForGroup(algodClient, error)) return;
    } else if (error instanceof SignOutcomeUnknownError) {
      console.error(`Sign outcome unknown (request ${error.requestId || "(no ID)"}): ${error.message}`);
      console.error(`Do not build a replacement until round ${error.lastValid} has passed.`);
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
async function waitForGroup(algodClient: algosdk.Algodv2, error: SubmissionUncertainError): Promise<boolean> {
  try {
    const { lastRound } = await algodClient.status().do();
    const rounds = error.lastValid > lastRound ? error.lastValid - lastRound : 1n;
    const info = await algosdk.waitForConfirmation(algodClient, error.txIds[0], Number(rounds));
    console.log(`Confirmed group in round ${info.confirmedRound}`);
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
