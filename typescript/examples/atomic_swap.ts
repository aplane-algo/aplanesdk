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
import { SignOutcomeUnknownError, SignerClient, SubmissionError, bytesToHex } from "aplanesdk";

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
    if (error instanceof SubmissionError) {
      console.error(error.message);
      if (!error.submitted) {
        console.error(
          "The submit call did not return success. If the cause is algod's own HTTP 400, the node " +
            "answered: read its reason, which decides what to do. Otherwise the node may or may not " +
            "have the group: follow the first ID with algosdk's wait, and if it does not confirm, " +
            "submit the same signed group again with submitSignedGroup.",
        );
        printSignedGroup(error);
      } else if (await waitForGroup(algodClient, error)) {
        return;
      }
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
 * Follow a submitted group with algosdk for at most 10 more rounds, never
 * past its last valid round, and for at least 1 round: given 0, algosdk's
 * wait throws without looking. A group confirms as a whole, so its first ID
 * is enough. A timeout means only that the wait ended.
 */
async function waitForGroup(algodClient: algosdk.Algodv2, error: SubmissionError): Promise<boolean> {
  try {
    const { lastRound } = await algodClient.status().do();
    const left = error.lastValid > lastRound ? error.lastValid - lastRound : 1n;
    const rounds = left < 10n ? left : 10n;
    const info = await algosdk.waitForConfirmation(algodClient, error.txIds[0], Number(rounds));
    console.log(`Confirmed group in round ${info.confirmedRound}`);
    return true;
  } catch (waitError) {
    const reason = waitError instanceof Error ? waitError.message : String(waitError);
    console.error(
      `Not seen confirmed (${reason}). It may still confirm until round ${error.lastValid}; ` +
        "after that round, check an indexer before building a replacement.",
    );
    printSignedGroup(error);
    return false;
  }
}

/** Print what following the group, or submitting it again with submitSignedGroup, needs. */
function printSignedGroup(error: SubmissionError): void {
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
}

main().catch(console.error);
