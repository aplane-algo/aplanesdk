/**
 * Hashlock claim example - demonstrates generic LogicSig with runtime arguments.
 *
 * This example shows how to claim funds from a hashlock LogicSig by providing
 * the preimage that hashes to the stored hash.
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
 * Prerequisites:
 *   - A hashlock key must exist in the signer's keystore
 *   - The hashlock address must have funds to claim
 *   - You must know the preimage that hashes to the stored hash
 */

import algosdk from "algosdk";
import { SignOutcomeUnknownError, SignerClient, SubmissionError, bytesToHex } from "aplanesdk";

// The hashlock address (must exist in apsigner keystore)
const HASHLOCK_ADDRESS = "HASHLOCKEXAMPLE7777777777777777777777777777777777777777";

// The recipient address (where funds will be sent)
const RECIPIENT = "RECIPIENTEXAMPLE777777777777777777777777777777777777777";

// The secret preimage (must hash to the stored hash)
// For SHA256: crypto.createHash('sha256').update(PREIMAGE).digest() === stored_hash
const PREIMAGE = new Uint8Array(Buffer.from("my_secret_preimage_32_bytes_long"));

async function main() {
  // Connect using config from $APCLIENT_DATA
  const signer = await SignerClient.fromEnv();
  const algodClient = new algosdk.Algodv2("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "http://localhost", 4001);

  try {
    // Discover required arguments for this LogicSig
    const keyInfo = await signer.getKeyInfo(HASHLOCK_ADDRESS);
    if (keyInfo?.signingArgs && keyInfo.signingArgs.length > 0) {
      console.log("Required arguments for this LogicSig:");
      for (const arg of keyInfo.signingArgs) {
        console.log(`  - ${arg.name}: ${arg.type} (${arg.description})`);
      }
    }

    // Build the claim: close the hashlock account to the recipient, which
    // sends it all the funds.
    const claim = await signer.prepareAccountClose(algodClient, {
      sender: HASHLOCK_ADDRESS,
      closeTo: RECIPIENT,
    });
    // The preimage is the LogicSig's runtime argument; the signer passes it
    // to the program, which checks its hash.
    claim.lsigArgs = { preimage: PREIMAGE };

    // Sign with the preimage argument, check, submit and wait for confirmation
    console.log("Sending hashlock claim with preimage...");
    const result = await signer.sendPrepared(algodClient, { transactions: [claim] });
    console.log(`Confirmed ${result.txIds[0]} in round ${result.confirmedRound}`);
    console.log("Hashlock claimed successfully!");
  } catch (error) {
    // Neither error means "claim again" with a new transaction.
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
    console.log(`Confirmed ${error.txIds[0]} in round ${info.confirmedRound}`);
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
