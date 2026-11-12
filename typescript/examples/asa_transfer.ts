/**
 * ASA (Algorand Standard Asset) transfer example.
 *
 * Works with any key type (Ed25519, Falcon, etc.), and for a rekeyed sender.
 * The server automatically handles fee pooling for large LogicSigs.
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

// Transaction parameters (replace with your actual addresses)
const SENDER = "ED255ACCOUNTEXAMPLE77777777777777777777777777777777777777777";
const RECEIVER = "RECEIVEREXAMPLE777777777777777777777777777777777777777777";
const ASSET_ID = 10458941; // replace with an ASA that exists on your LocalNet
const AMOUNT = 1; // Amount in base units

async function main() {
  // Connect using config from $APCLIENT_DATA
  const signer = await SignerClient.fromEnv();
  const algodClient = new algosdk.Algodv2("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "http://localhost", 4001);

  try {
    // Build the transfer. Both accounts must be opted into the asset, and the
    // sender must hold the amount and its fee; the helper checks all three,
    // and names the key that signs for a rekeyed sender.
    const prepared = await signer.prepareAsaTransfer(algodClient, {
      sender: SENDER,
      receiver: RECEIVER,
      assetId: ASSET_ID,
      amount: AMOUNT,
    });

    // Sign, check, submit and wait for confirmation (the server handles fee
    // pooling and any resource transactions a large LogicSig needs).
    console.log(`Sending ASA transfer for ${SENDER.slice(0, 12)}...`);
    const result = await signer.sendPrepared(algodClient, { transactions: [prepared] });
    console.log(`Confirmed ${result.txIds[0]} in round ${result.confirmedRound}`);
  } catch (error) {
    // Neither error means "send again": both transfers could execute.
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
