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
import { SignOutcomeUnknownError, SignerClient, SubmissionUncertainError } from "aplanesdk";

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
