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
import { SignOutcomeUnknownError, SignerClient, SubmissionUncertainError } from "aplanesdk";

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
    // Neither error means "claim again" with a new transaction: ask the node
    // where things stand.
    if (error instanceof SubmissionUncertainError) {
      console.error(`Outcome unknown for ${error.txIds.join(", ")} (${error.stage}): ${error.message}`);
      console.error(await advice(signer, algodClient, error));
    } else if (error instanceof SignOutcomeUnknownError) {
      console.error(`Sign outcome unknown (request ${error.requestId || "(no ID)"}): ${error.message}`);
      console.error(await advice(signer, algodClient, error));
    }
    throw error;
  } finally {
    await signer.close();
  }
}

/**
 * Where an uncertain outcome stands, asked of the node; it signs and submits
 * nothing. A check that fails is said as such, and the error it was asked
 * about is still the one that is thrown.
 */
async function advice(
  signer: SignerClient,
  algodClient: algosdk.Algodv2,
  error: SubmissionUncertainError | SignOutcomeUnknownError,
): Promise<string> {
  try {
    const report = await signer.resolveOutcome(algodClient, error);
    return `${report.state}: ${report.advice}`;
  } catch (checkError) {
    const reason = checkError instanceof Error ? checkError.message : String(checkError);
    return `Could not check the outcome (${reason}); look the transaction up before sending again.`;
  }
}

main().catch(console.error);
