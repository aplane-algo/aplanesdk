import { AlgorandClient, microAlgo } from "@algorandfoundation/algokit-utils";
import { SignerClient, createApsignerAccount } from "aplanesdk";

// Minimal AlgoKit Utils example using an apsigner-backed account.
const sender = process.env.APLANE_ADDRESS;
if (!sender) throw new Error("APLANE_ADDRESS is required");

const algorand = AlgorandClient.testNet();
const signer = await SignerClient.fromEnv();

try {
  const accountInfo = await algorand.account.getInformation(sender);
  const account = createApsignerAccount({
    client: signer,
    address: sender,
    authAddress: accountInfo.authAddr?.toString() ?? sender,
  });

  const txn = await algorand.createTransaction.payment({
    sender: account.addr,
    signer: account,
    receiver: account.addr,
    amount: microAlgo(0),
    validityWindow: 1000,
  });

  const signedTxns = await account.signer([txn], [0]);
  const response = await algorand.client.algod.sendRawTransaction(signedTxns);
  console.log(response.txId);
} finally {
  signer.close();
}
