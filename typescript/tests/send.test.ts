// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

// sendPrepared and the submission layer, ported from the Go SDK's
// send_test.go.

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import algosdk, { type Transaction } from "algosdk";
import { SignerClient } from "../src/client.js";
import {
  KeyNotFoundError,
  SigningRejectedError,
  SignOutcomeUnknownError,
  SignerUnavailableError,
  SubmissionRejectedError,
  SubmissionUncertainError,
  UnsupportedGroupError,
  UnsupportedSigningFlowError,
  errorText,
} from "../src/errors.js";
import {
  SIGNING_FLOW_BOUNDED1,
  SIGNING_FLOW_COSIGNED1,
  SIGNING_FLOW_ROTATING1,
  KEY_TYPE_WITNESS_FALCON1024,
  type PreparedGroup,
} from "../src/types.js";
import { describeSignedGroup, submitAndTrack, type SendResult } from "../src/send.js";
import { SignerError, isLostAnswer, markLostAnswer } from "../src/errors.js";
import { bytesToBase64, hexToBytes } from "../src/encoding.js";
import { fakeAccount, fakeAddress, fakePayment, signedHex } from "./fakeSigner.js";
import {
  FakeAlgod,
  SendSigner,
  alternateSpellings,
  algodHttpError,
  blobHex,
  installSigners,
  signedHexOf,
  statusBody,
  type FakeReply,
  type WireKey,
} from "./fakeNetwork.js";

const SIGNER = "http://signer.test";
const COSIGNER = "http://cosigner.test";

let restore: (() => void) | undefined;
afterEach(() => {
  restore?.();
  restore = undefined;
});

function fixture(signer: SendSigner, node = new FakeAlgod()) {
  restore = installSigners({ [SIGNER]: signer.handle });
  return { client: new SignerClient(SIGNER), algod: node as any, node };
}

function ordinaryKey(txn: Transaction): WireKey {
  return { address: txn.sender.toString(), key_type: "ed25519" };
}

function preparedFor(txn: Transaction): PreparedGroup {
  return { transactions: [{ transaction: txn, authAddress: txn.sender.toString() }] };
}

/** Assert error is an instance of type whose message contains text. */
function rejectsWith(type: new (...args: any[]) => Error, text: string | RegExp) {
  return (error: unknown) => {
    assert.ok(error instanceof type, `expected ${type.name}, got ${String(error)}`);
    if (typeof text === "string") {
      assert.ok(errorText(error).includes(text), `error ${errorText(error)} does not mention ${text}`);
    } else {
      assert.match(errorText(error), text);
    }
    return true;
  };
}

describe("sendPrepared", () => {
  it("signs, submits and confirms", async () => {
    const txn = fakePayment(41, 42, 1);
    const signer = new SendSigner([ordinaryKey(txn)]);
    const { client, algod, node } = fixture(signer);

    const result = await client.sendPrepared(algod, preparedFor(txn));
    const wantHex = signedHex(txn);
    assert.deepEqual(result.signedGroup, [wantHex]);
    assert.equal(node.submitted.length, 1, "submitted exactly the signed bytes once");
    assert.equal(blobHex(node.submitted[0]), wantHex);
    assert.equal(result.outcome, "confirmed");
    assert.equal(result.confirmedRound, 12n);
    assert.equal(result.flow, "");
    assert.equal(result.originalCount, 1);
    assert.equal(result.groupId, "");
    assert.deepEqual(result.txIds, [txn.txID()]);
    assert.deepEqual(result.fees, [1000n]);
    assert.equal(signer.count("/sign"), 1);
  });

  it("reports the group ID of a group", async () => {
    const first = fakePayment(41, 42, 1);
    const second = fakePayment(43, 44, 2);
    const signer = new SendSigner([ordinaryKey(first), ordinaryKey(second)]);
    const { client, algod, node } = fixture(signer);

    const result = await client.sendPrepared(algod, {
      transactions: [
        { transaction: first, authAddress: first.sender.toString() },
        { transaction: second, authAddress: second.sender.toString() },
      ],
    });
    assert.equal(result.signedGroup.length, 2);
    assert.equal(result.originalCount, 2);
    assert.notEqual(result.groupId, "");
    // The signer assigned the group, so the signed IDs are not the drafts'.
    assert.notEqual(result.txIds[0], first.txID());
    assert.equal(node.submitted.length, 1);
    assert.equal(blobHex(node.submitted[0]), result.signedGroup.join(""));
  });

  it("returns submitted with noWait", async () => {
    const txn = fakePayment(41, 42, 1);
    const { client, algod, node } = fixture(new SendSigner([ordinaryKey(txn)]));
    const result = await client.sendPrepared(algod, preparedFor(txn), { noWait: true });
    assert.equal(result.outcome, "submitted");
    assert.equal(result.confirmedRound, 0n);
    assert.equal(node.lookups, 0);
  });

  describe("refuses before signing", () => {
    const txn = fakePayment(41, 42, 1);
    const other = fakePayment(45, 46, 1);
    const sender = txn.sender.toString();
    const holder = other.sender.toString();
    const signedBase64 = bytesToBase64(hexToBytes(signedHex(txn)));
    const cases: Array<{
      name: string;
      keys: WireKey[];
      group: PreparedGroup;
      want: new (...args: any[]) => Error;
      text: string;
    }> = [
      {
        name: "rotating sender in a group",
        keys: [{ address: sender, signing_flow: SIGNING_FLOW_ROTATING1 }, { address: holder }],
        group: {
          transactions: [
            { transaction: txn, authAddress: sender },
            { transaction: other, authAddress: holder },
          ],
        },
        want: UnsupportedGroupError,
        text: "sends one transaction alone",
      },
      {
        // After a rotation the chain names a stage address, which the signer
        // does not hold; the sender's own record decides.
        name: "rotating sender bound to a key the signer does not hold",
        keys: [{ address: sender, signing_flow: SIGNING_FLOW_ROTATING1 }],
        group: { transactions: [{ transaction: txn, authAddress: holder }] },
        want: UnsupportedGroupError,
        text: "signs as itself",
      },
      {
        name: "rekeyed to a rotating account",
        keys: [{ address: holder, signing_flow: SIGNING_FLOW_ROTATING1 }],
        group: { transactions: [{ transaction: txn, authAddress: holder }] },
        want: UnsupportedGroupError,
        text: "signs only its own transactions",
      },
      {
        name: "unknown flow",
        keys: [{ address: sender, signing_flow: "future9" }],
        group: preparedFor(txn),
        want: UnsupportedSigningFlowError,
        text: "upgrade the SDK",
      },
      {
        name: "unknown flow beside a cosigned account",
        keys: [
          { address: sender, signing_flow: SIGNING_FLOW_COSIGNED1 },
          { address: holder, signing_flow: "future9" },
        ],
        group: {
          transactions: [
            { transaction: txn, authAddress: sender },
            { transaction: other, authAddress: holder },
          ],
        },
        want: UnsupportedSigningFlowError,
        text: "upgrade the SDK",
      },
      {
        name: "pre-signed position",
        keys: [{ address: sender }],
        group: { transactions: [{ signedTransactionBase64: signedBase64 }] },
        want: UnsupportedGroupError,
        text: "already signed",
      },
      {
        name: "foreign position",
        keys: [{ address: sender }],
        group: { transactions: [{ transaction: txn }] },
        want: UnsupportedGroupError,
        text: "no auth address",
      },
      {
        name: "key not held",
        keys: [{ address: holder }],
        group: preparedFor(txn),
        want: KeyNotFoundError,
        text: "not available for signing",
      },
      {
        name: "witness record is not a spending key",
        keys: [{ address: sender, is_spending_account: false }],
        group: preparedFor(txn),
        want: KeyNotFoundError,
        text: "not available for signing",
      },
    ];
    for (const test of cases) {
      it(test.name, async () => {
        const signer = new SendSigner(test.keys);
        const { client, algod, node } = fixture(signer);
        await assert.rejects(client.sendPrepared(algod, test.group), rejectsWith(test.want, test.text));
        assert.equal(signer.count("/sign"), 0);
        assert.equal(node.submitted.length, 0);
      });
    }
  });

  describe("routes the whole group by one flow", () => {
    const first = fakePayment(41, 42, 1);
    const second = fakePayment(43, 44, 2);
    const group: PreparedGroup = {
      transactions: [
        { transaction: first, authAddress: first.sender.toString() },
        { transaction: second, authAddress: second.sender.toString() },
      ],
    };
    const cases: Array<[string, string | undefined, string | undefined, string]> = [
      ["ordinary and bounded", undefined, SIGNING_FLOW_BOUNDED1, ""],
      ["cosigned first", SIGNING_FLOW_COSIGNED1, undefined, SIGNING_FLOW_COSIGNED1],
      ["cosigned last", SIGNING_FLOW_BOUNDED1, SIGNING_FLOW_COSIGNED1, SIGNING_FLOW_COSIGNED1],
    ];
    for (const [name, firstFlow, secondFlow, want] of cases) {
      it(name, async () => {
        const signer = new SendSigner([
          { address: first.sender.toString(), signing_flow: firstFlow },
          { address: second.sender.toString(), signing_flow: secondFlow },
        ]);
        const { client } = fixture(signer);
        const { flow } = await (client as any).classifySend(group);
        assert.equal(flow, want);
      });
    }
  });

  it("requires algod before contacting the signer", async () => {
    const txn = fakePayment(41, 42, 1);
    const signer = new SendSigner([ordinaryKey(txn)]);
    const { client } = fixture(signer);
    await assert.rejects(client.sendPrepared(undefined as any, preparedFor(txn)), /algodClient is required/);
    assert.deepEqual(signer.paths, []);
  });

  describe("sign failures", () => {
    const txn = fakePayment(41, 42, 1);

    it("no answer is an unknown outcome", async () => {
      const signer = new SendSigner([ordinaryKey(txn)], { sign: () => "drop" });
      const { client, algod, node } = fixture(signer);
      await assert.rejects(client.sendPrepared(algod, preparedFor(txn)), (error: unknown) => {
        assert.ok(error instanceof SignOutcomeUnknownError, String(error));
        assert.notEqual(error.requestId, "");
        assert.equal(error.requests?.length, 1);
        assert.equal(error.requests?.[0].auth_address, txn.sender.toString());
        return true;
      });
      assert.equal(signer.count("/sign"), 1);
      assert.equal(node.submitted.length, 0);
    });

    it("an unreadable answer is an unknown outcome", async () => {
      const signer = new SendSigner([ordinaryKey(txn)], { sign: () => ({ raw: '{"signed": ["ab' }) });
      const { client, algod, node } = fixture(signer);
      await assert.rejects(client.sendPrepared(algod, preparedFor(txn)), SignOutcomeUnknownError);
      assert.equal(node.submitted.length, 0);
    });

    it("a refusal is the signer's error", async () => {
      const signer = new SendSigner([ordinaryKey(txn)], {
        sign: () => ({ status: 403, body: { error: "rejected", code: "forbidden" } }),
      });
      const { client, algod, node } = fixture(signer);
      await assert.rejects(client.sendPrepared(algod, preparedFor(txn)), (error: unknown) => {
        assert.ok(error instanceof SigningRejectedError, String(error));
        assert.ok(!(error instanceof SignOutcomeUnknownError), "want !(error instanceof SignOutcomeUnknownError)");
        return true;
      });
      assert.equal(node.submitted.length, 0);
    });

    it("a response that fails verification is never submitted", async () => {
      const altered = fakePayment(41, 42, 999);
      const signer = new SendSigner([ordinaryKey(txn)], {
        sign: () => ({ body: { signed: [signedHex(altered)] } }),
      });
      const { client, algod, node } = fixture(signer);
      await assert.rejects(client.sendPrepared(algod, preparedFor(txn)), /verify signer response/);
      assert.equal(node.submitted.length, 0);
    });

    for (const body of ["123", '"ok"', "[]", "null", '{"signed":"x"}', '{"signed":[1]}', '{"mutations":"x"}', '{"error":5}']) {
      it(`a 200 body ${body} is an unknown outcome`, async () => {
        const signer = new SendSigner([ordinaryKey(txn)], { sign: () => ({ raw: body }) });
        const { client, algod, node } = fixture(signer);
        await assert.rejects(client.sendPrepared(algod, preparedFor(txn)), (error: unknown) => {
          assert.ok(error instanceof SignOutcomeUnknownError, String(error));
          assert.equal(error.requests?.length, 1);
          return true;
        });
        assert.equal(node.submitted.length, 0);
      });
    }

    // A null entry in a list takes its zero value, as the Go SDK reads it.
    it("a null entry in signed is read as an empty entry and refused plainly", async () => {
      const signer = new SendSigner([ordinaryKey(txn)], { sign: () => ({ raw: '{"signed":[null]}' }) });
      const { client, algod, node } = fixture(signer);
      await assert.rejects(client.sendPrepared(algod, preparedFor(txn)), (error: unknown) => {
        assert.ok(!(error instanceof SignOutcomeUnknownError), String(error));
        assert.match(errorText(error), /verify signer response: signer returned no signature for position 1/);
        return true;
      });
      assert.equal(node.submitted.length, 0);
    });

    it("a null fee index is read as index 0", async () => {
      const signer = new SendSigner([ordinaryKey(txn)], {
        behaviour: {
          feeRaise: { 0: 500 },
          tamper: (body) => {
            body.mutations.fees_modified = [null];
          },
        },
      });
      const { client, algod } = fixture(signer);
      const result = await client.sendPrepared(algod, preparedFor(txn));
      assert.deepEqual(result.mutations?.feesModified, [0]);
      assert.deepEqual(result.fees, [1500n]);
    });

    it("reads only the snake_case keys of the report", async () => {
      // A report with camelCase keys alone reports nothing the Go SDK reads,
      // so the raised fee is an unreported change.
      const signer = new SendSigner([ordinaryKey(txn)], {
        behaviour: {
          feeRaise: { 0: 500 },
          tamper: (body) => {
            body.mutations = { feesModified: [0], totalFeesDelta: 500, originalCount: 1, finalCount: 1 };
          },
        },
      });
      const { client, algod } = fixture(signer);
      await assert.rejects(client.sendPrepared(algod, preparedFor(txn)), /verify signer response/);
    });

    it("the same unreadable body keeps its class and message below the send", async () => {
      const signer = new SendSigner([ordinaryKey(txn)], { sign: () => ({ raw: '{"signed":[1]}' }) });
      const { client } = fixture(signer);
      await assert.rejects(client.signTransaction(txn), (error: unknown) => {
        assert.ok(error instanceof SignerError && !(error instanceof SignOutcomeUnknownError), String(error));
        assert.match(errorText(error), /malformed response: signed\[0\] is not a string/);
        return true;
      });
    });

    it("an abort after the keys are read stops before signing", async () => {
      // The send's own check stops it, not the signing call's check on an
      // aborted signal: signRequests is never entered.
      const controller = new AbortController();
      const signer = new SendSigner([ordinaryKey(txn)]);
      const { client, algod, node } = fixture(signer);
      restore?.();
      restore = installSigners({
        [SIGNER]: (path, body) => {
          const reply = signer.handle(path, body);
          if (path === "/keys") controller.abort();
          return reply;
        },
      });
      let signCalls = 0;
      const signRequests = client.signRequests.bind(client);
      (client as any).signRequests = (...args: Parameters<typeof signRequests>) => {
        signCalls++;
        return signRequests(...args);
      };
      await assert.rejects(
        client.sendPrepared(algod, preparedFor(txn), { signal: controller.signal }),
        (error: unknown) => {
          assert.ok(error instanceof SignerUnavailableError, String(error));
          assert.ok(!(error instanceof SignOutcomeUnknownError), "want !(error instanceof SignOutcomeUnknownError)");
          return true;
        },
      );
      assert.equal(signer.count("/keys"), 1);
      assert.equal(signCalls, 0, "signing was attempted after the signal aborted");
      assert.equal(node.submitted.length, 0);
    });

    it("an already aborted signal is a plain stop", async () => {
      const signer = new SendSigner([ordinaryKey(txn)]);
      const { client, algod, node } = fixture(signer);
      const controller = new AbortController();
      controller.abort();
      await assert.rejects(
        client.sendPrepared(algod, preparedFor(txn), { signal: controller.signal }),
        (error: unknown) => {
          assert.ok(error instanceof SignerUnavailableError, String(error));
          assert.ok(!(error instanceof SignOutcomeUnknownError), "want !(error instanceof SignOutcomeUnknownError)");
          return true;
        },
      );
      assert.deepEqual(signer.paths, [], "the signer was asked something");
      assert.equal(node.submitted.length, 0);
    });
  });

  describe("submission failures keep the signed bytes", () => {
    const txn = fakePayment(41, 42, 1);
    const wantHex = signedHex(txn);
    const wantId = txn.txID();
    const cases: Array<{
      name: string;
      node: (node: FakeAlgod) => void;
      waitRounds?: number;
      rejected: boolean;
      stage?: string;
      text: string;
    }> = [
      {
        name: "node refuses the group",
        node: (node) => {
          node.submit = () => {
            throw algodHttpError(400, "overspend");
          };
        },
        rejected: true,
        text: "overspend",
      },
      {
        name: "node fails without an answer about the group",
        node: (node) => {
          node.submit = () => {
            throw algodHttpError(500, "boom");
          };
        },
        rejected: false,
        stage: "submit",
        text: "boom",
      },
      {
        name: "node reports another transaction ID",
        node: (node) => {
          node.submit = () => ({ txid: "SOMEOTHERID" });
        },
        rejected: false,
        stage: "submit",
        text: "SOMEOTHERID",
      },
      {
        name: "pool drops the group",
        node: (node) => {
          node.pending = () => ({ poolError: "fee too low" });
        },
        rejected: true,
        text: "fee too low",
      },
      {
        name: "not confirmed within the wait",
        node: (node) => {
          node.pending = () => ({});
        },
        waitRounds: 2,
        rejected: false,
        stage: "confirm",
        text: "not confirmed after 2 rounds",
      },
    ];
    for (const test of cases) {
      it(test.name, async () => {
        const signer = new SendSigner([ordinaryKey(txn)]);
        const node = new FakeAlgod();
        test.node(node);
        const { client, algod } = fixture(signer, node);
        await assert.rejects(
          client.sendPrepared(algod, preparedFor(txn), { waitRounds: test.waitRounds }),
          (error: unknown) => {
            let kept: { signedGroup: string[]; txIds: string[] };
            if (error instanceof SubmissionRejectedError) {
              assert.ok(test.rejected, `error ${errorText(error)}, want an uncertain outcome`);
              kept = error;
            } else if (error instanceof SubmissionUncertainError) {
              assert.ok(!test.rejected, `error ${errorText(error)}, want a rejection`);
              assert.equal(error.stage, test.stage);
              kept = error;
            } else {
              assert.fail(`error ${String(error)}, want a typed submission error`);
            }
            assert.ok(errorText(error).includes(test.text), errorText(error));
            assert.deepEqual(kept.signedGroup, [wantHex]);
            assert.deepEqual(kept.txIds, [wantId]);
            return true;
          },
        );
        // Nothing is signed or submitted a second time.
        assert.equal(signer.count("/sign"), 1);
        assert.equal(node.submitted.length, 1);
      });
    }
  });

  it("sendPayment prepares, then sends", async () => {
    const sender = fakeAccount(41);
    const receiver = fakeAddress(42);
    const signer = new SendSigner([{ address: sender, key_type: "ed25519" }]);
    const { client, algod, node } = fixture(signer);

    const result = await client.sendPayment(algod, { sender, receiver, amount: 1_000_000 });
    assert.equal(result.outcome, "confirmed");
    assert.equal(node.submitted.length, 1);
    const sent = algosdk.decodeSignedTransaction(node.submitted[0]);
    assert.equal(sent.txn.sender.toString(), sender);
    assert.equal(sent.txn.payment?.receiver.toString(), receiver);
    assert.equal(sent.txn.payment?.amount, 1_000_000n);
  });

  it("reports what the signer added", async () => {
    const txn = fakePayment(41, 42, 1);
    const signer = new SendSigner([ordinaryKey(txn)], { behaviour: { feeRaise: { 0: 500 }, dummies: 1 } });
    const { client, algod, node } = fixture(signer);

    const result = await client.sendPrepared(algod, preparedFor(txn));
    assert.equal(result.originalCount, 1);
    assert.equal(result.signedGroup.length, 2);
    assert.equal(result.txIds.length, 2);
    assert.notEqual(result.groupId, "");
    assert.deepEqual(result.fees, [1500n, 0n]);
    assert.equal(result.mutations?.dummiesAdded, 1);
    assert.equal(result.mutations?.totalFeesDelta, 500);
    assert.notEqual(result.txIds[0], txn.txID(), "the txid is the draft's, not the signed transaction's");
    assert.equal(node.submitted.length, 1);
    assert.equal(blobHex(node.submitted[0]), result.signedGroup.join(""));
  });

  describe("confirmation wait", () => {
    const txn = fakePayment(41, 42, 1);

    it("looks once now and once after each round of the wait", async () => {
      for (const rounds of [1, 3]) {
        const node = new FakeAlgod();
        node.pending = () => ({});
        const { client, algod } = fixture(new SendSigner([ordinaryKey(txn)]), node);
        await assert.rejects(
          client.sendPrepared(algod, preparedFor(txn), { waitRounds: rounds }),
          (error: unknown) => error instanceof SubmissionUncertainError && error.stage === "confirm",
        );
        restore?.();
        assert.equal(node.lookups, rounds + 1, `waitRounds ${rounds}`);
        // At round 10 the first wait follows round 10, so it ends when round
        // 11 exists; the wait covers exactly the next rounds.
        const want = rounds === 1 ? "10" : "10,11,12";
        assert.equal(node.waits.join(","), want);
      }
    });

    it("the largest wait does not wrap around", async () => {
      const node = new FakeAlgod();
      let lookups = 0;
      node.pending = () => (++lookups < 4 ? {} : { confirmedRound: 13n });
      const { client, algod } = fixture(new SendSigner([ordinaryKey(txn)]), node);
      const result = await client.sendPrepared(algod, preparedFor(txn), { waitRounds: (1n << 64n) - 1n });
      assert.equal(result.confirmedRound, 13n);
    });

    it("refuses a wait that is not a round count before signing", async () => {
      const signer = new SendSigner([ordinaryKey(txn)]);
      const { client, algod } = fixture(signer);
      for (const bad of [1.5, -1, 1n << 64n, "3"] as any[]) {
        await assert.rejects(client.sendPrepared(algod, preparedFor(txn), { waitRounds: bad }), /waitRounds/);
      }
      assert.equal(signer.count("/sign"), 0);
    });
  });

  it("treats an already known group as submitted", async () => {
    const txn = fakePayment(41, 42, 1);
    const node = new FakeAlgod();
    node.submit = () => {
      throw algodHttpError(400, `TransactionPool.Remember: transaction already in ledger: ${txn.txID()}`);
    };
    const { client, algod } = fixture(new SendSigner([ordinaryKey(txn)]), node);
    // The node has these bytes from an earlier submission. That is not a
    // refusal: a caller told "rejected" might sign a replacement.
    const result = await client.sendPrepared(algod, preparedFor(txn));
    assert.equal(result.outcome, "confirmed");
  });

  describe("submit failures that are not answers", () => {
    const txn = fakePayment(41, 42, 1);

    it("connection dropped on submission", async () => {
      const node = new FakeAlgod();
      node.submit = () => {
        throw new TypeError("fetch failed");
      };
      const { client, algod } = fixture(new SendSigner([ordinaryKey(txn)]), node);
      await assert.rejects(client.sendPrepared(algod, preparedFor(txn)), (error: unknown) => {
        assert.ok(error instanceof SubmissionUncertainError, String(error));
        assert.equal(error.stage, "submit");
        assert.equal(error.signedGroup.length, 1);
        return true;
      });
    });

    it("signal aborted before submission", async () => {
      const node = new FakeAlgod();
      const result: SendResult = {
        flow: "",
        signedGroup: [signedHex(txn)],
        originalCount: 1,
        txIds: [],
        groupId: "",
        fees: [],
        outcome: "submitted",
        confirmedRound: 0n,
      };
      const raw = describeSignedGroup(result);
      const controller = new AbortController();
      controller.abort();
      await assert.rejects(
        submitAndTrack(node, raw, result, { noWait: false, waitRounds: 10n, signal: controller.signal }),
        (error: unknown) => {
          assert.ok(error instanceof SubmissionUncertainError, String(error));
          assert.equal(error.stage, "unsent");
          assert.ok(error.cause instanceof SignerUnavailableError, "want error.cause instanceof SignerUnavailableError");
          assert.match(errorText(error.cause), /aborted by caller/);
          return true;
        },
      );
      assert.equal(node.submitted.length, 0, "an aborted signal still submitted");
    });
  });

  it("submitSignedGroup refuses a group without its canonical group ID", async () => {
    const first = fakePayment(41, 42, 1);
    const second = fakePayment(43, 44, 2);
    const node = new FakeAlgod();
    // Two signed transactions that were never grouped.
    await assert.rejects(
      new SignerClient(SIGNER).submitSignedGroup(node as any, [signedHex(first), signedHex(second)]),
      /verify signed group: returned transaction 1 does not carry the canonical group ID/,
    );
    assert.equal(node.submitted.length, 0);
  });

  it("refuses a signed group shorter than what was prepared", () => {
    // submitSignedGroup counts what it is given, so the check is reached
    // directly: a signer response cannot be shorter and pass its own check.
    const result: SendResult = {
      flow: "",
      signedGroup: [signedHex(fakePayment(41, 42, 1))],
      originalCount: 2,
      txIds: [],
      groupId: "",
      fees: [],
      outcome: "submitted",
      confirmedRound: 0n,
    };
    assert.throws(() => describeSignedGroup(result), /signed group has 1 transaction\(s\), fewer than the 2 prepared/);
  });

  it("submitSignedGroup submits a signed group as given", async () => {
    const txn = fakePayment(41, 42, 1);
    const node = new FakeAlgod();
    const result = await new SignerClient(SIGNER).submitSignedGroup(node as any, [signedHex(txn)]);
    assert.equal(result.outcome, "confirmed");
    assert.deepEqual(result.txIds, [txn.txID()]);
    assert.equal(blobHex(node.submitted[0]), signedHex(txn));
    await assert.rejects(
      new SignerClient(SIGNER).submitSignedGroup(node as any, [signedHex(txn) + "00"]),
      /verify signed group/,
    );
  });
});

/**
 * A signer holding one cosigned account, its cosigner, and a node. fault
 * names a user-signer path and how it fails: "<path> drop" closes the
 * connection with no answer, "<path> truncate" answers 200 with a body cut
 * short.
 */
function cosignedFixture(fault: string, cosignerFault = "") {
  const bounded = fakeAddress(21);
  const key: WireKey = {
    address: bounded,
    key_type: "aplane.falcon1024.v1",
    signing_flow: SIGNING_FLOW_COSIGNED1,
    logic_sig_resources: {
      spend: { program_bytes: 5308, argument_bytes: 3358, max_opcode_cost: 20000 },
    },
    cosigner_component_key_type: KEY_TYPE_WITNESS_FALCON1024,
    bounded_authorization: {
      contract: "bounded2",
      max_fee: 1000,
      cosigner: { component_key_type: KEY_TYPE_WITNESS_FALCON1024, public_key_hex: "aabb" },
    },
  };
  const userPaths: string[] = [];
  const user = (path: string, body: any): FakeReply => {
    userPaths.push(path);
    if (fault === `${path} drop`) return "drop";
    if (fault === `${path} truncate`) return { raw: '{"request_id": "x", "signed_gr' };
    if (fault.startsWith(`${path} body `)) return { raw: fault.slice(`${path} body `.length) };
    switch (path) {
      case "/status":
        return { body: statusBody() };
      case "/keys":
        return { body: { count: 1, keys: [key] } };
      case "/plan":
        return { body: { transactions: [body.requests[0].txn_bytes_hex] } };
      case "/sign/component":
        return {
          body: {
            request_id: body.request_id,
            components: [{
              target_index: 0,
              kind: "bounded-base",
              auth_address: bounded,
              base_signatures: ["base-sig"],
              runtime_args: { proof: "aabb" },
              assembly_receipt: "receipt",
              signature_scheme: "aplane.falcon1024.v1",
              path: "spend",
            }],
          },
        };
      case "/sign/assemble":
        return {
          body: {
            request_id: body.request_id,
            signed_group: (body.group_bytes_hex as string[]).map((txnHex) => {
              const txn = algosdk.decodeUnsignedTransaction(hexToBytes(txnHex).slice(2));
              const lsig = new algosdk.LogicSig(new Uint8Array([0x0a, 0x81, 0x01]), [new Uint8Array([1])]);
              return signedHexOf(new algosdk.SignedTransaction({ txn, lsig }));
            }),
          },
        };
      case "/sign/cancel":
        return { body: { state: "canceled" } };
      default:
        throw new Error(`unexpected user path ${path}`);
    }
  };
  let cosignerCalls = 0;
  const cosigner = (path: string, body: any): FakeReply => {
    cosignerCalls++;
    if (cosignerFault === "drop") return "drop";
    if (cosignerFault.startsWith("body ")) return { raw: cosignerFault.slice("body ".length) };
    assert.equal(path, "/sign/component");
    assert.equal(body.targets[0].component_key, "COSIGNER_COMPONENT");
    return {
      body: {
        request_id: body.request_id,
        components: [{
          kind: "cosigner",
          target_index: 0,
          signature: "cosigner-sig",
          signature_scheme: KEY_TYPE_WITNESS_FALCON1024,
        }],
      },
    };
  };
  restore = installSigners({ [SIGNER]: user, [COSIGNER]: cosigner });
  const node = new FakeAlgod();
  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: bounded,
    receiver: fakeAddress(22),
    amount: 1000,
    suggestedParams: {
      fee: 1000, flatFee: true, minFee: 1000, firstValid: 1, lastValid: 100,
      genesisID: "testnet-v1.0", genesisHash: new Uint8Array(32),
    },
  });
  return {
    userClient: new SignerClient(SIGNER),
    cosignerClient: new SignerClient(COSIGNER),
    algod: node as any,
    node,
    txn,
    cosignerCalls: () => cosignerCalls,
    userPaths,
  };
}

describe("sendPrepared with a cosigned account", () => {
  it("signs, assembles and submits the group", async () => {
    const { userClient, cosignerClient, algod, node, txn, cosignerCalls } = cosignedFixture("");
    const result = await userClient.sendPrepared(algod, preparedFor(txn), {
      cosignerClient,
      cosignerComponentKey: "COSIGNER_COMPONENT",
    });
    assert.equal(result.flow, SIGNING_FLOW_COSIGNED1);
    assert.ok(result.cosigned?.boundedAssemblyResponse, "want result.cosigned?.boundedAssemblyResponse");
    assert.equal(cosignerCalls(), 1);
    assert.equal(node.submitted.length, 1);
    assert.equal(blobHex(node.submitted[0]), result.signedGroup.join(""));
    assert.equal(result.outcome, "confirmed");
    assert.equal(result.txIds[0], txn.txID());
    assert.equal(result.fees[0], 1000n);
  });

  it("refuses without a cosigner", async () => {
    const { userClient, algod, node, txn } = cosignedFixture("");
    await assert.rejects(userClient.sendPrepared(algod, preparedFor(txn)), (error: unknown) => {
      assert.match(errorText(error), /cosignerClient or cosignerResolver is required/);
      assert.ok(!(error instanceof SignOutcomeUnknownError), "want !(error instanceof SignOutcomeUnknownError)");
      return true;
    });
    assert.equal(node.submitted.length, 0);
  });

  describe("lost answers", () => {
    const cases: Array<[string, boolean]> = [
      // Approval-bearing steps: the signer may have acted.
      ["/sign/component drop", true],
      ["/sign/component truncate", true],
      ["/sign/assemble drop", true],
      ["/sign/assemble truncate", true],
      // Planning releases nothing, so its failure is a plain error.
      ["/plan drop", false],
      ["/plan truncate", false],
      // Nor does key listing.
      ["/keys drop", false],
    ];
    for (const [fault, unknown] of cases) {
      it(fault, async () => {
        const { userClient, cosignerClient, algod, node, txn } = cosignedFixture(fault);
        await assert.rejects(
          userClient.sendPrepared(algod, preparedFor(txn), {
            cosignerClient,
            cosignerComponentKey: "COSIGNER_COMPONENT",
          }),
          (error: unknown) => {
            assert.equal(error instanceof SignOutcomeUnknownError, unknown, String(error));
            return true;
          },
        );
        assert.equal(node.submitted.length, 0);
      });
    }
  });

  // A 200 body that cannot be read as the step's answer may stand for a
  // released signature, as an unparseable one does. A body that reads as the
  // answer and then fails its check is a plain refusal.
  describe("unreadable 200 answers", () => {
    const unreadable = ["123", '"ok"', "[]", "null"];
    const cases: Array<[string, string, boolean]> = [
      ...unreadable.map((body): [string, string, boolean] => ["/sign/component", body, true]),
      ["/sign/component", '{"components":"x"}', true],
      ["/sign/component", '{"components":[1]}', true],
      ["/sign/component", '{"request_id":7}', true],
      ...unreadable.map((body): [string, string, boolean] => ["/sign/assemble", body, true]),
      ["/sign/assemble", '{"signed_group":"x"}', true],
      ["/sign/assemble", '{"signed_group":[1]}', true],
      // Read as an answer, as the Go SDK reads it (an unknown field is
      // ignored), and refused by the check.
      ["/sign/component", '{"signed":"x"}', false],
      ["/sign/assemble", '{"signed":[1]}', false],
      // A null entry in a list takes its zero value, which the check refuses.
      ["/sign/component", '{"components":[null]}', false],
      ["/sign/assemble", '{"signed_group":[null]}', false],
    ];
    for (const [path, body, unknown] of cases) {
      it(`${path} answering ${body}`, async () => {
        const { userClient, cosignerClient, algod, node, txn } = cosignedFixture(`${path} body ${body}`);
        await assert.rejects(
          userClient.sendPrepared(algod, preparedFor(txn), {
            cosignerClient,
            cosignerComponentKey: "COSIGNER_COMPONENT",
          }),
          (error: unknown) => {
            assert.equal(error instanceof SignOutcomeUnknownError, unknown, String(error));
            return true;
          },
        );
        assert.equal(node.submitted.length, 0);
      });
    }
    for (const body of [...unreadable, '{"components":[1]}']) {
      it(`the cosigner answering ${body}`, async () => {
        const { userClient, cosignerClient, algod, txn } = cosignedFixture("", `body ${body}`);
        await assert.rejects(
          userClient.sendPrepared(algod, preparedFor(txn), {
            cosignerClient,
            cosignerComponentKey: "COSIGNER_COMPONENT",
          }),
          SignOutcomeUnknownError,
        );
      });
    }
  });

  it("an aborted signal asks the signer nothing", async () => {
    const { userClient, cosignerClient, algod, node, txn, cosignerCalls, userPaths } = cosignedFixture("");
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      userClient.sendPrepared(algod, preparedFor(txn), {
        cosignerClient,
        cosignerComponentKey: "COSIGNER_COMPONENT",
        signal: controller.signal,
      }),
      (error: unknown) => {
        assert.ok(error instanceof SignerUnavailableError, String(error));
        assert.ok(!(error instanceof SignOutcomeUnknownError), "a plain stop, not an unknown outcome");
        return true;
      },
    );
    assert.deepEqual(userPaths, []);
    assert.equal(cosignerCalls(), 0);
    assert.equal(node.submitted.length, 0);
  });

  it("a lost answer from the cosigner is an unknown outcome", async () => {
    // The cosigner's component request releases a signature too.
    const { userClient, cosignerClient, algod, node, txn } = cosignedFixture("", "drop");
    await assert.rejects(
      userClient.sendPrepared(algod, preparedFor(txn), {
        cosignerClient,
        cosignerComponentKey: "COSIGNER_COMPONENT",
      }),
      SignOutcomeUnknownError,
    );
    assert.equal(node.submitted.length, 0);
  });
});

// A rotating account rekeyed to an ordinary key the signer holds has left
// rotation: that key signs for it through the ordinary flow, once the chain
// confirms the rekey.
describe("an account that left rotation", () => {
  const txn = fakePayment(41, 42, 1);
  const sender = txn.sender.toString();
  const holder = fakeAccount(45);
  const keys: WireKey[] = [
    { address: sender, signing_flow: SIGNING_FLOW_ROTATING1 },
    { address: holder, key_type: "ed25519" },
  ];
  const group: PreparedGroup = { transactions: [{ transaction: txn, authAddress: holder }] };

  it("is signed by its key once the chain confirms the rekey", async () => {
    const signer = new SendSigner(keys);
    const node = new FakeAlgod();
    node.authAddrs[sender] = holder;
    const { client, algod } = fixture(signer, node);
    const result = await client.sendPrepared(algod, group);
    assert.equal(result.flow, "");
    assert.equal(signer.count("/sign"), 1);
    const sent = algosdk.decodeSignedTransaction(node.submitted[0]);
    assert.equal(sent.sgnr?.toString(), holder, "signed by the key the position named");
  });

  // A caller cannot have an ordinary key sign for an account that is still
  // rotating: nothing is asked of the signer.
  for (const [name, chainAuth] of [["still at stage 0", ""], ["rotated to a stage", fakeAddress(77)]]) {
    it(`is refused when ${name}`, async () => {
      const signer = new SendSigner(keys);
      const node = new FakeAlgod();
      if (chainAuth) node.authAddrs[sender] = chainAuth;
      const { client, algod } = fixture(signer, node);
      await assert.rejects(client.sendPrepared(algod, group), rejectsWith(UnsupportedGroupError, "is not rekeyed to it"));
      assert.equal(signer.count("/sign"), 0);
      assert.equal(node.submitted.length, 0);
    });
  }

  it("resolves to the held key", async () => {
    const { client } = fixture(new SendSigner(keys));
    const resolved = await client.resolveAuthAddress(sender, () => holder);
    assert.equal(resolved.authAddress, holder);
    assert.equal(resolved.isRekeyed, true);
    assert.equal(resolved.chainAuthAddress, holder);
  });

  // A still-rotating account must never be signed for by an ordinary key,
  // however its address or the key's is spelled. algosdk reads the alternate
  // spellings of an address (the unused low bits of the last character) as
  // the address, and the SDK compares addresses as strings.
  describe("with addresses in alternate spellings", () => {
    const spelled = alternateSpellings(sender)[0];
    const misspelledTxn = fakePayment(41, 42, 1, spelled);

    it("builds the transaction with the canonical sender", () => {
      assert.notEqual(spelled, sender);
      assert.equal(misspelledTxn.sender.toString(), sender);
    });

    const cases: Array<{ name: string; authAddress: string; chainAuth?: string; text: string }> = [
      { name: "a misspelled sender naming a held key", authAddress: holder, text: "is not rekeyed to it" },
      { name: "a misspelled held key", authAddress: alternateSpellings(holder)[0], text: "signs as itself" },
      { name: "the sender misspelled as its own auth address", authAddress: alternateSpellings(sender)[1], text: "signs as itself" },
      {
        name: "a chain that reports the held key misspelled",
        authAddress: holder,
        chainAuth: alternateSpellings(holder)[2],
        text: "is not rekeyed to it",
      },
    ];
    for (const test of cases) {
      it(`refuses ${test.name} before any /sign`, async () => {
        const signer = new SendSigner(keys);
        const node = new FakeAlgod();
        if (test.chainAuth) node.authAddrs[sender] = test.chainAuth;
        const { client, algod } = fixture(signer, node);
        await assert.rejects(
          client.sendPrepared(algod, { transactions: [{ transaction: misspelledTxn, authAddress: test.authAddress }] }),
          rejectsWith(UnsupportedGroupError, test.text),
        );
        assert.equal(signer.count("/sign"), 0, "an ordinary key was asked to sign for a rotating account");
        assert.equal(node.submitted.length, 0);
      });
    }
  });
});

describe("the lost-answer mark", () => {
  it("is a hidden property under a registered symbol that keeps the error as it was", () => {
    const error = new SignerUnavailableError("Failed to connect: fetch failed");
    const keys = Object.keys(error);
    const json = JSON.stringify(error);
    assert.equal(markLostAnswer(error), error);
    assert.ok(isLostAnswer(error), "want isLostAnswer(error)");
    assert.ok(error instanceof SignerUnavailableError, "want error instanceof SignerUnavailableError");
    assert.equal(error.message, "Failed to connect: fetch failed");
    assert.deepEqual(Object.keys(error), keys, "the mark is enumerable");
    assert.equal(JSON.stringify(error), json);
    assert.equal((error as any)[Symbol.for("aplanesdk.lostAnswer")], true);
    assert.equal(isLostAnswer(new SignerError("refused")), false);
    assert.equal(isLostAnswer(undefined), false);
    assert.equal(isLostAnswer("text"), false);
  });

  it("is recognised through a cause chain", () => {
    const lost = markLostAnswer(new SignerError("Server returned invalid JSON"));
    const wrapped = new SignerError("assembly failed");
    (wrapped as any).cause = lost;
    const outer = new Error("send failed");
    (outer as any).cause = wrapped;
    assert.ok(isLostAnswer(wrapped), "want isLostAnswer(wrapped)");
    assert.ok(isLostAnswer(outer), "want isLostAnswer(outer)");
    // A cycle ends the walk.
    const cyclic = new Error("a");
    (cyclic as any).cause = cyclic;
    assert.equal(isLostAnswer(cyclic), false);
  });

  it("is read from an error another copy of the package marked", () => {
    // Another build (ESM or CommonJS) has its own module state but the same
    // registered symbol.
    const error = new Error("fetch failed");
    Object.defineProperty(error, Symbol.for("aplanesdk.lostAnswer"), { value: true });
    assert.ok(isLostAnswer(error), "want isLostAnswer(error)");
  });
});
