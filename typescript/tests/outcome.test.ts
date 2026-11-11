// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

// resolveOutcome and waitForOutcome: where things stand after an uncertain
// outcome, from a fake node alone.

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import algosdk from "algosdk";
import { SignerClient } from "../src/client.js";
import {
  SignOutcomeUnknownError,
  SignerError,
  SignerUnavailableError,
  SubmissionUncertainError,
  WaitForOutcomeError,
  errorText,
} from "../src/errors.js";
import { encodeTransaction } from "../src/encoding.js";
import { newPreparedRotating, type PreparedRotating } from "../src/rotating.js";
import type { OutcomeReport } from "../src/outcome.js";
import { fakeAccount, fakeAddress } from "./fakeSigner.js";
import { algodHttpError, installSigners, testGenesisHash } from "./fakeNetwork.js";

const SIGNER = "http://signer.test";
const LAST_VALID = 200n;

let restore: (() => void) | undefined;
afterEach(() => {
  restore?.();
  restore = undefined;
});

type Found = "confirmed" | "pool" | "pool_error" | "not_found";

/** A fake node: its last round, and what a lookup of a transaction finds. */
class OutcomeNode {
  round: bigint;
  found: Found;
  confirmedRound = 150n;
  /** Fails the status call with this error. */
  statusFailure?: Error;
  /** Fails the lookup with this error. */
  lookupFailure?: Error;
  /** Called on each wait for the next round; unset, the round advances by one. */
  onWait?: () => Promise<void> | void;
  calls: string[] = [];
  lookedUp: string[] = [];

  constructor(round: bigint, found: Found = "not_found") {
    this.round = round;
    this.found = found;
  }

  status() {
    return {
      do: async () => {
        this.calls.push("status");
        if (this.statusFailure) throw this.statusFailure;
        return { lastRound: this.round };
      },
    };
  }

  statusAfterBlock(round: bigint) {
    return {
      do: async () => {
        this.calls.push(`after ${round}`);
        if (this.onWait) {
          await this.onWait();
        } else {
          this.round = round + 1n;
        }
        return { lastRound: this.round };
      },
    };
  }

  pendingTransactionInformation(txId: string) {
    return {
      do: async () => {
        this.calls.push("lookup");
        this.lookedUp.push(txId);
        if (this.lookupFailure) throw this.lookupFailure;
        switch (this.found) {
          case "confirmed":
            return { confirmedRound: this.confirmedRound, poolError: "" };
          case "pool":
            return { poolError: "" };
          case "pool_error":
            return { poolError: "transaction already in ledger or overspend" };
          default:
            throw algodHttpError(404, "could not find the transaction in the transaction pool or in the last 1000 confirmed rounds");
        }
      },
    };
  }
}

function submissionError(lastValid: bigint = LAST_VALID, txIds = ["TXIDONE", "TXIDTWO"]): SubmissionUncertainError {
  return new SubmissionUncertainError("confirm", ["aa", "bb"], txIds, new SignerError("not confirmed after 10 rounds"), lastValid);
}

function signError(lastValid: bigint | undefined = LAST_VALID, rotating?: PreparedRotating): SignOutcomeUnknownError {
  return new SignOutcomeUnknownError({
    requestId: "sdk-lost",
    rotating,
    lastValid,
    cause: new SignerUnavailableError("Failed to connect: connection closed"),
  });
}

/** A genuine prepared rotating group: one spend, rekeyed to the next stage. */
function preparedRotating(lastValid: bigint = LAST_VALID): PreparedRotating {
  const account = fakeAccount(41);
  const original = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: account,
    receiver: fakeAddress(42),
    amount: 5000,
    suggestedParams: {
      fee: 1000, flatFee: true, minFee: 1000, firstValid: lastValid - 50n, lastValid,
      genesisID: "testnet-v1.0", genesisHash: testGenesisHash,
    },
  });
  const next = fakeAddress(77);
  const spend = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: account,
    receiver: fakeAddress(42),
    amount: 5000,
    rekeyTo: next,
    suggestedParams: {
      fee: 1000, flatFee: true, minFee: 1000, firstValid: lastValid - 50n, lastValid,
      genesisID: "testnet-v1.0", genesisHash: testGenesisHash,
    },
  });
  return newPreparedRotating(
    encodeTransaction(original)[0],
    { account, stage: 0, target: 1, rekey_to: next, transactions: [encodeTransaction(spend)[0]] },
    undefined,
    undefined,
  );
}

/** A client whose signer records every request; the helper must make none. */
function quietClient(): { client: SignerClient; signerCalls: string[] } {
  const signerCalls: string[] = [];
  restore = installSigners({
    [SIGNER]: (path) => {
      signerCalls.push(path);
      return "drop";
    },
  });
  return { client: new SignerClient(SIGNER), signerCalls };
}

interface Want {
  state: string;
  safe: boolean;
  advice: string;
  confirmedRound?: bigint;
  lookups: number;
}

function check(report: OutcomeReport, node: OutcomeNode, want: Want, label: string): void {
  assert.equal(report.state, want.state, `${label}: state ${report.state}, want ${want.state}`);
  assert.equal(report.safeToReplace, want.safe, `${label}: safeToReplace ${report.safeToReplace}`);
  assert.equal(report.advice, want.advice, `${label}: advice ${JSON.stringify(report.advice)}`);
  assert.equal(report.confirmedRound, want.confirmedRound ?? 0n, `${label}: confirmedRound ${report.confirmedRound}`);
  assert.equal(report.lastValid, LAST_VALID, `${label}: lastValid ${report.lastValid}`);
  assert.equal(report.currentRound, node.round, `${label}: currentRound ${report.currentRound}`);
  assert.equal(node.lookedUp.length, want.lookups, `${label}: ${node.lookedUp.length} lookups, want ${want.lookups}`);
}

const CONFIRMED = "The group was confirmed in round 150. Do not send it again.";
const PENDING = "The group is in the node's pool. Wait; do not send again.";
const NOT_SEEN =
  "The node does not have the group and it can still execute until round 200. " +
  "Submit the same signed group again, or wait until round 200 has passed.";
const SUBMISSION_EXPIRED = "The group was not confirmed and can no longer execute. It is safe to build a new one.";
const TOO_OLD =
  "The group's validity ended more than 500 rounds ago and this node may no longer remember it. " +
  "Look the transaction ID up on an indexer before sending again.";
const SIGNABLE_ROTATING =
  "A signature may have been released and can execute until round 200. " +
  "Sign the same prepared group again, or wait until round 200 has passed.";
const SIGNABLE =
  "A signature may have been released and can execute until round 200. " +
  "Wait until round 200 has passed before building a replacement.";
const SIGN_EXPIRED = "No signature released by that request can execute any more. It is safe to build a new one.";

describe("resolveOutcome after a SubmissionUncertainError", () => {
  const rows: Array<[string, bigint, Found, Want]> = [
    ["confirmed", 150n, "confirmed", { state: "confirmed", safe: false, advice: CONFIRMED, confirmedRound: 150n, lookups: 1 }],
    ["confirmed long ago", 5000n, "confirmed", { state: "confirmed", safe: false, advice: CONFIRMED, confirmedRound: 150n, lookups: 1 }],
    ["in the pool", 150n, "pool", { state: "pending", safe: false, advice: PENDING, lookups: 1 }],
    ["not found, still valid", 150n, "not_found", { state: "not_seen", safe: false, advice: NOT_SEEN, lookups: 1 }],
    ["not found at the last valid round", 200n, "not_found", { state: "not_seen", safe: false, advice: NOT_SEEN, lookups: 1 }],
    ["a pool error, still valid", 200n, "pool_error", { state: "not_seen", safe: false, advice: NOT_SEEN, lookups: 1 }],
    ["not found, one round past", 201n, "not_found", { state: "expired", safe: true, advice: SUBMISSION_EXPIRED, lookups: 1 }],
    ["a pool error, one round past", 201n, "pool_error", { state: "expired", safe: true, advice: SUBMISSION_EXPIRED, lookups: 1 }],
    // The 500-round margin, on both sides.
    ["not found, 500 rounds past", 700n, "not_found", { state: "expired", safe: true, advice: SUBMISSION_EXPIRED, lookups: 1 }],
    ["not found, 501 rounds past", 701n, "not_found", { state: "too_old", safe: false, advice: TOO_OLD, lookups: 1 }],
    ["a pool error, 500 rounds past", 700n, "pool_error", { state: "expired", safe: true, advice: SUBMISSION_EXPIRED, lookups: 1 }],
    ["a pool error, 501 rounds past", 701n, "pool_error", { state: "too_old", safe: false, advice: TOO_OLD, lookups: 1 }],
  ];
  for (const [name, round, found, want] of rows) {
    it(name, async () => {
      const { client, signerCalls } = quietClient();
      const node = new OutcomeNode(round, found);
      const error = submissionError();
      const report = await client.resolveOutcome(node as any, error);
      check(report, node, want, name);
      assert.deepEqual(node.lookedUp, ["TXIDONE"], "the lookup is of the first transaction ID");
      assert.deepEqual(report.txIds, error.txIds, "the report does not carry the error's transaction IDs");
      assert.deepEqual(report.signedGroup, error.signedGroup, "the report does not carry the signed group");
      assert.equal(report.rotating, undefined, "a submission outcome has no prepared rotating group");
      assert.deepEqual(node.calls[0], "status", "the round is read before the lookup");
      assert.deepEqual(signerCalls, [], "the helper called the signer");
    });
  }
});

describe("resolveOutcome after a SignOutcomeUnknownError", () => {
  const rows: Array<[string, boolean, bigint, Found, Want]> = [
    ["rotating, confirmed", true, 150n, "confirmed", { state: "confirmed", safe: false, advice: CONFIRMED, confirmedRound: 150n, lookups: 1 }],
    ["rotating, in the pool", true, 150n, "pool", { state: "pending", safe: false, advice: PENDING, lookups: 1 }],
    ["rotating, not found, still valid", true, 200n, "not_found", { state: "signable", safe: false, advice: SIGNABLE_ROTATING, lookups: 1 }],
    ["rotating, a pool error, still valid", true, 150n, "pool_error", { state: "signable", safe: false, advice: SIGNABLE_ROTATING, lookups: 1 }],
    ["rotating, not found, one round past", true, 201n, "not_found", { state: "expired", safe: true, advice: SIGN_EXPIRED, lookups: 1 }],
    ["rotating, a pool error, long past", true, 5000n, "pool_error", { state: "expired", safe: true, advice: SIGN_EXPIRED, lookups: 1 }],
    // No IDs, so no lookup, whatever the node would find.
    ["not rotating, still valid", false, 200n, "confirmed", { state: "signable", safe: false, advice: SIGNABLE, lookups: 0 }],
    ["not rotating, one round past", false, 201n, "pool", { state: "expired", safe: true, advice: SIGN_EXPIRED, lookups: 0 }],
    // There is no too_old for a sign outcome.
    ["not rotating, long past", false, 5000n, "not_found", { state: "expired", safe: true, advice: SIGN_EXPIRED, lookups: 0 }],
  ];
  for (const [name, isRotating, round, found, want] of rows) {
    it(name, async () => {
      const { client, signerCalls } = quietClient();
      const node = new OutcomeNode(round, found);
      const prepared = isRotating ? preparedRotating() : undefined;
      const report = await client.resolveOutcome(node as any, signError(LAST_VALID, prepared));
      check(report, node, want, name);
      if (prepared) {
        assert.deepEqual(report.txIds, prepared.txIds(), "a rotating report does not carry the prepared IDs");
        assert.deepEqual(node.lookedUp, [prepared.txIds()[0]], "the lookup is of the prepared spend");
        assert.equal(report.rotating, prepared, "the report does not carry the prepared group");
      } else {
        assert.deepEqual(report.txIds, [], "a non-rotating sign outcome has no transaction IDs");
        assert.equal(report.rotating, undefined, "a non-rotating report carries a prepared group");
      }
      assert.equal(report.signedGroup, undefined, "a sign outcome has no signed group");
      assert.deepEqual(signerCalls, [], "the helper called the signer");
    });
  }
});

describe("resolveOutcome refusals", () => {
  for (const [name, value] of [
    ["a plain SignerError", new SignerError("Bad request: nope")],
    ["an Error", new Error("boom")],
    ["null", null],
    ["undefined", undefined],
    ["an object shaped like the error", { lastValid: 200n, txIds: ["X"], signedGroup: [] }],
  ] as Array<[string, unknown]>) {
    it(`refuses ${name} as not an uncertain outcome`, async () => {
      const { client } = quietClient();
      const node = new OutcomeNode(150n);
      for (const call of [
        () => client.resolveOutcome(node as any, value),
        () => client.waitForOutcome(node as any, value),
      ]) {
        await assert.rejects(call(), (error: unknown) => {
          assert.ok(error instanceof SignerError, `refusal is ${String(error)}`);
          assert.equal(errorText(error), "not an uncertain outcome", "refusal text");
          return true;
        });
      }
      assert.deepEqual(node.calls, [], "the node was asked something");
    });
  }

  it("refuses an error with no last valid round", async () => {
    const { client } = quietClient();
    const node = new OutcomeNode(150n);
    for (const error of [
      new SubmissionUncertainError("submit", ["aa"], ["TXIDONE"], new Error("lost")),
      new SignOutcomeUnknownError({ requestId: "r", cause: new Error("lost") }),
      new SignOutcomeUnknownError({ requestId: "r", rotating: preparedRotating(), cause: new Error("lost") }),
    ]) {
      await assert.rejects(client.resolveOutcome(node as any, error), (refusal: unknown) => {
        assert.ok(refusal instanceof SignerError, `refusal is ${String(refusal)}`);
        assert.equal(errorText(refusal), "the error carries no last valid round", "refusal text");
        return true;
      });
    }
    assert.deepEqual(node.calls, [], "the node was asked something");
  });

  it("refuses a SubmissionUncertainError with no transaction IDs, or an empty first one", async () => {
    const { client } = quietClient();
    const node = new OutcomeNode(150n);
    for (const txIds of [[], ["", "TXIDTWO"]]) {
      await assert.rejects(client.resolveOutcome(node as any, submissionError(LAST_VALID, txIds)), (refusal: unknown) => {
        assert.ok(refusal instanceof SignerError, `refusal is ${String(refusal)}`);
        assert.equal(errorText(refusal), "the error carries no transaction IDs", `refusal text for ${JSON.stringify(txIds)}`);
        return true;
      });
    }
    assert.deepEqual(node.calls, [], "the node was asked something");
  });

  it("checks the error's type, last valid round and IDs before the algod client", async () => {
    const { client } = quietClient();
    const cases: Array<[unknown, string]> = [
      [new Error("boom"), "not an uncertain outcome"],
      [submissionError(0n, []), "the error carries no last valid round"],
      [submissionError(LAST_VALID, []), "the error carries no transaction IDs"],
      [submissionError(), "algod client is required"],
      [signError(), "algod client is required"],
    ];
    for (const [error, text] of cases) {
      for (const call of [() => client.resolveOutcome(undefined as any, error), () => client.waitForOutcome(undefined as any, error)]) {
        await assert.rejects(call(), (refusal: unknown) => {
          assert.ok(refusal instanceof SignerError && !(refusal instanceof WaitForOutcomeError), `refusal is ${String(refusal)}`);
          assert.equal(errorText(refusal), text, "refusal text");
          return true;
        });
      }
    }
  });

  const failures: Array<[string, (node: OutcomeNode) => void, () => unknown]> = [
    ["the status call fails", (node) => {
      node.statusFailure = algodHttpError(500, "internal");
    }, () => submissionError()],
    ["the lookup fails with a 500", (node) => {
      node.lookupFailure = algodHttpError(500, "internal");
    }, () => submissionError()],
    ["the lookup loses its connection", (node) => {
      node.lookupFailure = new TypeError("fetch failed");
    }, () => submissionError()],
    ["a rotating lookup fails", (node) => {
      node.lookupFailure = algodHttpError(503, "unavailable");
    }, () => signError(LAST_VALID, preparedRotating())],
    ["the status call fails for a sign outcome", (node) => {
      node.statusFailure = new TypeError("fetch failed");
    }, () => signError()],
  ];
  for (const [name, breakNode, error] of failures) {
    it(`throws when ${name}, never reporting a state`, async () => {
      const { client } = quietClient();
      const node = new OutcomeNode(150n, "not_found");
      breakNode(node);
      await assert.rejects(client.resolveOutcome(node as any, error()), (failure: unknown) => {
        assert.ok(failure instanceof SignerError, `failure is ${String(failure)}`);
        assert.ok(!("state" in (failure as object)), "the failure is a report");
        return true;
      });
    });
  }

  it("an aborted signal asks the node nothing", async () => {
    const { client } = quietClient();
    const node = new OutcomeNode(150n);
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      client.resolveOutcome(node as any, submissionError(), { signal: controller.signal }),
      /aborted by caller/,
    );
    assert.deepEqual(node.calls, [], "the node was asked something");
  });
});

describe("waitForOutcome", () => {
  it("polls once per round until the group confirms", async () => {
    const { client, signerCalls } = quietClient();
    const node = new OutcomeNode(150n, "pool");
    let waits = 0;
    node.onWait = () => {
      waits++;
      node.round++;
      if (waits === 2) node.found = "confirmed";
    };
    const report = await client.waitForOutcome(node as any, submissionError());
    assert.equal(report.state, "confirmed", `state ${report.state}`);
    assert.equal(report.confirmedRound, 150n, "confirmed round");
    assert.deepEqual(
      node.calls,
      ["status", "lookup", "after 150", "status", "lookup", "after 151", "status", "lookup"],
      `calls ${node.calls.join(", ")}`,
    );
    assert.deepEqual(signerCalls, [], "the wait called the signer");
  });

  it("waits out a sign outcome until it expires", async () => {
    const { client } = quietClient();
    const node = new OutcomeNode(199n);
    const report = await client.waitForOutcome(node as any, signError());
    assert.equal(report.state, "expired", `state ${report.state}`);
    assert.equal(report.currentRound, 201n, `current round ${report.currentRound}`);
    assert.equal(report.safeToReplace, true, "an expired outcome is safe to replace");
    assert.deepEqual(node.calls, ["status", "after 199", "status", "after 200", "status"], `calls ${node.calls.join(", ")}`);
  });

  it("returns a too_old report at once", async () => {
    const { client } = quietClient();
    const node = new OutcomeNode(701n);
    const report = await client.waitForOutcome(node as any, submissionError());
    assert.equal(report.state, "too_old", `state ${report.state}`);
    assert.ok(!node.calls.some((call) => call.startsWith("after")), "a settled outcome waited for a round");
  });

  it("ends at its time limit with the last report", async () => {
    const { client } = quietClient();
    const node = new OutcomeNode(150n, "pool");
    // A node that never produces the next round, and ignores the signal.
    node.onWait = () => new Promise<void>(() => undefined);
    await assert.rejects(client.waitForOutcome(node as any, submissionError(), { timeoutMs: 30 }), (error: unknown) => {
      assert.ok(error instanceof WaitForOutcomeError, `error is ${String(error)}`);
      assert.equal(error.report?.state, "pending", `last report ${error.report?.state}`);
      assert.match(errorText(error.cause), /did not settle within 30 ms/, "cause names the time limit");
      return true;
    });
  });

  it("ends when the caller's signal aborts, with the last report", async () => {
    const { client } = quietClient();
    const node = new OutcomeNode(150n);
    const controller = new AbortController();
    node.onWait = () => {
      controller.abort();
      return new Promise<void>(() => undefined);
    };
    await assert.rejects(
      client.waitForOutcome(node as any, signError(), { signal: controller.signal }),
      (error: unknown) => {
        assert.ok(error instanceof WaitForOutcomeError, `error is ${String(error)}`);
        assert.equal(error.report?.state, "signable", `last report ${error.report?.state}`);
        assert.ok(error.cause instanceof SignerUnavailableError, "cause is the caller's abort");
        assert.match(errorText(error.cause), /aborted by caller/, "cause text");
        return true;
      },
    );
  });

  it("an already aborted signal asks the node nothing", async () => {
    const { client } = quietClient();
    const node = new OutcomeNode(150n);
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      client.waitForOutcome(node as any, signError(), { signal: controller.signal }),
      (error: unknown) => {
        assert.ok(error instanceof WaitForOutcomeError, `error is ${String(error)}`);
        assert.equal(error.report, undefined, "a report was made");
        return true;
      },
    );
    assert.deepEqual(node.calls, [], "the node was asked something");
  });

  it("a node failure while waiting ends the wait with the last report", async () => {
    const { client } = quietClient();
    const node = new OutcomeNode(150n, "pool");
    node.onWait = () => {
      throw algodHttpError(500, "internal");
    };
    await assert.rejects(client.waitForOutcome(node as any, submissionError()), (error: unknown) => {
      assert.ok(error instanceof WaitForOutcomeError, `error is ${String(error)}`);
      assert.equal(error.report?.state, "pending", `last report ${error.report?.state}`);
      assert.match(errorText(error.cause), /^wait for round 151: /, "the cause names the wait");
      return true;
    });
  });

  it("a node failure on a later check ends the wait with the last report", async () => {
    const { client } = quietClient();
    const node = new OutcomeNode(150n, "pool");
    node.onWait = () => {
      node.round++;
      node.lookupFailure = algodHttpError(500, "internal");
    };
    await assert.rejects(client.waitForOutcome(node as any, submissionError()), (error: unknown) => {
      assert.ok(error instanceof WaitForOutcomeError, `error is ${String(error)}`);
      assert.equal(error.report?.currentRound, 150n, `last report round ${error.report?.currentRound}`);
      assert.match(errorText(error.cause), /^look up transaction TXIDONE: /, "the cause is the lookup's failure");
      return true;
    });
  });

  it("a node failure on the first check ends the wait with no report", async () => {
    const { client } = quietClient();
    const node = new OutcomeNode(150n);
    node.statusFailure = algodHttpError(500, "internal");
    await assert.rejects(client.waitForOutcome(node as any, signError()), (error: unknown) => {
      assert.ok(error instanceof WaitForOutcomeError, `error is ${String(error)}`);
      assert.equal(error.report, undefined, "a report was made");
      assert.match(errorText(error.cause), /^read the node's current round: /, "the cause is the status failure");
      return true;
    });
  });

  it("refuses a time limit that is not a number of milliseconds", async () => {
    const { client } = quietClient();
    const node = new OutcomeNode(150n);
    for (const timeoutMs of [-1, Number.NaN, Number.POSITIVE_INFINITY, "5" as unknown as number, 2 ** 31]) {
      await assert.rejects(
        client.waitForOutcome(node as any, submissionError(), { timeoutMs }),
        /timeoutMs must/,
        `timeoutMs ${String(timeoutMs)} was accepted`,
      );
    }
    assert.deepEqual(node.calls, [], "the node was asked something");
  });
});
