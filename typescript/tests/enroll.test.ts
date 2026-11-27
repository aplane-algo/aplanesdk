// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

// requestEnrollment against an ssh2 server that answers the enroll exec as
// the node does: a reply on stdout and an exit status (1 when it refuses).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import ssh2 from "ssh2";
import {
  MAX_ENROLLMENT_ERROR_BYTES,
  parseEnrollmentReply,
  requestEnrollment,
  safeEnrollmentText,
  type EnrollmentResult,
} from "../src/utils.js";
import { publicBlob, rsaPem } from "./fakeSshNode.js";

const { Server, Client } = ssh2;

const ESC = String.fromCharCode(0x1b);
const RLO = String.fromCharCode(0x202e);

async function enrollAgainstServer(
  reply: Buffer | string,
  status: number,
  noClientAuth = false,
): Promise<EnrollmentResult> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-enroll-"));
  const clientKey = rsaPem();
  const keyPath = path.join(tmpDir, "id_rsa");
  fs.writeFileSync(keyPath, clientKey, { mode: 0o600 });
  const fingerprint = "SHA256:" +
    createHash("sha256").update(publicBlob(clientKey)).digest("base64").replace(/=+$/, "");
  const answer = Buffer.isBuffer(reply) ? reply : Buffer.from(reply.replaceAll("{fp}", fingerprint));

  const server = new Server({ hostKeys: [rsaPem()] }, (connection) => {
    connection.on("error", () => {});
    connection.on("authentication", (ctx) => {
      if (ctx.method === "none" && noClientAuth) return ctx.accept();
      if (ctx.method === "publickey") return ctx.accept();
      ctx.reject(["publickey"]);
    });
    connection.on("session", (acceptSession) => {
      acceptSession().on("exec", (acceptExec) => {
        const stream = acceptExec();
        stream.on("error", () => {});
        stream.write(answer);
        stream.exit(status);
        stream.end();
      });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  try {
    return await requestEnrollment("127.0.0.1", keyPath, {
      sshPort: address.port,
      knownHostsPath: path.join(tmpDir, "known_hosts"),
      autoAddHost: true,
      setupTimeout: 10_000,
    });
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(tmpDir, { recursive: true });
  }
}

describe("requestEnrollment against a node", () => {
  it("accepts an answer for the key it authenticated with", async () => {
    const result = await enrollAgainstServer("pending {fp}\n", 0);
    assert.equal(result.pending, true);
    assert.match(result.fingerprint, /^SHA256:/);
  });

  it("refuses a server that lets it in without its key's signature", async (t) => {
    // The SDK offers only its key; stand in for a client library that lets
    // the server skip that step.
    const connect = Client.prototype.connect;
    t.mock.method(Client.prototype, "connect", function (this: InstanceType<typeof Client>, config: ssh2.ConnectConfig) {
      return connect.call(this, { ...config, authHandler: ["none"] });
    });
    await assert.rejects(
      enrollAgainstServer("pending {fp}\n", 0, true),
      /did not authenticate this client's SSH key/,
    );
  });

  it("escapes an unexpected answer", () => {
    assert.throws(
      () => parseEnrollmentReply(`hello ${RLO}\u009b2J\x7f`, "SHA256:abc"),
      (error: Error) => {
        assert.equal(error.message, 'Unexpected enrollment response: "hello \\u202e\\u009b2J\\x7f"');
        return true;
      },
    );
  });

  it("refuses a public key file before connecting", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aplane-enroll-pub-"));
    const keyPath = path.join(tmpDir, "id_ed25519.pub");
    fs.writeFileSync(keyPath, ssh2.utils.generateKeyPairSync("ed25519").public);
    try {
      await assert.rejects(
        requestEnrollment("127.0.0.1", keyPath, { sshPort: 1, knownHostsPath: path.join(tmpDir, "known_hosts") }),
        /is not a private key/,
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it("refuses an oversized reply", async () => {
    await assert.rejects(enrollAgainstServer("x".repeat(4097), 0), /exceeded 4096 bytes/);
  });

  it("escapes and caps the refusal text", async () => {
    const reply = Buffer.concat([
      Buffer.from(`ERROR: ${ESC}[2Jqueue${RLO}full `),
      Buffer.from([0xff]),
      Buffer.from("y".repeat(400) + "\n"),
    ]);
    await assert.rejects(enrollAgainstServer(reply, 1), (error: Error) => {
      assert.ok(error.message.startsWith("\\x1b[2Jqueue\\u202efull \\xffyyy"), error.message);
      assert.ok(!error.message.includes(ESC) && !error.message.includes(RLO));
      assert.ok(error.message.endsWith("..."));
      assert.equal(Buffer.byteLength(error.message), MAX_ENROLLMENT_ERROR_BYTES + 3);
      return true;
    });
  });
});

describe("safeEnrollmentText", () => {
  it("escapes what does not print as itself, as Go does", () => {
    const cases: Array<[string | Buffer, string]> = [
      ["queue is full", "queue is full"],
      ["tab\there\nnewline", "tab\\there\\nnewline"],
      [`bell\x07 esc${ESC} del\x7f`, "bell\\a esc\\x1b del\\x7f"],
      [`c1\u0085 bidi${RLO} zero-width\u200b`, "c1\\u0085 bidi\\u202e zero-width\\u200b"],
      [Buffer.from([0x62, 0x61, 0x64, 0xff, 0x62]), "bad\\xffb"],
      [Buffer.from([0xc0, 0xaf]), "\\xc0\\xaf"],
      [Buffer.from([0xed, 0xa0, 0x80]), "\\xed\\xa0\\x80"],
      ["caf\u00e9 \u2713 \u{1F600}", "caf\u00e9 \u2713 \u{1F600}"],
    ];
    for (const [input, want] of cases) {
      assert.equal(safeEnrollmentText(input), want);
    }
  });

  it("cuts between characters", () => {
    const limit = MAX_ENROLLMENT_ERROR_BYTES;
    assert.equal(safeEnrollmentText("a".repeat(limit - 2) + ESC), "a".repeat(limit - 2) + "...");
    assert.equal(safeEnrollmentText("a".repeat(limit - 1) + "\u00e9"), "a".repeat(limit - 1) + "...");
  });
});
