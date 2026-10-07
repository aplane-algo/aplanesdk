// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

import assert from "node:assert/strict";
import test from "node:test";

import {
  CLIENT_SSH_KEY_REQUIREMENT,
  DEFAULT_SSH_SETUP_TIMEOUT_MS,
  MAX_SSH_SETUP_TIMEOUT_MS,
  SSH_ENROLLMENT_USERNAME,
  SSH_USERNAME,
  normalizeSSHSetupTimeout,
  sshConnectionFailedMessage,
  validateEnrollmentLabel,
} from "../src/ssh.js";

test("SSH usernames match the signer's fixed usernames", () => {
  assert.equal(SSH_USERNAME, "aplane");
  assert.equal(SSH_ENROLLMENT_USERNAME, "request-enrollment");
});

test("SSH setup timeout rejects values Node timers cannot represent", () => {
  assert.equal(normalizeSSHSetupTimeout(undefined), DEFAULT_SSH_SETUP_TIMEOUT_MS);
  assert.equal(normalizeSSHSetupTimeout(MAX_SSH_SETUP_TIMEOUT_MS), MAX_SSH_SETUP_TIMEOUT_MS);
  for (const value of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => normalizeSSHSetupTimeout(value), /positive number/);
  }
  for (const value of [MAX_SSH_SETUP_TIMEOUT_MS + 1, Number.MAX_SAFE_INTEGER]) {
    assert.throws(() => normalizeSSHSetupTimeout(value), /must not exceed/);
  }
});

test("SSH authentication failures name the key types the signer accepts", () => {
  const authFailure = Object.assign(new Error("All configured authentication methods failed"), {
    level: "client-authentication",
  });
  const clientMessage = sshConnectionFailedMessage(authFailure);
  assert.ok(clientMessage.includes(CLIENT_SSH_KEY_REQUIREMENT));
  assert.ok(clientMessage.includes("not enrolled"));
  const enrollmentMessage = sshConnectionFailedMessage(authFailure, SSH_ENROLLMENT_USERNAME);
  assert.ok(enrollmentMessage.includes(CLIENT_SSH_KEY_REQUIREMENT));
  assert.ok(!enrollmentMessage.includes("not enrolled"));

  const otherFailure = new Error("connect ECONNREFUSED");
  assert.equal(sshConnectionFailedMessage(otherFailure), "SSH connection failed: connect ECONNREFUSED");
});

test("enrollment labels are bounded, printable, and single-line", () => {
  validateEnrollmentLabel("");
  validateEnrollmentLabel("ci runner 01");
  assert.throws(() => validateEnrollmentLabel("x".repeat(65)), /at most 64 bytes/);
  assert.throws(() => validateEnrollmentLabel("two\nlines"), /printable and single-line/);
  assert.throws(() => validateEnrollmentLabel(" padded"), /whitespace/);
});
