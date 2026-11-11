// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * The shapes of the 200 answers to approval-bearing requests. A 200 answer is
 * read as the Go SDK decodes it: a field that is absent or null takes its zero
 * value, an unknown field is ignored, and a field of the wrong type makes the
 * whole answer unreadable. An unreadable answer is a lost answer: the signer
 * may have acted on the request. An answer of the right shape that then fails
 * a check is a plain refusal.
 */

type Shape =
  | "string"
  | "bool"
  | "int"
  | "uint"
  | { list: Shape }
  | { map: Shape }
  | { fields: Record<string, Shape> };

const INT_LIMIT = 2 ** 63;
// 2**64 itself, because a uint64 near the top arrives rounded up to it.
const UINT_LIMIT = 2 ** 64;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** What about value does not fit shape, or undefined when it fits. */
function shapeProblem(shape: Shape, value: unknown, where: string): string | undefined {
  if (shape === "string") {
    return typeof value === "string" ? undefined : `${where} is not a string`;
  }
  if (shape === "bool") {
    return typeof value === "boolean" ? undefined : `${where} is not a boolean`;
  }
  if (shape === "int") {
    return typeof value === "number" && Number.isInteger(value) && Math.abs(value) <= INT_LIMIT
      ? undefined
      : `${where} is not an integer`;
  }
  if (shape === "uint") {
    return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= UINT_LIMIT
      ? undefined
      : `${where} is not an unsigned integer`;
  }
  if ("list" in shape) {
    if (!Array.isArray(value)) return `${where} is not a list`;
    for (let index = 0; index < value.length; index++) {
      const problem = shapeProblem(shape.list, value[index], `${where}[${index}]`);
      if (problem) return problem;
    }
    return undefined;
  }
  if ("map" in shape) {
    if (!isPlainObject(value)) return `${where} is not an object`;
    for (const [key, item] of Object.entries(value)) {
      const problem = shapeProblem(shape.map, item, `${where}.${key}`);
      if (problem) return problem;
    }
    return undefined;
  }
  if (!isPlainObject(value)) return `${where} is not an object`;
  for (const [name, field] of Object.entries(shape.fields)) {
    const item = value[name];
    if (item === undefined || item === null) continue;
    const problem = shapeProblem(field, item, where ? `${where}.${name}` : name);
    if (problem) return problem;
  }
  return undefined;
}

/**
 * What makes a parsed 200 body unreadable as the answer shape describes, or
 * undefined when it can be read. The body itself must be an object.
 */
export function answerProblem(shape: Shape, body: unknown): string | undefined {
  if (!isPlainObject(body)) return "the answer is not an object";
  return shapeProblem(shape, body, "");
}

const MUTATION_REPORT: Shape = {
  fields: {
    dummies_added: "int",
    group_id_changed: "bool",
    fees_modified: { list: "int" },
    total_fees_delta: "int",
    original_count: "int",
    final_count: "int",
    passthrough_count: "int",
    foreign_count: "int",
    reason: "string",
  },
};

/** /sign */
export const GROUP_SIGN_ANSWER: Shape = {
  fields: { signed: { list: "string" }, mutations: MUTATION_REPORT, error: "string" },
};

/** /sign/rotating/sign */
export const ROTATING_SIGN_ANSWER: Shape = {
  fields: {
    signed: { list: "string" },
    stage: "uint",
    target: "uint",
    txid: "string",
    group_id: "string",
  },
};

const COMPONENT: Shape = {
  fields: {
    target_index: "int",
    kind: "string",
    signature: "string",
    signature_scheme: "string",
    auth_address: "string",
    base_signatures: { list: "string" },
    runtime_args: { map: "string" },
    assembly_receipt: "string",
    path: "string",
  },
};

/** /sign/component */
export const COMPONENT_ANSWER: Shape = {
  fields: { request_id: "string", components: { list: COMPONENT }, error: "string" },
};

/** /sign/assemble */
export const ASSEMBLY_ANSWER: Shape = {
  fields: { request_id: "string", signed_group: { list: "string" }, error: "string" },
};

export type AnswerShape = Shape;
