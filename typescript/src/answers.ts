// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * How the SDK reads a signer's 200 answer: as the Go SDK decodes it into its
 * typed struct. The body is exactly one JSON object; a field left out or null
 * takes its zero value; a null entry in a list takes its element's zero
 * value; an unknown field is ignored; a field of the wrong type, a number
 * outside the field's range, a null or non-object body, an empty or cut-off
 * body, and anything after the object make the answer unreadable.
 *
 * A number must be an integer a JavaScript number holds exactly (a safe
 * integer): JSON.parse rounds anything larger, so it cannot be read exactly
 * and is unreadable. And JSON.parse does not keep how a number was written,
 * so 3.0 is read as 3, where the Go SDK would refuse it.
 *
 * For an approval-bearing request an unreadable answer is a lost answer: the
 * signer may have acted on the request. An answer that is read and then
 * fails a check is a plain refusal.
 */

export type AnswerShape =
  | "string"
  | "bool"
  | "int"
  | "uint"
  | { list: AnswerShape }
  | { map: AnswerShape }
  | { fields: Record<string, AnswerShape> };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The value a missing entry of shape takes. */
function zeroValue(shape: AnswerShape): unknown {
  if (shape === "string") return "";
  if (shape === "bool") return false;
  if (shape === "int" || shape === "uint") return 0;
  if ("list" in shape) return [];
  if ("map" in shape) return {};
  return {};
}

class Unreadable extends Error {}

/** value read as shape: a copy, with null entries given their zero values. */
function readValue(shape: AnswerShape, value: unknown, where: string): unknown {
  if (shape === "string") {
    if (typeof value !== "string") throw new Unreadable(`${where} is not a string`);
    return value;
  }
  if (shape === "bool") {
    if (typeof value !== "boolean") throw new Unreadable(`${where} is not a boolean`);
    return value;
  }
  if (shape === "int") {
    if (!Number.isSafeInteger(value)) throw new Unreadable(`${where} is not an integer the SDK can read exactly`);
    return value;
  }
  if (shape === "uint") {
    if (!Number.isSafeInteger(value) || (value as number) < 0) {
      throw new Unreadable(`${where} is not an unsigned integer the SDK can read exactly`);
    }
    return value;
  }
  if ("list" in shape) {
    if (!Array.isArray(value)) throw new Unreadable(`${where} is not a list`);
    return value.map((item, index) =>
      item === null ? zeroValue(shape.list) : readValue(shape.list, item, `${where}[${index}]`));
  }
  if ("map" in shape) {
    if (!isPlainObject(value)) throw new Unreadable(`${where} is not an object`);
    const read: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      read[key] = item === null ? zeroValue(shape.map) : readValue(shape.map, item, `${where}.${key}`);
    }
    return read;
  }
  if (!isPlainObject(value)) throw new Unreadable(`${where || "the answer"} is not an object`);
  // Unknown fields are kept as they are and read by nothing.
  const read: Record<string, unknown> = { ...value };
  for (const [name, field] of Object.entries(shape.fields)) {
    const item = value[name];
    if (item === undefined || item === null) {
      delete read[name];
      continue;
    }
    read[name] = readValue(field, item, where ? `${where}.${name}` : name);
  }
  return read;
}

/**
 * Read a parsed 200 body as shape. Returns the answer, a copy in which a null
 * field is left out and a null list entry has its zero value, or the reason
 * it cannot be read. The body itself must be an object.
 */
export function readAnswer<T>(shape: AnswerShape, body: unknown): { answer: T } | { problem: string } {
  try {
    return { answer: readValue(shape, body, "") as T };
  } catch (error) {
    if (error instanceof Unreadable) return { problem: error.message };
    throw error;
  }
}

const MUTATION_REPORT: AnswerShape = {
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
export const GROUP_SIGN_ANSWER: AnswerShape = {
  fields: { signed: { list: "string" }, mutations: MUTATION_REPORT, error: "string" },
};

/** /sign/rotating/prepare */
export const ROTATING_PREPARE_ANSWER: AnswerShape = {
  fields: {
    account: "string",
    stage: "uint",
    target: "uint",
    rekey_to: "string",
    transactions: { list: "string" },
    mutations: MUTATION_REPORT,
  },
};

/** /sign/rotating/sign */
export const ROTATING_SIGN_ANSWER: AnswerShape = {
  fields: {
    signed: { list: "string" },
    stage: "uint",
    target: "uint",
    txid: "string",
    group_id: "string",
  },
};

const COMPONENT: AnswerShape = {
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
export const COMPONENT_ANSWER: AnswerShape = {
  fields: { request_id: "string", components: { list: COMPONENT }, error: "string" },
};

/** /sign/assemble */
export const ASSEMBLY_ANSWER: AnswerShape = {
  fields: { request_id: "string", signed_group: { list: "string" }, error: "string" },
};
