// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

/**
 * How the SDK reads a signer's 200 answer: as the Go SDK decodes it into its
 * typed struct. The body is exactly one JSON object; an unknown field is
 * ignored; a field of the wrong type, a number outside the field's range, a
 * null or non-object body, an empty or cut-off body, and anything after the
 * object make the answer unreadable.
 *
 * Null means zero at every depth, as in Go. A string, boolean or number
 * field left out or null reads as "", false or 0, in the answer and in every
 * object nested in it, unless it is declared optional (a Go pointer), when it
 * is left out. A list, map or object field left out or null is left out, and
 * its reader takes it as empty, as Go reads a nil one. A null entry in a list
 * or map reads as its element's zero value: an object entry as an object of
 * zero values.
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
  | { fields: Record<string, AnswerShape> }
  /** A field Go declares as a pointer: left out or null, it is left out. */
  | { optional: AnswerShape };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isScalar(shape: AnswerShape): shape is "string" | "bool" | "int" | "uint" {
  return typeof shape === "string";
}

/** The value a null entry of shape in a list or map takes. */
function zeroValue(shape: AnswerShape): unknown {
  if (shape === "string") return "";
  if (shape === "bool") return false;
  if (shape === "int" || shape === "uint") return 0;
  if ("list" in shape) return [];
  if ("map" in shape) return {};
  if ("optional" in shape) return undefined;
  return readValue(shape, {}, "");
}

class Unreadable extends Error {}

/** value read as shape: a copy, with null and missing values read as zero. */
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
  if ("optional" in shape) {
    return readValue(shape.optional, value, where);
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
      if (isScalar(field)) {
        read[name] = zeroValue(field);
      } else {
        delete read[name];
      }
      continue;
    }
    read[name] = readValue(field, item, where ? `${where}.${name}` : name);
  }
  return read;
}

/**
 * Read a parsed 200 body as shape. Returns the answer, a copy in which null
 * and missing values are read as the comment above says, or the reason it
 * cannot be read. The body itself must be an object.
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

// The shapes below follow the Go SDK's types (go/types.go), field for field:
// a field Go does not declare is not read, and a Go pointer is optional.

/** /plan */
export const PLAN_ANSWER: AnswerShape = {
  fields: { transactions: { list: "string" }, mutations: MUTATION_REPORT, error: "string" },
};

/** /sign/cancel */
export const CANCEL_ANSWER: AnswerShape = {
  fields: { success: "bool", state: "string", error: "string" },
};

/** DELETE /admin/keys */
export const DELETE_KEY_ANSWER: AnswerShape = {
  fields: { success: "bool", error: "string" },
};

/** /admin/generate */
export const GENERATE_ANSWER: AnswerShape = {
  fields: {
    address: "string",
    public_key_hex: "string",
    key_type: "string",
    is_witness_key: "bool",
    is_spending_account: { optional: "bool" },
    parameters: { map: "string" },
    error: "string",
  },
};

const ROTATING_RECOVERY_STATUS: AnswerShape = {
  fields: {
    active: "bool",
    kind: "string",
    grant_id: "uint",
    stages_charged: "uint",
    max_stages: "uint",
    active_seconds: "int",
    hint: { optional: "uint" },
    found_stage: { optional: "uint" },
    stopped: "string",
    stopped_kind: "string",
    stopped_grant_id: "uint",
    stopped_stage: { optional: "uint" },
    allowance_spent: "uint",
    allowance_max: "uint",
    suppressed_authorizer: "string",
  },
};

const ROTATING_ACCOUNT_STATUS: AnswerShape = {
  fields: {
    account: "string",
    authorizer: "string",
    round: "uint",
    classification: "string",
    stage: { optional: "uint" },
    preparation: "string",
    cached_entries: "uint",
    recovery: ROTATING_RECOVERY_STATUS,
  },
};

/** /status */
export const STATUS_ANSWER: AnswerShape = {
  fields: {
    node_role: "string",
    protocol_version: { fields: { major: "int", minor: "int" } },
    build_version: "string",
    state: "string",
    signer_locked: "bool",
    ready_for_signing: "bool",
    key_count: "int",
    keyset_revision: "uint",
    approval_wait_seconds: "int",
    warnings: { list: "string" },
    notes: { list: "string" },
    rotating: { list: ROTATING_ACCOUNT_STATUS },
  },
};

const RUNTIME_ARG: AnswerShape = {
  fields: {
    name: "string",
    type: "string",
    label: "string",
    description: "string",
    required: "bool",
    byte_length: "int",
    max_size: "int",
  },
};

const LOGIC_SIG_RESOURCE_USAGE: AnswerShape = {
  fields: { program_bytes: "uint", argument_bytes: "uint", max_opcode_cost: "uint" },
};

const LOGIC_SIG_RESOURCE_PROFILE: AnswerShape = {
  fields: {
    default: LOGIC_SIG_RESOURCE_USAGE,
    spend: LOGIC_SIG_RESOURCE_USAGE,
    spending_rekey: LOGIC_SIG_RESOURCE_USAGE,
    listed_rekey: LOGIC_SIG_RESOURCE_USAGE,
  },
};

const BOUNDED_AUTHORIZATION: AnswerShape = {
  fields: {
    contract: "string",
    base_signature_arg_layout: { fields: { count: "int", max_sizes: { list: "int" } } },
    spend_effects: { list: "string" },
    max_fee: { optional: "uint" },
    rekey: "string",
    rekey_list: { fields: { contract: "string", depth: "int", root: "string" } },
    cosigner: {
      fields: {
        contract: "string",
        component_key_type: "string",
        public_key_hex: "string",
        component_key_id: "string",
        signature_max_size: "int",
        required_on: { list: "string" },
      },
    },
    runtime_args: { list: RUNTIME_ARG },
    derived_args: {
      list: { fields: { name: "string", kind: "string", parameter: "string", max_size: "int" } },
    },
    argument_layout: {
      list: {
        fields: {
          index: "int",
          name: "string",
          source: "string",
          max_size: "int",
          paths: { fields: { spend: "string", spending_rekey: "string", listed_rekey: "string" } },
        },
      },
    },
    layer3_policy: "string",
  },
};

const KEY_INFO: AnswerShape = {
  fields: {
    address: "string",
    public_key_hex: "string",
    key_type: "string",
    authorization_kind: "string",
    signing_flow: "string",
    cosigner_component_key_type: "string",
    logic_sig_resources: LOGIC_SIG_RESOURCE_PROFILE,
    is_generic_lsig: "bool",
    is_witness_key: "bool",
    bounded_authorization: BOUNDED_AUTHORIZATION,
    is_spending_account: { optional: "bool" },
    signing_args: { list: RUNTIME_ARG },
    parameters: { map: "string" },
    template_provenance_status: "string",
    template_provenance_note: "string",
  },
};

/** /keys */
export const KEYS_ANSWER: AnswerShape = {
  fields: { count: "int", keys: { list: KEY_INFO } },
};

const CREATION_PARAM: AnswerShape = {
  fields: {
    name: "string",
    label: "string",
    description: "string",
    type: "string",
    required: "bool",
    max_length: "int",
    input_modes: {
      list: {
        fields: {
          name: "string",
          label: "string",
          transform: "string",
          byte_length: "int",
          input_type: "string",
        },
      },
    },
    min_items: "int",
    max_items: "int",
    options: { list: "string" },
    min: { optional: "uint" },
    max: { optional: "uint" },
    example: "string",
    placeholder: "string",
    default: "string",
  },
};

/** /keytypes */
export const KEYTYPES_ANSWER: AnswerShape = {
  fields: {
    key_types: {
      list: {
        fields: {
          key_type: "string",
          family: "string",
          display_name: "string",
          description: "string",
          authorization_kind: "string",
          requires_logicsig: "bool",
          mnemonic_word_count: "int",
          mnemonic_import: "bool",
          mnemonic_scheme: "string",
          signing_flow: "string",
          cosigner_component_key_type: "string",
          per_key_contract: "bool",
          boundary_schema: "string",
          bounded_authorization: BOUNDED_AUTHORIZATION,
          creation_params: { list: CREATION_PARAM },
          runtime_args: { list: RUNTIME_ARG },
        },
      },
    },
  },
};
