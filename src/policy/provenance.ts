// Manifest provenance — bind a compiled policy to the exact capability
// declaration it was compiled from.
//
// Why this exists:
//   A signed manifest proves the declaration didn't change. A compiled sandbox
//   enforces it. When a host composes the two, each layer needs a reproducible
//   anchor for the artifact it covers. capgate computes a `manifestHash` over its
//   OWN canonical capability manifest and stamps it on every artifact, so the
//   emitted policy is provably the policy for these exact declared bytes. The
//   anchor is a sibling — not the same artifact — as a signed MCP tool manifest's
//   manifestHash (e.g. io.modelcontextprotocol/signed-manifests §6): same RFC 8785
//   scheme, different document. Composing the two means carrying both hashes and
//   treating a mismatch as a host-level re-consent/refuse decision.
//
// Scope discipline:
//   capgate is a CONSUMER of this anchor — it hashes its own input. It is NOT a
//   producer of a public versioned hash format others must implement. The hash is
//   over capgate's *capability* manifest, which is a DIFFERENT document from an MCP
//   *tool* manifest. We deliberately do not ingest, verify, or hash the latter;
//   direct consumption of a tool-manifest manifestHash would require ingesting that
//   format and is intentionally out of scope — not built and not planned. No carrier
//   field for an external manifestHash will be added; composition stays host-side.
//
// Canonicalization:
//   RFC 8785 (JSON Canonicalization Scheme), constrained to the value space a
//   capgate manifest projection actually contains: strings, arrays, nested plain
//   objects, booleans, null, and INTEGERS only. Any non-integer number (float, NaN,
//   Infinity) is fail-closed — we throw rather than emit bytes we can't guarantee
//   match another implementation's number formatting. This keeps the bytes
//   interoperable with Raj §2 ("sorted keys, no whitespace") and Tom Farley's
//   JCS-canonicalized IR without capgate taking a runtime dependency.

import { createHash } from 'node:crypto';
import { GRAMMAR_VERSION } from './grammar.js';
import { CompilationError } from './ir.js';
import type { RawServerManifest } from './compiler.js';

/** Names the byte-format so a third party can reproduce the hash. */
export const CANONICALIZATION = 'RFC8785' as const;

/** Provenance block stamped on every compiled artifact. */
export interface Provenance {
  /** SHA-256 over the canonical capability-manifest projection. "sha256:" + lowercase hex. */
  manifestHash: string;
  /** Compiler grammar version the policy was produced under (distinct from the hash input). */
  grammarVersion: string;
  /** The canonical byte-format `manifestHash` is computed over. */
  canonicalization: typeof CANONICALIZATION;
}

// ---------------------------------------------------------------------------
// Canonical projection — the FIXED shape we hash.
//
// We hash only what determines the policy: identity + declared capability
// strings. description / inputSchema / grammar are excluded — they are
// informational (ir.ts) and must not flip a policy-drift anchor, and excluding
// inputSchema also keeps arbitrary JSON-Schema (which may carry floats) out of
// the fail-closed number domain. The shape is fixed (serverCapabilities defaults
// to []) so present/absent never changes the bytes.
// ---------------------------------------------------------------------------

export interface ManifestProjection {
  name: string;
  version: string;
  serverCapabilities: string[];
  tools: { name: string; capabilities: string[] }[];
}

export function manifestProjection(raw: RawServerManifest): ManifestProjection {
  return {
    name: raw.name,
    version: raw.version,
    serverCapabilities: raw.serverCapabilities ?? [],
    tools: raw.tools.map((t) => ({
      name: t.name,
      capabilities: t.capabilities,
    })),
  };
}

// ---------------------------------------------------------------------------
// Canonicalization (constrained RFC 8785 / JCS)
// ---------------------------------------------------------------------------

/**
 * Serialize a JSON value to its RFC 8785 canonical form, constrained to the
 * value space capgate manifests use. Object keys are sorted lexicographically by
 * UTF-16 code unit (JS default sort — JCS specifies code-point order; the two
 * agree for the BMP key names manifests use). No insignificant whitespace.
 *
 * Fail-closed: a non-integer number, NaN, Infinity, or an unsupported value
 * (undefined, function, bigint, symbol) throws CompilationError rather than
 * producing bytes we cannot guarantee are reproducible.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'number': {
      if (!Number.isFinite(value)) {
        throw new CompilationError(
          'CANONICALIZATION_UNSUPPORTED',
          `cannot canonicalize non-finite number ${String(value)}`
        );
      }
      if (!Number.isInteger(value)) {
        throw new CompilationError(
          'CANONICALIZATION_UNSUPPORTED',
          `cannot canonicalize non-integer number ${value} — capgate manifest hashing is integer-only`
        );
      }
      // Integer in safe range: JS String() gives the minimal decimal form,
      // which matches JCS for integers (no exponent, no trailing zeros).
      return String(value);
    }

    case 'string':
      return encodeString(value);

    case 'object': {
      if (Array.isArray(value)) {
        return '[' + value.map((el) => canonicalize(el)).join(',') + ']';
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      const members = keys.map((k) => encodeString(k) + ':' + canonicalize(obj[k]));
      return '{' + members.join(',') + '}';
    }

    default:
      // undefined, function, bigint, symbol
      throw new CompilationError(
        'CANONICALIZATION_UNSUPPORTED',
        `cannot canonicalize value of type ${typeof value}`
      );
  }
}

/**
 * Encode a string per RFC 8785 §3.2.2.2: the JSON minimal escaping. Control
 * characters and the two mandatory escapes (" and \) use short forms where
 * defined, else \u00XX. All other code points are emitted literally (UTF-8 on
 * the wire when the returned string is hashed as utf8 bytes).
 */
function encodeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    switch (ch) {
      case '"':
        out += '\\"';
        break;
      case '\\':
        out += '\\\\';
        break;
      case '\b':
        out += '\\b';
        break;
      case '\f':
        out += '\\f';
        break;
      case '\n':
        out += '\\n';
        break;
      case '\r':
        out += '\\r';
        break;
      case '\t':
        out += '\\t';
        break;
      default:
        if (code < 0x20) {
          out += '\\u' + code.toString(16).padStart(4, '0');
        } else {
          out += ch;
        }
    }
  }
  return out + '"';
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

/** SHA-256 over the canonical bytes of `projection`. Returns "sha256:" + lowercase hex. */
export function computeManifestHash(projection: ManifestProjection): string {
  const canonical = canonicalize(projection);
  const digest = createHash('sha256').update(canonical, 'utf8').digest('hex');
  return `sha256:${digest}`;
}

/** Build the full provenance block for a raw manifest. */
export function provenanceFor(raw: RawServerManifest): Provenance {
  return {
    manifestHash: computeManifestHash(manifestProjection(raw)),
    grammarVersion: GRAMMAR_VERSION,
    canonicalization: CANONICALIZATION,
  };
}
