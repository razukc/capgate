import { describe, it, expect } from 'vitest';
import {
  canonicalize,
  computeManifestHash,
  manifestProjection,
  provenanceFor,
  CANONICALIZATION,
} from '../../../src/policy/provenance.js';
import { compile } from '../../../src/policy/compiler.js';
import { CompilationError } from '../../../src/policy/ir.js';
import { GRAMMAR_VERSION } from '../../../src/policy/grammar.js';

describe('canonicalize (constrained RFC 8785 / JCS)', () => {
  it('sorts object keys lexicographically at every level', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalize({ z: { y: 1, x: 2 }, a: 3 })).toBe('{"a":3,"z":{"x":2,"y":1}}');
  });

  it('emits no insignificant whitespace', () => {
    expect(canonicalize({ a: [1, 2], b: 'x' })).toBe('{"a":[1,2],"b":"x"}');
  });

  it('preserves array order (arrays are not sorted)', () => {
    expect(canonicalize(['c', 'a', 'b'])).toBe('["c","a","b"]');
  });

  it('escapes strings per JSON minimal escaping', () => {
    // " \ \n \t \r \b \f  → short escapes; control char → \u00XX; literal otherwise
    const s = String.fromCharCode(0x22, 0x5c, 0x0a, 0x09, 0x01, 0x41);
    expect(canonicalize(s)).toBe('"\\"\\\\\\n\\t\\u0001A"');
    expect(canonicalize('/workspace/**')).toBe('"/workspace/**"'); // solidus NOT escaped
  });

  it('serializes booleans and null', () => {
    expect(canonicalize(true)).toBe('true');
    expect(canonicalize(false)).toBe('false');
    expect(canonicalize(null)).toBe('null');
  });

  it('serializes integers (e.g. ports) minimally', () => {
    expect(canonicalize(443)).toBe('443');
    expect(canonicalize(0)).toBe('0');
    expect(canonicalize(-1)).toBe('-1');
  });

  it('is fail-closed on non-integer numbers', () => {
    expect(() => canonicalize(1.5)).toThrow(CompilationError);
    expect(() => canonicalize(1.5)).toThrow(/integer/);
  });

  it('is fail-closed on NaN / Infinity', () => {
    expect(() => canonicalize(NaN)).toThrow(CompilationError);
    expect(() => canonicalize(Infinity)).toThrow(CompilationError);
  });

  it('is fail-closed on unsupported types', () => {
    expect(() => canonicalize(undefined)).toThrow(CompilationError);
    expect(() => canonicalize(10n)).toThrow(CompilationError);
  });
});

describe('manifestProjection', () => {
  it('projects identity + capability strings only, defaulting serverCapabilities to []', () => {
    const proj = manifestProjection({
      name: 'srv',
      version: '1.0.0',
      tools: [{ name: 't', description: 'ignored', capabilities: ['fs:read:/x'] }],
    });
    expect(proj).toEqual({
      name: 'srv',
      version: '1.0.0',
      serverCapabilities: [],
      tools: [{ name: 't', capabilities: ['fs:read:/x'] }],
    });
  });

  it('excludes description and inputSchema (informational, not policy-bearing)', () => {
    const proj = manifestProjection({
      name: 'srv',
      version: '1.0.0',
      tools: [
        {
          name: 't',
          description: 'a tool',
          inputSchema: { type: 'object', properties: { n: { type: 'number' } } },
          capabilities: ['fs:read:/x'],
        },
      ],
    });
    const t = proj.tools[0] as Record<string, unknown>;
    expect(t).not.toHaveProperty('description');
    expect(t).not.toHaveProperty('inputSchema');
  });
});

describe('computeManifestHash', () => {
  const fixedProjection = {
    name: 'srv',
    version: '1.0.0',
    serverCapabilities: [] as string[],
    tools: [{ name: 't', capabilities: ['fs:read:/x'] }],
  };

  it('matches a known-answer SHA-256 over the canonical bytes', () => {
    // canonical: {"name":"srv","serverCapabilities":[],"tools":[{"capabilities":["fs:read:/x"],"name":"t"}],"version":"1.0.0"}
    expect(computeManifestHash(fixedProjection)).toBe(
      'sha256:ed84115385089df118983e03900f9b6c473327cb48a663ca6d824a8cd3a5f807'
    );
  });

  it('is stable across source key order and whitespace (reproducibility)', () => {
    const a = manifestProjection({
      name: 'srv',
      version: '1.0.0',
      tools: [{ name: 't', capabilities: ['fs:read:/x'] }],
    });
    const b = manifestProjection({
      version: '1.0.0',
      tools: [{ capabilities: ['fs:read:/x'], name: 't' }],
      name: 'srv',
      serverCapabilities: [],
    } as Parameters<typeof manifestProjection>[0]);
    expect(computeManifestHash(a)).toBe(computeManifestHash(b));
  });

  it('changes when a capability changes (drift anchor)', () => {
    const base = manifestProjection({
      name: 'srv',
      version: '1.0.0',
      tools: [{ name: 't', capabilities: ['fs:read:/x'] }],
    });
    const drifted = manifestProjection({
      name: 'srv',
      version: '1.0.0',
      tools: [{ name: 't', capabilities: ['fs:read:/etc'] }],
    });
    expect(computeManifestHash(base)).not.toBe(computeManifestHash(drifted));
  });

  it('does NOT change when only a description changes (policy-drift, not text-drift)', () => {
    const withDesc = manifestProjection({
      name: 'srv',
      version: '1.0.0',
      tools: [{ name: 't', description: 'one', capabilities: ['fs:read:/x'] }],
    });
    const otherDesc = manifestProjection({
      name: 'srv',
      version: '1.0.0',
      tools: [{ name: 't', description: 'two', capabilities: ['fs:read:/x'] }],
    });
    expect(computeManifestHash(withDesc)).toBe(computeManifestHash(otherDesc));
  });
});

describe('provenanceFor / compile integration', () => {
  it('stamps a complete provenance block', () => {
    const prov = provenanceFor({
      name: 'srv',
      version: '1.0.0',
      tools: [{ name: 't', capabilities: ['fs:read:/x'] }],
    });
    expect(prov.manifestHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(prov.grammarVersion).toBe(GRAMMAR_VERSION);
    expect(prov.canonicalization).toBe(CANONICALIZATION);
  });

  it('compile() attaches provenance to the NormalizedPolicy', () => {
    const policy = compile({
      name: 'srv',
      version: '1.0.0',
      tools: [{ name: 't', capabilities: ['fs:read:/x'] }],
    });
    expect(policy.provenance).toBeDefined();
    expect(policy.provenance!.manifestHash).toBe(
      'sha256:ed84115385089df118983e03900f9b6c473327cb48a663ca6d824a8cd3a5f807'
    );
  });

  it('produces the same manifestHash regardless of which tools differ only in description', () => {
    const p1 = compile({
      name: 'srv',
      version: '1.0.0',
      tools: [{ name: 't', description: 'x', capabilities: ['net:connect:api.example.com:443'] }],
    });
    const p2 = compile({
      name: 'srv',
      version: '1.0.0',
      tools: [{ name: 't', description: 'y', capabilities: ['net:connect:api.example.com:443'] }],
    });
    expect(p1.provenance!.manifestHash).toBe(p2.provenance!.manifestHash);
  });
});
