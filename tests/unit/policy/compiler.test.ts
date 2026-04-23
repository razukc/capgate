import { describe, expect, it } from 'vitest';
import { compile, normalize, parseManifest } from '../../../src/policy/compiler';
import { GRAMMAR_VERSION, parseCapability } from '../../../src/policy/grammar';
import { CompilationError } from '../../../src/policy/ir';

describe('compiler.compile', () => {
  it('rejects manifest missing name', () => {
    expect(() =>
      compile({ name: '', version: '1.0.0', tools: [] } as any)
    ).toThrow(CompilationError);
  });

  it('unions server + tool capabilities', () => {
    const p = compile({
      name: 'srv',
      version: '1.0.0',
      serverCapabilities: ['clock:tzdata'],
      tools: [
        { name: 't', capabilities: ['fs:read:/x'] },
      ],
    });
    expect(p.clock).toBe('tzdata');
    expect(p.fs.map((f) => f.path)).toEqual(['/x']);
  });

  it('write implies read', () => {
    const p = normalize({ name: 's', version: '1' }, [
      parseCapability('fs:write:/a').capability,
    ]);
    expect(p.fs[0].actions).toEqual(['read', 'write']);
  });

  it('delete implies write implies read', () => {
    const p = normalize({ name: 's', version: '1' }, [
      parseCapability('fs:delete:/a').capability,
    ]);
    expect(p.fs[0].actions).toEqual(['read', 'write', 'delete']);
  });

  it('merges overlapping fs roots under a directory prefix', () => {
    const p = normalize({ name: 's', version: '1' }, [
      parseCapability('fs:read:/workspace/**').capability,
      parseCapability('fs:write:/workspace/src').capability,
    ]);
    expect(p.fs).toHaveLength(1);
    expect(p.fs[0].path).toBe('/workspace/**');
    expect(p.fs[0].actions).toEqual(['read', 'write']);
  });

  it('keeps disjoint fs roots separate', () => {
    const p = normalize({ name: 's', version: '1' }, [
      parseCapability('fs:read:/a').capability,
      parseCapability('fs:read:/b').capability,
    ]);
    expect(p.fs.map((f) => f.path).sort()).toEqual(['/a', '/b']);
  });

  it('ORs blockPrivate across net merges', () => {
    const p = normalize({ name: 's', version: '1' }, [
      parseCapability('net:connect:127.0.0.1:8080').capability,
      parseCapability('net:connect:127.0.0.1:8080').capability,
    ]);
    expect(p.net).toHaveLength(1);
    expect(p.net[0].blockPrivate).toBe(false);
  });

  it('inject dominates read for env', () => {
    const p = normalize({ name: 's', version: '1' }, [
      parseCapability('env:read:GITHUB_PAT').capability,
      parseCapability('env:inject:GITHUB_PAT').capability,
    ]);
    expect(p.env).toEqual([{ name: 'GITHUB_PAT', action: 'inject' }]);
  });

  it('tzdata dominates system for clock', () => {
    const p = normalize({ name: 's', version: '1' }, [
      parseCapability('clock:system').capability,
      parseCapability('clock:tzdata').capability,
    ]);
    expect(p.clock).toBe('tzdata');
  });

  it('sets nestedSandbox from refinement', () => {
    const p = normalize({ name: 's', version: '1' }, [
      parseCapability('exec:spawn:chromium?nestedSandbox=true').capability,
    ]);
    expect(p.nestedSandbox).toBe(true);
  });

  it('produces deterministic output order', () => {
    const a = compile({
      name: 's',
      version: '1.0.0',
      tools: [{ name: 't', capabilities: ['fs:read:/z', 'fs:read:/a', 'fs:read:/m'] }],
    });
    const b = compile({
      name: 's',
      version: '1.0.0',
      tools: [{ name: 't', capabilities: ['fs:read:/m', 'fs:read:/a', 'fs:read:/z'] }],
    });
    expect(a.fs.map((f) => f.path)).toEqual(b.fs.map((f) => f.path));
    expect(a.fs.map((f) => f.path)).toEqual(['/a', '/m', '/z']);
  });

  it('parseManifest preserves tool names and attaches parsed capabilities', () => {
    const m = parseManifest({
      name: 's',
      version: '1',
      tools: [{ name: 't1', capabilities: ['fs:read:/a'] }],
    });
    expect(m.tools[0].name).toBe('t1');
    expect(m.tools[0].capabilities[0].kind).toBe('fs');
  });

  it('accepts matching grammar version pin', () => {
    expect(() =>
      compile({
        grammar: GRAMMAR_VERSION,
        name: 's',
        version: '1',
        tools: [{ name: 't', capabilities: ['fs:read:/a'] }],
      })
    ).not.toThrow();
  });

  it('rejects mismatched grammar version with GRAMMAR_VERSION_MISMATCH', () => {
    expect(() =>
      compile({
        grammar: '99.0',
        name: 's',
        version: '1',
        tools: [{ name: 't', capabilities: ['fs:read:/a'] }],
      })
    ).toThrow(/GRAMMAR_VERSION_MISMATCH/);
  });

  it('accepts manifest without grammar field (forward compat)', () => {
    expect(() =>
      compile({
        name: 's',
        version: '1',
        tools: [{ name: 't', capabilities: ['fs:read:/a'] }],
      })
    ).not.toThrow();
  });
});
