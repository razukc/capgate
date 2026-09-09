import { describe, it, expect } from 'vitest';
import { compile, lowerToBwrap, lowerToDocker, lowerToEgress, CompilationError } from '../../../src/policy/index.js';

function manifestWith(caps: string[]) {
  return {
    name: 'test-server',
    version: '0.0.1',
    tools: [{ name: 't', capabilities: caps }],
  };
}

describe('ADAPTER_UNSUPPORTED strict-by-default', () => {
  it('bwrap: supports all current kinds (no throw)', () => {
    const policy = compile(
      manifestWith([
        'fs:read:/workspace/**',
        'net:connect:api.github.com:443',
        'exec:spawn:git',
        'env:inject:FOO',
        'ipc:connect:x11',
        'clock:tzdata',
        'assert:test.id:"desc"',
      ])
    );
    expect(() => lowerToBwrap(policy)).not.toThrow();
    expect(() => lowerToBwrap(policy, { strict: true })).not.toThrow();
  });

  it('docker: supports all current kinds (no throw)', () => {
    const policy = compile(
      manifestWith(['fs:read:/workspace/**', 'net:connect:api.github.com:443', 'clock:system'])
    );
    expect(() => lowerToDocker(policy)).not.toThrow();
  });

  it('egress strict: net+assert ok', () => {
    const policy = compile(manifestWith(['net:connect:api.github.com:443', 'assert:x:"y"']));
    expect(() => lowerToEgress(policy, { target: 'squid' })).not.toThrow();
    expect(() => lowerToEgress(policy, { target: 'nftables' })).not.toThrow();
  });

  it('egress strict: fs throws ADAPTER_UNSUPPORTED', () => {
    const policy = compile(manifestWith(['fs:read:/workspace/**']));
    expect(() => lowerToEgress(policy, { target: 'squid' })).toThrow(CompilationError);
    try {
      lowerToEgress(policy, { target: 'squid' });
    } catch (e) {
      expect((e as CompilationError).code).toBe('ADAPTER_UNSUPPORTED');
      expect((e as CompilationError).message).toContain('egress');
      expect((e as CompilationError).message).toContain('"fs"');
    }
  });

  it('egress strict: exec/env/ipc/clock throw', () => {
    for (const cap of ['exec:spawn:git', 'env:inject:FOO', 'ipc:connect:x11', 'clock:tzdata']) {
      const policy = compile(manifestWith([cap]));
      expect(() => lowerToEgress(policy, { target: 'nftables' })).toThrow(CompilationError);
    }
  });

  it('egress permissive: fs does not throw, emits config', () => {
    const policy = compile(manifestWith(['fs:read:/workspace/**', 'net:connect:api.github.com:443']));
    const art = lowerToEgress(policy, { target: 'squid', strict: false });
    expect(art.config).toContain('capgate-egress.squid.conf');
    expect(art.config).toContain('api.github.com');
  });

  it('egress permissive: fs+exec does not throw for nftables', () => {
    const policy = compile(manifestWith(['fs:read:/workspace/**', 'exec:spawn:git', 'net:connect:1.2.3.4:443']));
    expect(() => lowerToEgress(policy, { target: 'nftables', strict: false })).not.toThrow();
  });

  it('bwrap permissive still ok (no-op)', () => {
    const policy = compile(manifestWith(['fs:read:/workspace/**']));
    expect(() => lowerToBwrap(policy, { strict: false })).not.toThrow();
  });

  it('error context contains adapter and unsupported kinds', () => {
    const policy = compile(manifestWith(['fs:read:/tmp/**', 'exec:spawn:git']));
    try {
      lowerToEgress(policy, { target: 'squid' });
      expect.fail('should throw');
    } catch (e) {
      const err = e as CompilationError;
      expect(err.code).toBe('ADAPTER_UNSUPPORTED');
      expect(err.context?.adapter).toBe('egress');
      expect(err.context?.unsupported).toEqual(expect.arrayContaining(['fs', 'exec']));
    }
  });
});

describe('assertManifestShape element-type polish', () => {
  it('non-string capability element throws MANIFEST_SHAPE with index', () => {
    const raw: unknown = {
      name: 's',
      version: '0.0.1',
      tools: [{ name: 't', capabilities: [123 as unknown as string] }],
    };
    expect(() => compile(raw as Parameters<typeof compile>[0])).toThrow(CompilationError);
    try {
      compile(raw as Parameters<typeof compile>[0]);
    } catch (e) {
      expect((e as CompilationError).code).toBe('MANIFEST_SHAPE');
      expect((e as CompilationError).message).toContain('capabilities[0]');
    }
  });

  it('non-string serverCapabilities element throws', () => {
    const raw: unknown = {
      name: 's',
      version: '0.0.1',
      serverCapabilities: [456 as unknown as string],
      tools: [],
    };
    expect(() => compile(raw as Parameters<typeof compile>[0])).toThrow(CompilationError);
  });
});
