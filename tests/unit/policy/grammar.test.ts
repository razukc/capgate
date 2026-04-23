import { describe, expect, it } from 'vitest';
import { parseCapability } from '../../../src/policy/grammar';
import { CompilationError } from '../../../src/policy/ir';

describe('grammar.parseCapability', () => {
  it('parses fs with single action', () => {
    const { capability } = parseCapability('fs:read:/workspace');
    expect(capability).toEqual({
      kind: 'fs',
      actions: ['read'],
      scope: { path: '/workspace', isGlob: false },
      refinements: undefined,
    });
  });

  it('parses fs with multiple actions and glob', () => {
    const { capability } = parseCapability('fs:read,write:/workspace/**');
    expect(capability.kind).toBe('fs');
    if (capability.kind !== 'fs') throw new Error('narrow');
    expect(capability.actions).toEqual(['read', 'write']);
    expect(capability.scope.isGlob).toBe(true);
  });

  it('rejects relative fs paths', () => {
    expect(() => parseCapability('fs:read:workspace')).toThrow(CompilationError);
  });

  it('rejects unknown fs action', () => {
    expect(() => parseCapability('fs:execute:/workspace')).toThrow(/CAP_ACTION_UNKNOWN/);
  });

  it('parses net with port', () => {
    const { capability } = parseCapability('net:connect:api.github.com:443');
    if (capability.kind !== 'net') throw new Error('narrow');
    expect(capability.scope.host).toBe('api.github.com');
    expect(capability.scope.port).toBe(443);
    expect(capability.scope.blockPrivate).toBe(true);
  });

  it('flags net:* as blockPrivate', () => {
    const { capability } = parseCapability('net:connect:*');
    if (capability.kind !== 'net') throw new Error('narrow');
    expect(capability.scope.blockPrivate).toBe(true);
  });

  it('does not blockPrivate for explicit loopback', () => {
    const { capability } = parseCapability('net:connect:127.0.0.1:5432');
    if (capability.kind !== 'net') throw new Error('narrow');
    expect(capability.scope.blockPrivate).toBe(false);
  });

  it('rejects net port out of range', () => {
    expect(() => parseCapability('net:connect:x:70000')).toThrow(/CAP_NET_PORT/);
  });

  it('parses exec with basename only', () => {
    const { capability } = parseCapability('exec:spawn:git');
    if (capability.kind !== 'exec') throw new Error('narrow');
    expect(capability.scope.binary).toBe('git');
  });

  it('rejects exec with a path', () => {
    expect(() => parseCapability('exec:spawn:/usr/bin/git')).toThrow(/CAP_EXEC_PATH/);
  });

  it('parses env with UPPER_SNAKE name', () => {
    const { capability } = parseCapability('env:inject:GITHUB_PAT');
    if (capability.kind !== 'env') throw new Error('narrow');
    expect(capability.scope.name).toBe('GITHUB_PAT');
    expect(capability.actions).toEqual(['inject']);
  });

  it('rejects lowercase env name', () => {
    expect(() => parseCapability('env:inject:github_pat')).toThrow(/CAP_ENV_NAME/);
  });

  it('parses clock sources', () => {
    expect(parseCapability('clock:tzdata').capability.kind).toBe('clock');
    expect(parseCapability('clock:system').capability.kind).toBe('clock');
    expect(() => parseCapability('clock:wallclock')).toThrow(/CAP_CLOCK_SOURCE/);
  });

  it('parses assert with quoted description containing colons', () => {
    const { capability } = parseCapability(
      'assert:postgres.read_only:"all queries run in READ ONLY TRANSACTION: enforced by server"'
    );
    if (capability.kind !== 'assert') throw new Error('narrow');
    expect(capability.scope.id).toBe('postgres.read_only');
    expect(capability.scope.description).toContain('READ ONLY TRANSACTION');
  });

  it('parses nestedSandbox refinement', () => {
    const { capability } = parseCapability('exec:spawn:chromium?nestedSandbox=true');
    expect(capability.refinements?.nestedSandbox).toBe(true);
  });

  it('rejects unknown capability kind', () => {
    expect(() => parseCapability('gpu:access:nvidia0')).toThrow(/CAP_UNKNOWN_KIND/);
  });
});
