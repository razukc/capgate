// Security regression test for the bwrap net posture.
//
// bwrap's --unshare-net is all-or-nothing: it has no privilege to build
// veth/routes, so it cannot do selective egress on its own. The ONLY safe
// behavior is therefore full network isolation — declaring net MUST NOT cause
// the sandbox to share (and thus fully inherit) the host network namespace.
// A declared egress[] that silently grants the whole host network reads as a
// constraint while being an escalation; this test guards against that.

import { describe, expect, it } from 'vitest';
import { lowerToBwrap } from '../../../src/policy/adapters/bwrap';
import type { NormalizedPolicy } from '../../../src/policy/ir';

function policyWith(net: NormalizedPolicy['net'], nestedSandbox = false): NormalizedPolicy {
  return {
    server: { name: 'test', version: '0.0.0' },
    fs: [],
    net,
    exec: [],
    env: [],
    ipc: [],
    clock: 'none',
    assertions: [],
    nestedSandbox,
  };
}

describe('bwrap adapter — net never shares host netns', () => {
  it('emits --unshare-net even when egress is declared', () => {
    const artifact = lowerToBwrap(policyWith([{ host: 'api.github.com', port: 443, blockPrivate: true }]));
    expect(artifact.argv).toContain('--unshare-net');
  });

  it('emits --unshare-net for net>0 under nestedSandbox', () => {
    const artifact = lowerToBwrap(policyWith([{ host: '*', port: null, blockPrivate: true }], true));
    expect(artifact.argv).toContain('--unshare-net');
  });

  it('still emits --unshare-net when no net is declared (deny-by-default)', () => {
    const artifact = lowerToBwrap(policyWith([]));
    expect(artifact.argv).toContain('--unshare-net');
  });

  it('warns loudly that declared egress is NOT enforced by bwrap alone', () => {
    const artifact = lowerToBwrap(policyWith([{ host: 'api.github.com', port: 443, blockPrivate: true }]));
    expect(artifact.notes.some((n) => /not enforced by bwrap alone/i.test(n))).toBe(true);
  });
});
