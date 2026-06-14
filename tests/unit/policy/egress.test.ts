// Unit tests for the egress adapter.
//
// egress is the proxy-config lane: it compiles policy.net (+ blockPrivate) into
// a static config blob for a proxy the HOST already runs. capgate does NOT run
// a proxy — so these tests assert on the emitted config string and on the
// unenforceable[] honesty field, never on live network behavior.
//
// Fail-closed is the load-bearing invariant: every emitted config — squid or
// nftables, populated or empty — MUST terminate/default in deny/drop. The final
// block of tests guards exactly that across the whole matrix.

import { describe, expect, it } from 'vitest';
import { lowerToEgress } from '../../../src/policy/adapters/egress';
import type { NormalizedPolicy } from '../../../src/policy/ir';

function policyWith(net: NormalizedPolicy['net']): NormalizedPolicy {
  return {
    server: { name: 'test', version: '0.0.0' },
    fs: [],
    net,
    exec: [],
    env: [],
    ipc: [],
    clock: 'none',
    assertions: [],
    nestedSandbox: false,
  };
}

describe('egress adapter — squid target', () => {
  it('emits an allow rule before the unconditional deny-all terminator', () => {
    const a = lowerToEgress(policyWith([{ host: 'api.github.com', port: 443, blockPrivate: false }]), {
      target: 'squid',
    });
    const lines = a.config.split('\n');
    const allowIdx = lines.findIndex((l) => l.startsWith('http_access allow') && l.includes('CONNECT'));
    const denyAllIdx = lines.findIndex((l) => l.trim() === 'http_access deny all');
    expect(allowIdx).toBeGreaterThanOrEqual(0);
    expect(denyAllIdx).toBeGreaterThan(allowIdx);
    // deny all is the LAST non-empty line — nothing can be allowed after it.
    const lastNonEmpty = lines.filter((l) => l.trim() !== '').at(-1);
    expect(lastNonEmpty).toBe('http_access deny all');
    expect(a.config).toContain('acl cg_dst_0 dstdomain api.github.com');
    expect(a.config).toContain('acl cg_port_0 port 443');
    expect(a.filename).toBe('capgate-egress.squid.conf');
  });

  it('places the blockPrivate deny BEFORE the allow rules (deny wins)', () => {
    const a = lowerToEgress(policyWith([{ host: 'api.github.com', port: 443, blockPrivate: true }]), {
      target: 'squid',
    });
    const lines = a.config.split('\n');
    const denyPrivIdx = lines.findIndex((l) => l.trim() === 'http_access deny to_private');
    const allowIdx = lines.findIndex((l) => l.startsWith('http_access allow'));
    expect(denyPrivIdx).toBeGreaterThanOrEqual(0);
    expect(allowIdx).toBeGreaterThan(denyPrivIdx);
    expect(a.config).toContain('acl to_private dst');
  });

  it('omits the port acl when port is null and notes it', () => {
    const a = lowerToEgress(policyWith([{ host: 'example.com', port: null, blockPrivate: false }]), {
      target: 'squid',
    });
    expect(a.config).toContain('acl cg_dst_0 dstdomain example.com');
    expect(a.config).not.toContain('cg_port_0');
    expect(a.config).toContain('http_access allow cg_dst_0 CONNECT');
    expect(a.notes.some((n) => /any port/i.test(n))).toBe(true);
  });

  it('degenerates wildcard host "*" to allow-any (dstdomain .) and says so in a note', () => {
    const a = lowerToEgress(policyWith([{ host: '*', port: null, blockPrivate: true }]), { target: 'squid' });
    expect(a.config).toContain('acl cg_dst_0 dstdomain .');
    expect(a.notes.some((n) => /allow-any/i.test(n))).toBe(true);
    // blockPrivate still constrains the allow-any.
    expect(a.config).toContain('http_access deny to_private');
  });

  it('uses dst (not dstdomain) for an IP-literal host so squid can match it', () => {
    const a = lowerToEgress(policyWith([{ host: '10.1.2.3', port: 8080, blockPrivate: false }]), {
      target: 'squid',
    });
    expect(a.config).toContain('acl cg_dst_0 dst 10.1.2.3');
    expect(a.unenforceable).toHaveLength(0);
  });

  it('empty net → deny-all config with no allow lines', () => {
    const a = lowerToEgress(policyWith([]), { target: 'squid' });
    expect(a.config).not.toContain('http_access allow');
    expect(a.config.split('\n').filter((l) => l.trim() !== '').at(-1)).toBe('http_access deny all');
    expect(a.notes.some((n) => /all outbound denied/i.test(n))).toBe(true);
  });
});

describe('egress adapter — nftables target', () => {
  it('accepts an IP-literal host on its declared port and defaults to drop', () => {
    const a = lowerToEgress(policyWith([{ host: '93.184.216.34', port: 443, blockPrivate: false }]), {
      target: 'nftables',
    });
    expect(a.config).toContain('policy drop');
    expect(a.config).toContain('ip daddr 93.184.216.34 tcp dport 443 accept');
    expect(a.filename).toBe('capgate-egress.nftables');
    expect(a.unenforceable).toHaveLength(0);
  });

  it('pushes a hostname rule to unenforceable[] instead of emitting a broken rule', () => {
    const a = lowerToEgress(policyWith([{ host: 'api.github.com', port: 443, blockPrivate: false }]), {
      target: 'nftables',
    });
    expect(a.unenforceable).toHaveLength(1);
    expect(a.unenforceable[0].rule.host).toBe('api.github.com');
    expect(a.unenforceable[0].reason).toMatch(/filters IPs, not hostnames/i);
    // The hostname must NOT leak into the config as a daddr.
    expect(a.config).not.toContain('api.github.com');
    expect(a.config).not.toContain('accept');
  });

  it('emits blockPrivate drops BEFORE any accept', () => {
    const a = lowerToEgress(policyWith([{ host: '8.8.8.8', port: 53, blockPrivate: true }]), {
      target: 'nftables',
    });
    const lines = a.config.split('\n');
    const dropIdx = lines.findIndex((l) => /ip daddr \{.*\} drop/.test(l));
    const acceptIdx = lines.findIndex((l) => l.includes('accept'));
    expect(dropIdx).toBeGreaterThanOrEqual(0);
    expect(acceptIdx).toBeGreaterThan(dropIdx);
    expect(a.config).toContain('ip6 daddr {');
  });

  it('accepts without tcp dport when port is null', () => {
    const a = lowerToEgress(policyWith([{ host: '1.1.1.1', port: null, blockPrivate: false }]), {
      target: 'nftables',
    });
    expect(a.config).toContain('ip daddr 1.1.1.1 accept');
    expect(a.config).not.toContain('tcp dport');
  });

  it('uses ip6 daddr for an IPv6-literal host', () => {
    const a = lowerToEgress(policyWith([{ host: '2606:4700:4700::1111', port: 443, blockPrivate: false }]), {
      target: 'nftables',
    });
    expect(a.config).toContain('ip6 daddr 2606:4700:4700::1111 tcp dport 443 accept');
  });

  it('wildcard host "*" with no IP is unenforceable by nftables', () => {
    const a = lowerToEgress(policyWith([{ host: '*', port: null, blockPrivate: true }]), { target: 'nftables' });
    expect(a.unenforceable).toHaveLength(1);
    expect(a.unenforceable[0].rule.host).toBe('*');
    // blockPrivate drops still apply even though the allow is unenforceable.
    expect(a.config).toContain('drop');
    expect(a.config).not.toContain('accept');
  });

  it('empty net → policy drop with no accepts', () => {
    const a = lowerToEgress(policyWith([]), { target: 'nftables' });
    expect(a.config).toContain('policy drop');
    expect(a.config).not.toContain('accept');
    expect(a.notes.some((n) => /all outbound denied/i.test(n))).toBe(true);
  });
});

describe('egress adapter — fail-closed across the matrix', () => {
  const policies: NormalizedPolicy['net'][] = [
    [],
    [{ host: 'api.github.com', port: 443, blockPrivate: true }],
    [{ host: '*', port: null, blockPrivate: true }],
    [{ host: '10.1.2.3', port: 8080, blockPrivate: false }],
  ];
  for (const net of policies) {
    it(`squid terminates in deny-all (net=${net.length})`, () => {
      const a = lowerToEgress(policyWith(net), { target: 'squid' });
      expect(a.config.split('\n').filter((l) => l.trim() !== '').at(-1)).toBe('http_access deny all');
    });
    it(`nftables defaults to policy drop (net=${net.length})`, () => {
      const a = lowerToEgress(policyWith(net), { target: 'nftables' });
      expect(a.config).toContain('policy drop');
    });
  }
});
