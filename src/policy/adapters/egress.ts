// Egress adapter: NormalizedPolicy → static proxy config blob.
//
// This is the third lowering lane (see README "Why egress will lower to a proxy
// config, not a proxy"). bwrap and docker emit argv; this adapter emits a config
// *file* for a proxy the HOST already runs. Same compiler-not-runtime contract:
// capgate compiles policy.net (+ blockPrivate) into a config, and the host wires
// it into squid / nftables. We never open a socket.
//
// What this lane handles:
//   - squid:    allowlist by hostname via CONNECT (no TLS interception)
//   - nftables: allowlist by IP+port in-kernel (bypass-proof) + blockPrivate drops
//   - the blockPrivate RFC1918/loopback deny that bwrap/docker can only assert
//
// What this lane does NOT handle:
//   - RUNNING the proxy — the host owns the long-lived process; we emit a file.
//   - DNS resolution — nftables filters IPs, not names; hostname rules that it
//     cannot express are surfaced in unenforceable[], never silently dropped.
//   - TLS interception / secret inspection — out of scope for v0.1. squid here
//     is CONNECT-allowlist only; it sees SNI/host, never plaintext.
//
// Net posture (fail-closed). Every emitted config terminates or defaults in
// deny/drop: squid ends in an unconditional `http_access deny all`, nftables
// sets `policy drop`. No code path produces an allow-all config. An empty
// policy.net compiles to a deny-ALL config — mirroring how bwrap/docker treat
// net==0 (`--unshare-net` / `--network none`): declaring nothing grants nothing.

import { NormalizedPolicy } from '../ir.js';
import type { EgressRule } from './bwrap.js';

export type EgressTarget = 'squid' | 'nftables';

export interface EgressArtifact {
  /** Which backend this config targets. */
  target: EgressTarget;
  /** The config file contents, ready to write to disk and load into the proxy. */
  config: string;
  /** Suggested filename, e.g. "capgate-egress.squid.conf". */
  filename: string;
  /** Declared rules this target CANNOT honor — surfaced, never silently dropped. */
  unenforceable: { rule: EgressRule; reason: string }[];
  /** Human-readable diagnostics for audit logs / PR review. */
  notes: string[];
}

export interface EgressOptions {
  /** Required — no default. The caller must pick the backend the host runs. */
  target: EgressTarget;
}

// Private-range destinations the blockPrivate flag must deny. Kept as two lists
// because squid and nftables spell them differently (squid uses one `dst` acl
// covering both families; nftables splits ip / ip6 daddr sets).
const PRIVATE_V4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16'];
const PRIVATE_V6 = ['::1/128', 'fc00::/7', 'fe80::/10'];

export function lowerToEgress(policy: NormalizedPolicy, opts: EgressOptions): EgressArtifact {
  const rules: EgressRule[] = policy.net.map((n) => ({
    host: n.host,
    port: n.port,
    blockPrivate: n.blockPrivate,
  }));
  // blockPrivate is OR-ed across the policy: if ANY declared rule asks for the
  // private-range block, the whole config enforces it (deny wins, so a single
  // rule cannot opt the proxy out of a sibling rule's blockPrivate).
  const blockPrivate = rules.some((r) => r.blockPrivate);

  if (opts.target === 'squid') return lowerToSquid(rules, blockPrivate);
  if (opts.target === 'nftables') return lowerToNftables(rules, blockPrivate);
  // Fail-closed on an unknown target rather than emitting a permissive default.
  throw new Error(`[EGRESS_UNKNOWN_TARGET] unsupported egress target "${(opts as { target: string }).target}"`);
}

// ---------------------------------------------------------------------------
// squid — allowlist by hostname via CONNECT, no TLS interception
// ---------------------------------------------------------------------------
//
// squid matches on the CONNECT host, so it allowlists by DOMAIN cleanly and is
// the right target for rotating-CDN hostnames (api.github.com). IP-literal hosts
// are matched with a `dst` acl instead of `dstdomain`. The deny-all terminator
// is the last line, unconditional — nothing can be allowed past it.
function lowerToSquid(rules: EgressRule[], blockPrivate: boolean): EgressArtifact {
  const notes: string[] = [];
  const unenforceable: { rule: EgressRule; reason: string }[] = [];
  const lines: string[] = ['# capgate-egress.squid.conf (generated — do not edit)'];

  // ---------- blockPrivate (deny FIRST so it wins over the allows below) ----------
  if (blockPrivate) {
    lines.push(`acl to_private dst ${[...PRIVATE_V4, ...PRIVATE_V6].join(' ')}`);
    lines.push('http_access deny to_private');
  }

  // ---------- allow rules ----------
  rules.forEach((rule, i) => {
    const dstAcl = `cg_dst_${i}`;
    if (rule.host === '*') {
      // squid can't allowlist "any host" as a *restriction*: `*` means the rule
      // permits any destination. We represent it honestly as `dstdomain .`
      // (matches every domain) and lean on blockPrivate to be the only real
      // constraint left. Surfaced as a note so a reviewer sees the degeneracy.
      lines.push(`acl ${dstAcl} dstdomain .`);
      notes.push(
        `net[${i}]: host "*" degenerates to allow-any (dstdomain .) — squid cannot turn a wildcard into a restriction; only blockPrivate then constrains it.`
      );
    } else if (isIpLiteral(rule.host)) {
      // IP literal: squid matches it with `dst`, not `dstdomain`.
      lines.push(`acl ${dstAcl} dst ${rule.host}`);
    } else {
      lines.push(`acl ${dstAcl} dstdomain ${rule.host}`);
    }

    const aclRefs = [dstAcl];
    if (rule.port === null) {
      // Any port → no port acl. Noted so the widened scope is auditable.
      notes.push(`net[${i}]: port null (any port) — no port acl emitted for ${rule.host}.`);
    } else {
      const portAcl = `cg_port_${i}`;
      lines.push(`acl ${portAcl} port ${rule.port}`);
      aclRefs.push(portAcl);
    }
    lines.push(`http_access allow ${aclRefs.join(' ')} CONNECT`);
  });

  if (rules.length === 0) {
    notes.push('net: no egress declared — all outbound denied (deny-all only).');
  }

  // ---------- fail-closed terminator (unconditional, LAST line) ----------
  lines.push('http_access deny all');

  return {
    target: 'squid',
    config: lines.join('\n'),
    filename: 'capgate-egress.squid.conf',
    unenforceable,
    notes,
  };
}

// ---------------------------------------------------------------------------
// nftables — allowlist by IP+port in-kernel, bypass-proof
// ---------------------------------------------------------------------------
//
// nftables filters packets by destination IP; it cannot resolve or track
// rotating hostnames in-kernel. So hostname rules are NOT lowered to a (broken)
// rule — they are pushed to unenforceable[] with a reason pointing at the squid
// target. blockPrivate drops are emitted FIRST (before accepts), and the chain
// defaults to `policy drop` so anything not explicitly accepted is dropped.
function lowerToNftables(rules: EgressRule[], blockPrivate: boolean): EgressArtifact {
  const notes: string[] = [];
  const unenforceable: { rule: EgressRule; reason: string }[] = [];
  const body: string[] = [];

  // ---------- blockPrivate (drops FIRST, before any accept) ----------
  if (blockPrivate) {
    body.push(`    ip daddr { ${PRIVATE_V4.join(', ')} } drop`);
    body.push(`    ip6 daddr { ${PRIVATE_V6.join(', ')} } drop`);
  }

  // ---------- accept rules ----------
  rules.forEach((rule, i) => {
    if (rule.host === '*') {
      // Can't allowlist "any host" by IP. The blockPrivate drops above still
      // apply; the allow itself is unenforceable here.
      unenforceable.push({
        rule,
        reason:
          'nftables filters IPs, not hostnames; "*" cannot be expressed as an IP allowlist. Use the "squid" target for wildcard/hostname rules.',
      });
      return;
    }
    if (!isIpLiteral(rule.host)) {
      // Hostname (e.g. api.github.com): resolves to rotating CDN IPs that
      // nftables can't track. Surface it; do not emit a broken rule.
      unenforceable.push({
        rule,
        reason: `nftables filters IPs, not hostnames; ${rule.host} resolves to rotating IPs. Use the 'squid' target for hostname rules, or pin to resolved CIDRs.`,
      });
      return;
    }
    // IP literal: pick the family by colon presence and accept it.
    const fam = rule.host.includes(':') ? 'ip6' : 'ip';
    const dport = rule.port === null ? '' : ` tcp dport ${rule.port}`;
    if (rule.port === null) {
      notes.push(`net[${i}]: port null (any port) — accept emitted without tcp dport for ${rule.host}.`);
    }
    body.push(`    ${fam} daddr ${rule.host}${dport} accept`);
  });

  if (rules.length === 0) {
    notes.push('net: no egress declared — all outbound denied (policy drop, no accepts).');
  }
  if (unenforceable.length > 0) {
    notes.push(
      `net: ${unenforceable.length} rule(s) unenforceable by nftables (hostname/wildcard) — see unenforceable[]; compile those to the "squid" target.`
    );
  }

  // ---------- assemble table (policy drop = fail-closed default) ----------
  const lines: string[] = [
    '# capgate-egress.nftables (generated — do not edit)',
    'table inet capgate {',
    '  chain egress {',
    '    type filter hook output priority 0; policy drop;',
    ...body,
    '  }',
    '}',
  ];

  return {
    target: 'nftables',
    config: lines.join('\n'),
    filename: 'capgate-egress.nftables',
    unenforceable,
    notes,
  };
}

/**
 * True if `host` is an IPv4 or IPv6 literal (vs a DNS name). Heuristic, kept
 * deliberately simple: IPv4 is four dot-separated 0-255 octets; IPv6 is "has a
 * colon" (real names never contain colons). This is enough to decide squid
 * `dst` vs `dstdomain` and nftables accept-vs-unenforceable; we do not need a
 * full RFC parser here, and over-classifying a name as an IP would only ever
 * tighten matching, never loosen it.
 */
function isIpLiteral(host: string): boolean {
  if (host.includes(':')) return true; // IPv6 literal (names never contain ':')
  const octets = host.split('.');
  if (octets.length !== 4) return false;
  return octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255);
}
