// Adapter support matrix — which CapabilityKind each lowering target can enforce.
//
// Design: compiler stays adapter-agnostic (src/policy/compiler.ts:10). Each
// adapter validates its own NormalizedPolicy at entry and throws
// CompilationError('ADAPTER_UNSUPPORTED') when the policy contains a kind the
// target cannot lower. Strict by default (fail-closed); permissive opt-in via
// `strict:false` keeps old notes/unenforceable behaviour for mixed manifests
// (e.g. compiling a filesystem manifest to egress for DX).

import { CompilationError, NormalizedPolicy } from '../ir.js';
import type { CapabilityKind } from '../ir.js';

export type AdapterName = 'bwrap' | 'docker' | 'egress';

type SupportOpts = { strict?: boolean };

const SUPPORTED: Record<AdapterName, ReadonlySet<CapabilityKind>> = {
  bwrap: new Set<CapabilityKind>(['fs', 'net', 'exec', 'env', 'ipc', 'clock', 'assert']),
  docker: new Set<CapabilityKind>(['fs', 'net', 'exec', 'env', 'ipc', 'clock', 'assert']),
  // egress is net-only; non-net kinds are ignored with notes when permissive
  egress: new Set<CapabilityKind>(['net', 'assert']),
};

function kindsInPolicy(policy: NormalizedPolicy): CapabilityKind[] {
  const kinds: CapabilityKind[] = [];
  if (policy.fs.length > 0) kinds.push('fs');
  if (policy.net.length > 0) kinds.push('net');
  if (policy.exec.length > 0) kinds.push('exec');
  if (policy.env.length > 0) kinds.push('env');
  if (policy.ipc.length > 0) kinds.push('ipc');
  if (policy.clock !== 'none') kinds.push('clock');
  if (policy.assertions.length > 0) kinds.push('assert');
  // nestedSandbox is a refinement, not a kind — handled by adapters via notes
  return kinds;
}

export function assertSupported(
  policy: NormalizedPolicy,
  adapter: AdapterName,
  opts: SupportOpts = {}
): void {
  const strict = opts.strict ?? true;
  if (!strict) return;

  const supported = SUPPORTED[adapter];
  const present = kindsInPolicy(policy);
  const unsupported = present.filter((k) => !supported.has(k));
  if (unsupported.length === 0) return;

  // Egress is the only adapter with a non-universal set today. Keep the error
  // actionable: name the kinds and the fix (different target or --permissive).
  throw new CompilationError(
    'ADAPTER_UNSUPPORTED',
    `Adapter "${adapter}" cannot lower capability kind(s) ${unsupported
      .map((k) => `"${k}"`)
      .join(', ')} — present in policy ${present
      .map((k) => `"${k}"`)
      .join(', ')}, supported for "${adapter}" is ${[...supported]
      .map((k) => `"${k}"`)
      .join(', ')}. Choose a different target or re-run with --permissive (notes/unenforceable instead of fail-closed).`,
    { adapter, unsupported, present, supported: [...supported] }
  );
}
