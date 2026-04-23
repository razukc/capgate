// Compiler: ServerManifest → NormalizedPolicy.
//
// Responsibilities:
//   1. Parse capability strings in raw manifests into typed Capability values.
//   2. Union server-level + per-tool capabilities into a single flat list.
//   3. Normalize (write implies read; longer fs paths absorb shorter overlaps).
//   4. Dedupe by (kind, scope key).
//   5. Partition by kind into the NormalizedPolicy shape.
//
// The compiler is a pure function. No I/O. No adapter knowledge.

import { GRAMMAR_VERSION, parseCapability } from './grammar.js';
import {
  AssertScope,
  Capability,
  CompilationError,
  EnvAction,
  FsAction,
  NormalizedPolicy,
  ServerManifest,
  ToolManifest,
} from './ir.js';

// ---------------------------------------------------------------------------
// Raw manifest shape — what we accept from JSON. Mirrors ir.ServerManifest
// but with capability strings unparsed. Kept separate so the IR stays typed
// and the parse step is explicit.
// ---------------------------------------------------------------------------

export interface RawToolManifest extends Omit<ToolManifest, 'capabilities'> {
  capabilities: string[];
}

export interface RawServerManifest extends Omit<ServerManifest, 'tools' | 'serverCapabilities'> {
  /**
   * Optional grammar version pin (e.g. "0.0"). If present, must match the
   * compiler's GRAMMAR_VERSION. Absent = accept under any version (forward
   * compat for manifests written before this field existed).
   */
  grammar?: string;
  serverCapabilities?: string[];
  tools: RawToolManifest[];
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function compile(raw: RawServerManifest): NormalizedPolicy {
  assertManifestShape(raw);

  const parsed = parseManifest(raw);
  const all: Capability[] = [
    ...(parsed.serverCapabilities ?? []),
    ...parsed.tools.flatMap((t) => t.capabilities),
  ];

  return normalize(
    { name: raw.name, version: raw.version },
    all
  );
}

/** Parse a RawServerManifest into a ServerManifest with typed Capability[]. */
export function parseManifest(raw: RawServerManifest): ServerManifest {
  const serverCapabilities =
    raw.serverCapabilities?.map((s) => parseCapability(s).capability) ?? [];
  const tools: ToolManifest[] = raw.tools.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
    capabilities: t.capabilities.map((s) => parseCapability(s).capability),
  }));
  return { name: raw.name, version: raw.version, serverCapabilities, tools };
}

// ---------------------------------------------------------------------------
// Normalization pipeline
// ---------------------------------------------------------------------------

export function normalize(
  server: { name: string; version: string },
  caps: Capability[]
): NormalizedPolicy {
  const policy: NormalizedPolicy = {
    server,
    fs: [],
    net: [],
    exec: [],
    env: [],
    ipc: [],
    clock: 'none',
    assertions: [],
    nestedSandbox: false,
  };

  // Per-kind accumulators keyed by a canonical scope key.
  const fsAcc = new Map<string, { path: string; actions: Set<FsAction>; isGlob: boolean }>();
  const netAcc = new Map<string, { host: string; port: number | null; blockPrivate: boolean }>();
  const execAcc = new Map<string, { binary: string }>();
  const envAcc = new Map<string, { name: string; action: EnvAction }>();
  const ipcAcc = new Map<string, { endpoint: string }>();
  const assertAcc = new Map<string, AssertScope>();

  for (const cap of caps) {
    if (cap.refinements?.nestedSandbox) policy.nestedSandbox = true;

    switch (cap.kind) {
      case 'fs': {
        const key = cap.scope.path;
        const entry = fsAcc.get(key) ?? {
          path: cap.scope.path,
          actions: new Set<FsAction>(),
          isGlob: cap.scope.isGlob,
        };
        for (const a of cap.actions) entry.actions.add(a);
        fsAcc.set(key, entry);
        break;
      }
      case 'net': {
        const key = `${cap.scope.host}:${cap.scope.port ?? '*'}`;
        const entry = netAcc.get(key) ?? { ...cap.scope };
        // blockPrivate is OR-ed: if any declaration wants it blocked, block it.
        entry.blockPrivate = entry.blockPrivate || cap.scope.blockPrivate;
        netAcc.set(key, entry);
        break;
      }
      case 'exec': {
        execAcc.set(cap.scope.binary, { binary: cap.scope.binary });
        break;
      }
      case 'env': {
        // Inject dominates read (inject requires read); collapse to inject if present.
        const existing = envAcc.get(cap.scope.name);
        const action: EnvAction =
          existing?.action === 'inject' || cap.actions.includes('inject') ? 'inject' : 'read';
        envAcc.set(cap.scope.name, { name: cap.scope.name, action });
        break;
      }
      case 'ipc': {
        ipcAcc.set(cap.scope.endpoint, { endpoint: cap.scope.endpoint });
        break;
      }
      case 'clock': {
        // tzdata dominates system.
        if (cap.scope.source === 'tzdata') policy.clock = 'tzdata';
        else if (policy.clock === 'none') policy.clock = 'system';
        break;
      }
      case 'assert': {
        assertAcc.set(cap.scope.id, cap.scope);
        break;
      }
    }
  }

  policy.fs = mergeFsRoots(
    [...fsAcc.values()].map((e) => ({
      path: e.path,
      actions: normalizeFsActions([...e.actions]),
      isGlob: e.isGlob,
    }))
  );
  policy.net = [...netAcc.values()];
  policy.exec = [...execAcc.values()];
  policy.env = [...envAcc.values()];
  policy.ipc = [...ipcAcc.values()];
  policy.assertions = [...assertAcc.values()];

  stableSort(policy);
  return policy;
}

// ---------------------------------------------------------------------------
// FS normalization helpers
// ---------------------------------------------------------------------------

/** write/create/delete imply read; delete implies write. Canonical order. */
function normalizeFsActions(actions: FsAction[]): FsAction[] {
  const set = new Set(actions);
  if (set.has('delete')) set.add('write');
  if (set.has('write') || set.has('create') || set.has('delete')) set.add('read');
  const order: FsAction[] = ['read', 'create', 'write', 'delete'];
  return order.filter((a) => set.has(a));
}

/**
 * Merge fs roots where one path is a prefix-superset of another. bwrap and
 * friends bind directories — once /workspace/** is bound, /workspace/src is
 * redundant. We pick the shortest covering path and union the actions.
 *
 * This is a deliberately conservative merge: exact equality and simple prefix
 * only. No glob-intersection solver.
 */
function mergeFsRoots(
  roots: { path: string; actions: FsAction[]; isGlob: boolean }[]
): { path: string; actions: FsAction[]; isGlob: boolean }[] {
  // Stable sort by path length ascending → shortest first.
  const sorted = [...roots].sort((a, b) => prefixKey(a.path).localeCompare(prefixKey(b.path)));
  const out: typeof sorted = [];

  for (const r of sorted) {
    const covering = out.find((existing) => covers(existing.path, r.path));
    if (covering) {
      covering.actions = normalizeFsActions([...covering.actions, ...r.actions]);
      continue;
    }
    out.push({ ...r });
  }
  return out;
}

/** Strip glob suffixes for prefix comparison. "/a/**" → "/a/". */
function prefixKey(path: string): string {
  return path.replace(/\/\*\*$/, '/').replace(/\/\*$/, '/');
}

/** True if `a` covers `b` (a is a directory prefix of b, treating globs as open-ended). */
function covers(a: string, b: string): boolean {
  if (a === b) return true;
  const aKey = prefixKey(a);
  const bKey = prefixKey(b);
  if (aKey === bKey) return true;
  // a must end in "/" after normalization to be a directory prefix.
  if (!aKey.endsWith('/')) return false;
  return bKey.startsWith(aKey);
}

// ---------------------------------------------------------------------------
// Deterministic output — golden files demand stable ordering.
// ---------------------------------------------------------------------------

function stableSort(p: NormalizedPolicy): void {
  p.fs.sort((a, b) => a.path.localeCompare(b.path));
  p.net.sort((a, b) => a.host.localeCompare(b.host) || portCmp(a.port, b.port));
  p.exec.sort((a, b) => a.binary.localeCompare(b.binary));
  p.env.sort((a, b) => a.name.localeCompare(b.name));
  p.ipc.sort((a, b) => a.endpoint.localeCompare(b.endpoint));
  p.assertions.sort((a, b) => a.id.localeCompare(b.id));
}

function portCmp(a: number | null, b: number | null): number {
  if (a === b) return 0;
  if (a === null) return -1;
  if (b === null) return 1;
  return a - b;
}

// ---------------------------------------------------------------------------
// Input validation — shape-only. Grammar errors surface from parseCapability.
// ---------------------------------------------------------------------------

function assertManifestShape(raw: RawServerManifest): void {
  if (!raw || typeof raw !== 'object') {
    throw new CompilationError('MANIFEST_SHAPE', 'manifest must be an object');
  }
  if (raw.grammar !== undefined) {
    if (typeof raw.grammar !== 'string') {
      throw new CompilationError('MANIFEST_SHAPE', 'manifest.grammar must be a string');
    }
    if (raw.grammar !== GRAMMAR_VERSION) {
      throw new CompilationError(
        'GRAMMAR_VERSION_MISMATCH',
        `manifest declares grammar "${raw.grammar}" but compiler is at "${GRAMMAR_VERSION}"`,
        { declared: raw.grammar, supported: GRAMMAR_VERSION }
      );
    }
  }
  if (typeof raw.name !== 'string' || !raw.name) {
    throw new CompilationError('MANIFEST_SHAPE', 'manifest.name must be a non-empty string');
  }
  if (typeof raw.version !== 'string' || !raw.version) {
    throw new CompilationError('MANIFEST_SHAPE', 'manifest.version must be a non-empty string');
  }
  if (!Array.isArray(raw.tools)) {
    throw new CompilationError('MANIFEST_SHAPE', 'manifest.tools must be an array');
  }
  if (raw.serverCapabilities && !Array.isArray(raw.serverCapabilities)) {
    throw new CompilationError('MANIFEST_SHAPE', 'manifest.serverCapabilities must be an array');
  }
  for (const [i, t] of raw.tools.entries()) {
    if (!t || typeof t !== 'object') {
      throw new CompilationError('MANIFEST_SHAPE', `tools[${i}] must be an object`);
    }
    if (typeof t.name !== 'string' || !t.name) {
      throw new CompilationError('MANIFEST_SHAPE', `tools[${i}].name must be a non-empty string`);
    }
    if (!Array.isArray(t.capabilities)) {
      throw new CompilationError('MANIFEST_SHAPE', `tools[${i}].capabilities must be an array`);
    }
  }
}
