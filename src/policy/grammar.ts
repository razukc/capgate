// Capability string grammar — the shorthand humans write in manifests.
//
// Format:   <kind>:<actions>:<scope>[?refinement=value&...]
// Examples:
//   fs:read,write:/workspace/**
//   fs:read:/usr/share/zoneinfo
//   net:connect:api.github.com:443
//   net:connect:*                        (any host, any port; implicit blockPrivate=true)
//   exec:spawn:git
//   env:inject:GITHUB_PAT
//   ipc:connect:x11
//   clock:tzdata
//   assert:postgres.read_only_txn:"all queries run in READ ONLY TRANSACTION"
//
// The grammar is deliberately small. Anything that cannot be expressed here
// (e.g. seccomp syscall filters) is an adapter concern, not a capability.

import {
  Capability,
  CompilationError,
  FsAction,
  NetAction,
  ExecAction,
  EnvAction,
  IpcAction,
  Refinements,
} from './ir.js';

/**
 * Grammar version. Bumped whenever the capability string syntax, refinement
 * keys, or IR shape changes in a non-backwards-compatible way. Manifests MAY
 * declare `"grammar": "0.0"` to pin; the compiler rejects mismatches.
 *
 * Semver: MAJOR.MINOR, no patch. MINOR bumps are additive (new kind, new
 * refinement). MAJOR bumps remove or redefine existing syntax.
 */
export const GRAMMAR_VERSION = '0.0';

const FS_ACTIONS: ReadonlySet<FsAction> = new Set(['read', 'write', 'create', 'delete']);
const NET_ACTIONS: ReadonlySet<NetAction> = new Set(['connect']);
const EXEC_ACTIONS: ReadonlySet<ExecAction> = new Set(['spawn']);
const ENV_ACTIONS: ReadonlySet<EnvAction> = new Set(['read', 'inject']);
const IPC_ACTIONS: ReadonlySet<IpcAction> = new Set(['connect']);

const GLOB_CHARS = /[*?[\]]/;
const RFC1918_OR_LOOPBACK =
  /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1$|localhost$)/i;

export interface ParseResult {
  capability: Capability;
}

export function parseCapability(raw: string): ParseResult {
  const [body, refinementStr] = splitRefinements(raw);
  const parts = splitTop(body, ':');
  if (parts.length < 2) {
    throw new CompilationError('CAP_MALFORMED', `expected at least <kind>:<scope>, got "${raw}"`);
  }

  const kind = parts[0];
  const refinements = parseRefinements(refinementStr);

  switch (kind) {
    case 'fs':     return { capability: parseFs(parts, refinements, raw) };
    case 'net':    return { capability: parseNet(parts, refinements, raw) };
    case 'exec':   return { capability: parseExec(parts, refinements, raw) };
    case 'env':    return { capability: parseEnv(parts, refinements, raw) };
    case 'ipc':    return { capability: parseIpc(parts, refinements, raw) };
    case 'clock':  return { capability: parseClock(parts, refinements, raw) };
    case 'assert': return { capability: parseAssert(parts, refinements, raw) };
    default:
      throw new CompilationError('CAP_UNKNOWN_KIND', `unknown capability kind "${kind}"`, { raw });
  }
}

// ---------------------------------------------------------------------------
// Per-kind parsers
// ---------------------------------------------------------------------------

function parseFs(parts: string[], refinements: Refinements | undefined, raw: string): Capability {
  if (parts.length !== 3) {
    throw new CompilationError('CAP_FS_SHAPE', `fs needs <actions>:<path>, got "${raw}"`);
  }
  const actions = parseActions<FsAction>(parts[1], FS_ACTIONS, 'fs', raw);
  const path = parts[2];
  if (!path.startsWith('/')) {
    throw new CompilationError('CAP_FS_RELATIVE', `fs path must be absolute: "${path}"`);
  }
  return {
    kind: 'fs',
    actions,
    scope: { path, isGlob: GLOB_CHARS.test(path) },
    refinements,
  };
}

function parseNet(parts: string[], refinements: Refinements | undefined, raw: string): Capability {
  // net:connect:host  OR  net:connect:host:port
  if (parts.length < 3 || parts.length > 4) {
    throw new CompilationError('CAP_NET_SHAPE', `net needs <actions>:<host>[:<port>], got "${raw}"`);
  }
  const actions = parseActions<NetAction>(parts[1], NET_ACTIONS, 'net', raw);
  const host = parts[2];
  const port = parts.length === 4 ? parseInt(parts[3], 10) : null;
  if (port !== null && (Number.isNaN(port) || port < 1 || port > 65535)) {
    throw new CompilationError('CAP_NET_PORT', `net port out of range: "${parts[3]}"`);
  }
  const blockPrivate =
    host === '*' ? true : !RFC1918_OR_LOOPBACK.test(host);
  return {
    kind: 'net',
    actions,
    scope: { host, port, blockPrivate },
    refinements,
  };
}

function parseExec(parts: string[], refinements: Refinements | undefined, raw: string): Capability {
  if (parts.length !== 3) {
    throw new CompilationError('CAP_EXEC_SHAPE', `exec needs <actions>:<binary>, got "${raw}"`);
  }
  const actions = parseActions<ExecAction>(parts[1], EXEC_ACTIONS, 'exec', raw);
  const binary = parts[2];
  if (binary.includes('/')) {
    throw new CompilationError('CAP_EXEC_PATH', `exec binary is a basename only: "${binary}"`);
  }
  return { kind: 'exec', actions, scope: { binary }, refinements };
}

function parseEnv(parts: string[], refinements: Refinements | undefined, raw: string): Capability {
  if (parts.length !== 3) {
    throw new CompilationError('CAP_ENV_SHAPE', `env needs <actions>:<name>, got "${raw}"`);
  }
  const actions = parseActions<EnvAction>(parts[1], ENV_ACTIONS, 'env', raw);
  const name = parts[2];
  if (!/^[A-Z_][A-Z0-9_]*$/.test(name)) {
    throw new CompilationError('CAP_ENV_NAME', `env var name must be UPPER_SNAKE: "${name}"`);
  }
  return { kind: 'env', actions, scope: { name }, refinements };
}

function parseIpc(parts: string[], refinements: Refinements | undefined, raw: string): Capability {
  if (parts.length !== 3) {
    throw new CompilationError('CAP_IPC_SHAPE', `ipc needs <actions>:<endpoint>, got "${raw}"`);
  }
  const actions = parseActions<IpcAction>(parts[1], IPC_ACTIONS, 'ipc', raw);
  return { kind: 'ipc', actions, scope: { endpoint: parts[2] }, refinements };
}

function parseClock(parts: string[], refinements: Refinements | undefined, raw: string): Capability {
  if (parts.length !== 2) {
    throw new CompilationError('CAP_CLOCK_SHAPE', `clock needs <source>, got "${raw}"`);
  }
  const source = parts[1];
  if (source !== 'system' && source !== 'tzdata') {
    throw new CompilationError('CAP_CLOCK_SOURCE', `clock source must be system|tzdata: "${source}"`);
  }
  return { kind: 'clock', actions: [], scope: { source }, refinements };
}

function parseAssert(parts: string[], refinements: Refinements | undefined, raw: string): Capability {
  if (parts.length < 2) {
    throw new CompilationError('CAP_ASSERT_SHAPE', `assert needs <id>[:<description>], got "${raw}"`);
  }
  const id = parts[1];
  const description = parts.slice(2).join(':') || id;
  return { kind: 'assert', actions: [], scope: { id, description }, refinements };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseActions<T extends string>(
  raw: string,
  allowed: ReadonlySet<T>,
  kind: string,
  full: string
): T[] {
  if (!raw) throw new CompilationError('CAP_ACTIONS_EMPTY', `${kind} requires actions in "${full}"`);
  const parts = raw.split(',').map((a) => a.trim());
  const out: T[] = [];
  for (const a of parts) {
    if (!allowed.has(a as T)) {
      throw new CompilationError('CAP_ACTION_UNKNOWN', `${kind} action "${a}" not allowed`, {
        allowed: [...allowed],
      });
    }
    if (!out.includes(a as T)) out.push(a as T);
  }
  return out;
}

function splitRefinements(raw: string): [string, string | undefined] {
  const q = raw.indexOf('?');
  if (q === -1) return [raw, undefined];
  return [raw.slice(0, q), raw.slice(q + 1)];
}

function parseRefinements(raw: string | undefined): Refinements | undefined {
  if (!raw) return undefined;
  const out: Refinements = {};
  for (const pair of raw.split('&')) {
    const [k, v] = pair.split('=');
    if (k === 'nestedSandbox') {
      out.nestedSandbox = v === 'true' || v === '1';
    } else {
      (out.adapter ??= {})[k] = v ?? true;
    }
  }
  return out;
}

// splitTop is a colon-splitter that respects quoted segments so that
// assert:id:"text with : inside" parses correctly.
function splitTop(raw: string, sep: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQuote = false;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === '"') { inQuote = !inQuote; continue; }
    if (ch === sep && !inQuote) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  out.push(cur);
  return out;
}
