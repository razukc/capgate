// MCP → Sandbox Policy Compiler — Intermediate Representation
//
// Design notes (see README.md for rationale):
// - Capabilities are the unit of authorization. A ToolManifest declares zero or
//   more Capability values; the compiler lowers them into an adapter-specific
//   Policy (bwrap argv, egress-proxy rules, Worker resourceLimits, etc).
// - Capabilities are split into ENFORCEABLE and DECLARED. Enforceable ones are
//   enforced by some adapter (fs/net/exec/env/ipc). Declared ones are surfaced
//   as assertions the host or MCP server must honor (e.g. "read-only SQL").
// - Fail-closed: unknown kinds, malformed scopes, and missing required fields
//   MUST cause CompilationError. No best-effort. No silent drops.

import type { Provenance } from './provenance.js';

// ---------------------------------------------------------------------------
// Capability kinds
// ---------------------------------------------------------------------------

export type CapabilityKind =
  | 'fs'       // filesystem path access
  | 'net'      // network egress (host + optional port)
  | 'exec'     // process execution of a specific binary
  | 'env'      // environment variable read / injection
  | 'ipc'      // local IPC (unix socket, shared mem, X11)
  | 'clock'    // system clock / timezone db
  | 'assert';  // declared-only constraint for host/server enforcement

export type FsAction = 'read' | 'write' | 'create' | 'delete';
export type NetAction = 'connect';
export type ExecAction = 'spawn';
export type EnvAction = 'read' | 'inject';
export type IpcAction = 'connect';

// ---------------------------------------------------------------------------
// Capability scopes — each kind has a typed scope. No untyped bags.
// ---------------------------------------------------------------------------

export interface FsScope {
  /** Absolute path or glob. Relative paths are rejected at parse time. */
  path: string;
  /** True if `path` is a glob (contains *, **, ?, [). Derived, not input. */
  isGlob: boolean;
}

export interface NetScope {
  /** Hostname, IP, or wildcard ("*"). RFC1918 blocks are a separate flag. */
  host: string;
  /** TCP/UDP port. null = any port. */
  port: number | null;
  /** If true, RFC1918 + loopback destinations must be rejected by the proxy. */
  blockPrivate: boolean;
}

export interface ExecScope {
  /** Binary name resolved against PATH at compile time (e.g. "git", "chromium"). */
  binary: string;
}

export interface EnvScope {
  /** Variable name. Values are never embedded in the IR — handled by secret layer. */
  name: string;
}

export interface IpcScope {
  /** "unix:/path", "x11", "dbus:session", "dbus:system". */
  endpoint: string;
}

export interface ClockScope {
  /** "system" = wall clock only; "tzdata" = also needs /usr/share/zoneinfo. */
  source: 'system' | 'tzdata';
}

export interface AssertScope {
  /** Machine-readable assertion id, e.g. "postgres.read_only_txn". */
  id: string;
  /** Human explanation for audit logs and policy reviewers. */
  description: string;
}

// ---------------------------------------------------------------------------
// Capability — discriminated union keyed by `kind`
// ---------------------------------------------------------------------------

export type Capability =
  | { kind: 'fs'; actions: FsAction[]; scope: FsScope; refinements?: Refinements }
  | { kind: 'net'; actions: NetAction[]; scope: NetScope; refinements?: Refinements }
  | { kind: 'exec'; actions: ExecAction[]; scope: ExecScope; refinements?: Refinements }
  | { kind: 'env'; actions: EnvAction[]; scope: EnvScope; refinements?: Refinements }
  | { kind: 'ipc'; actions: IpcAction[]; scope: IpcScope; refinements?: Refinements }
  | { kind: 'clock'; actions: []; scope: ClockScope; refinements?: Refinements }
  | { kind: 'assert'; actions: []; scope: AssertScope; refinements?: Refinements };

export interface Refinements {
  /** Tool carries its own sandbox that conflicts with namespace isolation (e.g. Chromium). */
  nestedSandbox?: boolean;
  /** Adapter-specific free-form. Compiler passes through; adapters may read. */
  adapter?: Record<string, unknown>;
}

export function isEnforceable(cap: Capability): boolean {
  return cap.kind !== 'assert';
}

// ---------------------------------------------------------------------------
// Tool manifest — one entry per MCP tool
// ---------------------------------------------------------------------------

export interface ToolManifest {
  /** MCP tool name. Unique within a server. */
  name: string;
  /** MCP-declared description. Informational only; not used for enforcement. */
  description?: string;
  /** JSON Schema for tool input. Used for input validation, not policy. */
  inputSchema?: Record<string, unknown>;
  /** Declared capabilities. Empty array = pure function, no side effects. */
  capabilities: Capability[];
}

export interface ServerManifest {
  /** Server identifier, e.g. "@modelcontextprotocol/server-filesystem". */
  name: string;
  version: string;
  /** Capabilities that apply to every tool (e.g. "read tzdata" for time server). */
  serverCapabilities?: Capability[];
  tools: ToolManifest[];
}

// ---------------------------------------------------------------------------
// Compiled policy — the IR adapters consume. Adapters never see Capability;
// they see NormalizedPolicy, which has already been deduped, merged, and
// partitioned by kind.
// ---------------------------------------------------------------------------

export interface NormalizedPolicy {
  /** Server identity — carried through for logging and provenance. */
  server: { name: string; version: string };
  /**
   * Provenance binding this policy to the exact capability manifest it was
   * compiled from. Present when produced via compile() (which sees the source
   * manifest); absent when a NormalizedPolicy is built directly via normalize().
   */
  provenance?: Provenance;
  /** Deduped, merged fs roots. Write implies read. */
  fs: { path: string; actions: FsAction[]; isGlob: boolean }[];
  /** Deduped net endpoints. blockPrivate is OR-ed across merges. */
  net: { host: string; port: number | null; blockPrivate: boolean }[];
  /** Binaries the sandbox must keep executable. */
  exec: { binary: string }[];
  /** Env vars to inject (values resolved out-of-band from a secret store). */
  env: { name: string; action: EnvAction }[];
  /** IPC endpoints to expose. */
  ipc: { endpoint: string }[];
  /** Clock access profile. "none" if no clock capability declared. */
  clock: 'none' | 'system' | 'tzdata';
  /** Declared assertions. Adapter emits them as metadata, not as enforcement. */
  assertions: AssertScope[];
  /** True if any capability requested a nested sandbox. Adapters MUST react. */
  nestedSandbox: boolean;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class CompilationError extends Error {
  constructor(
    public code: string,
    message: string,
    public context?: Record<string, unknown>
  ) {
    super(`[${code}] ${message}`);
    this.name = 'CompilationError';
  }
}
