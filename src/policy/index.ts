// Public surface of the policy compiler. Re-exported from the root "capgate"
// entry point in src/index.ts.

export type {
  Capability,
  CapabilityKind,
  FsAction,
  NetAction,
  ExecAction,
  EnvAction,
  IpcAction,
  FsScope,
  NetScope,
  ExecScope,
  EnvScope,
  IpcScope,
  ClockScope,
  AssertScope,
  Refinements,
  ToolManifest,
  ServerManifest,
  NormalizedPolicy,
} from './ir.js';
export { CompilationError, isEnforceable } from './ir.js';

export { parseCapability, GRAMMAR_VERSION } from './grammar.js';
export type { ParseResult } from './grammar.js';

export { compile, parseManifest, normalize } from './compiler.js';
export type { RawServerManifest, RawToolManifest } from './compiler.js';

export { lowerToBwrap } from './adapters/bwrap.js';
export type { BwrapArtifact, BwrapOptions, EgressRule } from './adapters/bwrap.js';

export { lowerToDocker } from './adapters/docker.js';
export type { DockerArtifact, DockerOptions } from './adapters/docker.js';
