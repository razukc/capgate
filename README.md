# capgate

**Compile MCP tool manifests into sandbox policies.**

`capgate` is a pure TypeScript library that reads [Model Context Protocol](https://modelcontextprotocol.io) server manifests and emits concrete sandbox policies — bubblewrap argv, egress allowlist rules, environment injection lists, and declared-but-unenforced assertions — suitable for consumption by a host runtime.

It is a compiler, not a runtime. It does not execute tools, resolve secrets, or speak MCP on the wire.

```
manifest (JSON) → Capability[] (parsed) → NormalizedPolicy (merged) → adapter output
```

Status: **v0.0.1 — design partner preview.** The grammar, IR, and bwrap adapter are implemented and golden-tested. APIs may change before v0.1.

---

## Install

```bash
npm install capgate
```

Requires Node.js ≥ 18.

## Quick example

```ts
import { compile, lowerToBwrap } from 'capgate';

const manifest = {
  name: 'filesystem',
  version: '0.6.2',
  tools: [
    {
      name: 'read_file',
      description: 'Read a file from the workspace.',
      inputSchema: { type: 'object' },
      capabilities: ['fs:read:/workspace/**'],
    },
    {
      name: 'write_file',
      description: 'Write a file to the workspace.',
      inputSchema: { type: 'object' },
      capabilities: ['fs:read,write,create:/workspace/**'],
    },
  ],
};

const policy = compile(manifest);
const artifact = lowerToBwrap(policy);

// artifact.argv   — ready for execFile("bwrap", argv)
// artifact.egress — host egress proxy rules (empty here)
// artifact.notes  — audit-friendly diagnostics
```

See [`tests/fixtures/policy/`](tests/fixtures/policy) for worked examples covering filesystem, fetch, and puppeteer manifests.

### CLI

```bash
capgate compile manifest.json --target bwrap --pretty
cat manifest.json | capgate compile - --target bwrap
```

Exits non-zero on parse errors (3), unknown arguments (2), or `CompilationError` (4). See `capgate --help`.

---

## Why this exists

MCP tool manifests declare *what* a tool does; they do not declare *what host resources it needs*. Today every runtime either trusts servers fully (Claude Desktop, most wrappers) or wraps them in a one-size-fits-all container (AIO Sandbox, E2B). Neither approach lets a security policy be *derived from the manifest*. capgate closes that gap: a pure function from `ServerManifest` to adapter-specific policies.

## Scope for v0.1

**In scope:**
- Capability grammar covering `fs`, `net`, `exec`, `env`, `ipc`, `clock`, `assert`.
- Lowering to three targets: `bwrap` (Linux namespace sandbox), egress-proxy rules (net allowlist), Worker `resourceLimits` (in-process JS isolation).
- Golden-file tests from real MCP server manifests.

**Out of scope (deferred):**
- Firecracker / microVM adapter — needed for production but not for proving the abstraction.
- E2B / Daytona / Blaxel adapters — API stability varies; wait for a design partner.
- seccomp-bpf syscall filters — requires a separate IR; out of the capability model.
- MCP client/server implementation — this library consumes manifests, it does not speak MCP on the wire.

## Capability grammar

Capabilities are strings of the form `<kind>:<actions>:<scope>[?refinement=value&...]`.

```
fs:read,write:/workspace/**
fs:read:/usr/share/zoneinfo
net:connect:api.github.com:443
net:connect:*                         # any host, any port; implicit blockPrivate=true
exec:spawn:git
exec:spawn:chromium?nestedSandbox=true
env:inject:GITHUB_PAT
ipc:connect:x11
clock:tzdata
assert:postgres.read_only_txn:"all queries run in READ ONLY TRANSACTION"
```

The grammar rejects ambiguity (relative paths, bad ports, non-UPPER_SNAKE env vars) at parse time — fail-closed, always.

## Design notes

### Why capabilities are typed and discriminated

Early drafts used `{ resource: string; actions: string[]; scope: object }`. That failed the go/no-go test: every adapter had to re-parse `resource` to know what kind of capability it was looking at. The current discriminated union (`kind: 'fs' | 'net' | ...`) makes adapter code a flat switch; no string parsing past the grammar layer.

### Why enforceable vs declared

The go/no-go exercise revealed two capabilities that cannot be enforced at the sandbox layer: `fetch`'s RFC1918 block (sandbox can only toggle net on/off) and `postgres`'s read-only transaction guarantee (lives inside the MCP server). Silently dropping them would be a security lie. Promoting them to a first-class `assert:` capability keeps them in the audit trail: adapters emit them as metadata, the host is expected to verify them out-of-band, and the compiler fails compilation if an assertion is unrecognized by any configured validator (deferred to v0.2).

### Why the grammar is string-based

JSON-object capabilities are verbose and bury the kind under keys. The string form `fs:read,write:/workspace/**` is one line in a manifest, greps cleanly, and round-trips losslessly through the grammar.

### Why `nestedSandbox` is a refinement, not a kind

Chromium carries its own sandbox that fights namespace isolation. Every production sandbox tool has a special case for this. Rather than a new capability kind, `nestedSandbox=true` is a refinement on an existing `exec:` capability — the adapter sees it during lowering and emits a different bwrap profile (user/pid/ipc namespaces kept for inner-sandbox compatibility). The IR stays small; the edge case is explicit and documented.

## Non-goals that matter

- **The compiler does not decide trust.** Capability declarations come from the manifest; the compiler does not infer them from tool descriptions. Inference belongs in a separate auditing tool. A manifest that under-declares is a bug in the manifest.
- **The compiler does not execute.** It emits policy artifacts. Running bwrap, wiring proxies, and spawning Workers is the host's job.
- **The compiler does not resolve secrets.** `env:inject:GITHUB_PAT` carries the name only. A secret store resolves the value at runtime, outside this library.

## Failure modes

- Unknown capability kind → `CompilationError('CAP_UNKNOWN_KIND')`.
- Capability a configured adapter cannot lower → `CompilationError('ADAPTER_UNSUPPORTED')` *(impl. pending)*.
- Manifest missing required fields → `CompilationError('MANIFEST_SHAPE')`.

All compilation errors are fatal. There is no warning mode.

## Validation

Before committing to the capability-grammar abstraction, we ran a [go/no-go exercise](tests/fixtures/policy/GO_NO_GO.md) against 10 real MCP servers. 9/10 lowered mechanically to bwrap; 1 (puppeteer) surfaced the need for a `nestedSandbox` refinement; 2 (fetch, postgres) motivated the first-class `assert:` capability kind. That inventory is durable and names each server, its source, and the capability string set that should lower to it.

## Test strategy

Golden files. One fixture manifest → one expected policy per adapter. Every PR that changes grammar, IR, or an adapter must update the golden files in the same commit. Reviewers read the diff. This is the primary correctness mechanism; unit tests on the grammar are secondary.

```bash
npm test                      # run all tests
npm run test:update-goldens   # regenerate golden files after intentional changes
```

## Open questions before v0.1

1. **Egress proxy choice.** mitmproxy (great DX, slow, not prod-grade) vs nftables (hard to author, prod-grade, Linux-only) vs Envoy (prod-grade, ops-heavy). Current plan: ship a thin YAML spec the compiler emits, plus one reference binding to mitmproxy for dev. Let ops pick their own enforcement.
2. **Path glob semantics.** bwrap binds directories, not globs. A `fs:read:/workspace/**` capability lowers to `--ro-bind /workspace /workspace`, which is a *superset* of the declared scope. Runtime enforcement of globs is an MCP-server concern.
3. **Server-level vs tool-level capabilities.** v0.0 unions them. Finer-grained per-tool sandboxing (one sandbox per invocation) is possible but expensive — deferred until a user asks for it.

## Contributing

Design-partner stage. **Actively seeking feedback from teams reviewing MCP servers today** — please see [issue #1](https://github.com/razukc/capgate/issues/1) and share how your review process works (as much or as little as you can publicly). That is the single most valuable contribution right now.

If you have a concrete manifest + unexpected compiler output, file an issue with both. See [CONTRIBUTING.md](CONTRIBUTING.md) for what else is useful.

## Security

capgate compiles declarations into sandbox policies downstream hosts trust — bugs here can silently over-grant. Please report privately per [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
