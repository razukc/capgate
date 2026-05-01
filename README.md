# capgate

**Compile MCP tool manifests into sandbox policies.**

MCP servers today either run with full host trust (Claude Desktop, most wrappers) or get wrapped in a one-size-fits-all container. Neither lets you say *this server needs `fs:read:/workspace/**` and `net:connect:api.github.com:443`, nothing else* — and have a sandbox policy fall out of that declaration.

`capgate` is the missing compile step. It reads a [Model Context Protocol](https://modelcontextprotocol.io) server manifest, parses capability strings, and emits a concrete sandbox policy your host can hand straight to bubblewrap (Docker adapter shipping next).

```
manifest (JSON) → Capability[] → NormalizedPolicy → bwrap argv + egress rules + env list
```

It is a compiler, not a runtime. It does not execute tools, resolve secrets, or speak MCP on the wire.

**Validated against 10 real MCP servers** (filesystem, fetch, git, memory, time, github, postgres, sqlite, brave-search, puppeteer) — see [the inventory](tests/fixtures/policy/GO_NO_GO.md). 9/10 lower mechanically; the 10th (puppeteer) drove the `nestedSandbox` refinement.

Status: **v0.0.1.** Bwrap adapter is golden-tested and ready to embed. Grammar may evolve through v0.1 based on design-partner feedback.

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

The `argv` you'd hand to `bwrap` for the manifest above (abridged):

```
--unshare-net --unshare-pid --unshare-ipc --unshare-user-try
--die-with-parent --new-session
--ro-bind-try /usr /usr      --ro-bind-try /lib /lib
--ro-bind-try /etc/ssl /etc/ssl
--proc /proc --tmpfs /tmp
--bind /workspace /workspace
--clearenv --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Full golden output: [`tests/fixtures/policy/policies/bwrap/filesystem.json`](tests/fixtures/policy/policies/bwrap/filesystem.json). Worked examples for `fetch` (egress + assertions) and `puppeteer` (nested-sandbox edge case) live alongside it.

### CLI

```bash
capgate compile manifest.json --target bwrap --pretty
cat manifest.json | capgate compile - --target bwrap
```

Exits non-zero on parse errors (3), unknown arguments (2), or `CompilationError` (4). See `capgate --help`.

---

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

## Validated servers

Before committing to the capability-grammar abstraction, we ran a [go/no-go exercise](tests/fixtures/policy/GO_NO_GO.md) against 10 real MCP servers. The full inventory (capability strings, source links, lowering notes) lives in [`GO_NO_GO.md`](tests/fixtures/policy/GO_NO_GO.md); the summary:

| Server | Capabilities (excerpt) | Status | Fixture |
|---|---|---|---|
| [filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) | `fs:read,write:<roots>` | mechanical | [filesystem.json](tests/fixtures/policy/manifests/filesystem.json) |
| [fetch](https://github.com/modelcontextprotocol/servers/tree/main/src/fetch) | `net:connect:*`, `assert:fetch.block_rfc1918` | mechanical (assert) | [fetch.json](tests/fixtures/policy/manifests/fetch.json) |
| [git](https://github.com/modelcontextprotocol/servers/tree/main/src/git) | `fs:read,write:<repo>`, `exec:spawn:git`, `net:connect:*` | mechanical | — |
| [memory](https://github.com/modelcontextprotocol/servers/tree/main/src/memory) | `fs:read,write:$MEMORY_FILE_PATH` | mechanical | — |
| [time](https://github.com/modelcontextprotocol/servers/tree/main/src/time) | `fs:read:/usr/share/zoneinfo`, `clock:tzdata` | mechanical | — |
| [github](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/github) | `net:connect:api.github.com:443`, `env:inject:GITHUB_PERSONAL_ACCESS_TOKEN` | mechanical | — |
| [postgres](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/postgres) | `net:connect:<db>:<port>`, `assert:postgres.read_only_txn` | mechanical (assert) | — |
| [sqlite](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/sqlite) | `fs:read,write:<db_path>` | mechanical | — |
| [brave-search](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/brave-search) | `net:connect:api.search.brave.com:443`, `env:inject:BRAVE_API_KEY` | mechanical | — |
| [puppeteer](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/puppeteer) | `exec:spawn:chromium?nestedSandbox=true`, `ipc:connect:x11` | nested-sandbox | [puppeteer.json](tests/fixtures/policy/manifests/puppeteer.json) |

Three of the ten ship as golden-file fixtures (representatives of the distinct shapes); the remaining seven follow the filesystem or github shape and are tracked in `GO_NO_GO.md` for the next grammar review. **MCP server author?** If your server isn't listed and you'd like a fixture review, [open an issue](https://github.com/razukc/capgate/issues/new) with a link to the manifest.

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
