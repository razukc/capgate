# capgate

**Compile MCP tool manifests into sandbox policies.**

MCP servers today either run with full host trust (Claude Desktop, most wrappers) or get wrapped in a one-size-fits-all container. Neither lets you say *this server needs `fs:read:/workspace/**` and `net:connect:api.github.com:443`, nothing else* — and have a sandbox policy fall out of that declaration.

`capgate` is the missing compile step. It reads a [Model Context Protocol](https://modelcontextprotocol.io) server manifest, parses capability strings, and emits a concrete sandbox policy your host can hand straight to bubblewrap or `docker run`.

```
manifest (JSON) → Capability[] → NormalizedPolicy → adapter (bwrap | docker) → argv + egress + env + assertions
```

It is a compiler, not a runtime. It does not execute tools, resolve secrets, or speak MCP on the wire.

**Validated against 10 real MCP servers** (filesystem, fetch, git, memory, time, github, postgres, sqlite, brave-search, puppeteer) — see [the inventory](tests/fixtures/policy/GO_NO_GO.md). 9/10 lower mechanically; the 10th (puppeteer) drove the `nestedSandbox` refinement.

Status: **v0.0.2.** Two adapters (`bwrap`, `docker`) are golden-tested and ready to embed. Grammar may evolve through v0.1 based on design-partner feedback.

---

## Install

```bash
npm install capgate
```

Requires Node.js ≥ 18.

## Example

Consider an MCP `github` server that an agent uses with a personal access token. The threat: a tool description carrying adversarial text triggers a request to attacker-controlled infrastructure, exfiltrating the PAT. A default container won't stop this — it inherits the host environment and reaches any host on the internet. capgate compiles the manifest into a policy that does.

Three tools, three capability kinds, lowered to both adapters:

```ts
import { compile, lowerToBwrap, lowerToDocker } from 'capgate';

const manifest = {
  name: '@modelcontextprotocol/server-github',
  version: '0.6.2',
  tools: [
    {
      name: 'create_issue',
      description: 'Create an issue on a GitHub repository',
      capabilities: [
        'net:connect:api.github.com:443',
        'env:inject:GITHUB_PERSONAL_ACCESS_TOKEN',
      ],
    },
    {
      name: 'search_code',
      description: 'Search code in a local checkout',
      capabilities: [
        'fs:read:/workspace/**',
        'net:connect:api.github.com:443',
      ],
    },
    {
      name: 'apply_patch',
      description: 'Apply a code patch to the local checkout',
      capabilities: ['fs:read,write:/workspace/**'],
    },
  ],
};

const policy = compile(manifest);

const bwrap = lowerToBwrap(policy);
const docker = lowerToDocker(policy, { readOnlyRootfs: true });

// Both artifacts share the same shape:
//   .argv          — flags ready for execFile()
//   .egress        — host egress-proxy allowlist (compiler-emitted, host-enforced)
//   .envInjections — env var names the host must inject from a secret store
//   .assertions    — declared guarantees the sandbox cannot enforce; host verifies
//   .notes         — audit-friendly diagnostics (drift, edge cases, host decisions)
```

The compiler unions per-tool capabilities into a server-level policy: `apply_patch` widens `/workspace` from `:ro` to `:rw`, and only one env name (`GITHUB_PERSONAL_ACCESS_TOKEN`) survives the merge. Both artifacts produce the same `egress` entry, which is the load-bearing line — an egress proxy honoring it refuses any outbound request that isn't `api.github.com:443`, blocking PAT exfiltration to a third party.

```jsonc
// docker.egress  ===  bwrap.egress
[{ "host": "api.github.com", "port": 443, "blockPrivate": true }]
```

The `argv` for each adapter (`docker` shown in full; `bwrap` abridged):

```
# docker (full)
--rm --cap-drop ALL --security-opt no-new-privileges --read-only
--tmpfs /tmp
--volume /workspace:/workspace:rw
--env GITHUB_PERSONAL_ACCESS_TOKEN

# bwrap (abridged — see fixture for full output)
--unshare-uts --unshare-cgroup-try --unshare-user-try --unshare-pid --unshare-ipc
--die-with-parent --new-session
--ro-bind-try /usr /usr   --ro-bind-try /lib /lib   --ro-bind-try /etc/ssl /etc/ssl
--proc /proc   --tmpfs /tmp
--bind /workspace /workspace
--clearenv   --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
--setenv HOME /tmp
```

Note what's *missing* from the docker `argv`: no inherited host env, no host network, no extra capabilities, no writable rootfs. The `--env GITHUB_PERSONAL_ACCESS_TOKEN` line names the only secret that crosses the boundary; the host injects its value from a secret store at exec time. capgate emits the policy; enforcement is the host's job.

Full golden outputs: [`bwrap/github.json`](tests/fixtures/policy/policies/bwrap/github.json), [`docker/github.json`](tests/fixtures/policy/policies/docker/github.json). Worked examples for `filesystem`, `fetch` (egress + assertions), and `puppeteer` (nested-sandbox edge case) live alongside them.

### CLI

```bash
capgate compile manifest.json --target bwrap  --pretty
capgate compile manifest.json --target docker --pretty
cat manifest.json | capgate compile - --target docker
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

| Server | Capabilities (excerpt) | Status | Manifest | bwrap | docker |
|---|---|---|---|---|---|
| [filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) | `fs:read,write:<roots>` | mechanical | [filesystem.json](tests/fixtures/policy/manifests/filesystem.json) | [✓](tests/fixtures/policy/policies/bwrap/filesystem.json) | [✓](tests/fixtures/policy/policies/docker/filesystem.json) |
| [fetch](https://github.com/modelcontextprotocol/servers/tree/main/src/fetch) | `net:connect:*`, `assert:fetch.block_rfc1918` | mechanical (assert) | [fetch.json](tests/fixtures/policy/manifests/fetch.json) | [✓](tests/fixtures/policy/policies/bwrap/fetch.json) | [✓](tests/fixtures/policy/policies/docker/fetch.json) |
| [git](https://github.com/modelcontextprotocol/servers/tree/main/src/git) | `fs:read,write:<repo>`, `exec:spawn:git`, `net:connect:*` | mechanical | — | — | — |
| [memory](https://github.com/modelcontextprotocol/servers/tree/main/src/memory) | `fs:read,write:$MEMORY_FILE_PATH` | mechanical | — | — | — |
| [time](https://github.com/modelcontextprotocol/servers/tree/main/src/time) | `fs:read:/usr/share/zoneinfo`, `clock:tzdata` | mechanical | — | — | — |
| [github](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/github) | `net:connect:api.github.com:443`, `env:inject:GITHUB_PERSONAL_ACCESS_TOKEN` | mechanical | — | — | — |
| [postgres](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/postgres) | `net:connect:<db>:<port>`, `assert:postgres.read_only_txn` | mechanical (assert) | — | — | — |
| [sqlite](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/sqlite) | `fs:read,write:<db_path>` | mechanical | — | — | — |
| [brave-search](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/brave-search) | `net:connect:api.search.brave.com:443`, `env:inject:BRAVE_API_KEY` | mechanical | — | — | — |
| [puppeteer](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/puppeteer) | `exec:spawn:chromium?nestedSandbox=true`, `ipc:connect:x11` | nested-sandbox | [puppeteer.json](tests/fixtures/policy/manifests/puppeteer.json) | [✓](tests/fixtures/policy/policies/bwrap/puppeteer.json) | [✓](tests/fixtures/policy/policies/docker/puppeteer.json) |

Three of the ten ship as golden-file fixtures for both adapters (representatives of the distinct shapes — pure-fs, net+assert, nested-sandbox); the remaining seven follow the filesystem or github shape and are tracked in `GO_NO_GO.md` for the next grammar review. **MCP server author?** If your server isn't listed and you'd like a fixture review, [open an issue](https://github.com/razukc/capgate/issues/new) with a link to the manifest.

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
