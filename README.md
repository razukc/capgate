# capgate

**Compile MCP tool manifests into sandbox policies.**

MCP servers today either run with full host trust (Claude Desktop, most wrappers) or get wrapped in a one-size-fits-all container. Neither lets you say *this server needs `fs:read:/workspace/**` and `net:connect:api.github.com:443`, nothing else* — and have a sandbox policy fall out of that declaration.

`capgate` is the missing compile step. It reads a [Model Context Protocol](https://modelcontextprotocol.io) server manifest, parses capability strings, and emits a concrete sandbox policy your host can hand straight to bubblewrap or `docker run`.

```
manifest (JSON) → Capability[] → NormalizedPolicy → adapter (bwrap | docker) → argv + egress + env + assertions
```

It is a compiler, not a runtime. It does not execute tools, resolve secrets, or speak MCP on the wire. Its job is to make the sandbox boundary **reviewable in a PR before the first agent call** — what the server is allowed to reach lives in the repo, not in someone's `docker run` muscle memory.

**For platform and security engineers** who can't ship MCP servers under blanket host trust and don't want to hand-write bwrap argv or `docker run` flags per server. **Not for** end-user agent UIs (this isn't a runtime), or for teams who want post-hoc tool-call auditing (different layer — see [How capgate compares](#how-capgate-compares)).

---

## Install

```bash
npm install capgate
```

Requires Node.js ≥ 18.

## 30-second example

```ts
import { compile, lowerToDocker } from 'capgate';

const docker = lowerToDocker(compile({
  name: 'my-server',
  version: '0.1.0',
  tools: [{ name: 'read_file', capabilities: ['fs:read:/workspace/**'] }],
}));

console.log(docker.argv.join(' '));
// → --rm --cap-drop ALL --security-opt no-new-privileges --read-only
//   --tmpfs /tmp --network none --volume /workspace:/workspace:ro
```

One capability in, one container policy out. No declared network → `--network none`. Read-only declared → `:ro` mount. No env declared → no env crosses the boundary. The CLI prints the same artifact for `bwrap`.

## CLI

```bash
capgate compile manifest.json --target bwrap  --pretty
capgate compile manifest.json --target docker --pretty
cat manifest.json | capgate compile - --target docker
```

Exits non-zero on parse errors (3), unknown arguments (2), or `CompilationError` (4). See `capgate --help`.

---

## Worked example: `github` server with PAT

The 30-second example is a single tool with a single capability. A realistic MCP server has several tools, several capability kinds, and a threat model that motivates the sandbox in the first place.

**The threat.** An MCP `github` server runs with a personal access token in its environment. A tool description carrying adversarial text triggers an outbound request to attacker-controlled infrastructure, exfiltrating the PAT. A default container won't stop this — it inherits the host environment and reaches any host on the internet.

**The verdict.** capgate compiles the manifest below into a policy whose egress allowlist contains exactly one entry: `api.github.com:443`. An egress proxy honoring that allowlist refuses any outbound request that isn't api.github.com, blocking PAT exfiltration to a third party. No host env is inherited; only `GITHUB_PERSONAL_ACCESS_TOKEN` is named for the host's secret store to inject at exec time.

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

The compiler unions per-tool capabilities into a server-level policy: `apply_patch` widens `/workspace` from `:ro` to `:rw`, and only one env name survives the merge.

```jsonc
// docker.egress  ===  bwrap.egress
[{ "host": "api.github.com", "port": 443, "blockPrivate": true }]
```

Adapter `argv` (docker shown in full; bwrap abridged):

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

Note what's *missing* from the docker `argv`: no inherited host env, no host network, no extra capabilities, no writable rootfs. capgate emits the policy; enforcement is the host's job.

Full golden outputs: [`bwrap/github.json`](tests/fixtures/policy/policies/bwrap/github.json), [`docker/github.json`](tests/fixtures/policy/policies/docker/github.json). Worked examples for `filesystem`, `fetch` (egress + assertions), and `puppeteer` (nested-sandbox edge case) live alongside them.

---

## What's stable, what's evolving

`v0.0.x` is published for adopters who want to pin against capgate today. Stability commitments:

| Surface | Status in v0.0.x |
|---|---|
| Capability string grammar (`fs`, `net`, `env`, `assert` kinds) | **Stable.** String form will not change; new refinements are additive. |
| Adapter output shape (`argv`, `egress`, `envInjections`, `assertions`, `notes`) | **Stable.** Fields are additive; existing fields keep their semantics. |
| `compile()` and `lowerToBwrap` / `lowerToDocker` exports | **Stable.** |
| `exec`, `ipc`, `clock` capability kinds | **Usable.** May gain refinements (like `exec:?nestedSandbox=true` did); existing forms keep working. |
| Adapter option objects (e.g. `lowerToDocker(policy, { readOnlyRootfs })`) | **Evolving.** Will expand in v0.1 as more adapters land. |
| `assert:` validator hook | **Metadata-only in v0.0.x.** Runtime hook lands in v0.2. |

Pin a minor range against `v0.0.x` for production review pipelines. Grammar additions land in `v0.1`; existing strings keep parsing.

## How capgate compares

MCP-server security splits across several layers. capgate sits at compile-time policy emission. The other layers are not competitors — most teams running MCP servers in production end up wanting more than one.

| Approach | What it does | When you'd use it |
|---|---|---|
| **Compile-time policy emission** (capgate) | Reads a manifest, emits sandbox argv + egress allowlist. Static artifact, no runtime. | You want the sandbox policy reviewable in PR before the server ever runs. |
| **Runtime inspection** | Watches a running MCP server, flags risky tool calls against a threat catalog. | You want post-hoc audit signal on a server you didn't author. |
| **Signed receipts / decision logs** | Cryptographically logs each tool invocation. | You need a tamper-evident trail of which tools ran with what arguments. |
| **API gateway / per-request auth** | Authorizes each MCP request at a network boundary. | Your concern is *who* is allowed to call *which* tools, not what the tool can reach. |

If you arrived here from a comparison post and you wanted runtime inspection or signed receipts, capgate isn't that — but the artifact it emits can be the input to either.

---

## Validated servers

Before committing to the capability-grammar abstraction, we ran a [go/no-go exercise](tests/fixtures/policy/GO_NO_GO.md) against 10 real MCP servers. The full inventory (capability strings, source links, lowering notes) lives in [`GO_NO_GO.md`](tests/fixtures/policy/GO_NO_GO.md); the summary:

| Server | Capabilities (excerpt) | Status | Manifest | bwrap | docker |
|---|---|---|---|---|---|
| [filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) | `fs:read,write:<roots>` | mechanical | [filesystem.json](tests/fixtures/policy/manifests/filesystem.json) | [✓](tests/fixtures/policy/policies/bwrap/filesystem.json) | [✓](tests/fixtures/policy/policies/docker/filesystem.json) |
| [fetch](https://github.com/modelcontextprotocol/servers/tree/main/src/fetch) | `net:connect:*`, `assert:fetch.block_rfc1918` | mechanical (assert) | [fetch.json](tests/fixtures/policy/manifests/fetch.json) | [✓](tests/fixtures/policy/policies/bwrap/fetch.json) | [✓](tests/fixtures/policy/policies/docker/fetch.json) |
| [git](https://github.com/modelcontextprotocol/servers/tree/main/src/git) | `fs:read,write:<repo>`, `exec:spawn:git`, `net:connect:*` | mechanical | — | — | — |
| [memory](https://github.com/modelcontextprotocol/servers/tree/main/src/memory) | `fs:read,write:$MEMORY_FILE_PATH` | mechanical | — | — | — |
| [time](https://github.com/modelcontextprotocol/servers/tree/main/src/time) | `fs:read:/usr/share/zoneinfo`, `clock:tzdata` | mechanical | — | — | — |
| [github](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/github) | `net:connect:api.github.com:443`, `env:inject:GITHUB_PERSONAL_ACCESS_TOKEN` | mechanical | [github.json](tests/fixtures/policy/manifests/github.json) | [✓](tests/fixtures/policy/policies/bwrap/github.json) | [✓](tests/fixtures/policy/policies/docker/github.json) |
| [postgres](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/postgres) | `net:connect:<db>:<port>`, `assert:postgres.read_only_txn` | mechanical (assert) | — | — | — |
| [sqlite](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/sqlite) | `fs:read,write:<db_path>` | mechanical | — | — | — |
| [brave-search](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/brave-search) | `net:connect:api.search.brave.com:443`, `env:inject:BRAVE_API_KEY` | mechanical | — | — | — |
| [puppeteer](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/puppeteer) | `exec:spawn:chromium?nestedSandbox=true`, `ipc:connect:x11` | nested-sandbox | [puppeteer.json](tests/fixtures/policy/manifests/puppeteer.json) | [✓](tests/fixtures/policy/policies/bwrap/puppeteer.json) | [✓](tests/fixtures/policy/policies/docker/puppeteer.json) |

Four of the ten ship as golden-file fixtures for both adapters; the rest follow one of the four shapes and are tracked in `GO_NO_GO.md` for the next grammar review. **MCP server author?** If your server isn't listed and you'd like a fixture review, [open an issue](https://github.com/razukc/capgate/issues/new) with a link to the manifest.

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

If you have a concrete manifest + unexpected compiler output, file an issue with both. See [CONTRIBUTING.md](CONTRIBUTING.md) for what else is useful.

Design-partner stage: if you're already reviewing MCP servers in production and willing to share how your review process works, [issue #1](https://github.com/razukc/capgate/issues/1) has a question for you.

## Security

capgate compiles declarations into sandbox policies downstream hosts trust — bugs here can silently over-grant. Please report privately per [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
