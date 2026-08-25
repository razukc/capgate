# capgate

**Compile MCP tool manifests into sandbox policies.**

MCP servers today either run with full host trust (Claude Desktop, most wrappers) or get wrapped in a one-size-fits-all container. Neither lets you say *this server needs `fs:read:/workspace/**` and `net:connect:api.github.com:443`, nothing else* — and have a sandbox policy fall out of that declaration.

`capgate` is the missing compile step. It reads a [Model Context Protocol](https://modelcontextprotocol.io) server manifest, parses capability strings, and emits a concrete sandbox policy your host can hand straight to bubblewrap or `docker run`.

```
manifest (JSON) → Capability[] → NormalizedPolicy → adapter (bwrap | docker) → argv + egress + env + assertions
```

It is a **sandbox compiler for MCP servers**, not a runtime. It does not execute tools, resolve secrets, or speak MCP on the wire. Its job is to make the sandbox boundary **reviewable in a PR before the first agent call** — what the server is allowed to reach lives in the repo, not in someone's `docker run` muscle memory.

**For platform and security engineers** who can't ship MCP servers under blanket host trust and don't want to hand-write bwrap argv or `docker run` flags per server. **Not for** end-user agent UIs (this isn't a runtime), or for teams who want post-hoc tool-call auditing — that's a different lane (see [How capgate compares](#how-capgate-compares) below for the short version, or [A working map of MCP security tools](https://razukc.github.io/capgate/positioning/) for the full discussion).

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
capgate compile manifest.json --target egress --egress-target squid    --pretty
capgate compile manifest.json --target egress --egress-target nftables --pretty
cat manifest.json | capgate compile - --target docker
```

`--target egress` emits a static proxy config for a host-run proxy (`--egress-target squid|nftables`, default `squid`). Exits non-zero on parse errors (3), unknown arguments (2), or `CompilationError` (4). See `capgate --help`.

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
| Adapter output shape (`argv`, `egress`, `envInjections`, `assertions`, `provenance`, `notes`) | **Stable.** Fields are additive; existing fields keep their semantics. |
| `provenance` block (`manifestHash`, `grammarVersion`, `canonicalization`) | **Usable (v0.0.4+).** The RFC 8785 canonicalization profile and the `sha256:`-prefixed hash form are fixed; the projection it hashes (identity + capability strings) is additive. |
| `compile()` and `lowerToBwrap` / `lowerToDocker` exports | **Stable.** |
| `lowerToEgress(policy, { target })` (`squid` / `nftables`) | **Usable.** Artifact shape (`config`, `filename`, `unenforceable`, `notes`) is additive; more `EgressTarget` values land without breaking existing ones. |
| `exec`, `ipc`, `clock` capability kinds | **Usable.** May gain refinements (like `exec:?nestedSandbox=true` did); existing forms keep working. |
| Adapter option objects (e.g. `lowerToDocker(policy, { readOnlyRootfs })`) | **Evolving.** Will expand in v0.1 as more adapters land. |
| `assert:` validator hook | **Metadata-only in v0.0.x.** Runtime hook lands in v0.2. |

Pin a minor range against `v0.0.x` for production review pipelines. Grammar additions land in `v0.1`; existing strings keep parsing.

## Provenance: binding a policy to its manifest

Every compiled artifact carries a `provenance` block:

```jsonc
"provenance": {
  "manifestHash": "sha256:6c73dbf717b5d228f2e349a03426a87454190c42f59e2833afe8c901dc610466",
  "grammarVersion": "0.0",
  "canonicalization": "RFC8785"
}
```

`manifestHash` is SHA-256 over a canonical projection of the capability manifest — its identity (`name`, `version`) and declared capability strings, nothing else. It binds the emitted policy to the exact declaration it came from. Two properties fall out:

- **Reproducible.** The same manifest produces the same hash regardless of key order or whitespace (the projection is canonicalized per [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), JSON Canonicalization Scheme). Compile one manifest to `bwrap`, `docker`, and `egress` and you get the **same** `manifestHash` in all three artifacts — one canonical form, every enforcement target bound to one anchor.
- **A policy-drift anchor.** The hash covers what determines the policy. Edit a capability and the hash changes; edit a `description` and it does not — so a stale `manifestHash` is a genuine "the declared capabilities changed" signal, not noise from a doc tweak.

Canonicalization is **fail-closed**: a value capgate can't canonicalize reproducibly (a non-integer number, `NaN`, `Infinity`) raises `CompilationError` rather than emitting bytes that might hash differently elsewhere.

**One distinction worth stating plainly.** capgate's `manifestHash` is computed over *capgate's own capability manifest* — the document you write to declare what a server may do (`ManifestProjection` in `src/policy/provenance.ts:55`: `name`, `version`, `serverCapabilities`, `tools[].capabilities`). That is a different artifact from an MCP *tool* manifest (the server's published `tools/list` that a signing extension such as `io.modelcontextprotocol/signed-manifests` hashes). capgate does not ingest, verify, or hash `tools/list`; direct consumption of that proposal's `manifestHash` would require ingesting the tool-manifest format and is **intentionally out of scope — not built and not planned**. The two are **siblings** — same canonicalization scheme (RFC 8785, sorted keys, no whitespace, `src/policy/provenance.ts:88` fail-closed on non-integers), different documents — so anyone canonicalizing the same projection reproduces the same bytes without a bespoke convention. If you're composing capgate with a manifest-signing or call-attestation layer, capgate is a *consumer* of the canonical-bytes idea for its own input — not a producer of a versioned hash format you must implement, and not a verifier of `Ed25519`/`keyId`/`expiresAt`. That boundary is permanent.

## Composing with signed manifests (informative)

Signed tool manifests ([`#2913`](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2913), [`io.modelcontextprotocol/signed-manifests`](https://github.com/RajSidwadkar/mcp-signed-manifests/blob/main/docs/proposal.md)) prove descriptor integrity at admission — the `tools/list` the model reasoned against is the one the server actually signed. capgate proves a different invariant: that declaration, once admitted, maps to a concrete sandbox (`argv` + `egress`). Same problem family, orthogonal layers.

The join point is the fingerprint. That proposal defines `manifestHash = "sha256:" + hex(SHA-256(canonical_bytes(manifest)))` as a **reference anchor** (`proposal.md §6`); capgate defines a `manifestHash` over its own capability projection with the **same RFC 8785 scheme** but a **different document** (see [Provenance](#provenance-binding-a-policy-to-its-manifest) above). A host that both verifies `tools/manifest` and compiles with capgate can carry **both** hashes and treat a rotation between assessment and dispatch (`manifestHash` mismatch, `TOOL_MANIFEST_TAMPERED`) as a re-consent or refuse-dispatch decision — the same composition pattern discussed for `SEP-2828`/`vaara` and `decision-os-min` per-call grants in `#2913`. That binding is **host/gateway policy, not spec**: capgate stays a compiler, does not verify `Ed25519` signatures, manage `keyId`/`expiresAt`, or speak MCP on the wire. No new dependency, no carrier field, no layer collapse — each layer keeps its own verification, referenced by a shared canonical form. There is no planned `toolManifestHash` carrier in capgate artifacts.

If you don't use signed manifests, nothing changes. If you do, capgate's `provenance.manifestHash` remains the capability-drift anchor; the tool-manifest `manifestHash` lives alongside it in host state, not in capgate.

## How capgate compares

MCP-server security splits across three lanes. capgate is in the static-technical lane. The other two aren't competitors — most teams running MCP servers in production end up wanting more than one.

| Lane | What it does | When you'd use it |
|---|---|---|
| **Static technical** (capgate) | Reads a manifest, emits sandbox argv + egress allowlist. Static artifact, no runtime. | You want the sandbox policy reviewable in PR before the server ever runs. |
| **Static governance** | Reads a manifest, emits a compliance report against a threat catalog or policy framework. | You want a procedural sign-off on a server before it's adopted. |
| **Dynamic attestation** | Logs and cryptographically signs each tool call at runtime. | You need a tamper-evident record of what the server actually did. |

Two adjacent concerns are *not* on this map: per-request authentication (gateways / OAuth — about *who* is calling) and runtime threat detection (pattern-watching, anomaly alerts — about flagging in real time). Both are real categories; both are different conversations. See [A working map of MCP security tools](https://razukc.github.io/capgate/positioning/) for the full discussion.

If you arrived here from a comparison post and you wanted dynamic attestation or static governance, capgate isn't that — but the artifact it emits can be the input to either.

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
- Lowering to `bwrap` (Linux namespace sandbox), `docker` (`docker run` argv), and `egress` (proxy config — `squid` / `nftables`, **shipped**). Worker `resourceLimits` (in-process JS isolation) is the next target.
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

### Why egress lowers to a proxy config, not a proxy

`egress[]` is emitted by the bwrap and docker adapters but enforced by neither — the host is told to wire a proxy. The neither-adapter-can-actually-do-net property is real: bwrap's `--unshare-net` is all-or-nothing (it always isolates now; see the net posture in `bwrap.ts`), and Docker's default bridge NATs but doesn't allowlist. Closing that gap by *running* a proxy would turn capgate into a gateway and drag a long-running, root-adjacent process into a library whose whole value is being a static compiler.

The move keeps capgate a compiler: a third lowering target, `lowerToEgress(policy, { target })`, compiles `policy.net` into a config blob for a proxy the host *already runs* — `squid` (allowlist by hostname via CONNECT, no TLS interception) and `nftables` (allowlist by IP+port in-kernel, bypass-proof, plus the `blockPrivate` drops) ship today. Both configs are fail-closed: squid ends in an unconditional `http_access deny all`, nftables defaults to `policy drop`, and an empty `policy.net` compiles to a deny-ALL config. The artifact carries an `unenforceable[]` field naming every declared rule the chosen target *cannot* honor (e.g. nftables can't express `api.github.com` — it filters IPs, not rotating hostnames), so "portable" stays honest: it compiles everywhere and tells you what each backend loses. Envoy/Cloudflare/microVM targets are later entries behind the same `EgressTarget` switch; the IR does not change. This keeps Docker MCP Gateway and Cloudflare as *targets you compile to*, not competitors — the manifest stays the single reviewable source of truth, and enforcement is borrowed, not built.

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

1. **Egress proxy choice.** mitmproxy (great DX, slow, not prod-grade) vs nftables (hard to author, prod-grade, Linux-only) vs Envoy (prod-grade, ops-heavy). Direction settled: capgate stays a compiler and emits a config blob per target rather than running a proxy — see [Why egress lowers to a proxy config, not a proxy](#why-egress-lowers-to-a-proxy-config-not-a-proxy). Both `squid` and `nftables` now ship as reference bindings (they cover complementary cases — hostname-CONNECT vs in-kernel IP allowlist). Remaining sub-question is whether a dev-only mitmproxy emitter is worth carrying.
2. **Path glob semantics.** bwrap binds directories, not globs. A `fs:read:/workspace/**` capability lowers to `--ro-bind /workspace /workspace`, which is a *superset* of the declared scope. Runtime enforcement of globs is an MCP-server concern.
3. **Server-level vs tool-level capabilities.** v0.0 unions them. Finer-grained per-tool sandboxing (one sandbox per invocation) is possible but expensive — deferred until a user asks for it.

## Contributing

If you have a concrete manifest + unexpected compiler output, file an issue with both. See [CONTRIBUTING.md](CONTRIBUTING.md) for what else is useful.

Design-partner stage: if you're already reviewing MCP servers in production and willing to share how your review process works, [issue #1](https://github.com/razukc/capgate/issues/1) has a question for you.

## Security

capgate compiles declarations into sandbox policies downstream hosts trust — bugs here can silently over-grant. Please report privately per [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
