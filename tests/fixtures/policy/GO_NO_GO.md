# Go/no-go exercise — MCP server inventory

Before committing to the capability-grammar abstraction, we collected 10 real MCP servers and hand-wrote a bubblewrap policy for each to answer: *does the proposed IR cover what real servers need, and does lowering to bwrap actually work mechanically?*

**Verdict: GO.** 9/10 lowered mechanically. 1/10 (puppeteer) required a `nestedSandbox` refinement. Two servers (fetch, postgres) exposed semantic guarantees the sandbox layer cannot enforce — these motivated the first-class `assert:` capability kind rather than silently dropping them.

Exercise performed 2026-04 against READMEs and source of the servers below. Capability strings are what a well-authored manifest *should* declare for each server, not what the servers publish today (MCP manifests do not yet carry capability metadata — that is the gap this library exists to close).

| # | Server | Source | Capabilities | Verdict | Notes |
|---|---|---|---|---|---|
| 1 | filesystem | [modelcontextprotocol/servers/src/filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) | `fs:read:<roots>`, `fs:write,create,delete:<roots>` | mechanical | Read vs write differs only in `--ro-bind` vs `--bind`. Codified in [`manifests/filesystem.json`](manifests/filesystem.json). |
| 2 | fetch | [modelcontextprotocol/servers/src/fetch](https://github.com/modelcontextprotocol/servers/tree/main/src/fetch) | `net:connect:*`, `assert:fetch.block_rfc1918` | mechanical w/ caveat | RFC1918 block is not a bwrap primitive — lives in the egress proxy. Promoted to `assert:` so it stays in the audit trail. Codified in [`manifests/fetch.json`](manifests/fetch.json). |
| 3 | git | [modelcontextprotocol/servers/src/git](https://github.com/modelcontextprotocol/servers/tree/main/src/git) | `fs:read,write:<repo>`, `exec:spawn:git`, `net:connect:*` (fetch/push) | mechanical | `exec:spawn:git` covered by the `/usr` system mount. Net needed for remote operations. |
| 4 | memory | [modelcontextprotocol/servers/src/memory](https://github.com/modelcontextprotocol/servers/tree/main/src/memory) | `fs:read,write:$MEMORY_FILE_PATH` | mechanical | Same shape as filesystem with a single pinned file. |
| 5 | time | [modelcontextprotocol/servers/src/time](https://github.com/modelcontextprotocol/servers/tree/main/src/time) | `fs:read:/usr/share/zoneinfo`, `clock:tzdata` | mechanical | Motivated the `clock:` kind — timezone data is a bind, system clock is namespaced. No net, no user data. |
| 6 | github | [modelcontextprotocol/servers-archived/src/github](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/github) | `net:connect:api.github.com:443`, `env:inject:GITHUB_PERSONAL_ACCESS_TOKEN`, `fs:read,write:/workspace/**` | mechanical | Host pinning via egress proxy. Env-injection is the fourth primitive after fs/net/exec. Codified in [`manifests/github.json`](manifests/github.json) as a 3-tool union (create_issue + search_code + apply_patch) demonstrating per-tool→server-level merging. |
| 7 | postgres | [modelcontextprotocol/servers-archived/src/postgres](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/postgres) | `net:connect:<db>:<port>`, `assert:postgres.read_only_txn` | mechanical + **motivated `assert:`** | "Read-only SQL" is enforced by `BEGIN READ ONLY TRANSACTION` inside the server, not by the sandbox. Silently dropping the guarantee would be a security lie; the `assert:` kind keeps it in audit. |
| 8 | sqlite | [modelcontextprotocol/servers-archived/src/sqlite](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/sqlite) | `fs:read,write:<db_path>` | mechanical | Same shape as memory. |
| 9 | brave-search | [modelcontextprotocol/servers-archived/src/brave-search](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/brave-search) | `net:connect:api.search.brave.com:443`, `env:inject:BRAVE_API_KEY` | mechanical | Same shape as github. |
| 10 | puppeteer | [modelcontextprotocol/servers-archived/src/puppeteer](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/puppeteer) | `exec:spawn:chromium?nestedSandbox=true`, `net:connect:*`, `ipc:connect:x11`, `fs:read,write:/tmp/puppeteer/**` | **bespoke** | Chromium carries its own sandbox that fights namespace isolation. `nestedSandbox=true` keeps user/pid/ipc namespaces for the inner sandbox. Codified in [`manifests/puppeteer.json`](manifests/puppeteer.json). |

## What this exercise produced

Three primitives cover the mechanical 9:

1. **fs roots** — `--bind` / `--ro-bind`
2. **net hosts** — egress-proxy allowlist (bwrap is binary share/unshare only)
3. **exec binaries** — metadata; covered by the `/usr` system mount

Plus a fourth — **env / secret injection** (`env:inject:…`) — that every token-carrying server needs.

The exercise also surfaced two findings that shaped the IR:

- **Enforceable vs declared.** Not every capability can be enforced by a namespace sandbox. Rather than silently drop them, we keep them as `assert:` metadata on the artifact.
- **`nestedSandbox` as a refinement, not a kind.** Only Chromium/Electron and QEMU need it in practice. A refinement (`?nestedSandbox=true`) keeps the IR small; the adapter handles the edge case explicitly.

## Fixtures codified

Four of the ten are persisted as golden-file fixtures (representatives of the distinct shapes, not an exhaustive set):

- [`manifests/filesystem.json`](manifests/filesystem.json) — pure-FS shape (covers 9/10 real servers).
- [`manifests/fetch.json`](manifests/fetch.json) — `net` + `assert` (enforceable-vs-declared split).
- [`manifests/github.json`](manifests/github.json) — `net` (host-pinned) + `env:inject` + `fs`, with three tools that union into a server-level policy. Exercises the multi-tool merge path and is the README flagship example.
- [`manifests/puppeteer.json`](manifests/puppeteer.json) — `nestedSandbox` edge case.

The remaining 6 (git, memory, time, postgres, sqlite, brave-search) have hand-written capability lists in this document but are not yet codified as fixtures. They follow the filesystem or github shape and are low-value as additional golden files until the grammar or IR changes.

## Caveat

The exercise was done against README prose and source, not a live `tools/list` response. MCP manifests today do not publish capability metadata, so the capability strings above are *what a well-authored manifest should declare*, not what servers ship. v0.0 assumes manifest authors add capabilities by hand; a future heuristic inference pass over description + input schema is out of scope for v0.1.
