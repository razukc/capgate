# Policy Compiler Fixtures

Golden-file inputs for the MCP → Sandbox Policy Compiler.

## Layout

```
fixtures/policy/
  manifests/         # inputs — hand-authored MCP-style manifests
    filesystem.json  # pure-FS shape: read/write bounded by one root
    fetch.json       # net + declared assertion (RFC1918 block is proxy-enforced)
    puppeteer.json   # nested-sandbox edge: Chromium, X11 IPC, untrusted JS
  policies/          # expected outputs (added alongside adapters)
    <adapter>/<manifest>.json
```

Each manifest represents one of the three shapes identified during the
go/no-go exercise:

| Manifest   | Shape                                   | Why it's here                                      |
| ---------- | --------------------------------------- | -------------------------------------------------- |
| filesystem | pure fs, one root, read/write split     | 9/10 real MCP servers look like this               |
| fetch      | net:* + `assert:` for semantic rules    | Proves the enforceable-vs-declared IR split        |
| puppeteer  | nestedSandbox + IPC + exec + net + fs   | Proves the edge case doesn't break the abstraction |

## Authoring rules

- Capability strings follow `src/policy/grammar.ts`. Any input that the
  grammar rejects is by definition invalid — do not "relax" fixtures to
  make them pass.
- `serverCapabilities` applies to every tool. Per-tool entries are additive.
- If a capability cannot be enforced by any adapter (e.g. "read-only SQL"),
  use `assert:<id>:<description>`. Do not silently drop it.
- Treat these files as executable documentation. When the grammar changes,
  the fixtures change with it in the same PR.
