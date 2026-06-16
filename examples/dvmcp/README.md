# DVMCP capability manifests

The honest-minimum capgate manifests used in the case study
**"I pointed capgate at Damn Vulnerable MCP."**

Each file declares what the corresponding [Damn Vulnerable MCP](https://github.com/harishsg993010/damn-vulnerable-MCP-server)
challenge tool *claims* to need — not what its (deliberately broken) code actually does.
The point of the study is to compile that honest declaration and ask whether the
emitted boundary stops the attack anyway.

| Manifest | DVMCP challenge | capgate's effect |
|---|---|---|
| `challenge1-prompt-injection.json` | 1 — Basic Prompt Injection | ❌ model layer — only caps blast radius |
| `challenge3-excessive-permission.json` | 3 — Excessive Permission Scope | ✅ **prevents** — the bullseye |
| `challenge7-token-theft.json` | 7 — Token Theft | ◐ **contains** — egress allowlist blocks exfil |
| `challenge8-code-execution.json` | 8 — Malicious Code Execution | ◐ **contains** — boxes the blast radius |
| `challenge9-command-injection.json` | 9 — Command Injection | ◐ **contains** — blocks private ranges |

## Reproduce

From the repo root, with capgate built (`npm install && npm run build`):

```bash
node dist/cli.js compile examples/dvmcp/challenge3-excessive-permission.json --target docker --pretty
node dist/cli.js compile examples/dvmcp/challenge7-token-theft.json     --target egress --egress-target squid --pretty
node dist/cli.js compile examples/dvmcp/challenge9-command-injection.json --target egress --egress-target nftables --pretty
```

Or, once installed from npm (`npm i -g capgate`):

```bash
capgate compile examples/dvmcp/challenge3-excessive-permission.json --target docker --pretty
```

The CLI prints a JSON envelope — `{ "argv": [...], "egress": [...], "notes": [...] }`.
The `notes[]` field is where capgate tells you what it *couldn't* express precisely
(e.g. a filesystem glob lowered to a directory mount), and `unenforceable[]` is where
it refuses to silently drop a rule it can't enforce (e.g. a wildcard host on the
nftables target). Reading those two fields is the point — they are the honest edges
of the boundary.

Compiled against `capgate@0.0.3`.
