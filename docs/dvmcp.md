# I pointed capgate at Damn Vulnerable MCP. Here's what the compiled policy caught — and what it couldn't.

*A capability-compiler meets ten deliberately-broken MCP servers. The honest scorecard: it cleanly stops one class, shrinks the blast radius on several, and is useless against another. Knowing which is which is the whole point.*

---

## The setup

[Damn Vulnerable MCP (DVMCP)](https://github.com/harishsg993010/damn-vulnerable-MCP-server) is a teaching project: ten MCP servers, each built to demonstrate one attack — prompt injection, tool poisoning, excessive permission scope, token theft, command injection, and so on. It's the closest thing the ecosystem has to a shared adversarial fixture.

[capgate](https://github.com/razukc/capgate) is a *compile-time* tool. You write a manifest declaring what an MCP server is *allowed* to do — `fs:read:/workspace/**`, `net:connect:api.github.com:443`, nothing else — and it compiles that to a concrete sandbox policy (`docker run` flags, bwrap argv, or an egress-proxy config). It does **not** run anything, watch traffic, or inspect the server's code. It turns a declared capability set into an enforced boundary.

So this is a fair, falsifiable test: for each DVMCP challenge, I wrote the *honest minimum* manifest, compiled it, and asked one question — **does the boundary capgate emits actually stop the attack?**

The answer is not "yes" across the board, and the cases where it's "no" are the interesting ones.

---

## The bullseye: Challenge 3 — Excessive Permission Scope

The vulnerable tool advertises "read a file from the public directory" and then does this:

```python
@mcp.tool()
def read_file(filename: str) -> str:
    # VULNERABILITY: doesn't restrict file access to the public directory
    if os.path.exists(filename):          # any absolute path works
        with open(filename, "r") as f:
            return f.read()
```

The private directory next door holds `employee_salaries.txt`, `acquisition_plans.txt`, and `system_credentials.txt` (a live DB password and cloud API keys). A prompt-injected agent just calls `read_file("/tmp/dvmcp_challenge3/private/system_credentials.txt")` and walks out with everything.

The honest manifest — what the tool *claims* to need:

```json
{ "name": "read_file", "capabilities": ["fs:read:/tmp/dvmcp_challenge3/public/**"] }
```

capgate compiles it (`--target docker`) to:

```
--rm --cap-drop ALL --security-opt no-new-privileges --read-only
--network none
--volume /tmp/dvmcp_challenge3/public:/tmp/dvmcp_challenge3/public:ro
```

**The attack now fails — not because the path check got better, but because the private directory is not mounted into the container.** `read_file("/tmp/.../private/system_credentials.txt")` returns *file not found*, because inside the sandbox that file does not exist. The path-traversal bug is still in the code; capgate made it unreachable. Network is off, the filesystem is read-only, every capability is dropped.

capgate is loud about one approximation it made here. The output carries a `notes[]` entry: *"fs: `/tmp/dvmcp_challenge3/public/**` lowered to volume mount `/tmp/dvmcp_challenge3/public` — Docker mounts directories, not globs. Fine-grained glob enforcement is the server's job."* The declared capability was a glob; Docker can only mount a directory. capgate grants the *directory* and tells you, in the output, that the finer-grained glob is now the server's responsibility, not the sandbox's. That's the pattern for the whole exercise — the boundary is real, and the places it's coarser than the declaration are written down, not hidden.

This is capgate's bullseye. The vulnerability *is* over-broad reach, and a capability boundary is exactly the right shape of answer. One of ten — but it's a clean kill.

---

## The contains, not prevents: Challenges 7, 8, 9

These are the honest middle. capgate doesn't stop the bug; it shrinks what the bug can achieve.

### Challenge 7 — Token Theft → exfiltration blocked at egress

The tool leaks a bearer token and API key into an error string (which flows straight into the LLM context):

```python
Authorization: Bearer {email_token.get('access_token')}
API Key: {email_token.get('api_key')}
```

capgate can't stop the tool from *reading* its own token. What it can do is constrain where that token can *go*. The honest manifest declares one egress endpoint, and the `--target egress --egress-target squid` output is:

```
# capgate-egress.squid.conf (generated — do not edit)
acl to_private dst 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8 169.254.0.0/16 ::1/128 fc00::/7 fe80::/10
http_access deny to_private
acl cg_dst_0 dstdomain api.emailpro.com
acl cg_port_0 port 443
http_access allow cg_dst_0 cg_port_0 CONNECT
http_access deny all
```

A poisoned tool that tries to POST the token to `attacker.example.com` is refused at the proxy — the allowlist contains exactly one host, and the config ends in an unconditional `deny all`. The classic prompt-injection-to-exfiltration chain is broken at the network boundary.

**Honest caveat, stated plainly:** the token still reaches the model's context, and if an attacker can smuggle it out through the *one allowed channel* (a crafted request to `api.emailpro.com` itself), capgate does not see it. It closes the broad exfil path, not every conceivable one. (A second honesty note: DVMCP stores these tokens in a world-readable file; a faithful capgate manifest would never grant `fs` access to that file, so the tool couldn't read it at all. The egress allowlist is the backstop for when the secret legitimately lives in the process.)

### Challenge 8 — Malicious Code Execution → boxed, not blocked

This one exposes a real limit of the grammar, and it's worth being loud about. The tool is:

```python
@mcp.tool()
def execute_shell_command(command: str) -> str:
    result = subprocess.check_output(command, shell=True, ...)   # arbitrary shell
```

**capgate's capability grammar cannot express "run arbitrary shell."** `exec` is basename-only (`exec:spawn:git`), by design — there is no `exec:spawn:*`. So you *cannot* write an honest manifest that grants this tool what it actually does. capgate's own docs say it: *"a manifest that under-declares is a bug in the manifest."* capgate will not make a shell-exec tool safe, and it doesn't pretend to.

What it does instead is contain the blast radius of the surrounding server. Compile the *legitimate* tools (`get_system_info`, `analyze_log_file`) and you get:

```
--rm --cap-drop ALL --security-opt no-new-privileges --read-only
--network none
--volume /tmp/dvmcp_challenge8/logs:/tmp/dvmcp_challenge8/logs:ro
```

If `execute_shell_command` ships anyway and fires, it runs inside *that* box: no network, no Linux capabilities, read-only rootfs, no injected secrets, only the logs directory visible. Successful RCE that can't reach the network, can't escalate, and can't see a credential is a dramatically smaller incident. That's defense-in-depth — explicitly *not* prevention.

### Challenge 9 — Command Injection → private ranges blocked, public egress can't be

`network_diagnostic(target, options)` pipes user input straight into `shell=True`. It's a network tool, so the honest manifest must grant `net:connect:*` — and capgate is honest about what that costs:

```json
{ "egress": [{ "host": "*", "port": null, "blockPrivate": true }] }
```

A wildcard host means the egress *allowlist* can't help — you can't allowlist "everywhere." But `blockPrivate` is automatically set, and the `nftables` target enforces it in-kernel:

```
table inet capgate {
  chain egress {
    type filter hook output priority 0; policy drop;
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16 } drop
    ...
  }
}
```

So command injection still runs, and still reaches the public internet — but it *cannot* pivot to `169.254.169.254` (cloud metadata), `127.0.0.1` (local services), or RFC1918 internal hosts. And capgate refuses to fake the rest: the wildcard rule shows up in an `unenforceable[]` field with the reason *"nftables filters IPs, not hostnames; '*' cannot be expressed as an IP allowlist. Use the 'squid' target for wildcard/hostname rules."* It tells you what it can't do — and where to go instead — rather than silently dropping it.

---

## The honest miss: Challenge 1 — Basic Prompt Injection

The Challenge 1 tool has no teeth at all — it reads an in-memory dictionary:

```python
@mcp.tool()
def get_user_info(username: str) -> str:
    users = {"admin": "System administrator with full access", ...}
    return f"User information for {username}: {users.get(username)}"
```

The attack isn't about what the tool *reaches*. It's about convincing the model, through injected text, to ignore its instructions. The honest manifest is empty (`"capabilities": []`), and capgate compiles it to the most locked-down sandbox it can produce:

```
--rm --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp --network none
```

**And the prompt injection still works, completely.** capgate constrains what a tool is allowed to *do*; it has nothing to say about whether the LLM can be *talked into* doing it. Challenges 1, 2 (tool poisoning), and 6 (indirect injection) all live at the model layer, and a capability compiler is the wrong instrument for all three. It shrinks the blast radius if those attacks then try to *reach* something — but it does not prevent the manipulation itself.

Anyone who tells you a sandbox compiler stops prompt injection is selling you something. It doesn't. It makes prompt injection *less useful* by capping what the hijacked tools can touch.

---

## The scorecard

| # | Challenge | capgate's effect |
|---|---|---|
| 1 | Basic Prompt Injection | ❌ Doesn't prevent (model layer) — only caps blast radius |
| 2 | Tool Poisoning | ❌ Doesn't prevent (model layer) — only caps blast radius |
| 3 | **Excessive Permission Scope** | ✅ **Prevents** — the bullseye |
| 4 | Rug Pull | ◐ The declared capability set is the contract drift violates; `assert:` records it. No runtime enforcement in v0.0.x |
| 5 | Tool Shadowing | — Out of scope (naming/registry) |
| 6 | Indirect Prompt Injection | ❌ Doesn't prevent (model layer) — only caps blast radius |
| 7 | **Token Theft** | ◐ **Contains** — egress allowlist blocks exfil; token still readable |
| 8 | **Malicious Code Execution** | ◐ **Contains** — can't express shell-exec; boxes the blast radius |
| 9 | **Remote Access Control** (cmd injection) | ◐ **Contains** — blocks private ranges; can't allowlist public egress for a net tool |
| 10 | Multi-Vector | ◐ Partial — depends on the chain |

**One clean prevention. Four meaningful containments. Three honest misses. Two out-of-scope.**

That is the real shape of a capability compiler against a real adversarial corpus. It is not a silver bullet, and the cases it can't touch are exactly the cases the rest of the MCP-security stack (scanners, runtime monitors, the model's own defenses) exists to cover. capgate is one layer. It happens to be the layer that turns "this server can reach your whole disk and the open internet" into "this server can reach one directory, read-only, and one host" — and that boundary lives in a file you can review in a pull request before the server ever runs.

A static scanner like NVIDIA's SkillSpector lives one layer up: its least-privilege checks would flag Challenge 3 at review time — the tool's code reaches past its declaration, which trips an "underdeclared capability" rule before you ever install. But flagging the mismatch and enforcing the honest declaration are different jobs. A scanner tells you the manifest is dishonest; capgate makes an honest manifest *binding* — it confirms `fs:read:/tmp/dvmcp_challenge3/public/**` was declared, but only the compiled mount stops the tool reading the private directory anyway. You want both, and they don't substitute for each other.

---

## Reproduce it

The five capability manifests live in [`examples/dvmcp/`](https://github.com/razukc/capgate/tree/main/examples/dvmcp) in the capgate repo. Every policy above is the `argv`/`config` payload from `capgate@0.0.3` — the CLI prints a JSON envelope (`{ "argv": [...], "egress": [...], "notes": [...] }`); the blocks above show the payload, and I call out the `notes[]`/`unenforceable[]` fields explicitly where they matter, because those honest edges are the point. Run it yourself from the repo root (`npm install && npm run build`):

```bash
node dist/cli.js compile examples/dvmcp/challenge3-excessive-permission.json --target docker --pretty
node dist/cli.js compile examples/dvmcp/challenge7-token-theft.json --target egress --egress-target squid --pretty
node dist/cli.js compile examples/dvmcp/challenge9-command-injection.json --target egress --egress-target nftables --pretty
```

If you run MCP servers and decide their capability boundary by hand today — a devcontainer here, a mount list there — I'd genuinely like to know where that decision lives for you, and what it costs. That's the actual open question this whole exercise is circling.

*There's a [discussion thread for this post on dev.to](https://dev.to/kcrazy/i-pointed-capgate-at-damn-vulnerable-mcp-heres-what-it-caught-and-what-it-couldnt-52i1) — that's the best place to tell me where that boundary decision lives for you.*
