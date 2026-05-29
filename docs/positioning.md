# Static technical, static governance, dynamic attestation: a working map of MCP security tools

capgate is a sandbox compiler for Model Context Protocol servers. It reads a manifest, parses the capability strings, and emits a sandbox configuration — bubblewrap argv or `docker run` flags — that the host can hand straight to the runtime. The artifact lives in the repo, reviewed in a PR, before the server ever runs.

That's one lane. There are at least two others, each answering a different question about the server's behavior, each shipping a different kind of artifact. They aren't substitutes for each other — but they're routinely filed under the same label, which is what makes "MCP security" a confusing thing to evaluate.

This is the working map I use to keep them straight.

## Three lanes

### Static technical

**The question:** what is this server *allowed to reach*?

**The artifact:** a sandbox configuration — bubblewrap argv, `docker run` flags, an egress allowlist, an env-var policy. Compiled from the server's manifest, lives in the repo, reviewed in a PR before the server ever runs.

**What it isn't:** it doesn't execute the server, doesn't watch traffic, doesn't intercept calls. The output is a static artifact your host hands to the runtime.

This is the lane capgate is in. The tool is, literally, a compiler for that artifact.

### Static governance

**The question:** does this server's *declared behavior* meet our standards?

**The artifact:** a report — usually against a threat catalog, a compliance framework, or a policy document. Also compile-time, also emitted from the manifest, also repo-resident. The output is a verdict (or a list of findings), not a sandbox configuration.

**What it isn't:** it doesn't run the server either, but its question is procedural ("do we accept this server?"), not technical ("how do we contain it?"). A team that needs both will run both. A team that only needs one usually knows which question they're actually asking.

### Dynamic attestation

**The question:** what did this server *actually do*, at the moment it did it?

**The artifact:** a runtime decision log, usually cryptographically signed — a receipt per tool call, tamper-evident, queryable after the fact. Runtime, not compile-time. Doesn't reach the manifest; it reaches the wire.

**What it isn't:** it isn't *prevention*. Attestation tells you what happened. If you want the call blocked before it lands, you want one of the first two lanes — or you want a separate gateway, which is a different problem entirely (see below).

## Why these three

These three lanes share a common shape: each one verifies *something about the server itself*. They differ on **when** the verification happens (compile-time twice, runtime once) and on **what** is verified (capability scope, declared behavior, actual behavior).

Two things are deliberately *not* on this map even though they often get filed under "MCP security":

- **Per-request authentication and authorization** — gateways, OAuth flows, identity at the network boundary. That's about *who is calling*, not *what the server is allowed to do*. Important problem, different problem.
- **Runtime threat detection** — pattern-watching, prompt-injection sniffing, behavioral anomaly alerts. Adjacent to dynamic attestation but distinct: detection alerts you to a pattern, attestation gives you evidence of a specific event.

Both are real categories with their own tools. They're just not the same conversation as the three lanes above.

## What you do with the map

Most teams running MCP servers in production end up wanting more than one of the three. The pairings I see:

- **Static technical + dynamic attestation.** Constrain what the server *can* do at compile time; log what it *did* do at runtime. The two artifacts compose: the sandbox policy bounds the universe of possible events, and the attestation log records which events from that bounded universe actually happened.
- **Static technical + static governance.** Both compile-time, both repo-resident, both reviewed in PRs. One produces the sandbox; the other produces the sign-off.
- **All three.** Defense in depth where the cost of a bad call is high.

What you almost never need is *two tools doing the same lane*. If a project pitches itself as "MCP security" without telling you which lane it's in, the first question to ask is which of the three artifacts it actually produces.

## A note on this map

This is a working model, not a settled taxonomy. The three lanes have held up across the projects I've classified — but the MCP ecosystem is young enough that a fourth lane could emerge, or the boundaries between these could shift. The point of publishing the map isn't to fix the categories; it's to make explicit which question a given tool is answering, so two tools that answer different questions stop getting compared on the same axis.
