# Security policy

capgate is a security-adjacent library: it compiles declarations into sandbox policies that downstream hosts trust. A bug in the compiler can turn a permissive-looking manifest into a policy that silently over-grants access. Reports of such bugs are a high priority.

## Reporting a vulnerability

Please **do not** file security issues in the public GitHub tracker.

Email **kc.razu@gmail.com** with:

- A description of the issue
- A minimal manifest (and, if relevant, adapter target) that reproduces it
- The actual vs expected compiler output
- Your assessment of impact (e.g. "elevates read to write," "leaks env injection to unscoped tool")

Acknowledgment within 7 days. Fix timeline depends on severity but I will keep you informed.

## Scope

**In scope:**
- Compiler bugs that cause a capability to lower to a *broader* policy than declared (over-grant).
- Grammar bugs that accept malformed capability strings silently instead of raising `CompilationError`.
- Adapter bugs where the emitted artifact does not match the declared capability set.
- Golden-file fixtures that encode incorrect policy output.

**Out of scope:**
- Bugs in bwrap, egress proxies, or any downstream enforcement layer — report those upstream.
- Attacks on the host runtime that consumes capgate output (secret storage, proxy configuration, etc.).
- Denial of service via malformed JSON (the compiler is a pure function; callers are expected to bound input size).
- Theoretical "what if" concerns without a concrete manifest reproducing the issue.

## Disclosure

Responsible disclosure preferred. Once a fix is released, I'll publish a GitHub Security Advisory crediting the reporter (unless you prefer to remain anonymous).
