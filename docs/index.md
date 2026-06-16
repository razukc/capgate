# capgate

A sandbox compiler for Model Context Protocol servers. Reads a manifest, emits a sandbox configuration — bubblewrap argv or `docker run` flags — that your host can hand straight to the runtime. The sandbox boundary lives in the repo, reviewed in a PR, before the server ever runs.

- [GitHub repo](https://github.com/razukc/capgate) — install, examples, validated servers.

## Writing

- [A working map of MCP security tools](./positioning/) — three lanes of MCP security (static technical, static governance, dynamic attestation), where capgate sits, and what's deliberately not on the map.
- [I pointed capgate at Damn Vulnerable MCP](./dvmcp/) — the honest scorecard against ten deliberately-broken servers: one clean prevention, four containments, three misses. What a capability compiler does and doesn't stop.
