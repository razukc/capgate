# Changelog

All notable changes to capgate will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows semver once it reaches v0.1 — prior to that, expect breaking changes on any release.

## [Unreleased]

## [0.0.4] — 2026-06-17

### Added
- **Manifest provenance.** Every compiled artifact now carries a `provenance` block: `{ manifestHash, grammarVersion, canonicalization }`. `manifestHash` is `"sha256:" + hex` over a canonical projection of capgate's *own* capability manifest (identity + declared capability strings), binding the emitted policy to the exact declaration it was compiled from. Compiling one manifest to bwrap, docker, and egress yields the **same** `manifestHash` across all three — one canonical form, every enforcement target bound to one anchor. New public API: `computeManifestHash`, `canonicalize`, `manifestProjection`, `provenanceFor`, `CANONICALIZATION`, and the `Provenance` / `ManifestProjection` types.
- **Canonicalization** is RFC 8785 (JSON Canonicalization Scheme), hand-rolled and constrained to the value space a manifest projection occupies — keeping capgate's zero-runtime-dependency posture. It is **fail-closed**: a non-integer number, `NaN`, `Infinity`, or unsupported value throws `CompilationError` (`CANONICALIZATION_UNSUPPORTED`) rather than emitting bytes that might not reproduce elsewhere.
- `provenance.test.ts` — JCS unit vectors, fail-closed guards, hash stability (key-reorder/whitespace → same hash), drift detection (capability change → different hash), and a known-answer SHA-256.

### Changed
- **Artifact output shape**: all three adapter artifacts (`BwrapArtifact`, `DockerArtifact`, `EgressArtifact`) gain an optional `provenance` field, present whenever the artifact was produced via `compile()`. Golden fixtures regenerated. (Pre-0.1, breaking-shape changes are expected per the versioning note above.)

### Design notes
- The hash covers only identity + capability strings — **not** `description` / `inputSchema` (informational, not policy-bearing) — so `manifestHash` is a *policy-drift* anchor: it changes iff the compiled policy could change, and a description edit does not invalidate an approved policy.
- capgate is a **consumer** of this anchor: it hashes its own input and stamps it. It is not a producer of a public versioned hash format others must implement, and it does not ingest, verify, or hash an MCP *tool* manifest — capgate's capability manifest is a distinct document. The two are siblings — same RFC 8785 scheme, different documents — so a host composing capgate with `io.modelcontextprotocol/signed-manifests` (§6) carries both hashes in host state (no carrier field in capgate artifacts); the bytes remain reproducible by anyone who canonicalizes the same projection. This separation is intentional and permanent.

## [0.0.3] — 2026-06-15

### Added
- `lowerToEgress(policy, { target })` — third adapter. Compiles `policy.net` into a static config blob for a proxy the host already runs (capgate emits the config, it does not run the proxy), making the `egress[]` allowlist — previously enforced by neither bwrap nor docker — lowerable to something a host can enforce. Two targets behind one `EgressTarget` switch: `squid` (allowlist by hostname via CONNECT, no TLS interception) and `nftables` (allowlist by IP+port in-kernel, bypass-proof). The artifact carries an `unenforceable[]` field naming declared rules a given target cannot honor (e.g. nftables can't express rotating-CDN hostnames) — surfaced, never silently dropped.
- CLI gains `--target egress` with `--egress-target squid|nftables` (default `squid`).
- 21 egress unit tests + 4 golden fixtures (`squid`/`nftables` × `fetch`/`github`).

### Changed
- bwrap adapter never shares the host network namespace when egress is declared. Previously `--unshare-net` was omitted when `policy.net` was non-empty, intending "the host routes through an egress proxy"; the actual effect was the sandbox sharing the host netns with full, unrestricted reach (localhost, RFC1918, cloud metadata) while `egress[]` read as a restriction — a silent escalation. bwrap can't do selective egress (`--unshare-net` is all-or-nothing), so the lane now always isolates and the net note states plainly that declared egress is host-enforced, not bwrap-enforced.

### Design notes
- Fail-closed throughout the egress adapter: squid ends in an unconditional `http_access deny all`, nftables uses `policy drop`, empty `net` denies all egress, and `blockPrivate` is OR-ed so no single rule opts the proxy out of RFC1918/loopback/link-local drops.
- Egress enforcement is a host-policy-layer concern: capgate stays a compiler and emits a config for a proxy the host already runs, rather than becoming a gateway. Docker MCP Gateway and Cloudflare remain targets, not competitors.

## [0.0.2] — 2026-05-03

### Added
- `lowerToDocker(policy, opts)` — second adapter, parallel shape to `lowerToBwrap`. Emits `docker run` flags (volumes, `--network`, env names, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--read-only` rootfs by default) plus the same companion artifacts (`egress`, `envInjections`, `assertions`, `notes`).
- CLI gains `--target docker` alongside `bwrap`.
- Three Docker golden fixtures (filesystem, fetch, puppeteer) parallel to the bwrap goldens.

### Changed
- Relicensed from MIT to Apache-2.0 to add an explicit patent grant. Added `NOTICE` file. Relevant to enterprise embedding and OpenSSF norms.

### Design notes
- `nestedSandbox` is surfaced as a multi-option note, not silent elevation. Docker can't keep host pid/ipc namespaces the way bwrap does; granting `SYS_ADMIN` or `--privileged` is a host trust decision, not a compiler decision.
- `EgressRule` is shared between adapters (egress is host-policy-layer and target-agnostic). `dirForBind` is duplicated by design — future divergence in glob handling between adapters should be a deliberate edit.

## [0.0.1] — 2026-04-23

Initial design-partner preview release.

### Added
- Capability grammar (`fs`, `net`, `exec`, `env`, `ipc`, `clock`, `assert`) with `GRAMMAR_VERSION = "0.0"`.
- `compile(manifest)` — pure function from `RawServerManifest` to `NormalizedPolicy`.
- `lowerToBwrap(policy)` — adapter emitting bubblewrap argv, egress rules, env injection list, and declared assertions.
- `capgate` CLI — `capgate compile <manifest.json|-> [--target bwrap] [--pretty]`.
- Golden-file test suite covering filesystem, fetch, and puppeteer manifest shapes.
- [Go/no-go inventory](tests/fixtures/policy/GO_NO_GO.md) of 10 real MCP servers and their expected capability sets.

### Known limitations
- Only the `bwrap` adapter ships in v0.0. Firecracker, E2B, Daytona, and Worker adapters are deferred.
- Manifest schema validation is shape-only; no Zod schema yet (planned for v0.1).
- No secret resolution — `env:inject:*` carries names only.
- `ADAPTER_UNSUPPORTED` compilation error is reserved but not yet raised (adapters currently accept every capability type).
