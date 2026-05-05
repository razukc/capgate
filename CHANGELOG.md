# Changelog

All notable changes to capgate will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows semver once it reaches v0.1 — prior to that, expect breaking changes on any release.

## [Unreleased]

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
