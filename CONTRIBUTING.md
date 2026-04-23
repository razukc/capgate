# Contributing to capgate

Thanks for the interest. capgate is at design-partner stage (v0.0.x) — the grammar and IR are still actively changing, and the fastest way to help is to stress-test the abstraction against real MCP servers you'd like to sandbox.

## What we're looking for

1. **Manifests that break the grammar.** If you have an MCP server whose capability needs can't be expressed as `fs:… | net:… | exec:… | env:… | ipc:… | clock:… | assert:…`, open an issue with the server README and what you'd expect the capability set to look like. This is the single most valuable contribution right now.
2. **Adapter gaps.** If `lowerToBwrap` output doesn't match what your host would actually need to do to run the server safely, file an issue with the manifest, the current output, and the expected output. Golden-file diffs make this mechanical to review.
3. **Real-world feedback on the IR.** Does `assert:` capture the right thing? Should `nestedSandbox` live somewhere else? Are we missing a primitive (e.g. GPU, volume mounts, user-namespace mapping)? Open a discussion.

## What we're not looking for yet

- New adapters (Firecracker, E2B, Daytona). We'll accept these once there's a named partner using them and golden fixtures backing them. Sending a PR cold will get a polite "not yet."
- Heuristic inference from tool descriptions. That's a separate tool, not this library.
- MCP client/server protocol implementation.

## Development

```bash
npm install
npm run build
npm test
npm run test:update-goldens   # regenerate fixtures after intentional changes
```

Node ≥ 18 required. Tests are Vitest; the grammar tests live in `tests/unit/policy/grammar.test.ts` and the adapter goldens in `tests/fixtures/policy/policies/`.

## Changing the grammar or IR

1. Bump `GRAMMAR_VERSION` in `src/policy/grammar.ts` if the change breaks existing manifests (MINOR for additive, MAJOR for removing/redefining).
2. Update or add a golden fixture that demonstrates the change.
3. Run `npm run test:update-goldens` and commit the regenerated `tests/fixtures/policy/policies/**/*.json` in the same commit as the code change.
4. Reviewers read the golden diff. A change with no matching fixture update will be rejected.

## Filing issues

Use the [bug / policy mismatch template](.github/ISSUE_TEMPLATE/bug_or_policy_mismatch.md). Issues without a concrete manifest and expected output will be asked to add one before triage.

## Security

See [SECURITY.md](SECURITY.md). Please do **not** file security issues in the public tracker — email first.

## License

By contributing you agree your contributions are licensed under the MIT License.
