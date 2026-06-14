// Golden-file tests for the egress adapter.
//
// Each manifest under tests/fixtures/policy/manifests/*.json that declares net
// capabilities is compiled and lowered to BOTH egress targets; the result is
// serialized to tests/fixtures/policy/policies/egress/<target>/*.json. Unlike
// bwrap/docker, egress takes a required opts.target, so the harness iterates the
// (manifest × target) matrix. To accept a change, set UPDATE_GOLDEN=1 and rerun.
// Reviewers read the diff — the emitted proxy config is the artifact under review.
//
// Only manifests with net capabilities get egress fixtures (filesystem and
// puppeteer's net is covered indirectly; fetch + github are the net-bearing
// fixtures with stable shapes — wildcard-host and hostname+port respectively).

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { compile } from '../../../src/policy/compiler';
import { lowerToEgress, EgressArtifact, EgressTarget } from '../../../src/policy/adapters/egress';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_ROOT = join(HERE, '../../fixtures/policy');
// Manifests that declare net capabilities — the only ones egress is meaningful for.
const MANIFESTS = ['fetch', 'github'] as const;
const TARGETS: EgressTarget[] = ['squid', 'nftables'];

const UPDATE = process.env.UPDATE_GOLDEN === '1';

describe('egress adapter — golden files', () => {
  for (const name of MANIFESTS) {
    for (const target of TARGETS) {
      it(`${name}.json → policies/egress/${target}/${name}.json`, () => {
        const raw = JSON.parse(readFileSync(join(FIXTURE_ROOT, 'manifests', `${name}.json`), 'utf8'));
        const policy = compile(raw);
        const artifact = lowerToEgress(policy, { target });

        const serialized = serialize(artifact);
        const goldenPath = join(FIXTURE_ROOT, 'policies', 'egress', target, `${name}.json`);

        if (UPDATE || !existsSync(goldenPath)) {
          mkdirSync(dirname(goldenPath), { recursive: true });
          writeFileSync(goldenPath, serialized + '\n', 'utf8');
          if (!UPDATE) {
            throw new Error(`Golden file was missing; wrote ${goldenPath}. Review and commit.`);
          }
          return;
        }

        const expected = readFileSync(goldenPath, 'utf8').replace(/\n$/, '');
        expect(serialized).toBe(expected);
      });
    }
  }
});

function serialize(a: EgressArtifact): string {
  return JSON.stringify(a, null, 2);
}
