// Golden-file tests for the bwrap adapter.
//
// Each manifest under tests/fixtures/policy/manifests/*.json is compiled and
// lowered; the result is serialized to tests/fixtures/policy/policies/bwrap/*.json.
// To accept a change, set UPDATE_GOLDEN=1 and rerun. Reviewers read the diff.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { compile } from '../../../src/policy/compiler';
import { lowerToBwrap, BwrapArtifact } from '../../../src/policy/adapters/bwrap';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_ROOT = join(HERE, '../../fixtures/policy');
const MANIFESTS = ['filesystem', 'fetch', 'github', 'puppeteer'] as const;

const UPDATE = process.env.UPDATE_GOLDEN === '1';

describe('bwrap adapter — golden files', () => {
  for (const name of MANIFESTS) {
    it(`${name}.json → policies/bwrap/${name}.json`, () => {
      const raw = JSON.parse(readFileSync(join(FIXTURE_ROOT, 'manifests', `${name}.json`), 'utf8'));
      const policy = compile(raw);
      const artifact = lowerToBwrap(policy);

      const serialized = serialize(artifact);
      const goldenPath = join(FIXTURE_ROOT, 'policies', 'bwrap', `${name}.json`);

      if (UPDATE || !existsSync(goldenPath)) {
        mkdirSync(dirname(goldenPath), { recursive: true });
        writeFileSync(goldenPath, serialized + '\n', 'utf8');
        if (!UPDATE) {
          // First-run: fixture didn't exist. Fail so a human eyeballs the generated file.
          throw new Error(`Golden file was missing; wrote ${goldenPath}. Review and commit.`);
        }
        return;
      }

      const expected = readFileSync(goldenPath, 'utf8').replace(/\n$/, '');
      expect(serialized).toBe(expected);
    });
  }
});

function serialize(a: BwrapArtifact): string {
  // Stable, diff-friendly JSON. Arrays stay in compiler order (already sorted).
  return JSON.stringify(a, null, 2);
}
