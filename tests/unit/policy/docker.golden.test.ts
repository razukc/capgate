// Golden-file tests for the docker adapter.
//
// Each manifest under tests/fixtures/policy/manifests/*.json is compiled and
// lowered; the result is serialized to tests/fixtures/policy/policies/docker/*.json.
// To accept a change, set UPDATE_GOLDEN=1 and rerun. Reviewers read the diff.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { compile } from '../../../src/policy/compiler';
import { lowerToDocker, DockerArtifact } from '../../../src/policy/adapters/docker';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_ROOT = join(HERE, '../../fixtures/policy');
const MANIFESTS = ['filesystem', 'fetch', 'puppeteer'] as const;

const UPDATE = process.env.UPDATE_GOLDEN === '1';

describe('docker adapter — golden files', () => {
  for (const name of MANIFESTS) {
    it(`${name}.json → policies/docker/${name}.json`, () => {
      const raw = JSON.parse(readFileSync(join(FIXTURE_ROOT, 'manifests', `${name}.json`), 'utf8'));
      const policy = compile(raw);
      const artifact = lowerToDocker(policy);

      const serialized = serialize(artifact);
      const goldenPath = join(FIXTURE_ROOT, 'policies', 'docker', `${name}.json`);

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
});

function serialize(a: DockerArtifact): string {
  return JSON.stringify(a, null, 2);
}
