import { test } from 'node:test';
import assert from 'node:assert/strict';
import { prepareHosted } from './scripts/prepare-hosted.mjs';
import { mkdtemp, mkdir, copyFile, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';

test('explicit hosted preparation extracts the packaged scanner and verifies its SHA-256', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'crimson-hosted-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await mkdir(join(dir, 'dist'));
  await copyFile(new URL('./dist/crimson-pc-check.zip', import.meta.url), join(dir, 'dist/crimson-pc-check.zip'));
  await prepareHosted(pathToFileURL(dir + sep));
  const binary = await readFile(join(dir, 'dist/crimson-pc-check-windows-amd64.exe'));
  const checksum = (await readFile(join(dir, 'dist/checksums.txt'), 'utf8')).split(/\s/)[0];
  assert.equal(createHash('sha256').update(binary).digest('hex'), checksum); assert.equal(binary.toString('ascii', 0, 2), 'MZ');
  await writeFile(join(dir, 'dist/crimson-pc-check.zip'), 'not a zip archive');
  await assert.rejects(prepareHosted(pathToFileURL(dir + sep)));
});
