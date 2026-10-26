import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSignatures, inspectFile, hashBytes, MAX_FILE_SIZE, classifyHash } from './scanner.js';
const digest = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
test('SHA-256 matches the known hello test vector', async () => assert.equal(await hashBytes(new TextEncoder().encode('hello')), digest));
test('compares contents and does not flag a scary filename as a cheat', async () => {
  const library = parseSignatures([{ sha256: digest.toUpperCase(), name: 'Test fixture' }]);
  const match = await inspectFile(new File(['hello'], 'ordinary.txt'), library);
  assert.equal(match.status, 'match'); assert.equal(match.sha256, digest);
  assert.equal((await inspectFile(new File(['different'], 'cheat.exe'), library)).status, 'unmatched');
});
test('an absent library is unverified, not clean', async () => assert.equal((await inspectFile(new File(['hello'], 'file'), new Map())).status, 'unverified'));
test('oversized files are skipped before reading contents', async () => {
  const result = await inspectFile({ name: 'big', size: MAX_FILE_SIZE + 1, arrayBuffer() { throw new Error('Must not be read'); } }, new Map());
  assert.equal(result.status, 'skipped'); assert.equal(result.sha256, undefined);
});
test('rejects malformed signatures and duplicate hashes', () => {
  for (const value of [null, {}, [{ sha256: 'bad', name: 'bad' }], [{ sha256: digest, name: '' }], [{ sha256: digest, name: 'a' }, { sha256: digest, name: 'b' }]]) assert.throws(() => parseSignatures(value));
});
test('allowlisted and test fixtures are never classified as cheat review matches', () => {
  assert.equal(classifyHash(digest, parseSignatures([{ sha256: digest, name: 'Allowed', category: 'allowed' }])).status, 'allowed');
  assert.equal(classifyHash(digest, parseSignatures([{ sha256: digest, name: 'Demo', category: 'test' }])).status, 'test');
  assert.throws(() => parseSignatures([{ sha256: digest, name: 'Claim', category: 'cheat' }]));
  assert.throws(() => parseSignatures([{ sha256: digest, name: 'Claim', category: 'clean' }]));
});
