import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { createBackend } from './backend.js';

test('authenticated staff-to-scanner workflow and report boundaries', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'sentinel-api-test-'));
  const api = await createBackend(pathToFileURL(dir + sep));
  const server = http.createServer(async (req, res) => { if (!await api(req, res, new URL(req.url, 'http://localhost').pathname)) { res.writeHead(404); res.end(); } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); await rm(dir, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = async (path, body, token, headers = {}) => {
    const response = await fetch(base + '/api/' + path, { method: body === undefined ? 'GET' : 'POST', headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(token ? { Authorization: 'Bearer ' + token } : {}), ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, data: await response.json() };
  };
  let token, session, agent;
  const digest = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
  await t.test('denies unauthenticated staff access and cross-origin writes', async () => {
    assert.equal((await request('sessions')).status, 401);
    assert.equal((await request('auth/setup', { password: 'not-relevant-password' }, null, { Origin: 'https://other.example' })).status, 403);
  });
  await t.test('sets up password hashing and a staff session without storing plaintext', async () => {
    const password = randomBytes(24).toString('hex');
    const response = await request('auth/setup', { password });
    assert.equal(response.status, 200); token = response.data.token;
    assert.equal((await readFile(join(dir, 'state.json'), 'utf8')).includes(password), false);
    assert.equal((await request('auth/login', { password: 'incorrect-password' })).status, 401);
  });
  await t.test('creates one-time session with signature snapshot', async () => {
    const response = await request('sessions', { signatures: [{ sha256: digest, name: 'Harmless test fixture' }] }, token);
    assert.equal(response.status, 201); session = response.data;
    assert.match(session.code, /^\d{6}$/);
    assert.equal((await request('sessions', { signatures: [{ sha256: 'broken', name: 'bad' }] }, token)).status, 400);
  });
  await t.test('redeems a code only once and rejects invalid report tokens', async () => {
    const response = await request('sessions/redeem', { code: session.code });
    assert.equal(response.status, 200); agent = response.data;
    assert.equal((await request('sessions/redeem', { code: session.code })).status, 404);
    assert.equal((await request(`sessions/${session.id}/report`, { results: [] }, 'bad-token')).status, 401);
  });
  await t.test('rejects malformed evidence', async () => {
    assert.equal((await request(`sessions/${session.id}/report`, { results: [{ name: 'file', size: 5, sha256: 'invalid' }] }, agent.uploadToken)).status, 400);
  });
  await t.test('recomputes match classification and stores bounded process metadata', async () => {
    const response = await request(`sessions/${session.id}/report`, { processScanRequested: true, processScanLimited: true, coverageLimited: true, results: [{ name: 'C:\\private\\file.exe', size: 5, sha256: digest, status: 'unmatched', origin: 'running-process', processId: 1234 }] }, agent.uploadToken);
    assert.equal(response.status, 201);
    const stored = await request(`sessions/${session.id}`, undefined, token);
    assert.equal(stored.data.report.results[0].status, 'match');
    assert.equal(stored.data.report.results[0].name, 'file.exe');
    assert.equal(stored.data.report.results[0].processId, 1234);
    assert.equal(stored.data.report.processScanLimited, true);
    assert.equal((await request(`sessions/${session.id}/report`, { results: [] }, agent.uploadToken)).status, 409);
  });
  await t.test('sign-out revokes the staff token', async () => {
    assert.equal((await request('auth/logout', {}, token)).status, 200);
    assert.equal((await request('sessions', undefined, token)).status, 401);
  });
});
