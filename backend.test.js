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
    assert.equal((await request('library')).status, 401);
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
    assert.match(session.code, /^[A-HJ-NP-Z2-9]{8}$/);
    assert.match(session.invitePath, /^\/check\/[a-f0-9]{64}$/);
    assert.equal(session.sharingEnabled, false);
    assert.equal(session.inviteUrl, null);
    assert.equal((await request('sessions', { signatures: [{ sha256: 'broken', name: 'bad' }] }, token)).status, 400);
  });
  await t.test('redeems a code only once and rejects invalid report tokens', async () => {
    const invite = await request('invites/' + session.invitePath.split('/').pop());
    assert.equal(invite.status, 200); assert.equal(invite.data.state, 'pending');
    assert.equal(invite.data.localOnly, true); assert.equal(invite.data.code, undefined); assert.equal(invite.data.report, undefined);
    assert.equal((await request('invites/' + '0'.repeat(64))).status, 404);
    const response = await request('sessions/redeem', { code: session.code });
    assert.equal(response.status, 200); agent = response.data;
    assert.equal((await request('sessions/redeem', { code: session.code })).status, 404);
    assert.equal((await request('invites/' + session.invitePath.split('/').pop())).data.state, 'in-progress');
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
    assert.equal((await request('invites/' + session.invitePath.split('/').pop())).data.state, 'received');
  });
  await t.test('saves a versioned library and re-analyzes without changing original evidence', async () => {
    assert.equal((await request('sessions', { durationHours: 9999 }, token)).status, 400);
    assert.equal((await request(`sessions/${session.id}/analyze`, {}, token)).status, 409);
    const saved = await request('library', { baseRevision: 0, signatures: [{ sha256: digest, name: 'Harmless test fixture', source: 'Known hello test vector', category: 'test' }] }, token);
    assert.equal(saved.status, 200); assert.equal(saved.data.revision, 1);
    assert.equal((await request('library', { baseRevision: 0, signatures: [] }, token)).status, 409);
    const analysis = await request(`sessions/${session.id}/analyze`, {}, token);
    assert.equal(analysis.status, 201); assert.equal(analysis.data.results[0].status, 'test');
    const stored = await request(`sessions/${session.id}`, undefined, token);
    assert.equal(stored.data.report.results[0].status, 'match');
    assert.equal(stored.data.analyses.length, 1); assert.equal(stored.data.analyses[0].libraryRevision, 1);
    assert.equal((await request(`sessions/${session.id}/analyze`, {}, token)).status, 200);
    assert.equal((await request(`sessions/${session.id}`, undefined, token)).data.analyses.length, 1);
    const created = await request('sessions', {}, token); assert.equal(created.data.signatureCount, 1); assert.equal(created.data.libraryRevision, 1);
    const persisted = JSON.parse(await readFile(join(dir, 'state.json'), 'utf8')); assert.equal(persisted.library.entries[0].category, 'test');
    await createBackend(pathToFileURL(dir + sep));
  });
  await t.test('accepts authorized evidence-only scans while excluding account and command contents', async () => {
    const created = await request('sessions', {}, token);
    const redeemed = await request('sessions/redeem', { code: created.data.code });
    const response = await request(`sessions/${created.data.id}/report`, { results: [], options: { boot: true, activity: true }, evidence: { boot: { windowsVersion: 'Fixture OS', biosVendor: 'Fixture vendor', serialNumber: 'must-not-store' }, executions: [{ name: 'C:\\private\\sample.exe', timeUTC: '2026-01-01T10:00:00Z', source: 'Security', eventId: 4688, pathState: 'not-found', commandLine: 'must-not-store' }] } }, redeemed.data.uploadToken);
    assert.equal(response.status, 201);
    const stored = (await request(`sessions/${created.data.id}`, undefined, token)).data.report;
    assert.equal(stored.version, 4); assert.equal(stored.evidence.executions[0].name, 'sample.exe');
    assert.equal(JSON.stringify(stored).includes('must-not-store'), false);
  });
  await t.test('preserves authorized discovery paths and profiles but drops unconsented fields', async () => {
    for(const consent of [false,true]){
      const created=await request('sessions',{},token);const redeemed=await request('sessions/redeem',{code:created.data.code});
      const response=await request(`sessions/${created.data.id}/report`,{results:[{name:'fixture.exe',size:5,sha256:digest,origin:'standard-location',path:'C:\\Users\\fixture\\Desktop\\fixture.exe'}],options:{discovery:true,paths:consent,accounts:consent},evidence:{accounts:[{platform:'steam',id:'76561198000000001',name:'Fixture profile',source:'steam-local-profile',token:'must-not-store',verified:true}]}},redeemed.data.uploadToken);assert.equal(response.status,201);
      const stored=(await request(`sessions/${created.data.id}`,undefined,token)).data.report;
      assert.equal(stored.results[0].origin,'standard-location');assert.equal(!!stored.results[0].path,consent);assert.equal(!!stored.evidence.accounts,consent);assert.equal(JSON.stringify(stored).includes('must-not-store'),false);if(consent)assert.equal(stored.evidence.accounts[0].verified,false);
    }
  });
  await t.test('sign-out revokes the staff token', async () => {
    assert.equal((await request('auth/logout', {}, token)).status, 200);
    assert.equal((await request('sessions', undefined, token)).status, 401);
  });
});
