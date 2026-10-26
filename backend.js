import { randomBytes, randomInt, scryptSync, timingSafeEqual, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import { parseSignatures, classifyHash } from './scanner.js';
import { sanitizeEvidence, sanitizePE, trustStates } from './report-model.js';

export async function createBackend(directory, configuredPassword = '', settings = {}) {
  if (configuredPassword && (configuredPassword.length < 12 || configuredPassword.length > 256)) throw new Error('SENTINEL_ADMIN_PASSWORD must contain 12–256 characters.');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const stateFile = new URL('state.json', directory);
  let state;
  try { state = JSON.parse(await readFile(stateFile, 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; state = { auth: null, sessions: [] }; }
  state.library ||= { entries: [], revision: 0, updatedAt: null };
  parseSignatures(state.library.entries);
  const tokens = new Map(), limits = new Map();
  const secretHash = (password, salt) => scryptSync(password, salt, 64).toString('hex');
  let saveQueue = Promise.resolve();
  function save() {
    const data = JSON.stringify(state);
    saveQueue = saveQueue.catch(() => {}).then(async () => {
      const temp = new URL('state.json.tmp', directory);
      await writeFile(temp, data, { mode: 0o600 }); await rename(temp, stateFile);
    });
    return saveQueue;
  }
  const envAuth = configuredPassword ? { salt: 'sentinel-environment-password-v1', hash: secretHash(configuredPassword, 'sentinel-environment-password-v1') } : null;
  function fail(status, message) { throw Object.assign(new Error(message), { status }); }
  function limited(key, maximum) {
    const now = Date.now(), existing = limits.get(key);
    const value = existing && existing.until > now ? existing : { count: 0, until: now + 60000 };
    value.count++; limits.set(key, value);
    if (limits.size > 10000) for (const [key, entry] of limits) if (entry.until < now) limits.delete(key);
    if (value.count > maximum) fail(429, 'Too many requests. Try again in a minute.');
  }
  let migrated = false;
  for (const session of state.sessions) if (!/^[a-f0-9]{64}$/.test(session.inviteToken || '')) { session.inviteToken = randomBytes(32).toString('hex'); migrated = true; }
  if (migrated) await save();
  const publicOrigin = settings.publicOrigin && /^https:\/\//.test(settings.publicOrigin) && !['localhost', '127.0.0.1', '[::1]'].includes(new URL(settings.publicOrigin).hostname) ? new URL(settings.publicOrigin).origin : null;
  const publicSession = session => ({ id: session.id, code: session.code, createdAt: session.createdAt, expiresAt: session.expiresAt, signatureCount: session.signatures.length, libraryRevision: session.libraryRevision ?? null, redeemed: !!session.redeemed, report: session.report || null, analyses: session.analyses || [], sharingEnabled: !!publicOrigin, invitePath: '/check/' + session.inviteToken, inviteUrl: publicOrigin ? publicOrigin + '/check/' + session.inviteToken : null });
  function findInvite(token) {
    if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)) return null;
    return state.sessions.find(session => timingSafeEqual(Buffer.from(token), Buffer.from(session.inviteToken)) && session.expiresAt > Date.now()) || null;
  }
  const api = async function api(req, res, pathname) {
    if (!pathname.startsWith('/api/')) return false;
    const reply = (code, value) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); res.end(JSON.stringify(value)); };
    try {
      const ip = req.socket.remoteAddress;
      limited('all:' + ip, 180);
      if (req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) fail(403, 'Cross-origin requests are not allowed.');
      let body = {};
      if (req.method === 'POST') {
        if (!req.headers['content-type']?.startsWith('application/json')) fail(415, 'JSON content type required.');
        const chunks = []; let size = 0;
        for await (const chunk of req) { size += chunk.length; if (size > 2 * 1024 * 1024) fail(413, 'Request exceeds 2 MB.'); chunks.push(chunk); }
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { fail(400, 'Invalid JSON.'); }
        if (!body || Array.isArray(body) || typeof body !== 'object') fail(400, 'Expected a JSON object.');
      }
      if (pathname === '/api/auth/status' && req.method === 'GET') { reply(200, { setupRequired: !envAuth && !state.auth }); return true; }
      const inviteRoute = pathname.match(/^\/api\/invites\/([a-f0-9]{64})$/);
      if (inviteRoute && req.method === 'GET') {
        const session = findInvite(inviteRoute[1]);
        if (!session) fail(404, 'Invitation unavailable or expired. Ask staff for a new link.');
        reply(200, { expiresAt: session.expiresAt, state: session.report ? 'received' : session.redeemed ? 'in-progress' : 'pending', staffOrigin: publicOrigin, localOnly: !publicOrigin }); return true;
      }
      if ((pathname === '/api/auth/setup' || pathname === '/api/auth/login') && req.method === 'POST') {
        limited('login:' + ip, 8);
        if (typeof body.password !== 'string' || body.password.length < 12 || body.password.length > 256) fail(400, 'Use a password between 12 and 256 characters.');
        let auth = envAuth || state.auth;
        if (pathname.endsWith('/setup')) {
          if (auth) fail(409, 'Staff password already configured. Sign in instead.');
          if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(ip)) fail(403, 'Initial staff setup must run from localhost. Set SENTINEL_ADMIN_PASSWORD on the server for remote deployment.');
          const salt = randomBytes(24).toString('hex');
          auth = { salt, hash: secretHash(body.password, salt) }; state.auth = auth; await save();
        }
        if (!auth || !timingSafeEqual(Buffer.from(auth.hash, 'hex'), Buffer.from(secretHash(body.password, auth.salt), 'hex'))) fail(401, 'Incorrect password.');
        const token = randomBytes(32).toString('hex');
        for (const [key, entry] of tokens) if (entry < Date.now()) tokens.delete(key);
        tokens.set(token, Date.now() + 6 * 60 * 60 * 1000); reply(200, { token }); return true;
      }
      if (pathname === '/api/sessions/redeem' && req.method === 'POST') {
        limited('redeem:' + ip, 6);
        if (typeof body.code !== 'string' || !/^(?:\d{6}|[A-HJ-NP-Z2-9]{8})$/.test(body.code.toUpperCase())) fail(400, 'Enter the PIN from your invitation, not the staff password.');
        const session = state.sessions.find(s => s.code === body.code.toUpperCase() && s.expiresAt > Date.now() && !s.redeemed);
        if (!session) fail(404, 'Session unavailable, expired, or already redeemed.');
        session.redeemed = true; session.uploadToken = randomBytes(32).toString('hex'); await save();
        reply(200, { sessionId: session.id, uploadToken: session.uploadToken, expiresAt: session.expiresAt, signatures: session.signatures }); return true;
      }
      const reportRoute = pathname.match(/^\/api\/sessions\/([a-f0-9-]{36})\/report$/);
      if (reportRoute && req.method === 'POST') {
        const session = state.sessions.find(s => s.id === reportRoute[1]);
        const token = req.headers.authorization?.replace(/^Bearer /, '');
        if (!session?.uploadToken || !token || !/^[a-f0-9]{64}$/.test(token) || !timingSafeEqual(Buffer.from(token), Buffer.from(session.uploadToken))) fail(401, 'Invalid report token.');
        if (session.expiresAt <= Date.now()) fail(410, 'Session expired.');
        if (session.report) fail(409, 'A report has already been submitted.');
        const collected = sanitizeEvidence(body);
        if (!Array.isArray(body.results) || body.results.length > 1000 || (!body.results.length && !collected.options.boot && !collected.options.modules && !collected.options.activity)) fail(400, 'Report needs file results or an explicitly authorized evidence collection.');
        const library = parseSignatures(session.signatures);
        const results = body.results.map(file => {
          if (!file || typeof file.name !== 'string' || !file.name || file.name.length > 500 || !Number.isSafeInteger(file.size) || file.size < 0) fail(400, 'Invalid file result.');
          const name = file.name.split(/[\\/]/).pop();
          const origin = file.origin === 'loaded-module' && collected.options.modules ? 'loaded-module' : file.origin === 'running-process' && collected.options.processes ? 'running-process' : 'selected-folder';
          const processId = ['running-process', 'loaded-module'].includes(origin) && Number.isInteger(file.processId) && file.processId > 0 && file.processId <= 4294967295 ? file.processId : undefined;
          const metadata = collected.options.integrity ? { pe: sanitizePE(file.pe), integrityStatus: trustStates.has(file.integrityStatus) ? file.integrityStatus : undefined } : {};
          if (file.sha256 !== undefined && file.sha256 !== null) {
            if (typeof file.sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(file.sha256) || file.size > 200 * 1024 * 1024) fail(400, 'Invalid file hash or size.');
            const sha256 = file.sha256.toLowerCase();
            return { name, size: file.size, origin, processId, ...metadata, ...classifyHash(sha256, library) };
          }
          return { name, size: file.size, origin, processId, status: 'skipped', reason: 'Client could not hash this file.' };
        });
        session.report = { tool: 'Crimson PC Check', version: 2, completedAt: new Date().toISOString(), scope: 'Selected-folder file hashes and, if explicitly opted in, readable running executable file hashes. No process memory, registry or deleted-file inspection.', interpretation: 'Self-reported client evidence. No client attestation. A match is not proof of cheating; no match is not proof of a cheat-free PC.', libraryRevision: session.libraryRevision ?? null, coverageLimited: body.coverageLimited !== false, processScanRequested: body.processScanRequested === true, processScanLimited: body.processScanRequested === true && body.processScanLimited !== false, signaturesUsed: session.signatures, results };
        session.report.version = 3;
        session.report.scope = 'Authorized file hashes, optional FiveM DLL image metadata, PE/cache-only trust, boot metadata and existing bounded execution events. No memory dumps, account contents, command lines or screenshots.';
        Object.assign(session.report, collected);
        await save(); reply(201, { accepted: true }); return true;
      }
      const adminToken = req.headers.authorization?.replace(/^Bearer /, '');
      if (!adminToken || (tokens.get(adminToken) || 0) <= Date.now()) fail(401, 'Staff sign-in required.');
      if (pathname === '/api/library' && req.method === 'GET') { reply(200, state.library); return true; }
      if (pathname === '/api/library' && req.method === 'POST') {
        if (body.baseRevision !== state.library.revision) fail(409, 'Library changed. Reload it before saving to avoid overwriting another edit.');
        let library;
        try { library = parseSignatures(body.signatures); } catch (error) { fail(400, error.message); }
        if (library.size > 5000) fail(400, 'Saved libraries support at most 5,000 signatures.');
        state.library = { entries: Array.from(library, ([sha256, entry]) => ({ sha256, ...entry })), revision: state.library.revision + 1, updatedAt: new Date().toISOString() };
        await save(); reply(200, state.library); return true;
      }
      const analysisRoute = pathname.match(/^\/api\/sessions\/([a-f0-9-]{36})\/analyze$/);
      if (analysisRoute && req.method === 'POST') {
        const session = state.sessions.find(s => s.id === analysisRoute[1]);
        if (!session?.report) fail(404, 'A submitted report is required.');
        if (!state.library.entries.length) fail(409, 'Save a signature library before re-analyzing a report.');
        session.analyses ||= [];
        const last = session.analyses.at(-1);
        if (last?.libraryRevision === state.library.revision) { reply(200, last); return true; }
        const library = parseSignatures(state.library.entries);
        const analysis = { ...session.report, analyzedAt: new Date().toISOString(), libraryRevision: state.library.revision, signaturesUsed: state.library.entries, results: session.report.results.map(result => result.sha256 ? { ...result, ...classifyHash(result.sha256, library) } : { ...result }) };
        session.analyses.push(analysis); session.analyses = session.analyses.slice(-5);
        await save(); reply(201, analysis); return true;
      }
      if (pathname === '/api/auth/logout' && req.method === 'POST') { tokens.delete(adminToken); reply(200, { signedOut: true }); return true; }
      if (pathname === '/api/sessions' && req.method === 'GET') { reply(200, { sessions: state.sessions.slice().reverse().map(publicSession) }); return true; }
      if (pathname === '/api/sessions' && req.method === 'POST') {
        state.sessions = state.sessions.filter(s => s.createdAt > Date.now() - 24 * 60 * 60 * 1000);
        if (state.sessions.length >= 100) fail(429, 'Session limit reached. Sessions are retained for 24 hours.');
        let library;
        try { library = parseSignatures(body.signatures ?? state.library.entries); } catch (error) { fail(400, error.message); }
        if (library.size > 5000) fail(400, 'Remote sessions support at most 5,000 signatures.');
        const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        let code; do { code = Array.from({ length: 8 }, () => alphabet[randomInt(alphabet.length)]).join(''); } while (state.sessions.some(s => s.code === code));
        const duration = body.durationHours ?? 24;
        if (![0.5, 1, 24].includes(duration)) fail(400, 'Choose a 30-minute, 1-hour or 24-hour session.');
        const session = { id: randomUUID(), code, inviteToken: randomBytes(32).toString('hex'), createdAt: Date.now(), expiresAt: Date.now() + duration * 60 * 60 * 1000, redeemed: false, libraryRevision: body.signatures === undefined ? state.library.revision : null, signatures: Array.from(library, ([sha256, entry]) => ({ sha256, ...entry })) };
        state.sessions.push(session); await save(); reply(201, publicSession(session)); return true;
      }
      const sessionRoute = pathname.match(/^\/api\/sessions\/([a-f0-9-]{36})$/);
      if (sessionRoute && req.method === 'GET') {
        const session = state.sessions.find(s => s.id === sessionRoute[1]);
        if (!session) fail(404, 'Session not found.'); reply(200, publicSession(session)); return true;
      }
      fail(404, 'Unknown API endpoint.');
    } catch (error) { reply(error.status || 500, { error: error.status ? error.message : 'Internal server error.' }); }
    return true;
  };
  api.findInvite = findInvite;
  api.publicOrigin = publicOrigin;
  return api;
}
