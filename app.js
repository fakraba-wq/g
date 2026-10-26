import { inspectFile, parseSignatures } from './scanner.js';

const $ = id => document.getElementById(id);
let files = [], signatures = new Map(), results = [], busy = false, report = null;
const cryptoAvailable = !!globalThis.crypto?.subtle;
function updateControls() {
  $('run-scan').disabled = busy || !cryptoAvailable || !files.length || !$('consent').checked;
  for (const id of ['select-files', 'select-folder', 'import-signatures', 'consent']) $(id).disabled = busy;
  $('export-report').disabled = busy || !report;
}
function selectFiles(selection) {
  if (busy) return;
  if (selection.length > 1000) { $('status').textContent = 'Please select at most 1,000 files per check.'; return; }
  files = Array.from(selection);
  const bytes = files.reduce((sum, file) => sum + file.size, 0);
  $('selection-count').textContent = `${files.length} file${files.length === 1 ? '' : 's'} selected · ${formatSize(bytes)}`;
  $('status').textContent = files.length ? 'Files selected. Confirm permission, then run your check.' : 'No files selected.';
  updateControls();
}
function formatSize(bytes) { return bytes < 1024 ? bytes + ' B' : bytes < 1048576 ? (bytes / 1024).toFixed(1) + ' KB' : (bytes / 1048576).toFixed(1) + ' MB'; }
function download(name, content) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(content, null, 2)], { type: 'application/json' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = name; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function renderResults() {
  const labels = { match: 'Signature match', unmatched: 'No exact match', unverified: 'No library loaded', skipped: 'Skipped', error: 'Read failed' };
  $('result-rows').replaceChildren();
  for (const result of results) {
    const tr = document.createElement('tr');
    const name = document.createElement('td'); name.textContent = result.name;
    if (result.origin) { const origin = document.createElement('small'); origin.textContent = result.origin === 'running-process' ? `Running executable${result.processId ? ' · PID ' + result.processId : ''}` : 'Selected folder'; name.append(origin); }
    const size = document.createElement('td'); size.textContent = formatSize(result.size);
    const details = document.createElement('td');
    const hash = document.createElement('code'); hash.textContent = result.sha256 || result.reason; details.append(hash);
    if (result.signature) {
      const label = document.createElement('small'); label.textContent = result.signature.name;
      const source = document.createElement('small'); source.textContent = 'Source: ' + result.signature.source;
      details.append(label, source);
    }
    const status = document.createElement('td'), badge = document.createElement('span');
    badge.className = 'result-badge ' + result.status; badge.textContent = labels[result.status]; status.append(badge);
    tr.append(name, size, details, status); $('result-rows').append(tr);
  }
  const checked = results.filter(r => r.sha256).length;
  $('stat-files').replaceChildren(document.createTextNode(checked + ' '), Object.assign(document.createElement('small'), { textContent: 'files' }));
  $('stat-matches').replaceChildren(document.createTextNode(results.filter(r => r.status === 'match').length + ' '), Object.assign(document.createElement('small'), { textContent: 'matches' }));
  $('result-count').textContent = String(results.length);
  $('empty-results').hidden = results.length > 0; $('results-table').hidden = !results.length;
}
$('select-files').addEventListener('click', () => $('file-input').click());
$('select-folder').addEventListener('click', () => $('folder-input').click());
for (const id of ['file-input', 'folder-input']) $(id).addEventListener('change', event => { selectFiles(event.target.files); event.target.value = ''; });
$('consent').addEventListener('change', updateControls);
for (const event of ['dragenter', 'dragover']) $('dropzone').addEventListener(event, e => { e.preventDefault(); if (!busy) $('dropzone').classList.add('drag'); });
for (const event of ['dragleave', 'drop']) $('dropzone').addEventListener(event, e => { e.preventDefault(); $('dropzone').classList.remove('drag'); });
$('dropzone').addEventListener('drop', e => selectFiles(e.dataTransfer.files));
$('import-signatures').addEventListener('click', () => $('signature-input').click());
$('signature-input').addEventListener('change', async event => {
  const file = event.target.files[0]; event.target.value = ''; if (!file || busy) return;
  try {
    if (file.size > 5 * 1024 * 1024) throw new Error('Signature JSON must be 5 MB or smaller.');
    const parsed = parseSignatures(JSON.parse(await file.text()));
    if (busy) return;
    signatures = parsed;
    $('stat-signatures').replaceChildren(document.createTextNode(signatures.size + ' '), Object.assign(document.createElement('small'), { textContent: 'hashes' }));
    $('library-title').textContent = signatures.size ? file.name : 'Library is empty';
    $('library-caption').textContent = 'User-supplied · provenance not independently verified';
    $('signature-status').textContent = `${signatures.size} signatures loaded. Changes apply to the next check. Existing results retain their original library.`;
  } catch (error) { $('signature-status').textContent = 'Import failed: ' + error.message; }
});
$('download-example').addEventListener('click', () => download('signature-format.json', [{ sha256: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', name: 'Demonstration only: file containing hello (not a cheat)', source: 'Harmless format example; replace with your verified signatures' }]));
$('export-report').addEventListener('click', () => { if (report) download('sentinel-report-' + report.completedAt.slice(0, 10) + '.json', report); });
$('run-scan').addEventListener('click', async () => {
  if (busy || !files.length || !$('consent').checked || !cryptoAvailable) return;
  busy = true; report = null; results = []; updateControls(); renderResults();
  const snapshot = new Map(signatures), startedAt = new Date().toISOString();
  $('progress').hidden = false; $('progress').max = files.length; $('progress').value = 0;
  for (const [index, file] of files.entries()) {
    $('status').textContent = `Checking ${index + 1} of ${files.length}: ${file.name}`;
    await new Promise(resolve => setTimeout(resolve, 0));
    try { results.push(await inspectFile(file, snapshot)); }
    catch { results.push({ name: file.name, size: file.size, status: 'error', reason: 'File could not be read or hashed.' }); }
    $('progress').value = index + 1;
  }
  renderResults();
  report = { tool: 'Sentinel FiveM File Check', version: 1, startedAt, completedAt: new Date().toISOString(), scope: 'User-selected files only. No process, memory, deleted-file or whole-PC inspection.', interpretation: 'Matches are exact comparisons against a user-supplied library, not proof of cheating. Unmatched or unverified files do not establish a cheat-free PC.', signaturesUsed: Array.from(snapshot, ([sha256, entry]) => ({ sha256, ...entry })), results };
  busy = false; updateControls();
  const skipped = results.filter(r => !r.sha256).length;
  $('status').textContent = `Check complete. ${results.length - skipped} files hashed${skipped ? `, ${skipped} skipped or unreadable` : ''}. Review matches and library provenance before drawing conclusions.`;
  $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
});
if (!cryptoAvailable) $('status').textContent = 'Secure hashing is unavailable. Open this application on localhost or HTTPS.';
updateControls();

let staffToken = sessionStorage.getItem('sentinel-staff-token') || '', setupRequired = false, sessionsBusy = false;
async function api(path, payload) {
  const response = await fetch('/api/' + path, { method: payload === undefined ? 'GET' : 'POST', headers: { ...(payload === undefined ? {} : { 'Content-Type': 'application/json' }), ...(staffToken ? { Authorization: 'Bearer ' + staffToken } : {}) }, ...(payload === undefined ? {} : { body: JSON.stringify(payload) }) });
  const body = await response.json();
  if (!response.ok) {
    if (response.status === 401) { staffToken = ''; sessionStorage.removeItem('sentinel-staff-token'); showStaff(); }
    throw new Error(body.error || 'Request failed.');
  }
  return body;
}
function showStaff() { $('staff-form').hidden = !!staffToken; $('session-controls').hidden = !staffToken; }
async function loadSessions() {
  if (!staffToken) return;
  const { sessions } = await api('sessions');
  $('session-list').replaceChildren();
  if (!sessions.length) { $('session-list').textContent = 'No sessions yet. Create a code to start a Windows check.'; return; }
  for (const session of sessions) {
    const row = document.createElement('div'); row.className = 'session-row';
    const code = document.createElement('strong'); code.className = 'session-code'; code.textContent = session.code;
    const info = document.createElement('div');
    const title = document.createElement('span'); title.textContent = session.report ? 'Report received' : Date.now() > session.expiresAt ? 'Expired' : session.redeemed ? 'Scanner connected · awaiting report' : 'Waiting for player';
    const detail = document.createElement('small'); detail.textContent = `${session.signatureCount} signatures · Expires ${new Date(session.expiresAt).toLocaleTimeString()}`;
    info.append(title, detail); row.append(code, info);
    if (session.report) {
      const view = document.createElement('button'); view.className = 'secondary'; view.textContent = 'View report';
      view.addEventListener('click', () => {
        if (busy) { $('session-status').textContent = 'Wait for the current local check to finish.'; return; }
        report = session.report; results = report.results; renderResults(); updateControls();
        $('status').textContent = `Windows session ${session.code}: self-reported client evidence${report.coverageLimited ? ' · coverage limited' : ''}. Review manually; this is not client attestation.`;
        $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
      }); row.append(view);
    }
    $('session-list').append(row);
  }
}
$('staff-form').addEventListener('submit', async event => {
  event.preventDefault(); if (sessionsBusy) return; sessionsBusy = true; $('staff-login').disabled = true;
  try {
    const response = await api('auth/' + (setupRequired ? 'setup' : 'login'), { password: $('staff-password').value });
    staffToken = response.token; sessionStorage.setItem('sentinel-staff-token', staffToken); $('staff-password').value = ''; setupRequired = false;
    $('staff-label').textContent = 'Staff password'; $('staff-login').textContent = 'Sign in'; $('staff-password').autocomplete = 'current-password';
    showStaff(); await loadSessions(); $('session-status').textContent = 'Staff signed in. Sessions use your currently loaded signature library.';
  } catch (error) { $('session-status').textContent = error.message; }
  finally { sessionsBusy = false; $('staff-login').disabled = false; }
});
$('staff-logout').addEventListener('click', async () => { try { await api('auth/logout', {}); staffToken = ''; sessionStorage.removeItem('sentinel-staff-token'); $('session-list').replaceChildren(); showStaff(); $('session-status').textContent = 'Signed out.'; } catch (error) { $('session-status').textContent = error.message; } });
$('create-session').addEventListener('click', async () => {
  if (sessionsBusy) return; sessionsBusy = true; $('create-session').disabled = true;
  try {
    const session = await api('sessions', { signatures: Array.from(signatures, ([sha256, entry]) => ({ sha256, ...entry })) });
    await loadSessions(); $('session-status').textContent = `Session ${session.code} created. Share this code privately with the player. ${signatures.size ? 'Signatures attached.' : 'No library attached: files will be unverified.'}`;
  } catch (error) { $('session-status').textContent = error.message; }
  finally { sessionsBusy = false; $('create-session').disabled = false; }
});
$('refresh-sessions').addEventListener('click', async () => { try { await loadSessions(); $('session-status').textContent = 'Session list refreshed.'; } catch (error) { $('session-status').textContent = error.message; } });
async function initializeStaff() {
  try {
    const status = await api('auth/status'); setupRequired = status.setupRequired;
    if (setupRequired) { $('staff-label').textContent = 'Create your staff password (localhost only)'; $('staff-login').textContent = 'Set up staff'; $('staff-password').autocomplete = 'new-password'; }
    showStaff(); if (staffToken) await loadSessions();
    $('session-status').textContent = staffToken ? 'Staff workspace ready.' : setupRequired ? 'Set your password locally, or configure SENTINEL_ADMIN_PASSWORD on a remote server.' : 'Sign in to create sessions and review player reports.';
  } catch (error) { $('session-status').textContent = 'Sessions unavailable: ' + error.message; }
}
initializeStaff();
