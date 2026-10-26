import { inspectFile, parseSignatures, hashBytes } from './scanner.js';
import { renderEvidence } from './report-view.js';
import { openInvite, refreshInvite, setupInvites } from './invite-view.js';

const $ = id => document.getElementById(id);
let files = [], signatures = new Map(), results = [], busy = false, report = null;
let activeSession = null, originalReport = null, libraryRevision = 0, libraryDirty = false;
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
  renderEvidence(report, $('result-search').value.trim());
  const labels = { match: 'Signature match · review', unmatched: 'No exact match', unverified: 'Unverified · no library', skipped: 'Skipped', error: 'Read failed', allowed: 'Staff allowlisted', test: 'Harmless test match' };
  $('result-rows').replaceChildren();
  const query = $('result-search').value.trim().toLowerCase(), filter = $('result-filter').value;
  const visible = results.filter(result => (filter === 'all' || (filter === 'skipped' ? ['skipped', 'error'].includes(result.status) : result.status === filter)) && [result.name, result.sha256, result.signature?.name, result.signature?.source].filter(Boolean).join(' ').toLowerCase().includes(query));
  visible.sort((a, b) => Number(b.status === 'match') - Number(a.status === 'match'));
  for (const result of visible) {
    const tr = document.createElement('tr');
    const name = document.createElement('td'); name.textContent = result.name;
    if (result.origin) { const origin = document.createElement('small'); origin.textContent = result.origin === 'loaded-module' ? `FiveM DLL · PID ${result.processId || 'unavailable'}` : result.origin === 'running-process' ? `Running executable${result.processId ? ' · PID ' + result.processId : ''}` : 'Selected folder'; name.append(origin); }
    const size = document.createElement('td'); size.textContent = formatSize(result.size);
    const details = document.createElement('td');
    const hash = document.createElement('code'); hash.textContent = result.sha256 || result.reason; details.append(hash);
    if (result.signature) {
      const label = document.createElement('small'); label.textContent = result.signature.name + ' · ' + (result.signature.category || 'review');
      const source = document.createElement('small'); source.textContent = 'Source: ' + result.signature.source;
      details.append(label, source);
    }
    const status = document.createElement('td'), badge = document.createElement('span');
    badge.className = 'result-badge ' + result.status; badge.textContent = labels[result.status]; status.append(badge);
    tr.append(name, size, details, status); $('result-rows').append(tr);
  }
  if (results.length && !visible.length) { const row = document.createElement('tr'), cell = document.createElement('td'); cell.colSpan = 4; cell.textContent = 'No files match this search or filter.'; row.append(cell); $('result-rows').append(row); }
  const checked = results.filter(r => r.sha256).length;
  $('stat-files').replaceChildren(document.createTextNode(checked + ' '), Object.assign(document.createElement('small'), { textContent: 'files' }));
  $('stat-matches').replaceChildren(document.createTextNode(results.filter(r => r.status === 'match').length + ' '), Object.assign(document.createElement('small'), { textContent: 'matches' }));
  $('result-count').textContent = `${visible.length} / ${results.length}`;
  $('empty-results').hidden = results.length > 0; $('results-table').hidden = !results.length;
  $('report-controls').hidden = !results.length; $('report-summary').hidden = !results.length;
  if (results.length) {
    const skipped = results.filter(r => !r.sha256).length, matches = results.filter(r => r.status === 'match').length;
    const libraryCount = report?.signaturesUsed?.length || 0;
    $('report-summary').textContent = `${checked} files hashed · ${matches} review matches · ${skipped} skipped/unreadable. ${libraryCount ? `Compared with ${libraryCount} staff-supplied signatures${report?.libraryRevision ? ' · revision ' + report.libraryRevision : ''}.` : 'No signature library: this is an inventory, not a cheat verdict.'} ${report?.coverageLimited ? 'Coverage is limited; some items could not be inspected.' : 'Only the authorized selection was checked.'}${report?.analyzedAt ? ' Re-analyzed ' + new Date(report.analyzedAt).toLocaleString() + '; original evidence retained.' : ''}`;
  }
  $('reanalyze-report').disabled = !activeSession || !staffToken || busy;
  $('original-report').hidden = !originalReport || report === originalReport;
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
    signatures = parsed; libraryDirty = true; renderLibrary();
    $('library-title').textContent = signatures.size ? file.name : 'Library is empty';
    $('library-caption').textContent = 'User-supplied · provenance not independently verified';
    $('signature-status').textContent = `${signatures.size} signatures loaded. Changes apply to the next check. Existing results retain their original library.`;
  } catch (error) { $('signature-status').textContent = 'Import failed: ' + error.message; }
});
$('download-example').addEventListener('click', () => download('crimson-signature-format.json', [{ sha256: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', name: 'Harmless hello test fixture — not a cheat', source: 'Five UTF-8 bytes: hello. Format testing only.', category: 'test' }]));
$('export-report').addEventListener('click', () => { if (report) download('crimson-report-' + report.completedAt.slice(0, 10) + '.json', report); });
$('run-scan').addEventListener('click', async () => {
  if (busy || !files.length || !$('consent').checked || !cryptoAvailable) return;
  busy = true; report = null; activeSession = null; originalReport = null; results = []; updateControls(); renderResults();
  const snapshot = new Map(signatures), startedAt = new Date().toISOString();
  $('progress').hidden = false; $('progress').max = files.length; $('progress').value = 0;
  for (const [index, file] of files.entries()) {
    $('status').textContent = `Checking ${index + 1} of ${files.length}: ${file.name}`;
    await new Promise(resolve => setTimeout(resolve, 0));
    try { results.push(await inspectFile(file, snapshot)); }
    catch { results.push({ name: file.name, size: file.size, status: 'error', reason: 'File could not be read or hashed.' }); }
    $('progress').value = index + 1;
  }
  report = { tool: 'Crimson PC Check', version: 2, startedAt, completedAt: new Date().toISOString(), scope: 'User-selected files only. No process, memory, deleted-file or whole-PC inspection.', interpretation: 'Matches are exact comparisons against a user-supplied library, not proof of cheating. Unmatched or unverified files do not establish a cheat-free PC.', signaturesUsed: Array.from(snapshot, ([sha256, entry]) => ({ sha256, ...entry })), results };
  renderResults();
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
function showStaff() { $('staff-form').hidden = !!staffToken; $('session-controls').hidden = !staffToken; renderLibrary(); }
async function loadSessions() {
  if (!staffToken) return;
  const { sessions } = await api('sessions');
  $('session-list').replaceChildren();
  if (!sessions.length) { $('session-list').textContent = 'No sessions yet. Create a code to start a Windows check.'; return; }
  for (const session of sessions) {
    refreshInvite(session);
    const row = document.createElement('div'); row.className = 'session-row';
    const code = document.createElement('strong'); code.className = 'session-code'; code.textContent = session.code;
    const info = document.createElement('div');
    const title = document.createElement('span'); title.textContent = session.report ? 'Report received' : Date.now() > session.expiresAt ? 'Expired' : session.redeemed ? 'Scanner connected · awaiting report' : 'Waiting for player';
    const detail = document.createElement('small'); detail.textContent = `${session.signatureCount ? session.signatureCount + ' signatures' : 'Inventory only · no signatures'} · Expires ${new Date(session.expiresAt).toLocaleTimeString()}`;
    info.append(title, detail); row.append(code, info);
    const invite = document.createElement('button'); invite.className = 'secondary'; invite.textContent = 'Invitation'; invite.addEventListener('click', () => openInvite(session, { download: downloadSessionScanner, read: id => api('sessions/' + id) })); row.append(invite);
    if (!session.redeemed && !session.report && Date.now() < session.expiresAt) {
      const scanner = document.createElement('button'); scanner.className = 'secondary'; scanner.textContent = 'Guided scanner';
      scanner.addEventListener('click', () => downloadSessionScanner(session, scanner)); row.append(scanner);
      const copy = document.createElement('button'); copy.className = 'text-button'; copy.textContent = 'Copy code';
      copy.addEventListener('click', async () => { try { await navigator.clipboard.writeText(session.code); $('session-status').textContent = 'Session code copied.'; } catch { $('session-status').textContent = 'Select the PIN and copy it manually.'; } }); row.append(copy);
    }
    if (session.report) {
      const view = document.createElement('button'); view.className = 'secondary'; view.textContent = 'View report';
      view.addEventListener('click', () => {
        if (busy) { $('session-status').textContent = 'Wait for the current local check to finish.'; return; }
        activeSession = session.id; originalReport = session.report; report = session.analyses?.at(-1) || session.report; results = report.results; renderResults(); updateControls();
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
    showStaff(); if (!libraryDirty) await loadLibrary(); else { libraryRevision = (await api('library')).revision; renderLibrary(); } await loadSessions(); $('session-status').textContent = 'Staff signed in. Download a guided session scanner to prefill its server and code.';
  } catch (error) { $('session-status').textContent = error.message; }
  finally { sessionsBusy = false; $('staff-login').disabled = false; }
});
$('staff-logout').addEventListener('click', async () => { try { await api('auth/logout', {}); staffToken = ''; sessionStorage.removeItem('sentinel-staff-token'); $('session-list').replaceChildren(); showStaff(); $('session-status').textContent = 'Signed out.'; } catch (error) { $('session-status').textContent = error.message; } });
$('create-session').addEventListener('click', async () => {
  if (sessionsBusy) return; sessionsBusy = true; $('create-session').disabled = true;
  try {
    const session = await api('sessions', { durationHours: Number($('session-duration').value), ...(libraryDirty ? { signatures: Array.from(signatures, ([sha256, entry]) => ({ sha256, ...entry })) } : {}) });
    await loadSessions(); openInvite(session, { download: downloadSessionScanner, read: id => api('sessions/' + id) }); $('session-status').textContent = `Session ${session.code} created. Share this code privately with the player. ${signatures.size ? 'Signatures attached.' : 'No library attached: files will be unverified.'}`;
  } catch (error) { $('session-status').textContent = error.message; }
  finally { sessionsBusy = false; $('create-session').disabled = false; }
});
$('refresh-sessions').addEventListener('click', async () => { try { await loadSessions(); $('session-status').textContent = 'Session list refreshed.'; } catch (error) { $('session-status').textContent = error.message; } });
async function initializeStaff() {
  try {
    const status = await api('auth/status'); setupRequired = status.setupRequired;
    if (setupRequired) { $('staff-label').textContent = 'Create your staff password (localhost only)'; $('staff-login').textContent = 'Set up staff'; $('staff-password').autocomplete = 'new-password'; }
    showStaff(); if (staffToken) { await loadLibrary(); await loadSessions(); }
    $('session-status').textContent = staffToken ? 'Staff workspace ready.' : setupRequired ? 'Set your password locally, or configure SENTINEL_ADMIN_PASSWORD on a remote server.' : 'Sign in to create sessions and review player reports.';
  } catch (error) { $('session-status').textContent = 'Sessions unavailable: ' + error.message; }
}
initializeStaff();

function renderLibrary() {
  $('stat-signatures').replaceChildren(document.createTextNode(signatures.size + ' '), Object.assign(document.createElement('small'), { textContent: 'hashes' }));
  $('save-library').disabled = !staffToken || busy;
  $('reload-library').disabled = !staffToken || busy;
  $('library-caption').textContent = libraryDirty ? 'Unsaved draft · staff-supplied' : libraryRevision ? `Saved revision ${libraryRevision} · staff-supplied` : 'No saved library · inventory only';
  $('create-session').textContent = signatures.size ? '＋ Create session' : '＋ Create inventory session';
  $('library-preview').replaceChildren();
  for (const [hash, entry] of Array.from(signatures).slice(0, 6)) {
    const row = document.createElement('div'); row.className = 'library-entry';
    const label = document.createElement('span'); label.textContent = entry.name;
    const category = document.createElement('small'); category.textContent = entry.category + ' · ' + hash.slice(0, 12) + '…'; label.append(category);
    const remove = document.createElement('button'); remove.className = 'text-button'; remove.textContent = 'Remove'; remove.disabled = busy;
    remove.addEventListener('click', () => { signatures.delete(hash); libraryDirty = true; renderLibrary(); }); row.append(label, remove); $('library-preview').append(row);
  }
  if (signatures.size > 6) { const note = document.createElement('small'); note.textContent = `Showing 6 of ${signatures.size}. Export JSON to review the complete library.`; $('library-preview').append(note); }
}
async function loadLibrary() {
  const library = await api('library'); signatures = parseSignatures(library.entries); libraryRevision = library.revision; libraryDirty = false;
  $('library-title').textContent = signatures.size ? 'Saved staff signature library' : 'Bring your trusted signatures'; renderLibrary();
  $('signature-status').textContent = `Saved revision ${libraryRevision} · ${signatures.size} signatures. No independent verification of source claims.`;
}
$('save-library').addEventListener('click', async () => {
  $('save-library').disabled = true;
  try { const library = await api('library', { baseRevision: libraryRevision, signatures: Array.from(signatures, ([sha256, entry]) => ({ sha256, ...entry })) }); libraryRevision = library.revision; libraryDirty = false; $('signature-status').textContent = `Library saved · revision ${libraryRevision}. Existing reports remain unchanged; re-analyze them explicitly.`; }
  catch (error) { $('signature-status').textContent = error.message; } finally { renderLibrary(); }
});
$('reload-library').addEventListener('click', async () => { if (libraryDirty && !confirm('Discard the unsaved draft and load the saved staff library?')) return; try { await loadLibrary(); } catch (error) { $('signature-status').textContent = error.message; } });
$('export-library').addEventListener('click', () => download('crimson-signatures.json', Array.from(signatures, ([sha256, entry]) => ({ sha256, ...entry }))));
$('signature-form').addEventListener('submit', event => {
  event.preventDefault(); if (busy) return;
  try { const sha256 = $('signature-hash').value.toLowerCase(); if (signatures.has(sha256)) throw new Error('This hash already exists. Remove its existing draft entry before replacing it.');
    const parsed = parseSignatures([{ sha256, name: $('signature-name').value, source: $('signature-source').value, category: $('signature-category').value }]);
    signatures.set(sha256, parsed.get(sha256)); libraryDirty = true; renderLibrary(); $('signature-form').reset(); $('signature-status').textContent = 'Added to draft. Save the library to retain it across restarts.';
  } catch (error) { $('signature-status').textContent = error.message; }
});
for (const id of ['result-search', 'result-filter']) $(id).addEventListener(id === 'result-search' ? 'input' : 'change', renderResults);
$('original-report').addEventListener('click', () => { if (originalReport) { report = originalReport; results = report.results; renderResults(); } });
$('reanalyze-report').addEventListener('click', async () => {
  if (!activeSession) return; $('reanalyze-report').disabled = true;
  try { report = await api(`sessions/${activeSession}/analyze`, {}); results = report.results; renderResults(); await loadSessions(); }
  catch (error) { $('status').textContent = error.message; } finally { $('reanalyze-report').disabled = !activeSession || !staffToken || busy; }
});
async function downloadSessionScanner(session, button) {
  button.disabled = true; button.textContent = 'Preparing…';
  try {
    const [binaryResponse, checksumResponse] = await Promise.all([fetch('/scanner.exe'), fetch('/scanner-checksums.txt')]);
    if (!binaryResponse.ok || !checksumResponse.ok) throw new Error('Scanner build is unavailable. Use the EXE included in the project ZIP.');
    const binary = await binaryResponse.arrayBuffer(), checksum = (await checksumResponse.text()).trim().split(/\s/)[0];
    if (!/^[a-f0-9]{64}$/.test(checksum) || await hashBytes(binary) !== checksum) throw new Error('Scanner checksum mismatch. Download stopped.');
    const config = new TextEncoder().encode(JSON.stringify({ server: session.inviteUrl ? new URL(session.inviteUrl).origin : location.origin, code: session.code }));
    const footer = new Uint8Array(12); new DataView(footer.buffer).setUint32(0, config.length, true); footer.set(new TextEncoder().encode('CRMSNCFG'), 4);
    const url = URL.createObjectURL(new Blob([binary, config, footer], { type: 'application/octet-stream' }));
    const link = document.createElement('a'); link.href = url; link.download = `crimson-session-${session.code}.exe`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 5000);
    $('session-status').textContent = 'Guided scanner downloaded with this private session code and server prefilled. Share only with the intended player. Windows security policy still applies.';
  } catch (error) { $('session-status').textContent = error.message; } finally { button.disabled = false; button.textContent = 'Guided scanner'; }
}
setInterval(() => { if (staffToken && !document.hidden && !sessionsBusy) loadSessions().catch(error => { $('session-status').textContent = error.message; }); }, 10000);

document.addEventListener('visibilitychange', () => { if (staffToken && !document.hidden && !sessionsBusy) loadSessions().catch(error => { $('session-status').textContent = error.message; }); });

setupInvites();
