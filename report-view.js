import { reportSummary } from './report-model.js';

const el = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; };
const trustLabels = { 'valid-cached': 'Windows trust: valid using cached certificates', unsigned: 'No Windows signature found', 'digest-mismatch': 'Windows signature digest mismatch — review', expired: 'Windows trust: expired', untrusted: 'Windows trust: untrusted locally', unavailable: 'Windows trust unavailable' };
let selected = 'overview';
let latest = null, search = '';
const date = value => value && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString() : 'Not collected';
function pill(text, kind = 'neutral') { return el('span', 'evidence-pill ' + kind, text); }
function note(text) { return el('p', 'evidence-note', text); }
function row(title, detail, kind = 'info', hash, path) {
  const node = el('article', 'evidence-row ' + kind), icon = el('span', 'evidence-icon', kind === 'review' ? '!' : 'i'), content = el('div');
  content.append(el('strong', '', title), note(detail));
  if (hash) { const code = el('code', 'evidence-hash', hash); content.append(code); }
  if(path){const location=el('code','file-location',path);const button=el('button','copy-path','Copy path');button.type='button';button.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(path);button.textContent='Copied';}catch{button.textContent='Select path and press Ctrl+C';}});content.append(location,button);}
  node.append(icon, content, pill(kind === 'review' ? 'REVIEW' : 'INFO', kind));
  return node;
}
function factGrid(values) {
  const grid = el('div', 'evidence-facts');
  for (const [label, value] of values) { const card = el('div'); card.append(el('span', '', label), el('strong', '', value ?? 'Not collected')); grid.append(card); }
  return grid;
}
function empty(title, detail) { const section = el('div', 'evidence-empty'); section.append(el('span', 'evidence-empty-icon', '◈'), el('h3', '', title), note(detail)); return section; }
function draw() {
  const root = document.getElementById('evidence-workbench'); if (!root) return;
  root.replaceChildren(); root.hidden = !latest; if (!latest) return;
  const report = latest, summary = reportSummary(report), entries = report.results || [], evidence = report.evidence || {};
  const matched = entries.filter(file => file.status === 'match'), integrity = entries.filter(file => file.pe), modules = entries.filter(file => file.origin === 'loaded-module'), activity = evidence.executions || [];
  const matches = object => !search || JSON.stringify(object).toLowerCase().includes(search.toLowerCase());
  const header = el('div', 'evidence-report-heading'); header.append(el('div', '', 'CRIMSON / EVIDENCE REPORT'), pill('SELF-REPORTED · NOT ATTESTED'));
  root.append(header);
  const counts = el('div', 'evidence-stats');
  for (const [label, value, detail] of [['Files hashed', summary.hashed, `${summary.skipped} skipped or unreadable`], ['Review observations', summary.matches + summary.digestMismatches, 'Matches and signature integrity issues'], ['Collected activity', summary.activity, 'Existing execution records only']]) {
    const card = el('div'); card.append(el('span', '', label), el('strong', '', String(value)), note(detail)); counts.append(card);
  }
  root.append(counts);
  const assessment = el('div', 'cleaning-assessment');
  const assessmentText = el('div'); assessmentText.append(el('strong', '', 'Cleaning assessment'), note('Not implemented. A missing log, missing path or enabled Fast Startup does not establish that a PC was cleaned to hide cheats.'));
  assessment.append(assessmentText, pill('NOT ASSESSED')); root.append(assessment);
  const layout = el('div', 'evidence-layout'), rail = el('nav', 'evidence-rail'), panel = el('section', 'evidence-panel'); rail.setAttribute('aria-label', 'Report categories');
  rail.append(el('h3', '', 'Evidence results'), note('Only collected data is counted.'));
  const categories = [['overview', 'Overview', summary.matches + summary.digestMismatches], ['integrity', 'Integrity logs', summary.integrity], ['modules', 'FiveM DLL modules', summary.modules], ['activity', 'Execution timeline', summary.activity], ['boot', 'Boot & system', summary.boot], ['accounts','Accounts',summary.accounts], ['compilation', 'PE timestamps', summary.integrity], ['recording', 'Recording filenames', entries.filter(file => ['obs64.exe','obs32.exe','sharex.exe','medal.exe','streamlabsobs.exe','nvidia overlay.exe'].includes(file.name.toLowerCase())).length], ['coverage', 'Collection coverage', evidence.collection?.length || 0], ['external', 'External records', null], ['summary', 'Analyst summary', null]];
  for (const [key, title, count] of categories) {
    const button = el('button', selected === key ? 'active' : '', title), badge = el('span', '', count === null ? key === 'external' ? 'UNAVAILABLE' : 'FACTS' : String(count));
    button.append(badge); button.setAttribute('aria-pressed', String(selected === key)); button.addEventListener('click', () => { selected = key; draw(); }); rail.append(button);
  }
  const selectedTitle = categories.find(([key]) => key === selected)?.[1] || 'Overview';
  panel.append(el('h3', 'evidence-panel-title', selectedTitle));
  const body = el('div', 'evidence-panel-body');
  if (selected === 'overview') {
    for (const file of matched.filter(matches)) body.append(row(file.signature?.name || file.name, `${file.name} · exact SHA-256 match to a staff-supplied ${file.signature?.category || 'review'} entry. Source: ${file.signature?.source || 'not provided'}. This is not independent proof of cheating.`, 'review', file.sha256,file.path));
    for (const file of entries.filter(file => file.integrityStatus === 'digest-mismatch').filter(matches)) body.append(row(file.name, 'The client reports a Windows signature digest mismatch. Investigate the file and source; this alone is not a cheat verdict.', 'review', file.sha256,file.path));
    if (!body.childElementCount) body.append(empty('No review observations from the available evidence', report.signaturesUsed?.length ? 'This does not establish a clean PC. Unknown versions, uncollected files and incomplete sources remain outside coverage.' : 'No signature library was used for this collection. It is an inventory, not a cheat verdict.'));
  } else if (selected === 'integrity') {
    body.append(note('PE timestamps are header metadata and can be forged or unset. Unsigned files can be legitimate. Windows trust uses local cached certificates; no online revocation check is claimed.'));
    for (const file of integrity.filter(matches)) body.append(row(file.name, `${file.pe.isDLL ? 'DLL' : 'Executable'} · ${file.pe.machine} · PE timestamp: ${date(file.pe.linkerTimeUTC)} · ${trustLabels[file.integrityStatus] || 'Windows trust not collected'}`, file.integrityStatus === 'digest-mismatch' ? 'review' : 'info', file.sha256,file.path));
    if (!integrity.length) body.append(empty('No PE/integrity metadata collected', 'Enable the PE and Windows signatures option in a new guided scan. Old reports do not gain metadata through re-analysis.'));
  } else if (selected === 'modules') {
    for (const file of modules.filter(matches)) body.append(row(file.name, `DLL image reported by Windows for a FiveM/GTA process${file.processId ? ' · PID ' + file.processId : ''}. ${file.status === 'match' ? 'Staff signature match requires review.' : 'Being a loaded DLL is not proof of a cheat.'}`, file.status === 'match' ? 'review' : 'info', file.sha256,file.path));
    if (!modules.length) body.append(empty('No FiveM DLL entries available', 'The option may not have been selected, FiveM may not have been running, or process access may have been limited. Consult Collection coverage.'));
  } else if (selected === 'activity') {
    body.append(note(`Window start: ${date(evidence.windowStartUTC)}. Up to 100 existing Sysmon/Security process-creation events. No raw command lines, account details or PowerShell history contents are collected.`));
    for (const event of [...activity].sort((a, b) => b.timeUTC.localeCompare(a.timeUTC)).filter(matches)) body.append(row(event.name, `${date(event.timeUTC)} · ${event.source} / event ${event.eventId} · current path: ${event.pathState}. A missing current path does not prove deletion or intent.`, 'info', undefined, event.path));
    if (!activity.length) body.append(empty('No execution records available', 'Logs may be disabled, inaccessible, empty, or not authorized for this scan. Auditing is never enabled automatically.'));
  } else if (selected === 'boot') {
    const boot = evidence.boot;
    if (boot) {
      body.append(factGrid([['Windows', boot.windowsVersion || 'Not reported'], ['Last boot', date(boot.lastBootUTC)], ['BIOS vendor', boot.biosVendor || 'Not reported'], ['BIOS version', boot.biosVersion || 'Not reported'], ['Board manufacturer', boot.boardManufacturer || 'Not reported'], ['Board product', boot.boardProduct || 'Not reported'], ['Fast Startup', typeof boot.fastBootEnabled === 'boolean' ? boot.fastBootEnabled ? 'Enabled' : 'Disabled' : 'Unavailable']]));
      body.append(note('Fast Startup is a standard Windows feature. These facts do not establish a boot chain, cleaning attempt or cheat. Serial numbers and hardware identifiers are excluded.'));
    } else body.append(empty('Boot information not available', 'Select boot/system metadata in a new scan. A legacy report has no supported boot evidence.'));
  } else if (selected === 'accounts') {
    body.append(note('Only explicitly shared profile identifiers are listed. Steam profiles were remembered locally; Discord IDs were supplied by the player. Ownership, current sign-in and external cheater records are not verified. No tokens, passwords or private messages are collected.'));
    for(const profile of (evidence.accounts||[]).filter(matches)){
      const item=row(profile.name,`${profile.platform.toUpperCase()} · ID: ${profile.id} · ${profile.source==='player-provided'?'Player-provided':'Locally remembered profile'} · UNVERIFIED`);
      if(profile.platform==='steam'&&/^7656[0-9]{13}$/.test(profile.id)){const link=el('a','account-link','Open public Steam profile ↗');link.href='https://steamcommunity.com/profiles/'+profile.id;link.target='_blank';link.rel='noopener noreferrer';item.append(link);}body.append(item);
    }
    if(!evidence.accounts?.length)body.append(empty('No shared profile identifiers', 'Enable profile sharing in a new scan. A Discord ID can be entered by the player. Discord OAuth and other account providers are not configured. This is not a list of every account on the PC.'));
  } else if (selected === 'compilation') {
    body.append(note('PE header timestamps are untrusted metadata, not file creation dates or proof of execution. Reproducible builds may use zero.'));
    for (const file of integrity.filter(matches)) body.append(row(file.name, `${file.pe.machine} · ${file.pe.isDLL ? 'DLL' : 'EXE'} · PE timestamp: ${date(file.pe.linkerTimeUTC)}`, 'info', file.sha256,file.path));
    if (!integrity.length) body.append(empty('No PE timestamps collected', 'Enable PE metadata in a new scan.'));
  } else if (selected === 'recording') {
    const recording = entries.filter(file => ['obs64.exe','obs32.exe','sharex.exe','medal.exe','streamlabsobs.exe','nvidia overlay.exe'].includes(file.name.toLowerCase()));
    body.append(note('These are filename observations for recording-capable software, not verified publisher identities or cheating indicators.'));
    for (const file of recording.filter(matches)) body.append(row(file.name, 'A recording-capable filename was observed in the authorized selection. No cheating conclusion is drawn.', 'info', file.sha256,file.path));
    if (!recording.length) body.append(empty('No matching filenames in collected entries', 'Uncollected or renamed software is outside this observation.'));
  } else if (selected === 'coverage') {
    body.append(note(report.coverageLimited ? 'Coverage is limited. Some sources or files were unavailable.' : 'Only the explicitly authorized selection was inspected. This is not a whole-PC guarantee.'));
    for (const source of evidence.collection || []) body.append(row(source.key, `${source.state} · ${source.count} entries. ${source.note}`));
    if (!evidence.collection?.length) body.append(empty('Legacy file inventory', 'This report predates detailed collection statuses. Missing evidence is not a clean result.'));
    for(const root of evidence.roots||[])body.append(row(root.label,'Authorized standard discovery location. Only EXE/DLL files within the stated limits were considered.','info',undefined,root.path));
    body.append(row('Excluded data', 'Private account contents, Discord memberships, PowerShell history contents, screenshots, credentials and process memory dumps are not collected.'));
  } else if (selected === 'external') {
    body.append(empty('No external provider connected', 'Cheater databases require licensed API access and documented identifiers. No third-party result is fabricated, scraped from a private account or inferred from community membership.'));
    body.append(pill('NO QUERY PERFORMED'));
  } else {
    body.append(factGrid([['Files hashed', summary.hashed], ['Exact review matches', summary.matches], ['Integrity observations', summary.digestMismatches], ['DLL entries', summary.modules], ['Execution records', summary.activity], ['Signature library', report.signaturesUsed?.length || 0]]));
    body.append(note('This is a deterministic evidence summary, not an AI opinion or statistical risk score. Review the source, coverage and original collection before making a decision. No automatic ban is issued.'));
  }
  panel.append(body); layout.append(rail, panel); root.append(layout);
  root.append(note(`Collected: ${date(report.completedAt)}${report.analyzedAt ? ' · Re-analyzed: ' + date(report.analyzedAt) : ''}. ${report.interpretation || 'Client-reported evidence; review required.'}`));
}
export function renderEvidence(report, query = '') { latest = report; search = query; draw(); }
