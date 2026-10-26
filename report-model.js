const states = new Set(['collected', 'partial', 'unavailable', 'not-requested']);
const keys = new Set(['modules', 'boot', 'activity', 'integrity', 'discovery', 'accounts']);
export const trustStates = new Set(['valid-cached', 'unsigned', 'digest-mismatch', 'expired', 'untrusted', 'unavailable']);
const text = (value, max = 200) => typeof value === 'string' ? value.replace(/[\u0000-\u001f]/g, '').slice(0, max) : '';
const date = value => typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : '';
export function sanitizePath(value) {
 if(typeof value!=='string'||value.length>2048||/[\u0000-\u001f\u007f]/.test(value))return undefined;
 return /^(?:[A-Za-z]:[\\/]|\/(?!\/))/.test(value)?value:undefined;
}
export function sanitizePE(pe) {
  if (!pe || !['x86', 'x64', 'arm64', 'unknown'].includes(pe.machine) || !Number.isInteger(pe.timestamp) || pe.timestamp < 0 || pe.timestamp > 0xffffffff || typeof pe.isDLL !== 'boolean') return undefined;
  return { machine: pe.machine, timestamp: pe.timestamp, isDLL: pe.isDLL, ...(pe.timestamp ? { linkerTimeUTC: new Date(pe.timestamp * 1000).toISOString() } : {}) };
}
export function sanitizeEvidence(body) {
  const options = Object.fromEntries(['processes', 'modules', 'integrity', 'boot', 'activity', 'discovery', 'accounts', 'paths'].map(key => [key, body.options?.[key] === true]));
  options.processes ||= body.processScanRequested === true;
  const source = body.evidence || {}, evidence = { collection: [] };
  for (const key of keys) {
    const entry = Array.isArray(source.collection) ? source.collection.find(item => item?.key === key) : null;
    evidence.collection.push({ key, state: options[key] ? states.has(entry?.state) && entry.state !== 'not-requested' ? entry.state : 'unavailable' : 'not-requested', count: options[key] && Number.isInteger(entry?.count) && entry.count >= 0 ? Math.min(entry.count, 1000) : 0, note: options[key] ? text(entry?.note, 400) || 'Collection status not supplied.' : 'Not authorized in this scan.' });
  }
  if (options.boot && source.boot && typeof source.boot === 'object') {
    evidence.boot = Object.fromEntries(['windowsVersion', 'biosVendor', 'biosVersion', 'boardManufacturer', 'boardProduct'].map(key => [key, text(source.boot[key])]));
    evidence.boot.lastBootUTC = date(source.boot.lastBootUTC);
    if (typeof source.boot.fastBootEnabled === 'boolean') evidence.boot.fastBootEnabled = source.boot.fastBootEnabled;
  }
  if (options.activity && Array.isArray(source.executions)) {
    evidence.executions = source.executions.slice(0, 100).filter(row => row && ((row.source === 'Microsoft-Windows-Sysmon/Operational' && row.eventId === 1) || (row.source === 'Security' && row.eventId === 4688)) && date(row.timeUTC) && text(row.name)).map(row => ({ name: text(row.name).split(/[\\/]/).pop(), ...(options.paths && sanitizePath(row.path)?{path:sanitizePath(row.path)}:{}), timeUTC: date(row.timeUTC), source: row.source, eventId: row.eventId, pathState: ['present', 'not-found', 'unknown'].includes(row.pathState) ? row.pathState : 'unknown' }));
    evidence.windowStartUTC = date(source.windowStartUTC);
  }
  if(options.discovery&&options.paths&&Array.isArray(source.roots))evidence.roots=source.roots.slice(0,10).filter(root=>root&&sanitizePath(root.path)).map(root=>({label:text(root.label,60),path:sanitizePath(root.path)}));
  if(options.accounts&&Array.isArray(source.accounts)){
   const seen=new Set();evidence.accounts=source.accounts.slice(0,51).filter(row=>row&&((row.platform==='steam'&&/^7656[0-9]{13}$/.test(row.id)&&row.source==='steam-local-profile')||(row.platform==='discord'&&/^[0-9]{17,20}$/.test(row.id)&&row.source==='player-provided'))).filter(row=>{const key=row.platform+':'+row.id;if(seen.has(key))return false;seen.add(key);return true}).map(row=>({platform:row.platform,id:row.id,name:text(row.name)||'Profile',source:row.source,verified:false}));
  }
  return { options, evidence };
}
export function reportSummary(report) {
  const rows = report?.results || [];
  return { accounts:report?.evidence?.accounts?.length || 0, files: rows.length, hashed: rows.filter(row => row.sha256).length, matches: rows.filter(row => row.status === 'match').length, skipped: rows.filter(row => !row.sha256).length, integrity: rows.filter(row => row.pe).length, digestMismatches: rows.filter(row => row.integrityStatus === 'digest-mismatch').length, modules: rows.filter(row => row.origin === 'loaded-module').length, activity: report?.evidence?.executions?.length || 0, boot: report?.evidence?.boot ? 1 : 0 };
}
