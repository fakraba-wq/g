const states = new Set(['collected', 'partial', 'unavailable', 'not-requested']);
const keys = new Set(['modules', 'boot', 'activity', 'integrity']);
export const trustStates = new Set(['valid-cached', 'unsigned', 'digest-mismatch', 'expired', 'untrusted', 'unavailable']);
const text = (value, max = 200) => typeof value === 'string' ? value.replace(/[\u0000-\u001f]/g, '').slice(0, max) : '';
const date = value => typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : '';
export function sanitizePE(pe) {
  if (!pe || !['x86', 'x64', 'arm64', 'unknown'].includes(pe.machine) || !Number.isInteger(pe.timestamp) || pe.timestamp < 0 || pe.timestamp > 0xffffffff || typeof pe.isDLL !== 'boolean') return undefined;
  return { machine: pe.machine, timestamp: pe.timestamp, isDLL: pe.isDLL, ...(pe.timestamp ? { linkerTimeUTC: new Date(pe.timestamp * 1000).toISOString() } : {}) };
}
export function sanitizeEvidence(body) {
  const options = Object.fromEntries(['processes', 'modules', 'integrity', 'boot', 'activity'].map(key => [key, body.options?.[key] === true]));
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
    evidence.executions = source.executions.slice(0, 100).filter(row => row && ((row.source === 'Microsoft-Windows-Sysmon/Operational' && row.eventId === 1) || (row.source === 'Security' && row.eventId === 4688)) && date(row.timeUTC) && text(row.name)).map(row => ({ name: text(row.name).split(/[\\/]/).pop(), timeUTC: date(row.timeUTC), source: row.source, eventId: row.eventId, pathState: ['present', 'not-found', 'unknown'].includes(row.pathState) ? row.pathState : 'unknown' }));
    evidence.windowStartUTC = date(source.windowStartUTC);
  }
  return { options, evidence };
}
export function reportSummary(report) {
  const rows = report?.results || [];
  return { files: rows.length, hashed: rows.filter(row => row.sha256).length, matches: rows.filter(row => row.status === 'match').length, skipped: rows.filter(row => !row.sha256).length, integrity: rows.filter(row => row.pe).length, digestMismatches: rows.filter(row => row.integrityStatus === 'digest-mismatch').length, modules: rows.filter(row => row.origin === 'loaded-module').length, activity: report?.evidence?.executions?.length || 0, boot: report?.evidence?.boot ? 1 : 0 };
}
