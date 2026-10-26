import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeEvidence, sanitizePE, reportSummary } from './report-model.js';
import { parsePE } from './scanner.js';

test('unconsented system/activity evidence and unknown private fields are discarded', () => {
  const body = { options: {}, evidence: { boot: { biosVendor: 'fixture', serialNumber: 'private-serial' }, executions: [{ name: 'sample.exe', timeUTC: '2026-01-01T10:00:00Z', source: 'Security', eventId: 4688, commandLine: 'private-command', user: 'private-user' }] } };
  const result = sanitizeEvidence(body);
  assert.equal(result.evidence.boot, undefined); assert.equal(result.evidence.executions, undefined);
  assert.ok(result.evidence.collection.every(row => row.state === 'not-requested'));
  body.options = { boot: true, activity: true };
  const accepted = sanitizeEvidence(body), serialized = JSON.stringify(accepted);
  assert.equal(accepted.evidence.executions[0].name, 'sample.exe');
  for (const text of ['serialNumber', 'private-serial', 'commandLine', 'private-command', 'private-user']) assert.equal(serialized.includes(text), false);
});
test('event sources are allowlisted, paths stripped, dates validated and counts bounded', () => {
  const event = { name: 'C:\\private\\sample.exe', timeUTC: '2026-01-01T10:00:00Z', source: 'Security', eventId: 4688, pathState: 'deleted-because-cheating' };
  const result = sanitizeEvidence({ options: { activity: true }, evidence: { executions: Array(150).fill(event) } });
  assert.equal(result.evidence.executions.length, 100); assert.equal(result.evidence.executions[0].name, 'sample.exe'); assert.equal(result.evidence.executions[0].pathState, 'unknown');
  const invalid = sanitizeEvidence({ options: { activity: true }, evidence: { executions: [{ ...event, timeUTC: 'bad' }, { ...event, source: 'browser-history' }] } });
  assert.equal(invalid.evidence.executions.length, 0);
});
test('PE header parser rejects truncated/unbounded offsets and recomputes timestamp facts', () => {
  const bytes = new ArrayBuffer(256), data = new DataView(bytes);
  data.setUint16(0, 0x5a4d, true); data.setUint32(60, 128, true); data.setUint32(128, 0x4550, true); data.setUint16(132, 0x8664, true); data.setUint32(136, 1000000000, true); data.setUint16(150, 0x2000, true);
  const pe = parsePE(bytes); assert.equal(pe.machine, 'x64'); assert.equal(pe.isDLL, true);
  assert.equal(sanitizePE({ ...pe, linkerTimeUTC: 'forged' }).linkerTimeUTC, new Date(1000000000000).toISOString());
  data.setUint32(60, 0xffffffff, true); assert.equal(parsePE(bytes), undefined); assert.equal(parsePE(new ArrayBuffer(5)), undefined);
});
test('ordinary unsigned files and missing event paths are not converted into cheat detections', () => {
  const summary = reportSummary({ results: [{ name: 'normal.exe', sha256: 'a'.repeat(64), status: 'unmatched', integrityStatus: 'unsigned', pe: { timestamp: 0 } }], evidence: { executions: [{ pathState: 'not-found' }] } });
  assert.equal(summary.matches, 0); assert.equal(summary.digestMismatches, 0); assert.equal(summary.integrity, 1); assert.equal(summary.activity, 1);
});
