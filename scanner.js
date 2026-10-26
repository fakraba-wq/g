export const MAX_FILE_SIZE = 200 * 1024 * 1024;
export function parseSignatures(value) {
  if (!Array.isArray(value) || value.length > 50000) throw new Error('Expected an array of up to 50,000 signatures.');
  const map = new Map();
  for (const entry of value) {
    if (!entry || typeof entry.sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(entry.sha256) || typeof entry.name !== 'string' || !entry.name.trim() || entry.name.length > 200) throw new Error('Every signature needs a 64-character SHA-256 and a name (1–200 characters).');
    const hash = entry.sha256.toLowerCase();
    if (map.has(hash)) throw new Error('Duplicate SHA-256 in signature list.');
    const category = entry.category || 'review';
    if (!['cheat', 'review', 'allowed', 'test'].includes(category)) throw new Error('Signature category must be cheat, review, allowed or test.');
    if (category === 'cheat' && (typeof entry.source !== 'string' || !entry.source.trim())) throw new Error('Staff-classified cheat entries require a source or evidence reference.');
    map.set(hash, { name: entry.name.trim(), source: typeof entry.source === 'string' ? entry.source.slice(0, 500) : 'Not provided', category });
  }
  return map;
}
export function classifyHash(sha256, signatures) {
  const signature = signatures.get(sha256) || null;
  const status = signature ? signature.category === 'allowed' ? 'allowed' : signature.category === 'test' ? 'test' : 'match' : signatures.size ? 'unmatched' : 'unverified';
  return { sha256, status, signature };
}
export async function hashBytes(bytes) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}
export async function inspectFile(file, signatures) {
  const base = { name: file.name, size: file.size };
  if (file.size > MAX_FILE_SIZE) return { ...base, status: 'skipped', reason: 'Over the 200 MB per-file limit' };
  const sha256 = await hashBytes(await file.arrayBuffer());
  return { ...base, ...classifyHash(sha256, signatures) };
}
