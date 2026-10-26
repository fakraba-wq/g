// Explicit deployment preparation. Never runs automatically to restore a deleted/quarantined EXE.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';

function entry(zip, wanted) {
  let end = -1;
  for (let offset = zip.length - 22; offset >= Math.max(0, zip.length - 65557); offset--) if (zip.readUInt32LE(offset) === 0x06054b50) { end = offset; break; }
  if (end < 0) throw new Error('ZIP directory not found.');
  const count = zip.readUInt16LE(end + 10); if (count > 500) throw new Error('Unexpected archive size.');
  let offset = zip.readUInt32LE(end + 16);
  for (let i = 0; i < count; i++) {
    if (offset + 46 > zip.length || zip.readUInt32LE(offset) !== 0x02014b50) throw new Error('Invalid ZIP directory.');
    const flags = zip.readUInt16LE(offset + 8), method = zip.readUInt16LE(offset + 10), compressed = zip.readUInt32LE(offset + 20), size = zip.readUInt32LE(offset + 24);
    const nameLength = zip.readUInt16LE(offset + 28), extra = zip.readUInt16LE(offset + 30), comment = zip.readUInt16LE(offset + 32), local = zip.readUInt32LE(offset + 42);
    const name = zip.toString('utf8', offset + 46, offset + 46 + nameLength); offset += 46 + nameLength + extra + comment;
    if (name !== wanted) continue;
    if (flags & 1 || ![0, 8].includes(method) || size > 32 * 1024 * 1024 || local + 30 > zip.length || zip.readUInt32LE(local) !== 0x04034b50) throw new Error('Unsupported ZIP entry.');
    const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
    if (start + compressed > zip.length) throw new Error('Truncated ZIP entry.');
    const data = method === 0 ? zip.subarray(start, start + compressed) : inflateRawSync(zip.subarray(start, start + compressed), { maxOutputLength: 32 * 1024 * 1024 });
    if (data.length !== size) throw new Error('ZIP entry size mismatch.'); return data;
  }
  throw new Error('Required packaged artifact missing: ' + wanted);
}
export async function prepareHosted(root = new URL('../', import.meta.url)) {
  const zip = await readFile(new URL('dist/crimson-pc-check.zip', root)); if (zip.length > 32 * 1024 * 1024) throw new Error('Archive exceeds deployment limit.');
  const binary = entry(zip, 'crimson-pc-check/dist/crimson-pc-check-windows-amd64.exe');
  const checksums = entry(zip, 'crimson-pc-check/dist/checksums.txt');
  const expected = checksums.toString('utf8').trim().split(/\s/)[0];
  if (!/^[a-f0-9]{64}$/.test(expected) || createHash('sha256').update(binary).digest('hex') !== expected) throw new Error('Packaged Windows scanner checksum mismatch.');
  await mkdir(new URL('dist/', root), { recursive: true });
  await writeFile(new URL('dist/crimson-pc-check-windows-amd64.exe', root), binary);
  await writeFile(new URL('dist/checksums.txt', root), checksums);
}
if (process.argv[1] === fileURLToPath(import.meta.url)) { await prepareHosted(); console.log('Hosted Windows scanner prepared and SHA-256 verified.'); }
