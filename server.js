import http from 'node:http';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createBackend } from './backend.js';
import { pathToFileURL } from 'node:url';
import { resolve, sep } from 'node:path';
const data = process.env.SENTINEL_DATA_DIR ? pathToFileURL(resolve(process.env.SENTINEL_DATA_DIR) + sep) : new URL('./.sentinel/', import.meta.url);
let publicBase = process.env.PUBLIC_URL;
if (publicBase) {
  const parsed = new URL(publicBase);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash || !['', '/'].includes(parsed.pathname)) throw new Error('PUBLIC_URL must be an HTTP(S) origin without credentials or a path.');
  publicBase = parsed.origin;
}
const api = await createBackend(data, process.env.SENTINEL_ADMIN_PASSWORD, { publicOrigin: publicBase });
const files = { '/': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/scanner.js': ['scanner.js', 'text/javascript'], '/style.css': ['style.css', 'text/css'], '/assets/crimson-logo.png': ['assets/crimson-logo.png', 'image/png'] };
files['/report-model.js'] = ['report-model.js', 'text/javascript'];
files['/report-view.js'] = ['report-view.js', 'text/javascript'];
files['/invite-view.js'] = ['invite-view.js', 'text/javascript'];
files['/vendor/qr.js'] = ['vendor/qr.js', 'text/javascript'];
files['/player.js'] = ['player.js', 'text/javascript'];
const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (pathname === '/health') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ status: 'ok', application: 'Crimson PC Check' })); }
  const invitedDownload = pathname.match(/^\/check\/([a-f0-9]{64})\/scanner\.exe$/);
  if (invitedDownload && req.method === 'GET') {
    const session = api.findInvite(invitedDownload[1]);
    if (!session || session.redeemed || session.report) { res.writeHead(410, { 'Content-Type': 'text/plain' }); return res.end('Invitation expired or already used. Ask staff for a new invitation.'); }
    if (!api.publicOrigin) { res.writeHead(409, { 'Content-Type': 'text/plain' }); return res.end('Internet invitations require a configured public HTTPS address.'); }
    try {
      const binary = await readFile(new URL('./dist/crimson-pc-check-windows-amd64.exe', import.meta.url));
      const expected = (await readFile(new URL('./dist/checksums.txt', import.meta.url), 'utf8')).trim().split(/\s/)[0];
      if (!/^[a-f0-9]{64}$/.test(expected) || createHash('sha256').update(binary).digest('hex') !== expected) throw new Error('Scanner checksum mismatch');
      const config = Buffer.from(JSON.stringify({ server: api.publicOrigin, code: session.code }));
      const footer = Buffer.alloc(12); footer.writeUInt32LE(config.length); footer.write('CRMSNCFG', 4, 'ascii');
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="crimson-session-${session.code}.exe"`, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' });
      return res.end(Buffer.concat([binary, config, footer]));
    } catch { res.writeHead(503); return res.end('The Windows scanner build is unavailable. Contact staff.'); }
  }
  if (await api(req, res, pathname)) return;
  const downloads = {
    '/scanner.exe': ['dist/crimson-pc-check-windows-amd64.exe', 'application/octet-stream', 'crimson-pc-check-windows-amd64.exe'],
    '/scanner-checksums.txt': ['dist/checksums.txt', 'text/plain', 'checksums.txt'],
    '/download-project.zip': ['dist/crimson-pc-check.zip', 'application/zip', 'crimson-pc-check.zip']
  };
  if (downloads[pathname]) {
    const [path, contentType, filename] = downloads[pathname];
    try {
      const content = await readFile(new URL(path, import.meta.url));
      res.writeHead(200, { 'Content-Type': contentType, 'Content-Disposition': `attachment; filename="${filename}"`, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' }); return res.end(content);
    } catch { res.writeHead(503); return res.end(pathname === '/download-project.zip' ? 'Project archive is not available on this server.' : 'Build the scanner with npm run build:scanner first.'); }
  }
  if (pathname === '/scanner.ps1') {
    const host = req.headers.host || 'localhost:3000';
    if (!/^[a-zA-Z0-9.:[\]-]+$/.test(host)) { res.writeHead(400); return res.end('Invalid host'); }
    const base = publicBase || `http://${host}`;
    const uri = new URL(base);
    if (!['http:', 'https:'].includes(uri.protocol)) { res.writeHead(500); return res.end('Invalid PUBLIC_URL'); }
    const source = await readFile(new URL('./scanner.ps1', import.meta.url), 'utf8');
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Disposition': 'attachment; filename="sentinel-scanner.ps1"', 'Cache-Control': 'no-store' });
    return res.end(source.replace('__SERVER_URL__', base.replaceAll("'", "''")));
  }
  if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405); return res.end('Method not allowed'); }
  const file = /^\/check\/[a-f0-9]{64}$/.test(pathname) ? ['player.html', 'text/html'] : files[pathname];
  if (!file) { res.writeHead(404); return res.end('Not found'); }
  try {
    const body = await readFile(new URL(file[0], import.meta.url));
    res.writeHead(200, { 'Content-Type': file[1] + '; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'" });
    res.end(body);
  } catch { res.writeHead(500); res.end('Unable to serve application'); }
});
server.listen(Number(process.env.PORT || 3000), process.env.HOST || '127.0.0.1', () => console.log('Crimson PC Check running on port ' + (process.env.PORT || 3000)));
