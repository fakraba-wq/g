import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createBackend } from './backend.js';
import { pathToFileURL } from 'node:url';
import { resolve, sep } from 'node:path';
const data = process.env.SENTINEL_DATA_DIR ? pathToFileURL(resolve(process.env.SENTINEL_DATA_DIR) + sep) : new URL('./.sentinel/', import.meta.url);
const api = await createBackend(data, process.env.SENTINEL_ADMIN_PASSWORD);
let publicBase = process.env.PUBLIC_URL;
if (publicBase) {
  const parsed = new URL(publicBase);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash || !['', '/'].includes(parsed.pathname)) throw new Error('PUBLIC_URL must be an HTTP(S) origin without credentials or a path.');
  publicBase = parsed.origin;
}
const files = { '/': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/scanner.js': ['scanner.js', 'text/javascript'], '/style.css': ['style.css', 'text/css'] };
const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (await api(req, res, pathname)) return;
  const downloads = {
    '/scanner.exe': ['dist/sentinel-scanner-windows-amd64.exe', 'application/octet-stream', 'sentinel-scanner-windows-amd64.exe'],
    '/scanner-checksums.txt': ['dist/checksums.txt', 'text/plain', 'checksums.txt'],
    '/download-project.zip': ['dist/sentinel-project.zip', 'application/zip', 'sentinel-project.zip']
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
  const file = files[pathname];
  if (!file) { res.writeHead(404); return res.end('Not found'); }
  try {
    const body = await readFile(new URL(file[0], import.meta.url));
    res.writeHead(200, { 'Content-Type': file[1] + '; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'" });
    res.end(body);
  } catch { res.writeHead(500); res.end('Unable to serve application'); }
});
server.listen(Number(process.env.PORT || 3000), process.env.HOST || '127.0.0.1', () => console.log('Sentinel running on port ' + (process.env.PORT || 3000)));
