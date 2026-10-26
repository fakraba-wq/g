"""Package distributable source and the built Windows scanner, never local state."""
from pathlib import Path
import hashlib
import zipfile

root = Path(__file__).resolve().parent.parent
names = ['package.json', '.gitignore', 'index.html', 'style.css', 'app.js', 'backend.js',
         'backend.test.js', 'runtime.test.js', 'invite-view.js', 'player.html', 'player.js', 'package-lock.json', 'Dockerfile', '.dockerignore', 'compose.yaml', 'Caddyfile', '.env.example', 'HOSTING.md', 'report-model.js', 'report-model.test.js', 'report-view.js', 'server.js', 'scanner.js', 'scanner.test.js', 'scanner.ps1',
         'start-crimson.cmd', 'start-sentinel.cmd', 'README.md', 'QUICKSTART.txt', 'UPDATE.txt',
         'dist/crimson-pc-check-windows-amd64.exe', 'dist/checksums.txt']
files = [root / name for name in names]
for directory in ['client', 'scripts', 'assets', 'vendor']:
    files.extend(p for p in (root / directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
binary = root / 'dist/crimson-pc-check-windows-amd64.exe'
assert hashlib.sha256(binary.read_bytes()).hexdigest() == (root / 'dist/checksums.txt').read_text().split()[0]
archive = root / 'dist/crimson-pc-check.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as output:
    for file in sorted(set(files)):
        relative = file.relative_to(root)
        assert '.sentinel' not in relative.parts and '.git' not in relative.parts
        output.write(file, 'crimson-pc-check/' + relative.as_posix())
with zipfile.ZipFile(archive) as output:
    assert output.testzip() is None
print(f'Created {archive.name}: {archive.stat().st_size:,} bytes; no credentials or local reports included.')
