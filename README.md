# Sentinel — FiveM File Check

A responsive, private-by-default file-integrity dashboard. Uses real browser SHA-256 hashing, a user-imported signature library, and downloadable JSON evidence reports. No third-party dependencies or bundled cheat signatures.

## Run

Node.js 22+ is required. From this directory:

```sh
npm start
```

Open `http://localhost:3000`. Use HTTPS when hosting remotely; Web Crypto hashing requires a secure context. `PORT` overrides port 3000. Run `npm test` for the scanner tests.

## Use

1. Import a JSON signature library from a source you trust (optional; without it files are marked **unverified**).
2. Select files or a folder, confirm permission, and run a check.
3. Review hashes, matched signature names, and sources. Export the JSON report if needed.

Signature format:

```json
[
  {
    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "name": "Harmless demonstration: file containing hello, not a cheat",
    "source": "Format example only; use your independently verified signatures"
  }
]
```

The example is the hash of the five UTF-8 bytes `hello`. It demonstrates matching, not cheat detection. Browser libraries are limited to 5 MB / 50,000 entries (remote sessions: 5,000), each file to 200 MB, and each check to 1,000 files. Oversized and unreadable files are reported separately. Browser file checks never upload data. Windows clients submit filenames, sizes, hashes and optional process IDs only after explicit consent.

## Scope

This is an MVP file-integrity workflow, **not a commercial-grade anti-cheat or a clone of Ocean/NAPS**. Native Windows clients optionally enumerate accessible running executables and hash their on-disk files; this is not process-memory inspection. It does not inspect deleted files, browser history, credentials, registry entries or the whole PC. No match does not prove a cheat-free PC; a match only establishes equality to a user-supplied signature, whose accuracy is not independently verified. Modified or unknown binaries will evade exact hash matching. Reports are self-reported, not attested; a modified client can fabricate evidence. Do not use it to automatically ban players. Not affiliated with Ocean, NAPS, Cfx.re, or Rockstar Games.

## Staff sessions and Windows scanner

1. Open the site locally and create a staff password (12+ characters). Passwords are salted and scrypt-hashed. For remote deployment, set `SENTINEL_ADMIN_PASSWORD` securely on the server before starting it; first-time browser setup is restricted to loopback connections. Staff tokens expire after six hours; sign-out revokes the token.
2. Import verified signatures and create a session. The six-digit code is single-use and expires after 30 minutes. Share it privately.
3. The player downloads and reviews either the native x64 scanner or the PowerShell folder scanner. The native scanner asks for the HTTPS server origin and code, a folder, separate opt-in to hash readable running executables, and permission to begin.
4. The scanner saves a local JSON report and asks again before sending it. The server compares reported hashes against the session's signature snapshot, rather than trusting client-supplied match labels. Each session accepts one report.
5. Staff refresh the session list, view the report and export it. Coverage limits, unreadable files and unverified results stay visible.

### Build native client

Use an official Go 1.24+ toolchain:

```sh
npm run test:scanner
npm run build:scanner
```

Set `GO_BIN` if Go is not on PATH. This environment's build script also detects `/workspace/.tools/go/bin/go`. The build uses only Go standard-library packages; no external module downloads. Artifacts: `dist/sentinel-scanner-windows-amd64.exe` and `dist/checksums.txt`. These are served by `/scanner.exe` and `/scanner-checksums.txt`. Sources are in `client/`; PowerShell source is `scanner.ps1`.

The EXE is **unsigned**. Its checksum identifies this build; it does not replace publisher signing. Follow your Windows security policy. Do not disable antivirus or bypass platform warnings. Native Windows API code can be cross-compiled on Linux, but must be runtime-tested on a real Windows machine before operational use. Go core tests on Linux do not validate Windows process enumeration. The PowerShell script is provided for source review and selected-folder scanning; it has not been runtime-tested here.

### Hosting and data

By default the server binds `127.0.0.1:3000`. Configure `HOST=0.0.0.0` only for intentional hosting behind an HTTPS reverse proxy. Set `PUBLIC_URL=https://your-check-domain.example` so the PowerShell download points to the right server; native clients ask for the origin explicitly. Both clients require HTTPS for remote servers. No TLS verification is disabled. Run one server process; JSON persistence is not designed for multi-instance hosting.

`SENTINEL_DATA_DIR` overrides local `.sentinel/` storage. Keep it private and outside a publicly served directory. Auth metadata and reports persist there, with restrictive file permissions. Completed sessions are pruned after 24 hours when creating new sessions; expiry limits submission, not storage access. No file contents are stored. The upload token is scoped to one session; codes are rate-limited and redeemable once. A code is a private invitation, not verified player identity. Staff sessions and submissions are covered by API tests, including auth boundaries, replay rejection and server-side classification.

Not yet included: a verified cheat-signature feed, signed Windows releases, Windows runtime validation, tamper resistance, staff roles, production database/migrations, audits and deployment. Detection accuracy against actual FiveM cheats has not been established.
