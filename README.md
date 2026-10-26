# Crimson PC Check — v3

A red and charcoal FiveM file-integrity dashboard using the provided Crimson RP logo. Includes a guided Windows scanner, staff sessions, persistent signature library, original evidence plus re-analysis, search/filter and JSON export. Node.js and Go standard-library servers; QR generation is bundled locally with its third-party licenses. No npm install is needed to start the downloaded application.

## Start

Node.js 22+ is required. On Windows, double-click `start-crimson.cmd`. Otherwise run `npm start` from this directory. Open `http://localhost:3000`. Keep the server window open. The legacy `start-sentinel.cmd` delegates to the new launcher.

Create a staff password locally (12–256 characters). Passwords are salted and scrypt-hashed. For remote hosting, configure `SENTINEL_ADMIN_PASSWORD` securely before startup; initial browser setup is allowed from loopback only. Staff sign-in tokens expire after six hours and are revoked by sign-out.

See `QUICKSTART.txt` for the Windows walkthrough and `UPDATE.txt` for upgrading without losing your existing data. Local data remains in `.sentinel/` for backward compatibility; it is never bundled or committed.

## Guided Windows checks

1. Import signatures from a source you have independently reviewed, or add a name, SHA-256, classification and evidence reference. Click **Save library**. Revisions and source references persist on the server.
2. Create a session. Without signatures the button explicitly creates an **inventory session**, not a cheat verdict. New PINs contain eight characters, are redeemable once and default to a 24-hour lifetime; staff can choose one hour or 30 minutes. Legacy six-digit codes remain supported.
3. Click **Guided scanner** on the session row. The website verifies the base binary checksum, then appends a bounded JSON configuration footer with the server origin and that private code. This personalized EXE has a different SHA-256 from the base build. Do not share it with unintended players. This is not publisher signing.
4. Launch the EXE. A local browser wizard opens. Choose a folder using the native picker and/or opt in to readable running executable file hashing. Check the permission box and start. Invalid input stays on-screen; no terminal commands are needed. The generic EXE in `dist/` opens the same wizard with the staff origin defaulted to localhost and the session code left blank.
5. Review the local report. Sharing is a separate checkbox and action. Nothing is uploaded automatically. Basic reports contain filenames, sizes, hashes, origins and optional process IDs. Optional sources are described below. Raw file contents, browser history, credentials, private accounts and process-memory contents are not collected.
6. Staff sessions refresh every ten seconds while the tab is visible. Open the report, search or filter it, and export JSON. After saving new signatures, **Re-analyze with saved library** compares the existing hashes again without rescanning the player. Original collection evidence is retained; the last five separate analyses are stored.

The local wizard binds a random loopback port, uses a random access token, checks Host/Origin and requires token-authenticated JSON for operations. It stops on **Fermer le scanner**, console closure or a one-hour lifetime. It does not install a service or start itself on login. Local reports are saved to temporary JSON files on the player's PC.

The legacy terminal interface remains available with `-cli`; confirmation words are case-insensitive. Optional `-server` and `-code` flags prefill either interface. `-no-open` prints the private local wizard URL for diagnostics instead of opening a browser.

## Private player invitations

Create a session to open its invitation dialog: PIN, expiry, Windows download, copy link, locally generated QR and real session status. Public invitations require a configured HTTPS `PUBLIC_URL` and a deployed reachable server. Without it, the dialog provides a clearly labelled local preview; a localhost address cannot be shared with another PC. Linux scanner downloads are explicitly unavailable.

The private `/check/<random-token>` landing page exposes only invitation status and a session-specific Windows download, not staff reports or the staff PIN. The executable embeds the staff origin and PIN. Downloads stop after redemption or expiry. Possession of an invitation is not verified player identity. See [HOSTING.md](HOSTING.md).

## Optional Windows evidence and report panels

Each source is optional in the guided scanner. Alongside selected-folder and running EXE hashes, the scanner can collect:

- DLL paths loaded by accessible FiveM/GTA processes and hash the on-disk files, without reading process-memory contents.
- PE architecture and COFF timestamps from scanned files. Timestamps are editable metadata, not execution or file-creation dates.
- Cache-only Windows signature trust status. It does not fetch certificate data from the network; unavailable or unsigned does not mean cheat.
- Basic Windows/BIOS/board facts, last boot and the Fast Startup setting. This option reads selected system metadata and one registry setting; no serial numbers are included.
- Up to 100 existing Security 4688 / Sysmon 1 execution events since boot (24-hour fallback). This needs available logs and existing access permissions. The scanner never enables auditing or requests elevation. Reports retain executable basenames, times, source and current path availability, without usernames or command lines. A path currently missing does not prove deletion or cleaning.

The report workbench separates overview, integrity, FiveM modules, execution timeline, boot facts, PE timestamps, recording-tool filenames and collection coverage. Recording-tool names are observations only. Cleaning is **not assessed**. External cheater databases are **not connected**, and the analyst summary is deterministic counts, not an AI verdict. Unavailable sources remain explicitly unavailable. Windows collectors have been cross-compiled but still require runtime testing on Windows.

## Signature format and meaning

```json
[
  {
    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "name": "Harmless hello test fixture — not a cheat",
    "source": "Five UTF-8 bytes: hello; demonstration only",
    "category": "test"
  }
]
```

Supported categories: `review` (default for legacy entries), `cheat` (a staff claim requiring an evidence reference), `allowed`, and `test`. Tests and allowlisted matches are not counted as cheat review matches. Sources are retained as provenance metadata, not independently verified. Duplicate hashes and malformed entries are rejected. Browser imports support 50,000 entries / 5 MB; saved libraries and remote sessions support 5,000 entries. Each file is limited to 200 MB and each scan to 1,000 entries. Access failures and truncation limit coverage and are shown explicitly.

No verified FiveM cheat feed is bundled. A matching hash establishes equality with a staff-provided signature; it does not prove the player cheated. No exact match or an empty library does not establish a clean PC. Renamed binaries with identical contents still match; modified binaries evade exact hash matching. Reports are self-reported and not attested; a modified client can fabricate evidence. This is not equivalent to commercial Ocean/NAPS detection, a whole-PC scan, or a process-memory anti-cheat. Do not use it for automatic bans.

## Build and checks

```sh
npm ci # development checks and rebuilding the bundled QR only
npm test
npm run test:scanner
npm run build:scanner
# Optional Linux browser integration check (requires Chromium):
npm run test:browser
python scripts/package-project.py
```

Go 1.24+ is needed to build or test the scanner. `GO_BIN` selects a toolchain; this cloud checkout also detects `/workspace/.tools/go/bin/go`. Builds require no external Go modules. Output: `dist/crimson-pc-check-windows-amd64.exe`, `dist/checksums.txt`, and `dist/crimson-pc-check.zip`. The ZIP contains the source, supplied logo, base Windows binary, checksums and launchers; it excludes local credentials and reports.

`npm run test:browser` starts isolated staff and local scanner servers, uses headless Chromium, exercises consent, collection, sharing, persistent signatures, re-analysis and downloads, and saves screenshots in ignored `.test-artifacts/`. Set `CHROMIUM_BIN` if Chromium is not on PATH. It does not validate Windows-specific APIs.

The Windows build is unsigned. Follow your Windows security policy; do not disable antivirus or bypass platform warnings. Its base checksum identifies the build, not its publisher. Core hashing, consent/transport logic and the browser wizard can be tested on Linux. The v2 guided browser flow was exercised by the user on Windows. The new v3 module, signature-trust and system/event collectors still need runtime testing on real Windows; cross-compilation is not runtime validation. The optional legacy PowerShell folder scanner is retained and has not been runtime-tested here.

## Hosting and storage

Defaults: `HOST=127.0.0.1`, `PORT=3000`. For intentional remote hosting use an HTTPS reverse proxy and set `HOST=0.0.0.0` and `PUBLIC_URL=https://your-check-domain.example`. `PUBLIC_URL` supplies public invitation links and the staff address embedded in personalized EXEs. Local sessions fall back to the current site origin. Clients require HTTPS for non-loopback staff servers. Never disable TLS verification. No live public deployment is included. Docker/Caddy configuration is supplied in `HOSTING.md`; it needs your real DNS hostname and VPS configuration.

`SENTINEL_DATA_DIR` changes the private storage directory. Run one server process; JSON persistence is not designed for concurrent replicas. Reports, session-scoped upload tokens and auth metadata live in `.sentinel/` with restrictive permissions. Completed sessions are pruned after 24 hours when creating new sessions. Expiry controls report submission, not immediate deletion. Authenticated staff can read stored reports. A code is a private invitation, not verified player identity. Library saves use optimistic revision checks to avoid overwriting another edit.

Not included: a verified cheat-signature feed, signed/attested Windows clients, staff roles, production database/migrations, deployment or established detection accuracy against actual FiveM cheats. Independent tool; not affiliated with Ocean, NAPS, Cfx.re or Rockstar Games.
