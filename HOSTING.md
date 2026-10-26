# Host Crimson PC Check on a VPS

The project name is **Crimson PC Check**. `PUBLIC_DOMAIN` must be an actual registered DNS hostname you control, such as `check.example.com`; the project name alone is not a domain. No VPS has been configured or public site deployed by this release.

## Linux VPS with Docker Compose

1. Install Docker Engine and its Compose plugin on your Linux VPS. Point your real hostname's DNS A record to the VPS public IPv4 address. Add an AAAA record only if IPv6 reaches this VPS. Allow inbound TCP 80 and 443; keep port 3000 private. Check that no other service occupies 80/443.
2. Clone this repository or copy the extracted project onto the VPS. The canonical `dist/crimson-pc-check.zip` from the repository is required by the container build. If using an extracted project, copy the downloaded ZIP into its `dist/` folder under that exact name.
3. Copy `.env.example` to a private `.env`. Fill in `PUBLIC_DOMAIN` with your actual DNS hostname, without `https://` or a path. Set `CRIMSON_ADMIN_PASSWORD` to a unique 12–256 character staff password. Do this privately on the VPS; never send the file or password in chat or commit it. Restrict file access with `chmod 600 .env`.
4. Run `docker compose up -d --build`. Caddy requests and renews a certificate for the configured domain. DNS and both ports must already work. The application runs as the unprivileged Node user; staff data and certificate state use persistent volumes.
5. Open `https://YOUR-ACTUAL-HOSTNAME`, sign in and create a session. Its Invitation dialog now offers the player link and QR. Test that link from a second device, download the Windows scanner, explicitly authorize a small test selection, review and send it, then verify that staff sees the actual report.

Check `docker compose logs --tail=100` if startup or TLS fails. Do not post logs containing private invitation URLs, PINs, tokens or secrets. `/health` returns only basic service health. The supplied recipe must still be validated on your VPS; it does not establish detection accuracy or guarantee deployment success.

## Existing HTTPS reverse proxy

Use Node.js 22+ and one server process. Prepare the Windows binary with `npm run prepare:hosted` if cloning from Git (it extracts only the binary/checksum from the packaged ZIP and verifies SHA-256). The downloaded source ZIP already includes the binary. This preparation is explicit and does not run automatically to restore a file removed by security software.

Set `PUBLIC_URL=https://YOUR-ACTUAL-HOSTNAME`, a private `SENTINEL_ADMIN_PASSWORD`, `SENTINEL_DATA_DIR` to a persistent private directory, and bind `HOST=127.0.0.1`, `PORT=3000` behind your local HTTPS proxy. For container networking the supplied image binds `0.0.0.0` internally; Compose does not publish that port. Forward to the application using your proxy and keep TLS verification enabled in clients.

## Data and updates

Back up private staff storage securely before upgrades. Docker stores it in the `crimson-data` volume; local installations use `.sentinel/`. Do not run `docker compose down -v` when preserving data. Do not share backups or put them in the public repository. A fresh Docker deployment starts with separate storage; it does not automatically migrate your Windows `.sentinel` directory.

Use one application instance: JSON persistence is not a shared database for replicas. Session expiry stops new submissions, not immediate deletion of existing reports. Existing retention prunes old sessions when new ones are created. Staff authentication is required for report access. Treat invitations and downloaded personalized EXEs as private bearer invitations. Rotate the staff password and invalidate sessions if private state is exposed.

The Windows scanner is unsigned. Follow Windows security policy. Linux downloads, external cheater-database providers, screenshot capture, private-account contents/session scraping and process-memory inspection are not implemented. A public link lets the player choose and authorize a check; it does not remotely scan their PC by itself.

V4 local invitations now support same-PC loopback downloads without a public domain; this does not make the site reachable on other PCs. Full paths and local Steam public profile identifiers remain explicit per-scan options. Discord IDs are player-provided, unverified, and no Discord OAuth application is configured.
