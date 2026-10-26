import QRCode from './vendor/qr.js';

let current = null, downloadScanner = null, readSession = null;
const $ = id => document.getElementById(id);
function showMessage(message) { $('invite-message').textContent = message; }
async function copy(text) {
  try { await navigator.clipboard.writeText(text); showMessage('Copied. Share the invitation privately with the intended player.'); }
  catch { showMessage('Clipboard access unavailable. Select and copy the displayed value manually.'); }
}
export function refreshInvite(session) {
  if (!$('invite-dialog')?.open || current?.id !== session.id) return;
  current = session;
  const expired = Date.now() >= session.expiresAt, state = session.report ? 'Report received' : expired ? 'Expired' : session.redeemed ? 'Scan started · awaiting report' : 'Pending';
  $('invite-pin').textContent = session.code;
  $('invite-status').textContent = state;
  $('invite-expiry').textContent = 'Available until ' + new Date(session.expiresAt).toLocaleString() + ' · one report per session.';
  $('invite-progress').max = 100;
  if (session.report) $('invite-progress').value = 100; else if (session.redeemed && !expired) $('invite-progress').removeAttribute('value'); else $('invite-progress').value = 0;
  $('invite-percentage').textContent = session.report ? '100% · report received' : session.redeemed && !expired ? 'Progress not reported by client' : expired ? 'Expired' : 'Not started';
  const shareable = !!session.inviteUrl && !expired;
  $('invite-url').value = shareable ? session.inviteUrl : '';
  $('invite-url').placeholder = 'Configure a public HTTPS address to enable sharing';
  for (const id of ['invite-copy-link', 'invite-copy-link-small', 'invite-download-qr', 'invite-copy-qr']) $(id).disabled = !shareable;
  $('invite-qr').hidden = !shareable; $('invite-qr-placeholder').hidden = shareable;
  $('invite-hosting').hidden = !!session.sharingEnabled;
  $('invite-preview').href = session.inviteUrl || (location.origin + session.invitePath);
  $('invite-preview').textContent = session.inviteUrl ? 'Open player page ↗' : 'Preview locally on this PC ↗';
  $('invite-windows').disabled = expired || session.redeemed;
  if (shareable) QRCode.toCanvas($('invite-qr'), session.inviteUrl, { width: 160, margin: 3, errorCorrectionLevel: 'M', color: { dark: '#100c10', light: '#ffffff' } }).catch(() => showMessage('QR generation failed. The invitation URL can still be copied.'));
}
export function openInvite(session, handlers) {
  current = session; downloadScanner = handlers.download; readSession = handlers.read;
  $('invite-dialog').showModal(); showMessage(''); refreshInvite(session);
}
export function setupInvites() {
  const close = () => $('invite-dialog').close();
  $('invite-close').addEventListener('click', close); $('invite-close-bottom').addEventListener('click', close);
  $('invite-dialog').addEventListener('click', event => { if (event.target === $('invite-dialog')) { const bounds = $('invite-dialog').getBoundingClientRect(); if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) close(); } });
  $('invite-copy-pin').addEventListener('click', () => copy(current.code));
  for (const id of ['invite-copy-link', 'invite-copy-link-small']) $(id).addEventListener('click', () => { if (current?.inviteUrl) copy(current.inviteUrl); });
  $('invite-windows').addEventListener('click', () => { if (current) downloadScanner(current, $('invite-windows')); });
  $('invite-download-qr').addEventListener('click', () => {
    if (!current?.inviteUrl) return;
    $('invite-qr').toBlob(blob => { if (!blob) return; const url = URL.createObjectURL(blob), anchor = document.createElement('a'); anchor.href = url; anchor.download = `crimson-invite-${current.code}.png`; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 3000); });
  });
  $('invite-copy-qr').addEventListener('click', () => {
    if (!current?.inviteUrl || !globalThis.ClipboardItem) { showMessage('Image clipboard not supported. Use Download QR.'); return; }
    $('invite-qr').toBlob(async blob => { try { await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]); showMessage('QR image copied.'); } catch { showMessage('Image copy unavailable. Use Download QR.'); } });
  });
  setInterval(async () => { if (!$('invite-dialog').open || !current || !readSession) return; try { refreshInvite(await readSession(current.id)); } catch (error) { showMessage(error.message); } }, 10000);
}
