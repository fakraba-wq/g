const token = location.pathname.split('/')[2], $ = id => document.getElementById(id);
let running = true;
async function refresh() {
  if (!running) return;
  try {
    const response = await fetch('/api/invites/' + token);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Invitation indisponible');
    const labels = { pending: 'Invitation prête', 'in-progress': 'Vérification démarrée', received: 'Rapport reçu par le staff' };
    $('player-status').textContent = labels[data.state] || data.state;
    $('player-expiry').textContent = 'Expiration : ' + new Date(data.expiresAt).toLocaleString();
    const available = data.state === 'pending' && (!data.localOnly || ['localhost','127.0.0.1','[::1]'].includes(location.hostname));
    $('player-download').classList.toggle('disabled-link', !available); $('player-download').setAttribute('aria-disabled', String(!available));
    if (available) $('player-download').href = location.pathname + '/scanner.exe'; else $('player-download').removeAttribute('href');
    $('player-message').textContent = data.localOnly ? 'Lien local : vous pouvez télécharger et vérifier ce PC. Ce lien ne fonctionne pas depuis un autre PC.' : data.state === 'received' ? 'Vous pouvez fermer cette page. Le rapport reste privé au staff.' : data.state === 'in-progress' ? 'Le PIN est déjà utilisé. Continuez dans le scanner qui a démarré cette vérification.' : 'Le scanner ouvre une fenêtre Crimson locale (ou le navigateur si aucun mode application n’est disponible).';
    if (data.state === 'received') running = false;
  } catch (error) { $('player-status').textContent = 'Invitation indisponible'; $('player-message').textContent = error.message; $('player-download').removeAttribute('href'); $('player-download').classList.add('disabled-link'); running = false; }
  if (running) setTimeout(refresh, 10000);
}
refresh();
