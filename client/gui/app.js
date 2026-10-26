const $=id=>document.getElementById(id), token=new URL(location.href).searchParams.get('token');
let currentPhase='idle',polling=false,closed=false;
async function api(path,body){const response=await fetch('/api/'+path,{method:body===undefined?'GET':'POST',headers:{'X-Crimson-Token':token,...(body===undefined?{}:{'Content-Type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)})});const data=await response.json();if(!response.ok)throw new Error(data.error||'Action impossible');return data;}
function message(text){$('message').textContent=text;}
async function state(){if(polling||closed)return;polling=true;try{render(await api('status'));}catch(error){if(closed)return;message('Scanner local inaccessible. Relancez l’application si vous avez fermé sa fenêtre.');}finally{polling=false;}}
function render(data){if(closed)return;currentPhase=data.phase;const busy=['connecting','scanning','sharing'].includes(data.phase),reportReady=!!data.report;
 $('scan-form').hidden=busy||reportReady;$('progress-card').hidden=!busy;$('report-card').hidden=!reportReady||busy;
 document.body.classList.toggle('is-scanning',busy);
 $('progress-text').textContent=data.message;$('progress-count').textContent=data.count+' fichiers';message(busy?'':data.message);
 $('cancel').hidden=data.phase==='sharing';
 for(const n of [1,2,3])$('step-'+n).classList.toggle('active',n===(reportReady?3:busy?2:1));
 if(reportReady&&!busy){const report=data.report;$('file-count').textContent=report.results.length;$('hash-count').textContent=report.results.filter(file=>file.sha256).length;$('coverage').textContent=report.coverageLimited?'Limitée':'Sélection';$('rows').replaceChildren();
  for(const file of report.results){const row=document.createElement('tr');for(const text of [file.name,file.origin==='loaded-module'?'DLL FiveM':file.origin==='running-process'?'Programme en cours':'Dossier choisi',file.sha256||file.reason||'Non lu']){const cell=document.createElement('td');cell.textContent=text;row.append(cell);}if(file.path){const path=document.createElement('small');path.className='file-location';path.textContent=file.path;row.firstChild.append(path);}$('rows').append(row);}
  $('profile-preview').replaceChildren();for(const profile of report.evidence?.accounts||[]){const line=document.createElement('p');line.className='profile-preview';line.textContent=profile.platform.toUpperCase()+' · '+profile.name+' · '+profile.id+' · '+(profile.source==='player-provided'?'fourni par le joueur':'profil local mémorisé')+' · non vérifié';$('profile-preview').append(line);}
  $('report-path').textContent='Copie locale : '+data.reportPath;$('share-controls').hidden=data.phase==='submitted';$('sent').hidden=data.phase!=='submitted';$('share').disabled=!$('share-consent').checked;
 }
 if(!['idle','ready','submitted','error'].includes(data.phase))setTimeout(state,700);
}
$('scan-form').addEventListener('submit',async event=>{event.preventDefault();$('start').disabled=true;message('');try{await api('scan',{server:$('server').value.trim(),code:$('code').value.trim(),folder:$('folder').value.trim(),discovery:$('discovery').checked,paths:$('paths').checked,accounts:$('accounts').checked,discordId:$('accounts').checked?$('discord-id').value.trim():'',processes:$('processes').checked,modules:$('modules').checked,integrity:$('integrity').checked,boot:$('boot').checked,activity:$('activity').checked,consent:$('consent').checked});$('share-server').textContent=$('server').value.trim();await state();setTimeout(state,800);}catch(error){message(error.message);}finally{$('start').disabled=false;}});
$('pick-folder').addEventListener('click',async()=>{$('pick-folder').disabled=true;try{const data=await api('folder',{});if(data.folder)$('folder').value=data.folder;}catch(error){message(error.message);}finally{$('pick-folder').disabled=false;}});
$('share-consent').addEventListener('change',()=>{$('share').disabled=!$('share-consent').checked;});
$('share').addEventListener('click',async()=>{$('share').disabled=true;try{const pending=api('share',{consent:$('share-consent').checked});await state();await pending;await state();}catch(error){message(error.message);await state();}});
$('cancel').addEventListener('click',async()=>{try{await api('cancel',{});await state();}catch(error){message(error.message);}});
$('quit').addEventListener('click',async()=>{try{await api('quit',{});closed=true;$('scan-form').hidden=true;$('progress-card').hidden=true;$('report-card').hidden=true;$('quit').disabled=true;message('Scanner fermé. Vous pouvez fermer cet onglet.');}catch(error){message(error.message);}});
async function init(){try{const config=await api('config');$('server').value=config.server||'http://localhost:3000';$('code').value=config.code||'';$('share-server').textContent=$('server').value;$('scan-roots').replaceChildren();for(const root of config.roots||[]){const li=document.createElement('li');li.textContent=root.label+' · '+root.path;$('scan-roots').append(li);}if(!config.roots?.length){const li=document.createElement('li');li.textContent='Aucun emplacement standard accessible détecté. Choisissez un dossier.';$('scan-roots').append(li);}await state();}catch(error){message(error.message);}}
init();

$('standard-profile').addEventListener('click',()=>{for(const id of ['discovery','processes','modules','integrity','boot'])$(id).checked=true;message('Profil standard sélectionné : recherche automatique et programmes en cours. Chemins, profils et événements restent des choix séparés.');});

$('code').addEventListener('input',()=>{$('code').value=$('code').value.toUpperCase();});

$('accounts').addEventListener('change',()=>{$('discord-id').disabled=!$('accounts').checked;});
setInterval(state,10000);
