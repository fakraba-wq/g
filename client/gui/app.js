const $=id=>document.getElementById(id), token=new URL(location.href).searchParams.get('token');
let currentPhase='idle',polling=false,closed=false;
async function api(path,body){const response=await fetch('/api/'+path,{method:body===undefined?'GET':'POST',headers:{'X-Crimson-Token':token,...(body===undefined?{}:{'Content-Type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)})});const data=await response.json();if(!response.ok)throw new Error(data.error||'Action impossible');return data;}
function message(text){$('message').textContent=text;}
async function state(){if(polling||closed)return;polling=true;try{render(await api('status'));}catch(error){if(closed)return;message('Scanner local inaccessible. Relancez l’application si vous avez fermé sa fenêtre.');}finally{polling=false;}}
function render(data){if(closed)return;currentPhase=data.phase;const busy=['connecting','scanning','sharing'].includes(data.phase),reportReady=!!data.report;
 $('scan-form').hidden=busy||reportReady;$('progress-card').hidden=!busy;$('report-card').hidden=!reportReady||busy;
 $('progress-text').textContent=data.message;$('progress-count').textContent=data.count+' fichiers';message(busy?'':data.message);
 $('cancel').hidden=data.phase==='sharing';
 for(const n of [1,2,3])$('step-'+n).classList.toggle('active',n===(reportReady?3:busy?2:1));
 if(reportReady&&!busy){const report=data.report;$('file-count').textContent=report.results.length;$('hash-count').textContent=report.results.filter(file=>file.sha256).length;$('coverage').textContent=report.coverageLimited?'Limitée':'Sélection';$('rows').replaceChildren();
  for(const file of report.results){const row=document.createElement('tr');for(const text of [file.name,file.origin==='loaded-module'?'DLL FiveM':file.origin==='running-process'?'Programme en cours':'Dossier choisi',file.sha256||file.reason||'Non lu']){const cell=document.createElement('td');cell.textContent=text;row.append(cell);}$('rows').append(row);}
  $('report-path').textContent='Copie locale : '+data.reportPath;$('share-controls').hidden=data.phase==='submitted';$('sent').hidden=data.phase!=='submitted';$('share').disabled=!$('share-consent').checked;
 }
 if(!['idle','ready','submitted','error'].includes(data.phase))setTimeout(state,700);
}
$('scan-form').addEventListener('submit',async event=>{event.preventDefault();$('start').disabled=true;message('');try{await api('scan',{server:$('server').value.trim(),code:$('code').value.trim(),folder:$('folder').value.trim(),processes:$('processes').checked,modules:$('modules').checked,integrity:$('integrity').checked,boot:$('boot').checked,activity:$('activity').checked,consent:$('consent').checked});$('share-server').textContent=$('server').value.trim();await state();setTimeout(state,800);}catch(error){message(error.message);}finally{$('start').disabled=false;}});
$('pick-folder').addEventListener('click',async()=>{$('pick-folder').disabled=true;try{const data=await api('folder',{});if(data.folder)$('folder').value=data.folder;}catch(error){message(error.message);}finally{$('pick-folder').disabled=false;}});
$('share-consent').addEventListener('change',()=>{$('share').disabled=!$('share-consent').checked;});
$('share').addEventListener('click',async()=>{$('share').disabled=true;try{const pending=api('share',{consent:$('share-consent').checked});await state();await pending;await state();}catch(error){message(error.message);await state();}});
$('cancel').addEventListener('click',async()=>{try{await api('cancel',{});await state();}catch(error){message(error.message);}});
$('quit').addEventListener('click',async()=>{try{await api('quit',{});closed=true;$('scan-form').hidden=true;$('progress-card').hidden=true;$('report-card').hidden=true;$('quit').disabled=true;message('Scanner fermé. Vous pouvez fermer cet onglet.');}catch(error){message(error.message);}});
async function init(){try{const config=await api('config');$('server').value=config.server||'http://localhost:3000';$('code').value=config.code||'';$('share-server').textContent=$('server').value;await state();}catch(error){message(error.message);}}
init();

$('standard-profile').addEventListener('click',()=>{for(const id of ['processes','modules','integrity','boot'])$(id).checked=true;message('Profil standard sélectionné. Les événements d’exécution restent un choix séparé.');});

$('code').addEventListener('input',()=>{$('code').value=$('code').value.toUpperCase();});
