function getCookie(name){ const m = document.cookie.match(new RegExp('(^| )'+name+'=([^;]+)')); return m?decodeURIComponent(m[2]):''; }
async function reload(){
  const r = await fetch('/admin/api/clients', {headers:{'X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin'}); const j = await r.json();
  if(j.code!==0){document.getElementById('list').innerText='load failed';return}
  const rows = j.data.map(function(x){return '<tr data-cid="'+x.client_id+'"><td>'+(x.client_id||'')+'</td><td>'+(x.name||'')+'</td><td>'+(x.status||'')+'</td></tr>';}).join('');
  document.getElementById('list').innerHTML = '<table class="layui-table"><thead><tr><th>ID</th><th>Name</th><th>Status</th></tr></thead><tbody>'+rows+'</tbody></table>';
  window.__CLIENTS__ = j.data.reduce((m,x)=>{m[x.client_id]=x; return m;}, {});
}
async function createCli(){
  const f = document.getElementById('createForm');
  let ruris=[], scopes=[];
  try { ruris = JSON.parse(f.redirect_uris.value||'[]'); } catch(e){ alert('RedirectURIs JSON invalid'); return }
  try { scopes = JSON.parse(f.scopes.value||'[]'); } catch(e){ alert('Scopes JSON invalid'); return }
  const body = { client_id: f.client_id.value, name: f.name.value, redirect_uris: ruris, scopes: scopes };
  const r = await fetch('/admin/api/clients',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin', body: JSON.stringify(body)});
  const j = await r.json(); if(j.code===0){ reload(); } else { alert(j.message) }
}
async function setStatus(){
  const f = document.getElementById('statusForm');
  const cid = f.client_id.value; const st = parseInt(f.status.value||'0');
  const r = await fetch('/admin/api/clients/'+cid+'/status',{method:'PATCH', headers:{'Content-Type':'application/json','X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin', body: JSON.stringify({status:st})});
  const j = await r.json(); if(j.code===0){ reload() } else { alert(j.message) }
}
async function updateCli(){
  const f = document.getElementById('editForm');
  const cid = f.client_id.value; let body = {};
  if(f.name.value) body.name = f.name.value;
  if(f.redirect_uris.value) { try{ body.redirect_uris = JSON.parse(f.redirect_uris.value);}catch(e){ alert('RedirectURIs JSON invalid'); return } }
  if(f.post_logout_uris.value) { try{ body.post_logout_uris = JSON.parse(f.post_logout_uris.value);}catch(e){ alert('PostLogoutURIs JSON invalid'); return } }
  if(f.scopes.value) { try{ body.scopes = JSON.parse(f.scopes.value);}catch(e){ alert('Scopes JSON invalid'); return } }
  const r = await fetch('/admin/api/clients/'+cid,{method:'PUT', headers:{'Content-Type':'application/json','X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin', body: JSON.stringify(body)});
  const j = await r.json(); if(j.code===0){ reload() } else { alert(j.message) }
}
async function setSecret(){
  const f = document.getElementById('secretForm');
  const cid = f.client_id.value; const body = {secret: f.secret.value};
  const r = await fetch('/admin/api/clients/'+cid,{method:'PUT', headers:{'Content-Type':'application/json','X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin', body: JSON.stringify(body)});
  const j = await r.json(); if(j.code===0){ alert('Secret updated'); } else { alert(j.message) }
}
function prefill(cid){ const x = (window.__CLIENTS__||{})[cid]; if(!x) return; const f = document.getElementById('editForm'); f.client_id.value = x.client_id||''; f.name.value = x.name||''; f.redirect_uris.value = x.redirect_uris||'[]'; f.post_logout_uris.value = x.post_logout_uris||'[]'; f.scopes.value = x.scopes||'[]'; const sf = document.getElementById('statusForm'); sf.client_id.value = x.client_id||''; sf.status.value = x.status||''; const sec = document.getElementById('secretForm'); sec.client_id.value = x.client_id||''; }
document.addEventListener('DOMContentLoaded', function(){
  const list = document.getElementById('list');
  list.addEventListener('click', function(e){ const tr=e.target.closest('tr'); if(!tr) return; const cid=tr.getAttribute('data-cid'); if(cid) prefill(cid); });
  const btnCreate=document.getElementById('btnCreate'); if(btnCreate) btnCreate.addEventListener('click', createCli);
  const btnSetStatus=document.getElementById('btnSetStatus'); if(btnSetStatus) btnSetStatus.addEventListener('click', setStatus);
  const btnUpdate=document.getElementById('btnUpdate'); if(btnUpdate) btnUpdate.addEventListener('click', updateCli);
  const btnSetSecret=document.getElementById('btnSetSecret'); if(btnSetSecret) btnSetSecret.addEventListener('click', setSecret);
  reload();
});
