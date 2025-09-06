function getCookie(name){ const m = document.cookie.match(new RegExp('(^| )'+name+'=([^;]+)')); return m?decodeURIComponent(m[2]):''; }
async function reload(){
  const uid = document.getElementById('f_uid').value.trim();
  const cid = document.getElementById('f_cid').value.trim();
  let url = '/admin/api/consents';
  const qs = [];
  if(uid) qs.push('user_id='+encodeURIComponent(uid));
  if(cid) qs.push('client_id='+encodeURIComponent(cid));
  if(qs.length>0) url += '?' + qs.join('&');
  const r = await fetch(url, {headers:{'X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin'}); const j = await r.json();
  if(j.code!==0){document.getElementById('list').innerText='load failed';return}
  const rows = j.data.map(function(x){return '<tr><td>'+x.id+'</td><td>'+x.user_id+'</td><td>'+x.client_id+'</td><td>'+x.scopes+'</td><td><button data-id="'+x.id+'" class="layui-btn layui-btn-danger layui-btn-xs btn-del">Delete</button></td></tr>';}).join('');
  document.getElementById('list').innerHTML = '<table class="layui-table"><thead><tr><th>ID</th><th>User</th><th>Client</th><th>Scopes</th><th>Op</th></tr></thead><tbody>'+rows+'</tbody></table>';
}
async function del(id){ const r = await fetch('/admin/api/consents/'+id,{method:'DELETE', headers:{'X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin'}); const j = await r.json(); if(j.code===0){ reload() } else { alert(j.message) } }

document.addEventListener('DOMContentLoaded', function(){
  const btn = document.getElementById('btnSearch'); if(btn){ btn.addEventListener('click', function(){ reload(); }); }
  const list = document.getElementById('list');
  list.addEventListener('click', function(e){
    const t = e.target; if(t && t.classList.contains('btn-del')){ const id = t.getAttribute('data-id'); del(id); }
  });
  reload();
});
