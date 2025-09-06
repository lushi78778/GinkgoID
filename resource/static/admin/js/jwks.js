function getCookie(name){ const m = document.cookie.match(new RegExp('(^| )'+name+'=([^;]+)')); return m?decodeURIComponent(m[2]):''; }
async function reload(){
  const r = await fetch('/admin/api/jwks', {headers:{'X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin'}); const j = await r.json();
  if(j.code!==0){document.getElementById('list').innerText='load failed';return}
  const rows = j.data.map(function(x){return '<tr><td>'+x.kid+'</td><td>'+x.alg+'</td><td>'+x.status+'</td></tr>';}).join('');
  document.getElementById('list').innerHTML = '<table class="layui-table"><thead><tr><th>KID</th><th>ALG</th><th>Status</th></tr></thead><tbody>'+rows+'</tbody></table>';
}
async function rot(alg){ const r = await fetch('/admin/api/jwks/rotate?alg='+alg,{method:'POST', headers:{'X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin'}); const j = await r.json(); if(j.code===0){ reload() } else { alert(j.message) } }
document.addEventListener('DOMContentLoaded', function(){
  const a=document.getElementById('btnRotAll'), r=document.getElementById('btnRotRS'), e=document.getElementById('btnRotES');
  if(a) a.addEventListener('click', ()=>rot('ALL'));
  if(r) r.addEventListener('click', ()=>rot('RS256'));
  if(e) e.addEventListener('click', ()=>rot('ES256'));
  reload();
});
