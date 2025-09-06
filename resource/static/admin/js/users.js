function getCookie(name){ const m = document.cookie.match(new RegExp('(^| )'+name+'=([^;]+)')); return m?decodeURIComponent(m[2]):''; }
async function reload(){
  const r = await fetch('/admin/api/users', {headers:{'X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin'}); const j = await r.json();
  if(j.code!==0){document.getElementById('list').innerText='load failed';return}
  window.__USERS__ = j.data.reduce((m,x)=>{m[x.id]=x; return m;}, {});
  const rows = j.data.map(function(x){
    const ev = x.email_verified? 'true':'false';
    return '<tr><td>'+x.id+'</td><td>'+x.username+'</td><td>'+(x.email||'')+'</td><td>'+ev+'</td>'+
           '<td><button class="layui-btn layui-btn-xs btn-toggle-ev" data-id="'+x.id+'">Toggle Verify</button></td></tr>';
  }).join('');
  document.getElementById('list').innerHTML = '<table class="layui-table"><thead><tr><th>ID</th><th>Username</th><th>Email</th><th>Email Verified</th><th>Op</th></tr></thead><tbody>'+rows+'</tbody></table>';
}
async function createU(){
  const f = document.getElementById('createUser');
  const body = { username:f.username.value, password:f.password.value, email:f.email.value };
  const r = await fetch('/admin/api/users',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin', body: JSON.stringify(body)});
  const j = await r.json(); if(j.code===0){ reload(); } else { alert(j.message) }
}
async function setPw(){
  const f = document.getElementById('pwForm');
  const id = f.id.value; const body = {password:f.password.value};
  const r = await fetch('/admin/api/users/'+id+'/password',{method:'PATCH', headers:{'Content-Type':'application/json','X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin', body: JSON.stringify(body)});
  const j = await r.json(); if(j.code===0){ alert('Password updated'); } else { alert(j.message) }
}
async function setEmail(){
  const f = document.getElementById('emailForm');
  const id = f.id.value; const body = {email:f.email.value, email_verified: f.verified.checked};
  const r = await fetch('/admin/api/users/'+id+'/email',{method:'PATCH', headers:{'Content-Type':'application/json','X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin', body: JSON.stringify(body)});
  const j = await r.json(); if(j.code===0){ reload(); } else { alert(j.message) }
}
async function toggleEV(id){
  const u = (window.__USERS__||{})[id]; if(!u) return; const body = { email: u.email||'', email_verified: !u.email_verified };
  const r = await fetch('/admin/api/users/'+id+'/email',{method:'PATCH', headers:{'Content-Type':'application/json','X-CSRF-Token': getCookie('csrf_token')}, credentials:'same-origin', body: JSON.stringify(body)});
  const j = await r.json(); if(j.code===0){ reload(); } else { alert(j.message) }
}
document.addEventListener('DOMContentLoaded', function(){
  const btnCreate=document.getElementById('btnCreateUser'); if(btnCreate) btnCreate.addEventListener('click', createU);
  const btnSetPw=document.getElementById('btnSetPw'); if(btnSetPw) btnSetPw.addEventListener('click', setPw);
  const btnSetEmail=document.getElementById('btnSetEmail'); if(btnSetEmail) btnSetEmail.addEventListener('click', setEmail);
  const list=document.getElementById('list'); list.addEventListener('click', function(e){ const t=e.target; if(t && t.classList.contains('btn-toggle-ev')){ const id=t.getAttribute('data-id'); toggleEV(id); }});
  reload();
});
