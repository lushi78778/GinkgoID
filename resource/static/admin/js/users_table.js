function getCookie(name){ const m=document.cookie.match(new RegExp('(^| )'+name+'=([^;]+)')); return m?decodeURIComponent(m[2]):''; }
document.addEventListener('DOMContentLoaded', function(){
  layui.use(['table','layer'], function(){
    const table = layui.table, layer=layui.layer;
    const render = ()=>{
      const kw = (document.getElementById('uqInput')||{value:''}).value;
      table.render({
        elem:'#tblUsers', id:'usersTable', url:'/admin/api/users/table',
        headers:{'X-CSRF-Token':getCookie('csrf_token')}, where:{q:kw},
        request:{pageName:'page',limitName:'limit'},
        parseData:res=>({code:res.code,msg:res.msg||res.message||'',count:res.count||0,data:res.data||[]}),
        toolbar:'#toolbarUsers', defaultToolbar:['filter','exports','print'], height:'full-220',
        page:true, limit:10, cellMinWidth:120, size:'sm', even:true,
        cols:[[ {field:'id',title:'ID',width:80,sort:true},
                {field:'username',title:'Username',minWidth:180},
                {field:'email',title:'Email',minWidth:220},
                {field:'email_verified',title:'Verified',width:100,align:'center', templet:d=>d.email_verified?'Yes':'No'},
                {field:'role',title:'Role',width:120,align:'center'},
                {title:'Op',width:320,align:'center',templet:d=>`<button class="layui-btn layui-btn-xs" data-op="passwd" data-id="${d.id}">Passwd</button> <button class="layui-btn layui-btn-normal layui-btn-xs" data-op="email" data-id="${d.id}">Email</button> <button class="layui-btn layui-btn-warm layui-btn-xs" data-op="role" data-id="${d.id}">Role</button> <button class="layui-btn layui-btn-danger layui-btn-xs" data-op="revoke" data-id="${d.id}">Kick</button>`}
        ]]
      });
    };
    render();
    table.on('toolbar(usersTable)', function(obj){ if(obj.event==='search') render(); if(obj.event==='add') openCreate(); });
    document.body.addEventListener('click', async (e)=>{
      const b=e.target.closest('button'); if(!b) return; const op=b.getAttribute('data-op'); const id=b.getAttribute('data-id');
      if(op==='passwd'){ openPasswd(id); }
      if(op==='email'){ openEmail(id); }
      if(op==='role'){ openRole(id); }
      if(op==='revoke'){ revokeAll(id); }
    });
    function openCreate(){
      const html=`<div style="padding:16px;"><div class="layui-form"><div class="layui-form-item"><label class="layui-form-label">Username</label><div class="layui-input-block"><input id="nu_user" class="layui-input"></div></div><div class="layui-form-item"><label class="layui-form-label">Password</label><div class="layui-input-block"><input id="nu_pass" class="layui-input"></div></div><div class="layui-form-item"><label class="layui-form-label">Email</label><div class="layui-input-block"><input id="nu_email" class="layui-input"></div></div><div class="layui-form-item"><label class="layui-form-label">Role</label><div class="layui-input-block"><select id="nu_role" class="layui-input"><option value="user">user</option><option value="operator">operator</option><option value="auditor">auditor</option><option value="admin">admin</option></select></div></div></div></div>`;
      const idx=layer.open({title:'Add User',type:1,area:['520px','420px'],content:html,btn:['Save','Cancel'],yes:async()=>{const body={username:nu_user.value,password:nu_pass.value,email:nu_email.value,role:document.getElementById('nu_role').value};const r=await fetch('/admin/api/users',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':getCookie('csrf_token')},credentials:'same-origin',body:JSON.stringify(body)}).then(r=>r.json()); if(r.code===0){layer.close(idx);layer.msg('Saved');render();}else{layer.msg(r.message||'failed');}}});
    }
    function openPasswd(id){
      const html=`<div style="padding:16px;"><div class="layui-form"><div class="layui-form-item"><label class="layui-form-label">New Password</label><div class="layui-input-block"><input id="pw_new" class="layui-input"></div></div></div></div>`;
      const idx=layer.open({title:'Set Password',type:1,area:['520px','240px'],content:html,btn:['Save','Cancel'],yes:async()=>{const body={password:pw_new.value};const r=await fetch('/admin/api/users/'+id+'/password',{method:'PATCH',headers:{'Content-Type':'application/json','X-CSRF-Token':getCookie('csrf_token')},credentials:'same-origin',body:JSON.stringify(body)}).then(r=>r.json()); if(r.code===0){layer.close(idx);layer.msg('Saved');render();}else{layer.msg(r.message||'failed');}}});
    }
    function openEmail(id){
      const html=`<div style="padding:16px;"><div class="layui-form"><div class="layui-form-item"><label class="layui-form-label">Email</label><div class="layui-input-block"><input id="em_val" class="layui-input"></div></div><div class="layui-form-item"><label class="layui-form-label">Verified</label><div class="layui-input-block"><input id="em_v" type="checkbox" lay-skin="primary"></div></div></div></div>`;
      const idx=layer.open({title:'Set Email',type:1,area:['520px','300px'],content:html,btn:['Save','Cancel'],yes:async()=>{const body={email:em_val.value,email_verified:document.getElementById('em_v').checked};const r=await fetch('/admin/api/users/'+id+'/email',{method:'PATCH',headers:{'Content-Type':'application/json','X-CSRF-Token':getCookie('csrf_token')},credentials:'same-origin',body:JSON.stringify(body)}).then(r=>r.json()); if(r.code===0){layer.close(idx);layer.msg('Saved');render();}else{layer.msg(r.message||'failed');}}});
    }
    function openRole(id){
      const html=`<div style="padding:16px;"><div class="layui-form"><div class="layui-form-item"><label class="layui-form-label">Role</label><div class="layui-input-block"><select id="role_val" class="layui-input"><option value="user">user</option><option value="operator">operator</option><option value="auditor">auditor</option><option value="admin">admin</option></select></div></div></div></div>`;
      const idx=layer.open({title:'Set Role',type:1,area:['520px','260px'],content:html,btn:['Save','Cancel'],yes:async()=>{const body={role:document.getElementById('role_val').value};const r=await fetch('/admin/api/users/'+id+'/role',{method:'PATCH',headers:{'Content-Type':'application/json','X-CSRF-Token':getCookie('csrf_token')},credentials:'same-origin',body:JSON.stringify(body)}).then(r=>r.json()); if(r.code===0){layer.close(idx);layer.msg('Saved');render();}else{layer.msg(r.message||'failed');}}});
    }
    async function revokeAll(id){
      const ok = await fetch('/admin/api/users/'+id+'/sessions/revoke_all',{method:'POST',headers:{'X-CSRF-Token':getCookie('csrf_token')},credentials:'same-origin'}).then(r=>r.json()); if(ok.code===0){ layer.msg('Revoked'); render(); } else { layer.msg(ok.message||'failed'); }
    }
  });
});
