function getCookie(name){ const m=document.cookie.match(new RegExp('(^| )'+name+'=([^;]+)')); return m?decodeURIComponent(m[2]):''; }
document.addEventListener('DOMContentLoaded', function(){
  layui.use(['table','layer','form'], function(){
    const table = layui.table, layer=layui.layer;
    const render = ()=>{
      table.render({
        elem: '#tblClients',
        id: 'clientsTable',
        url: '/admin/api/clients/table',
        headers: {'X-CSRF-Token': getCookie('csrf_token')},
        where: { q: (document.getElementById('qInput')||document.getElementById('q')||{value:''}).value },
        request: { pageName: 'page', limitName: 'limit' },
        parseData: function(res){ return { code: res.code, msg: res.msg||res.message||'', count: res.count||0, data: res.data||[] }; },
        toolbar: '#toolbarClients',
        defaultToolbar: ['filter','exports','print'],
        height: 'full-220',
        page: true,
        limit: 10,
        cellMinWidth: 120,
        size: 'sm',
        even: true,
        cols: [[
          {field:'client_id', title:'ClientID', width:200},
          {field:'name', title:'Name', minWidth:220},
          {field:'status', title:'Status', width:80, align:'center'},
          {title:'Op', width:200, align:'center', templet: d=>`<button class="layui-btn layui-btn-xs" data-op="edit" data-id="${d.client_id}">Edit</button> <button class="layui-btn layui-btn-warm layui-btn-xs" data-op="toggle" data-id="${d.client_id}" data-status="${d.status}">${d.status==1?'Disable':'Enable'}</button>`}
        ]]
      });
    };

    render();

    // toolbar buttons inside table header
    table.on('toolbar(clientsTable)', function(obj){
      if(obj.event==='search'){ render(); }
      if(obj.event==='add'){ openEdit(); }
    });

    // delegate row ops
    document.body.addEventListener('click', async (e)=>{
      const t=e.target; if(!t.closest) return; const btn=t.closest('button'); if(!btn) return;
      const op=btn.getAttribute('data-op'); if(!op) return;
      const id=btn.getAttribute('data-id');
      if(op==='edit'){ openEdit(id); }
      if(op==='toggle'){
        const st=parseInt(btn.getAttribute('data-status')||'0');
        const nst = st===1?0:1;
        const ok = await fetch('/admin/api/clients/'+id+'/status', {method:'PATCH', headers:{'Content-Type':'application/json','X-CSRF-Token':getCookie('csrf_token')}, credentials:'same-origin', body: JSON.stringify({status:nst})}).then(r=>r.json());
        if(ok.code===0){ layer.msg('Updated'); render(); } else { layer.msg(ok.message||'failed'); }
      }
    });

    function openEdit(id){
      const isNew = !id;
      const title = isNew? 'Add Client' : 'Edit '+id;
      const formHtml = `
      <div style="padding:16px;">
        <div class="layui-form" id="editFrm">
          <div class="layui-form-item">
            <label class="layui-form-label">ClientID</label>
            <div class="layui-input-block"><input id="e_cid" class="layui-input" ${isNew?'':'disabled'} value="${id||''}"></div>
          </div>
          <div class="layui-form-item"><label class="layui-form-label">Name</label><div class="layui-input-block"><input id="e_name" class="layui-input"></div></div>
          <div class="layui-form-item"><label class="layui-form-label">RedirectURIs</label><div class="layui-input-block"><textarea id="e_ruris" class="layui-textarea" placeholder='["http://localhost:8081/callback"]'></textarea></div></div>
          <div class="layui-form-item"><label class="layui-form-label">PostLogoutURIs</label><div class="layui-input-block"><textarea id="e_pluris" class="layui-textarea" placeholder='[]'></textarea></div></div>
          <div class="layui-form-item"><label class="layui-form-label">Scopes</label><div class="layui-input-block"><textarea id="e_scopes" class="layui-textarea" placeholder='["openid","profile","email"]'></textarea></div></div>
        </div>
      </div>`;
      const idx = layer.open({title, type:1, area:['680px','560px'], content: formHtml, btn:['Save','Cancel'], yes: async function(){
          try{
            const cid = document.getElementById('e_cid').value.trim();
            const name = document.getElementById('e_name').value.trim();
            const ruris = JSON.parse(document.getElementById('e_ruris').value||'[]');
            const pluris = JSON.parse(document.getElementById('e_pluris').value||'[]');
            const scopes = JSON.parse(document.getElementById('e_scopes').value||'[]');
            let resp;
            if(isNew){
              resp = await fetch('/admin/api/clients',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':getCookie('csrf_token')}, credentials:'same-origin', body: JSON.stringify({client_id:cid,name,redirect_uris:ruris,post_logout_uris:pluris,scopes})}).then(r=>r.json());
            }else{
              resp = await fetch('/admin/api/clients/'+cid,{method:'PUT', headers:{'Content-Type':'application/json','X-CSRF-Token':getCookie('csrf_token')}, credentials:'same-origin', body: JSON.stringify({name,redirect_uris:ruris,post_logout_uris:pluris,scopes})}).then(r=>r.json());
            }
            if(resp.code===0){ layer.close(idx); layer.msg('Saved'); render(); } else { layer.msg(resp.message||'failed'); }
          }catch(e){ layer.msg('JSON invalid: '+e.message); }
      }});
      // prefill if edit: we can fetch one from table cache or call list API
      if(!isNew){
        fetch('/admin/api/clients', {headers:{'X-CSRF-Token':getCookie('csrf_token')}, credentials:'same-origin'}).then(r=>r.json()).then(j=>{
          if(j.code===0){
            const row = (j.data||[]).find(x=>x.client_id===id);
            if(row){
              document.getElementById('e_name').value = row.name||'';
              try{ document.getElementById('e_ruris').value = JSON.stringify(JSON.parse(row.redirect_uris||'[]'), null, 2);}catch(e){ document.getElementById('e_ruris').value = row.redirect_uris||'[]'; }
              try{ document.getElementById('e_pluris').value = JSON.stringify(JSON.parse(row.post_logout_uris||'[]'), null, 2);}catch(e){ document.getElementById('e_pluris').value = row.post_logout_uris||'[]'; }
              try{ document.getElementById('e_scopes').value = JSON.stringify(JSON.parse(row.scopes||'[]'), null, 2);}catch(e){ document.getElementById('e_scopes').value = row.scopes||'[]'; }
            }
          }
        });
      }
    }
  });
});
