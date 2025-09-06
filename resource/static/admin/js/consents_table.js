function getCookie(name){ const m=document.cookie.match(new RegExp('(^| )'+name+'=([^;]+)')); return m?decodeURIComponent(m[2]):''; }
document.addEventListener('DOMContentLoaded', function(){
  layui.use(['table','layer'], function(){
    const table=layui.table, layer=layui.layer;
    const render=()=>{
      const uid=(document.getElementById('c_uid')||{value:''}).value;
      const cid=(document.getElementById('c_cid')||{value:''}).value;
      table.render({
        elem:'#tblConsents', id:'consentsTable', url:'/admin/api/consents/table',
        headers:{'X-CSRF-Token':getCookie('csrf_token')}, where:{user_id:uid, client_id:cid},
        request:{pageName:'page',limitName:'limit'},
        parseData:res=>({code:res.code,msg:res.msg||res.message||'',count:res.count||0,data:res.data||[]}),
        toolbar:'#toolbarConsents', defaultToolbar:['filter','exports','print'], height:'full-220',
        page:true, limit:10, cellMinWidth:120, size:'sm', even:true,
        cols:[[ {field:'id',title:'ID',width:80,sort:true},
                {field:'user_id',title:'User',width:120},
                {field:'client_id',title:'Client',minWidth:160},
                {field:'scopes',title:'Scopes',minWidth:260},
                {title:'Op',width:120,align:'center',templet:d=>`<button class=\"layui-btn layui-btn-danger layui-btn-xs\" data-op=\"del\" data-id=\"${d.id}\">Delete</button>`}
        ]]
      });
    };
    render();
    table.on('toolbar(consentsTable)', obj=>{ if(obj.event==='search') render(); });
    document.body.addEventListener('click', async (e)=>{
      const b=e.target.closest('button'); if(!b) return; if(b.getAttribute('data-op')!=='del') return; const id=b.getAttribute('data-id');
      layer.confirm('Delete consent '+id+'?', async function(idx){
        const r=await fetch('/admin/api/consents/'+id,{method:'DELETE',headers:{'X-CSRF-Token':getCookie('csrf_token')},credentials:'same-origin'}).then(r=>r.json());
        if(r.code===0){ layer.msg('Deleted'); render(); } else { layer.msg(r.message||'failed'); }
        layer.close(idx);
      });
    });
  });
});

