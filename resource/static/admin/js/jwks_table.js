function getCookie(name){ const m=document.cookie.match(new RegExp('(^| )'+name+'=([^;]+)')); return m?decodeURIComponent(m[2]):''; }
document.addEventListener('DOMContentLoaded', function(){
  layui.use(['table','layer'], function(){
    const table=layui.table, layer=layui.layer;
    const render=()=>{
      table.render({
        elem:'#tblJWKS', id:'jwksTable', url:'/admin/api/jwks',
        headers:{'X-CSRF-Token':getCookie('csrf_token')},
        parseData:res=>({code:res.code||0,msg:res.message||'',count:(res.data||[]).length,data:res.data||[]}),
        toolbar:'#toolbarJWKS', defaultToolbar:['filter','exports','print'], height:'full-220',
        page:false, cellMinWidth:120, size:'sm', even:true,
        cols:[[ {field:'kid',title:'KID',minWidth:260},
                {field:'alg',title:'ALG',width:100,align:'center'},
                {field:'status',title:'Status',width:120,align:'center'}
        ]]
      });
    };
    render();
    table.on('toolbar(jwksTable)', async function(obj){
      let alg=''; if(obj.event==='rotALL') alg='ALL'; if(obj.event==='rotRS') alg='RS256'; if(obj.event==='rotES') alg='ES256';
      if(!alg) return; const r=await fetch('/admin/api/jwks/rotate?alg='+alg,{method:'POST',headers:{'X-CSRF-Token':getCookie('csrf_token')},credentials:'same-origin'}).then(r=>r.json()); if(r.code===0){ layer.msg('Rotated'); render(); } else { layer.msg(r.message||'failed'); }
    });
  });
});

