document.addEventListener('DOMContentLoaded', function(){
  if (window.layui) { layui.use('element', function(){ /* init nav */ }); }
  var frame = document.getElementById('mainFrame');
  document.querySelectorAll('.menu-link').forEach(function(a){
    a.addEventListener('click', function(e){ e.preventDefault(); var href = a.getAttribute('data-href'); if(href){ frame.setAttribute('src', href); } });
  });
});

