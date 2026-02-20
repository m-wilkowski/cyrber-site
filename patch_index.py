#!/usr/bin/env python3
import re, os

path = os.path.expanduser('~/cyrber/static/index.html')
with open(path, 'r', encoding='utf-8') as f:
    html = f.read()

# 1. NAV - dodaj SCHEDULER
old_nav = '<a href="/dashboard"'
new_nav = '<a href="/scheduler" style="font-family:\'Share Tech Mono\',monospace;font-size:10px;letter-spacing:.2em;color:rgba(184,204,236,.6);text-decoration:none;padding:4px 10px;border:1px solid transparent;transition:all .2s" onmouseover="this.style.color=\'#4a8fd4\'" onmouseout="this.style.color=\'rgba(184,204,236,.6)\'">SCHEDULER</a>\n    <a href="/dashboard"'
html = html.replace(old_nav, new_nav, 1)

# 2. max-width
html = re.sub(r'max-width:\s*\d+px', 'max-width: 1280px', html, count=1)

# 3. CSS nowych sekcji
new_css = """
.res-section{background:rgba(12,18,32,.75);border:1px solid var(--border2);margin-bottom:10px;backdrop-filter:blur(6px)}
.res-section-hdr{display:flex;align-items:center;justify-content:space-between;padding:11px 20px;cursor:pointer;user-select:none;transition:background .15s}
.res-section-hdr:hover{background:rgba(74,143,212,.04)}
.res-section-hdr.open{border-bottom:1px solid var(--border2)}
.res-section-title{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:.3em;color:var(--accent)}
.res-section-arrow{font-size:11px;color:var(--silver);transition:transform .2s}
.res-section-hdr.open .res-section-arrow{transform:rotate(90deg)}
.res-section-body{padding:16px 20px;display:none}
.res-section-body.open{display:block}
.narr-text{font-size:14px;line-height:1.9;font-style:italic;color:var(--silver);border-left:3px solid var(--accent);padding-left:16px;margin-bottom:14px}
.narr-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px}
.nst{background:rgba(74,143,212,.06);border:1px solid var(--border2);padding:10px 14px}
.nst-lbl{font-family:'Share Tech Mono',monospace;font-size:8px;letter-spacing:.25em;color:rgba(184,204,236,.5);margin-bottom:4px}
.nst-val{font-size:13px;font-weight:600;color:var(--white)}
.nst-val.red{color:var(--red)}.nst-val.grn{color:var(--green)}
.exec-box{background:rgba(74,143,212,.05);border:1px solid var(--border2);padding:12px 16px;font-size:13px;line-height:1.7;color:var(--silver)}
.chain-blk{background:rgba(74,143,212,.04);border:1px solid rgba(74,143,212,.2);padding:14px 16px;margin-bottom:10px}
.chain-blk:last-child{margin-bottom:0}
.chain-hdr{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:5px}
.chain-nm{font-size:14px;font-weight:600;color:var(--white)}
.chain-badge{font-family:'Share Tech Mono',monospace;font-size:10px;font-weight:700}
.chain-meta{font-family:'Share Tech Mono',monospace;font-size:10px;color:rgba(184,204,236,.45);margin-bottom:10px}
.ch-step{padding:7px 0;border-bottom:1px solid rgba(74,143,212,.07)}
.ch-step:last-of-type{border-bottom:none}
.ch-sn{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:.2em;color:var(--accent)}
.ch-act{font-size:13px;color:var(--white);margin:2px 0}
.ch-vuln{font-family:'Share Tech Mono',monospace;font-size:10px;color:rgba(184,204,236,.45)}
.ch-res{font-size:11px;color:var(--green);margin-top:3px}
.chain-final{font-size:12px;color:var(--orange);margin-top:8px;font-weight:600}
.chain-biz{font-family:'Share Tech Mono',monospace;font-size:10px;color:rgba(184,204,236,.45);margin-top:4px}
.dt{width:100%;border-collapse:collapse;font-size:12px}
.dt th{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:.2em;color:var(--accent);text-align:left;padding:6px 10px;border-bottom:1px solid var(--border)}
.dt td{padding:7px 10px;border-bottom:1px solid rgba(74,143,212,.06);color:var(--silver)}
.dt td:first-child{color:var(--white);font-family:'Share Tech Mono',monospace}
.dt tr:hover td{background:rgba(74,143,212,.04)}
.sqli-box{display:flex;align-items:center;gap:16px;border:1px solid;padding:12px 16px}
.sqli-status{font-size:14px;font-weight:700;letter-spacing:.05em}
.fp-bar{display:flex;gap:14px;align-items:center;background:rgba(61,220,132,.06);border:1px solid rgba(61,220,132,.2);padding:7px 14px;font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--green);margin-bottom:10px}
"""
html = html.replace('</style>', new_css + '\n</style>', 1)

# 4. renderResults
old_r = r'function renderResults\(res, elapsed\).*?getElementById\(\'res\'\)\.scrollIntoView.*?\n\}'
new_r = '''function renderResults(res, elapsed) {
  var a = res.analysis || {};
  var risk = (a.risk_level || 'N/A');
  var riskKey = risk.toUpperCase()
    .replace(/Ą/g,'A').replace(/Ć/g,'C').replace(/Ę/g,'E').replace(/Ł/g,'L')
    .replace(/Ń/g,'N').replace(/Ó/g,'O').replace(/Ś/g,'S').replace(/Ź/g,'Z')
    .replace(/Ż/g,'Z').replace(/ą/g,'A').replace(/ć/g,'C').replace(/ę/g,'E')
    .replace(/ł/g,'L').replace(/ń/g,'N').replace(/ó/g,'O').replace(/ś/g,'S')
    .replace(/ź/g,'Z').replace(/ż/g,'Z');
  var rb = document.getElementById('rb');
  rb.textContent = risk;
  rb.className = 'risk-badge ' + riskKey;
  var metaEl = document.getElementById('meta') || document.getElementById('scanMeta');
  if(metaEl) metaEl.innerHTML = 'TARGET: '+res.target+'<br>FINDINGS: '+(res.findings_count||0)+(elapsed?'<br>TIME: '+elapsed+'s':'');
  document.getElementById('sum').textContent = a.summary || '—';
  var ul = document.getElementById('iss');
  ul.innerHTML = '';
  (a.top_issues||[]).forEach(function(iss,i){
    var li=document.createElement('li');
    li.innerHTML='<span class="inum">'+String(i+1).padStart(2,'0')+'</span><span>'+iss+'</span>';
    ul.appendChild(li);
  });
  var sevrow = document.getElementById('sevrow');
  sevrow.innerHTML = '';
  var findings = (res.nuclei&&res.nuclei.findings)||[];
  var sc={high:0,medium:0,low:0,info:0};
  findings.forEach(function(f){var s=(f.info&&f.info.severity)||'info';if(sc[s]!==undefined)sc[s]++;else sc.info++;});
  var hasAny=false;
  Object.keys(sc).forEach(function(s){if(sc[s]>0){hasAny=true;var sp=document.createElement('span');sp.className='sev '+s;sp.textContent=s.toUpperCase()+': '+sc[s];sevrow.appendChild(sp);}});
  if(!hasAny) sevrow.innerHTML='<span class="sev info">TOTAL: '+(res.findings_count||0)+'</span>';
  document.getElementById('rec').textContent = a.recommendations || '—';
  var pf=document.getElementById('pf');
  pf.classList.remove('sweep');pf.style.width='100%';
  setTimeout(function(){document.getElementById('pw').classList.remove('on');pf.style.width='0';},800);
  setSt('Reconnaissance complete · '+(res.findings_count||0)+' findings · Risk: '+risk,'done');
  if(window._lastTaskId){var pb=document.getElementById('pdfBtn');pb.href=API+'/scans/'+window._lastTaskId+'/pdf';pb.style.display='inline-block';}
  renderExtended(res);
  document.getElementById('res').classList.add('on');
  document.getElementById('scanBtn').disabled=false;
  document.getElementById('res').scrollIntoView({behavior:'smooth'});
}

function mkSec(title,content,open){
  return '<div class="res-section"><div class="res-section-hdr"'+(open?' data-open="1"':'')+'><div class="res-section-title">'+title+'</div><div class="res-section-arrow">›</div></div><div class="res-section-body'+(open?' open':'')+'">'+content+'</div></div>';
}

function renderExtended(res) {
  var ext=document.getElementById('extSections');
  if(!ext) return;
  var h='';
  if(res.fp_filter&&res.fp_filter.original_count>0)
    h+='<div class="fp-bar">FILTRACJA FP: '+res.fp_filter.filtered_count+' / '+res.fp_filter.original_count+' · usunięto '+res.fp_filter.removed+' fałszywych alarmów</div>';

  var nd=res.hacker_narrative||{};
  var narr=nd.narrative||res.narrative||'';
  if(narr){
    var nh='<div class="narr-text">'+narr.replace(/\\n/g,'<br>').replace(/\\*\\*/g,'')+'</div>';
    nh+='<div class="narr-stats">';
    if(nd.time_to_compromise) nh+='<div class="nst"><div class="nst-lbl">CZAS PRZEJĘCIA</div><div class="nst-val">'+nd.time_to_compromise+'</div></div>';
    if(nd.potential_loss)     nh+='<div class="nst"><div class="nst-lbl">POTENCJALNA STRATA</div><div class="nst-val red">'+nd.potential_loss+'</div></div>';
    if(nd.fix_cost)           nh+='<div class="nst"><div class="nst-lbl">KOSZT NAPRAWY</div><div class="nst-val grn">'+nd.fix_cost+'</div></div>';
    nh+='</div>';
    if(nd.executive_summary) nh+='<div class="exec-box">'+nd.executive_summary+'</div>';
    h+=mkSec('// PERSPEKTYWA HAKERA',nh,true);
  }

  var chains=(res.exploit_chains&&res.exploit_chains.chains)||[];
  if(chains.length){
    var IC={KRYTYCZNY:'#ff4444',WYSOKI:'#ff8c00',ŚREDNI:'#f5c518'};
    var ch='';
    chains.forEach(function(c){
      var col=IC[c.impact]||'#4a8fd4';
      ch+='<div class="chain-blk"><div class="chain-hdr"><span class="chain-nm">'+c.name+'</span><span class="chain-badge" style="color:'+col+'">'+c.impact+' · '+c.probability+'%</span></div>';
      ch+='<div class="chain-meta">Czas: '+c.total_time+' · Priorytet: '+c.remediation_priority+'</div>';
      (c.steps||[]).forEach(function(s){
        ch+='<div class="ch-step"><div class="ch-sn">KROK '+s.step+'</div><div class="ch-act">'+s.action+'</div><div class="ch-vuln">'+s.vulnerability+' · '+s.time+'</div><div class="ch-res">→ '+s.result+'</div></div>';
      });
      ch+='<div class="chain-final">Dostęp końcowy: '+c.final_access+'</div><div class="chain-biz">'+c.business_impact+'</div></div>';
    });
    h+=mkSec('// ŁAŃCUCHY EXPLOITÓW ('+chains.length+')',ch,true);
  }

  var ports=res.ports||[];
  if(ports.length){
    var pt='<table class="dt"><thead><tr><th>PORT</th><th>SERVICE</th><th>VERSION</th><th>STATE</th></tr></thead><tbody>';
    ports.forEach(function(p){pt+='<tr><td>'+p.port+'</td><td>'+p.service+'</td><td>'+(p.version||'—')+'</td><td>'+p.state+'</td></tr>';});
    h+=mkSec('// OTWARTE PORTY ('+ports.length+')',pt+'</tbody></table>',false);
  }

  var gf=(res.gobuster&&res.gobuster.findings)||[];
  if(gf.length){
    var gb='<table class="dt"><thead><tr><th>ŚCIEŻKA</th><th>STATUS</th><th>ROZMIAR</th></tr></thead><tbody>';
    gf.slice(0,30).forEach(function(f){gb+='<tr><td>'+f.path+'</td><td>'+f.status+'</td><td>'+(f.size||'—')+'</td></tr>';});
    if(gf.length>30) gb+='<tr><td colspan="3" style="color:rgba(184,204,236,.35);font-size:10px">... i '+(gf.length-30)+' więcej</td></tr>';
    h+=mkSec('// KATALOGI — GOBUSTER ('+gf.length+')',gb+'</tbody></table>',false);
  }

  if(res.sqlmap){
    var vuln=res.sqlmap.vulnerable;
    var sc2=vuln?'#ff4444':'#3ddc84';
    var sl=vuln?'PODATNY NA SQL INJECTION':'BRAK SQL INJECTION';
    var sb='<div class="sqli-box" style="border-color:'+sc2+'40;background:'+sc2+'0a"><div class="sqli-status" style="color:'+sc2+'">'+sl+'</div>';
    if(res.sqlmap.injectable_params&&res.sqlmap.injectable_params.length) sb+='<div style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:var(--silver)">Parametry: '+res.sqlmap.injectable_params.join(', ')+'</div>';
    sb+='</div>';
    h+=mkSec('// SQL INJECTION',sb,false);
  }

  if(res.testssl&&res.testssl.grade){
    var gc={A:'#3ddc84',B:'#f5c518',C:'#ff8c00',F:'#ff4444'}[res.testssl.grade]||'#4a8fd4';
    var tl='<div style="display:flex;align-items:center;gap:20px;margin-bottom:12px"><div style="font-family:Orbitron,sans-serif;font-size:36px;font-weight:900;color:'+gc+'">'+res.testssl.grade+'</div><div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:var(--silver)">TLS GRADE</div></div>';
    if(res.testssl.issues&&res.testssl.issues.length){
      tl+='<table class="dt"><thead><tr><th>PROBLEM</th><th>SEVERITY</th></tr></thead><tbody>';
      res.testssl.issues.forEach(function(i){tl+='<tr><td>'+(i.description||i)+'</td><td>'+(i.severity||'—')+'</td></tr>';});
      tl+='</tbody></table>';
    } else tl+='<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#3ddc84">BRAK PROBLEMÓW TLS</div>';
    h+=mkSec('// BEZPIECZEŃSTWO TLS',tl,false);
  }

  ext.innerHTML=h;
  ext.querySelectorAll('.res-section-hdr').forEach(function(hdr){
    hdr.addEventListener('click',function(){
      hdr.classList.toggle('open');
      hdr.nextElementSibling.classList.toggle('open');
    });
  });
}'''
html = re.sub(old_r, new_r, html, flags=re.DOTALL)

# 5. loadScanDetail - pobiera chains + narrative
old_lsd = r'function loadScanDetail\(taskId\).*?}\s*\);?\s*\}'
new_lsd = '''function loadScanDetail(taskId) {
  window._lastTaskId = taskId;
  Promise.all([
    fetch(API+'/scans/'+taskId).then(function(r){return r.json();}),
    fetch(API+'/scans/'+taskId+'/chains').then(function(r){return r.json();}).catch(function(){return {};}),
    fetch(API+'/scans/'+taskId+'/narrative').then(function(r){return r.json();}).catch(function(){return {};})
  ]).then(function(results){
    var s=results[0]; var chainsData=results[1]; var narrData=results[2];
    if(!s) return;
    var combined={
      target:s.target, findings_count:s.findings_count,
      analysis:{summary:s.summary,risk_level:s.risk_level,top_issues:s.top_issues||[],recommendations:s.recommendations},
      nuclei:{findings:[]},
      ports:s.ports||[], gobuster:s.gobuster||{}, sqlmap:s.sqlmap||null,
      testssl:s.testssl||null, fp_filter:s.fp_filter||null,
      exploit_chains:chainsData.exploit_chains||chainsData||{},
      hacker_narrative:narrData.hacker_narrative||narrData||{}
    };
    renderResults(combined,0);
    var metaEl=document.getElementById('scanMeta')||document.getElementById('meta');
    if(metaEl) metaEl.innerHTML='TARGET: '+s.target+'<br>FINDINGS: '+s.findings_count+'<br>DATE: '+(s.completed_at?new Date(s.completed_at).toLocaleString('pl-PL'):'N/A');
  });
}'''
html = re.sub(old_lsd, new_lsd, html, flags=re.DOTALL)

# 6. Wstaw div#extSections za sekcją rec (jeśli nie ma)
if 'id="extSections"' not in html:
    html = html.replace(
        'id="rec"',
        'id="rec"',
        1
    )
    # Wstaw za div zawierającym id="rec"
    html = re.sub(
        r'(id="rec"[^<]*</(?:p|div|span|textarea)[^>]*>)',
        r'\1\n<div id="extSections" style="margin-top:12px"></div>',
        html, count=1
    )

with open(path,'w',encoding='utf-8') as f:
    f.write(html)

print("PATCHED:", path)
