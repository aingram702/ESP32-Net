// ===========================================================================
//  web_ui.h  —  Single-page dashboard served by the C2, embedded in PROGMEM.
//
//  Terminal / hacker theme matched to the node repos' style.css (green-on-black
//  with scanlines). One tab per node. Polls GET /api/data every 2s and renders;
//  the toolbar buttons queue control commands via POST /api/cmd.
// ===========================================================================
#pragma once
#include <Arduino.h>

static const char INDEX_HTML[] PROGMEM = R"HTMLDOC(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESP32-NET // C2</title>
<style>
:root{
  --bg:#04140d; --panel:#06190f; --line:#0c3a26; --accent:#00ff9c;
  --accent-dim:#0a8f5e; --txt:#bdffe2; --muted:#5f9d83; --warn:#ffd166;
  --crit:#ff4d6d; --info:#4dd0ff;
  --mono:ui-monospace,"JetBrains Mono","SFMono-Regular",Consolas,monospace;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{
  background:radial-gradient(1200px 600px at 70% -10%,#0a2417 0,var(--bg) 60%);
  color:var(--txt);font-family:var(--mono);font-size:13px;line-height:1.45;
  -webkit-font-smoothing:antialiased;overflow-x:hidden;
}
.scanlines{position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(transparent 0,transparent 2px,rgba(0,0,0,.18) 3px);
  mix-blend-mode:overlay;opacity:.4}
.topbar{display:flex;align-items:center;justify-content:space-between;
  padding:10px 16px;border-bottom:1px solid var(--line);
  background:linear-gradient(180deg,#072114,#04140d);position:sticky;top:0;z-index:50}
.brand{font-weight:700;letter-spacing:3px;font-size:18px;
  text-shadow:0 0 8px rgba(0,255,156,.6)}
.brand small{display:block;font-size:10px;letter-spacing:1px;color:var(--muted)}
.status-strip{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.stat{font-size:11px;color:var(--accent);background:#06251757;
  border:1px solid var(--line);padding:3px 8px;border-radius:4px}
.dot{font-size:13px;color:var(--crit)}
.dot.ok{color:var(--accent);text-shadow:0 0 6px var(--accent)}
.tabs{display:flex;gap:2px;padding:6px 12px 0;flex-wrap:wrap;
  border-bottom:1px solid var(--line)}
.tab{background:transparent;color:var(--muted);border:1px solid transparent;
  border-bottom:none;padding:8px 16px;cursor:pointer;font-family:var(--mono);
  border-radius:6px 6px 0 0;font-size:12px;letter-spacing:1px}
.tab:hover{color:var(--txt)}
.tab.active{color:var(--accent);background:var(--panel);border-color:var(--line);
  box-shadow:0 -2px 10px rgba(0,255,156,.08)}
main{padding:16px}
.panel{display:none;animation:fade .2s ease}
.panel.active{display:block}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1}}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;
  padding:12px 16px;min-width:130px}
.card .k{font-size:10px;color:var(--muted);letter-spacing:1px;text-transform:uppercase}
.card .v{font-size:22px;color:var(--accent);font-weight:700;
  text-shadow:0 0 6px rgba(0,255,156,.35)}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.btn{background:#06301d;color:var(--accent);border:1px solid var(--accent-dim);
  padding:6px 12px;border-radius:5px;cursor:pointer;font-family:var(--mono);
  font-size:12px;letter-spacing:1px}
.btn:hover{box-shadow:0 0 8px rgba(0,255,156,.3)}
.btn.stop{background:#3a0d18;color:#ff8ba0;border-color:var(--crit)}
.btn.ghost{background:transparent;color:var(--muted);border-color:var(--line)}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #0a2a1b;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:280px}
th{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:10px;
  letter-spacing:1px;position:sticky;top:0;background:var(--panel)}
tr:hover td{background:#07261759}
.tablewrap{border:1px solid var(--line);border-radius:8px;overflow:auto;
  max-height:62vh;background:var(--panel)}
.tag{font-size:10px;padding:1px 6px;border-radius:3px;border:1px solid var(--line)}
.tag.crit{background:#3a0d18;color:#ff8ba0;border-color:var(--crit)}
.tag.warn{background:#3a2c08;color:var(--warn);border-color:var(--warn)}
.tag.ok{background:#06301d;color:var(--accent);border-color:var(--accent-dim)}
.bars{display:inline-block;width:46px;height:9px;background:#0a2a1b;border-radius:2px;
  overflow:hidden;vertical-align:middle}
.bars > i{display:block;height:100%;background:var(--accent)}
.muted{color:var(--muted)}
.empty{padding:24px;text-align:center;color:var(--muted)}
.foot{padding:10px 16px;color:var(--muted);font-size:11px;border-top:1px solid var(--line)}
</style>
</head>
<body>
<div class="scanlines"></div>
<div class="topbar">
  <div class="brand">ESP32-NET<small>// command &amp; control</small></div>
  <div class="status-strip">
    <span class="stat"><span id="d-wd" class="dot">&#9679;</span> WARDRIVER</span>
    <span class="stat"><span id="d-ws" class="dot">&#9679;</span> WARSNIFFER</span>
    <span class="stat"><span id="d-bd" class="dot">&#9679;</span> BLUEDRIVER</span>
    <span class="stat" id="clients">clients: -</span>
  </div>
</div>

<div class="tabs">
  <button class="tab active" data-p="overview">[ OVERVIEW ]</button>
  <button class="tab" data-p="wardriver">[ WARDRIVER ]</button>
  <button class="tab" data-p="warsniffer">[ WARSNIFFER ]</button>
  <button class="tab" data-p="bluedriver">[ BLUEDRIVER ]</button>
</div>

<main>
  <!-- OVERVIEW -->
  <section id="overview" class="panel active">
    <div class="cards">
      <div class="card"><div class="k">WiFi APs</div><div class="v" id="ov-wifi">0</div></div>
      <div class="card"><div class="k">BLE devices</div><div class="v" id="ov-ble">0</div></div>
      <div class="card"><div class="k">Frames seen</div><div class="v" id="ov-frames">0</div></div>
      <div class="card"><div class="k">WIDS alerts</div><div class="v" id="ov-alerts">0</div></div>
      <div class="card"><div class="k">Threats</div><div class="v" id="ov-threats">0</div></div>
      <div class="card"><div class="k">C2 uptime</div><div class="v" id="ov-uptime">0s</div></div>
    </div>
    <div class="tablewrap"><table>
      <thead><tr><th>Node</th><th>State</th><th>Last seen</th><th>Uptime</th><th>Heap</th><th>Detail</th></tr></thead>
      <tbody id="ov-nodes"></tbody>
    </table></div>
  </section>

  <!-- WARDRIVER -->
  <section id="wardriver" class="panel">
    <div class="toolbar">
      <button class="btn" onclick="cmd('wardriver','scan',1)">SCAN ON</button>
      <button class="btn stop" onclick="cmd('wardriver','scan',0)">SCAN OFF</button>
      <button class="btn ghost" onclick="cmd('wardriver','clear')">CLEAR STORE</button>
      <a class="btn ghost" href="/api/export/wifi" download>EXPORT CSV</a>
      <span class="muted" id="wd-gps">gps: --</span>
    </div>
    <div class="tablewrap"><table>
      <thead><tr><th>BSSID</th><th>SSID</th><th>Ch</th><th>Enc</th><th>RSSI</th><th>Vendor</th><th>Flag</th><th>Seen</th></tr></thead>
      <tbody id="wd-rows"></tbody>
    </table></div>
  </section>

  <!-- WARSNIFFER -->
  <section id="warsniffer" class="panel">
    <div class="toolbar">
      <button class="btn" onclick="cmd('warsniffer','scan',1)">CAPTURE ON</button>
      <button class="btn stop" onclick="cmd('warsniffer','scan',0)">CAPTURE OFF</button>
      <button class="btn ghost" onclick="cmd('warsniffer','hop',1)">HOP ON</button>
      <button class="btn ghost" onclick="cmd('warsniffer','clear')">CLEAR</button>
      <a class="btn ghost" href="/api/export/sniff" download>EXPORT CSV</a>
      <span class="muted" id="ws-meta">ch: -- &nbsp; frames: --</span>
    </div>
    <div class="cards" id="ws-counters"></div>
    <h4 class="muted">AP / STA inventory</h4>
    <div class="tablewrap" style="max-height:34vh"><table>
      <thead><tr><th>BSSID</th><th>SSID</th><th>Ch</th><th>RSSI</th><th>Clients</th></tr></thead>
      <tbody id="ws-aps"></tbody>
    </table></div>
    <h4 class="muted">WIDS alerts</h4>
    <div class="tablewrap" style="max-height:24vh"><table>
      <thead><tr><th>Type</th><th>BSSID</th><th>Detail</th><th>When</th></tr></thead>
      <tbody id="ws-alerts"></tbody>
    </table></div>
    <h4 class="muted">Probed SSIDs (client preferred-network lists)</h4>
    <div class="tablewrap" style="max-height:24vh"><table>
      <thead><tr><th>SSID</th><th>Hits</th><th>Last seen</th></tr></thead>
      <tbody id="ws-probes"></tbody>
    </table></div>
  </section>

  <!-- BLUEDRIVER -->
  <section id="bluedriver" class="panel">
    <div class="toolbar">
      <button class="btn" onclick="cmd('bluedriver','scan',1)">SCAN ON</button>
      <button class="btn stop" onclick="cmd('bluedriver','scan',0)">SCAN OFF</button>
      <button class="btn ghost" onclick="cmd('bluedriver','config',1)">ACTIVE SCAN</button>
      <button class="btn ghost" onclick="cmd('bluedriver','config',0)">PASSIVE</button>
      <button class="btn ghost" onclick="cmd('bluedriver','clear')">CLEAR</button>
      <a class="btn ghost" href="/api/export/ble" download>EXPORT CSV</a>
      <span class="muted">GATT: click a row to enqueue enumeration</span>
    </div>
    <div class="tablewrap"><table>
      <thead><tr><th>Address</th><th>Name</th><th>Type</th><th>Vendor</th><th>MfgID</th><th>RSSI</th><th>Hits</th><th>Services</th></tr></thead>
      <tbody id="bd-rows"></tbody>
    </table></div>
    <h4 class="muted">GATT enumeration result</h4>
    <div class="tablewrap" style="max-height:34vh"><pre id="bd-gatt" style="margin:0;padding:10px;white-space:pre-wrap;color:var(--txt)">no GATT enumeration yet — click a device row above</pre></div>
  </section>
</main>

<div class="foot">ESP32-Net C2 dashboard &middot; passive recon / WIDS &middot; authorized testing only</div>

<script>
"use strict";
// ---- tab switching --------------------------------------------------------
document.querySelectorAll(".tab").forEach(function(t){
  t.addEventListener("click",function(){
    document.querySelectorAll(".tab").forEach(function(x){x.classList.remove("active");});
    document.querySelectorAll(".panel").forEach(function(x){x.classList.remove("active");});
    t.classList.add("active");
    document.getElementById(t.dataset.p).classList.add("active");
  });
});

function esc(s){ s=(s==null?"":String(s));
  return s.replace(/[&<>"]/g,function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]; }); }
function rssiBar(r){ var q=Math.max(0,Math.min(100, r<=-100?0:(r>=-50?100:2*(r+100))));
  return '<span class="bars"><i style="width:'+q+'%"></i></span> '+r; }
function ago(ms){ if(ms==null) return "--"; var s=Math.floor(ms/1000);
  if(s<60) return s+"s"; if(s<3600) return Math.floor(s/60)+"m"; return Math.floor(s/3600)+"h"; }
function dur(s){ if(s==null) return "--"; if(s<60) return s+"s";
  if(s<3600) return Math.floor(s/60)+"m"; return Math.floor(s/3600)+"h"; }
function kb(b){ return b==null?"--":Math.round(b/1024)+"K"; }

function setDot(id,online){ var e=document.getElementById(id);
  e.className="dot"+(online?" ok":""); }

function cmd(target,c,on){
  var body={target:target,cmd:c};
  if(on!==undefined) body.on=on;
  fetch("/api/cmd",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify(body)}).catch(function(){});
}

function render(d){
  // top status dots
  setDot("d-wd", d.nodes.wardriver.online);
  setDot("d-ws", d.nodes.warsniffer.online);
  setDot("d-bd", d.nodes.bluedriver.online);
  document.getElementById("clients").textContent="clients: "+d.apClients;

  // overview cards
  document.getElementById("ov-wifi").textContent   = d.wardriver.aps.length;
  document.getElementById("ov-ble").textContent    = d.bluedriver.devs.length;
  document.getElementById("ov-frames").textContent = d.warsniffer.frames.total||0;
  document.getElementById("ov-alerts").textContent = d.warsniffer.alerts.length;
  var threats=d.wardriver.aps.filter(function(a){return a.flag;}).length;
  document.getElementById("ov-threats").textContent=threats;
  document.getElementById("ov-uptime").textContent=dur(d.uptime);

  var nb="";
  [["WarDriver","wardriver"],["WarSniffer","warsniffer"],["BlueDriver","bluedriver"]]
  .forEach(function(p){ var n=d.nodes[p[1]];
    nb+="<tr><td>"+p[0]+"</td><td>"+(n.online
        ?'<span class="tag ok">ONLINE</span>':'<span class="tag crit">OFFLINE</span>')
      +"</td><td>"+ago(n.lastSeenMs)+"</td><td>"+dur(n.uptime)+"</td><td>"+kb(n.heap)
      +"</td><td class='muted'>"+esc(n.detail||"")+"</td></tr>"; });
  document.getElementById("ov-nodes").innerHTML=nb||'<tr><td colspan=6 class="empty">no nodes have reported yet</td></tr>';

  // WARDRIVER
  var g=d.wardriver.gps;
  document.getElementById("wd-gps").textContent = g&&g.valid
    ? "gps: "+g.lat.toFixed(5)+", "+g.lon.toFixed(5)+" ("+g.sats+" sats)" : "gps: no fix";
  var wr="";
  d.wardriver.aps.forEach(function(a){
    var flag = a.flag ? '<span class="tag crit">'+esc(a.flag)+'</span>'
             : (a.enc==="OPEN" ? '<span class="tag warn">OPEN</span>' : "");
    wr+="<tr><td>"+esc(a.mac)+"</td><td>"+(a.ssid?esc(a.ssid):'<span class=muted>&lt;hidden&gt;</span>')
      +"</td><td>"+a.ch+"</td><td>"+esc(a.enc)+"</td><td>"+rssiBar(a.rssi)+"</td><td>"+esc(a.vendor||"")
      +"</td><td>"+flag+"</td><td>"+ago(a.seenMs)+"</td></tr>"; });
  document.getElementById("wd-rows").innerHTML=wr||'<tr><td colspan=8 class="empty">no WiFi networks yet</td></tr>';

  // WARSNIFFER
  var f=d.warsniffer.frames;
  document.getElementById("ws-meta").textContent =
    "ch: "+(d.warsniffer.channel||"-")+"   frames: "+(f.total||0)+"   dropped: "+(d.warsniffer.dropped||0);
  var counters=[["mgmt",f.mgmt],["ctrl",f.ctrl],["data",f.data],["beacon",f.beacon],
                ["probe",f.probe],["deauth",f.deauth],["eapol",f.eapol]];
  document.getElementById("ws-counters").innerHTML=counters.map(function(c){
    return '<div class="card"><div class="k">'+c[0]+'</div><div class="v">'+(c[1]||0)+'</div></div>';}).join("");
  var ap="";
  d.warsniffer.aps.forEach(function(a){
    ap+="<tr><td>"+esc(a.bssid)+"</td><td>"+(a.ssid?esc(a.ssid):'<span class=muted>&lt;hidden&gt;</span>')
      +"</td><td>"+a.ch+"</td><td>"+rssiBar(a.rssi)+"</td><td>"+a.clients+"</td></tr>"; });
  document.getElementById("ws-aps").innerHTML=ap||'<tr><td colspan=5 class="empty">no APs observed yet</td></tr>';
  var al="";
  d.warsniffer.alerts.forEach(function(x){
    al+='<tr><td><span class="tag crit">'+esc(x.type)+'</span></td><td>'+esc(x.bssid||"")
      +"</td><td>"+esc(x.detail||"")+"</td><td>"+ago(x.ageMs)+"</td></tr>"; });
  document.getElementById("ws-alerts").innerHTML=al||'<tr><td colspan=4 class="empty">no alerts</td></tr>';
  var pb="";
  (d.warsniffer.probes||[]).forEach(function(p){
    pb+="<tr><td>"+esc(p.ssid)+"</td><td>"+p.hits+"</td><td>"+ago(p.seenMs)+"</td></tr>"; });
  document.getElementById("ws-probes").innerHTML=pb||'<tr><td colspan=3 class="empty">no directed probe requests captured</td></tr>';

  // BLUEDRIVER
  var bd="";
  d.bluedriver.devs.forEach(function(v){
    var at = (v.type==="random")?1:0;   // addrType: 0=public, 1=random
    bd+="<tr style='cursor:pointer' title='click to enqueue GATT enumeration' "
      +"onclick=\"gatt('"+esc(v.mac)+"',"+at+")\"><td>"+esc(v.mac)+"</td><td>"
      +(v.name?esc(v.name):'<span class=muted>--</span>')
      +"</td><td>"+esc(v.type||"")+"</td><td>"+esc(v.vendor||"")+"</td><td>"+esc(v.mfgId||"")
      +"</td><td>"+rssiBar(v.rssi)+"</td><td>"+v.hits+"</td><td class='muted'>"+esc(v.services||"")+"</td></tr>"; });
  document.getElementById("bd-rows").innerHTML=bd||'<tr><td colspan=8 class="empty">no BLE devices yet</td></tr>';

  // GATT result panel
  if(d.bluedriver.gatt){
    document.getElementById("bd-gatt").textContent =
      "("+ago(d.bluedriver.gattAgeMs)+" ago)\n"+JSON.stringify(d.bluedriver.gatt,null,2);
  }
}

// queue a GATT enumeration for a tapped BLE device
function gatt(mac,addrType){
  fetch("/api/cmd",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({target:"bluedriver",cmd:"gatt",mac:mac,addrType:addrType})}).catch(function(){});
  document.getElementById("bd-gatt").textContent="GATT enumeration queued for "+mac+" — result appears here in ~10s...";
}

function poll(){
  fetch("/api/data").then(function(r){return r.json();})
    .then(render).catch(function(){})
    .finally(function(){ setTimeout(poll, 2000); });
}
poll();
</script>
</body>
</html>
)HTMLDOC";
