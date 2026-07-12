<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Container Control</title>
<style>
  :root{
    --bg: #0a0c10;
    --panel: #12151b;
    --panel-2: #171b22;
    --border: #1f242c;
    --border-soft: #21262f;
    --text: #e7e9ec;
    --muted: #7c8494;
    --muted-2: #565d69;
    --mono: 'SF Mono', 'JetBrains Mono', ui-monospace, Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, sans-serif;

    --green: #34d399;
    --green-dim: rgba(52,211,153,0.12);
    --amber: #f5a524;
    --amber-dim: rgba(245,165,36,0.14);
    --red: #f4495f;
    --red-dim: rgba(244,73,95,0.14);
    --violet: #8b8cf0;
    --violet-dim: rgba(139,140,240,0.14);
  }

  *{ box-sizing:border-box; }
  html,body{ margin:0; padding:0; }
  body{
    background: radial-gradient(1200px 600px at 10% -10%, #10131a 0%, var(--bg) 55%);
    color: var(--text);
    font-family: var(--sans);
    -webkit-font-smoothing: antialiased;
    padding: 28px 32px 60px;
    min-height: 100vh;
  }

  .wrap{ max-width: 1240px; margin: 0 auto; }

  /* ---------- Header ---------- */
  header{
    display:flex; justify-content:space-between; align-items:flex-start;
    gap:20px; margin-bottom: 22px; flex-wrap: wrap;
  }
  .title-block h1{
    font-size: 26px; font-weight: 700; margin: 0 0 4px; letter-spacing: -0.01em;
  }
  .title-block p{ margin:0; color: var(--muted); font-size: 13.5px; max-width: 560px; }

  .header-actions{ display:flex; gap:10px; align-items:center; flex-wrap: wrap; }

  .btn{
    display:inline-flex; align-items:center; gap:7px;
    background: var(--panel-2); border:1px solid var(--border-soft);
    color: var(--text); padding: 8px 14px; border-radius: 8px;
    font-size: 13px; font-weight: 600; cursor: pointer;
    transition: border-color .15s ease, transform .1s ease, background .15s ease;
    font-family: inherit;
  }
  .btn:hover{ border-color:#333a45; background:#1b2029; }
  .btn:active{ transform: translateY(1px); }
  .btn:focus-visible{ outline: 2px solid var(--violet); outline-offset: 2px; }

  .btn-restart:hover{ color:#c9cdd6; }
  .btn-pause:hover{ color: var(--amber); border-color: rgba(245,165,36,0.35); }
  .btn-stop{ color: var(--red); }
  .btn-stop:hover{ background: rgba(244,73,95,0.08); border-color: rgba(244,73,95,0.4); }
  .btn-unpause{ color: var(--green); }
  .btn-unpause:hover{ background: rgba(52,211,153,0.08); border-color: rgba(52,211,153,0.4); }
  .btn-start{ color: var(--green); }

  select.filter{
    appearance: none; -webkit-appearance:none;
    background: var(--panel-2) url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="10" height="6"><path d="M0 0l5 6 5-6z" fill="%237c8494"/></svg>') no-repeat right 12px center;
    border:1px solid var(--border-soft); color: var(--text);
    padding: 8px 32px 8px 14px; border-radius: 8px; font-size: 13px; font-weight: 600;
    font-family: inherit; cursor:pointer;
  }
  select.filter:focus-visible{ outline: 2px solid var(--violet); outline-offset: 2px; }

  /* ---------- Attention banner ---------- */
  .attention{
    display:none;
    margin-bottom: 26px;
    border:1px solid rgba(244,73,95,0.3);
    background: linear-gradient(180deg, rgba(244,73,95,0.06), rgba(244,73,95,0.02));
    border-radius: 12px;
    padding: 16px 18px 6px;
  }
  .attention.show{ display:block; }
  .attention-head{
    display:flex; align-items:center; gap:8px; margin-bottom: 12px;
  }
  .attention-head .dot{
    width:7px; height:7px; border-radius:50%; background: var(--red);
    box-shadow: 0 0 0 4px rgba(244,73,95,0.15);
  }
  .attention-head h2{ font-size: 13.5px; margin:0; font-weight:700; letter-spacing:.02em; text-transform:uppercase; color:#ff8698; }
  .attention-head span{ color: var(--muted); font-size: 12.5px; font-weight: 500; }

  .attention-grid{
    display:grid; grid-template-columns: repeat(auto-fill, minmax(300px,1fr));
    gap: 10px; padding-bottom: 16px;
  }

  /* ---------- Section headers ---------- */
  .section-label{
    font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .06em;
    color: var(--muted-2); margin: 28px 0 12px; padding-left: 2px;
  }

  /* ---------- Grid of cards ---------- */
  .grid{
    display:grid;
    grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
    gap: 14px;
  }

  /* Standalone card */
  .card{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px 16px 14px;
    position: relative;
    overflow: hidden;
    transition: border-color .15s ease;
  }
  .card::before{
    content:''; position:absolute; left:0; top:0; bottom:0; width:3px;
    background: var(--edge, var(--green));
  }
  .card.status-paused{ --edge: var(--amber); }
  .card.status-stopped{ --edge: var(--muted-2); }
  .card.status-unhealthy{ --edge: var(--red); }
  .card.status-running{ --edge: var(--green); }

  .row-top{ display:flex; align-items:flex-start; justify-content:space-between; gap:10px; flex-wrap:wrap; margin-bottom: 10px;}
  .name-block{ display:flex; align-items:baseline; gap:9px; flex-wrap:wrap; min-width:0; }
  .name-block .name{ font-size: 15px; font-weight: 700; }
  .name-block .image{ font-family: var(--mono); font-size: 11.5px; color: var(--muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }

  .badge{
    display:inline-flex; align-items:center; gap:4px;
    font-size: 10.5px; font-weight: 700; padding: 2px 8px; border-radius: 999px;
    border:1px solid transparent; white-space:nowrap;
  }
  .badge-stack{ background: var(--violet-dim); color: var(--violet); border-color: rgba(139,140,240,0.3); }
  .badge-nobackup{ background: transparent; color: var(--muted-2); border-color: var(--border-soft); font-weight:600; }

  .status-pill{
    display:inline-flex; align-items:center; gap:6px;
    font-size: 11.5px; font-weight: 700; padding: 4px 10px; border-radius: 999px;
  }
  .status-pill .dot{ width:6px; height:6px; border-radius:50%; }
  .status-running{ background: var(--green-dim); color: var(--green); }
  .status-running .dot{ background: var(--green); }
  .status-paused-pill{ background: var(--amber-dim); color: var(--amber); }
  .status-paused-pill .dot{ background: var(--amber); }
  .status-stopped-pill{ background: rgba(124,132,148,0.14); color: var(--muted); }
  .status-stopped-pill .dot{ background: var(--muted-2); }
  .status-unhealthy-pill{ background: var(--red-dim); color: var(--red); }
  .status-unhealthy-pill .dot{ background: var(--red); animation: pulse 1.6s ease-in-out infinite; }

  @keyframes pulse{ 0%,100%{opacity:1;} 50%{opacity:.35;} }

  .actions{ display:flex; gap:8px; margin-top: 12px; }
  .actions .btn{ flex:1; justify-content:center; padding:7px 10px; font-size:12.5px; }

  /* ---------- Stack group (immich etc) ---------- */
  .stack{
    grid-column: 1 / -1;
    background: linear-gradient(180deg, rgba(139,140,240,0.045), transparent 40%), var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 16px 16px 14px;
  }
  .stack-head{
    display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;
    margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid var(--border-soft);
  }
  .stack-head .left{ display:flex; align-items:center; gap:10px; }
  .stack-head h3{ margin:0; font-size:15px; font-weight:700; }
  .stack-summary{ display:flex; gap:6px; }

  .stack-members{
    display:grid; grid-template-columns: repeat(auto-fill, minmax(300px,1fr));
    gap: 10px; position: relative;
  }
  .member{
    position:relative; padding-left: 18px;
    background: var(--panel-2); border:1px solid var(--border-soft);
    border-radius: 10px; padding: 12px 12px 10px 18px;
  }
  .member::before{
    content:''; position:absolute; left:0; top:0; bottom:0; width:3px; border-radius: 3px 0 0 3px;
    background: var(--edge, var(--green));
  }
  .member.status-paused{ --edge: var(--amber); }
  .member.status-stopped{ --edge: var(--muted-2); }
  .member.status-unhealthy{ --edge: var(--red); }
  .member.status-running{ --edge: var(--green); }

  .member .row-top{ margin-bottom: 8px; }
  .member .name{ font-size: 13.5px; }
  .member .image{ font-size: 10.5px; }
  .member .actions .btn{ padding: 6px 8px; font-size: 11.5px; }

  .empty-state{
    text-align:center; padding: 50px 20px; color: var(--muted); font-size: 13.5px;
    border: 1px dashed var(--border-soft); border-radius: 12px;
  }

  /* ---------- Responsive ---------- */
  @media (max-width: 720px){
    body{ padding: 18px 14px 40px; }
    header{ flex-direction:column; align-items:stretch; }
    .header-actions{ justify-content: space-between; }
    .header-actions select.filter, .header-actions .btn{ flex:1; }
    .grid, .attention-grid, .stack-members{ grid-template-columns: 1fr; }
    .actions{ flex-wrap: wrap; }
    .actions .btn{ min-width: 30%; }
  }
</style>
</head>
<body>
<div class="wrap">

  <header>
    <div class="title-block">
      <h1>Container Control</h1>
      <p>Every container in your stack, grouped by compose dependencies — start, stop, restart, or pause any of them directly.</p>
    </div>
    <div class="header-actions">
      <select class="filter" id="filterSelect">
        <option value="all">All containers</option>
        <option value="attention">Needs attention</option>
        <option value="running">Running</option>
        <option value="paused">Paused</option>
        <option value="stopped">Stopped</option>
        <option value="unhealthy">Unhealthy</option>
      </select>
      <button class="btn" id="refreshBtn">↻ Refresh</button>
    </div>
  </header>

  <div class="attention" id="attentionBanner">
    <div class="attention-head">
      <span class="dot"></span>
      <h2>Needs attention</h2>
      <span id="attentionCount"></span>
    </div>
    <div class="attention-grid" id="attentionGrid"></div>
  </div>

  <div id="sectionLabel" class="section-label">All containers</div>
  <div class="grid" id="mainGrid"></div>
  <div class="empty-state" id="emptyState" style="display:none;">Nothing matches this filter.</div>

</div>

<script>
const DATA = [
  { id:'caddy', name:'caddy', image:'caddy:latest', group:'caddy', status:'paused' },
  { id:'docksentry', name:'docksentry', image:'amayer1983/docksentry:latest', group:null, status:'running' },
  { id:'homebox', name:'homebox', image:'ghcr.io/sysadminsmedia/homebox:latest', group:'Homebox', status:'running' },
  { id:'homepage', name:'homepage', image:'ghcr.io/gethomepage/homepage:latest', group:null, status:'paused' },
  { id:'immich_machine_learning', name:'immich_machine_learning', image:'ghcr.io/immich-app/immich-machine-learning:release', group:'immich', status:'running' },
  { id:'immich_postgres', name:'immich_postgres', image:'ghcr.io/immich-app/postgres:14-vectorchord0.4.3-pgvectors0.2.0', group:'immich', status:'running' },
  { id:'immich_redis', name:'immich_redis', image:'valkey/valkey:9', group:'immich', status:'running' },
  { id:'immich_server', name:'immich_server', image:'ghcr.io/immich-app/immich-server:release', group:'immich', status:'unhealthy' },
  { id:'prestoback', name:'prestoback', image:'piklz/prestoback:dev', group:null, status:'running' },
  { id:'trilium', name:'trilium', image:'triliumnext/trilium:latest', group:'trilium', status:'running' },
  { id:'vaultwarden', name:'vaultwarden', image:'vaultwarden/server:latest', group:'vaultwarden', status:'running' },
];

const state = {};
DATA.forEach(d => state[d.id] = d.status);

const STATUS_META = {
  running:   { label: 'running · healthy', pillClass: 'status-running' },
  unhealthy: { label: 'running · unhealthy', pillClass: 'status-unhealthy-pill' },
  paused:    { label: 'paused', pillClass: 'status-paused-pill' },
  stopped:   { label: 'stopped', pillClass: 'status-stopped-pill' },
};

function pill(status){
  const m = STATUS_META[status];
  return `<span class="status-pill ${m.pillClass}"><span class="dot"></span>${m.label}</span>`;
}

function actionButtons(item, compact){
  const s = state[item.id];
  const size = compact ? '' : '';
  let btns = '';
  if (s === 'paused') {
    btns += `<button class="btn btn-unpause" onclick="setStatus('${item.id}','running')">▶ Unpause</button>`;
    btns += `<button class="btn btn-stop" onclick="setStatus('${item.id}','stopped')">■ Stop</button>`;
  } else if (s === 'stopped') {
    btns += `<button class="btn btn-start" onclick="setStatus('${item.id}','running')">▶ Start</button>`;
  } else {
    btns += `<button class="btn btn-restart" onclick="pulseRestart('${item.id}')">↻ Restart</button>`;
    btns += `<button class="btn btn-pause" onclick="setStatus('${item.id}','paused')">❙❙ Pause</button>`;
    btns += `<button class="btn btn-stop" onclick="setStatus('${item.id}','stopped')">■ Stop</button>`;
  }
  return btns;
}

function badgeFor(item){
  if (item.group) return `<span class="badge badge-stack">✓ ${item.group}</span>`;
  return `<span class="badge badge-nobackup">not backed up</span>`;
}

function cardHTML(item, memberStyle){
  const s = state[item.id];
  const cls = memberStyle ? 'member' : 'card';
  return `
    <div class="${cls} status-${s}" data-id="${item.id}">
      <div class="row-top">
        <div class="name-block">
          <span class="name">${item.name}</span>
          <span class="image">${item.image}</span>
        </div>
        ${badgeFor(item)}
      </div>
      ${pill(s)}
      <div class="actions">${actionButtons(item)}</div>
    </div>`;
}

function groupData(items){
  const groups = {};
  const solo = [];
  items.forEach(item => {
    if (item.group) {
      const members = DATA.filter(d => d.group === item.group);
      if (members.length > 1) {
        groups[item.group] = groups[item.group] || members;
        return;
      }
    }
    solo.push(item);
  });
  return { groups, solo };
}

function stackHTML(groupName, members){
  const statuses = members.map(m => state[m.id]);
  const worst = statuses.includes('unhealthy') ? 'unhealthy'
    : statuses.includes('stopped') ? 'stopped'
    : statuses.includes('paused') ? 'paused' : 'running';
  const counts = { running:0, unhealthy:0, paused:0, stopped:0 };
  statuses.forEach(s => counts[s]++);
  let summary = '';
  if (counts.unhealthy) summary += `<span class="status-pill status-unhealthy-pill"><span class="dot"></span>${counts.unhealthy} unhealthy</span>`;
  if (counts.paused) summary += `<span class="status-pill status-paused-pill"><span class="dot"></span>${counts.paused} paused</span>`;
  if (counts.stopped) summary += `<span class="status-pill status-stopped-pill"><span class="dot"></span>${counts.stopped} stopped</span>`;
  if (counts.running) summary += `<span class="status-pill status-running"><span class="dot"></span>${counts.running} healthy</span>`;

  return `
    <div class="stack">
      <div class="stack-head">
        <div class="left">
          <span class="badge badge-stack">✓ ${groupName}</span>
          <h3>${groupName} stack</h3>
        </div>
        <div class="stack-summary">${summary}</div>
      </div>
      <div class="stack-members">
        ${members.map(m => cardHTML(m, true)).join('')}
      </div>
    </div>`;
}

function matchesFilter(item, filter){
  const s = state[item.id];
  if (filter === 'all') return true;
  if (filter === 'attention') return s !== 'running';
  return s === filter;
}

function render(){
  const filter = document.getElementById('filterSelect').value;

  // Attention banner always shows anything not-running, regardless of filter,
  // unless the filter itself already isolates a single non-running status.
  const attentionItems = DATA.filter(d => state[d.id] !== 'running');
  const banner = document.getElementById('attentionBanner');
  const grid = document.getElementById('attentionGrid');
  const showBanner = attentionItems.length > 0 && filter === 'all';
  banner.classList.toggle('show', showBanner);
  if (showBanner) {
    document.getElementById('attentionCount').textContent = `${attentionItems.length} container${attentionItems.length>1?'s':''} paused, stopped, or unhealthy`;
    grid.innerHTML = attentionItems.map(i => cardHTML(i)).join('');
  }

  const visible = DATA.filter(d => matchesFilter(d, filter));
  const label = document.getElementById('sectionLabel');
  const labels = { all:'All containers', attention:'Needs attention', running:'Running', paused:'Paused', stopped:'Stopped', unhealthy:'Unhealthy' };
  label.textContent = labels[filter];

  const mainGrid = document.getElementById('mainGrid');
  const empty = document.getElementById('emptyState');

  if (visible.length === 0) {
    mainGrid.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  const { groups, solo } = groupData(visible);
  let html = '';
  Object.entries(groups).forEach(([name, members]) => {
    html += stackHTML(name, members);
  });
  solo.forEach(item => { html += cardHTML(item); });
  mainGrid.innerHTML = html;
}

function setStatus(id, status){
  state[id] = status;
  render();
}

function pulseRestart(id){
  const el = document.querySelector(`[data-id="${id}"]`);
  if (el) { el.style.opacity = '0.5'; setTimeout(() => { el.style.opacity = '1'; render(); }, 350); }
}

document.getElementById('filterSelect').addEventListener('change', render);
document.getElementById('refreshBtn').addEventListener('click', () => {
  const btn = document.getElementById('refreshBtn');
  btn.textContent = '↻ Refreshing…';
  setTimeout(() => { btn.textContent = '↻ Refresh'; render(); }, 500);
});

render();
</script>
</body>
</html>