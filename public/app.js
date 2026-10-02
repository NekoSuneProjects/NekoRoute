import { esc, flag, countryName, countryLabel, regions } from '/common.js?v=0507-20260914T1552';

const $ = s => document.querySelector(s);
const state = { stats: null, region: '', country: '', protocol: '', networkType: '', status: 'online', page:1, pageSize:50, pages:1, total:0 };

function option(value, label) { return `<option value="${esc(value)}">${esc(label)}</option>`; }
function syncSelects() {
  $('#regionSelect').value = state.region;
  $('#countrySelect').value = state.country;
  $('#protocolSelect').value = state.protocol;
  $('#networkTypeSelect').value = state.networkType;
  $('#statusSelect').value = state.status;
  document.querySelectorAll('.region-card').forEach(el => el.classList.toggle('active', el.dataset.region === state.region));
}

function renderRegions() {
  const by = state.stats?.byRegion || {};
  const max = Math.max(1, ...regions.map(r => Number(by[r] || 0)));
  const icons = {
    'North America':'🌎','South America':'🌎','Europe':'🌍','Africa':'🌍','Asia':'🌏','Oceania':'🌏','Other':'🌐'
  };
  $('#regionGrid').innerHTML = regions.map(region => {
    const count = Number(by[region] || 0);
    const pct = Math.round((count / max) * 100);
    return `<button data-region="${esc(region)}" class="region-card flex flex-col justify-between rounded-2xl border border-zinc-800 bg-[#080d0a]/80 p-4 text-left transition hover:-translate-y-0.5 hover:border-emerald-500/40">
      <div class="flex items-start justify-between gap-3"><div><div class="text-xs text-zinc-500">${esc(region)}</div><div class="mt-1 text-2xl font-black">${count}</div></div><span class="text-xl opacity-70">${icons[region]}</span></div>
      <div><div class="mb-1 flex justify-between text-[10px] uppercase tracking-wider text-zinc-600"><span>relative pool</span><span>${pct}%</span></div><div class="h-1.5 overflow-hidden rounded-full bg-zinc-900"><div class="h-full rounded-full bg-emerald-400" style="width:${pct}%"></div></div></div>
    </button>`;
  }).join('');
  document.querySelectorAll('.region-card').forEach(btn => btn.onclick = () => {
    state.region = state.region === btn.dataset.region ? '' : btn.dataset.region;
    state.country = '';
    syncSelects();
    loadProxies({resetPage:true});
  });
}

function buildFilters() {
  $('#regionSelect').innerHTML = option('', 'All regions') + regions.map(r => option(r,r)).join('');
  const countries = Object.entries(state.stats?.byCountry || {}).sort((a,b) => countryName(a[0]).localeCompare(countryName(b[0])));
  $('#countrySelect').innerHTML = option('', 'All countries') + countries.map(([c,n]) => option(c, `${countryLabel(c)} · ${n}`)).join('');
  syncSelects();
}

async function loadStats() {
  const res = await fetch('/api/stats');
  state.stats = await res.json();
  $('#statTotal').textContent = state.stats.total;
  $('#statOnline').textContent = state.stats.online;
  $('#statDegraded').textContent = state.stats.degraded;
  $('#statUnchecked').textContent = state.stats.unchecked;
  $('#healthPill').innerHTML = `<span class="mr-1 text-emerald-400">●</span> API online · ${state.stats.online} healthy`;
  renderRegions(); buildFilters();
}

function networkBadge(network = {}) {
  let label = 'Unknown', cls = 'bg-zinc-800 text-zinc-400';
  if (network.isTor) { label='Tor'; cls='bg-purple-500/10 text-purple-300'; }
  else if (network.isVpn) { label='VPN'; cls='bg-sky-500/10 text-sky-300'; }
  else if (network.isProxy) { label='Proxy'; cls='bg-amber-500/10 text-amber-300'; }
  else if (network.isHomeResidential) { label='Residential'; cls='bg-emerald-500/10 text-emerald-300'; }
  else if (network.isHostingProvider || network.connectionType === 'hosting') { label='Hosting / VPS'; cls='bg-indigo-500/10 text-indigo-300'; }
  else if (network.isNonResidential) { label='Non-residential'; cls='bg-zinc-700/40 text-zinc-300'; }
  return `<span class="rounded-full px-2 py-1 text-xs font-bold ${cls}" title="${esc(network.org || network.detectionReason || '')}">${label}</span>`;
}

function statusBadge(status) {
  const cls = status === 'online' ? 'bg-emerald-500/10 text-emerald-300' : status === 'degraded' ? 'bg-amber-500/10 text-amber-300' : status === 'offline' ? 'bg-rose-500/10 text-rose-300' : 'bg-zinc-800 text-zinc-400';
  return `<span class="rounded-full px-2 py-1 text-xs font-bold ${cls}">${esc(status)}</span>`;
}

async function loadProxies({ resetPage=false } = {}) {
  if (resetPage) state.page = 1;
  const q = new URLSearchParams({ page:String(state.page), pageSize:String(state.pageSize) });
  if (state.region) q.set('region', state.region);
  if (state.country) q.set('country', state.country);
  if (state.protocol) q.set('protocol', state.protocol);
  if (state.networkType) q.set('networkType', state.networkType);
  if (state.status) q.set('status', state.status);
  const res = await fetch('/api/v1/nodes?' + q);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  const nodes = data.items || [];
  state.page = Number(data.page || 1); state.pages = Number(data.pages || 1); state.total = Number(data.total || 0);
  $('#tableSummary').textContent = `${state.total} matching nodes · ${nodes.length} on this page`;
  $('#tablePage').textContent = `Page ${state.page} of ${state.pages}`;
  $('#tablePrev').disabled = state.page <= 1;
  $('#tableNext').disabled = state.page >= state.pages;
  $('#proxyRows').innerHTML = nodes.length ? nodes.map(n => `<tr class="hover:bg-emerald-500/[.025]"><td class="px-5 py-3 font-mono text-xs text-zinc-300">${esc(n.address)}</td><td class="px-4 py-3">${flag(n.country)} <span class="font-semibold">${esc(countryName(n.country))}</span> <span class="text-xs text-zinc-600">(${esc(n.country)})</span><div class="text-xs text-zinc-600">${esc(n.region)} · ${esc(n.city)}</div></td><td class="px-4 py-3"><span class="rounded-lg border border-zinc-800 bg-black/20 px-2 py-1 font-mono text-xs">${esc(n.protocol)}</span></td><td class="px-4 py-3">${networkBadge(n.network)}</td><td class="px-4 py-3">${n.latencyMs == null ? '—' : `${n.latencyMs} ms`}</td><td class="px-4 py-3">${n.reliability == null ? '—' : `${n.reliability}%`}</td><td class="px-4 py-3">${statusBadge(n.status)}</td><td class="px-5 py-3 text-xs text-zinc-500">${n.lastCheck ? new Date(n.lastCheck).toLocaleString() : 'Never'}</td></tr>`).join('') : `<tr><td colspan="8" class="px-5 py-14 text-center text-zinc-500">No nodes match these filters yet.</td></tr>`;
}

for (const [id,key] of [['regionSelect','region'],['countrySelect','country'],['protocolSelect','protocol'],['networkTypeSelect','networkType'],['statusSelect','status']]) {
  $('#'+id)?.addEventListener('change', e => { state[key]=e.target.value; syncSelects(); loadProxies({resetPage:true}); });
}
$('#reloadBtn').onclick = async () => { await loadStats(); await loadProxies(); };
$('#clearFilters').onclick = () => { Object.assign(state,{region:'',country:'',protocol:'',networkType:'',status:'online',page:1}); syncSelects(); loadProxies({resetPage:true}); };
$('#tablePrev').onclick=()=>{if(state.page>1){state.page--;loadProxies();}};
$('#tableNext').onclick=()=>{if(state.page<state.pages){state.page++;loadProxies();}};
$('#tablePageSize').onchange=e=>{state.pageSize=Number(e.target.value||50);state.page=1;loadProxies({resetPage:true});};
try { await loadStats(); await loadProxies(); }
catch (e) { $('#healthPill').textContent = 'API unavailable'; console.error(e); }
setInterval(async () => { try { await loadStats(); await loadProxies(); } catch {} }, 30000);
