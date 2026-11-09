/* vpngate-agg 前端。零依赖原生 JS：
 * 整套打进 Go 二进制（go:embed），没有任何外部 CDN 依赖，
 * 因此 CSP 可以只允许 'self' 并且禁掉 inline script —— 这是最硬的 XSS 防线。
 * 上游给的字符串（节点名、运营商、留言）一律用 textContent 写入，不走 innerHTML。
 */
'use strict';

/* ============================ 小工具 ============================ */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const SVG_NS = 'http://www.w3.org/2000/svg';

// SVG 元素必须用 createElementNS 创建，而且 class 要用 setAttribute
// （SVGElement.className 是 SVGAnimatedString，直接赋值不管用）。
function sv(tag, attrs = {}, children = []) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'text') node.textContent = String(v);
    else node.setAttribute(k, String(v));
  }
  (Array.isArray(children) ? children : [children]).forEach((c) => { if (c) node.appendChild(c); });
  return node;
}

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = String(v);
    else if (k === 'dataset') Object.assign(node.dataset, v);
    // style 必须逐条用 CSSOM 写：CSP 是 style-src 'self'，setAttribute('style') 会被浏览器拒掉。
    else if (k === 'style') {
      for (const decl of String(v).split(';')) {
        const i = decl.indexOf(':');
        if (i < 0) continue;
        const prop = decl.slice(0, i).trim();
        const val = decl.slice(i + 1).trim();
        if (prop && val) node.style.setProperty(prop, val);
      }
    }
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of [].concat(children)) {
    if (c === null || c === undefined || c === false) continue;
    node.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
  }
  return node;
}

function debounce(fn, ms) {
  let t = null;
  return function (...args) {
    clearTimeout(t);
    t = setTimeout(() => fn.apply(this, args), ms);
  };
}

const LEVEL_ZH = {
  stable: '稳定', reachable: '可达', unknown: '未知', flaky: '抖动', down: '不可达', untested: '未测',
};
const SERVICE_ZH = {
  'openvpn': 'OpenVPN 应答', 'softether': 'SoftEther 应答', 'responded': '有应答',
  'no-reply': '连接成功但未应答', 'tcp-open': 'TCP 可达', 'refused': '端口拒绝(RST)',
  'timeout': '握手超时', 'unreachable': '网络不可达', 'blocked': '本地地址策略拦截', 'unknown': '未测',
};
const PURITY_ZH = { excellent: '极纯净', good: '纯净', fair: '一般', poor: '较差', bad: '脏' };
const JOB_ZH = { refresh: '刷新源', probe: '连通测试', purity: '纯净度扫描' };

function fmtMs(ms) {
  ms = Number(ms) || 0;
  if (ms <= 0) return '–';
  if (ms < 1000) return ms + ' ms';
  return (ms / 1000).toFixed(2) + ' s';
}

function fmtMbps(bps) {
  bps = Number(bps) || 0;
  if (bps <= 0) return '–';
  const mbps = bps / 1e6;
  if (mbps >= 1000) return (mbps / 1000).toFixed(1) + ' Gbps';
  if (mbps >= 1) return mbps.toFixed(0) + ' Mbps';
  return (bps / 1e3).toFixed(0) + ' Kbps';
}

// Go 的零值时间会序列化成 "0001-01-01T00:00:00Z" —— 字符串是真的，
// 只判 `t ?` 不够，界面上就会出现「上次落盘 0001-01-01」。
function hasTime(t) {
  if (!t) return false;
  const d = new Date(t);
  return !isNaN(d.getTime()) && d.getUTCFullYear() >= 1971;
}

function fmtRel(t) {
  if (!hasTime(t)) return '–';
  const d = new Date(t);
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 0) return '刚刚';
  if (s < 60) return s + ' 秒前';
  if (s < 3600) return Math.round(s / 60) + ' 分钟前';
  if (s < 86400) return Math.round(s / 3600) + ' 小时前';
  if (s < 86400 * 30) return Math.round(s / 86400) + ' 天前';
  return d.toISOString().slice(0, 10);
}

function fmtTime(t) {
  if (!t) return '–';
  const d = new Date(t);
  if (isNaN(d.getTime())) return '–';
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// flag 把两位国家码换成 emoji 旗子。空码返回地球。
function flag(code) {
  const c = (code || '').toUpperCase();
  if (c.length !== 2 || c < 'A' || c > 'Z') return '🌐';
  const A = 0x1f1e6;
  return String.fromCodePoint(A + c.charCodeAt(0) - 65, A + c.charCodeAt(1) - 65);
}

function num(n) {
  n = Number(n) || 0;
  return n.toLocaleString('en-US');
}

/* ============================ 会话与请求 ============================ */

const state = {
  csrf: '',
  authed: false,
  authDisabled: false,
  username: '',
  stats: null,
  nodes: [],
  total: 0,
  offset: 0,
  limit: 100,
  sort: 'recommend',
  desc: false,
  pingSource: 'best',
  selected: new Set(),
  drawerId: null,
  detail: null,
  sse: null,
  job: null,        // {kind, done, total, ok}
  jobSeq: 0,
  timer: null,
  view: 'overview',   // 当前页：overview 总览 / nodes 节点列表
  nodesDirty: false,  // 在总览页时列表被 SSE 改过，切回节点列表要补拉一次
};

async function api(path, opts = {}) {
  const init = { method: opts.method || (opts.body ? 'POST' : 'GET'), credentials: 'same-origin', headers: {} };
  if (opts.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.headers['X-CSRF-Token'] = state.csrf || '';
    init.body = JSON.stringify(opts.body || {});
  }
  const resp = await fetch(path, init);
  let data = null;
  const ct = resp.headers.get('content-type') || '';
  if (ct.includes('application/json')) {
    data = await resp.json().catch(() => null);
  } else {
    const text = await resp.text();
    data = { ok: resp.ok, text };
  }
  if (resp.status === 401) {
    showLogin(data && data.error ? data.error : '请先登录');
    throw new Error('unauthorized');
  }
  if (!resp.ok || (data && data.ok === false)) {
    throw new Error((data && data.error) || ('HTTP ' + resp.status));
  }
  return data;
}

/* ============================ 提示 ============================ */

function toast(msg, kind = 'info', ms = 4200) {
  const box = $('#toasts');
  if (!box) return;
  const t = el('div', { class: 'toast ' + kind, text: msg });
  box.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0';
    setTimeout(() => t.remove(), 260);
  }, ms);
}

/* ============================ 登录 ============================ */

function showLogin(err) {
  state.authed = false;
  $('#view-app').hidden = true;
  $('#view-login').hidden = false;
  const box = $('#login-error');
  if (err) {
    box.hidden = false;
    box.textContent = err;
  } else {
    box.hidden = true;
  }
  closeSSE();
  setTimeout(() => $('#login-pass').focus(), 60);
}

function showApp() {
  state.authed = true;
  $('#view-login').hidden = true;
  $('#view-app').hidden = false;
  // 先定页面：默认总览，#/nodes 直接进节点列表（刷新后回得来）。
  showView(viewFromHash(), { pushHash: false });
  connectSSE();
  loadStats();
  loadNodes();
}

async function doLogin(ev) {
  ev.preventDefault();
  const btn = $('#login-submit');
  btn.disabled = true;
  btn.textContent = '登录中…';
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: $('#login-user').value.trim(), password: $('#login-pass').value }),
    });
    const data2 = await res.json().catch(() => ({}));
    if (!res.ok || data2.ok === false) {
      showLogin(data2.error || ('登录失败 (HTTP ' + res.status + ')'));
      return;
    }
    state.csrf = data2.csrf || '';
    state.username = data2.username || '';
    $('#login-pass').value = '';
    await boot();
  } catch (e) {
    showLogin(e.message === 'unauthorized' ? '登录失败' : e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '登录';
  }
}

/* ============================ 启动 ============================ */

async function boot() {
  let s;
  try {
    s = await api('/api/session');
  } catch (e) {
    if (e.message !== 'unauthorized') toast('读取会话失败: ' + e.message, 'err');
    return;
  }
  state.authDisabled = !!s.auth_disabled;
  state.csrf = s.csrf || '';
  state.username = s.username || '';
  if (s.title) $('#brand-title').textContent = s.title;
  if (!s.authed) { showLogin(''); return; }
  showApp();
}

/* ============================ SSE ============================ */

function closeSSE() {
  if (state.sse) { state.sse.close(); state.sse = null; }
  setConn('idle', '未连接');
}

function setConn(kind, text) {
  const n = $('#conn-state');
  if (!n) return;
  n.className = 'conn conn-' + kind;
  n.textContent = text;
}

function connectSSE() {
  closeSSE();
  const es = new EventSource('/api/events');
  state.sse = es;
  es.onopen = () => setConn('live', '实时');
  es.onerror = () => setConn('bad', '重连中');
  es.onmessage = (ev) => {
    let e;
    try { e = JSON.parse(ev.data); } catch { return; }
    handleEvent(e);
  };
}

function handleEvent(e) {
  const d = e.data || {};
  switch (e.type) {
    case 'hello':
      setConn('live', '实时');
      if (d.running && d.running.length) startJob(d.running[0], {});
      break;
    case 'refresh:start':
      startJob('refresh', { total: 0 });
      break;
    case 'probe:start':
      startJob('probe', { total: d.total || 0 });
      break;
    case 'purity:start':
      startJob('purity', { total: d.total || 0 });
      break;
    case 'probe:progress':
    case 'purity:progress':
      updateJob(e.type.split(':')[0], d);
      break;
    case 'purity:result':
      state.puritySeen = (state.puritySeen || 0) + 1;
      if (state.puritySeen % 5 === 0) scheduleReloadNodes(1500);
      break;
    case 'refresh:done':
    case 'probe:done':
    case 'purity:done': {
      const kind = e.type.split(':')[0];
      finishJob(kind, d);
      if (d.ok === false && d.err) toast(JOB_ZH[kind] + '失败: ' + d.err, 'err', 6500);
      else if (kind !== 'probe') toast(JOB_ZH[kind] + '完成', 'ok', 2600);
      loadStats();
      scheduleReloadNodes();
      break;
    }
    case 'probe:one':
      loadNodes();
      break;
    case 'probe:progress-lite':
      break;
    default:
      break;
  }
}

function startJob(kind, info) {
  state.job = { kind, total: info.total || 0, done: 0, ok: 0 };
  _jobStarted = Date.now();
  const bar = $('#progressbar');
  bar.hidden = false;
  $('#progress-bar').style.width = '0%';
  $('#progress-text').textContent = JOB_ZH[kind] + ' 进行中…';
  state.jobSeq++;
}

function updateJob(kind, d) {
  if (!state.job || state.job.kind !== kind) return;
  state.job.done = d.done || 0;
  state.job.ok = d.ok || 0;
  if (d.total) state.job.total = d.total;
  const pct = state.job.total ? Math.min(100, (100 * state.job.done) / state.job.total) : 0;
  $('#progress-bar').style.width = pct.toFixed(1) + '%';
  const eta = state.job.total && state.job.done > 2
    ? Math.round((Date.now() - jobStartAt()) * (state.job.total - state.job.done) / state.job.done / 1000)
    : 0;
  $('#progress-text').textContent =
    `${JOB_ZH[kind]} ${state.job.done}/${state.job.total}` +
    (kind === 'probe' ? ` · 可达 ${state.job.ok}` : (d.ok !== undefined ? ` · 成功 ${d.ok}` : '')) +
    (eta > 0 ? ` · 约剩 ${eta}s` : '') +
    (d.last ? ` · ${d.last}` : '');
  if (kind === 'probe' && state.job.done % 12 === 0) scheduleReloadNodes(2500);
}

let _jobStarted = Date.now();
function jobStartAt() { return _jobStarted; }

function finishJob(kind, d) {
  if (state.job && state.job.kind !== kind) return;
  state.job = null;
  $('#progressbar').hidden = true;
  _jobStarted = Date.now();
  renderPipeline();
}

/* ============================ 统计与流水线 ============================ */

async function loadStats() {
  try {
    const data = await api('/api/stats');
    state.stats = data;
    renderStats();
    renderPipeline();
    renderMap();
    fillCountryOptions(data.countries || []);
  } catch (e) {
    if (e.message !== 'unauthorized') toast('统计读取失败: ' + e.message, 'err');
  }
}

function renderStats() {
  const s = (state.stats && state.stats.stats) || {};
  $('#m-nodes').textContent = num(s.nodes || 0);
  $('#m-nodes-sub').textContent = `池内 ${num(s.pool_nodes || 0)} · 本轮名单 ${num(s.fresh_nodes || 0)} · 已测 ${num((s.alive || 0) + (s.down || 0) + (s.unknown || 0))}`;
  $('#m-alive').textContent = num(s.alive || 0);
  $('#m-alive-sub').textContent = `不确定 ${num(s.unknown || 0)} · 不可达 ${num(s.down || 0)} · 未测 ${num(s.untested || 0)}`;
  $('#m-ping').textContent = fmtMs(s.median_ping_ms || 0);
  $('#m-ping-sub').textContent = `TCP ${num(s.tcp || 0)} · UDP ${num(s.udp || 0)}`;
  $('#m-purity').textContent = s.median_purity ? s.median_purity + ' 分' : '未测';
  $('#m-purity-sub').textContent = `已查 ${num(s.purity_checked || 0)} 个 IP` + (hasTime(s.purity_at) ? ` · ${fmtRel(s.purity_at)}` : '');
  $('#m-res').textContent = (s.residential_share ? s.residential_share.toFixed(1) : '0') + '%';
  // 家宽必须说清证据强度：来源认定（外部来源给了类型）和推导（ASN / 运营商名）
  // 差一个可信度级别；「类型未知」更要显式写出来，否则会被读成「都不是家宽」。
  {
    const bits = [];
    if (s.residential_verified) bits.push(`来源认定 ${num(s.residential_verified)}`);
    if (s.residential_derived) bits.push(`推导 ${num(s.residential_derived)}`);
    if (s.purity_type_unknown) bits.push(`类型未知 ${num(s.purity_type_unknown)}`);
    const speed = `官方均速 ${(s.avg_upstream_mbps || 0).toFixed(0)} Mbps`;
    $('#m-res-sub').textContent = bits.length ? bits.join(' · ') + ' · ' + speed : speed;
  }
  $('#m-countries').textContent = num(s.countries || 0);
  $('#m-countries-sub').textContent = `最近探测 ${hasTime(s.probed_at) ? fmtRel(s.probed_at) : '从未'}`;
}

// basisLabel 把后端的类型依据（type_source）翻成人话。
// 来源名（ipinfo 之类）和推导标记（derived:asn:AS4766）是两种可信度，别混着显示。
function basisLabel(src) {
  const s = String(src || '');
  if (s.startsWith('derived:asn:')) return '类型推导：' + s.slice(12) + ' 是消费级宽带运营商，且没有任何机房 / 代理 / VPN / Tor 证据';
  if (s.startsWith('derived:isp:')) return '类型推导：运营商名含「' + s.slice(12) + '」且无机房证据（低置信：政企专线用同一个品牌名）';
  if (s) return '类型来自：' + s;
  return '';
}

function renderPipeline() {
  const st = state.stats || {};
  const sources = st.sources_config || [];
  const stats = st.sources || [];
  const box = $('#sources');
  box.textContent = '';
  sources.forEach((cfg, i) => {
    const run = stats.find((s) => s.name === cfg.name) || {};
    const cls = 'source' + (run.err ? ' err' : '');
    const left = el('div', {}, [
      el('b', { text: cfg.label + (cfg.enabled ? '' : '（已关闭）') }),
      el('div', { class: 'url', text: cfg.url || '' }),
      el('div', {
        class: 'stat',
        text: run.err ? '失败: ' + run.err
          : run.nodes !== undefined
            ? `${run.nodes} 节点 · ${run.ms || 0}ms · ${run.via || ''}${run.commit ? ' @' + String(run.commit).slice(0, 8) : ''}`
            : (cfg.enabled ? '本轮还没跑' : ''),
      }),
    ]);
    const badge = cfg.enabled
      ? (run.err ? el('span', { class: 'badge badge-bad', text: '异常' }) : el('span', { class: 'badge badge-ok', text: '正常' }))
      : el('span', { class: 'badge', text: '关闭' });
    box.appendChild(el('div', { class: cls }, [left, badge]));
  });

  // 任务卡片
  const jobs = st.jobs || {};
  const jb = $('#jobs');
  jb.textContent = '';
  for (const kind of ['refresh', 'probe', 'purity']) {
    const j = jobs[kind] || {};
    const running = (st.running || []).includes(kind);
    const done = j.done || 0, total = j.total || 0;
    let pct = total ? Math.min(100, (100 * done) / total) : 0;
    if (j.status === 'done') pct = 100;
    const bar = el('div', { class: 'job-bar' }, [el('i', { style: `width:${pct}%` })]);
    const head = el('div', { class: 'job-top' }, [
      el('span', {}, [
        JOB_ZH[kind],
        el('span', { class: 'muted', text: ' · ' + (running ? '进行中' : (j.status === 'failed' ? '失败' : (j.status === 'cancelled' ? '已取消' : '空闲'))) }),
      ]),
      el('span', { class: 'muted num', text: total ? `${done}/${total}` : (j.status || 'idle') }),
    ]);
    const node = el('div', { class: 'job' }, [
      head, bar,
      // 消息最多两行（CSS 里 clamp），完整内容挂 title：不裁的话一行采集日志能把
      // 整个面板顶到屏幕外，两块面板也就没法在一屏里等高。
      el('div', { class: 'job-msg', title: (j.message || ''), text: (j.message || '') + (hasTime(j.ended_at) ? ` · ${fmtRel(j.ended_at)}` : (hasTime(j.started_at) ? ` · ${fmtRel(j.started_at)}` : '')) }),
    ]);
    if (running) {
      const live = state.job && state.job.kind === kind ? state.job : null;
      if (live) {
        node.querySelector('.job-bar > i').style.width = (live.total ? Math.min(100, (100 * live.done) / live.total) : 5) + '%';
        node.querySelector('.job-top > span:last-child').textContent = live.total ? `${live.done}/${live.total}` : '运行中';
      }
    }
    jb.appendChild(node);
  }
  $('#pipeline-updated').textContent = hasTime(st.last_save) ? '上次落盘 ' + fmtRel(st.last_save) : '';
}

/* ============================ 页面切换（总览 / 节点列表）============================ */

// 只有两个页面，用 hash 手工路由就够：#/ 总览，#/nodes 节点列表。
// 筛选状态留在内存里（不写进 URL），来回切页不用重新筛；SSE 在总览页
// 会跳过整表重绘，切回节点列表时补一次。
const VIEWS = ['overview', 'nodes'];

function viewFromHash() {
  return /^#\/nodes\b/.test(location.hash) ? 'nodes' : 'overview';
}

function nodesVisible() { return !$('#view-nodes').hidden; }

function showView(name, opts = {}) {
  if (!VIEWS.includes(name)) name = 'overview';
  state.view = name;
  $('#view-overview').hidden = name !== 'overview';
  $('#view-nodes').hidden = name !== 'nodes';
  $$('#tabs .tab').forEach((t) => {
    const on = t.dataset.tab === name;
    t.classList.toggle('is-active', on);
    if (on) t.setAttribute('aria-current', 'page'); else t.removeAttribute('aria-current');
  });
  if (opts.pushHash !== false) {
    const want = name === 'nodes' ? '#/nodes' : '#/';
    if (location.hash !== want) location.hash = want;  // 触发 hashchange，showView 幂等
  }
  if (name === 'nodes' && state.nodesDirty) { state.nodesDirty = false; loadNodes(); }
  if (name === 'overview') renderMap();
  window.scrollTo(0, 0);
}

// 卡片点进节点列表：顺手把对应的筛选/排序选好，省一次手工操作。
function cardJump(which) {
  showView('nodes');
  switch (which) {
    case 'alive':
      setMulti('#f-level', ['stable', 'reachable']);
      setSortUI('recommend', false);
      break;
    case 'ping':
      state.pingSource = 'best';
      $('#f-ping-src').value = 'best';
      setSortUI('ping', false);   // 后端把「越大越好」的列归一成同方向，升序就是最好在前
      break;
    case 'purity':
      $('#f-purity-only').checked = true;
      setSortUI('purity', false);
      break;
    case 'res':
      $('#f-residential').checked = true;
      break;
    default:
      break;  // countries：只跳页，不动筛选
  }
  reload();
}

// setSortUI / setMulti 是把「用户操作了筛选控件」这件事同步到 state、控件和表头箭头，
// 三个地方不同步就会出现「下拉框显示按延迟排，表里其实按推荐分排」。
function setSortUI(key, desc) {
  state.sort = key;
  state.desc = desc;
  $('#f-sort').value = key;
  const d = $('#f-dir');
  d.dataset.dir = desc ? 'desc' : 'asc';
  d.textContent = desc ? '↓' : '↑';
  $$('#nodes-table thead th').forEach((x) => { x.classList.remove('sorted'); delete x.dataset.arrow; });
  const th = $('#nodes-table thead th[data-sort="' + key + '"]');
  if (th) {
    th.classList.add('sorted');
    th.dataset.arrow = desc ? '↓' : '↑';
  }
}

function setMulti(sel, values) {
  $$(sel + ' option').forEach((o) => { o.selected = values.includes(o.value); });
}

/* ============================ 国家分布气泡图 ============================ */

// 国家码 → 中心点经纬度（粗略够用）。CSP 是 script-src 'self' 且没有 CDN，地图数据
// 只能自带：世界轮廓 SVG 要 150KB 起，还得清洗非 ISO 区域；这张表几 KB，画「等距柱状
// 投影 + 气泡」足够看清 47 个国家的分布。没坐标的国家不会画在图上，但会在图例里点名，
// 不会悄悄少掉。
const COUNTRY_LL = {
  AD: [1.5, 42.5], AE: [54, 24], AF: [66, 34], AG: [-61.8, 17.1], AL: [20, 41], AM: [45, 40.1], AO: [17.5, -12.3],
  AR: [-64, -34], AT: [14.5, 47.6], AU: [134, -25.5], AZ: [47.4, 40.4], BA: [17.8, 44], BB: [-59.5, 13.2],
  BD: [90.2, 23.9], BE: [4.5, 50.6], BF: [-1.6, 12.4], BG: [25.2, 42.7], BH: [50.6, 26.1], BI: [29.9, -3.4],
  BJ: [2.3, 9.6], BN: [114.6, 4.5], BO: [-64.7, -16.7], BR: [-51.9, -14.2], BS: [-77.5, 24.2], BT: [90.4, 27.5],
  BW: [24.7, -22.3], BY: [28, 53.5], BZ: [-88.8, 17.2], CA: [-106.2, 56.1], CD: [23.7, -2.9], CF: [20.9, 6.6],
  CG: [15.8, -0.2], CH: [8.2, 46.8], CI: [-5.5, 7.6], CL: [-71.5, -37.6], CM: [12.8, 5.7], CN: [104.2, 35.9],
  CO: [-73.8, 4.6], CR: [-84, 9.9], CU: [-79.5, 21.9], CV: [-23.6, 15.1], CY: [33.4, 35.1], CZ: [15.4, 49.8],
  DE: [10.5, 51.2], DJ: [43.3, 11.8], DK: [9.3, 56.2], DO: [-70.7, 19], DZ: [2.6, 28.2], EC: [-78.5, -1.8],
  EE: [25.6, 58.7], EG: [29.9, 26.8], ER: [38.9, 15.2], ES: [-3.7, 40.3], ET: [39.9, 9.1], FI: [26, 64.1],
  FJ: [178, -17.8], FK: [-59.9, -51.7], FR: [2.5, 46.7], GA: [11.7, -0.8], GB: [-1.5, 52.9], GE: [43.4, 42.2],
  GH: [-1.2, 7.9], GL: [-42.6, 71.7], GM: [-16.5, 13.4], GN: [-10.9, 10.4], GQ: [10.4, 1.7], GR: [23.7, 39.1],
  GT: [-90.4, 15.7], GU: [144.8, 13.4], GW: [-15.2, 12.2], GY: [-58.9, 4.9], HK: [114.2, 22.4], HN: [-86.5, 15.2],
  HR: [15.5, 45.6], HT: [-72.3, 19.1], HU: [19.5, 47.2], ID: [118, -2.5], IE: [-8.1, 53.3], IL: [35, 31.5],
  IN: [78.9, 22.4], IQ: [43.7, 33.2], IR: [53.7, 32.4], IS: [-18.6, 65], IT: [12.6, 42.5], JM: [-77.3, 18.1],
  JO: [36.2, 30.8], JP: [138.3, 36.2], KE: [37.9, 0.2], KG: [74.8, 41.4], KH: [105, 12.8], KP: [127.2, 40.2],
  KR: [127.8, 36.5], KW: [47.5, 29.4], KZ: [67, 48.2], LA: [103.7, 19.9], LB: [35.9, 33.9], LI: [9.6, 47.1],
  LC: [-61, 13.9], LK: [80.7, 7.9], LR: [-9.4, 6.5], LT: [23.9, 55.4], LU: [6.1, 49.8], LV: [25.5, 56.9], LY: [17.9, 27],
  MA: [-7.1, 31.8], MD: [28.5, 47.2], ME: [19.4, 42.7], MG: [46.9, -19.1], MK: [21.7, 41.6], ML: [-3.5, 17.6],
  MM: [96, 21.1], MN: [103.8, 46.2], MO: [113.5, 22.2], MR: [-10.3, 20.5], MT: [14.4, 35.9], MU: [57.6, -20.3],
  MV: [73.4, 3.2], MW: [34.3, -13.3], MX: [-102.5, 23.9], MY: [102, 3.9], MZ: [35.5, -18.7], NA: [18.5, -22.9],
  NE: [8.5, 17.4], NG: [8.3, 9.1], NI: [-85.2, 12.9], NL: [5.3, 52.2], NO: [8.5, 60.5], NP: [84.1, 28.4],
  NZ: [172.5, -41.8], OM: [56, 21], PA: [-80.4, 8.7], PE: [-75, -9.9], PG: [143.6, -6.3], PH: [122, 12.9],
  PK: [69.3, 30.4], PL: [19.4, 52.1], PR: [-66.4, 18.2], PT: [-8.2, 39.6], PY: [-58.4, -23.3], QA: [51.2, 25.3],
  RO: [25, 45.9], RS: [20.9, 44.1], RU: [95, 60], RW: [29.9, -1.9], SA: [45, 24], SD: [30.2, 15.6],
  SE: [16.8, 62], SG: [103.8, 1.35], SI: [14.8, 46.2], SK: [19.7, 48.7], SL: [-11.8, 8.5], SN: [-14.5, 14.5],
  SO: [45.8, 5.2], SR: [-56, 4.2], SS: [30.2, 7.6], ST: [6.6, 0.2], SY: [38.5, 35], SZ: [31.5, -26.5],
  TD: [18.7, 15.5], TG: [1.1, 8.6], TH: [101, 15.6], TJ: [71, 38.9], TM: [59.6, 39.3], TN: [9.5, 34],
  TR: [35.2, 39], TW: [121, 23.7], UA: [31.2, 49.2], UG: [32.6, 1.4], US: [-98.4, 39.5], UY: [-56, -32.8],
  UZ: [64, 41.4], VE: [-66.6, 7.1], VN: [106.3, 16.4], YE: [47.7, 15.9], ZA: [25, -29.2], ZM: [26.4, -13.5],
  ZW: [29.8, -19],
};

// 没有轮廓数据，靠几个大洲名把人眼定位住。位置是空的海洋，不会跟气泡重叠。
const CONTINENT_HINTS = [
  { text: '北美', lon: -100, lat: 52 },
  { text: '南美', lon: -60, lat: -8 },
  { text: '欧洲', lon: 12, lat: 62 },
  { text: '非洲', lon: 20, lat: -16 },
  { text: '亚洲', lon: 92, lat: 66 },
  { text: '大洋洲', lon: 140, lat: -38 },
];

const MAP_W = 720;
const MAP_H = 360;

// 每个指标决定「按什么上色」和「tooltip 怎么写」。气泡大小恒为节点数 ——
// 大小换成数值的话，一个国家 2 个节点和 700 个节点在图上就不成比例了。
// norm() 的第二个参数是各指标的取值上限（ctx，renderMap 里按有坐标的国家算），
// 计数型指标用它做归一化；都开平方，否则 US 一个点就把其他国家染成同一种红。
const MAP_METRICS = {
  nodes: {
    label: '节点数',
    value: (c) => c.nodes || 0,
    norm: (c, ctx) => Math.sqrt((c.nodes || 0) / ctx.nodes),
    detail: (c) => `${num(c.nodes || 0)} 个节点`,
    short: (c) => num(c.nodes || 0),
  },
  alive: {
    label: '可达数',
    value: (c) => c.alive || 0,
    norm: (c, ctx) => Math.sqrt((c.alive || 0) / ctx.alive),
    detail: (c) => `可达 ${num(c.alive || 0)} 个/${num(c.nodes || 0)} 个节点` +
      (c.nodes ? `（${Math.round((100 * (c.alive || 0)) / c.nodes)}%）` : ''),
    short: (c) => num(c.alive || 0),
  },
  res: {
    label: '家宽数',
    value: (c) => c.residential || 0,
    norm: (c, ctx) => Math.sqrt((c.residential || 0) / ctx.res),
    detail: (c) => `志愿者家宽 ${num(c.residential || 0)} 个/${num(c.nodes || 0)} 个节点` +
      (c.nodes ? `（${Math.round((100 * (c.residential || 0)) / c.nodes)}%）` : ''),
    short: (c) => num(c.residential || 0),
  },
  ping: {
    label: '中位延迟',
    value: (c) => c.med_ping_ms || 0,
    // 延迟是「越小越好」，所以上色反过来；1200ms 以上一律按最差算。
    norm: (c) => (c.med_ping_ms ? Math.max(0, 1 - Math.min(c.med_ping_ms, 1200) / 1200) : -1),
    // 标签取「前六名」也必须取最快的那六个，否则这个指标下贴出来的是最慢的国家。
    rank: 'asc',
    detail: (c) => (c.med_ping_ms ? '中位延迟 ' + fmtMs(c.med_ping_ms) : '没测过延迟'),
    short: (c) => (c.med_ping_ms ? fmtMs(c.med_ping_ms) : '–'),
  },
};

let mapMetric = (() => {
  try {
    const v = localStorage.getItem('vpa-map-metric');
    return MAP_METRICS[v] ? v : 'nodes';
  } catch { return 'nodes'; }
})();

const mapPx = (lon) => ((lon + 180) / 360) * MAP_W;
const mapPy = (lat) => ((90 - lat) / 180) * MAP_H;

// 上色用 hsl() 直接写在 fill 属性上：CSP 只禁 inline style 属性，
// 呈现属性不受限，而且不用为四个指标各写五级 CSS 规则。
function mapColor(t) {
  const v = Math.max(0, Math.min(1, t));
  const hue = 18 + v * 150;      // 18（偏红）→ 168（偏青绿）
  const light = 46 + v * 12;
  return `hsl(${hue.toFixed(0)} 68% ${light.toFixed(0)}%)`;
}

function setMapMetric(name) {
  if (!MAP_METRICS[name]) return;
  mapMetric = name;
  $$('#map-metric .seg-btn').forEach((b) => b.classList.toggle('is-active', b.dataset.metric === name));
  try { localStorage.setItem('vpa-map-metric', name); } catch { /* 隐私模式忽略 */ }
  renderMap();
}

function renderMap() {
  const box = $('#map');
  if (!box) return;
  const all = (state.stats && state.stats.countries) || [];
  const m = MAP_METRICS[mapMetric] || MAP_METRICS.nodes;

  box.textContent = '';
  const svg = sv('svg', {
    class: 'map-svg',
    viewBox: `0 0 ${MAP_W} ${MAP_H}`,
    preserveAspectRatio: 'xMidYMid meet',
    role: 'img',
    'aria-label': '按国家的节点分布气泡图',
  });
  svg.appendChild(sv('rect', { class: 'map-bg', x: 0, y: 0, width: MAP_W, height: MAP_H }));
  // 底图轮廓来自 world-map.js（Natural Earth 110m，构建时压成 SVG path 打进二进制）。
  // 没有它就只有网格 + 气泡，看着不像地图；文件缺失（旧缓存之类）时跳过，别整个画不出来。
  const world = window.VPA_WORLD || {};
  if (world.land) svg.appendChild(sv('path', { class: 'map-land', d: world.land }));
  if (world.borders) svg.appendChild(sv('path', { class: 'map-border', d: world.borders }));
  for (let lon = -150; lon <= 150; lon += 30) {
    svg.appendChild(sv('line', { class: 'map-grid', x1: mapPx(lon), y1: 0, x2: mapPx(lon), y2: MAP_H }));
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    svg.appendChild(sv('line', { class: 'map-grid', x1: 0, y1: mapPy(lat), x2: MAP_W, y2: mapPy(lat) }));
  }
  svg.appendChild(sv('line', { class: 'map-equator', x1: 0, y1: mapPy(0), x2: MAP_W, y2: mapPy(0) }));
  CONTINENT_HINTS.forEach((c) => {
    svg.appendChild(sv('text', { class: 'map-continent', x: mapPx(c.lon), y: mapPy(c.lat), 'text-anchor': 'middle', text: c.text }));
  });

  const drawn = all.filter((c) => c.code && c.code !== '?' && COUNTRY_LL[c.code]);
  const noCoord = all.filter((c) => c.code && c.code !== '?' && !COUNTRY_LL[c.code]);
  const unknown = all.find((c) => c.code === '?');
  const maxNodes = Math.max(1, ...drawn.map((c) => c.nodes || 0));
  // 计数型指标（可达数 / 家宽数）各自按有坐标国家的最大值归一化：可达数永远≤
  // 节点数，共用节点数的最大值会把颜色全挤到冷端，看不出差异。
  const maxOf = (key) => Math.max(1, ...drawn.map((c) => c[key] || 0));
  const ctx = { nodes: maxNodes, alive: maxOf('alive'), res: maxOf('residential') };

  // 大的后画，小的先画，否则大国气泡把小国盖住看不见。
  drawn.sort((a, b) => (a.nodes || 0) - (b.nodes || 0));
  drawn.forEach((c) => {
    const ll = COUNTRY_LL[c.code];
    const r = 3.2 + 21 * Math.sqrt((c.nodes || 0) / maxNodes);
    const t = m.norm(c, ctx);
    const g = sv('g', { class: 'map-dot' + (t < 0 ? ' na' : ''), 'data-code': c.code });
    g.appendChild(sv('title', {
      text: `${c.name || c.code} (${c.code}) · ${num(c.nodes || 0)} 节点 · ` +
        `可达 ${num(c.alive || 0)} · 家宽 ${num(c.residential || 0)} · 中位纯净度 ${c.med_purity || 0} · ` +
        (c.med_ping_ms ? '中位延迟 ' + fmtMs(c.med_ping_ms) : '没测过延迟'),
    }));
    const dot = { cx: mapPx(ll[0]), cy: mapPy(ll[1]), r };
    if (t >= 0) dot.fill = mapColor(t);   // t<0（这个指标没有数据）交给 CSS 的 .na 上色
    g.appendChild(sv('circle', dot));
    svg.appendChild(g);
  });

  // 只给当前指标前六名贴标签：全贴就糊成一片了。
  // 四个指标现在都是计数（节点数 / 可达数 / 家宽数）或极值（延迟），按取值
  // 排就天然先给大国贴标签，不再需要以前那种「节点数 ≥5」的门槛。
  const hasCode = (c) => c.code && c.code !== '?' && COUNTRY_LL[c.code];
  // norm() 返回负数 = 这个指标对这个国家没数据（比如从没测过延迟），
  // 不能参与排名：否则按延迟升序贴出来的前六名全是「没测过延迟」。
  const hasData = (c) => m.norm(c, ctx) >= 0;
  let ranked = all.filter((c) => hasCode(c) && hasData(c));
  const asc = m.rank === 'asc';
  const top = ranked.slice().sort((a, b) => (asc ? m.value(a) - m.value(b) : m.value(b) - m.value(a))).slice(0, 6);
  // 标签要防重叠：欧洲那一串国家挨得很近，全用「正上方」这一种摆法就会
  // 叠成一团糊字（试过一次，DE/SE/FI 的标签互相压在对方气泡上）。
  // 这里按「上 → 下 → 右 → 左」找第一个不撞已有气泡也不撞别的标签的位置，
  // 四个位置都被占就放弃这个标签 —— 少一个标签比糊一片好。
  const boxOf = (x, y, r) => ({ x0: x - r, x1: x + r, y0: y - r, y1: y + r });
  const placed = drawn.map((c) => {
    const ll = COUNTRY_LL[c.code];
    return boxOf(mapPx(ll[0]), mapPy(ll[1]), 3.2 + 21 * Math.sqrt((c.nodes || 0) / maxNodes));
  });
  const hits = (b) => placed.some((p) => !(b.x1 < p.x0 || b.x0 > p.x1 || b.y1 < p.y0 || b.y0 > p.y1));
  top.forEach((c) => {
    const ll = COUNTRY_LL[c.code];
    const cx = mapPx(ll[0]);
    const cy = mapPy(ll[1]);
    const r = 3.2 + 21 * Math.sqrt((c.nodes || 0) / maxNodes);
    const txt = `${c.code} ${m.short(c)}`;
    const w = txt.length * 5.6 + 4;
    const cand = [
      { x: cx, y: cy - r - 5, a: 'middle' },
      { x: cx, y: cy + r + 12, a: 'middle' },
      { x: cx + r + 5, y: cy + 3, a: 'start' },
      { x: cx - r - 5, y: cy + 3, a: 'end' },
    ];
    for (const k of cand) {
      const x0 = k.a === 'middle' ? k.x - w / 2 : (k.a === 'start' ? k.x : k.x - w);
      const b = { x0, x1: x0 + w, y0: k.y - 10, y1: k.y + 3 };
      if (b.x0 < 3 || b.x1 > MAP_W - 3 || b.y0 < 3 || b.y1 > MAP_H - 3) continue;
      if (hits(b)) continue;
      placed.push(b);
      svg.appendChild(sv('text', { class: 'map-label', x: k.x, y: k.y, 'text-anchor': k.a, text: txt }));
      return;
    }
  });
  box.appendChild(svg);

  renderMapRank(ranked.slice().sort((a, b) => m.value(b) - m.value(a)), m, mapMetric === 'ping' ? 'asc' : 'desc', ctx);

  const legend = $('#map-legend');
  if (legend) {
    legend.textContent = '';
    legend.appendChild(el('span', { class: 'lg-key', text: m.label }));
    const sw = el('span', { class: 'lg-scale' });
    [0, 0.25, 0.5, 0.75, 1].forEach((t) => sw.appendChild(el('span', { class: 'lg-swatch', style: `background:${mapColor(t)}` })));
    legend.appendChild(sw);
    const biggest = drawn.slice(-1)[0];
    // 计数型指标（可达数 / 家宽数）的颜色没有 0-100% 那种天然刻度，标出
    // 「这个指标最多的是谁」当地标，否则深浅读不出量级。
    const scaleTop = drawn.reduce((a, c) => (!a || m.value(c) > m.value(a) ? c : a), null);
    const scaleNote = (mapMetric === 'alive' || mapMetric === 'res') && scaleTop
      ? ` · 颜色按${m.label}，最多 ${scaleTop.name || scaleTop.code} ${num(m.value(scaleTop))} 个`
      : '';
    legend.appendChild(el('span', {
      text: `气泡大小 = 节点数` + (biggest ? ` · 最多 ${biggest.name || biggest.code} ${num(biggest.nodes)} 个` : '') +
        scaleNote + ` · 共 ${num(drawn.length)} 个国家`,
    }));
    if (unknown && unknown.nodes) legend.appendChild(el('span', { text: `没有国家码的节点 ${num(unknown.nodes)} 个（不画在图上）` }));
    if (noCoord.length) {
      legend.appendChild(el('span', {
        class: 'lg-warn',
        text: `${noCoord.length} 个国家没有坐标画不出来：${noCoord.map((c) => c.code).join(' ')}`,
      }));
    }
  }
}

// renderMapRank 把当前指标的国家排行画成可点的小条：地图是 2:1 的，面板比它高
// 时地图只能居中，中间那段空白正好放它；顺带给键盘一条「按国家筛」的路
//（SVG 气泡本身不做 focus，靠这几行补上）。
function renderMapRank(list, m, order, ctx) {
  const box = $('#map-rank');
  if (!box) return;
  box.textContent = '';
  const sorted = list.slice().sort((a, b) => (order === 'asc' ? m.value(a) - m.value(b) : m.value(b) - m.value(a)));
  const take = sorted.slice(0, 8);
  if (!take.length) return;
  // 条长按「这一指标下的取值」给，延迟取负向（越快条越长），否则条长会跟颜色打架。
  const vals = take.map((c) => Math.max(0, m.norm(c, ctx)));
  const vmax = Math.max(...vals, 1e-9);
  take.forEach((c, i) => {
    const pct = Math.max(3, Math.round((100 * vals[i]) / vmax));
    box.appendChild(el('div', {
      class: 'rank-row', dataset: { code: c.code }, title: m.detail(c) + ' · 点一下按这个国家筛',
    }, [
      el('span', { class: 'rank-code', text: c.code }),
      el('span', {}, [
        el('span', { class: 'rank-name', text: c.name || c.code }),
        el('span', { class: 'rank-bar' }, [el('i', { style: `width:${pct}%` })]),
      ]),
      el('span', { class: 'rank-val', text: m.short(c) }),
    ]));
  });
}

// 图上点一个国家：把国家筛选设成它（只选这一个），跳节点列表。
function applyCountryFilter(code) {
  const sel = $('#f-country');
  setMulti('#f-country', [code]);
  showView('nodes');
  reload();
  toast(`已按${code === '?' ? '未知地区' : '国家 ' + code} 筛选`, 'info', 2600);
}

function fillCountryOptions(countries) {
  const sel = $('#f-country');
  const keep = Array.from(sel.selectedOptions).map((o) => o.value);
  sel.textContent = '';
  countries.forEach((c) => {
    const code = c.code || '?';
    const label = `${code === '?' ? '未知地区' : flag(code) + ' ' + code} (${c.nodes})`;
    sel.appendChild(el('option', { value: code, text: label }));
  });
  if (keep.length) {
    Array.from(sel.options).forEach((o) => { if (keep.includes(o.value)) o.selected = true; });
  }
}

/* ============================ 列表 ============================ */

function currentFilters() {
  const q = (s) => (s || '').trim();
  const multi = (id) => Array.from($(id).selectedOptions).map((o) => o.value).filter(Boolean);
  const p = new URLSearchParams();
  const text = q($('#search').value);
  if (text) p.set('q', text);
  const countries = multi('#f-country');
  if (countries.length) p.set('country', countries.join(','));
  const protos = multi('#f-proto');
  if (protos.length) p.set('proto', protos.join(','));
  const levels = multi('#f-level');
  if (levels.length) p.set('level', levels.join(','));
  const minP = q($('#f-min-purity').value);
  if (minP) p.set('min_purity', minP);
  const maxPing = q($('#f-max-ping').value);
  if (maxPing) p.set('max_ping', maxPing);
  if ($('#f-residential').checked) p.set('residential', '1');
  if ($('#f-fresh').checked) p.set('fresh', '1');
  if ($('#f-purity-only').checked) p.set('purity_only', '1');
  p.set('sort', state.sort);
  p.set('dir', state.desc ? 'desc' : 'asc');
  p.set('ping_source', state.pingSource);
  p.set('offset', state.offset);
  p.set('limit', state.limit);
  return p;
}

function filterSummary() {
  const out = [];
  const push = (k, v, clear) => out.push({ k, v, clear });
  const text = $('#search').value.trim();
  if (text) push('搜索', text, () => { $('#search').value = ''; });
  Array.from($('#f-country').selectedOptions).forEach((o) => push('国家', o.value, () => { o.selected = false; }));
  Array.from($('#f-proto').selectedOptions).forEach((o) => push('协议', o.value.toUpperCase(), () => { o.selected = false; }));
  Array.from($('#f-level').selectedOptions).forEach((o) => push('状态', LEVEL_ZH[o.value] || o.value, () => { o.selected = false; }));
  if ($('#f-min-purity').value) push('纯净度≥', $('#f-min-purity').value, () => { $('#f-min-purity').value = ''; });
  if ($('#f-max-ping').value) push('延迟≤', $('#f-max-ping').value + 'ms', () => { $('#f-max-ping').value = ''; });
  if ($('#f-residential').checked) push('只看', '志愿者家宽', () => { $('#f-residential').checked = false; });
  if ($('#f-fresh').checked) push('只看', '本轮官方名单', () => { $('#f-fresh').checked = false; });
  if ($('#f-purity-only').checked) push('只看', '已有纯净度结论', () => { $('#f-purity-only').checked = false; });
  return out;
}

function renderChips() {
  const box = $('#active-chips');
  box.textContent = '';
  filterSummary().forEach((c) => {
    box.appendChild(el('span', { class: 'chip chip-solid' }, [
      el('span', { class: 'muted', text: c.k }),
      el('b', { text: c.v }),
      el('button', { title: '移除', text: '✕', onclick: () => { c.clear(); reload(); } }),
    ]));
  });
}

const scheduleReloadNodes = debounce(() => loadNodes(), 260);

async function loadNodes() {
  // 总览页不重绘整表：一轮探测能推上百次更新，看不见的表格没必要跟着重排。
  // 标个脏标记，切回节点列表时补一次。
  if (!nodesVisible()) { state.nodesDirty = true; return; }
  const body = $('#nodes-body');
  if (!body.dataset.loading) {
    body.dataset.loading = '1';
    body.textContent = '';
    for (let i = 0; i < 6; i++) {
      const tr = el('tr', { class: 'skeleton' });
      for (let c = 0; c < 11; c++) tr.appendChild(el('td', {}, [el('span')]));
      body.appendChild(tr);
    }
  }
  try {
    const data = await api('/api/nodes?' + currentFilters().toString());
    state.nodes = data.items || [];
    state.total = data.total || 0;
    renderTable();
    renderPager();
    renderChips();
  } catch (e) {
    if (e.message === 'unauthorized') return;
    toast('节点列表读取失败: ' + e.message, 'err');
  } finally {
    delete body.dataset.loading;
  }
}

function reload(resetPage = true) {
  if (resetPage) state.offset = 0;
  loadNodes();
}

function pingClass(ms) {
  if (!ms) return 'ping-none';
  if (ms <= 120) return 'ping-fast';
  if (ms <= 350) return 'ping-mid';
  return 'ping-slow';
}

// 延迟列只报本机实测：EWMA → 最近一次成功的 RTT。官方 Ping 和 Cloudflare 观测
// 都要显式选口径才用：否则「我们还没测过」的节点会拿别人那张网的数顶在这一列上，
// 而 sort=ping / max_ping（store 的 best 口径，见 query.localPing）也只认实测 ——
// 显示与排序必须用同一个值，不然是「列上写着待测试，却按官方 44ms 排在前面」。
//
// 已判定不可达的节点任何口径都不给延迟数：EWMA 只由成功的探测喂出来，不清空也
// 不按时间衰减（见 store/health.go），旧数字挂在「已挂」的行上会被读成「现在还能
// 连，只是慢」。历史值在 title 和详情面板里；后端的 sort=ping / max_ping 同口径不参与。
function pickPing(n) {
  const health = n.health || {};
  const level = health.level || healthLevel(health);
  const ewma = health.ewma_ping_ms || 0;
  const lastOK = health.last_ok || '';
  if (level === 'down') {
    const stale = ewma || (n.probe && n.probe.ok ? n.probe.rtt_ms : 0);
    return { v: 0, src: '', note: '已判定不可达', stale: stale, lastOK: lastOK };
  }
  if (state.pingSource === 'upstream') {
    const v = n.upstream_ping_ms || 0;
    return { v: v, src: v ? '官方' : '', note: v ? '' : '官方没给值' };
  }
  if (state.pingSource === 'cloudflare') {
    const v = n.cf_tcp && n.cf_tcp.connect_ms ? n.cf_tcp.connect_ms : 0;
    return { v: v, src: v ? 'Cloudflare' : '', note: v ? '' : '无 Cloudflare 观测' };
  }
  // local 与后端同口径：优先最近一次成功的值，没有才退 EWMA。
  if (state.pingSource === 'local') {
    const v = n.probe && n.probe.ok ? (n.probe.rtt_ms || 0) : ewma;
    return { v: v, src: v ? '实测' : '', note: v ? '' : noteWhenUnmeasured(health) };
  }
  // best：本机实测 EWMA，没有就看最近一次成功的 RTT。
  const live = n.probe && n.probe.ok ? (n.probe.rtt_ms || 0) : 0;
  const v = ewma || live;
  return { v: v, src: v ? '实测' : '', note: v ? '' : noteWhenUnmeasured(health) };
}

// 没有实测延迟时得说清是哪种“没有”：还没测过（待测试）与测了但没连上
// （未测出延迟）是两个完全不同的结论。
function noteWhenUnmeasured(health) {
  return (health.tests || 0) > 0 ? '未测出延迟' : '待测试';
}

function renderTable() {
  const body = $('#nodes-body');
  body.textContent = '';
  $('#nodes-empty').hidden = state.nodes.length > 0;
  if (!state.nodes.length) {
    $('#nodes-empty-text').textContent = state.total === 0 ? '没有符合条件的节点' : '本页没有数据';
  }
  for (const n of state.nodes) {
    body.appendChild(rowFor(n));
  }
  $('#check-all').checked = state.nodes.length > 0 && state.nodes.every((n) => state.selected.has(n.id));
  updateSelectedLabel();
}

function rowFor(n) {
  const health = n.health || {};
  const level = health.level || healthLevel(health);
  const ping = pickPing(n);
  const purity = n.purity || null;
  const tr = el('tr', { dataset: { id: n.id } });
  if (state.selected.has(n.id)) tr.classList.add('selected');

  tr.appendChild(el('td', { class: 'col-check' }, [
    el('input', {
      type: 'checkbox', checked: state.selected.has(n.id),
      onchange: (ev) => {
        if (ev.target.checked) state.selected.add(n.id); else state.selected.delete(n.id);
        tr.classList.toggle('selected', ev.target.checked);
        updateSelectedLabel();
      },
    }),
  ]));

  const dot = el('span', { class: 'dot dot-' + level, title: (LEVEL_ZH[level] || level) + confText(health) });
  const sub = el('div', { class: 'sub' }, [
    n.ip,
    n.vendor ? el('span', { class: 'vendor', text: ' · ' + n.vendor }) : null,
    n.asn_hint ? el('span', { text: ' · ' + n.asn_hint }) : null,
  ]);
  tr.appendChild(el('td', {}, [
    el('div', { class: 'cell-node' }, [
      el('div', { class: 'cell-title' }, [dot, el('b', { text: n.hostname || '(无名)' })]),
      sub,
    ]),
  ]));

  // 纯净度
  const score = purity ? purity.score : null;
  const lvl = purity ? purity.level : 'none';
  const pcell = el('div', { class: 'purity p-' + lvl }, [
    el('div', { class: 'purity-top' }, [
      el('span', { class: 'purity-score', text: score === null ? '未测' : String(score) }),
      purity ? el('span', { class: 'type-chip type-' + purity.ip_type, text: purity.type_label || purity.ip_type }) : null,
      // 类型是我们推出来的就挂个「推导」标记：列表上一眼能看出这个「住宅宽带」
      // 是 AS 表推的，不是哪个来源说的。
      purity && String(purity.type_source || '').startsWith('derived:')
        ? el('span', { class: 'type-chip chip-derived', text: '推导', title: basisLabel(purity.type_source) }) : null,
    ]),
    el('div', { class: 'purity-bar' }, [el('i', { style: `width:${score === null ? 0 : score}%` })]),
  ]);
  tr.appendChild(el('td', { class: 'row-click' }, [pcell]));

  tr.appendChild(el('td', {}, [
    el('span', { class: 'flag', text: flag(n.country_code) }),
    el('span', { text: ' ' + (n.country_code || '未知'), title: n.country || '' }),
  ]));

  tr.appendChild(el('td', {}, [
    el('span', { class: 'badge badge-' + (n.proto === 'tcp' ? 'tcp' : 'udp'), text: (n.proto || '?').toUpperCase() }),
    el('span', { class: 'mono', text: ' :' + (n.port || '?') }),
    n.config_local ? null : el('span', { class: 'badge badge-warn', text: '配置按需拉取', title: '这个节点来自镜像累积池，正文在点开或下载时才从 CDN 取' }),
  ]));

  const pingCell = el('div', { class: 'ping ' + pingClass(ping.v) }, [
    el('b', { text: ping.v ? fmtMs(ping.v) : '–' }),
  ]);
  if (ping.note) {
    const off = el('small', { class: 'ping-off', text: ping.note });
    if (ping.note === '已判定不可达') {
      off.title = ping.stale
        ? `历史实测 ${fmtMs(ping.stale)}（最近成功 ${hasTime(ping.lastOK) ? fmtRel(ping.lastOK) : '无记录'}）。已判定不可达，列表不再给延迟数，延迟排序/筛选也不把它算进去；完整历史在详情里。`
        : '已判定不可达，没有可引用的延迟数。';
    } else if (ping.note === '待测试') {
      off.title = '本机还没测过这个节点。官方 Ping 不参与这一列（要看它就切延迟口径）。';
    } else if (ping.note === '未测出延迟') {
      off.title = '测过，但一次都没连上过（超时 / 无回包也算不出延迟）。详情面板里有每次的原因。';
    }
    pingCell.appendChild(off);
  } else if (ping.src) {
    pingCell.appendChild(el('small', { text: ping.src }));
  }
  tr.appendChild(el('td', {}, [pingCell]));

  tr.appendChild(el('td', { class: 'num', text: n.upstream_score ? num(n.upstream_score) : '–' }));
  tr.appendChild(el('td', { class: 'num', text: fmtMbps(n.upstream_speed_bps) }));
  tr.appendChild(el('td', { class: 'num', text: n.sessions ? num(n.sessions) : '–' }));
  tr.appendChild(el('td', {}, [
    el('div', { class: 'time-ago', text: fmtRel(n.last_seen) }),
    n.in_latest_source === false ? el('div', { class: 'time-ago', text: '不在本轮名单' }) : null,
  ]));

  const ops = el('td', { class: 'col-ops' });
  ops.appendChild(el('button', { class: 'btn btn-ghost btn-xs', text: '详情', onclick: () => openDrawer(n.id) }));
  ops.appendChild(el('button', { class: 'btn btn-ghost btn-xs', text: '测试', onclick: (ev) => probeOne(n.id, ev.target) }));
  ops.appendChild(el('button', { class: 'btn btn-ghost btn-xs', text: '纯净度', onclick: (ev) => purityOne(n.id, ev.target) }));
  ops.appendChild(el('button', { class: 'btn btn-ghost btn-xs', text: '下载', onclick: () => downloadConfig(n.id) }));
  tr.appendChild(ops);

  tr.addEventListener('click', (ev) => {
    if (ev.target.closest('button') || ev.target.matches('input')) return;
    openDrawer(n.id);
  });
  return tr;
}

function confText(health) {
  const c = Math.round((health.confidence || 0) * 100);
  const t = health.tests || 0;
  return c || t ? ` · 置信 ${c}% (${t} 次测试，成功 ${health.successes || 0})` : '';
}

// 后端已经在 health.level 里算好了档位，这里只是读到老快照（缺这个字段）时的本地备份，
// 规则必须跟 model.HealthLevel 一模一样：没拿到明确结论（alive 为 null）不能算已挂，
// 否则表格里标着「已挂」、按「已挂」筛却筛不出来，两边对不上。
function healthLevel(h) {
  if (!h.tests) return 'untested';
  if (h.alive === true) return (h.success_pct || 0) >= 80 ? 'stable' : 'reachable';
  if (h.alive === false) return (h.fail_streak || 0) >= 2 ? 'down' : 'flaky';
  return (h.successes || 0) > 0 ? 'flaky' : 'unknown';
}

function renderPager() {
  const from = state.total === 0 ? 0 : state.offset + 1;
  const to = Math.min(state.total, state.offset + state.limit);
  $('#pg-info').textContent = `${from}-${to} / 共 ${num(state.total)} 个节点`;
  $('#pg-prev').disabled = state.offset <= 0;
  $('#pg-next').disabled = to >= state.total;
}

function updateSelectedLabel() {
  $('#pg-selected').textContent = state.selected.size ? `已选 ${state.selected.size} 个` : '';
}

function patchPurityRow(d) {
  for (const n of state.nodes) {
    if (n.ip !== d.ip) continue;
    n.purity = { score: d.score, level: d.level, ip_type: d.type, type_label: typeLabel(d.type), checked_at: new Date().toISOString() };
  }
  renderTable();
}

// decodeRaw 解掉 []byte 在 JSON 里的 base64，并尽量把响应格式化成可读 JSON。
function decodeRaw(s) {
  let text = String(s);
  try { text = atob(s); } catch { /* 已经是明文 */ }
  try { text = JSON.stringify(JSON.parse(text), null, 2); } catch { /* 不是 JSON 就原样显示 */ }
  return text;
}

function typeLabel(t) {
  const map = {
    residential: '住宅宽带', mobile: '移动网络', business: '企业线路', education: '科研教育',
    government: '政府机构', hosting: '数据中心/机房', 'vpn-proxy': '代理/VPN 出口', tor: 'Tor 出口',
    cdn: 'CDN', 'search-engine': '搜索引擎爬虫', 'vpngate-hosting': 'VPN Gate 自营机房', unknown: '未知类型',
  };
  return map[t] || t || '未知类型';
}

/* ============================ 行内操作 ============================ */

async function probeOne(id, btn) {
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  try {
    const res = await api(`/api/nodes/${encodeURIComponent(id)}/probe`, { method: 'POST', body: {} });
    const p = res.probe || {};
    const ok = p.ok;
    toast(`${p.host || ''}:${p.port || ''} → ${SERVICE_ZH[p.service] || p.service}` + (p.rtt_ms ? ` · ${fmtMs(p.rtt_ms)}` : ''), ok ? 'ok' : 'warn', 5200);
    await loadNodes();
    if (state.drawerId === id) { state.detail = null; openDrawer(id, true); }
  } catch (e) {
    toast('测试失败: ' + e.message, 'err');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '测试'; }
  }
}

async function purityOne(id, btn) {
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  try {
    const res = await api(`/api/nodes/${encodeURIComponent(id)}/purity`, { method: 'POST', body: { force: false } });
    const p = res.purity || {};
    toast(`${p.ip} 纯净度 ${p.score}（${PURITY_ZH[p.level] || p.level}·${p.type_label || ''}）`, p.score >= 70 ? 'ok' : 'warn', 5600);
    await loadNodes();
    if (state.drawerId === id) { state.detail = null; openDrawer(id, true); }
  } catch (e) {
    toast('纯净度检测失败: ' + e.message, 'err');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '纯净度'; }
  }
}

function downloadConfig(id) {
  window.location.assign(`/api/nodes/${encodeURIComponent(id)}/config`);
}

function currentExportURL(ids) {
  const p = new URLSearchParams();
  if (ids && ids.length) p.set('ids', ids.join(','));
  else {
    const f = currentFilters();
    f.delete('limit'); f.delete('offset');
    for (const [k, v] of f.entries()) p.set(k, v);
  }
  p.set('format', 'ovpn');
  return '/api/export?' + p.toString();
}

/* ============================ 抽屉详情 ============================ */

async function openDrawer(id, force) {
  state.drawerId = id;
  $('#drawer').hidden = false;
  $('#drawer-mask').hidden = false;
  if (state.detail && state.detail.id === id && !force) { renderDrawer(); return; }
  $('#drawer-body').textContent = '';
  $('#drawer-body').appendChild(el('div', { class: 'muted', text: '加载中…' }));
  try {
    const data = await api(`/api/nodes/${encodeURIComponent(id)}`);
    state.detail = Object.assign({ id }, data);
    renderDrawer();
  } catch (e) {
    $('#drawer-body').textContent = '';
    $('#drawer-body').appendChild(el('div', { class: 'muted', text: '加载失败: ' + e.message }));
  }
}

function closeDrawer() {
  state.drawerId = null;
  state.detail = null;
  $('#drawer').hidden = true;
  $('#drawer-mask').hidden = true;
}

function kvBlock(title, rows) {
  const dl = el('dl', { class: 'kv' });
  for (const [k, v] of rows) {
    if (v === null || v === undefined || v === '') continue;
    dl.appendChild(el('dt', { text: k }));
    dl.appendChild(el('dd', { class: typeof v === 'string' && v.length > 40 ? 'mono' : '', text: String(v) }));
  }
  return el('div', { class: 'block' }, [el('h3', { text: title }), dl]);
}

function renderDrawer() {
  const d = state.detail;
  const n = d.node || {};
  const body = $('#drawer-body');
  body.textContent = '';
  $('#d-title').textContent = n.hostname || '节点详情';
  $('#d-sub').textContent = `${n.ip}:${n.port || '?'} / ${(n.proto || '?').toUpperCase()} · ${n.country || '未知地区'} · 推荐分 ${Math.round(d.recommend || 0)}`;

  // 基本
  const health = n.health || {};
  const level = health.level || healthLevel(health);
  body.appendChild(kvBlock('基本信息', [
    ['节点 ID', n.id],
    ['IP', n.ip],
    ['连接地址', `${n.server || n.ip}:${n.port || '?'} ${n.proto || ''}`],
    ['国家/地区', `${flag(n.country_code)} ${n.country || n.country_code || '未知'}`],
    ['协议/加密', `${(n.proto || '?').toUpperCase()} · ${n.cipher || '?'} / ${n.auth_algorithm || '?'}`],
    ['服务厂商', n.vendor === 'softether' ? 'SoftEther（OpenVPN 兼容）' : (n.vendor || '未知')],
    ['内联证书', n.has_certs ? '有' : '无（导入时要补证书）'],
    ['官方分/速度/会话', `${num(n.upstream_score || 0)} · ${fmtMbps(n.upstream_speed_bps)} · ${num(n.sessions || 0)}`],
    ['运营商', n.operator || ''],
    ['留言', n.message || ''],
    ['首次/最近出现', `${fmtRel(n.first_seen)} / ${fmtRel(n.last_seen)}`],
    ['数据来源', n.last_source || ''],
    ['配置正文', n.config_local ? `本地已有（sha ${String(n.config_sha256).slice(0, 12)}…）` : `按需拉取（sha ${String(n.config_sha256).slice(0, 12)}…）`],
  ]));

  // 可达性
  const probe = n.probe;
  const probeRows = [
    ['判定', (LEVEL_ZH[level] || level) + confText(health)],
    ['测试次数', `${health.tests || 0} 次，成功 ${health.successes || 0}，连续失败 ${health.fail_streak || 0}`],
    ['最近成功', hasTime(health.last_ok) ? fmtRel(health.last_ok) : '从未'],
  ];
  // 列表上已经不给已挂节点的延迟数了，详情里就得把这个历史 EWMA 说出来，
  // 否则这个数字就只在探测历史里逐条躺着，没人会去算。
  if (health.ewma_ping_ms) {
    probeRows.push(['历史 EWMA', fmtMs(health.ewma_ping_ms) + (level === 'down' ? '（已判定不可达，不参与延迟排序）' : '')]);
  }
  if (probe) {
    probeRows.push(['最近一次', `${fmtTime(probe.at)} · ${SERVICE_ZH[probe.service] || probe.service} · ${probe.rtt_ms ? fmtMs(probe.rtt_ms) : '–'}`]);
    if (probe.detail) probeRows.push(['应答内容', probe.detail]);
    if (probe.reason) probeRows.push(['备注', probe.reason]);
    probeRows.push(['耗时', `TCP ${fmtMs(probe.connect_ms)} · 总 ${fmtMs(probe.duration_ms)} · 尝试 ${probe.attempts || 1} 次`]);
  }
  body.appendChild(kvBlock('连通性（本机实测）', probeRows));

  // Cloudflare 第三方观测
  if (n.cf_tcp) {
    const cf = n.cf_tcp;
    body.appendChild(kvBlock('Cloudflare Worker 观测（第三方）', [
      ['状态', ({ reachable: '可达', unreachable: '不可达', unknown: '未知', not_applicable: '不适用（UDP）' })[cf.status] || cf.status],
      ['观测时间', hasTime(cf.checked_at) ? fmtRel(cf.checked_at) : '–'],
      ['建连耗时', cf.connect_ms ? fmtMs(cf.connect_ms) : '–'],
      ['连续失败', cf.consecutive_failures || 0],
      ['成功端点', cf.connected_endpoint || ''],
    ]));
  }

  // 纯净度
  if (n.purity) {
    body.appendChild(purityBlock(n.purity));
  } else {
    body.appendChild(el('div', { class: 'block' }, [
      el('h3', { text: 'IP 纯净度' }),
      el('div', { class: 'muted small', text: '还没测过。点下方「查纯净度」，或用顶栏的「纯净度扫描」批量跑。' }),
    ]));
  }

  // 探测历史
  if ((n.probes || []).length) {
    const hist = el('div', { class: 'history' });
    n.probes.slice(-8).reverse().forEach((s) => {
      hist.appendChild(el('div', { class: 'history-row' }, [
        el('span', { text: fmtRel(s.at) }),
        el('span', {}, [el('span', { class: 'dot dot-' + (s.ok ? 'reachable' : 'down'), text: '' })]),
        el('span', { text: `${SERVICE_ZH[s.service] || s.service || '–'} · ${s.rtt_ms ? fmtMs(s.rtt_ms) : '–'}${s.reason ? ' · ' + s.reason : ''}` }),
      ]));
    });
    body.appendChild(el('div', { class: 'block' }, [el('h3', { text: '探测历史（最近 8 次）' }), hist]));
  }

  // 同 IP 其他节点
  if ((d.same_ip || []).length) {
    const wrap = el('div', { class: 'block' }, [el('h3', { text: `同一 IP 上的其他节点 (${d.same_ip.length})` })]);
    d.same_ip.forEach((s) => {
      wrap.appendChild(el('button', {
        class: 'btn-link', text: `${s.hostname} · ${s.port}/${(s.proto || '?').toUpperCase()} · ${s.country_code || '?'}`,
        onclick: () => openDrawer(s.id),
      }));
    });
    wrap.appendChild(el('div', { class: 'muted small', text: '纯净度是按 IP 查的，这几个共享同一份结论。' }));
    body.appendChild(wrap);
  }

  // 备注
  if ((n.notes || []).length) {
    const ul = el('ul', { class: 'small muted' });
    n.notes.forEach((x) => ul.appendChild(el('li', { text: x })));
    body.appendChild(el('div', { class: 'block' }, [el('h3', { text: '解析备注' }), ul]));
  }

  // 配置预览
  if (d.config_preview) {
    body.appendChild(el('div', { class: 'block' }, [
      el('h3', { text: '.ovpn 配置预览' + (d.config_truncated ? '（截断）' : '') }),
      el('pre', { class: 'config-preview', text: d.config_preview }),
    ]));
  } else {
    body.appendChild(el('div', { class: 'block' }, [
      el('h3', { text: '.ovpn 配置' }),
      el('div', { class: 'muted small', text: '正文不在本地：点「下载 .ovpn」或复制时会从镜像按 sha 现取（已校验 SHA-256）。' }),
    ]));
  }
}

function purityBlock(p) {
  const wrap = el('div', { class: 'block' });
  wrap.appendChild(el('h3', { text: `IP 纯净度 · ${typeLabel(p.ip_type)}` }));
  if (p.type_source) {
    wrap.appendChild(el('div', { class: 'muted small', text: basisLabel(p.type_source) }));
  }

  const pct = p.score || 0;
  const color = pct >= 85 ? 'var(--ok)' : pct >= 70 ? 'var(--ok)' : pct >= 50 ? 'var(--warn)' : 'var(--bad)';
  const ring = el('div', { class: 'gauge-ring', style: `background: conic-gradient(${color} ${pct * 3.6}deg, var(--line) 0deg)` }, [
    el('div', { text: String(pct) }),
  ]);
  const meta = el('div', { class: 'gauge-meta' }, [
    el('b', { text: PURITY_ZH[p.level] || p.level, style: `color:${color}` }),
    el('span', { text: `${p.ip}` }),
    el('span', { class: 'muted', text: `可信度 ${p.confidence || 0}% · ${fmtRel(p.checked_at)}检测` }),
    el('span', { class: 'muted', text: [p.asn, p.org, p.isp, p.domain].filter(Boolean).join(' · ') }),
    p.country ? el('span', { class: 'muted', text: '归属地: ' + p.country }) : null,
  ]);
  wrap.appendChild(el('div', { class: 'gauge' }, [ring, meta]));

  // 风险因子表（照 IPQuality 的 Risk Factors 模块）
  const fac = p.factors || {};
  const grid = el('div', { class: 'factors' });
  const specs = [
    ['公开代理', fac.proxy], ['VPN 出口', fac.vpn], ['Tor 出口', fac.tor], ['数据中心', fac.datacenter],
    ['移动网络', fac.mobile], ['滥用记录', fac.abuser], ['爬虫/扫描', fac.bot],
  ];
  specs.forEach(([label, v]) => {
    const cls = v === true || v === null ? (v === true ? 'yes' : 'na') : 'no';
    grid.appendChild(el('div', { class: 'factor ' + cls }, [
      el('span', { text: label }),
      el('b', { text: v === true ? '是' : v === false ? '否' : '未知' }),
    ]));
  });
  if (fac.abuse_score !== undefined && fac.abuse_score !== null) {
    grid.appendChild(el('div', { class: 'factor' }, [el('span', { text: '滥用置信分' }), el('b', { text: String(fac.abuse_score) })]));
  }
  wrap.appendChild(grid);

  // 理由
  if ((p.reasons || []).length) {
    const ul = el('ul', { class: 'small muted' });
    p.reasons.forEach((r) => ul.appendChild(el('li', { text: r })));
    wrap.appendChild(el('div', { class: 'muted small', text: '判定依据' }));
    wrap.appendChild(ul);
  }

  // 各来源明细
  const table = el('table', { class: 'providers' });
  table.appendChild(el('thead', {}, [el('tr', {}, [
    el('th', { text: '来源' }), el('th', { text: '风险分' }), el('th', { text: '类型' }),
    el('th', { text: 'ASN / 组织' }), el('th', { text: '状态' }), el('th', {}),
  ])]));
  const tb = el('tbody');
  (p.providers || []).forEach((v) => {
    const tr = el('tr', {}, [
      el('td', { text: v.name }),
      el('td', { class: 'num', text: v.score === null || v.score === undefined ? '–' : `${v.score}${v.score_name ? ' (' + v.score_name + ')' : ''}` }),
      el('td', { text: v.ip_type ? typeLabel(v.ip_type) : '–' }),
      el('td', { class: 'asn', text: [v.asn, v.org].filter(Boolean).join(' ') || '–' }),
      el('td', {}, [v.ok
        ? el('span', { class: 'badge badge-ok', text: v.ms + 'ms' })
        : el('span', { class: 'badge badge-bad', text: '失败' })]),
      el('td', {}, [
        v.err ? el('span', { class: 'small', text: v.err, title: v.err }) : null,
        v.raw ? el('button', {
          class: 'btn btn-ghost btn-xs', text: '原始响应',
          onclick: (ev) => {
            const box = el('div', { class: 'raw-json', text: decodeRaw(v.raw) });
            ev.target.parentNode.replaceChild(box, ev.target);
          },
        }) : null,
      ]),
    ]);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  wrap.appendChild(el('div', { class: 'block' }, [el('h3', { text: '来源明细（谁说了什么）' }), table]));
  return wrap;
}

/* ============================ 设置弹窗 ============================ */

async function openSettings() {
  $('#modal-mask').hidden = false;
  const body = $('#modal-body');
  body.textContent = '';
  body.appendChild(el('div', { class: 'muted', text: '加载中…' }));
  await loadSettings();
}

// loadSettings 重画整个设置弹窗：打开时画一次，每项存完再画一次。
// 用服务器返回值当唯一真相，改失败时界面自然回到原值，不需要前端自己回退 DOM。
async function loadSettings() {
  const body = $('#modal-body');
  try {
    const s = await api('/api/settings');
    body.textContent = '';
    // 宽屏下两列并排：四块面板单列排下来要 1800+px，弹窗只有 600 多 px 可视高度，
    // 一屏连一块半都放不下，滚来滚去看起来就像「内容被遮住了」。
    body.appendChild(el('div', { class: 'settings-cols' }, [
      settingsNodes(s),
      settingsProbe(s),
      settingsPurity(s),
      settingsPassword(),
    ]));
    // 配置文件路径 / 数据目录 / 版本：诊断时要用，但只留一行小字，不占一块面板。
    body.appendChild(el('div', {
      class: 'settings-meta',
      text: `数据目录 ${s.data_dir || '–'} · 配置 ${s.config_path || '（未落盘）'} · 版本 ${s.version || '–'}`,
    }));
  } catch (e) {
    body.textContent = '';
    body.appendChild(el('div', { class: 'muted', text: '加载失败: ' + e.message }));
  }
}

// ===================== 设置面板（三块：节点 / 探查 / 纯净度） =====================
//
// 视觉上只有两层：面板（section）+ 行。行与行之间用一条细分割线，不再每行套一个
// 盒子 —— 一层盒子套一层盒子会让人找不到「哪几项是一组」，也挤没了留白。
// 行的骨架固定为「左边标签 + 说明，右边控件」，所以开关和输入框在一列里对齐。

function settingsSection(title, desc, footNote) {
  const list = el('div', { class: 'settings-list' });
  const box = el('section', { class: 'settings-section' }, [
    el('header', { class: 'settings-head' }, [
      el('h3', { text: title }),
      desc ? el('p', { class: 'settings-desc', text: desc }) : null,
    ]),
    list,
    footNote ? el('p', { class: 'settings-foot', text: footNote }) : null,
  ]);
  box.list = list;
  return box;
}

// settingsGroupLabel 在同一个面板里分小段（比如「来源」和「淘汰」）。
function settingsGroupLabel(sec, text) {
  sec.list.appendChild(el('div', { class: 'settings-group-label', text }));
}

// srow 拼一行：左「标签 + 说明」，右「控件」。
function srow(label, hint, control) {
  const text = el('div', { class: 'srow-text' }, [
    el('span', { class: 'srow-label', text: label }),
    hint ? el('span', { class: 'srow-hint', text: hint }) : null,
  ]);
  return el('div', { class: 'srow' }, [text, el('div', { class: 'srow-ctl' }, [control])]);
}

// settingToggle 是一个能直接改的开关行。
//
// 改完用服务器返回的值重画，不自作主张改 DOM：开关点了却没生效时（比如三个源
// 不能全关），界面上必须说清楚为什么没改成，否则用户以为已经关了。
function settingToggle(sec, label, hint, checked, field) {
  const box = el('input', { type: 'checkbox' });
  box.checked = !!checked;
  const track = el('span', { class: 'track' });
  const toggle = el('label', { class: 'toggle', title: label }, [box, track]);
  const row = srow(label, hint, toggle);
  row.classList.add('srow-toggle');
  if (!checked) row.classList.add('off');

  box.addEventListener('change', async () => {
    const want = box.checked;
    box.disabled = true;
    toggle.classList.add('busy');
    const hintEl = row.querySelector('.srow-hint');
    try {
      await api('/api/settings', { method: 'POST', body: { [field]: want } });
      toast(`${label}已${want ? '开启' : '关闭'}，下一轮生效`, 'ok');
      await loadSettings();
    } catch (e) {
      box.checked = !want; // 服务器没收，拧回原样
      row.classList.toggle('off', box.checked !== true);
      if (hintEl) {
        hintEl.textContent = '没改成：' + e.message;
        hintEl.classList.add('err');
      }
      toast(e.message, 'bad');
    } finally {
      box.disabled = false;
      toggle.classList.remove('busy');
    }
  });
  sec.list.appendChild(row);
  return row;
}

// settingNumber 是能直接改的数字行：失焦或回车才提交，且只在值真的变了时发请求 ——
// 每敲一个字符就 POST 一次会把配置文件连写好几次。
function settingNumber(sec, label, hint, value, field, opts) {
  const o = opts || {};
  const current = value === undefined || value === null ? '' : String(value);
  const input = el('input', { type: 'number', value: current, 'aria-label': label });
  if (o.min !== undefined) input.min = String(o.min);
  if (o.max !== undefined) input.max = String(o.max);
  const ctl = el('span', { class: 'num-ctl' }, [
    input,
    o.unit ? el('span', { class: 'num-unit', text: o.unit }) : null,
  ]);
  const row = srow(label, hint, ctl);
  row.classList.add('srow-number');
  const hintEl = row.querySelector('.srow-hint');

  const fail = (msg) => {
    if (hintEl) {
      hintEl.textContent = msg;
      hintEl.classList.add('err');
    }
    toast(`${label}：${msg}`, 'bad');
  };

  const commit = async () => {
    const raw = String(input.value).trim();
    const got = Number(raw);
    if (raw === '' || !Number.isInteger(got)) {
      input.value = current; // 当场退回原值，别留一个非法数字在框里
      fail('要填整数');
      return;
    }
    if (got === Number(current)) return;
    if (o.min !== undefined && (got < o.min || got > o.max)) {
      input.value = current;
      fail(`范围 ${o.min} ~ ${o.max}${o.unit || ''}`);
      return;
    }
    input.disabled = true;
    try {
      await api('/api/settings', { method: 'POST', body: { [field]: got } });
      toast(`${label} 已改成 ${got}${o.unit || ''}`, 'ok');
      await loadSettings();
    } catch (e) {
      toast(e.message, 'bad');
      await loadSettings(); // 服务器没收，重新读一遍就是回滚
    } finally {
      input.disabled = false;
    }
  };
  input.addEventListener('change', commit);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      input.blur();
    } else if (e.key === 'Escape') {
      input.value = current;
      input.blur();
    }
  });
  sec.list.appendChild(row);
  return row;
}

// settingStatus 是一行只读状态（来源的启用情况、成功/失败数）。
//
// 圆点跟在标签后面、数值靠右：这样状态圆点排成一条竖线，成功/失败数也右对齐，
// 七八个来源列下来不会看着一列数字左右乱跳。
function settingStatus(sec, label, hint, state) {
  const labelEl = el('span', { class: 'srow-label' }, [
    el('span', { class: 'dot dot-' + (state.kind || 'off') }),
    el('span', { text: label }),
  ]);
  const text = el('div', { class: 'srow-text' }, [
    labelEl,
    hint ? el('span', { class: 'srow-hint', text: hint }) : null,
  ]);
  const ctl = el('span', { class: 'status-text', text: state.text });
  sec.list.appendChild(el('div', { class: 'srow srow-status' }, [text, el('div', { class: 'srow-ctl' }, [ctl])]));
}

function settingsNodes(s) {
  const src = s.sources || {};
  const mi = src.mirrors || {};
  const cdn = src.cdn || {};
  const sec = settingsSection('节点配置', '拉哪些名单、留多久、怎么淘汰。官方主站是必开来源，不在开关里。',
    '开关下一轮生效；天数和轮数立即生效，正在跑的那一轮不变。要连官方主站一起关只能改配置文件里的 sources.vpngate.enabled。');

  settingsGroupLabel(sec, '来源');
  settingToggle(sec, '镜像站点', 'sites.aspx 上的官方镜像，按 /24 去重后每轮全抓', mi.enabled, 'mirrors_enabled');
  settingToggle(sec, 'vpngate-list-mirror', '第三方镜像名单，不是 VPN Gate 官方', cdn.enabled, 'cdn_enabled');
  settingToggle(sec, '含累积池', '多出来的老节点和它们的 .ovpn', cdn.use_pool, 'cdn_pool_enabled');
  settingToggle(sec, '保留机房节点', '官方自营机房（public-vpn-*、219.100.37.0/24），不是家宽', src.keep_vpngate_own, 'keep_vpngate_own');

  settingsGroupLabel(sec, '淘汰');
  settingNumber(sec, '最长缺席天数', '本轮名单里没有的节点，缺席满这么多天才删', src.keep_days, 'keep_days', { min: 1, max: 90, unit: '天' });
  settingNumber(sec, '最大失败次数', `缺席满 ${src.purge_absent_hours || 24}h 后，连负这么多轮明确失败就删`, src.purge_fail_rounds, 'purge_fail_rounds', { min: 1, max: 12, unit: '轮' });
  return sec;
}

function settingsProbe(s) {
  const p = s.probe || {};
  const sec = settingsSection('可用性探查', 'TCP 连通 + OpenVPN 硬重置握手，判断节点到底能不能用。',
    '间隔与超时对下一轮生效；并发改动不影响正在跑的那一轮。');

  settingToggle(sec, '启用探测', '关掉后节点一律显示「未测」', p.enabled, 'probe_enabled');
  settingsGroupLabel(sec, '节拍');
  settingNumber(sec, '探测间隔', `一轮后再隔 ${p.unknown_retry_minutes || 60} 分钟补测「说不清」的 TCP 节点`, p.interval_minutes, 'probe_interval_minutes', { min: 5, max: 1440, unit: '分钟' });
  settingNumber(sec, '探测并发', '同时拨出去的节点数', p.concurrency, 'probe_concurrency', { min: 1, max: 512, unit: '个' });
  settingsGroupLabel(sec, '超时');
  settingNumber(sec, 'TCP 超时', 'TCP 连接等待上限', p.tcp_timeout_seconds, 'probe_tcp_timeout_seconds', { min: 1, max: 30, unit: '秒' });
  settingNumber(sec, 'UDP 超时', 'UDP 不回包算「说不清」，不算挂了', p.udp_timeout_seconds, 'probe_udp_timeout_seconds', { min: 1, max: 30, unit: '秒' });
  settingToggle(sec, 'OpenVPN 握手', '发 P_CONTROL_HARD_RESET 认服务指纹', p.handshake, 'probe_handshake');
  return sec;
}

function settingsPurity(s) {
  const p = s.purity || {};
  const sec = settingsSection('IP 纯净度检查', '多来源投票给出 0-100 分、类型和风险因子。',
    'API key 在 config.json 的 purity.keys 里配，或用 IPINFO_TOKEN / SCAMALYTICS_KEY 等环境变量。');

  settingToggle(sec, '启用纯净度检测', '关掉后节点一律显示「未测」', p.enabled, 'purity_enabled');
  settingNumber(sec, '限流次数（每分钟）', '免费来源的查询上限，带 key 的来源按 3 倍算', p.requests_per_minute, 'purity_rpm', { min: 1, max: 600, unit: '次' });

  // 来源状态压成两行。逐个来源一行看着齐全，但七个来源就是 270px 的空白行，
  // 把真正的配置项挤出可视区。这里只留两行：在跑的那几个（带成功/失败数）
  // 和没启用的那几个（说明为什么没启用）。
  settingsGroupLabel(sec, '来源状态');
  const all = s.purity_providers || [];
  const on = all.filter((v) => v.enabled);
  const off = all.filter((v) => !v.enabled);
  const onText = on.length
    ? on.map((v) => `${v.name} ${v.ok || 0}/${v.failed || 0}${v.last_err ? '（' + v.last_err + '）' : ''}`).join(' · ')
    : '没有来源在跑';
  settingStatus(sec, '在跑（成功/失败）', '', { kind: on.length ? 'on' : 'warn', text: onText });
  settingStatus(sec, '没启用', '', {
    kind: 'off',
    text: off.length ? off.map((v) => `${v.name}${v.needs_key && !v.has_key ? ' 缺 key' : ''}`).join(' · ') : '无',
  });
  return sec;
}

function settingsPassword() {
  const sec = settingsSection('登录口令', '改完立即生效，已登录的会话不受影响。');
  const cur = el('input', { type: 'password', placeholder: '当前口令', autocomplete: 'current-password', required: true });
  const next = el('input', { type: 'password', placeholder: '至少 8 位', autocomplete: 'new-password', required: true });
  const err = el('span', { class: 'pw-err', text: '' });
  const submit = el('button', { class: 'btn btn-primary btn-sm', type: 'submit', text: '保存口令' });
  const form = el('form', { class: 'settings-pw' }, [
    srow('当前口令', '', cur),
    srow('新口令', '', next),
    el('div', { class: 'settings-pw-foot' }, [err, submit]),
  ]);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    err.textContent = '';
    submit.disabled = true;
    try {
      await api('/api/password', { method: 'POST', body: { current: cur.value, next: next.value } });
      toast('口令已更新', 'ok');
      cur.value = next.value = '';
    } catch (e) {
      err.textContent = e.message;
    } finally {
      submit.disabled = false;
    }
  });
  sec.list.appendChild(form);
  return sec;
}

function closeModal() { $('#modal-mask').hidden = true; }

/* ============================ 顶栏动作 ============================ */

async function act(kind, extra) {
  try {
    if (kind === 'refresh') {
      const r = await api('/api/refresh', { method: 'POST', body: {} });
      if (r.started) startJob('refresh', {});
    } else if (kind === 'probe') {
      const body = Object.assign({
        selection: '',
        countries: Array.from($('#f-country').selectedOptions).map((o) => o.value).filter(Boolean),
        protocols: Array.from($('#f-proto').selectedOptions).map((o) => o.value).filter(Boolean),
        force: false,
      }, extra || {});
      const r = await api('/api/probe', { method: 'POST', body });
      toast(`本轮目标 ${r.targets} 个${r.skipped ? ' · 跳过 ' + Object.entries(r.skipped).map(([k, v]) => `${k} ${v}`).join('，') : ''}`, 'info', 5200);
      if (r.started) startJob('probe', { total: r.targets });
    } else if (kind === 'purity') {
      const body = Object.assign({
        countries: Array.from($('#f-country').selectedOptions).map((o) => o.value).filter(Boolean),
        force: false,
      }, extra || {});
      const r = await api('/api/purity', { method: 'POST', body });
      toast('已启动纯净度扫描（来源: ' + (r.sources || []).join(', ') + '）', 'info');
      if (r.started) startJob('purity', {});
    } else if (kind === 'export') {
      window.location.assign(currentExportURL(Array.from(state.selected)));
    } else if (kind === 'settings') {
      openSettings();
    } else if (kind === 'theme') {
      toggleTheme();
    } else if (kind === 'logout') {
      await api('/api/logout', { method: 'POST', body: {} });
      state.csrf = '';
      showLogin('已退出登录');
    } else if (kind === 'probe-selected') {
      if (!state.selected.size) { toast('先勾选要测的节点', 'warn'); return; }
      await act('probe', { ids: Array.from(state.selected), limit: state.selected.size, force: true });
    } else if (kind === 'purity-selected') {
      if (!state.selected.size) { toast('先勾选要查的节点', 'warn'); return; }
      const nodes = state.nodes.filter((n) => state.selected.has(n.id));
      await act('purity', { ips: Array.from(new Set(nodes.map((n) => n.ip))), force: false });
    } else if (kind === 'export-selected') {
      if (!state.selected.size) { toast('先勾选要导出的节点', 'warn'); return; }
      window.location.assign(currentExportURL(Array.from(state.selected)));
    }
  } catch (e) {
    if (e.message === 'unauthorized') return;
    if (/已经在跑/.test(e.message)) toast('已有同类任务在运行，请等它结束', 'warn');
    else toast('操作失败: ' + e.message, 'err');
  }
}

function toggleTheme() {
  const b = document.body;
  const next = b.classList.contains('theme-dark') ? 'theme-light' : 'theme-dark';
  b.classList.remove('theme-dark', 'theme-light');
  b.classList.add(next);
  try { localStorage.setItem('vpa-theme', next); } catch { /* 隐私模式下忽略 */ }
}

/* ============================ 事件绑定 ============================ */

function bind() {
  $('#login-form').addEventListener('submit', doLogin);

  // 在总览页打字搜索要自动跳到节点列表，否则看着像搜索没反应。
  // 浏览器前进/后退直接落到对应页面。
  window.addEventListener('hashchange', () => showView(viewFromHash(), { pushHash: false }));
  // 地图指标可能被上次会话记住过，按钮高亮要跟实际指标对齐。
  $$('#map-metric .seg-btn').forEach((b) => b.classList.toggle('is-active', b.dataset.metric === mapMetric));

  // 图上点国家 = 按这个国家筛（只选这一个）。
  // 图上的气泡和下面的排行条都能点：同一个处理。
  $('#map').addEventListener('click', (ev) => {
    const dot = ev.target.closest('[data-code]');
    if (dot) applyCountryFilter(dot.dataset.code);
  });
  $('#map-rank').addEventListener('click', (ev) => {
    const row = ev.target.closest('[data-code]');
    if (row) applyCountryFilter(row.dataset.code);
  });

  $('#search').addEventListener('input', debounce(() => {
    if (!nodesVisible()) showView('nodes');
    reload();
  }, 320));
  ['#f-country', '#f-proto', '#f-level', '#f-sort', '#f-ping-src', '#f-min-purity', '#f-max-ping'].forEach((sel) => {
    const n = $(sel);
    n.addEventListener('change', () => {
      if (sel === '#f-sort') { state.sort = n.value; state.desc = false; }
      if (sel === '#f-ping-src') { state.pingSource = n.value; renderTable(); }
      reload();
    });
    if (n.type === 'number') n.addEventListener('input', debounce(() => reload(), 320));
  });
  ['#f-residential', '#f-fresh', '#f-purity-only'].forEach((sel) => $(sel).addEventListener('change', () => reload()));
  $('#f-reset').addEventListener('click', () => {
    $('#search').value = '';
    ['#f-country', '#f-proto', '#f-level'].forEach((sel) => { Array.from($(sel).options).forEach((o) => { o.selected = false; }); });
    $('#f-min-purity').value = '';
    $('#f-max-ping').value = '';
    $('#f-residential').checked = $('#f-fresh').checked = $('#f-purity-only').checked = false;
    $('#f-sort').value = 'recommend';
    state.sort = 'recommend';
    state.offset = 0;
    loadNodes();
  });

  $('#f-dir').addEventListener('click', () => {
    state.desc = !state.desc;
    $('#f-dir').dataset.dir = state.desc ? 'desc' : 'asc';
    $('#f-dir').textContent = state.desc ? '↓' : '↑';
    reload();
  });

  $$('#nodes-table thead th[data-sort]').forEach((th) => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      // 后端已经把「越大越好」的列（纯净度/分数/速度）归一成同一个方向，
      // 所以升序就是最佳在前 —— 换列时一律从升序开始，再点一次才反向。
      if (state.sort === key) state.desc = !state.desc;
      else { state.sort = key; state.desc = false; }
      $('#f-sort').value = key;
      $$('#nodes-table thead th').forEach((x) => { x.classList.remove('sorted'); delete x.dataset.arrow; });
      th.classList.add('sorted');
      th.dataset.arrow = state.desc ? '↓' : '↑';
      reload();
    });
  });

  $('#check-all').addEventListener('change', (ev) => {
    state.nodes.forEach((n) => { if (ev.target.checked) state.selected.add(n.id); else state.selected.delete(n.id); });
    renderTable();
  });

  $('#pg-prev').addEventListener('click', () => { state.offset = Math.max(0, state.offset - state.limit); loadNodes(); });
  $('#pg-next').addEventListener('click', () => { state.offset += state.limit; loadNodes(); });
  $('#pg-size').addEventListener('change', (ev) => { state.limit = Number(ev.target.value) || 100; state.offset = 0; loadNodes(); });

  // 顶栏与抽屉的按钮都用 data 属性集中派发，避免内联 onclick（CSP 禁内联）。
  document.addEventListener('click', (ev) => {
    const actBtn = ev.target.closest('[data-act]');
    if (actBtn) {
      ev.preventDefault();
      const kind = actBtn.dataset.act;
      // 纯页面内的动作（切页、卡片跳转、地图指标）不进 act()：那边全是打后端的任务。
      if (kind === 'tab') { showView(actBtn.dataset.tab); return; }
      if (kind === 'card') { cardJump(actBtn.dataset.card); return; }
      if (kind === 'map-metric') { setMapMetric(actBtn.dataset.metric); return; }
      act(kind);
      return;
    }
    const dact = ev.target.closest('[data-dact]');
    if (dact && state.drawerId) {
      ev.preventDefault();
      const kind = dact.dataset.dact;
      if (kind === 'probe') probeOne(state.drawerId, dact);
      else if (kind === 'purity') purityOne(state.drawerId, dact);
      else if (kind === 'download') downloadConfig(state.drawerId);
      else if (kind === 'copy') copyConfig(state.drawerId);
      return;
    }
    if (ev.target.id === 'drawer-mask') closeDrawer();
    if (ev.target.id === 'modal-mask') closeModal();
  });

  $('#d-close').addEventListener('click', closeDrawer);
  $('#modal-close').addEventListener('click', closeModal);
  $('#progress-cancel').addEventListener('click', async () => {
    if (!state.job) return;
    try { await api('/api/cancel', { method: 'POST', body: { kind: state.job.kind } }); toast('正在取消…', 'info'); }
    catch (e) { toast('取消失败: ' + e.message, 'err'); }
  });

  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') { closeDrawer(); closeModal(); }
    if (ev.key === '/' && !/input|textarea|select/i.test(document.activeElement.tagName)) {
      ev.preventDefault();
      showView('nodes');   // 搜索只在节点列表有用，先跳过去
      $('#search').focus();
    }
  });

  const saved = (() => { try { return localStorage.getItem('vpa-theme'); } catch { return null; } })();
  if (saved) {
    document.body.classList.remove('theme-dark', 'theme-light');
    document.body.classList.add(saved);
  }
}

async function copyConfig(id) {
  try {
    const resp = await fetch(`/api/nodes/${encodeURIComponent(id)}/config`, { credentials: 'same-origin' });
    if (!resp.ok) {
      const t = await resp.text();
      throw new Error(t.length > 160 ? t.slice(0, 160) : 'HTTP ' + resp.status);
    }
    const text = await resp.text();
    try {
      await navigator.clipboard.writeText(text);
      toast('配置已复制到剪贴板', 'ok');
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
      toast('配置已复制（旧浏览器回退方案）', 'ok');
    }
  } catch (e) {
    toast('复制失败: ' + e.message, 'err');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  bind();
  boot();
  state.timer = setInterval(() => { if (state.authed) loadStats(); }, 60000);
});
