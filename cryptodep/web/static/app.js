'use strict';

const $ = id => document.getElementById(id);
const stageNames = {clone: 'Clone repo', a1_ingestion: 'Baca kode', a2_detection: 'Deteksi', a3_reasoning: 'Dependensi', a4_builder: 'Susun graph', a5_planner: 'Rencana migrasi'};
const stageActivity = {clone: 'Meng-clone repository…', a1_ingestion: 'Membaca kode sumber…', a2_detection: 'Mendeteksi penggunaan kriptografi…', a3_reasoning: 'Menalar dependensi…', a4_builder: 'Membangun graph…', a5_planner: 'Menyusun laporan migrasi…'};
const quantumNames = {quantum_vulnerable: 'Rentan serangan kuantum (algoritma Shor)', grover_weakened: 'Diperlemah algoritma Grover; tinjau ukuran kunci', quantum_safe_symmetric: 'Simetris/hash; tidak rentan Shor', quantum_safe_pqc: 'Algoritma pascakuantum (PQC)', unknown: 'Belum diketahui'};
const statusNames = {running: 'Sedang dipindai', completed: 'Selesai', partial: 'Selesai sebagian', failed: 'Gagal', interrupted: 'Terputus'};
const typeNames = {AppComponent: 'Komponen', CryptoLibrary: 'Library', CryptoAlgorithm: 'Algoritma', PQCAlgorithm: 'Kandidat PQC', KeyMaterial: 'Material kunci', Protocol: 'Protokol', BusinessProcess: 'Proses bisnis'};
let current = null;
let documentData = null;
let graph = null;
let history = [];
let settings = {};
let polling = false;
let selectedNodeId = null;
let localFocus = false;
let activeLayout = null;
let layoutReady = false;
let lastTap = {id: null, time: 0};
let detailTimer = null;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

async function api(path, options = {}) {
  const response = await fetch(path, {headers: {'Content-Type': 'application/json'}, ...options});
  if (response.status === 204) return null;
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Permintaan tidak berhasil. Coba kembali.');
  return data;
}

function notice(message, error = false) {
  $('notice').textContent = message;
  $('notice').hidden = !message;
  $('notice').classList.toggle('error', error);
}

function normalized(value) { return String(value || '').split('.').pop().toLowerCase(); }
function riskLevel(node) { return node.metadata?.risk_assessment?.level || (normalized(node.quantum_vuln_class) === 'quantum_vulnerable' ? 'red' : 'gray'); }
function required(node) { return riskLevel(node) === 'red'; }
function riskLabel(node) {
  if (node.metadata?.risk_assessment) return node.metadata.risk_assessment.label;
  if (required(node)) return 'Perlu tindakan migrasi';
  if (node.node_type !== 'CryptoAlgorithm') return 'Komponen pendukung';
  if (!node.quantum_vuln_class || normalized(node.quantum_vuln_class) === 'unknown') return '? Belum diketahui';
  return 'Tidak ditandai perlu migrasi PQC';
}
function repoName(url) { return url.replace('https://github.com/', ''); }
function date(value) { return new Intl.DateTimeFormat('id-ID', {dateStyle: 'medium', timeStyle: 'short'}).format(new Date(value)); }

function showProgress(scan) {
  // While running, the canvas shows the stages; the panel appears once the scan has ended.
  $('progress-panel').hidden = scan.status === 'running';
  $('scan-status').textContent = statusNames[scan.status] || scan.status;
  const steps = Object.entries(scan.progress);
  const complete = steps.filter(([, status]) => status === 'completed').length;
  $('stage-count').textContent = `${complete} dari ${steps.length} tahap selesai`;
  $('stages').replaceChildren(...steps.map(([stage, status]) => {
    const li = element('li', stageNames[stage] || stage, status);
    li.title = `${stageNames[stage] || stage}: ${status}`;
    return li;
  }));
  // Mirror the active stage on the empty graph canvas while the scan runs.
  const running = scan.status === 'running';
  $('canvas-stages').hidden = !running;
  $('empty-state').classList.toggle('scanning', running);
  if (!running) return;
  $('canvas-stages').replaceChildren(...steps.map(([stage, status]) => element('li', stageNames[stage] || stage, status)));
  const active = steps.find(([, status]) => status === 'running')?.[0];
  $('empty-state').querySelector('h3').textContent = stageActivity[active] || 'Menyiapkan pemindaian…';
}

async function refreshHistory() {
  history = await api('/api/scans');
  $('history-count').textContent = history.length;
  updateScanControls();
  const rows = history.map(scan => {
    const row = element('div', undefined, 'history-row');
    const button = element('button', undefined, 'history-item');
    const content = element('div');
    content.append(element('strong', repoName(scan.repo_url)), element('p', `${date(scan.created_at)} · ${scan.model}`));
    if (scan.summary.nodes !== undefined) content.append(element('p', `${scan.summary.nodes} node · ${scan.summary.edges} hubungan · ${scan.summary.requires_migration} prioritas PQC inti`));
    button.append(content, element('span', statusNames[scan.status] || scan.status, 'badge'));
    button.addEventListener('click', () => { $('history-dialog').close(); openScan(scan).catch(error => notice(error.message, true)); });
    const remove = element('button', '×', 'icon-button history-delete');
    remove.setAttribute('aria-label', `Hapus riwayat ${repoName(scan.repo_url)}`);
    remove.disabled = scan.status === 'running';
    remove.title = remove.disabled ? 'Pemindaian yang berjalan tidak dapat dihapus' : 'Hapus riwayat dan berkas hasil';
    remove.addEventListener('click', () => deleteScan(scan));
    row.append(button, remove);
    return row;
  });
  $('history-list').replaceChildren(...(rows.length ? rows : [element('p', 'Belum ada pemindaian. Hasil pertama Anda akan tersimpan di sini.', 'muted')]));
}

// Viewing a scan locks the repo field; "Pemindaian baru" unlocks it for the next URL.
let viewing = false;

function updateScanControls() {
  const running = history.some(scan => scan.status === 'running');
  $('repo-url').disabled = viewing;
  document.body.classList.toggle('compact', Boolean(current));
  // One scan at a time: block both "start" and "new scan" until the running scan ends.
  $('scan-button').disabled = running;
  $('scan-button').textContent = running ? 'Proses pemindaian…' : viewing ? 'Pemindaian baru' : 'Mulai pemindaian ↗';
}

function newScan() {
  viewing = false; $('repo-url').value = '';
  updateScanControls(); $('repo-url').focus();
}

function confirmDialog(message) {
  const dialog = $('confirm-dialog');
  $('confirm-message').textContent = message;
  dialog.returnValue = '';
  dialog.showModal();
  return new Promise(resolve => dialog.addEventListener('close', () => resolve(dialog.returnValue === 'ok'), {once: true}));
}

async function deleteScan(scan) {
  if (!await confirmDialog(`Riwayat ${repoName(scan.repo_url)} beserta berkas hasil dan percakapannya akan dihapus. Tindakan ini tidak dapat dibatalkan.`)) return;
  try {
    await api(`/api/scans/${scan.id}`, {method: 'DELETE'});
    if (current?.id === scan.id) {
      current = null; clearResult(); toggleLog(false); $('log-toggle').hidden = true;
      $('result-title').textContent = 'Dependency graph'; $('scan-badge').textContent = 'Belum ada pemindaian';
      $('progress-panel').hidden = true; notice('');
      viewing = false; $('repo-url').value = '';
    }
    await refreshHistory();
  } catch (error) { notice(error.message, true); }
}

let askFlow = null;

function clearAsk() {
  clearInterval(askFlow); askFlow = null;
  if (graph) graph.elements().removeClass('ask-dim ask-hit ask-path');
}

function addMessage(role, text) {
  const message = element('div', undefined, `ask-message ${role}`);
  message.append(element('p', text));
  $('ask-log').append(message);
  $('ask-log').scrollTop = $('ask-log').scrollHeight;
  return message;
}

function toggleAsk(open, focus = true) {
  $('ask-panel').hidden = !open; $('ask-toggle').hidden = open;
  $('ask-toggle').setAttribute('aria-expanded', String(open));
  if (!open) clearAsk();
  if (focus) (open ? $('ask-input') : $('ask-toggle')).focus();
}

function renderAnswer(result, message) {
  const byId = new Map((documentData?.nodes || []).map(node => [node.node_id, node]));
  const chips = element('div', undefined, 'ask-nodes');
  chips.append(...result.node_ids.map(id => {
    const button = element('button', byId.get(id)?.label || id, `related-button risk-${riskLevel(byId.get(id) || {})}`);
    button.type = 'button'; button.addEventListener('click', () => showDetail(id));
    return button;
  }));
  if (result.node_ids.length) {
    const again = element('button', '↺ Sorot di graph', 'related-button ask-again');
    again.type = 'button'; again.addEventListener('click', () => highlightAnswer(result)); chips.append(again);
  }
  message.replaceChildren(element('p', result.answer), chips);
  $('ask-log').scrollTop = $('ask-log').scrollHeight;
}

async function loadQuestions(scanId) {
  const saved = await api(`/api/scans/${scanId}/questions`);
  if (current?.id !== scanId || !saved.length) return;
  $('ask-log').querySelector('.ask-hint')?.remove();
  for (const item of saved) { addMessage('user', item.question); renderAnswer(item, addMessage('assistant', '')); }
}

function highlightAnswer(result) {
  clearAsk();
  if (!graph || !result.node_ids.length) return;
  const hits = graph.collection(result.node_ids.map(id => graph.getElementById(id)));
  let path = graph.collection();
  for (let i = 1; i < result.path.length; i++) {
    const [a, b] = [result.path[i - 1], result.path[i]];
    path = path.union(graph.edges().filter(edge => [edge.source().id(), edge.target().id()].sort().join() === [a, b].sort().join()));
  }
  graph.elements().addClass('ask-dim');
  hits.union(path).union(hits.edgesWith(hits)).removeClass('ask-dim');
  hits.addClass('ask-hit'); path.addClass('ask-path');
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduced) graph.fit(hits, 70); else graph.animate({fit: {eles: hits, padding: 70}, duration: 500});
  // Moving dashes show the answer's path as a flow along the edges.
  if (path.length && !reduced) { let offset = 0; askFlow = setInterval(() => path.style('line-dash-offset', offset -= 1), 40); }
}

function clearResult() {
  stopForces();
  clearAsk();
  $('ask-log').replaceChildren(element('p', 'Tanyakan apa saja tentang graph ini. Contoh: "Komponen apa yang terdampak jika RSA dibobol?" Node terkait akan disorot di graph.', 'ask-hint'));
  documentData = null;
  selectedNodeId = null; localFocus = false;
  clearTimeout(detailTimer); detailTimer = null;
  layoutReady = false; lastTap = {id: null, time: 0};
  if (activeLayout) activeLayout.stop();
  $('local-graph').setAttribute('aria-pressed', 'false');
  $('local-graph').textContent = 'Fokus lokal';
  $('filter-empty').hidden = true;
  $('graph-tooltip').hidden = true;
  $('risk-filter').value = 'all'; $('type-filter').value = 'all';
  $('node-search').value = '';
  if (graph) { graph.destroy(); graph = null; }
  $('empty-state').hidden = false;
  $('node-detail').hidden = true;
  $('result-meta').hidden = true;
  $('node-count').textContent = '0';
  $('edge-count').textContent = '0';
  $('migration-count').textContent = '';
  $('node-list').replaceChildren();
  $('list-empty').hidden = false;
  for (const id of ['fit-graph', 'zoom-in', 'zoom-out', 'node-search', 'download-cdg', 'relayout-graph', 'local-graph', 'ask-input', 'ask-button', 'ask-toggle']) $(id).disabled = true;
}

async function openScan(scan) {
  current = scan;
  clearResult();
  $('result-title').textContent = repoName(scan.repo_url);
  $('repo-url').value = scan.repo_url;
  viewing = true; updateScanControls();
  $('log-toggle').hidden = false;
  $('scan-badge').textContent = statusNames[scan.status] || scan.status;
  showProgress(scan);
  // Older partial scans stored a message pointing at the footer; the details now live in the log.
  notice(scan.status === 'partial' ? 'Sebagian tahap memiliki keterbatasan. Lihat rinciannya di Log proses.' : scan.error || '', ['failed', 'interrupted'].includes(scan.status));
  if (['completed', 'partial'].includes(scan.status)) {
    const data = await api(`/api/scans/${scan.id}/graph`);
    if (current.id !== scan.id) return;
    documentData = data;
    drawResult();
    loadQuestions(scan.id).catch(error => notice(`Riwayat percakapan tidak dapat dimuat: ${error.message}`, true));
  } else {
    // No graph to ask about (e.g. a scan is running), so the chatbox closes.
    toggleAsk(false, false);
    if (scan.status !== 'running') $('empty-state').querySelector('h3').textContent = 'Graph belum tersedia.';
    $('empty-state').querySelector('p').textContent = scan.status === 'running' ? 'Sembari menunggu proses pemindaian. Anda dapat membuka riwayat pemindaian terdahulu.' : scan.error || 'Mulai pemindaian baru untuk mencoba kembali.';
  }
  // After the graph loads, so a partial result's limitations are part of the log summary.
  loadLog().catch(error => notice(`Log proses tidak dapat dimuat: ${error.message}`, true));
}

// Graph colours come from CSS tokens, so light/dark mode share one palette definition.
function graphStyle() {
  const css = getComputedStyle(document.documentElement);
  const t = name => css.getPropertyValue(`--${name}`).trim();
  return [
    {selector: 'node', style: {'background-color': t('g-node'), 'border-color': t('g-node-line'), 'border-width': 1, width: 'data(size)', height: 'data(size)', label: 'data(label)', 'font-family': 'Inter', 'font-size': 12, color: t('steel'), 'text-valign': 'bottom', 'text-margin-y': 8, 'text-wrap': 'wrap', 'text-max-width': 120, 'transition-property': 'opacity', 'transition-duration': '180ms'}},
    // Shape encodes node type; colour encodes risk.
    {selector: 'node[type="AppComponent"]', style: {shape: 'round-rectangle'}},
    {selector: 'node[type="CryptoLibrary"]', style: {shape: 'round-hexagon'}},
    {selector: 'node[type="KeyMaterial"]', style: {shape: 'round-triangle'}},
    {selector: 'node[type="Protocol"]', style: {shape: 'round-pentagon'}},
    {selector: 'node[type="BusinessProcess"]', style: {shape: 'round-tag'}},
    {selector: 'node[risk="red"]', style: {'background-color': t('g-red'), 'border-color': t('red'), color: t('red')}},
    {selector: 'node[risk="orange"]', style: {'background-color': t('g-orange'), 'border-color': t('orange'), color: t('orange')}},
    {selector: 'node[risk="unknown"]', style: {'background-color': t('white'), 'border-style': 'dashed', 'border-width': 2}},
    {selector: 'node[type="PQCAlgorithm"]', style: {shape: 'round-diamond', 'background-color': t('g-green'), 'border-color': t('green'), color: t('green')}},
    {selector: 'edge', style: {width: 1, 'line-color': t('g-edge'), 'target-arrow-color': t('g-arrow'), 'target-arrow-shape': 'triangle', 'arrow-scale': .7, 'curve-style': 'bezier', label: 'data(label)', 'font-family': 'Inter', 'font-size': 10, color: t('ash'), 'text-background-color': t('white'), 'text-background-opacity': .9, 'text-background-padding': 3, 'text-rotation': 'autorotate', 'transition-property': 'opacity', 'transition-duration': '180ms'}},
    {selector: 'edge[label="migrates_to"]', style: {'line-color': t('g-green'), 'target-arrow-color': t('green'), 'line-style': 'dashed', 'line-dash-pattern': [5, 4], width: 1.5}},
    {selector: ':selected', style: {'border-color': t('ink'), 'border-width': 3}},
    {selector: '.hover-fade', style: {opacity: .16}},
    {selector: '.hover-active', style: {'z-index': 10}},
    {selector: '.pinned', style: {'border-width': 3, 'border-style': 'double'}},
    {selector: '.ask-dim', style: {opacity: .12}},
    {selector: 'node.ask-hit', style: {'border-color': t('ink'), 'border-width': 3, 'z-index': 20}},
    {selector: 'edge.ask-path', style: {width: 3, 'line-color': t('ink'), 'target-arrow-color': t('ink'), 'line-style': 'dashed', 'line-dash-pattern': [7, 5], 'z-index': 20}}
  ];
}

const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');
const themeIcons = {dark: 'M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5Z',
  light: 'M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6 7 7M17 17l1.4 1.4M5.6 18.4 7 17M17 7l1.4-1.4M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z'};

function currentTheme() { return document.documentElement.dataset.theme || (darkQuery.matches ? 'dark' : 'light'); }

// A manual choice (data-theme) overrides the OS setting; without one the OS setting applies.
function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme;
  const dark = currentTheme() === 'dark';
  $('theme-toggle').setAttribute('aria-label', dark ? 'Ganti ke mode terang' : 'Ganti ke mode gelap');
  $('theme-toggle').querySelector('path').setAttribute('d', dark ? themeIcons.light : themeIcons.dark);
  if (graph) { graph.style(graphStyle()); applyDisplayOptions(); }
}

darkQuery.addEventListener('change', () => applyTheme());
$('theme-toggle').addEventListener('click', () => {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  try { localStorage.setItem('cryptodep-theme', next); } catch { /* storage blocked: choice lasts until reload */ }
  applyTheme(next);
});
try { applyTheme(localStorage.getItem('cryptodep-theme')); } catch { applyTheme(); }

function drawResult() {
  const nodes = documentData.nodes || [];
  const ids = new Set(nodes.map(node => node.node_id));
  const edges = (documentData.edges || []).filter(edge => ids.has(edge.source_id) && ids.has(edge.target_id));
  $('node-count').textContent = nodes.length;
  $('edge-count').textContent = edges.length;
  const counts = documentData.risk_summary || {};
  $('migration-count').textContent = `${counts.red || 0} migrasi PQC · ${counts.orange || 0} tinjau keamanan · ${counts.unknown || 0} belum diketahui`;
  $('empty-state').hidden = nodes.length > 0;
  if (!nodes.length) {
    $('empty-state').querySelector('h3').textContent = 'Tidak ada node kriptografi yang ditemukan.';
    $('empty-state').querySelector('p').textContent = 'Ini bukan jaminan kode bebas dari penggunaan atau kelemahan kriptografi. Tinjau cakupan dan catatan analisis.';
  }
  for (const id of ['fit-graph', 'zoom-in', 'zoom-out', 'node-search', 'relayout-graph', 'ask-input', 'ask-button', 'ask-toggle']) $(id).disabled = !nodes.length;
  $('download-cdg').disabled = false;
  if (typeof cytoscape !== 'function') {
    notice('Renderer graph tidak tersedia. Gunakan tampilan Daftar untuk membaca hasil.', true);
    setView('list');
  } else {
    const degrees = new Map(nodes.map(node => [node.node_id, 0]));
    for (const edge of edges) { degrees.set(edge.source_id, degrees.get(edge.source_id) + 1); degrees.set(edge.target_id, degrees.get(edge.target_id) + 1); }
    graph = cytoscape({
      container: $('graph'), minZoom: .15, maxZoom: 3, wheelSensitivity: 1,
      elements: [
        ...nodes.map(node => ({data: {id: node.node_id, label: (riskLevel(node) === 'unknown' ? '? ' : '') + (node.label || node.node_type), type: node.node_type, risk: riskLevel(node), degree: degrees.get(node.node_id), size: 24 + Math.min(16, degrees.get(node.node_id)) * 2}})),
        ...edges.map((edge, index) => ({data: {id: `edge-${index}`, source: edge.source_id, target: edge.target_id, label: edge.edge_type, evidence: edge.evidence || '', confidence: edge.confidence}}))
      ],
      style: graphStyle(),
      layout: {name: 'preset'}
    });
    graph.on('tap', 'node', event => {
      const id = event.target.id(); const now = Date.now();
      clearTimeout(detailTimer);
      // Keep the node still until a possible second click, before opening the side panel.
      if (lastTap.id === id && now - lastTap.time < 350) {
        showDetail(id); toggleLocal(true); lastTap = {id: null, time: 0};
      } else {
        lastTap = {id, time: now};
        detailTimer = setTimeout(() => showDetail(id), 350);
      }
    });
    graph.on('grab', () => clearTimeout(detailTimer));
    // Obsidian-style: dragging a node pulls its neighbours, then the graph settles.
    graph.on('drag free', 'node', () => runForces());
    graph.on('tap', 'edge', event => showEdgeDetail(event.target));
    graph.on('mouseover', 'node', event => {
      highlightConnections(event.target);
      const node = nodes.find(node => node.node_id === event.target.id());
      const position = event.target.renderedPosition();
      $('graph-tooltip').textContent = `${node.label}\n${riskLabel(node)} · ${event.target.data('degree')} hubungan`;
      $('graph-tooltip').style.left = `${Math.max(8, Math.min(position.x + 15, $('graph').clientWidth - 235))}px`;
      $('graph-tooltip').style.top = `${Math.max(8, Math.min(position.y + 15, $('graph').clientHeight - 90))}px`;
      $('graph-tooltip').hidden = false;
    });
    graph.on('mouseout', 'node', () => { $('graph-tooltip').hidden = true; highlightConnections(selectedNodeId ? graph.getElementById(selectedNodeId) : null); });
    graph.on('pan zoom drag', () => { $('graph-tooltip').hidden = true; });
    applyDisplayOptions();
    applyFilters();
    layoutGraph();
  }
  renderList();
  const meta = $('result-meta');
  const summary = documentData.scan_stats || {};
  meta.replaceChildren(element('span', `Commit ${current.commit_sha?.slice(0, 12) || 'tidak diketahui'} · ${summary.total_files ?? summary.files_scanned ?? '—'} file · ${current.model} · ${date(current.created_at)}`));
  for (const [kind, label] of [['cdg', 'CDG JSON'], ['cbom', 'CBOM'], ['report', 'Laporan']]) {
    const link = element('a', label); link.href = `/api/scans/${current.id}/download/${kind}`; meta.append(link);
  }
  for (const note of documentData.analysis_notes || []) meta.append(element('p', note));
  meta.hidden = false;
}

function renderList() {
  const visible = visibleNodeIds();
  const rows = (documentData?.nodes || []).filter(node => visible.has(node.node_id)).map(node => {
    const row = element('tr');
    const name = element('td');
    const button = element('button', node.label || node.node_type, `node-button risk-${riskLevel(node)}`);
    button.addEventListener('click', () => showDetail(node.node_id)); name.append(button);
    const risk = element('td'); risk.append(element('span', riskLabel(node), `risk risk-${riskLevel(node)}`));
    const assessment = node.metadata?.risk_assessment;
    if (assessment?.classical_warnings.length) risk.append(element('span', assessment.classical_warnings.map(warning => warning.title).join(' · '), 'risk-caption'));
    row.append(name, element('td', typeNames[node.node_type] || node.node_type), risk, element('td', node.confidence == null ? '—' : `${Math.round(node.confidence * 100)}%`));
    return row;
  });
  $('node-list').replaceChildren(...rows);
  $('list-empty').hidden = rows.length > 0;
  $('list-empty').textContent = documentData?.nodes?.length ? 'Tidak ada node sesuai pencarian atau filter.' : 'Belum ada node untuk ditampilkan.';
}

function section(parent, title) { parent.append(element('p', title, 'detail-label')); }

function showDetail(id) {
  clearTimeout(detailTimer); detailTimer = null;
  const node = documentData?.nodes.find(item => item.node_id === id);
  if (!node) return;
  selectedNodeId = id;
  $('local-graph').disabled = !graph || !graph.getElementById(id).visible();
  const body = $('detail-body');
  body.replaceChildren(element('h3', node.label || node.node_type), element('span', typeNames[node.node_type] || node.node_type, 'badge'));
  body.append(element('span', riskLabel(node), `assessment-badge risk-${riskLevel(node)}`));
  const actions = element('div', undefined, 'node-actions');
  const focus = element('button', localFocus ? 'Graph keseluruhan' : 'Fokus tetangga', 'button ghost focus-node-action');
  focus.disabled = !graph; focus.addEventListener('click', () => toggleLocal()); actions.append(focus);
  const pin = element('button', graph?.getElementById(id).locked() ? 'Lepas posisi' : 'Sematkan posisi', 'button ghost');
  pin.disabled = !graph;
  pin.addEventListener('click', () => {
    const target = graph.getElementById(id);
    if (target.locked()) { target.unlock().removeClass('pinned'); } else { target.lock().addClass('pinned'); }
    pin.textContent = target.locked() ? 'Lepas posisi' : 'Sematkan posisi';
  });
  actions.append(pin); body.append(actions);
  section(body, 'Risiko kuantum');
  const assessment = node.metadata?.risk_assessment;
  body.append(element('p', assessment?.pqc_reason || riskLabel(node)));
  if (node.quantum_vuln_class) body.append(element('p', `Klasifikasi kuantum: ${quantumNames[normalized(node.quantum_vuln_class)] || node.quantum_vuln_class}`));
  if (node.migration_urgency_score != null) body.append(element('p', `Skor urgensi PQC inti: ${node.migration_urgency_score}/100`));
  if (node.parameter_set) body.append(element('p', `Parameter: ${node.parameter_set}`));
  if (node.node_type === 'CryptoAlgorithm') {
    section(body, 'Peringatan keamanan klasik');
    const warnings = assessment?.classical_warnings || [];
    if (!warnings.length) body.append(element('p', 'Tidak ada peringatan dari aturan klasik yang tersedia. Ini bukan pemeriksaan lengkap seluruh kelemahan kriptografi.'));
    for (const warning of warnings) {
      const card = element('div', undefined, 'warning-card');
      card.append(element('strong', warning.title), element('p', warning.reason), element('p', warning.action));
      for (const [index, source] of (warning.sources || []).entries()) {
        const link = element('a', `Rujukan ${index + 1}`); link.href = source; link.target = '_blank'; link.rel = 'noopener noreferrer'; card.append(link);
      }
      body.append(card);
    }
  }
  section(body, 'Kepastian & cakupan analisis');
  const detectionNames = {static_rule: 'Aturan statis', hybrid: 'Statis + LLM', llm_semantic: 'Usulan LLM'};
  const methods = (assessment?.detection_methods || []).map(method => detectionNames[normalized(method)] || method);
  body.append(element('p', `Asal temuan: ${methods.join(', ') || 'belum diketahui'}`));
  if (node.confidence != null) body.append(element('p', `Confidence yang dicatat: ${Math.round(node.confidence * 100)}%`));
  body.append(element('p', assessment?.evidence_status || 'Bukti belum tersedia'), element('p', assessment?.analysis_limit || 'Hubungan graph belum membuktikan perilaku saat runtime.'));
  if (node.node_type === 'CryptoAlgorithm') {
    section(body, 'Lokasi kode & bukti');
    const findings = node.metadata?.findings || [];
    if (!findings.length) body.append(element('p', node.source_ref || 'Bukti lokasi belum tersedia untuk hasil ini.'));
    for (const finding of findings) {
      const item = element('div', undefined, 'evidence-item');
      const url = current.commit_sha && finding.file ? `${current.repo_url}/blob/${current.commit_sha}/${finding.file.split('/').map(encodeURIComponent).join('/')}#L${finding.line}` : null;
      if (url) {
        const link = element('a', finding.source_ref); link.href = url; link.target = '_blank'; link.rel = 'noopener noreferrer'; item.append(link);
      } else item.append(element('p', finding.source_ref));
      item.append(element('pre', finding.evidence || 'Bukti belum tersedia.'));
      body.append(item);
    }
    section(body, 'Saran migrasi');
    let suggestions = node.metadata?.migration_suggestions || [];
    if (!suggestions.length) suggestions = documentData.edges.filter(edge => edge.source_id === id && edge.edge_type === 'migrates_to').map(edge => ({algorithm: documentData.nodes.find(n => n.node_id === edge.target_id)?.label, reason: edge.evidence}));
    if (!suggestions.length) body.append(element('p', required(node) ? 'Tinjau konteks penggunaan dan parameter sebelum menentukan pengganti.' : 'Tidak ada saran migrasi PQC pada hasil ini. Kelemahan klasik tetap perlu ditinjau.'));
    for (const suggestion of suggestions) {
      const card = element('div', undefined, 'suggestion');
      card.append(element('strong', suggestion.algorithm || 'Perlu peninjauan'));
      if (suggestion.context) card.append(element('p', suggestion.context.replaceAll('_', ' ')));
      if (suggestion.reason) card.append(element('p', suggestion.reason));
      if (suggestion.hybrid) card.append(element('p', `Hybrid: ${suggestion.hybrid}`));
      body.append(card);
    }
    section(body, 'Komponen yang perlu ditinjau');
    const queue = [{id, path: [node.label]}]; const visited = new Set([id]); let found = 0;
    while (queue.length) {
      const item = queue.shift();
      for (const edge of documentData.edges.filter(edge => edge.target_id === item.id && edge.edge_type !== 'migrates_to')) {
        if (visited.has(edge.source_id)) continue;
        visited.add(edge.source_id);
        const source = documentData.nodes.find(n => n.node_id === edge.source_id);
        if (!source) continue;
        const path = [source.label, ...item.path];
        if (source.node_type === 'AppComponent') {
          const button = element('button', source.label, 'related-button'); button.addEventListener('click', () => showDetail(source.node_id)); body.append(button, element('p', path.join(' → '))); found++;
        }
        queue.push({id: source.node_id, path});
      }
    }
    if (!found) body.append(element('p', 'Belum ada komponen terkait yang dapat ditelusuri dari graph ini.'));
  } else {
    if (node.file_path || node.source_ref) { section(body, 'Lokasi sumber'); body.append(element('p', node.file_path || node.source_ref)); }
    section(body, 'Hubungan terkait');
    let count = 0;
    for (const edge of documentData.edges.filter(edge => edge.source_id === id || edge.target_id === id)) {
      const other = documentData.nodes.find(n => n.node_id === (edge.source_id === id ? edge.target_id : edge.source_id));
      if (!other) continue;
      const button = element('button', `${other.label} · ${edge.edge_type}`, 'related-button'); button.addEventListener('click', () => showDetail(other.node_id)); body.append(button); count++;
    }
    if (!count) body.append(element('p', 'Tidak ada hubungan pada hasil ini.'));
  }
  $('node-detail').hidden = false;
  $('node-detail').scrollTop = 0;
  if (graph) {
    const target = graph.getElementById(id);
    graph.elements().unselect(); target.select(); highlightConnections(target);
    // The detail panel floats over the canvas; slide the graph so the selected node stays visible.
    const limit = graph.width() - $('node-detail').offsetWidth - 40;
    const x = target.renderedPosition().x;
    if (target.visible() && x > limit) graph.animate({panBy: {x: limit - x, y: 0}}, {duration: 300});
  }
}

function visibleNodeIds() {
  const nodes = documentData?.nodes || [];
  const edges = documentData?.edges || [];
  const query = $('node-search').value.trim().toLowerCase();
  const linked = new Set(edges.flatMap(edge => [edge.source_id, edge.target_id]));
  const ids = new Set(nodes.filter(node => {
    const text = `${node.label} ${node.node_type} ${node.algorithm_family || ''} ${node.file_path || ''} ${node.source_ref || ''}`.toLowerCase();
    return text.includes(query) && ($('risk-filter').value === 'all' || riskLevel(node) === $('risk-filter').value)
      && ($('type-filter').value === 'all' || node.node_type === $('type-filter').value)
      && ($('show-orphans').checked || linked.has(node.node_id));
  }).map(node => node.node_id));
  if (!localFocus || !selectedNodeId || !ids.has(selectedNodeId)) return ids;
  const reached = new Set([selectedNodeId]);
  let frontier = new Set([selectedNodeId]);
  for (let depth = 0; depth < Number($('local-depth').value); depth++) {
    const next = new Set();
    for (const edge of edges) {
      if (!ids.has(edge.source_id) || !ids.has(edge.target_id)) continue;
      if (frontier.has(edge.source_id) && !reached.has(edge.target_id)) next.add(edge.target_id);
      if (frontier.has(edge.target_id) && !reached.has(edge.source_id)) next.add(edge.source_id);
    }
    for (const id of next) reached.add(id);
    frontier = next;
  }
  return reached;
}

function applyFilters() {
  const ids = visibleNodeIds();
  const total = documentData?.nodes?.length || 0;
  $('node-count').textContent = ids.size === total ? String(total) : `${ids.size}/${total}`;
  $('filter-empty').hidden = !total || ids.size > 0;
  if (graph) {
    graph.batch(() => {
      graph.nodes().forEach(node => ids.has(node.id()) ? node.show() : node.hide());
      graph.edges().forEach(edge => ids.has(edge.source().id()) && ids.has(edge.target().id()) ? edge.show() : edge.hide());
    });
    $('edge-count').textContent = graph.edges(':visible').length;
    if (selectedNodeId && !ids.has(selectedNodeId)) {
      selectedNodeId = null; localFocus = false; $('node-detail').hidden = true;
    }
    $('local-graph').disabled = !selectedNodeId;
    highlightConnections(selectedNodeId ? graph.getElementById(selectedNodeId) : null);
  }
  $('local-graph').setAttribute('aria-pressed', String(localFocus));
  $('local-graph').textContent = localFocus ? 'Graph keseluruhan' : 'Fokus lokal';
  document.querySelectorAll('.focus-node-action').forEach(button => { button.textContent = localFocus ? 'Graph keseluruhan' : 'Fokus tetangga'; });
  renderList();
}

function highlightConnections(node) {
  if (!graph) return;
  graph.elements().removeClass('hover-fade hover-active');
  if (!node || !node.length || !node.visible()) return;
  graph.elements(':visible').addClass('hover-fade');
  node.closedNeighborhood().filter(':visible').removeClass('hover-fade').addClass('hover-active');
}

function toggleLocal(force) {
  if (!graph || !selectedNodeId) return;
  localFocus = typeof force === 'boolean' ? force : !localFocus;
  applyFilters(); fitGraph();
}

function fitGraph() {
  if (graph && !$('graph-view').hidden && graph.nodes(':visible').length) graph.fit(graph.elements(':visible'), 45);
}

let forceFrame = null;
let forceHeat = 0;

function stopForces() { cancelAnimationFrame(forceFrame); forceFrame = null; }

// Small live force simulation (repulsion + edge springs) so the graph reacts while dragging.
// shortcut: O(n²) per frame, skipped above 250 nodes; switch to a Barnes-Hut library if graphs grow.
function runForces() {
  forceHeat = 1;
  if (forceFrame || !graph || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const nodes = graph.nodes(':visible');
  if (nodes.length > 250) return;
  if (activeLayout) activeLayout.stop();
  const velocity = new Map();
  const tick = () => {
    const list = graph.nodes(':visible');
    const position = new Map(list.map(node => [node.id(), {...node.position()}]));
    const force = new Map(list.map(node => [node.id(), {x: 0, y: 0}]));
    const repel = Number($('repel-force').value) / 3; const length = Number($('link-distance').value);
    for (let i = 0; i < list.length; i++) for (let j = i + 1; j < list.length; j++) {
      const a = position.get(list[i].id()); const b = position.get(list[j].id());
      const dx = a.x - b.x; const dy = a.y - b.y; const d2 = Math.max(dx * dx + dy * dy, 100); const d = Math.sqrt(d2);
      // Collision push below ~80px keeps nodes and their labels apart while dragging.
      const f = repel / d2 + Math.max(0, 80 - d) * .35; const fa = force.get(list[i].id()); const fb = force.get(list[j].id());
      fa.x += dx / d * f; fa.y += dy / d * f; fb.x -= dx / d * f; fb.y -= dy / d * f;
    }
    graph.edges(':visible').forEach(edge => {
      const a = position.get(edge.source().id()); const b = position.get(edge.target().id());
      if (!a || !b || a === b) return;
      const dx = b.x - a.x; const dy = b.y - a.y; const d = Math.max(Math.hypot(dx, dy), 1); const f = (d - length) * .03;
      const fa = force.get(edge.source().id()); const fb = force.get(edge.target().id());
      fa.x += dx / d * f; fa.y += dy / d * f; fb.x -= dx / d * f; fb.y -= dy / d * f;
    });
    let moving = 0;
    graph.batch(() => list.forEach(node => {
      if (node.grabbed() || node.locked()) return;
      const v = velocity.get(node.id()) || {x: 0, y: 0}; const f = force.get(node.id());
      v.x = Math.max(-25, Math.min(25, (v.x + f.x * forceHeat) * .7)); v.y = Math.max(-25, Math.min(25, (v.y + f.y * forceHeat) * .7));
      velocity.set(node.id(), v); moving = Math.max(moving, Math.abs(v.x) + Math.abs(v.y));
      const p = position.get(node.id()); node.position({x: p.x + v.x, y: p.y + v.y});
    }));
    if (!graph.nodes(':grabbed').length) forceHeat *= .97;
    forceFrame = forceHeat > .03 || moving > .2 ? requestAnimationFrame(tick) : null;
  };
  forceFrame = requestAnimationFrame(tick);
}

function layoutGraph(animate = true) {
  if (!graph || $('graph-view').hidden || !graph.nodes(':visible').length) return;
  stopForces();
  layoutReady = true;
  if (activeLayout) activeLayout.stop();
  const visible = graph.elements(':visible');
  const pinned = graph.nodes(':locked').map(node => ({node, position: {...node.position()}}));
  activeLayout = visible.layout({name: visible.nodes().length > 250 ? 'circle' : 'cose',
    animate: animate && !window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    animationDuration: 450, padding: 45, randomize: !pinned.length,
    nodeRepulsion: Number($('repel-force').value), idealEdgeLength: Number($('link-distance').value),
    // Count labels as part of each node so text does not end up under neighbouring nodes.
    nodeDimensionsIncludeLabels: true, nodeOverlap: 24, spacingFactor: 1.1,
    componentSpacing: 100, numIter: 1000,
    stop: () => { for (const item of pinned) item.node.position(item.position); fitGraph(); }});
  activeLayout.run();
}

function applyDisplayOptions() {
  if (!graph) return;
  const scale = Number($('node-size').value) / 100;
  graph.nodes().forEach(node => node.style({width: node.data('size') * scale, height: node.data('size') * scale}));
  graph.style().selector('node').style('label', $('show-labels').checked ? 'data(label)' : '')
    .selector('edge').style({label: $('show-edge-labels').checked ? 'data(label)' : '',
      'target-arrow-shape': $('show-arrows').checked ? 'triangle' : 'none'}).update();
}

function showEdgeDetail(target) {
  clearTimeout(detailTimer); detailTimer = null;
  const source = target.source().data('label'); const destination = target.target().data('label');
  const body = $('detail-body');
  body.replaceChildren(element('h3', target.data('label')), element('p', `${source} → ${destination}`));
  section(body, 'Bukti hubungan');
  body.append(element('pre', target.data('evidence') || 'Bukti teks belum tersedia.'));
  if (target.data('confidence') != null) body.append(element('p', `Confidence yang dicatat: ${Math.round(target.data('confidence') * 100)}%`));
  body.append(element('p', 'Hubungan ini berasal dari analisis statis/penalaran dependensi. Dukungan import bukan bukti aliran data atau pemanggilan runtime.'));
  $('node-detail').hidden = false;
  graph.elements().unselect(); target.select();
}

function setView(view) {
  const showGraph = view === 'graph';
  $('graph-view').hidden = !showGraph; $('list-view').hidden = showGraph;
  for (const [id, selected] of [['graph-tab', showGraph], ['list-tab', !showGraph]]) {
    $(id).classList.toggle('selected', selected); $(id).setAttribute('aria-selected', String(selected));
  }
  if (showGraph && graph) { graph.resize(); if (!layoutReady) layoutGraph(false); else fitGraph(); }
}

async function loadSettings() {
  settings = await api('/api/settings');
  $('model-caption').textContent = settings.model ? `AI / ${settings.model}` : 'Endpoint AI belum dikonfigurasi';
}

async function openSettings() {
  try {
    await loadSettings();
    $('ai-endpoint').value = settings.endpoint || '';
    $('ai-model').value = settings.model || '';
    $('ai-key').value = ''; $('clear-key').checked = false;
    $('ai-key').placeholder = settings.has_key ? 'Key tersimpan · kosongkan untuk mempertahankan' : 'Masukkan API key';
    $('key-status').textContent = settings.has_key ? 'Key tersimpan di server. Nilainya tidak ditampilkan kembali.' : 'Key hanya disimpan di server dan tidak dikirim kembali ke browser.';
    $('settings-message').textContent = '';
    $('settings-dialog').showModal();
  } catch (error) { notice(error.message, true); }
}

function settingsPayload() {
  const value = {endpoint: $('ai-endpoint').value.trim(), model: $('ai-model').value.trim()};
  if ($('clear-key').checked) value.api_key = '';
  else if ($('ai-key').value) value.api_key = $('ai-key').value;
  return value;
}

$('scan-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (viewing) { newScan(); return; }
  if (!settings.endpoint || !settings.model) { notice('Hubungkan endpoint dan nama model AI sebelum mulai.'); openSettings(); return; }
  $('scan-button').disabled = true;
  try {
    const scan = await api('/api/scans', {method: 'POST', body: JSON.stringify({repo_url: $('repo-url').value.trim()})});
    await refreshHistory(); await openScan(scan);
  } catch (error) { notice(error.message, true); await refreshHistory().catch(() => {}); }
});
$('settings-open').addEventListener('click', openSettings);
$('settings-inline').addEventListener('click', openSettings);
$('settings-close').addEventListener('click', () => $('settings-dialog').close());
$('settings-dialog').addEventListener('close', () => { $('ai-key').value = ''; });
$('history-open').addEventListener('click', async () => { try { await refreshHistory(); $('history-dialog').showModal(); } catch (error) { notice(error.message, true); } });
$('history-close').addEventListener('click', () => $('history-dialog').close());
$('workspace-link').addEventListener('click', () => $('repo-url').focus());
$('settings-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.submitter; button.disabled = true;
  try {
    await api('/api/settings', {method: 'PUT', body: JSON.stringify(settingsPayload())});
    await loadSettings(); $('settings-dialog').close(); notice('Pengaturan AI disimpan. Berlaku untuk pemindaian berikutnya.');
  } catch (error) { $('settings-message').textContent = error.message; }
  finally { button.disabled = false; }
});
$('test-ai').addEventListener('click', async () => {
  if (!$('settings-form').reportValidity()) return;
  $('test-ai').disabled = true; $('settings-message').textContent = 'Menguji koneksi dan respons JSON…';
  try { const result = await api('/api/settings/test', {method: 'POST', body: JSON.stringify(settingsPayload())}); $('settings-message').textContent = result.message; }
  catch (error) { $('settings-message').textContent = error.message; }
  finally { $('test-ai').disabled = false; }
});
$('graph-tab').addEventListener('click', () => setView('graph'));
$('list-tab').addEventListener('click', () => setView('list'));
$('detail-close').addEventListener('click', () => {
  $('node-detail').hidden = true;
  if (!localFocus) { selectedNodeId = null; $('local-graph').disabled = true; }
  if (graph) { graph.elements().unselect(); highlightConnections(localFocus ? graph.getElementById(selectedNodeId) : null); graph.resize(); fitGraph(); }
});
$('ask-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!current || !documentData) return;
  const id = current.id;
  const question = $('ask-input').value.trim();
  $('ask-log').querySelector('.ask-hint')?.remove();
  addMessage('user', question); $('ask-input').value = '';
  const reply = addMessage('assistant pending', 'Berpikir…');
  $('ask-button').disabled = true;
  try {
    const result = await api(`/api/scans/${id}/ask`, {method: 'POST', body: JSON.stringify({question})});
    if (current?.id !== id) return;
    reply.classList.remove('pending'); renderAnswer(result, reply); highlightAnswer(result);
  } catch (error) {
    reply.classList.remove('pending'); reply.classList.add('error'); reply.firstChild.textContent = error.message;
  } finally { $('ask-button').disabled = !documentData?.nodes?.length; $('ask-input').focus(); }
});
$('ask-toggle').addEventListener('click', () => toggleAsk(true));
$('ask-close').addEventListener('click', () => toggleAsk(false));
$('fit-graph').addEventListener('click', fitGraph);
$('relayout-graph').addEventListener('click', () => layoutGraph());
$('local-graph').addEventListener('click', () => toggleLocal());
$('zoom-in').addEventListener('click', () => graph?.zoom({level: graph.zoom() * 1.2, renderedPosition: {x: graph.width() / 2, y: graph.height() / 2}}));
$('zoom-out').addEventListener('click', () => graph?.zoom({level: graph.zoom() / 1.2, renderedPosition: {x: graph.width() / 2, y: graph.height() / 2}}));
$('download-cdg').addEventListener('click', () => { if (current) window.location.href = `/api/scans/${current.id}/download/cdg`; });
$('node-search').addEventListener('input', () => {
  applyFilters(); fitGraph();
});

for (const id of ['risk-filter', 'type-filter', 'show-orphans', 'local-depth']) $(id).addEventListener('change', () => {
  $('depth-value').textContent = $('local-depth').value;
  applyFilters(); fitGraph();
});
for (const id of ['show-labels', 'show-edge-labels', 'show-arrows', 'node-size']) $(id).addEventListener('change', () => { applyDisplayOptions(); fitGraph(); });
for (const id of ['link-distance', 'repel-force']) $(id).addEventListener('change', () => layoutGraph());
$('reset-graph-options').addEventListener('click', () => {
  $('risk-filter').value = 'all'; $('type-filter').value = 'all'; $('node-search').value = '';
  $('local-depth').value = '1'; $('depth-value').textContent = '1';
  $('show-orphans').checked = true; $('show-labels').checked = true;
  $('show-edge-labels').checked = false; $('show-arrows').checked = true;
  $('node-size').value = '100'; $('link-distance').value = '100'; $('repel-force').value = '8000';
  localFocus = false;
  if (graph) graph.nodes().unlock().removeClass('pinned');
  applyDisplayOptions(); applyFilters(); layoutGraph();
  if (selectedNodeId && !$('node-detail').hidden) showDetail(selectedNodeId);
});
$('fullscreen-graph').addEventListener('click', async () => {
  try {
    if (document.fullscreenElement) await document.exitFullscreen();
    else await document.querySelector('.workspace').requestFullscreen();
  } catch { notice('Mode layar penuh tidak tersedia di browser ini.'); }
});
document.addEventListener('fullscreenchange', () => {
  $('fullscreen-graph').setAttribute('aria-label', document.fullscreenElement ? 'Keluar layar penuh' : 'Layar penuh');
  if (graph) { graph.resize(); fitGraph(); }
});
$('graph-view').addEventListener('keydown', event => {
  if (!graph || event.target.matches('input,select,textarea')) return;
  const step = event.shiftKey ? 100 : 30;
  const movement = {ArrowLeft: {x: step, y: 0}, ArrowRight: {x: -step, y: 0}, ArrowUp: {x: 0, y: step}, ArrowDown: {x: 0, y: -step}};
  if (movement[event.key]) { event.preventDefault(); graph.panBy(movement[event.key]); }
  if (event.key === '+' || event.key === '=') { event.preventDefault(); $('zoom-in').click(); }
  if (event.key === '-') { event.preventDefault(); $('zoom-out').click(); }
  if (event.key === 'Escape' && localFocus) toggleLocal(false);
});
document.addEventListener('click', event => {
  const options = document.querySelector('.graph-options');
  if (!options.contains(event.target)) options.open = false;
});

new ResizeObserver(() => {
  if (graph && !$('graph-view').hidden) { graph.resize(); fitGraph(); }
}).observe($('graph'));

let logOpen = false;
// Log events after which the worker waits on the AI endpoint.
const waitingEvents = {a2_llm_escalation: 'menunggu verifikasi temuan dari model AI', a3_llm_request: 'menunggu penalaran dependensi dari model AI',
  a5_plan_built: 'menunggu model AI menulis laporan migrasi', detection_start: 'menjalankan Semgrep'};

const failureNames = {llm_escalation_failed: 'verifikasi temuan oleh model AI gagal; temuan itu tidak dimasukkan',
  llm_call_failed: 'penalaran dependensi oleh model AI gagal; hanya hubungan dari analisis statis yang dipakai',
  llm_report_failed: 'model AI gagal menulis laporan; laporan ringkas cadangan dipakai'};

async function loadLog() {
  if (!current || !logOpen) return;
  const id = current.id;
  const {lines, now} = await api(`/api/scans/${id}/log`);
  if (current?.id !== id || !logOpen) return;
  const box = $('log-lines');
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  box.replaceChildren(...(lines.length ? lines.map(line => element('span', line + '\n',
    /\[(error|critical)/.test(line) ? 'log-error' : /\[warning/.test(line) ? 'log-warn' : /\[debug/.test(line) ? 'log-muted' : undefined))
    : [element('span', 'Belum ada log untuk pemindaian ini.', 'log-muted')]));
  // LLM calls are not streamed, so a long call leaves the log silent; say what the scan is waiting for.
  const stamp = lines.at(-1)?.match(/^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)/);
  if (current.status === 'running' && stamp) {
    // Both stamps are server-local wall time; reading both as UTC keeps the difference correct.
    const seconds = Math.round((Date.parse(now.replace(' ', 'T') + 'Z') - Date.parse(`${stamp[1]}T${stamp[2]}Z`)) / 1000);
    const waiting = Object.entries(waitingEvents).find(([event]) => lines.at(-1).includes(event))?.[1] || 'masih bekerja';
    if (seconds >= 5) box.append(element('span', `⏳ ${waiting} · ${seconds} dtk tanpa log baru`, 'log-live'));
  }
  // Limitations of a partial result are summarised here instead of the result footer.
  const failures = documentData?.analysis_errors || [];
  if (failures.length) {
    box.append(element('span', `\n── Keterbatasan hasil (${failures.length}) ──\n`, 'log-warn'));
    for (const failure of failures) box.append(element('span', `⚠ ${failure.agent}: ${failureNames[failure.type] || failure.type}. Hasil perlu ditinjau.\n`, 'log-warn'));
  }
  // Follow new lines unless the user scrolled up to read older ones.
  if (atBottom) box.scrollTop = box.scrollHeight;
}

function toggleLog(open) {
  logOpen = open;
  $('scan-log').hidden = !open;
  $('log-toggle').setAttribute('aria-expanded', String(open));
  if (open) { $('log-lines').scrollTop = $('log-lines').scrollHeight; loadLog().catch(error => notice(`Log proses tidak dapat dimuat: ${error.message}`, true)); }
}

$('log-toggle').addEventListener('click', () => toggleLog(!logOpen));
$('log-close').addEventListener('click', () => { toggleLog(false); $('log-toggle').focus(); });

async function poll() {
  if (polling) return;
  const active = history.find(scan => scan.status === 'running');
  if (!active) return;
  polling = true;
  try {
    const latest = await api(`/api/scans/${active.id}`);
    history = history.map(scan => scan.id === latest.id ? latest : scan);
    if (current?.id === latest.id) {
      current = latest; showProgress(latest); $('scan-badge').textContent = statusNames[latest.status];
      if (latest.status !== 'running') await openScan(latest);
      else loadLog().catch(() => {}); // transient log errors are shown by the next successful poll
    }
    if (latest.status !== 'running') await refreshHistory();
  } catch (error) { notice(`Koneksi progres terganggu: ${error.message}`, true); }
  finally { polling = false; }
}

(async () => {
  try {
    $('repo-url').value = ''; // browsers may restore the old value on reload
    await Promise.all([loadSettings(), refreshHistory()]);
  } catch (error) { notice(`Dashboard belum dapat terhubung: ${error.message}`, true); }
  setInterval(poll, 1500);
})();
