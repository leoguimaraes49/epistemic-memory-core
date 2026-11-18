"""Interface Web Interativa Zero-Dependência — SVG Knowledge Graph & Lineage Inspector.

Renderiza exclusivamente HTML5 + CSS + SVG + JavaScript nativo (100% stdlib, sem CDNs),
com escapamento estrito contra XSS em HTML/SVG e token de sessão injetado por bootstrap.
"""
from __future__ import annotations

import json

GATEWAY_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Epistemic HTTP Gateway — Live Lineage Graph Explorer</title>
<style>
  :root {
    --bg: #070d19;
    --panel: #0f172a;
    --panel-alt: #162238;
    --border: #263554;
    --text: #f1f5f9;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --accent-hover: #0ea5e9;
    --active: #34d399;
    --suspended: #f59e0b;
    --danger: #f87171;
    --superseded: #94a3b8;
    --cls-source: #38bdf8;
    --cls-entity: #818cf8;
    --cls-eval: #c084fc;
    --cls-assertion: #34d399;
    --cls-synthesis: #fbbf24;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    padding: 18px 22px;
  }
  .wrap { max-width: 1440px; margin: 0 auto; }
  header {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 14px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 18px;
  }
  h1 { font-size: 1.35rem; font-weight: 700; display: flex; align-items: center; gap: 10px; }
  .sub { font-size: 0.82rem; color: var(--muted); }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 0.73rem;
    font-weight: 700;
    padding: 3px 10px;
    border-radius: 999px;
    border: 1px solid rgba(56, 189, 248, 0.35);
    background: rgba(56, 189, 248, 0.12);
    color: var(--accent);
  }
  .badge-active { border-color: rgba(52, 211, 153, 0.45); background: rgba(52, 211, 153, 0.14); color: var(--active); }
  .badge-suspended { border-color: rgba(245, 158, 11, 0.5); background: rgba(245, 158, 11, 0.16); color: var(--suspended); }
  .badge-superseded { border-color: rgba(148, 163, 184, 0.4); background: rgba(148, 163, 184, 0.14); color: var(--superseded); }
  .badge-danger { border-color: rgba(248, 113, 113, 0.5); background: rgba(248, 113, 113, 0.16); color: var(--danger); }

  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin-bottom: 16px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 15px;
  }
  .kpi-label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
  .kpi-val { font-size: 1.55rem; font-weight: 700; margin-top: 3px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.78rem; }

  .toolbar {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    margin-bottom: 16px;
  }
  .btn-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  button {
    background: var(--accent);
    color: #06101e;
    border: none;
    border-radius: 8px;
    padding: 8px 13px;
    font-weight: 700;
    font-size: 0.82rem;
    cursor: pointer;
    transition: 0.15s;
  }
  button:hover { background: var(--accent-hover); }
  button.sec { background: var(--panel-alt); color: var(--text); border: 1px solid var(--border); }
  button.sec:hover { border-color: var(--accent); }
  button.sec.active-filter { border-color: var(--accent); background: rgba(56, 189, 248, 0.18); color: var(--accent); }
  button.warn { background: var(--suspended); color: #06101e; }
  button:disabled { opacity: 0.45; cursor: not-allowed; }
  .auth-bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 8px 12px;
    margin-bottom: 16px;
    justify-content: space-between;
  }
  .auth-bar input {
    margin: 0;
    width: 310px;
    max-width: 100%;
  }

  .workspace-grid {
    display: grid;
    grid-template-columns: 1.55fr 1fr;
    gap: 16px;
    margin-bottom: 18px;
  }
  @media (max-width: 1100px) { .workspace-grid { grid-template-columns: 1fr; } }

  .svg-stage {
    background: #050a14;
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: auto;
    min-height: 460px;
    max-height: 640px;
    position: relative;
  }
  svg#lineage-svg { display: block; min-width: 860px; min-height: 450px; }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    font-size: 0.76rem;
    color: var(--muted);
    margin-top: 10px;
  }
  .legend span { display: inline-flex; align-items: center; gap: 5px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }

  .inspector-section { margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); }
  .inspector-section h3 { font-size: 0.86rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 8px; }
  .kv-row { display: flex; justify-content: space-between; gap: 8px; font-size: 0.82rem; margin-bottom: 5px; }
  .hash-box {
    background: #050a14;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 9px;
    word-break: break-all;
    color: #93c5fd;
    margin-top: 4px;
  }
  .list-item {
    background: var(--panel-alt);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 10px;
    margin-bottom: 6px;
    font-size: 0.81rem;
    cursor: pointer;
  }
  .list-item:hover { border-color: var(--accent); }
  .diff-view {
    background: #050a14;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px;
    max-height: 220px;
    overflow: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.76rem;
    white-space: pre-wrap;
  }
  .diff-add { color: #4ade80; }
  .diff-del { color: #f87171; }
  .diff-hdr { color: #38bdf8; font-weight: 700; }

  .console-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }
  @media (max-width: 980px) { .console-grid { grid-template-columns: 1fr; } }
  input, select, textarea {
    width: 100%;
    background: #050a14;
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 11px;
    font-size: 0.84rem;
    margin-bottom: 9px;
  }
  textarea { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.79rem; }
  pre.json-out {
    background: #050a14;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px;
    font-size: 0.78rem;
    max-height: 340px;
    overflow: auto;
    color: #cbd5e1;
    white-space: pre-wrap;
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>
        🕸️ Epistemic HTTP Gateway
        <span class="badge" id="hdr-mode">REST v1 · Verificando...</span>
        <span class="badge badge-suspended" id="hdr-auth-scope">🔒 Modo Somente Leitura (read_only)</span>
      </h1>
      <p class="sub">Gateway REST JSON Poliglota + Inspetor Visual SVG de Linhagem, Hashes SHA-256 e Raio de Impacto (Stale-on-Write)</p>
    </div>
    <div class="btn-row">
      <button class="sec" id="btn-seed" disabled title="Desbloqueie a escrita com o Token de Operador Bearer abaixo">🌱 Popular Grafo Demo via REST</button>
      <button class="warn" id="btn-rectify-demo" disabled title="Desbloqueie a escrita com o Token de Operador Bearer abaixo">⚡ Retificar Fonte Primária (Cascata)</button>
      <button class="sec" id="btn-refresh">🔄 Sincronizar Grafo</button>
    </div>
  </header>

  <div class="auth-bar">
    <div class="sub">
      <strong>Fronteira de Confiança Local:</strong> A página inicia com sessão <code>read_only</code> (inspeção de grafo e linhagem). Para mutações REST, informe o token Bearer do operador em memória JS:
    </div>
    <div class="btn-row">
      <label for="operator-write-token" class="sub" style="font-weight:600">Desbloquear Escrita (Token de Operador Bearer)</label>
      <input
        type="password"
        id="operator-write-token"
        class="mono"
        autocomplete="off"
        spellcheck="false"
        placeholder="Cole o Bearer Token de operador (read_write)..."
      >
      <button id="btn-unlock-write" type="button">🔓 Desbloquear Escrita</button>
      <button class="sec" id="btn-lock-write" type="button" style="display:none">🔒 Voltar para Leitura</button>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="card">
      <div class="kpi-label">Geração do Cofre (SHA-256)</div>
      <div class="kpi-val mono" id="kpi-gen" style="font-size:1.05rem;margin-top:8px">--</div>
      <div class="sub" id="kpi-issues">Verificando integridade...</div>
    </div>
    <div class="card">
      <div class="kpi-label">Registros Ativos</div>
      <div class="kpi-val" style="color:var(--active)" id="kpi-active">--</div>
      <div class="sub" id="kpi-total">Total catalogado: --</div>
    </div>
    <div class="card">
      <div class="kpi-label">Suspensos (Blast Radius)</div>
      <div class="kpi-val" style="color:var(--suspended)" id="kpi-suspended">--</div>
      <div class="sub">Derivados com RevRef desatualizado</div>
    </div>
    <div class="card">
      <div class="kpi-label">Revisões Superadas (Histórico)</div>
      <div class="kpi-val" style="color:var(--superseded)" id="kpi-superseded">--</div>
      <div class="sub">Preservadas em estado/revisoes</div>
    </div>
    <div class="card">
      <div class="kpi-label">Recibos lab-assurance-2</div>
      <div class="kpi-val" id="kpi-receipts">--</div>
      <div class="sub" id="kpi-receipts-detail">Comprovantes determinísticos</div>
    </div>
  </div>

  <div class="toolbar">
    <div class="btn-row" id="status-filters">
      <span class="sub">Filtrar Status:</span>
      <button class="sec active-filter" data-filter="all">Todos</button>
      <button class="sec" data-filter="active">Ativos (active)</button>
      <button class="sec" data-filter="suspended">Suspensos (suspended)</button>
      <button class="sec" data-filter="superseded">Superados (superseded)</button>
    </div>
    <div class="btn-row" style="min-width:300px">
      <input id="quick-search-input" placeholder="Busca híbrida (/api/v1/search)..." style="margin:0;width:240px">
      <button id="btn-quick-search">Buscar</button>
      <button class="sec" id="btn-clear-selection">Limpar Seleção</button>
    </div>
  </div>

  <div class="workspace-grid">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
        <strong>Mapa Epistemológico SVG & Cadeias RevRef</strong>
        <span class="sub" id="graph-hint">Clique em qualquer nó para inspecionar linhagem e raio de impacto</span>
      </div>
      <div class="svg-stage">
        <svg id="lineage-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 920 480"></svg>
      </div>
      <div class="legend">
        <span><i class="dot" style="background:var(--cls-source)"></i> 30_Fontes</span>
        <span><i class="dot" style="background:var(--cls-entity)"></i> 10_Entidades</span>
        <span><i class="dot" style="background:var(--cls-eval)"></i> 40_Avaliacoes</span>
        <span><i class="dot" style="background:var(--cls-assertion)"></i> 20_Afirmacoes</span>
        <span><i class="dot" style="background:var(--cls-synthesis)"></i> 50_Sinteses</span>
        <span><i class="dot" style="background:var(--active)"></i> Borda Sólida: Active</span>
        <span><i class="dot" style="background:var(--suspended)"></i> Tracejado Âmbar: Suspended / Blast Radius</span>
      </div>
    </div>

    <div class="card" id="inspector-card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <strong>Inspetor de Linhagem & SHA-256</strong>
        <span class="badge" id="insp-status-badge">Nenhum nó selecionado</span>
      </div>
      <div id="inspector-body" style="margin-top:10px">
        <p class="sub">Selecione uma fonte primária ou registro derivado no grafo SVG ao lado para inspecionar:</p>
        <ul class="sub" style="margin:8px 0 0 18px">
          <li>Ancestrais primários em <code>30_Fontes</code> com revisão pinada (<code>RevRef</code>);</li>
          <li>Dependentes transitivos a jusante (<em>blast radius</em> ativo vs suspenso);</li>
          <li>Resumo criptográfico <code>SHA-256</code> do arquivo controlado e diff entre revisões.</li>
        </ul>
      </div>
    </div>
  </div>

  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <strong>🧪 Console Interativo REST JSON (/api/v1/*)</strong>
      <span class="sub">Autenticado por sessão local Bearer · Teto de payload: 64 KB</span>
    </div>
    <div class="console-grid">
      <div>
        <label class="sub">Preset de Endpoint</label>
        <select id="rest-preset">
          <option value="health">GET /api/v1/health</option>
          <option value="graph">GET /api/v1/graph?include_superseded=true</option>
          <option value="lineage">GET /api/v1/lineage/&lt;record_id&gt;</option>
          <option value="post_source">POST /api/v1/sources</option>
          <option value="rectify_source">POST /api/v1/sources/rectify</option>
          <option value="post_knowledge">POST /api/v1/knowledge</option>
          <option value="verify_claims">POST /api/v1/verify-claims</option>
          <option value="search">POST /api/v1/search</option>
        </select>
        <div style="display:grid;grid-template-columns:110px 1fr;gap:8px">
          <select id="rest-method">
            <option value="GET">GET</option>
            <option value="POST">POST</option>
          </select>
          <input id="rest-path" value="/api/v1/health" class="mono">
        </div>
        <input id="rest-token-override" placeholder="Bearer Token opcional (vazio = token bootstrap da UI)" class="mono">
        <textarea id="rest-body" rows="8" placeholder="Corpo JSON (para POST)..."></textarea>
        <button id="btn-send-rest">Executar Requisição HTTP</button>
      </div>
      <div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <span class="sub">Resposta do Gateway</span>
          <span class="badge" id="rest-status-pill">Pronto</span>
        </div>
        <pre class="json-out" id="rest-output">Selecione um endpoint e clique em "Executar Requisição HTTP".</pre>
      </div>
    </div>
  </div>
</div>

<script>
(() => {
const GW_UI_TOKEN = __GW_UI_TOKEN_JSON__;
const SVG_NS = "http://www.w3.org/2000/svg";

// Mantido exclusivamente em memória de closure JS; nunca persistido em disco/storage.
let operatorWriteToken = "";
let currentAuthScope = "read_only";
let graphState = { nodes: [], edges: [], superseded_revisions: [], receipts: [] };
let activeFilter = "all";
let selectedNodeId = null;
let selectedLineage = null;

function escapeHtml(val) {
  return String(val ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function updateWriteControlsUi() {
  const scopeBadge = document.getElementById("hdr-auth-scope");
  const seedBtn = document.getElementById("btn-seed");
  const rectBtn = document.getElementById("btn-rectify-demo");
  const lockBtn = document.getElementById("btn-lock-write");
  const isRw = currentAuthScope === "read_write" && Boolean(operatorWriteToken);
  if (isRw) {
    scopeBadge.className = "badge badge-active";
    scopeBadge.textContent = "🔓 Escrita Desbloqueada (read_write)";
    seedBtn.disabled = false;
    rectBtn.disabled = false;
    seedBtn.title = "Popula registros demonstrativos usando o Token de Operador Bearer";
    rectBtn.title = "Retifica a fonte primária na revisão 1 usando o Token de Operador Bearer";
    lockBtn.style.display = "inline-block";
  } else {
    scopeBadge.className = "badge badge-suspended";
    scopeBadge.textContent = "🔒 Modo Somente Leitura (read_only)";
    seedBtn.disabled = true;
    rectBtn.disabled = true;
    seedBtn.title = "Desbloqueie a escrita com o Token de Operador Bearer";
    rectBtn.title = "Desbloqueie a escrita com o Token de Operador Bearer";
    lockBtn.style.display = "none";
  }
}

function getBearerToken(explicitToken = null) {
  if (explicitToken) return explicitToken;
  const custom = document.getElementById("rest-token-override").value.trim();
  if (custom) return custom;
  if (operatorWriteToken) return operatorWriteToken;
  return GW_UI_TOKEN;
}

async function gwFetch(path, method = "GET", bodyObj = null, explicitToken = null) {
  const t0 = performance.now();
  const headers = {
    "Authorization": "Bearer " + getBearerToken(explicitToken),
    "Accept": "application/json"
  };
  const opts = { method, headers };
  if (method !== "GET" && method !== "HEAD") {
    headers["Content-Type"] = "application/json";
    opts.body = typeof bodyObj === "string" ? bodyObj : JSON.stringify(bodyObj ?? {});
  }
  const res = await fetch(path, opts);
  const elapsedMs = Math.round(performance.now() - t0);
  let data = null;
  try {
    data = await res.json();
  } catch (_err) {
    data = { status: "parse_error", http_status: res.status };
  }
  return { httpStatus: res.status, elapsedMs, data };
}

function classColor(epistemeClass) {
  if (epistemeClass === "30_Fontes") return "#38bdf8";
  if (epistemeClass === "10_Entidades") return "#818cf8";
  if (epistemeClass === "40_Avaliacoes") return "#c084fc";
  if (epistemeClass === "20_Afirmacoes") return "#34d399";
  if (epistemeClass === "50_Sinteses") return "#fbbf24";
  return "#94a3b8";
}

function columnIndex(epistemeClass) {
  if (epistemeClass === "30_Fontes") return 0;
  if (epistemeClass === "10_Entidades" || epistemeClass === "40_Avaliacoes") return 1;
  if (epistemeClass === "20_Afirmacoes") return 2;
  return 3;
}

function statusBadgeClass(st) {
  if (st === "active" || st === "verified") return "badge badge-active";
  if (st === "suspended" || st === "stale") return "badge badge-suspended";
  if (st === "superseded") return "badge badge-superseded";
  return "badge badge-danger";
}

async function refreshDashboard() {
  const [hRes, gRes] = await Promise.all([
    gwFetch("/api/v1/health"),
    gwFetch("/api/v1/graph?include_superseded=true")
  ]);
  if (hRes.httpStatus === 200 && hRes.data) {
    const h = hRes.data;
    document.getElementById("hdr-mode").textContent =
      h.embeddings && h.embeddings.available ? "REST v1 · ONNX E5 + Grafo" : "REST v1 · Léxico + Grafo";
    document.getElementById("kpi-gen").textContent = (h.generation || "--").slice(0, 16) + "...";
    document.getElementById("kpi-gen").title = h.generation || "";
    document.getElementById("kpi-issues").textContent =
      (h.structural_issues && h.structural_issues.length)
        ? h.structural_issues.length + " problemas estruturais"
        : "0 problemas estruturais · íntegro";
    document.getElementById("kpi-active").textContent = h.counts.active_records;
    document.getElementById("kpi-total").textContent = "Total catalogado: " + h.counts.total_records;
    document.getElementById("kpi-suspended").textContent = h.counts.suspended_records;
    document.getElementById("kpi-superseded").textContent = h.counts.superseded_revisions;
    document.getElementById("kpi-receipts").textContent = h.counts.receipts_total;
    document.getElementById("kpi-receipts-detail").textContent =
      h.counts.receipts_verified + " verificados · " + h.counts.receipts_stale + " stale";
  }
  if (gRes.httpStatus === 200 && gRes.data) {
    graphState = gRes.data;
    if (selectedNodeId && graphState.nodes.some(n => n.id === selectedNodeId && !n.is_historical_snapshot)) {
      await selectNode(selectedNodeId, false);
    }
    renderSvgGraph();
  }
}

function renderSvgGraph() {
  const svg = document.getElementById("lineage-svg");
  while (svg.firstChild) svg.removeChild(svg.firstChild);

  const visibleNodes = graphState.nodes.filter(n => {
    if (activeFilter === "all") return !n.is_historical_snapshot;
    return n.status === activeFilter;
  });

  if (!visibleNodes.length) {
    svg.setAttribute("viewBox", "0 0 920 320");
    const txt = document.createElementNS(SVG_NS, "text");
    txt.setAttribute("x", "460");
    txt.setAttribute("y", "160");
    txt.setAttribute("text-anchor", "middle");
    txt.setAttribute("fill", "#94a3b8");
    txt.setAttribute("font-size", "14");
    txt.textContent = "Nenhum registro para exibir neste filtro. Use 'Popular Grafo Demo via REST' ou envie POST /api/v1/sources.";
    svg.appendChild(txt);
    return;
  }

  const defs = document.createElementNS(SVG_NS, "defs");
  const makeMarker = (id, color) => {
    const m = document.createElementNS(SVG_NS, "marker");
    m.setAttribute("id", id);
    m.setAttribute("viewBox", "0 0 10 10");
    m.setAttribute("refX", "9");
    m.setAttribute("refY", "5");
    m.setAttribute("markerWidth", "6");
    m.setAttribute("markerHeight", "6");
    m.setAttribute("orient", "auto-start-reverse");
    const p = document.createElementNS(SVG_NS, "path");
    p.setAttribute("d", "M 0 1 L 10 5 L 0 9 z");
    p.setAttribute("fill", color);
    m.appendChild(p);
    return m;
  };
  defs.appendChild(makeMarker("arrow-active", "#475569"));
  defs.appendChild(makeMarker("arrow-upstream", "#38bdf8"));
  defs.appendChild(makeMarker("arrow-suspended", "#f59e0b"));
  svg.appendChild(defs);

  const cols = [[], [], [], []];
  const colTitles = ["30_Fontes (Primárias)", "10_Entidades / 40_Aval.", "20_Afirmacoes", "50_Sinteses / Derivados"];
  visibleNodes.forEach(n => cols[columnIndex(n.episteme_class)].push(n));

  const maxRows = Math.max(1, ...cols.map(c => c.length));
  const width = 960;
  const height = Math.max(460, 95 + maxRows * 92);
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

  const colX = [30, 270, 510, 745];
  const nodeW = 195;
  const nodeH = 66;
  const pos = new Map();

  colTitles.forEach((label, idx) => {
    const hdr = document.createElementNS(SVG_NS, "text");
    hdr.setAttribute("x", String(colX[idx] + nodeW / 2));
    hdr.setAttribute("y", "28");
    hdr.setAttribute("text-anchor", "middle");
    hdr.setAttribute("fill", "#64748b");
    hdr.setAttribute("font-size", "11");
    hdr.setAttribute("font-weight", "700");
    hdr.textContent = label;
    svg.appendChild(hdr);
  });

  cols.forEach((list, cIdx) => {
    list.forEach((n, rIdx) => {
      pos.set(n.id, { x: colX[cIdx], y: 52 + rIdx * 88, node: n });
    });
  });

  const upstreamSet = new Set(
    selectedLineage ? (selectedLineage.upstream.upstream_nodes || []).map(u => u.id) : []
  );
  const downstreamMap = new Map(
    selectedLineage ? (selectedLineage.downstream.dependents || []).map(d => [d.id, d.status]) : []
  );

  const edgeGroup = document.createElementNS(SVG_NS, "g");
  (graphState.edges || []).forEach(e => {
    const fromP = pos.get(e.from);
    const toP = pos.get(e.to);
    if (!fromP || !toP) return;

    const inSelectedChain = selectedNodeId && (
      (e.from === selectedNodeId && upstreamSet.has(e.to)) ||
      (upstreamSet.has(e.from) && upstreamSet.has(e.to)) ||
      (e.to === selectedNodeId && downstreamMap.has(e.from)) ||
      (downstreamMap.has(e.from) && downstreamMap.has(e.to))
    );

    const x1 = toP.x + nodeW;
    const y1 = toP.y + nodeH / 2;
    const x2 = fromP.x;
    const y2 = fromP.y + nodeH / 2;
    const dx = Math.max(45, Math.abs(x2 - x1) * 0.45);

    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`);
    path.setAttribute("fill", "none");

    const isBroken = e.outdated || e.link_status !== "active";
    let stroke = isBroken ? "#f59e0b" : "#334155";
    let marker = isBroken ? "url(#arrow-suspended)" : "url(#arrow-active)";
    let sw = isBroken ? "2.2" : "1.5";
    if (inSelectedChain) {
      stroke = isBroken ? "#f59e0b" : "#38bdf8";
      marker = isBroken ? "url(#arrow-suspended)" : "url(#arrow-upstream)";
      sw = "2.8";
    }
    path.setAttribute("stroke", stroke);
    path.setAttribute("stroke-width", sw);
    if (isBroken) path.setAttribute("stroke-dasharray", "6 4");
    if (selectedNodeId && !inSelectedChain) path.setAttribute("opacity", "0.22");
    path.setAttribute("marker-end", marker);
    edgeGroup.appendChild(path);
  });
  svg.appendChild(edgeGroup);

  const nodeGroup = document.createElementNS(SVG_NS, "g");
  pos.forEach(({ x, y, node }) => {
    const g = document.createElementNS(SVG_NS, "g");
    g.style.cursor = "pointer";

    const isSelected = node.id === selectedNodeId;
    const isUp = upstreamSet.has(node.id);
    const isDown = downstreamMap.has(node.id);
    if (selectedNodeId && !isSelected && !isUp && !isDown) {
      g.setAttribute("opacity", "0.32");
    }

    const rect = document.createElementNS(SVG_NS, "rect");
    rect.setAttribute("x", String(x));
    rect.setAttribute("y", String(y));
    rect.setAttribute("width", String(nodeW));
    rect.setAttribute("height", String(nodeH));
    rect.setAttribute("rx", "9");
    rect.setAttribute("fill", isSelected ? "#172554" : "#0f172a");

    let border = classColor(node.episteme_class);
    if (node.status === "suspended") border = "#f59e0b";
    else if (node.status === "superseded") border = "#64748b";
    rect.setAttribute("stroke", isSelected ? "#f8fafc" : border);
    rect.setAttribute("stroke-width", isSelected ? "2.8" : (isUp || isDown ? "2.4" : "1.6"));
    if (node.status === "suspended") rect.setAttribute("stroke-dasharray", "5 3");
    g.appendChild(rect);

    const pill = document.createElementNS(SVG_NS, "text");
    pill.setAttribute("x", String(x + 10));
    pill.setAttribute("y", String(y + 18));
    pill.setAttribute("fill", classColor(node.episteme_class));
    pill.setAttribute("font-size", "10");
    pill.setAttribute("font-weight", "700");
    pill.textContent = `${node.record_type} · v${node.revision} · ${node.status.toUpperCase()}`;
    g.appendChild(pill);

    const title = document.createElementNS(SVG_NS, "text");
    title.setAttribute("x", String(x + 10));
    title.setAttribute("y", String(y + 37));
    title.setAttribute("fill", "#f1f5f9");
    title.setAttribute("font-size", "11.5");
    title.setAttribute("font-weight", "600");
    const rawTitle = String(node.title || node.id);
    title.textContent = rawTitle.length > 25 ? rawTitle.slice(0, 24) + "…" : rawTitle;
    g.appendChild(title);

    const shaTxt = document.createElementNS(SVG_NS, "text");
    shaTxt.setAttribute("x", String(x + 10));
    shaTxt.setAttribute("y", String(y + 54));
    shaTxt.setAttribute("fill", "#94a3b8");
    shaTxt.setAttribute("font-size", "9.5");
    shaTxt.setAttribute("font-family", "monospace");
    shaTxt.textContent = `sha256:${String(node.sha256 || "").slice(0, 14)}…`;
    g.appendChild(shaTxt);

    g.addEventListener("click", () => {
      const targetId = node.record_id || node.id;
      selectNode(targetId, true);
    });
    nodeGroup.appendChild(g);
  });
  svg.appendChild(nodeGroup);
}

async function selectNode(recordId, rerender = true) {
  selectedNodeId = recordId;
  const res = await gwFetch("/api/v1/lineage/" + encodeURIComponent(recordId));
  if (res.httpStatus !== 200 || !res.data || res.data.status !== "ok") {
    selectedLineage = null;
    return;
  }
  selectedLineage = res.data;
  renderInspector(res.data);
  if (rerender) renderSvgGraph();
}

function renderInspector(lin) {
  const rec = lin.record;
  const badge = document.getElementById("insp-status-badge");
  badge.className = statusBadgeClass(rec.status);
  badge.textContent = `${rec.episteme_class} · ${rec.status.toUpperCase()} (v${rec.revision})`;

  const container = document.getElementById("inspector-body");
  container.innerHTML = "";

  const meta = document.createElement("div");
  meta.innerHTML = `
    <div style="font-weight:700;font-size:0.98rem;margin-bottom:4px">${escapeHtml(rec.title)}</div>
    <div class="sub mono" style="margin-bottom:6px">ID: ${escapeHtml(rec.id)}</div>
    <div class="kv-row"><span class="sub">Classe / Pasta:</span><span>${escapeHtml(rec.folder)}</span></div>
    <div class="kv-row"><span class="sub">Impacto Downstream:</span><span>${escapeHtml(lin.impact.total_downstream_dependents)} dependente(s) (${escapeHtml(lin.impact.suspended_dependents_count)} suspenso(s))</span></div>
    <div class="sub" style="margin-top:6px">SHA-256 do Arquivo Controlado:</div>
    <div class="hash-box mono">${escapeHtml(rec.sha256)}</div>
  `;
  container.appendChild(meta);

  const upSec = document.createElement("div");
  upSec.className = "inspector-section";
  const upSources = lin.upstream.primary_sources || [];
  upSec.innerHTML = `<h3>Fontes Primárias Ancestrais (${upSources.length})</h3>`;
  if (!upSources.length) {
    const p = document.createElement("p");
    p.className = "sub";
    p.textContent = rec.record_type === "source" ? "Este registro já é uma Fonte Primária em 30_Fontes." : "Nenhuma fonte primária ancestral.";
    upSec.appendChild(p);
  } else {
    upSources.forEach(src => {
      const item = document.createElement("div");
      item.className = "list-item";
      const mismatch = src.outdated ? ` · PINADO v${src.pinned_revision} != ATUAL v${src.current_revision}` : ` · RevRef v${src.pinned_revision} OK`;
      item.innerHTML = `<strong>${escapeHtml(src.title)}</strong> <span class="${statusBadgeClass(src.outdated ? 'suspended' : 'active')}">${escapeHtml(mismatch)}</span>`;
      item.addEventListener("click", () => selectNode(src.record_id, true));
      upSec.appendChild(item);
    });
  }
  container.appendChild(upSec);

  const downSec = document.createElement("div");
  downSec.className = "inspector-section";
  const deps = lin.downstream.dependents || [];
  downSec.innerHTML = `<h3>Raio de Impacto / Dependentes Transitivos (${deps.length})</h3>`;
  if (!deps.length) {
    const p = document.createElement("p");
    p.className = "sub";
    p.textContent = "Nenhum registro derivado depende deste nó.";
    downSec.appendChild(p);
  } else {
    deps.forEach(dep => {
      const item = document.createElement("div");
      item.className = "list-item";
      item.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center">
          <strong>[Salto ${escapeHtml(dep.hop_distance)}] ${escapeHtml(dep.title)}</strong>
          <span class="${statusBadgeClass(dep.status)}">${escapeHtml(dep.status)}</span>
        </div>
        <div class="sub">${escapeHtml(dep.record_type)} · v${escapeHtml(dep.revision)}</div>
      `;
      item.addEventListener("click", () => selectNode(dep.id, true));
      downSec.appendChild(item);
    });
  }
  container.appendChild(downSec);

  if (rec.revision_diff && rec.revision_diff.length) {
    const diffSec = document.createElement("div");
    diffSec.className = "inspector-section";
    diffSec.innerHTML = `<h3>Diff Auditado de Revisão (v${escapeHtml(rec.revision - 1)} → v${escapeHtml(rec.revision)})</h3>`;
    const pre = document.createElement("div");
    pre.className = "diff-view";
    rec.revision_diff.forEach(line => {
      const ln = document.createElement("div");
      if (line.startsWith("+") && !line.startsWith("+++")) ln.className = "diff-add";
      else if (line.startsWith("-") && !line.startsWith("---")) ln.className = "diff-del";
      else if (line.startsWith("@@") || line.startsWith("---") || line.startsWith("+++")) ln.className = "diff-hdr";
      ln.textContent = line;
      pre.appendChild(ln);
    });
    diffSec.appendChild(pre);
    container.appendChild(diffSec);
  }
}

function applyPreset() {
  const preset = document.getElementById("rest-preset").value;
  const methodEl = document.getElementById("rest-method");
  const pathEl = document.getElementById("rest-path");
  const bodyEl = document.getElementById("rest-body");
  const firstNode = selectedNodeId || (graphState.nodes[0] ? graphState.nodes[0].id : "<record_id>");
  const firstSource = (graphState.nodes.find(n => n.record_type === "source") || {}).id || "<source_id>";

  if (preset === "health") {
    methodEl.value = "GET";
    pathEl.value = "/api/v1/health";
    bodyEl.value = "";
  } else if (preset === "graph") {
    methodEl.value = "GET";
    pathEl.value = "/api/v1/graph?include_superseded=true";
    bodyEl.value = "";
  } else if (preset === "lineage") {
    methodEl.value = "GET";
    pathEl.value = "/api/v1/lineage/" + firstNode;
    bodyEl.value = "";
  } else if (preset === "post_source") {
    methodEl.value = "POST";
    pathEl.value = "/api/v1/sources";
    bodyEl.value = JSON.stringify({
      operation_key: "webhook-src-" + Date.now(),
      title: "Telemetria Financeira Microsserviço Billing",
      source_kind: "document",
      content: JSON.stringify({ servico: "billing-api", capex_brl: 30000, opex_brl: 90000, sla_bps: 9990 }, null, 2)
    }, null, 2);
  } else if (preset === "rectify_source") {
    methodEl.value = "POST";
    pathEl.value = "/api/v1/sources/rectify";
    bodyEl.value = JSON.stringify({
      operation_key: "rectify-" + Date.now(),
      record_id: firstSource,
      expected_revision: 1,
      reason: "Reajuste auditado da premissa contratual primária",
      content: JSON.stringify({ servico: "gateway-cluster", capex_brl: 50000, opex_brl: 195000, sla_bps: 9950 }, null, 2)
    }, null, 2);
  } else if (preset === "post_knowledge") {
    methodEl.value = "POST";
    pathEl.value = "/api/v1/knowledge";
    bodyEl.value = JSON.stringify({
      operation_key: "know-ent-" + Date.now(),
      record_type: "entity",
      title: "Serviço de Pagamentos Core",
      payload: {
        entity_kind: "project",
        purpose: "Integração governada via HTTP Gateway",
        project_status: "active",
        identity_status: "identified",
        origin_refs: [{ record_id: firstSource, revision: 1 }]
      }
    }, null, 2);
  } else if (preset === "verify_claims") {
    methodEl.value = "POST";
    pathEl.value = "/api/v1/verify-claims";
    bodyEl.value = JSON.stringify({
      operation_key: "verify-" + Date.now(),
      claims: [
        { id: "sla_bps", kind: "field", value: 9995, refs: [{ record_id: firstSource, revision: 1, path: "/sla_bps" }] }
      ]
    }, null, 2);
  } else if (preset === "search") {
    methodEl.value = "POST";
    pathEl.value = "/api/v1/search";
    bodyEl.value = JSON.stringify({ query: "latência orçamento arquitetura", limit: 8, depth: 1 }, null, 2);
  }
}

async function seedDemoViaRest() {
  const sDoc = await gwFetch("/api/v1/sources", "POST", {
    operation_key: "ui-demo-src-cotacao",
    title: "Cotação Cluster Inferência #GW-01",
    source_kind: "document",
    content: JSON.stringify({
      fornecedor: "AtlasCompute",
      capex_brl: 40000,
      opex_brl: 160000,
      sla_bps: 9995,
      etapas: {
        e1: ["nodo_gpu", "requires", "rede_rdma"],
        e2: ["rede_rdma", "requires", "homologacao_sec"]
      }
    }, null, 2)
  });
  const sAta = await gwFetch("/api/v1/sources", "POST", {
    operation_key: "ui-demo-src-ata",
    title: "Ata Comitê de Arquitetura",
    source_kind: "conversation",
    content: "Clara Mendes informou que o teto anual aprovado para inferência é 210000 reais."
  });
  if (!sDoc.data.record || !sAta.data.record) {
    await refreshDashboard();
    return;
  }
  const refDoc = sDoc.data.rev_ref;
  const refAta = sAta.data.rev_ref;

  const ent = await gwFetch("/api/v1/knowledge", "POST", {
    operation_key: "ui-demo-ent-clara",
    record_type: "entity",
    title: "Clara Mendes",
    payload: {
      entity_kind: "person",
      display_name: "Clara Mendes",
      aliases: ["Clara"],
      identity_status: "identified",
      origin_refs: [refAta]
    }
  });
  if (ent.data.record) {
    const asrt = await gwFetch("/api/v1/knowledge", "POST", {
      operation_key: "ui-demo-assert-teto",
      record_type: "assertion",
      title: "Teto anual relatado por Clara Mendes",
      payload: {
        subject_ref: ent.data.rev_ref,
        predicate: "reports_value",
        nature: "third_party_report",
        asserted_by: "http_gateway_ui",
        source_refs: [refAta],
        value: { type: "number", content: 210000, unit: "BRL" },
        attribution_evidence: {
          source_ref: refAta,
          quote: "Clara Mendes informou que o teto anual aprovado para inferência é 210000 reais."
        },
        context_description: "Comitê de Arquitetura"
      }
    });
    if (asrt.data.record) {
      await gwFetch("/api/v1/knowledge", "POST", {
        operation_key: "ui-demo-syn-parecer",
        record_type: "synthesis",
        title: "Parecer de Enquadramento Financeiro AtlasCompute",
        payload: {
          synthesis_kind: "knowledge_summary",
          content: "Custo de 1º ano de R$ 200.000 respeita o limite de R$ 210.000 aprovado por Clara Mendes.",
          scope: "Cotação #GW-01 v1 + Ata Comitê v1",
          basis_refs: [refDoc, asrt.data.rev_ref],
          limitations: ["Qualquer revisão da cotação suspende este parecer automaticamente."],
          coverage_status: "supported_within_scope",
          as_of: "2026-11-17"
        }
      });
    }
  }
  await gwFetch("/api/v1/verify-claims", "POST", {
    operation_key: "ui-demo-receipt-v1",
    claims: [
      {
        id: "custo_total_ano1",
        kind: "sum",
        value: 200000,
        refs: [
          { record_id: refDoc.record_id, revision: refDoc.revision, path: "/capex_brl" },
          { record_id: refDoc.record_id, revision: refDoc.revision, path: "/opex_brl" }
        ]
      },
      {
        id: "cadeia_rdma",
        kind: "chain",
        value: ["nodo_gpu", "requires", "homologacao_sec"],
        refs: [
          { record_id: refDoc.record_id, revision: refDoc.revision, path: "/etapas/e1" },
          { record_id: refDoc.record_id, revision: refDoc.revision, path: "/etapas/e2" }
        ]
      }
    ]
  });
  selectedNodeId = refDoc.record_id;
  await refreshDashboard();
}

async function rectifyDemoSource() {
  const src = graphState.nodes.find(n => n.record_type === "source" && !n.is_historical_snapshot && n.revision === 1);
  if (!src) {
    document.getElementById("rest-output").textContent = "Popule o grafo demo primeiro ou selecione uma fonte na revisão 1.";
    return;
  }
  const res = await gwFetch("/api/v1/sources/rectify", "POST", {
    operation_key: "ui-demo-rectify-" + src.id.slice(0, 8),
    record_id: src.id,
    expected_revision: 1,
    reason: "Reajuste tarifário do fornecedor alterou OpEx anual para R$ 195.000",
    content: JSON.stringify({
      fornecedor: "AtlasCompute",
      capex_brl: 40000,
      opex_brl: 195000,
      sla_bps: 9980,
      etapas: {
        e1: ["nodo_gpu", "requires", "rede_rdma"],
        e2: ["rede_rdma", "requires", "homologacao_sec"]
      }
    }, null, 2)
  });
  document.getElementById("rest-status-pill").textContent = "HTTP " + res.httpStatus + " · " + res.elapsedMs + "ms";
  document.getElementById("rest-output").textContent = JSON.stringify(res.data, null, 2);
  selectedNodeId = src.id;
  await refreshDashboard();
}

async function unlockWriteMode() {
  const input = document.getElementById("operator-write-token");
  const candidate = input.value.trim();
  const pill = document.getElementById("rest-status-pill");
  if (!candidate) {
    pill.className = "badge badge-danger";
    pill.textContent = "Token vazio";
    document.getElementById("rest-output").textContent = "Informe o Token de Operador Bearer para desbloquear operações de escrita.";
    return;
  }
  const check = await gwFetch("/api/v1/health", "GET", null, candidate);
  if (check.httpStatus === 200 && check.data && check.data.auth_scope === "read_write") {
    operatorWriteToken = candidate;
    currentAuthScope = "read_write";
    input.value = "";
    updateWriteControlsUi();
    pill.className = "badge badge-active";
    pill.textContent = "Escrita Desbloqueada (read_write)";
    document.getElementById("rest-output").textContent = JSON.stringify(
      { status: "ok", auth_scope: "read_write", note: "Token mantido apenas em memória JS desta aba." },
      null,
      2
    );
    await refreshDashboard();
  } else {
    operatorWriteToken = "";
    currentAuthScope = "read_only";
    updateWriteControlsUi();
    pill.className = "badge badge-danger";
    pill.textContent = "Credencial rejeitada (HTTP " + check.httpStatus + ")";
    document.getElementById("rest-output").textContent = JSON.stringify(check.data, null, 2);
  }
}

function lockWriteMode() {
  operatorWriteToken = "";
  currentAuthScope = "read_only";
  document.getElementById("operator-write-token").value = "";
  updateWriteControlsUi();
  const pill = document.getElementById("rest-status-pill");
  pill.className = "badge badge-suspended";
  pill.textContent = "Modo Leitura (read_only)";
}

document.getElementById("btn-unlock-write").addEventListener("click", unlockWriteMode);
document.getElementById("btn-lock-write").addEventListener("click", lockWriteMode);
document.getElementById("operator-write-token").addEventListener("keydown", ev => {
  if (ev.key === "Enter") {
    ev.preventDefault();
    unlockWriteMode();
  }
});

document.getElementById("btn-refresh").addEventListener("click", refreshDashboard);
document.getElementById("btn-seed").addEventListener("click", seedDemoViaRest);
document.getElementById("btn-rectify-demo").addEventListener("click", rectifyDemoSource);
document.getElementById("btn-clear-selection").addEventListener("click", () => {
  selectedNodeId = null;
  selectedLineage = null;
  document.getElementById("insp-status-badge").className = "badge";
  document.getElementById("insp-status-badge").textContent = "Nenhum nó selecionado";
  renderSvgGraph();
});

document.querySelectorAll("#status-filters button").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#status-filters button").forEach(b => b.classList.remove("active-filter"));
    btn.classList.add("active-filter");
    activeFilter = btn.getAttribute("data-filter") || "all";
    renderSvgGraph();
  });
});

document.getElementById("btn-quick-search").addEventListener("click", async () => {
  const q = document.getElementById("quick-search-input").value.trim();
  if (!q) return;
  const res = await gwFetch("/api/v1/search", "POST", { query: q, limit: 10, depth: 1 });
  document.getElementById("rest-status-pill").textContent = "HTTP " + res.httpStatus + " · " + res.elapsedMs + "ms";
  document.getElementById("rest-output").textContent = JSON.stringify(res.data, null, 2);
  if (res.data && res.data.results && res.data.results.length) {
    await selectNode(res.data.results[0].id, true);
  }
});

document.getElementById("rest-preset").addEventListener("change", applyPreset);
document.getElementById("btn-send-rest").addEventListener("click", async () => {
  const method = document.getElementById("rest-method").value;
  const path = document.getElementById("rest-path").value.trim();
  const rawBody = document.getElementById("rest-body").value;
  const res = await gwFetch(path, method, method === "GET" ? null : rawBody);
  const pill = document.getElementById("rest-status-pill");
  pill.className = res.httpStatus < 400 ? "badge badge-active" : "badge badge-danger";
  pill.textContent = `HTTP ${res.httpStatus} · ${res.elapsedMs}ms`;
  document.getElementById("rest-output").textContent = JSON.stringify(res.data, null, 2);
  if (method === "POST" && res.httpStatus < 300) {
    await refreshDashboard();
  }
});

window.addEventListener("DOMContentLoaded", async () => {
  updateWriteControlsUi();
  await refreshDashboard();
  applyPreset();
});
})();
</script>
</body>
</html>
"""


def render_gateway_html(ui_token: str) -> bytes:
    """Injeta com segurança JSON o token de sessão local da interface web."""
    safe_json_literal = json.dumps(ui_token)
    return GATEWAY_HTML_TEMPLATE.replace("__GW_UI_TOKEN_JSON__", safe_json_literal).encode("utf-8")
