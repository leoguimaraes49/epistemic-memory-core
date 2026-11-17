"""Servidor Web Local Interativo do Epistemic Dossier Studio (100% Python stdlib).

Inclui proteção contra DNS Rebinding (validação de `Host`), proteção CSRF por
token de sessão (`X-Dossie-Token`) + `Origin`/`Sec-Fetch-Site`, teto de payload
e execução concorrente via `ThreadingHTTPServer`.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING

from .scenarios import SCENARIO_CATALOG, load_scenario, simulate_premise_change

if TYPE_CHECKING:
    from .engine_adapter import DossieWorkspace

MAX_BODY_BYTES = 65536
_ALLOWED_HOST_RE = re.compile(r"^(?:127\.0\.0\.1|localhost|\[::1\])(?::([1-9]\d{0,4}))?$", re.I)

STUDIO_HTML = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Epistemic Dossier Studio — Auditoria de Decisões & Premissas</title>
<style>
  :root {
    --bg: #0b1120;
    --panel: #131c31;
    --panel-alt: #1b2742;
    --border: #293856;
    --text: #f1f5f9;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --accent-hover: #0ea5e9;
    --ok: #34d399;
    --warn: #fbbf24;
    --danger: #f87171;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 20px; line-height: 1.5; }
  .wrap { max-width: 1280px; margin: 0 auto; }
  header { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 14px; padding-bottom: 16px; border-bottom: 1px solid var(--border); margin-bottom: 20px; }
  h1 { font-size: 1.4rem; display: flex; align-items: center; gap: 10px; }
  .sub { font-size: 0.85rem; color: var(--muted); }
  .pill { font-size: 0.75rem; font-weight: 700; padding: 3px 10px; border-radius: 999px; border: 1px solid rgba(56,189,248,0.35); background: rgba(56,189,248,0.12); color: var(--accent); }
  .pill-ok { border-color: rgba(52,211,153,0.4); background: rgba(52,211,153,0.14); color: var(--ok); }
  .pill-warn { border-color: rgba(251,191,36,0.45); background: rgba(251,191,36,0.15); color: var(--warn); }
  .pill-danger { border-color: rgba(248,113,113,0.45); background: rgba(248,113,113,0.15); color: var(--danger); }
  .grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 20px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px; }
  .kpi-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
  .kpi-val { font-size: 1.65rem; font-weight: 700; margin-top: 4px; }
  .grid-2 { display: grid; grid-template-columns: 1.2fr 0.8fr; gap: 16px; margin-bottom: 18px; }
  @media (max-width: 960px) { .grid-2 { grid-template-columns: 1fr; } }
  h2 { font-size: 1.05rem; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
  .btn-row { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }
  button { background: var(--accent); color: #08101f; border: none; border-radius: 8px; padding: 9px 14px; font-weight: 700; font-size: 0.85rem; cursor: pointer; transition: 0.15s; }
  button:hover { background: var(--accent-hover); }
  button.sec { background: var(--panel-alt); color: var(--text); border: 1px solid var(--border); }
  button.sec:hover { border-color: var(--accent); }
  button.warn { background: #f59e0b; color: #08101f; }
  input, textarea, select { width: 100%; background: #08101f; color: var(--text); border: 1px solid var(--border); border-radius: 8px; padding: 9px 12px; font-size: 0.875rem; margin-bottom: 10px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.83rem; }
  th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; }
  pre { background: #070d19; border: 1px solid var(--border); border-radius: 8px; padding: 12px; font-size: 0.8rem; overflow-x: auto; color: #cbd5e1; white-space: pre-wrap; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>🏛️ Epistemic Dossier Studio <span class="pill" id="emb-pill">Verificando motor...</span></h1>
      <p class="sub">Auditoria determinística de decisões, contratos, atribuição de autoria e invalidação em cascata sobre o Epistemic Memory Core</p>
    </div>
    <div class="btn-row" style="margin:0">
      <button class="sec" onclick="refreshAll()">🔄 Atualizar Dossiê</button>
    </div>
  </header>

  <div class="grid-4">
    <div class="card"><div class="kpi-label">Registros no Grafo</div><div class="kpi-val" id="kpi-total">--</div><div class="sub" id="kpi-types">Fontes + Derivados</div></div>
    <div class="card"><div class="kpi-label">Vigentes no Escopo</div><div class="kpi-val" style="color:var(--ok)" id="kpi-active">--</div><div class="sub">Bases íntegras por SHA-256</div></div>
    <div class="card"><div class="kpi-label">Suspensos (Stale-on-Write)</div><div class="kpi-val" style="color:var(--warn)" id="kpi-stale">--</div><div class="sub">Exigem revalidação explícita</div></div>
    <div class="card"><div class="kpi-label">Comprovantes Emitidos</div><div class="kpi-val" id="kpi-receipts">--</div><div class="sub" id="kpi-receipts-sub">Verificação sem LLM</div></div>
  </div>

  <div class="card" style="margin-bottom:18px">
    <h2><span>🎬 Cenários Práticos & Simulador de Mudança de Premissa</span><span class="sub" id="active-scenario-label">Selecione um dossiê</span></h2>
    <div class="btn-row">
      <button class="sec" onclick="loadScenario('engenharia_cotacao')">1. Engenharia & Cloud (Cotação GPU)</button>
      <button class="sec" onclick="loadScenario('juridico_contrato')">2. Jurídico (Contrato MSA & Aditivos)</button>
      <button class="sec" onclick="loadScenario('pesquisa_decisao')">3. Pesquisa & Avaliação (IFO-2 + Trial)</button>
      <button class="warn" onclick="simulateMutation()">⚡ Simular Mudança de Premissa no Cenário Atual</button>
      <button class="sec" onclick="testAttributionFirewall()">🛡️ Testar Bloqueio de Falsa Atribuição</button>
    </div>
    <pre id="event-banner">Carregue um dos 3 cenários acima ou cadastre suas próprias fontes abaixo para inspecionar o grafo epistêmico.</pre>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2><span>🕸️ Grafo Epistêmico & Vigência de Registros</span></h2>
      <div id="nodes-container">Carregando registros...</div>
    </div>
    <div class="card">
      <h2><span>⚖️ Comprovantes Determinísticos (lab-assurance-2)</span></h2>
      <div id="receipts-container" style="margin-bottom:18px">Nenhum comprovante emitido.</div>
      <h2><span>🔍 Busca Híbrida (Léxica + Grafo + E5)</span></h2>
      <div style="display:flex;gap:8px;margin-bottom:10px">
        <input id="q-input" placeholder="Buscar termo, cláusula, pessoa ou métrica..." style="margin:0" onkeypress="if(event.key==='Enter') runSearch()">
        <button onclick="runSearch()">Buscar</button>
      </div>
      <div id="search-box" class="sub">Resultados filtram automaticamente inferências suspensas.</div>
    </div>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2><span>📥 Registrar Nova Fonte Primária no Dossiê</span></h2>
      <input id="src-key" placeholder="Chave de idempotência (ex.: doc-proposta-02)">
      <input id="src-title" placeholder="Título da fonte ou documento">
      <select id="src-kind">
        <option value="document">Documento Técnico / Contrato (document)</option>
        <option value="conversation">Ata / Conversa Atribuível (conversation)</option>
        <option value="publication">Publicação / Referência (publication)</option>
      </select>
      <textarea id="src-content" rows="4" placeholder="Conteúdo textual ou JSON canônico da fonte..."></textarea>
      <button onclick="submitSource()">Gravar Fonte com SHA-256</button>
    </div>
    <div class="card">
      <h2><span>✏️ Retificar Fonte Existente (Gera Histórico + Cascata)</span></h2>
      <input id="rect-id" placeholder="UUID da fonte a retificar (clique em um ID na tabela)">
      <input id="rect-rev" type="number" value="1" placeholder="Revisão atual esperada">
      <input id="rect-reason" placeholder="Motivo formal da retificação (obrigatório)">
      <textarea id="rect-content" rows="4" placeholder="Novo conteúdo integral revisado..."></textarea>
      <button class="warn" onclick="submitRectification()">Aplicar Retificação Auditada</button>
    </div>
  </div>
</div>

<script>
const STUDIO_TOKEN = "__STUDIO_CSRF_TOKEN__";
let currentScenario = "engenharia_cotacao";

function esc(v) {
  const d = document.createElement("span");
  d.textContent = String(v ?? "");
  return d.innerHTML;
}

async function api(path, method = "GET", body = null) {
  const opts = { method, headers: {} };
  if (method !== "GET") {
    opts.headers["Content-Type"] = "application/json";
    opts.headers["X-Dossie-Token"] = STUDIO_TOKEN;
    opts.body = JSON.stringify(body || {});
  }
  const r = await fetch(path, opts);
  return await r.json();
}

function selectSourceForRect(id, rev) {
  document.getElementById("rect-id").value = id;
  document.getElementById("rect-rev").value = rev;
}

async function refreshAll() {
  const snap = await api("/api/snapshot");
  if (snap.status !== "ok") return;
  document.getElementById("kpi-total").textContent = snap.total_records;
  document.getElementById("kpi-active").textContent = snap.active_records;
  document.getElementById("kpi-stale").textContent = snap.stale_records;
  document.getElementById("kpi-receipts").textContent = snap.receipts.length;
  const validRec = snap.receipts.filter(r => r.status === "verified").length;
  document.getElementById("kpi-receipts-sub").textContent = `${validRec}/${snap.receipts.length} íntegros na geração atual`;
  document.getElementById("emb-pill").textContent = snap.embeddings_active ? "ONNX E5 + Grafo Ativo" : "Léxico + Grafo Ativo";

  if (!snap.nodes.length) {
    document.getElementById("nodes-container").innerHTML = '<p class="sub">Dossiê vazio. Carregue um cenário acima ou grave uma fonte.</p>';
  } else {
    let h = '<table><thead><tr><th>Tipo</th><th>Título & Resumo</th><th>Rev</th><th>Status</th></tr></thead><tbody>';
    for (const n of snap.nodes) {
      const ok = n.validity === "current_within_scope";
      const cls = ok ? "pill-ok" : "pill-warn";
      const lbl = ok ? "VIGENTE" : "SUSPENSO";
      const clickAttr = n.record_type === "source" ? `style="cursor:pointer;text-decoration:underline" onclick="selectSourceForRect('${esc(n.id)}', ${Number(n.revision)})"` : "";
      h += `<tr>
        <td><span class="pill">${esc(n.record_type)}</span></td>
        <td><strong ${clickAttr} title="${esc(n.id)}">${esc(n.title)}</strong><div class="sub">${esc(n.summary)}</div></td>
        <td>v${esc(n.revision)}</td>
        <td><span class="pill ${cls}">${lbl}</span></td>
      </tr>`;
    }
    h += "</tbody></table>";
    document.getElementById("nodes-container").innerHTML = h;
  }

  if (!snap.receipts.length) {
    document.getElementById("receipts-container").innerHTML = '<p class="sub">Nenhum comprovante emitido ainda.</p>';
  } else {
    let rh = '<table><thead><tr><th>Comprovante</th><th>Veredito Atual</th><th>Alegações</th></tr></thead><tbody>';
    for (const rc of snap.receipts) {
      const cls = rc.status === "verified" ? "pill-ok" : (rc.status === "stale" ? "pill-warn" : "pill-danger");
      const claimsTxt = (rc.claims || []).map(c => `${c.id}: ${c.status}`).join(" · ");
      rh += `<tr>
        <td><code>${esc(rc.receipt_id.slice(0, 10))}...</code></td>
        <td><span class="pill ${cls}">${esc(rc.status.toUpperCase())}</span></td>
        <td class="sub">${esc(claimsTxt || (rc.errors || []).join(", "))}</td>
      </tr>`;
    }
    rh += "</tbody></table>";
    document.getElementById("receipts-container").innerHTML = rh;
  }
}

async function loadScenario(id) {
  currentScenario = id;
  document.getElementById("active-scenario-label").textContent = "Cenário: " + id;
  const res = await api("/api/scenario/load", "POST", { scenario_id: id });
  document.getElementById("event-banner").textContent = JSON.stringify(res, null, 2);
  await refreshAll();
}

async function simulateMutation() {
  const res = await api("/api/scenario/mutate", "POST", { scenario_id: currentScenario });
  document.getElementById("event-banner").textContent = JSON.stringify(res, null, 2);
  await refreshAll();
}

async function testAttributionFirewall() {
  const res = await api("/api/test-attribution-firewall", "POST", {});
  document.getElementById("event-banner").textContent = JSON.stringify(res, null, 2);
}

async function runSearch() {
  const q = document.getElementById("q-input").value.trim();
  if (!q) return;
  const res = await api("/api/search", "POST", { query: q, limit: 8 });
  if (!res.results || !res.results.length) {
    document.getElementById("search-box").textContent = `Sem resultados vigentes (suspensos filtrados: ${res.excluded_stale ?? 0}).`;
    return;
  }
  let h = `<div class="sub" style="margin-bottom:6px">Modo: ${esc(res.mode)} · Suspensos ocultados: ${esc(res.excluded_stale)}</div><table><tbody>`;
  for (const r of res.results) {
    h += `<tr><td><span class="pill">${esc(r.record_type)}</span></td><td><strong>${esc(r.title)}</strong> (v${esc(r.revision)})</td></tr>`;
  }
  h += "</tbody></table>";
  document.getElementById("search-box").innerHTML = h;
}

async function submitSource() {
  const key = document.getElementById("src-key").value.trim() || ("src-" + Date.now());
  const title = document.getElementById("src-title").value.trim();
  const kind = document.getElementById("src-kind").value;
  const content = document.getElementById("src-content").value;
  const res = await api("/api/source/create", "POST", { key, title, source_kind: kind, content });
  document.getElementById("event-banner").textContent = JSON.stringify(res, null, 2);
  await refreshAll();
}

async function submitRectification() {
  const record_id = document.getElementById("rect-id").value.trim();
  const expected_revision = Number(document.getElementById("rect-rev").value);
  const reason = document.getElementById("rect-reason").value.trim();
  const content = document.getElementById("rect-content").value;
  const key = "rect-" + Date.now();
  const res = await api("/api/source/rectify", "POST", { key, record_id, expected_revision, reason, content });
  document.getElementById("event-banner").textContent = JSON.stringify(res, null, 2);
  await refreshAll();
}

window.onload = refreshAll;
</script>
</body>
</html>
"""


def _allowed_host(host: str) -> bool:
    match = _ALLOWED_HOST_RE.fullmatch((host or "").strip())
    if not match:
        return False
    port_s = match.group(1)
    return port_s is None or 1 <= int(port_s) <= 65535


def create_studio_server(workspace: "DossieWorkspace", host: str = "127.0.0.1", port: int = 8090) -> ThreadingHTTPServer:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("Por segurança, o Dossier Studio vincula exclusivamente em interface de loopback local.")

    csrf_token = secrets.token_hex(24)
    lock = threading.RLock()

    class StudioHandler(BaseHTTPRequestHandler):
        def _verify_host(self) -> bool:
            if not _allowed_host(self.headers.get("Host", "")):
                self._send_json({"status": "denied", "reason": "Host HTTP não autorizado"}, code=403)
                return False
            return True

        def _verify_csrf(self) -> bool:
            sec_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
            if sec_site and sec_site not in ("same-origin", "none"):
                self._send_json({"status": "denied", "reason": "Requisição cross-site bloqueada"}, code=403)
                return False
            origin = (self.headers.get("Origin") or "").strip()
            if origin:
                parsed = urllib.parse.urlparse(origin)
                if parsed.scheme not in ("http", "https") or (parsed.hostname or "").lower() not in ("127.0.0.1", "localhost", "::1"):
                    self._send_json({"status": "denied", "reason": "Origem não autorizada"}, code=403)
                    return False
            supplied = self.headers.get("X-Dossie-Token") or ""
            if not supplied or not secrets.compare_digest(supplied, csrf_token):
                self._send_json({"status": "denied", "reason": "Token de sessão inválido"}, code=403)
                return False
            return True

        def _read_body(self) -> dict | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except (TypeError, ValueError):
                self._send_json({"status": "invalid", "reason": "Content-Length inválido"}, code=400)
                return None
            if length < 0:
                self._send_json({"status": "invalid", "reason": "Content-Length negativo"}, code=400)
                return None
            if length > MAX_BODY_BYTES:
                self._send_json({"status": "invalid", "reason": "Corpo excede 64 KB"}, code=413)
                return None
            if length == 0:
                return {}
            try:
                obj = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                self._send_json({"status": "invalid", "reason": "JSON inválido"}, code=400)
                return None
            if not isinstance(obj, dict):
                self._send_json({"status": "invalid", "reason": "Objeto JSON esperado"}, code=400)
                return None
            return obj

        def do_GET(self):
            if not self._verify_host():
                return
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path in ("/", "/index.html"):
                body = STUDIO_HTML.replace("__STUDIO_CSRF_TOKEN__", csrf_token).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'")
                self.end_headers()
                self.wfile.write(body)
            elif parsed.path == "/api/scenarios":
                self._send_json({"status": "ok", "scenarios": list(SCENARIO_CATALOG.values())})
            elif parsed.path == "/api/snapshot":
                with lock:
                    self._send_json(workspace.snapshot())
            else:
                self._send_json({"status": "not_found", "reason": "Rota inexistente"}, code=404)

        def do_POST(self):
            if not self._verify_host() or not self._verify_csrf():
                return
            data = self._read_body()
            if data is None:
                return
            parsed = urllib.parse.urlparse(self.path)
            from nucleo import Conflict, Invalid, Locked, Uncertain

            try:
                with lock:
                    if parsed.path == "/api/scenario/load":
                        sid = str(data.get("scenario_id", "engenharia_cotacao"))
                        res = load_scenario(workspace, sid)
                        self._send_json({"status": "ok", "loaded": res})
                    elif parsed.path == "/api/scenario/mutate":
                        sid = str(data.get("scenario_id", "engenharia_cotacao"))
                        res = simulate_premise_change(workspace, sid)
                        self._send_json({"status": "ok", "mutation": res})
                    elif parsed.path == "/api/source/create":
                        res = workspace.ingest_source(
                            str(data.get("key", "")),
                            str(data.get("title", "")),
                            str(data.get("content", "")),
                            source_kind=str(data.get("source_kind", "document")),
                        )
                        self._send_json(res)
                    elif parsed.path == "/api/source/rectify":
                        res = workspace.rectify_source(
                            str(data.get("key", "")),
                            str(data.get("record_id", "")),
                            int(data.get("expected_revision", 1)),
                            str(data.get("content", "")),
                            str(data.get("reason", "")),
                        )
                        self._send_json({"status": "ok", **res})
                    elif parsed.path == "/api/search":
                        res = workspace.search(str(data.get("query", "")), limit=int(data.get("limit", 10)))
                        self._send_json({"status": "ok", **res})
                    elif parsed.path == "/api/test-attribution-firewall":
                        self._send_json(_run_attribution_demo(workspace))
                    else:
                        self._send_json({"status": "not_found", "reason": "Endpoint inexistente"}, code=404)
            except (Invalid, Conflict, Uncertain, Locked, ValueError, KeyError) as exc:
                self._send_json({"status": "rejected", "error_type": type(exc).__name__, "reason": str(exc)}, code=422)

        def _send_json(self, payload: dict, code: int = 200):
            raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            if code >= 400:
                self.close_connection = True
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)
            self.wfile.flush()

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer((host, port), StudioHandler)
    server.csrf_token = csrf_token  # type: ignore[attr-defined]
    return server


def _run_attribution_demo(ws: "DossieWorkspace") -> dict:
    """Demonstra ao vivo o bloqueio determinístico de falsa atribuição entre duas pessoas."""
    from atribuicao import AttributionError

    ata = ws.ingest_source(
        "demo-attr-ata",
        "Ata de Teste de Atribuição Estrita",
        "Lívia Rocha aprovou a janela técnica de 45ms. Bruno Tavares definiu o teto emergencial de 190000 reais.",
        source_kind="conversation",
    )
    ref_ata = {"record_id": ata["id"], "revision": ata["revision"]}
    livia = ws.register_person("demo-attr-livia", "Lívia Rocha", ref_ata, aliases=["Lívia"])
    ws.register_person("demo-attr-bruno", "Bruno Tavares", ref_ata, aliases=["Bruno"])
    try:
        ws.register_assertion(
            "demo-attr-ataque-" + os.urandom(4).hex(),
            "Tentativa inválida de atribuir fala de Bruno a Lívia",
            subject_ref={"record_id": livia["id"], "revision": livia["revision"]},
            predicate="reports_value",
            nature="third_party_report",
            asserted_by="simulador_adversarial",
            refs_list=[ref_ata],
            value={"type": "number", "content": 190000},
            evidence_quote="Bruno Tavares definiu o teto emergencial de 190000 reais.",
            evidence_source=ref_ata,
        )
    except AttributionError as blocked:
        return {
            "firewall_triggered": True,
            "verdict": "BLOCKED_BY_ATTRIBUTION_FIREWALL",
            "attempted_subject": "Lívia Rocha",
            "quote_owner_in_source": "Bruno Tavares",
            "engine_reason": str(blocked),
        }
    return {"firewall_triggered": False, "verdict": "UNEXPECTED_PASS"}
