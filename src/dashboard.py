#!/usr/bin/env python3
"""
Dashboard Web Local para o Epistemic Memory Core
Interface interativa de visualização, busca e operação do sistema.
Utiliza apenas a biblioteca padrão do Python (sem dependências externas).
"""
from collections import deque
import json
import math
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import ponte_pessoal as p

MAX_POST_BYTES = 65536
DEFAULT_RATE_LIMIT_REQUESTS = 300
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60.0
_MAX_DRAIN_BYTES = 262144
_DRAIN_CHUNK_BYTES = 16384
SESSION_TOKEN = secrets.token_hex(24)
_ALLOWED_HOST_RE = re.compile(r'^(?:127\.0\.0\.1|localhost|\[::1\])(?::([1-9]\d{0,4}))?$', re.I)


class RateLimiter:
    """Limitador de taxa em janela deslizante thread-safe usando apenas stdlib."""

    def __init__(self, max_requests=DEFAULT_RATE_LIMIT_REQUESTS, window_seconds=DEFAULT_RATE_LIMIT_WINDOW_SECONDS):
        if type(max_requests) is not int or max_requests < 1:
            raise ValueError('max_requests deve ser inteiro positivo')
        if not isinstance(window_seconds, (int, float)) or isinstance(window_seconds, bool) or not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError('window_seconds deve ser número finito positivo')
        self.max_requests = max_requests
        self.window_seconds = float(window_seconds)
        self._lock = threading.Lock()
        self._buckets = {}

    def allow(self, key='default'):
        with self._lock:
            now = time.monotonic()
            cutoff = now - self.window_seconds
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= 1024:
                    stale_keys = [k for k, q in self._buckets.items() if not q or q[-1] <= cutoff]
                    for stale in stale_keys:
                        self._buckets.pop(stale, None)
                    if len(self._buckets) >= 1024:
                        return False, 0, self.window_seconds
                bucket = deque()
                self._buckets[key] = bucket
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                retry_after = max(0.0, self.window_seconds - (now - bucket[0]))
                return False, 0, retry_after
            bucket.append(now)
            return True, max(0, self.max_requests - len(bucket)), 0.0

    def reset(self):
        with self._lock:
            self._buckets.clear()

HTML_PAGE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Epistemic Memory Core — Dashboard de Operação & Governança</title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --primary-hover: #0284c7;
            --success: #4ade80;
            --warning: #fbbf24;
            --danger: #f87171;
            --badge-bg: rgba(56, 189, 248, 0.15);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.5;
            padding: 24px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
        }
        .logo-area h1 { font-size: 1.5rem; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 8px; }
        .logo-area p { color: var(--text-muted); font-size: 0.875rem; }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            background: var(--badge-bg);
            color: var(--primary);
            border: 1px solid rgba(56, 189, 248, 0.3);
        }
        .badge-success { background: rgba(74, 222, 128, 0.15); color: var(--success); border-color: rgba(74, 222, 128, 0.3); }
        .badge-warning { background: rgba(251, 191, 36, 0.15); color: var(--warning); border-color: rgba(251, 191, 36, 0.3); }

        /* Grid de Métricas */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }
        .metric-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px;
        }
        .metric-title { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 6px; }
        .metric-value { font-size: 1.6rem; font-weight: 700; color: var(--text); }
        .metric-sub { font-size: 0.75rem; color: var(--text-muted); margin-top: 4px; }

        /* Tabs */
        .tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--border); margin-bottom: 20px; }
        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 10px 18px;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
        }
        .tab-btn:hover { color: var(--text); }
        .tab-btn.active { color: var(--primary); border-bottom-color: var(--primary); }

        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* Card Section */
        .panel {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }
        .panel-title { font-size: 1.15rem; font-weight: 600; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }

        /* Formulários e Busca */
        .search-box {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
        }
        input[type="text"] {
            flex: 1;
            padding: 12px 16px;
            background: #0f172a;
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 0.95rem;
        }
        input[type="text"]:focus { outline: none; border-color: var(--primary); }
        button.btn {
            background: var(--primary);
            color: #0f172a;
            border: none;
            border-radius: 8px;
            padding: 12px 20px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        button.btn:hover { background: var(--primary-hover); }
        button.btn-outline {
            background: transparent;
            color: var(--text);
            border: 1px solid var(--border);
        }
        button.btn-outline:hover { background: var(--surface-hover); }

        /* Tabelas */
        table { width: 100%; border-collapse: collapse; margin-top: 12px; }
        th, td { text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--border); font-size: 0.875rem; }
        th { color: var(--text-muted); font-weight: 600; }
        tr:hover { background: var(--surface-hover); }

        /* Ações Rápidas */
        .actions-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
        }
        .action-card {
            background: #0f172a;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        .action-card h3 { font-size: 0.95rem; margin-bottom: 6px; }
        .action-card p { font-size: 0.8rem; color: var(--text-muted); margin-bottom: 14px; }

        pre {
            background: #0f172a;
            padding: 14px;
            border-radius: 8px;
            border: 1px solid var(--border);
            overflow-x: auto;
            font-size: 0.8rem;
            color: #38bdf8;
            max-height: 350px;
        }
        .loading { color: var(--text-muted); font-style: italic; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-area">
                <h1>🧠 Epistemic Memory Core <span class="badge" id="version-badge">v0.5</span></h1>
                <p>Protocolo de Memória Estruturada, Governança Epistemológica & Busca Híbrida</p>
            </div>
            <div>
                <button class="btn btn-outline" onclick="loadAll()">🔄 Atualizar Estado</button>
            </div>
        </header>

        <!-- Métricas Rápidas -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-title">Trabalhador Autônomo</div>
                <div class="metric-value" id="worker-status">--</div>
                <div class="metric-sub" id="worker-heartbeat">Heartbeat: verificando...</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Registros Catalogados</div>
                <div class="metric-value" id="records-count">--</div>
                <div class="metric-sub" id="flow-status">Verificando referências...</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Autotestes Locais</div>
                <div class="metric-value" id="test-status">--</div>
                <div class="metric-sub" id="test-detail">Verificando último resultado...</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Demandas do Grafo</div>
                <div class="metric-value" id="demands-count">--</div>
                <div class="metric-sub" id="demands-waiting">0 pendências</div>
            </div>
        </div>

        <!-- Abas -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('tab-busca')">🔍 Busca e Grafo</button>
            <button class="tab-btn" onclick="switchTab('tab-demandas')">📋 Demandas & Pendências</button>
            <button class="tab-btn" onclick="switchTab('tab-fontes')">📚 Catálogo de Fontes</button>
            <button class="tab-btn" onclick="switchTab('tab-operacoes')">⚡ Ações & Manutenção</button>
            <button class="tab-btn" onclick="switchTab('tab-manual')">📖 Manual & Contratos</button>
        </div>

        <!-- Aba 1: Busca Híbrida -->
        <div id="tab-busca" class="tab-content active">
            <div class="panel">
                <div class="panel-title">
                    <span>Recuperação Semântica, Lexical e Expansão de Grafo</span>
                    <span class="badge" id="embedding-status">Busca vetorial: verificando...</span>
                </div>
                <div class="search-box">
                    <input type="text" id="search-input" placeholder="Digite uma busca conceitual ou pergunta..." onkeypress="if(event.key==='Enter') executeSearch()">
                    <button class="btn" onclick="executeSearch()">Buscar</button>
                </div>
                <div id="search-results" class="loading">Digite algo acima para consultar o grafo.</div>
            </div>
        </div>

        <!-- Aba 2: Demandas -->
        <div id="tab-demandas" class="tab-content">
            <div class="panel">
                <div class="panel-title">Fila de Demandas & Esclarecimentos</div>
                <div id="demands-table-container">Carregando demandas...</div>
            </div>
        </div>

        <!-- Aba 3: Fontes -->
        <div id="tab-fontes" class="tab-content">
            <div class="panel">
                <div class="panel-title">Fontes Primárias & Evidências Gravadas</div>
                <div id="sources-table-container">Carregando fontes...</div>
            </div>
        </div>

        <!-- Aba 4: Operações -->
        <div id="tab-operacoes" class="tab-content">
            <div class="panel">
                <div class="panel-title">Tarefas de Manutenção em Segundo Plano</div>
                <div class="actions-grid">
                    <div class="action-card">
                        <div>
                            <h3>Auditoria de Integridade</h3>
                            <p>Verifica todos os arquivos Markdown, hashes SHA-256 e detecção de edições externas.</p>
                        </div>
                        <button class="btn btn-outline" onclick="triggerTask('audit_vault')">Enfileirar Auditoria</button>
                    </div>
                    <div class="action-card">
                        <div>
                            <h3>Atualizar Visões Sintéticas</h3>
                            <p>Reconstrói índices e visualizações consolidadas em 80_Visoes.</p>
                        </div>
                        <button class="btn btn-outline" onclick="triggerTask('refresh_view')">Atualizar Visões</button>
                    </div>
                    <div class="action-card">
                        <div>
                            <h3>Bateria de Autotestes</h3>
                            <p>Enfileira os autotestes em fixtures fictícias; requer trabalhador ativo.</p>
                        </div>
                        <button class="btn btn-outline" onclick="triggerTask('selftest')">Executar Autotestes</button>
                    </div>
                </div>
                <div style="margin-top: 24px;">
                    <h3 style="font-size: 0.95rem; margin-bottom: 8px;">Log de Resposta da Operação:</h3>
                    <pre id="op-log">Nenhuma ação recente executada.</pre>
                </div>
            </div>
        </div>

        <!-- Aba 5: Manual -->
        <div id="tab-manual" class="tab-content">
            <div class="panel">
                <div class="panel-title">Arquitetura de Governança (17 Capítulos)</div>
                <p style="color: var(--text-muted); margin-bottom: 16px;">
                    O sistema é regido por contratos formais de epistemologia, persistência atômica e prevenção de dirty reads.
                </p>
                <div id="manual-content">
                    <table>
                        <thead>
                            <tr><th>Capítulo</th><th>Título</th><th>Finalidade</th></tr>
                        </thead>
                        <tbody>
                            <tr><td>Capítulo 01</td><td>Fundamentos</td><td>Separação entre evidência e inferência, identificadores imutáveis.</td></tr>
                            <tr><td>Capítulo 05</td><td>Memória de Busca</td><td>Busca lexical, vetores E5 locais e fusão por RRF.</td></tr>
                            <tr><td>Capítulo 12</td><td>Execução Verificada</td><td>Transações em duas fases e travas exclusivas no SO.</td></tr>
                            <tr><td>Capítulo 15</td><td>Garantias de Execução</td><td>Reserva de nomes atômica, bloqueio de dirty reads e recibos determinísticos.</td></tr>
                            <tr><td>Capítulo 16</td><td>Retomada & Supervisão</td><td>Recuperação de tarefas expiradas e monitoramento contínuo.</td></tr>
                            <tr><td>Capítulo 17</td><td>Atribuição & Continuações</td><td>Controle estrito de sujeitos/citações e contratos de fila congelados.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        function escapeHTML(value) {
            const element = document.createElement('span');
            element.textContent = String(value ?? '');
            return element.innerHTML;
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }

        const EMC_CSRF_TOKEN = "__EMC_CSRF_TOKEN__";

        async function fetchAPI(endpoint, options = {}) {
            try {
                const reqOptions = { ...options };
                const method = (reqOptions.method || 'GET').toUpperCase();
                if (method !== 'GET' && method !== 'HEAD') {
                    reqOptions.headers = {
                        ...(reqOptions.headers || {}),
                        'X-EMC-Token': EMC_CSRF_TOKEN
                    };
                }
                const res = await fetch(endpoint, reqOptions);
                return await res.json();
            } catch (err) {
                console.error("Erro na API:", err);
                return { status: "error", error: err.toString() };
            }
        }

        async function loadAll() {
            // Estado Geral
            const estado = await fetchAPI('/api/estado');
            if (estado.status === 'ok') {
                document.getElementById('version-badge').textContent = 'v' + estado.version + ' (' + (estado.runtime_patch || 'sem patch informado') + ')';
            }

            // Configuração e último resultado dos testes (não executa testes).
            const diagnostic = await fetchAPI('/api/diagnostico');
            const testStatus = document.getElementById('test-status');
            const testDetail = document.getElementById('test-detail');
            const embedStatus = document.getElementById('embedding-status');
            if (diagnostic.status === 'ok') {
                const t = diagnostic.tests;
                const labels = {passed: 'APROVADOS', failed: 'FALHARAM', incomplete: 'INCOMPLETOS',
                    changed_during_test: 'CÓDIGO ALTERADO', stale: 'DESATUALIZADOS', not_run: 'NÃO EXECUTADOS'};
                testStatus.textContent = labels[t.status] || 'INDETERMINADO';
                testDetail.textContent = t.suites == null ? 'Sem resultado válido para este código' :
                    t.passed + '/' + t.suites + ' suítes aprovadas' + (t.checked_at ? ' · ' + t.checked_at : '');
                embedStatus.textContent = diagnostic.embeddings_enabled ?
                    'Busca vetorial: configurada (disponibilidade não verificada)' : 'Busca vetorial: desativada';
            } else {
                testStatus.textContent = 'INDISPONÍVEL';
                testDetail.textContent = 'Não foi possível consultar os autotestes';
                embedStatus.textContent = 'Busca vetorial: estado indisponível';
            }

            // Executor & Worker
            const executor = await fetchAPI('/api/executor');
            if (executor.worker) {
                const w = executor.worker;
                const workerLabels = {not_started: 'NÃO INICIADO', stopped: 'PARADO',
                    not_running: 'PARADO', stale: 'SEM PULSO RECENTE', running: 'ATIVO'};
                document.getElementById('worker-status').textContent = workerLabels[w.health] || 'INDETERMINADO';
                document.getElementById('worker-heartbeat').textContent = w.heartbeat_age_seconds != null ? 'Último pulso há ' + Number(w.heartbeat_age_seconds).toFixed(1) + 's' : 'Sem pulso registrado';
            }

            // Fluxo
            const fluxo = await fetchAPI('/api/fluxo');
            if (fluxo.status === 'ok') {
                document.getElementById('records-count').textContent = fluxo.records ?? '--';
                document.getElementById('flow-status').textContent = fluxo.issues && fluxo.issues.length ? 
                    fluxo.issues.length + ' problemas de referências' : 'Sem problemas de referências encontrados';
            } else if (fluxo.reason) {
                document.getElementById('records-count').textContent = '--';
                document.getElementById('flow-status').textContent = fluxo.reason;
            }

            // Demandas
            loadDemandas();
            loadFontes();
        }

        async function loadDemandas() {
            const data = await fetchAPI('/api/demandas');
            if (data && data.status === 'denied') {
                document.getElementById('demands-count').textContent = '--';
                document.getElementById('demands-waiting').textContent = 'Acesso bloqueado';
                document.getElementById('demands-table-container').textContent = data.reason || 'Acesso desabilitado.';
                return;
            }
            if (data && data.demands) {
                document.getElementById('demands-count').textContent = data.demands.length;
                const waiting = data.demands.filter(d => d.operational_status === 'waiting_user' || d.operational_status === 'expired_needs_review').length;
                document.getElementById('demands-waiting').textContent = waiting + ' aguardando revisão/usuário';

                let html = '<table><thead><tr><th>ID</th><th>Chave</th><th>Status Operacional</th><th>Ações / Pergunta</th></tr></thead><tbody>';
                data.demands.forEach(d => {
                    const badgeClass = d.operational_status === 'completed' ? 'badge-success' : 'badge-warning';
                    html += `<tr>
                        <td><code>${escapeHTML(d.id.substring(0, 8))}...</code></td>
                        <td>${escapeHTML(d.request_key)}</td>
                        <td><span class="badge ${badgeClass}">${escapeHTML(d.operational_status)}</span></td>
                        <td>${d.question ? '<strong>' + escapeHTML(d.question) + '</strong>' : escapeHTML(d.error || 'N/A')}</td>
                    </tr>`;
                });
                html += '</tbody></table>';
                document.getElementById('demands-table-container').innerHTML = html;
            }
        }

        async function loadFontes() {
            const data = await fetchAPI('/api/fontes');
            if (data && data.status === 'denied') {
                document.getElementById('sources-table-container').textContent = data.reason || 'Acesso desabilitado.';
                return;
            }
            if (data && data.records) {
                let html = '<table><thead><tr><th>ID</th><th>Título</th><th>Revisão</th></tr></thead><tbody>';
                data.records.slice(0, 15).forEach(f => {
                    html += `<tr>
                        <td><code>${escapeHTML(f.id.substring(0, 8))}...</code></td>
                        <td>${escapeHTML(f.title)}</td>
                        <td>Rev ${escapeHTML(f.revision)}</td>
                    </tr>`;
                });
                html += '</tbody></table>';
                document.getElementById('sources-table-container').innerHTML = html;
            }
        }

        async function executeSearch() {
            const query = document.getElementById('search-input').value.trim();
            if (!query) return;
            const container = document.getElementById('search-results');
            container.textContent = 'Consultando a busca configurada...';

            const res = await fetchAPI('/api/buscar', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ consulta: query, limite: 8 })
            });

            if (res.status && res.status !== 'ok') {
                container.textContent = 'Busca indisponível: ' + (res.reason || res.error || res.message || JSON.stringify(res));
            } else if (res.results && res.results.length) {
                let html = '<table><thead><tr><th>Tipo</th><th>Título</th><th>Score RRF</th><th>Citação / Trecho</th></tr></thead><tbody>';
                res.results.forEach(r => {
                    html += `<tr>
                        <td><span class="badge">${escapeHTML(r.record_type || r.kind || 'nota')}</span></td>
                        <td><strong>${escapeHTML(r.title || r.id)}</strong></td>
                        <td>${typeof r.score === 'number' ? r.score.toFixed(4) : '—'}</td>
                        <td>${escapeHTML(r.snippet || (r.text ? r.text.substring(0, 140) + '...' : ''))}</td>
                    </tr>`;
                });
                html += '</tbody></table>';
                container.innerHTML = html;
            } else {
                container.innerHTML = '<p style="color:var(--text-muted); padding: 12px;">Nenhum resultado encontrado para a busca.</p>';
            }
        }

        async function triggerTask(tipo) {
            const opLog = document.getElementById('op-log');
            opLog.textContent = 'Enviando comando ' + tipo + ' para a fila...';
            const res = await fetchAPI('/api/manutencao', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ tipo: tipo })
            });
            opLog.textContent = JSON.stringify(res, null, 2);
            setTimeout(loadAll, 1000);
        }

        window.onload = loadAll;
    </script>
</body>
</html>
"""

def dashboard_diagnostic():
    """Consulta configuração e resultado anterior, sem iniciar os autotestes."""
    execution = p.estado_execucao()
    if execution.get('status') != 'ok':
        return execution
    from autoteste import REAL_SYSTEM, fingerprint
    report_path = REAL_SYSTEM / 'estado' / 'autoteste.json'
    tests = {'status': 'not_run', 'suites': None, 'passed': None}
    try:
        if report_path.exists():
            report = json.loads(report_path.read_text(encoding='utf-8'))
            suites = report.get('suites', [])
            tests = {'status': report.get('status', 'unknown'), 'suites': len(suites),
                     'passed': sum(s.get('status') == 'passed' for s in suites),
                     'checked_at': report.get('checked_at')}
            if report.get('fingerprint') != fingerprint():
                tests['status'] = 'stale'
    except (OSError, ValueError, TypeError, AttributeError):
        tests = {'status': 'unknown', 'suites': None, 'passed': None}
    return {'status': 'ok', 'tests': tests,
            'embeddings_enabled': bool(execution.get('enabled') and execution.get('embeddings_enabled'))}


def _is_allowed_host(host_header):
    if not isinstance(host_header, str):
        return False
    match = _ALLOWED_HOST_RE.fullmatch(host_header.strip())
    if not match:
        return False
    port_str = match.group(1)
    return port_str is None or 1 <= int(port_str) <= 65535


class DashboardHandler(BaseHTTPRequestHandler):
    csrf_token = SESSION_TOKEN
    _server_limiter_lock = threading.Lock()

    def _init_request_tracking(self):
        self._body_consumed = False

    def _get_rate_limiter(self):
        limiter = getattr(self.server, 'rate_limiter', None)
        if limiter is None:
            with self._server_limiter_lock:
                limiter = getattr(self.server, 'rate_limiter', None)
                if limiter is None:
                    limiter = RateLimiter()
                    self.server.rate_limiter = limiter
        return limiter

    def _check_rate_limit(self):
        limiter = self._get_rate_limiter()
        client_key = self.client_address[0] if self.client_address else 'local'
        allowed, _, retry_after = limiter.allow(client_key)
        if not allowed:
            retry_seconds = max(1, math.ceil(retry_after))
            self.send_json(
                {
                    'status': 'rate_limited',
                    'error': 'rate_limit_exceeded',
                    'retry_after_seconds': retry_seconds,
                    'reason': 'Limite temporário de requisições excedido; aguarde antes de tentar novamente.',
                },
                code=429,
                extra_headers={
                    'Retry-After': str(retry_seconds),
                    'X-RateLimit-Limit': str(limiter.max_requests),
                    'X-RateLimit-Remaining': '0',
                },
            )
            return False
        return True

    def _drain_unconsumed_body(self):
        """Drena corpos pequenos/moderados antes de fechar em erro >= 400 (evita TCP RST no Windows)."""
        if getattr(self, '_body_consumed', False):
            return
        self._body_consumed = True
        if self.command in ('GET', 'HEAD'):
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except (TypeError, ValueError):
            return
        if length <= 0 or length > _MAX_DRAIN_BYTES:
            return
        prev_timeout = self.connection.gettimeout()
        try:
            self.connection.settimeout(0.5)
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, _DRAIN_CHUNK_BYTES))
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            pass
        finally:
            try:
                self.connection.settimeout(prev_timeout)
            except OSError:
                pass

    def _check_host(self):
        if not _is_allowed_host(self.headers.get('Host', '')):
            self.send_json({'status': 'denied', 'reason': 'Host HTTP não autorizado'}, code=403)
            return False
        return True

    def _check_csrf(self):
        sec_site = (self.headers.get('Sec-Fetch-Site') or '').strip().lower()
        if sec_site and sec_site not in ('same-origin', 'none'):
            self.send_json({'status': 'denied', 'reason': 'Requisição cross-site bloqueada'}, code=403)
            return False
        origin = (self.headers.get('Origin') or '').strip()
        if origin:
            parsed = urllib.parse.urlparse(origin)
            if parsed.scheme not in ('http', 'https') or (parsed.hostname or '').lower() not in ('127.0.0.1', 'localhost', '::1'):
                self.send_json({'status': 'denied', 'reason': 'Origem HTTP não autorizada'}, code=403)
                return False
        supplied = self.headers.get('X-EMC-Token') or ''
        if not supplied or not secrets.compare_digest(supplied, self.csrf_token):
            self.send_json({'status': 'denied', 'reason': 'Token de sessão ausente ou inválido'}, code=403)
            return False
        return True

    def _read_json_body(self):
        if self.headers.get('Transfer-Encoding'):
            self._body_consumed = True
            self.send_json({'status': 'invalid', 'reason': 'Transfer-Encoding não suportado'}, code=411)
            return None
        raw_len = self.headers.get('Content-Length', '0')
        try:
            length = int(raw_len)
        except (TypeError, ValueError):
            self._body_consumed = True
            self.send_json({'status': 'invalid', 'reason': 'Content-Length inválido'}, code=400)
            return None
        if length < 0:
            self._body_consumed = True
            self.send_json({'status': 'invalid', 'reason': 'Content-Length negativo'}, code=400)
            return None
        if length > MAX_POST_BYTES:
            self._drain_unconsumed_body()
            self.send_json({'status': 'invalid', 'reason': 'Corpo excede limite de 64 KB'}, code=413)
            return None
        self._body_consumed = True
        if length == 0:
            return {}
        try:
            payload = json.loads(self.rfile.read(length).decode('utf-8'))
        except (UnicodeDecodeError, ValueError):
            self.send_json({'status': 'invalid', 'reason': 'Corpo JSON inválido'}, code=400)
            return None
        if not isinstance(payload, dict):
            self.send_json({'status': 'invalid', 'reason': 'Objeto JSON esperado'}, code=400)
            return None
        return payload

    def do_GET(self):
        self._init_request_tracking()
        if not self._check_host() or not self._check_rate_limit():
            return
        url = urllib.parse.urlparse(self.path)
        if url.path in ('/', '/index.html'):
            rendered = HTML_PAGE.replace('__EMC_CSRF_TOKEN__', self.csrf_token).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(rendered)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'")
            self.end_headers()
            try:
                self.wfile.write(rendered)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True
        elif url.path == '/api/estado':
            self.send_json(p.estado())
        elif url.path == '/api/diagnostico':
            self.send_json(dashboard_diagnostic())
        elif url.path == '/api/executor':
            self.send_json(p.estado_executor())
        elif url.path == '/api/fluxo':
            self.send_json(p.verificar_fluxo())
        elif url.path == '/api/demandas':
            self.send_json(p.listar_demandas(30))
        elif url.path == '/api/fontes':
            self.send_json(p.listar_fontes())
        else:
            self.send_json({'status': 'not_found', 'reason': 'Não encontrado'}, code=404)

    def do_POST(self):
        self._init_request_tracking()
        if not self._check_host() or not self._check_rate_limit() or not self._check_csrf():
            return
        data = self._read_json_body()
        if data is None:
            return
        url = urllib.parse.urlparse(self.path)
        if url.path == '/api/buscar':
            query = data.get('consulta', '')
            limite = data.get('limite', 10)
            self.send_json(p.buscar_contexto(query, limite=limite))
        elif url.path == '/api/manutencao':
            tipo = data.get('tipo', 'refresh_view')
            op_key = 'dash-' + os.urandom(8).hex()
            self.send_json(p.enfileirar_manutencao(op_key, tipo))
        elif url.path == '/api/autotestes':
            self.send_json(p.executar_autotestes())
        else:
            self.send_json({'status': 'not_found', 'reason': 'Endpoint não encontrado'}, code=404)

    def send_json(self, data, code=200, extra_headers=None):
        if code >= 400:
            self._drain_unconsumed_body()
            self.close_connection = True
        payload_bytes = json.dumps(data, indent=2, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(payload_bytes)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Cache-Control', 'no-store')
        if extra_headers:
            for header_name, header_val in extra_headers.items():
                self.send_header(header_name, header_val)
        if code >= 400:
            self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(payload_bytes)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def log_message(self, format, *args):
        # Silencia logs de polling do dashboard no terminal
        return

def run_dashboard(port=8080, max_tries=20, rate_limit_requests=DEFAULT_RATE_LIMIT_REQUESTS, rate_limit_window_seconds=DEFAULT_RATE_LIMIT_WINDOW_SECONDS):
    limiter = RateLimiter(max_requests=rate_limit_requests, window_seconds=rate_limit_window_seconds)
    last_error = None
    for candidate_port in range(port, min(65536, port + max(1, max_tries))):
        server_address = ('127.0.0.1', candidate_port)
        try:
            httpd = ThreadingHTTPServer(server_address, DashboardHandler)
            httpd.rate_limiter = limiter
        except OSError as exc:
            last_error = exc
            continue
        try:
            print(f"Epistemic Memory Core dashboard: http://127.0.0.1:{candidate_port}")
            print("Pressione Ctrl+C para encerrar.")
            httpd.serve_forever()
            return
        finally:
            httpd.server_close()
    raise OSError(f"Nenhuma porta local disponível a partir de {port}") from last_error


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8080
    run_dashboard(port)


if __name__ == '__main__':
    main()
