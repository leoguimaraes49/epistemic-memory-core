# 🕸️ Epistemic HTTP Gateway & Live Lineage Graph Explorer

Gateway HTTP/REST local endurecido (**100% biblioteca padrão do Python**) construído sobre o **Epistemic Memory Core** para permitir que aplicações em **Node.js, Go, Rust, C#, webhooks e microsserviços** consumam e alimentem memória epistemológica governada via JSON sobre HTTP (`127.0.0.1:8095`), acompanhado de um **Inspetor Visual SVG Interativo de Linhagem e Raio de Impacto (*Stale-on-Write*)**.

---

## Arquitetura e Garantias Governadas

1. **Separação Estrita entre Evidência Primária e Derivação:**
   - Fontes primárias residem exclusivamente em `30_Fontes` (`Store`) com resumo criptográfico `SHA-256` e histórico imutável em `estado/revisoes/`.
   - Entidades (`10_Entidades`), afirmações (`20_Afirmacoes`), avaliações (`40_Avaliacoes`) e sínteses (`50_Sinteses`) exigem vínculos explícitos por revisão (`RevRef`: `{"record_id": "...", "revision": N}`).
2. **Invalidação Transitiva Auditável (*Stale-on-Write*):**
   - Ao retificar uma fonte primária (`POST /api/v1/sources/rectify`), todos os registros derivados e comprovantes que dependem direta ou transitivamente da revisão superada passam automaticamente para `status: "suspended"` / `stale`, sendo ocultados das buscas até revalidação explícita.
3. **Firewall de Atribuição (`atribuicao.py`) e Contratos Canônicos (`esquemas.py`):**
   - `POST /api/v1/knowledge` bloqueia deterministicamente (`HTTP 422`) falsas atribuições entre interlocutores, inferências disfarçadas de relato pessoal e diagnósticos clínicos implícitos.
4. **Comprovantes Determinísticos Sem LLM (`lab-assurance-2`):**
   - `POST /api/v1/verify-claims` verifica ponteiros JSON RFC 6901 (`field`), somas inteiras (`sum`) e cadeias transitivas (`chain`), emitindo recibos assinados por `SHA-256` contra o manifesto vigente do cofre.
5. **Endurecimento de Segurança Local:**
   - Vinculação exclusiva em loopback (`127.0.0.1` / `::1`) com `ThreadingHTTPServer`;
   - Proteção estrita contra *DNS Rebinding* no cabeçalho `Host` (`HTTP 403`);
   - Autenticação constante no tempo via `hmac.compare_digest` em `Authorization: Bearer <api_token>` (`HTTP 401`), mais token de sessão isolado por origem para a UI em `GET /`;
   - Teto rígido de `64 KB` por corpo HTTP (`HTTP 413` com `Content-Length` explícito, drenagem limitada segura para sockets BSD/macOS/Windows, `close_connection = True` e `wfile.flush()`);
   - Cabeçalhos `Content-Security-Policy`, `X-Frame-Options: DENY` e escapamento contra XSS em HTML/SVG.

---

## Como Executar

### 1. Subir o Servidor + Interface Web SVG (`http://127.0.0.1:8095`)

No Windows (PowerShell):
```powershell
$env:CEREBRO_PESSOAL_ACESSO="permitido"
$env:EMC_EMBEDDINGS_DIR="./modelos/e5-multilingual-small"
python apps/http_gateway/cli.py --workspace ./testes_temporarios/meu-gateway --token meu-token-local serve --port 8095 --seed-demo
```

No Linux / macOS:
```bash
CEREBRO_PESSOAL_ACESSO=permitido \
python3 apps/http_gateway/cli.py --workspace ./testes_temporarios/meu-gateway --token meu-token-local serve --port 8095 --seed-demo
```

### 2. Demonstração Ponta a Ponta via CLI (Porta Efêmera)
```bash
python apps/http_gateway/cli.py --workspace ./testes_temporarios/gw-demo demo
```

---

## Referência da API REST (`/api/v1/*`)

Todas as rotas `/api/v1/*` exigem o cabeçalho `Authorization: Bearer <api_token>`.

### 1. Saúde e Geração do Cofre — `GET /api/v1/health`
```bash
curl -sS http://127.0.0.1:8095/api/v1/health \
  -H "Authorization: Bearer meu-token-local"
```

### 2. Registrar Fonte Primária — `POST /api/v1/sources`
```bash
curl -sS -X POST http://127.0.0.1:8095/api/v1/sources \
  -H "Authorization: Bearer meu-token-local" \
  -H "Content-Type: application/json" \
  -d '{
    "operation_key": "ext-cotacao-01",
    "title": "Proposta Infraestrutura GPU",
    "source_kind": "document",
    "content": "{\"fornecedor\":\"Orion\",\"capex\":40000,\"opex\":160000,\"sla_bps\":9995}"
  }'
```

### 3. Registrar Conhecimento Governado — `POST /api/v1/knowledge`
```bash
curl -sS -X POST http://127.0.0.1:8095/api/v1/knowledge \
  -H "Authorization: Bearer meu-token-local" \
  -H "Content-Type: application/json" \
  -d '{
    "operation_key": "ext-ent-projeto-01",
    "record_type": "entity",
    "title": "Cluster Inferência Orion",
    "payload": {
      "entity_kind": "project",
      "purpose": "Reduzir latência p99 abaixo de 40ms",
      "project_status": "active",
      "identity_status": "identified",
      "origin_refs": [{"record_id": "<SOURCE_UUID>", "revision": 1}]
    }
  }'
```

### 4. Emitir Comprovante Determinístico (`lab-assurance-2`) — `POST /api/v1/verify-claims`
```bash
curl -sS -X POST http://127.0.0.1:8095/api/v1/verify-claims \
  -H "Authorization: Bearer meu-token-local" \
  -H "Content-Type: application/json" \
  -d '{
    "operation_key": "ext-recibo-orcamento-v1",
    "claims": [
      {
        "id": "custo_ano1",
        "kind": "sum",
        "value": 200000,
        "refs": [
          {"record_id": "<SOURCE_UUID>", "revision": 1, "path": "/capex"},
          {"record_id": "<SOURCE_UUID>", "revision": 1, "path": "/opex"}
        ]
      }
    ]
  }'
```

### 5. Busca Híbrida (Léxica + Grafo + ONNX E5) — `POST /api/v1/search`
```bash
curl -sS -X POST http://127.0.0.1:8095/api/v1/search \
  -H "Authorization: Bearer meu-token-local" \
  -H "Content-Type: application/json" \
  -d '{"query": "latência infraestrutura Orion", "limit": 8, "depth": 1}'
```

### 6. Retificar Fonte e Inspecionar Cascata — `POST /api/v1/sources/rectify` & `GET /api/v1/lineage/<id>`
```bash
# Retificar fonte primária (v1 -> v2)
curl -sS -X POST http://127.0.0.1:8095/api/v1/sources/rectify \
  -H "Authorization: Bearer meu-token-local" \
  -H "Content-Type: application/json" \
  -d '{
    "operation_key": "ext-cotacao-rect-v2",
    "record_id": "<SOURCE_UUID>",
    "expected_revision": 1,
    "reason": "Reajuste tarifário anual do fornecedor",
    "content": "{\"fornecedor\":\"Orion\",\"capex\":40000,\"opex\":195000,\"sla_bps\":9985}"
  }'

# Consultar grafo completo e linhagem/raio de impacto
curl -sS "http://127.0.0.1:8095/api/v1/graph?include_superseded=true" \
  -H "Authorization: Bearer meu-token-local"

curl -sS "http://127.0.0.1:8095/api/v1/lineage/<SOURCE_UUID>" \
  -H "Authorization: Bearer meu-token-local"
```
