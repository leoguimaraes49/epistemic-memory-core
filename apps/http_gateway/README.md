# 🕸️ Epistemic HTTP Gateway & Live Lineage Graph Explorer

Gateway HTTP/REST local endurecido (**100% biblioteca padrão do Python**) construído sobre o **Epistemic Memory Core** para permitir que aplicações em **Node.js, Go, Rust, C#, webhooks e microsserviços** consumam e alimentem memória epistemológica governada via JSON sobre HTTP (`127.0.0.1:8095`), acompanhado de um **Inspetor Visual SVG Interativo de Linhagem e Raio de Impacto (*Stale-on-Write*)**.

---

## Arquitetura e Garantias Governadas

1. **Separação Estrita entre Evidência Primária e Derivação:**
   - Fontes primárias residem exclusivamente em `30_Fontes` (`Store`) com resumo criptográfico `SHA-256` e histórico imutável em `estado/revisoes/`.
   - Entidades (`10_Entidades`), afirmações (`20_Afirmacoes`), avaliações (`40_Avaliacoes`) e sínteses (`50_Sinteses`) exigem vínculos explícitos por revisão (`RevRef`: `{"record_id": "...", "revision": N}`).
2. **Comprovantes Históricos Imutáveis em Replay (`gateway_operacoes.sqlite3`):**
   - Operações confirmadas em `POST /api/v1/sources`, `POST /api/v1/sources/rectify` e `POST /api/v1/knowledge` associam um recibo durável (`PRAGMA synchronous=FULL`) à chave `operation_key` e recuperam os bytes e `SHA-256` exatos da revisão correspondente em `estado/revisoes/` ou `estado/conhecimento_revisoes/`.
   - Ao repetir (`replayed: true`) uma chave antiga — mesmo após novas retificações ou reinicialização do servidor —, o gateway devolve exatamente a evidência histórica daquela operação (`sha256`, `old_sha256`, `new_sha256`, `diff` exato entre `from_revision` e `to_revision` e `revision_count_at_operation`), expondo o estado vivo atual separadamente em `current_state`.
3. **Invalidação Transitiva Auditável (*Stale-on-Write*):**
   - Ao retificar uma fonte primária (`POST /api/v1/sources/rectify`), todos os registros derivados e comprovantes que dependem direta ou transitivamente da revisão superada passam automaticamente para `status: "suspended"` / `stale`, sendo ocultados das buscas até revalidação explícita.
4. **Firewall de Atribuição (`atribuicao.py`) e Contratos Canônicos (`esquemas.py`):**
   - `POST /api/v1/knowledge` bloqueia deterministicamente (`HTTP 422`) falsas atribuições entre interlocutores, inferências disfarçadas de relato pessoal e diagnósticos clínicos implícitos.
5. **Comprovantes Determinísticos Sem LLM (`lab-assurance-2`):**
   - `POST /api/v1/verify-claims` verifica ponteiros JSON RFC 6901 (`field`), somas inteiras (`sum`) e cadeias transitivas (`chain`), emitindo recibos assinados por `SHA-256` contra o manifesto vigente do cofre.

---

## Modelo de Confiança Local e Escopos de Credencial

Em máquinas compartilhadas ou ambientes locais com múltiplos agentes/sandboxes de níveis distintos de confiança, o simples acesso à porta de loopback (`127.0.0.1`) **não** concede permissão de escrita no cofre:

| Perfil de Credencial | Origem | Escopo | Operações Permitidas |
| :--- | :--- | :--- | :--- |
| **`ui_session_token`** | Injetado no bootstrap `GET /` da interface web | **`read_only`** | Apenas inspeção sem mutação: `GET /api/v1/health`, `GET /api/v1/graph`, `GET /api/v1/lineage/<id>` e busca sem efeito colateral (`POST /api/v1/search` com `read_only: true`). Qualquer endpoint de escrita retorna **`HTTP 403`** (`{"status": "forbidden", "error": "insufficient_scope", "required_scope": "read_write", "current_scope": "read_only"}`). |
| **`api_token` (Operador)** | Definido via `--api-token` / `--token`, `EMC_GATEWAY_TOKEN` ou impresso no terminal do operador ao iniciar | **`read_write`** | Leitura e escrita completas (`POST /api/v1/sources`, `POST /api/v1/sources/rectify`, `POST /api/v1/knowledge`, `POST /api/v1/verify-claims`, `POST /api/v1/search` com indexação). |

- **Interface Web (`GET /`):** carrega por padrão em **Modo Somente Leitura** (grafo SVG e inspetor de linhagem funcionam imediatamente). Para executar mutações pela interface, o operador informa o token no campo **"Desbloquear Escrita (Token de Operador Bearer)"** no cabeçalho — mantido exclusivamente em memória de closure JavaScript da aba atual, nunca gravado em disco, cookies ou `localStorage`.
- **Demais Camadas HTTP:** vinculação exclusiva em loopback (`127.0.0.1` / `::1`), validação anti-*DNS Rebinding* em `Host` (`HTTP 403`), comparação em tempo constante via `hmac.compare_digest`, teto rígido de `64 KB` por payload (`HTTP 413`) e cabeçalhos `Content-Security-Policy` + `X-Frame-Options: DENY`.

---

## Autorização de Escopo e Execução (Clone ou Pacote `.whl`)

Por segurança, `EpistemicGatewayRuntime` valida o escopo autorizado **antes** de criar qualquer pasta ou arquivo em disco (uma tentativa em diretório não autorizado falha com `Invalid` deixando a pasta intacta):
- **Via CLI (`emc-gateway` / `cli.py --workspace DIR`):** o operador autoriza explicitamente o workspace informado na linha de comando. Quando `--cleanup` é usado, a CLI cria um subdiretório descartável exclusivo (`emc-gw-demo-*`) dentro de `DIR` e remove **apenas** esse subdiretório ao encerrar, preservando arquivos preexistentes no diretório pai mesmo em caso de falha.
- **Via Integração Programática Python (`EpistemicGatewayRuntime.from_workspace(DIR)`):** defina `EMC_AUTHORIZED_ROOTS=/caminho/permitido` (múltiplas raízes separadas por `os.pathsep`, `;` no Windows ou `:` no Linux/macOS) ou configure `EMC_SYSTEM` + `EMC_VAULT`.
- **Instalação via Wheel fora do clone:** os capítulos de `00_Manual/` e `manual_manifest.json` são carregados automaticamente via `recursos_pacote` (`emc_resources`) quando executados fora da árvore Git.

### 1. Subir o Servidor + Interface Web SVG (`http://127.0.0.1:8095`)

No Windows (PowerShell):
```powershell
$env:CEREBRO_PESSOAL_ACESSO="permitido"
$env:EMC_EMBEDDINGS_DIR="./modelos/e5-multilingual-small"
python apps/http_gateway/cli.py --workspace ./testes_temporarios/meu-gateway --api-token meu-token-local serve --port 8095 --seed-demo
```

No Linux / macOS (ou via entrypoint instalado `emc-gateway`):
```bash
CEREBRO_PESSOAL_ACESSO=permitido \
emc-gateway --workspace ./meu-gateway --api-token meu-token-local serve --port 8095 --seed-demo
```

### 2. Demonstração Ponta a Ponta via CLI (Porta Efêmera + Limpeza Escopada)
```bash
python apps/http_gateway/cli.py --workspace ./testes_temporarios/gw-demo --cleanup demo
```

---

## Referência da API REST (`/api/v1/*`)

Rotas de leitura aceitam `read_only` ou `read_write`; rotas de mutação exigem `Authorization: Bearer <api_token>` com escopo `read_write`.

### 1. Saúde e Geração do Cofre — `GET /api/v1/health`
```bash
curl -sS http://127.0.0.1:8095/api/v1/health \
  -H "Authorization: Bearer meu-token-local"
```

### 2. Registrar Fonte Primária — `POST /api/v1/sources` (`read_write`)
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

### 3. Registrar Conhecimento Governado — `POST /api/v1/knowledge` (`read_write`)
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

### 4. Emitir Comprovante Determinístico (`lab-assurance-2`) — `POST /api/v1/verify-claims` (`read_write`)
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
