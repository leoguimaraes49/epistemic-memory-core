# 🧠 Epistemic Agent Memory SDK

SDK Python *in-process* e adaptador universal de *Function Calling* sobre o **Epistemic Memory Core**, projetado para integrar memória governada e auditável diretamente em malhas multiagente (**LangGraph**, **OpenAI Agents**, **Google Gemini SDK** ou *loops* customizados) sem exigir transporte `stdio` MCP — tanto em clone editável quanto instalado via pacote `.whl` (`pip install .`).

## Garantias Epistemológicas Preservadas

1. **Separação Estrita (`30_Fontes` vs. Derivados):** Relatos, atas e cotações primárias permanecem imutáveis por revisão em `30_Fontes` com verificação `SHA-256`; entidades (`10_Entidades`), afirmações (`20_Afirmacoes`), sínteses (`50_Sinteses`) e questões (`60_Questoes`) exigem pinagem explícita `RevRef` (`{"record_id": ..., "revision": ...}`).
2. **Comprovantes Históricos Exatos em *Replay* Idempotente:** Toda mutação (`remember_source`, `rectify_source`, `register_entity`, `assert_fact`, `synthesize`, `prepare_decision`) persiste comprovante durável em `estado/sdk_operacoes.sqlite3` (`PRAGMA synchronous=FULL`) vinculado a `operation_key` e reconstrói *snapshots* exatos de revisão (`estado/revisoes/` e `estado/conhecimento_revisoes/`). Repetir uma chave antiga após novas retificações ou reinício do processo devolve o `sha256`, o `diff` (`from_revision -> to_revision`) e os derivados suspensos daquela operação histórica (`replayed: true`), separando o estado vivo atual em `current_state`.
3. **Firewall Determinístico de Atribuição (`atribuicao.py`):** `assert_fact()` bloqueia antes da escrita qualquer tentativa de atribuir falas, métricas numéricas ou pronomes não resolvidos à pessoa errada, bem como primeira pessoa oriunda de documentos externos.
4. **Zero Diagnóstico Clínico Implícito & Revisão Humana Isolada:** Nenhum registro aceita campos de diagnóstico clínico implícito, e `register_human_review()` jamais é exposta ao catálogo autônomo de ferramentas do LLM.
5. **Comprovantes Criptográficos Sem LLM (`lab-assurance-2`):** `verify_claims()` valida campos RFC 6901 (`field`), somas inteiras (`sum`) e cadeias transitivas (`chain`: `requires` / `precedes`) diretamente contra fontes primárias.
6. **Cascata *Stale-on-Write* e Raio de Impacto:** `rectify_source()` preserva a revisão anterior em `estado/revisoes/`, calcula o *diff* unificado exato entre revisões, suspende derivados dependentes (`needs_revalidation`) e marca comprovantes anteriores como `stale`.

---

## Autorização de Escopo de Workspace (Clone Editável e Wheel)

Por segurança, `EpistemicMemoryClient` valida o escopo do diretório **antes** de criar qualquer pasta ou arquivo em disco. Uma chamada não autorizada a `EpistemicMemoryClient.from_workspace("/caminho/nao-autorizado")` levanta `Invalid('raiz fora do escopo autorizado')` e mantém a pasta de destino **100% vazia**.

Para operar um *workspace* externo (inclusive quando instalado via `.whl` fora do clone Git, onde capítulos de `00_Manual/` e `manual_manifest.json` são carregados automaticamente via `recursos_pacote` / `emc_resources`), utilize uma das opções sancionadas:

1. **Lista explícita `EMC_AUTHORIZED_ROOTS` (recomendado para aplicações e múltiplos *workspaces*):**
   - Linux / macOS: `export EMC_AUTHORIZED_ROOTS="/dados/agentes:/outro/escopo"`
   - Windows (PowerShell): `$env:EMC_AUTHORIZED_ROOTS="D:\DadosAgentes;D:\OutroEscopo"`
2. **Processo dedicado a um único cofre (`EMC_SYSTEM` + `EMC_VAULT` ou `bootstrap_workspace_env`):**
   - Defina `EMC_SYSTEM=/caminho/ws/sistema` e `EMC_VAULT=/caminho/ws/cofre` antes de iniciar o processo, ou chame `bootstrap_workspace_env("/caminho/ws")` na inicialização da aplicação.
3. **Área efêmera de testes locais no clone:** subdiretórios dentro de `<REAL_SYSTEM>/testes_temporarios/`.

---

## Uso Rápido em Python

```python
import json
import os
from apps.agent_memory_sdk import EpistemicMemoryClient, make_operation_key

os.environ["EMC_AUTHORIZED_ROOTS"] = "/tmp/meu-workspace-governado"
client = EpistemicMemoryClient.from_workspace("/tmp/meu-workspace-governado/agente-01")

# 1. Ingerir fonte primária estruturada (comprovante histórico fixado à revisão 1)
fonte = client.remember_source(
    "Cotação Cluster #01",
    json.dumps({"capex": 40000, "opex": 120000, "sla_bps": 9995}),
    source_kind="document",
    operation_key=make_operation_key("ingest", "cotacao-01"),
)
# fonte["sha256"] -> SHA-256 exato da revisão 1
# fonte["current_state"] -> {"current_revision": 1, "current_sha256": ..., "currently_stale_ids": []}

# 2. Emitir comprovante determinístico lab-assurance-2
recibo = client.verify_claims(
    [
        {
            "id": "custo_ano1",
            "kind": "sum",
            "value": 160000,
            "refs": [
                {"record_id": fonte["id"], "revision": 1, "path": "/capex"},
                {"record_id": fonte["id"], "revision": 1, "path": "/opex"},
            ],
        }
    ]
)

# 3. Recuperar contexto híbrido (RRF lexical + ONNX E5 quando disponível + grafo)
ctx = client.recall_context("sla_bps capex", limit=5)

# 4. Inspecionar raio de impacto (ativos vs. suspensos)
raio = client.blast_radius(fonte["id"])
```

---

## Adaptador de *Function Calling* (OpenAI & Gemini)

```python
# Esquemas prontos para provedores de LLM
openai_tools = client.as_openai_tools()
gemini_decls = client.as_gemini_declarations()

# Despacho seguro com JSON estruturado e código de erro determinístico
resposta = client.dispatch_tool_call(
    "recall_context",
    '{"query": "orçamento anual", "limit": 5}',
    call_id="call_01",
)
# -> {"ok": True, "status": "ok", "tool": "recall_context", "error_code": None, "result": {...}}
```

### Códigos Determinísticos de Erro (`ErrorCode`)

| Código | Significado |
|---|---|
| `ACCESS_DENIED` | Cofre com `implantacao.lock` ativo ou sem `CEREBRO_PESSOAL_ACESSO=permitido`. |
| `UNKNOWN_TOOL` | Ferramenta inexistente ou vedada ao modelo (ex.: revisão humana). |
| `MALFORMED_ARGUMENTS` | JSON malformado, `NaN`/`Infinity`, tipo incorreto ou chave desconhecida. |
| `ATTRIBUTION_FIREWALL_BLOCKED` | Violação de sujeito, número trocado ou pronome ambíguo em `atribuicao.py`. |
| `REVISION_CONFLICT` | `RevRef` desatualizada, chave reutilizada para outro pedido ou base `stale`. |
| `RESOURCE_LOCKED` | Arquivo controlado temporariamente ocupado (`retryable: true`). |
| `UNCERTAIN_EFFECT` | Operação anterior interrompida exigindo reconciliação antes de repetir. |
| `VALIDATION_ERROR` | Violação estrutural/contratual (`Invalid`, diagnóstico proibido, escopo não autorizado, limites). |
| `IO_STORAGE_ERROR` | Falha de E/S local ou SQLite. |

---

## Demonstração Multiagente e Suíte de Testes

### Executar Handoff Multiagente (`Researcher -> Verifier -> Decision -> Cascade`)

Quando `--workspace DIR` é informado, a demonstração cria um subdiretório descartável próprio (`emc-sdk-demo-*`) dentro de `DIR`; `--cleanup` remove **exclusivamente** esse subdiretório descartável, preservando intactos quaisquer arquivos preexistentes em `DIR` mesmo em caso de falha.

Windows (PowerShell):
```powershell
$env:CEREBRO_PESSOAL_ACESSO="permitido"
.\.venv\Scripts\python.exe apps/agent_memory_sdk/cli_demo.py --workspace .\testes_temporarios\demo --cleanup
```

Linux / macOS:
```bash
CEREBRO_PESSOAL_ACESSO=permitido ./.venv/bin/python apps/agent_memory_sdk/cli_demo.py --workspace ./testes_temporarios/demo --cleanup
```

### Executar Suíte Automatizada (`unittest`)

```powershell
$env:CEREBRO_PESSOAL_ACESSO="permitido"
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "testes_agent_sdk.py" -v
```
