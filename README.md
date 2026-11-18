# Epistemic Memory Core — Protocolo Local de Memória Auditável

> **Motor transacional de memória estruturada, governança de premissas, verificação determinística de alegações e busca híbrida local em SQLite + Markdown — utilizável diretamente via CLI e aplicações web locais ou conectado opcionalmente a agentes via MCP, SDK Python e Gateway HTTP/REST.**

🇺🇸 [Read in English](README.en.md) · [Epistemic Dossier Studio](apps/dossie_studio/README.md) · [Agent Memory SDK](apps/agent_memory_sdk/README.md) · [HTTP Gateway](apps/http_gateway/README.md) · [Manual Normativo (17 Capítulos)](00_Manual/indice-manual-cerebro.md) · [Arquitetura Detalhada](docs/guias/ARQUITETURA.md)

[![CI](https://github.com/leoguimaraes49/epistemic-memory-core/actions/workflows/testes.yml/badge.svg)](https://github.com/leoguimaraes49/epistemic-memory-core/actions/workflows/testes.yml)
[![Python 3.11 | 3.12](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![MCP 1.26](https://img.shields.io/badge/protocol-MCP%201.26%20%7C%20SDK%20%7C%20REST-purple.svg)](https://modelcontextprotocol.io/)
[![ONNX Local](https://img.shields.io/badge/embeddings-E5--multilingual%20(ONNX%20Local)-green.svg)](https://github.com/microsoft/onnxruntime)
[![SQLite + Markdown](https://img.shields.io/badge/storage-SQLite%20%2B%20Markdown-orange.svg)](https://obsidian.md/)
[![28 suítes](https://img.shields.io/badge/testes-28%20su%C3%ADtes-blue.svg)](#busca-vetorial-local-e-bateria-de-28-suítes-automatizadas)
[![v0.5.9](https://img.shields.io/badge/version-v0.5.9-blueviolet.svg)](https://github.com/leoguimaraes49/epistemic-memory-core/releases/tag/v0.5.9)

![Visão Geral da Arquitetura](docs/arquitetura.jpg)

> Para os fluxogramas Mermaid por cenário, diagrama de sequência transacional, tabela dos 25 módulos em `src/` e índice completo dos 17 capítulos normativos, consulte [`docs/guias/ARQUITETURA.md`](docs/guias/ARQUITETURA.md).

---

## O que o motor resolve

1. **Deriva de premissas sem invalidação:** quando uma fonte primária (`30_Fontes`) é retificada ou excluída, sínteses, escores e comprovantes dependentes são suspensos automaticamente em cascata (*stale-on-write*), mantendo histórico de revisões e raio de impacto auditável (`Knowledge.lineage`).
2. **Falsa atribuição de autoria:** o firewall determinístico (`src/atribuicao.py`) valida entidades pessoais, apelidos, pronomes e citações literais antes da gravação, bloqueando trocas de interlocutor, métricas numéricas cruzadas e vazamento de primeira pessoa em documentos externos.
3. **Leituras sujas, escrita truncada e divergência em replay:** toda mutação exige `operation_key`, registra proposta em SQLite (`PRAGMA synchronous=FULL`), retém trava exclusiva de sistema operacional até o `COMMIT` e emite recibos históricos imutáveis por operação — isolando a prova da revisão original de qualquer `current_state` consultado depois.
4. **Mistura entre relato observado e inferência:** fontes primárias (`30_Fontes`) permanecem fisicamente separadas do conhecimento derivado (`10_Entidades`, `20_Afirmacoes`, `50_Sinteses`), com verificação formal de alegações (`field` RFC-6901, `sum` estrito e `chain` acíclico) na biblioteca padrão (`lab-assurance-2`), sem chamadas a LLMs.

---

## Ecossistema Incluso (100% Funcional Sem IA Obrigatória)

| Componente | Papel e Superfície de Uso | Requisitos de IA |
| :--- | :--- | :--- |
| [`src/`](src/) ([Arquitetura](docs/guias/ARQUITETURA.md)) | **Motor Core, Servidor MCP (`ponte_pessoal.py`, 33 ferramentas), CLI (`emc` / `linhagem`), Painel (`:8080`) e Autoevolução (`melhorias.py`):** persistência ACID, busca híbrida RRF e laboratório determinístico de 4 classes. | **Nenhuma** (MCP opcional) |
| [`apps/dossie_studio/`](apps/dossie_studio/README.md) | **Epistemic Dossier Studio (`emc-dossie`, `:8090`):** bancada web e CLI para auditoria de cotações de engenharia, contratos jurídicos e protocolos de pesquisa com simulação *stale-on-write*. | **Nenhuma** |
| [`apps/agent_memory_sdk/`](apps/agent_memory_sdk/README.md) | **Agent Memory SDK (`in-process`):** cliente Python tipado com recibos históricos por `operation_key`, limpeza segura em subdiretório descartável e esquemas prontos para OpenAI, Gemini e LangGraph. | **Opcional** (*tool calling* sob demanda) |
| [`apps/http_gateway/`](apps/http_gateway/README.md) | **HTTP Gateway & Grafo SVG (`emc-gateway`, `:8095`):** API REST JSON v1 para qualquer linguagem + Inspetor Visual SVG de linhagem com sessão `read_only` na UI e token `Bearer` de operador (`read_write`) para escrita. | **Nenhuma** |

```powershell
# Bancada interativa de auditoria (cenários prontos: engenharia_cotacao, juridico_contrato, pesquisa_decisao)
.\.venv\Scripts\python.exe apps/dossie_studio/cli.py --workspace ./testes_temporarios/dossie serve --preload engenharia_cotacao

# Demonstração multiagente do SDK Python (cria e limpa apenas subdiretório descartável próprio)
.\.venv\Scripts\python.exe apps/agent_memory_sdk/cli_demo.py --workspace ./testes_temporarios/sdk-demo --cleanup

# Gateway REST v1 + Inspetor SVG de Linhagem em http://127.0.0.1:8095 e inspeção de linhagem via CLI
.\.venv\Scripts\python.exe apps/http_gateway/cli.py --workspace ./testes_temporarios/gw-demo serve --port 8095 --seed-demo
.\.venv\Scripts\python.exe src/cli.py linhagem <RECORD_ID>
```

---

## Como Começar (Clone Editável vs Pacote Wheel + Autorização de Escopo)

### 1. Instalação (Python 3.11 ou 3.12 — Windows, Linux e macOS)

```powershell
git clone https://github.com/leoguimaraes49/epistemic-memory-core.git
cd epistemic-memory-core
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-execucao04.txt

# Opção A — Desenvolvimento editável no clone (expondo emc, emc-mcp, emc-dashboard, emc-verifier, emc-dossie, emc-gateway):
.\.venv\Scripts\python.exe -m pip install --no-deps -e .

# Opção B — Pacote Wheel autossuficiente (embarca 00_Manual/*.md e config/*.json em emc_resources para rodar fora do clone):
.\.venv\Scripts\python.exe -m pip install --no-deps .
```

*(Em Linux/macOS, substitua `.\.venv\Scripts\python.exe` por `./.venv/bin/python`.)*

### 2. Autorização de Escopo de Workspace (`EMC_SYSTEM`, `EMC_VAULT`, `EMC_AUTHORIZED_ROOTS`)
Por segurança, `nucleo.is_authorized_scope` valida os diretórios **antes** de criar qualquer pasta ou banco SQLite. Por padrão, apenas o par principal (`EMC_SYSTEM` + `EMC_VAULT`) e subpastas sob `testes_temporarios/` são aceitos; caminhos fora de escopo levantam `Invalid("raiz fora do escopo autorizado")` deixando diretórios vazios intocados.

Para operar fora do clone Git (por exemplo, a partir de um `.whl` instalado em outro projeto), autorize explicitamente a pasta externa via **`EMC_AUTHORIZED_ROOTS`** (separado por `;` no Windows ou `:` no Linux/macOS) ou aponte `EMC_SYSTEM` e `EMC_VAULT`:

```powershell
# Exemplo fora do clone Git usando o pacote instalado (emc, emc-gateway, emc-dossie ou SDK Python):
$env:CEREBRO_PESSOAL_ACESSO = "permitido"
$env:EMC_AUTHORIZED_ROOTS = "C:\projetos\meu-workspace-externo"
$env:EMC_GATEWAY_TOKEN = "token-operador-local-secreto"

emc-gateway --workspace "C:\projetos\meu-workspace-externo\auditoria" serve --port 8095 --seed-demo
```

Para inicializar um cofre limpo para o Obsidian dentro do clone:
```powershell
.\.venv\Scripts\python.exe scripts/iniciar-template.py --destino ./meu-cofre --nome "Meu Cofre"
.\.venv\Scripts\python.exe src/dashboard.py   # Painel operacional local em http://127.0.0.1:8080
```

### 3. Fronteira de Confiança Local do HTTP Gateway (`read_only` vs `read_write`)
Em máquinas compartilhadas ou múltiplos agentes locais com níveis distintos de confiança, o bind em `127.0.0.1:8095` separa estritamente inspeção visual e mutação:

| Credencial | Escopo | Operações Permitidas | Comportamento em Escrita (`POST`) |
| :--- | :--- | :--- | :--- |
| `ui_session_token` (embutido em `GET /`) | `read_only` | `GET /api/v1/health`, `/api/v1/graph`, `/api/v1/lineage/<id>` e busca sem mutação canônica | Rejeitado com **`HTTP 403`** (`insufficient_scope`) em `/sources`, `/sources/rectify`, `/knowledge` e `/verify-claims` |
| Token de Operador (`--api-token` / `EMC_GATEWAY_TOKEN`) | `read_write` | Leitura integral + criação, retificação, registro de conhecimento e recibos `lab-assurance-2` | Autorizado via `Authorization: Bearer <token>` (`hmac.compare_digest`) ou desbloqueio em memória no topo da UI |

### 4. Conexão Opcional via Model Context Protocol (33 Ferramentas)
```json
{
  "mcpServers": {
    "cerebro_pessoal": {
      "command": "C:/caminho/epistemic-memory-core/.venv/Scripts/python.exe",
      "args": ["C:/caminho/epistemic-memory-core/src/ponte_pessoal.py"],
      "env": { "CEREBRO_PESSOAL_ACESSO": "permitido" }
    }
  }
}
```
Veja também os guias operacionais de [Execução](docs/guias/EXECUCAO.md), [Autonomia](docs/guias/AUTONOMIA.md) e [Execução Integrada](docs/guias/EXECUCAO-INTEGRADA.md).

---

## Estrutura Enxuta do Repositório

```text
├── 00_Manual/                   # Especificação normativa imutável (17 capítulos + manifesto SHA-256)
├── apps/                        # Aplicações e adaptadores sobre os contratos canônicos
│   ├── agent_memory_sdk/        # SDK Python in-process + Function Calling opcional (OpenAI, Gemini, LangGraph)
│   ├── dossie_studio/           # Bancada Web (:8090) + CLI para auditoria de decisões, contratos e pesquisa
│   └── http_gateway/            # Gateway REST JSON v1 (:8095) + Inspetor SVG (read_only UI / read_write Bearer)
├── config/                      # Manifestos operacionais (manual_manifest.json, execucao.json, autonomia.json)
├── docs/                        # Diagramas (arquitetura.jpg, architecture-en.jpg) e docs/guias/ARQUITETURA.md
├── scripts/                     # iniciar-template.py, benchmark_escala.py, stress_caos_concorrencia.py
├── src/                         # Motor epistêmico (25 módulos Python + pacote emc_resources no build wheel)
├── tests/                       # 28 suítes oficiais (autoteste) + 2 scripts MCP de regressão
├── LICENSE                      # Licença Non-Commercial Source-Available de autoria exclusiva
├── pyproject.toml / setup.py    # Pacote v0.5.9, recursos wheel e 6 CLIs (emc, emc-mcp, emc-dashboard, emc-verifier, emc-dossie, emc-gateway)
└── requirements-execucao04.txt  # Dependências Python fixadas por versão
```

---

## Busca Vetorial Local e Bateria de 28 Suítes Automatizadas

A busca semântica executa `intfloat/multilingual-e5-small` localmente em CPU via ONNX Runtime, conferindo o `SHA-256` antes da carga e persistindo vetores sem perda em `recuperacao.sqlite3` (`packed_f64` binário IEEE-754 por padrão ou `json`, rejeitando formatos com perda como `packed_f32`). Para executar a bateria completa, salve em `modelos/e5-multilingual-small/` (ou aponte `EMC_EMBEDDINGS_DIR`):
- [model.onnx](https://huggingface.co/intfloat/multilingual-e5-small/blob/614241f622f53c4eeff9890bdc4f31cfecc418b3/onnx/model.onnx) (470 MB) · [tokenizer.json](https://huggingface.co/intfloat/multilingual-e5-small/blob/614241f622f53c4eeff9890bdc4f31cfecc418b3/tokenizer.json) (17 MB)

As **28 suítes oficiais** rodam continuamente em **Ubuntu 24.04 (Python 3.11 e 3.12)**, **macOS 15** e **Windows Server 2022**:
- **Empacotamento Wheel (`1 suíte`):** `testes_empacotamento_wheel.py` — build `.whl` limpo com `emc_resources` e execução real fora do clone.
- **Adaptadores Universais (`3 suítes`):** `testes_agent_sdk.py`, `testes_http_gateway.py` e `testes_dossie_studio.py` — recibos históricos em replay pré/pós-reinício, escopos `read_only`/`read_write`, validação pré-mkdir e `--cleanup` isolado.
- **Hardening, Caos e Escala (`3 suítes`):** `testes_hardening_motor.py`, `testes_fuzz_caos.py` e `testes_auditoria_escala.py` — `Knowledge.lineage`, autocura de BLOBs vetoriais, RFC-6901, fuzzing Unicode e queda abrupta (`os._exit`).
- **Laboratório de Autoevolução (`3 suítes`):** `testes_evolucao_lab.py`, `testes_melhorias_seguranca.py` e `testes_operacao_melhorias.py` — índice SQLite real, isolamento AST e auditoria iterativa de 1.000+ adoções.
- **Núcleo ACID, Fila, Atribuição e MCP (`18 suítes`):** cobertura completa de travas SO, cascata *stale*, firewall de autoria, contratos congelados e protocolo MCP (matriz completa em [`docs/guias/ARQUITETURA.md`](docs/guias/ARQUITETURA.md#6-matriz-das-28-suítes-oficiais-de-teste-tests)).

```powershell
$env:CEREBRO_PESSOAL_ACESSO = "permitido"
.\.venv\Scripts\python.exe src/cli.py autotestes
.\.venv\Scripts\python.exe scripts/stress_caos_concorrencia.py --workers 6 --ops 15
```

*(Em Linux/macOS: `CEREBRO_PESSOAL_ACESSO=permitido ./.venv/bin/python src/cli.py autotestes`.)*

---

## Garantias, Limites Conscientes e Licença

- **Garantias físicas e de protocolo:** integridade por `SHA-256`, cadeias auditáveis de revisão, travas exclusivas por plataforma retidas até o `COMMIT` SQLite (`CreateFileW dwShareMode=0` no Windows; `flock` + `verify_posix_file` em Linux/macOS — veja [Garantias de Execução](00_Manual/manual-cerebro-15-garantias-de-execucao.md#arquivos-controlados-por-plataforma)), validação de escopo pré-escrita e recibos `lab-assurance-2` verificáveis sem LLM.
- **Limites conscientes:** o sistema não inventa diagnósticos nem perfis inferidos, não emite probabilidades sem base empírica, não transmite relatos locais para serviços externos não autorizados e jamais executa autoalteração arbitrária de código ou escalação de privilégios.
- **Licença:** distribuído sob licença **Non-Commercial Source-Available** ([`LICENSE`](LICENSE)) de autoria exclusiva de **Leonardo Guimarães (`@leoguimaraes49`)** — permitido para estudo, pesquisa acadêmica, auditoria técnica e uso estritamente pessoal sem fins lucrativos; vedado uso comercial, revenda ou oferta hospedada/SaaS sem autorização prévia por escrito do Autor.
