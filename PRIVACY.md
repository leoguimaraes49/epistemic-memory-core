# Privacy Policy — Epistemic Memory Core

**Last updated:** 2026-11-25  
**Repository:** https://github.com/leoguimaraes49/epistemic-memory-core  
**Maintainer:** Leonardo Guimarães (`@leoguimaraes49`)

## 1. Local-First Principle & Zero Telemetry

Epistemic Memory Core is a **local-first** memory engine and Model Context Protocol (MCP) server designed to run entirely on the operator's own machine.

- **No telemetry or analytics:** The software contains no analytics SDKs, crash reporters, usage beacons, or tracking endpoints.
- **No developer-hosted cloud backend:** The maintainer does not collect, receive, store, or process any data from your vault, queries, SQLite databases, or MCP sessions.
- **Default-deny content gate:** Access to personal vault contents via the MCP bridge (`src/ponte_pessoal.py`) is disabled by default until the operator explicitly sets `CEREBRO_PESSOAL_ACESSO=permitido` in the local process environment.

## 2. Data Stored Locally

All persistent records stay strictly inside the two operator-authorized local directories (`EMC_SYSTEM` and `EMC_VAULT`, or paths explicitly allowlisted via `EMC_AUTHORIZED_ROOTS` and validated by `nucleo.is_authorized_scope` prior to directory creation):

- **Markdown Vault (`EMC_VAULT`):** Primary sources (`30_Fontes/`), derived entities, assertions, evaluations, syntheses, open questions, operational records, and views (`10_Entidades/` through `80_Visoes/`), plus read-only normative chapters (`00_Manual/`).
- **Local SQLite & Operational State (`EMC_SYSTEM/estado/`):** Control ledger (`controle.sqlite3` with `PRAGMA secure_delete=ON`), derived knowledge index (`conhecimento.sqlite3`), local search vectors and query history (`recuperacao.sqlite3`), durable queue and coordination databases (`fila.sqlite3`, `coordenacao/coordenacao.sqlite3`), deterministic claim receipts (`comprovantes/`), SDK/Gateway operation ledgers (`sdk_operacoes.sqlite3`, `gateway_operacoes.sqlite3` with `PRAGMA secure_delete=ON`), and local revision history.
- **Storage Security Boundaries:** New controlled and lock files apply restrictive POSIX permissions (`0o600` on POSIX platforms). **Vault files and SQLite databases are not encrypted at rest by this software**; operators should rely on operating-system disk encryption (e.g., BitLocker, FileVault, LUKS) and OS account isolation.

## 3. Local AI Embeddings (100% Offline)

When local semantic search is enabled (`src/recuperacao.py`), the `intfloat/multilingual-e5-small` model (`model.onnx` and `tokenizer.json`) runs strictly offline on the local CPU via `onnxruntime` after verifying pinned `SHA-256` digests. Production code never downloads model files or transmits text to remote embedding services.

## 4. Optional External Network & Subprocess Integrations

With default configuration (`config/execucao.json`), **no outbound internet connections are made**. External traffic occurs only when explicitly enabled and invoked by the operator:

1. **Bounded Bibliographic Search (`src/pesquisa.py`):**
   - Strictly allowlisted to `https://api.crossref.org/works` with HTTP redirects rejected, a 15-second timeout, and a 1.5 MB response size limit.
   - Sends only 1 to 5 predefined English technical terms from a closed dictionary (`TERMS`) — free-form text and personal biographical content are rejected before any request is issued.
   - Resulting DOI links (`https://doi.org/...`) are stored solely as reference metadata strings and are not fetched automatically.
2. **Optional External Text Model CLI (`src/provedores.py`):**
   - Disabled by default (`model.enabled: false`).
   - Only invoked if the operator explicitly enables `model.enabled: true` and configures an approved local CLI executable. When launched, it runs in read-only ephemeral mode with web search disabled and third-party API key environment variables (`OPENAI_API_KEY`, `CODEX_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`) stripped from the child environment. Any prompt text submitted through an operator-enabled external CLI is governed by that provider's own privacy policy.
3. **Loopback-Only Local HTTP Surfaces:**
   - The operational dashboard (`src/dashboard.py`), Epistemic Dossier Studio (`apps/dossie_studio/web.py`), and HTTP Gateway (`apps/http_gateway/server.py`) strictly bind to local loopback interfaces (`127.0.0.1`, `localhost`, or `::1`) and enforce `Host` validation, CSRF/Bearer authentication, payload limits, and rate limiting.

## 5. Secrets & Environment Variables

Sensitive environment variables (such as `EMC_GATEWAY_TOKEN`) are read exclusively for local loopback Bearer authentication (`hmac.compare_digest`), are never transmitted over the network, are stripped from external model and signature-check child environments (`src/provedores.py`), and are never written to disk. When starting `emc-gateway serve` interactively, the active operator Bearer token is printed once to local terminal stdout so the operator can unlock write actions in the local browser UI.

## 6. Data Retention & User-Controlled Deletion

- Operators control all files directly on their local filesystem and may delete the workspace at any time.
- The MCP tool `excluir_fonte` performs controlled deletion of a primary source and its local revision history only upon explicit operator request, recording a tombstone without resurrecting deleted text. Deletion applies strictly to local storage and cannot erase copies exported to external systems or MCP clients.

## 7. Security & Contact

For vulnerability reports or privacy questions, see [SECURITY.md](SECURITY.md) or open an issue at https://github.com/leoguimaraes49/epistemic-memory-core/issues.
