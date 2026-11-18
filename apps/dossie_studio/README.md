# 🏛️ Epistemic Dossier Studio

Aplicação prática construída sobre o **Epistemic Memory Core** para **auditoria de decisões técnicas, revisão contratual e experimentos rastreáveis**, operando 100% localmente sobre cofres Markdown + SQLite sem dependências externas de front-end.

## O que o aplicativo resolve na prática

1. **Separação Estrita entre Evidência Primária e Parecer Derivado:** Cotações, contratos e atas ficam isolados em `30_Fontes` com hash `SHA-256`; entidades, afirmações, decisões (`apoio_decisao.py`) e sínteses apontam para a revisão exata (`RevRef`).
2. **Firewall Determinístico de Atribuição (`atribuicao.py`):** Impede que valores numéricos ou falas de uma pessoa em uma ata sejam atribuídos a outra pessoa.
3. **Comprovantes Criptográficos Sem LLM (`verificador_evidencias.py`):** Verifica somas financeiras (`sum`), campos estruturados (`field` via ponteiros RFC 6901) e cadeias de dependência (`chain`: `requires`/`precedes`), emitindo recibos auditáveis `lab-assurance-2`.
4. **Simulador de Raio de Impacto (*Stale-on-Write*):** Quando uma cotação, cláusula contratual ou diário de experimento é retificado, o estúdio preserva a revisão anterior em `estado/revisoes/`, exibe o *diff* unificado e suspende automaticamente em cascata todos os pareceres, escores e comprovantes afetados.

---

## Como executar

### Interface Web Interativa (`http://127.0.0.1:8090`)
```powershell
# Subir já pré-carregado com o cenário de Engenharia & Cloud
.\.venv\Scripts\python.exe apps/dossie_studio/cli.py --workspace ./meu-dossie serve --preload engenharia_cotacao
```

No Linux / macOS:
```bash
./.venv/bin/python apps/dossie_studio/cli.py --workspace ./meu-dossie serve --preload engenharia_cotacao
```

### Operação via Linha de Comando (CLI)
```powershell
# 1. Listar os 3 cenários disponíveis (Engenharia, Jurídico, Pesquisa)
.\.venv\Scripts\python.exe apps/dossie_studio/cli.py scenarios

# 2. Carregar cenário jurídico em workspace isolado
.\.venv\Scripts\python.exe apps/dossie_studio/cli.py --workspace ./meu-dossie load juridico_contrato

# 3. Simular retificação contratual (2º Aditivo) e inspecionar cascata de invalidação
.\.venv\Scripts\python.exe apps/dossie_studio/cli.py --workspace ./meu-dossie mutate juridico_contrato

# 4. Consultar estado do grafo e validade dos comprovantes
.\.venv\Scripts\python.exe apps/dossie_studio/cli.py --workspace ./meu-dossie status
```
