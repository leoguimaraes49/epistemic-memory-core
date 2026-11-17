"""Cenários realistas de auditoria de decisões, contratos e experimentos sobre o Epistemic Memory Core.

Cada cenário demonstra:
1. Separação estrita entre fontes primárias (`30_Fontes`) e conhecimento derivado;
2. Firewall de atribuição de sujeito/citação (`atribuicao.py`);
3. Emissão de comprovantes determinísticos (`field`, `sum`, `chain` via `verificador_evidencias.py`);
4. Simulação ao vivo de mudança de premissa (`rectify_source`), suspendendo em cascata
   registros derivados e invalidando comprovantes sem apagar o histórico anterior.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .engine_adapter import DossieWorkspace


SCENARIO_CATALOG = {
    "engenharia_cotacao": {
        "id": "engenharia_cotacao",
        "title": "Engenharia & Cloud — Cotação de Cluster de Inferência",
        "domain": "Engenharia de Software / Infraestrutura",
        "description": (
            "Compara fornecedores para migração de cluster GPU com cotação JSON auditável, "
            "ata técnica com múltiplos engenheiros, cadeia transitiva de dependências e recibo matemático."
        ),
        "mutation_label": "Emitir Aditivo de Reajuste da Cotação NebulaCloud (Sobe OpEx e reduz SLA)",
    },
    "juridico_contrato": {
        "id": "juridico_contrato",
        "title": "Jurídico & Compliance — Auditoria de Contrato MSA e Aditivos",
        "domain": "Jurídico / Governança Contratual",
        "description": (
            "Rastreia cláusulas financeiras e prazos de rescisão entre contrato-base, aditivo vinculado "
            "(`parent_source_ref`), revisão humana escopada pelo cliente e parecer jurídico."
        ),
        "mutation_label": "Registrar 2º Aditivo Retificador (Altera prazo de aviso prévio de 30 para 90 dias)",
    },
    "pesquisa_decisao": {
        "id": "pesquisa_decisao",
        "title": "Pesquisa & Produtividade — Protocolo Estruturado e Experimento Real",
        "domain": "Pesquisa Aplicada / Apoio à Decisão",
        "description": (
            "Executa instrumento estruturado com item reverso (`40_Avaliacoes`), recomendação, "
            "experimento controlado (`trial`) e desfecho observado (`outcome`) sem diagnóstico implícito."
        ),
        "mutation_label": "Retificar Resposta do Item 1 após Conferência de Diário (Suspende escore derivado)",
    },
}


def load_scenario(ws: "DossieWorkspace", scenario_id: str) -> dict:
    if scenario_id == "engenharia_cotacao":
        return _load_engenharia(ws)
    if scenario_id == "juridico_contrato":
        return _load_juridico(ws)
    if scenario_id == "pesquisa_decisao":
        return _load_pesquisa(ws)
    raise ValueError(f"Cenário desconhecido: {scenario_id}")


def simulate_premise_change(ws: "DossieWorkspace", scenario_id: str) -> dict:
    if scenario_id == "engenharia_cotacao":
        return _mutate_engenharia(ws)
    if scenario_id == "juridico_contrato":
        return _mutate_juridico(ws)
    if scenario_id == "pesquisa_decisao":
        return _mutate_pesquisa(ws)
    raise ValueError(f"Cenário desconhecido: {scenario_id}")


def _load_engenharia(ws: "DossieWorkspace") -> dict:
    quote_nebula = {
        "fornecedor": "NebulaCloud",
        "moeda": "BRL",
        "capex_setup": 45000,
        "opex_anual": 180000,
        "sla_bps": 9995,
        "latencia_p99_ms": 38,
        "dependencias": {
            "etapa_1": ["cluster_gpu_l40s", "requires", "link_dedicado_10g"],
            "etapa_2": ["link_dedicado_10g", "requires", "homologacao_rede_matriz"],
        },
    }
    src_quote = ws.ingest_source(
        "eng-cotacao-nebula",
        "Cotação Oficial NebulaCloud #NC-2026-09",
        json.dumps(quote_nebula, ensure_ascii=False, indent=2),
        source_kind="document",
        origin_description="Proposta comercial assinada pela NebulaCloud",
    )
    src_ata = ws.ingest_source(
        "eng-ata-arquitetura",
        "Ata da Revisão de Arquitetura — Gate Técnico",
        (
            "Marina Costa informou que o limite máximo aceitável de latência p99 do gateway é 45ms. "
            "Carlos Eduardo relatou que o orçamento anual de infraestrutura aprovado pela diretoria é 240000 reais."
        ),
        source_kind="conversation",
    )

    ref_quote = {"record_id": src_quote["id"], "revision": src_quote["revision"]}
    ref_ata = {"record_id": src_ata["id"], "revision": src_ata["revision"]}

    marina = ws.register_person("eng-person-marina", "Marina Costa", ref_ata, aliases=["Marina"], summary="Arquiteta Principal de Sistemas")
    carlos = ws.register_person("eng-person-carlos", "Carlos Eduardo", ref_ata, aliases=["Carlos"], summary="Gerente de Operações e FinOps")
    proj = ws.register_entity(
        "eng-proj-inferencia",
        "Migração do Cluster de Inferência v2",
        {
            "entity_kind": "project",
            "purpose": "Reduzir latência p99 abaixo de 45ms com previsibilidade de custo anual",
            "project_status": "active",
            "origin_refs": [ref_quote, ref_ata],
        },
    )

    assert_marina = ws.register_assertion(
        "eng-assert-latencia-marina",
        "Restrição de latência relatada por Marina Costa",
        subject_ref={"record_id": marina["id"], "revision": 1},
        predicate="reports_preference",
        nature="third_party_report",
        asserted_by="dossie_studio",
        refs_list=[ref_ata],
        value={"type": "text", "content": "limite máximo aceitável de latência p99 de 45ms"},
        evidence_quote="Marina Costa informou que o limite máximo aceitável de latência p99 do gateway é 45ms.",
        evidence_source=ref_ata,
        context_description="Gate técnico de infraestrutura",
    )
    assert_carlos = ws.register_assertion(
        "eng-assert-orcamento-carlos",
        "Teto orçamentário relatado por Carlos Eduardo",
        subject_ref={"record_id": carlos["id"], "revision": 1},
        predicate="reports_value",
        nature="third_party_report",
        asserted_by="dossie_studio",
        refs_list=[ref_ata],
        value={"type": "number", "content": 240000, "unit": "BRL/ano"},
        evidence_quote="Carlos Eduardo relatou que o orçamento anual de infraestrutura aprovado pela diretoria é 240000 reais.",
        evidence_source=ref_ata,
        context_description="Orçamento aprovado de FinOps",
    )

    parecer = ws.register_synthesis(
        "eng-parecer-viabilidade",
        "Parecer Técnico — Viabilidade da Proposta NebulaCloud (Rev 1)",
        content=(
            "A proposta NebulaCloud (R$ 225.000 no 1º ano; SLA 99,95%; p99 38ms) cumpre simultaneamente "
            "a restrição técnica de 45ms definida por Marina Costa e o teto anual de R$ 240.000 informado por Carlos Eduardo."
        ),
        scope="Avaliação exclusiva da revisão 1 da Cotação #NC-2026-09 e da Ata do Gate Técnico",
        basis_refs=[
            ref_quote,
            {"record_id": assert_marina["id"], "revision": 1},
            {"record_id": assert_carlos["id"], "revision": 1},
            {"record_id": proj["id"], "revision": 1},
        ],
        limitations=[
            "Depende da homologação de rede da matriz antes da entrada em produção.",
            "Qualquer reajuste na cotação invalida automaticamente este parecer.",
        ],
    )

    decisao = ws.register_decision(
        "eng-decisao-fornecedor",
        "Seleção de Fornecedor para Cluster GPU",
        "Definir infraestrutura do cluster de inferência respeitando SLA >= 99,9% e custo de 1º ano <= R$ 240 mil.",
        [
            {
                "descricao": "Contratar NebulaCloud (L40S dedicado com link 10G)",
                "origem": "relatada_pelo_usuario",
                "pros": ["Custo total de 1º ano R$ 225.000 dentro do teto", "Latência p99 de 38ms (< 45ms)"],
                "contras": ["Exige homologação prévia do link dedicado 10G"],
                "incertezas": ["Prazo da operadora local para ativação da fibra"],
            },
            {
                "descricao": "Manter operação atual sob demanda em nuvem pública",
                "origem": "sugerida_pela_ia",
                "pros": ["Zero CapEx inicial de instalação"],
                "contras": ["Picos de latência p99 acima de 65ms em horário comercial"],
                "incertezas": ["Variação cambial mensal"],
            },
        ],
        [ref_quote, ref_ata],
        ["Qual o prazo contratual da operadora para concluir a homologação do link 10G?"],
    )

    claims = [
        {
            "id": "custo_primeiro_ano_brl",
            "kind": "sum",
            "value": 225000,
            "refs": [
                {"record_id": src_quote["id"], "revision": 1, "path": "/capex_setup"},
                {"record_id": src_quote["id"], "revision": 1, "path": "/opex_anual"},
            ],
        },
        {
            "id": "sla_contratado_bps",
            "kind": "field",
            "value": 9995,
            "refs": [{"record_id": src_quote["id"], "revision": 1, "path": "/sla_bps"}],
        },
        {
            "id": "cadeia_implantacao",
            "kind": "chain",
            "value": ["cluster_gpu_l40s", "requires", "homologacao_rede_matriz"],
            "refs": [
                {"record_id": src_quote["id"], "revision": 1, "path": "/dependencias/etapa_1"},
                {"record_id": src_quote["id"], "revision": 1, "path": "/dependencias/etapa_2"},
            ],
        },
    ]
    receipt = ws.issue_controlled_receipt("eng-recibo-cotacao-v1", claims, context_ids=[src_quote["id"]])

    return {
        "scenario_id": "engenharia_cotacao",
        "primary_source_id": src_quote["id"],
        "ata_source_id": src_ata["id"],
        "marina_id": marina["id"],
        "carlos_id": carlos["id"],
        "synthesis_id": parecer["id"],
        "decision": decisao,
        "receipt": receipt,
    }


def _mutate_engenharia(ws: "DossieWorkspace") -> dict:
    sources = {s["title"]: s for s in ws.store.list()}
    target = sources["Cotação Oficial NebulaCloud #NC-2026-09"]
    if target["revision"] >= 2:
        return {"status": "already_simulated", "message": "A revisão 2 da cotação já foi aplicada neste dossiê."}
    revised_quote = {
        "fornecedor": "NebulaCloud",
        "moeda": "BRL",
        "capex_setup": 45000,
        "opex_anual": 216000,
        "sla_bps": 9950,
        "latencia_p99_ms": 42,
        "dependencias": {
            "etapa_1": ["cluster_gpu_l40s", "requires", "link_dedicado_10g"],
            "etapa_2": ["link_dedicado_10g", "requires", "homologacao_rede_matriz"],
        },
    }
    return ws.rectify_source(
        "eng-retifica-cotacao-v2",
        target["id"],
        1,
        json.dumps(revised_quote, ensure_ascii=False, indent=2),
        "Fornecedor reajustou tabela de energia/GPUs (OpEx anual subiu para R$ 216.000, total 1º ano R$ 261.000 > teto) e reduziu SLA para 99,50%.",
    )


def _load_juridico(ws: "DossieWorkspace") -> dict:
    msa_doc = {
        "instrumento": "MSA-2026-401",
        "partes": [" Horizonte Logística S.A.", "Vektor Sistemas Ltda."],
        "multa_rescisoria_brl": 120000,
        "retencao_garantia_brl": 30000,
        "prazo_aviso_previo_dias": 30,
        "foro": "Comarca de São Paulo/SP",
    }
    src_msa = ws.ingest_source(
        "jur-contrato-msa",
        "Contrato Mestre de Serviços MSA-2026-401",
        json.dumps(msa_doc, ensure_ascii=False, indent=2),
        source_kind="document",
        origin_description="Instrumento contratual assinado digitalmente",
    )
    ref_msa = {"record_id": src_msa["id"], "revision": 1}

    src_aditivo1 = ws.ingest_source(
        "jur-aditivo-01",
        "1º Termo Aditivo — Cláusula de Proteção de Dados",
        "Fica estipulado o prazo máximo de 15 dias úteis para expurgo de backups mediante rescisão contratual.",
        source_kind="document",
        origin_description="Primeiro aditivo vinculado ao MSA-2026-401",
        extra_metadata={"parent_source_ref": ref_msa},
    )
    ref_ad1 = {"record_id": src_aditivo1["id"], "revision": 1}

    src_reuniao = ws.ingest_source(
        "jur-entrevista-diretoria",
        "Alinhamento com Diretoria Jurídica",
        "Helena Martins confirmou que o prazo operacional mínimo para transição sem ruptura logística é de 30 dias.",
        source_kind="conversation",
    )
    ref_reuniao = {"record_id": src_reuniao["id"], "revision": 1}

    helena = ws.register_person("jur-person-helena", "Helena Martins", ref_reuniao, aliases=["Helena"], summary="Diretora Jurídica")
    assert_prazo = ws.register_assertion(
        "jur-assert-transicao",
        "Janela mínima de transição confirmada por Helena Martins",
        subject_ref={"record_id": helena["id"], "revision": 1},
        predicate="reports_preference",
        nature="user_report",
        asserted_by="dossie_studio",
        refs_list=[ref_reuniao],
        value={"type": "text", "content": "transição mínima de 30 dias"},
        evidence_quote="Helena Martins confirmou que o prazo operacional mínimo para transição sem ruptura logística é de 30 dias.",
        evidence_source=ref_reuniao,
    )
    ws.register_human_review(
        "jur-revisao-humana-1",
        assert_prazo["id"],
        1,
        "confirmed_by_user",
        ref_reuniao,
        "prazo operacional mínimo para transição sem ruptura logística é de 30 dias",
        "Confirmação literal da janela operacional informada na reunião",
    )

    parecer_jur = ws.register_synthesis(
        "jur-parecer-rescisao",
        "Parecer Jurídico — Exposição Financeira e Prazo de Saída",
        content=(
            "Na vigência da Revisão 1 do MSA-2026-401, a exposição máxima de saída soma R$ 150.000 "
            "(multa + retenção) com aviso prévio de 30 dias compatível com a janela operacional."
        ),
        scope="MSA-2026-401 Rev 1 + 1º Aditivo",
        basis_refs=[ref_msa, ref_ad1, {"record_id": assert_prazo["id"], "revision": 2}],
        limitations=["Sujeito a alteração caso sobrevenha novo termo aditivo modificando prazos."],
    )

    receipt = ws.issue_controlled_receipt(
        "jur-recibo-exposicao-v1",
        [
            {
                "id": "exposicao_total_saida_brl",
                "kind": "sum",
                "value": 150000,
                "refs": [
                    {"record_id": src_msa["id"], "revision": 1, "path": "/multa_rescisoria_brl"},
                    {"record_id": src_msa["id"], "revision": 1, "path": "/retencao_garantia_brl"},
                ],
            },
            {
                "id": "aviso_previo_dias",
                "kind": "field",
                "value": 30,
                "refs": [{"record_id": src_msa["id"], "revision": 1, "path": "/prazo_aviso_previo_dias"}],
            },
        ],
        context_ids=[src_msa["id"]],
    )
    return {
        "scenario_id": "juridico_contrato",
        "primary_source_id": src_msa["id"],
        "synthesis_id": parecer_jur["id"],
        "receipt": receipt,
    }


def _mutate_juridico(ws: "DossieWorkspace") -> dict:
    sources = {s["title"]: s for s in ws.store.list()}
    target = sources["Contrato Mestre de Serviços MSA-2026-401"]
    if target["revision"] >= 2:
        return {"status": "already_simulated", "message": "O 2º Aditivo já foi aplicado neste dossiê."}
    msa_v2 = {
        "instrumento": "MSA-2026-401",
        "partes": [" Horizonte Logística S.A.", "Vektor Sistemas Ltda."],
        "multa_rescisoria_brl": 180000,
        "retencao_garantia_brl": 30000,
        "prazo_aviso_previo_dias": 90,
        "foro": "Comarca de São Paulo/SP",
    }
    return ws.rectify_source(
        "jur-retifica-msa-v2",
        target["id"],
        1,
        json.dumps(msa_v2, ensure_ascii=False, indent=2),
        "2º Termo Aditivo ampliou o aviso prévio obrigatório para 90 dias e reajustou a cláusula penal para R$ 180.000.",
    )


def _load_pesquisa(ws: "DossieWorkspace") -> dict:
    from avaliacoes import finish

    src_spec = ws.ingest_source(
        "pesq-fonte-protocolo",
        "Especificação do Índice de Foco Operacional (IFO-2)",
        "Instrumento técnico interno de auto-observação de blocos de trabalho profundo (escala 1 a 5, item 2 invertido). Não constitui instrumento clínico.",
        source_kind="document",
        origin_description="Protocolo interno de engenharia de produtividade",
    )
    src_relato = ws.ingest_source(
        "pesq-relato-semana1",
        "Diário de Observação — Semana 1 (Blocos Matinais)",
        "Rafael Lima registrou nota 4 em continuidade de foco e nota 2 em interrupções externas após desligar notificações.",
        source_kind="conversation",
    )
    ref_spec = {"record_id": src_spec["id"], "revision": 1}
    ref_relato = {"record_id": src_relato["id"], "revision": 1}

    rafael = ws.register_person("pesq-person-rafael", "Rafael Lima", ref_relato, aliases=["Rafael"])
    inst = ws.knowledge.apply(
        "pesq-instrumento-ifo",
        "instrument",
        "Índice de Foco Operacional IFO-2",
        {
            "instrument_name": "IFO-2",
            "instrument_version": "1.0",
            "purpose": "Mensuração descritiva de continuidade em sessões técnicas (não clínico)",
            "constructs": ["foco_sustentado"],
            "language": "pt-BR",
            "original_source_refs": [ref_spec],
            "target_population": "engenheiros_em_rotina_local",
            "age_scope": "adult",
            "items_source_ref": ref_spec,
            "instructions_source_ref": ref_spec,
            "scoring_rule_ref": ref_spec,
            "missing_response_rule": "require_all_items",
            "use_conditions": "Registro descritivo sem inferência clínica",
            "administration_modes": ["self_report"],
            "verification_status": "verified_for_intended_scope",
            "verification_refs": [ref_spec],
            "verification_scope": "Uso estritamente descritivo em experimentos pessoais de rotina",
            "scoring_spec": {
                "method": "weighted_sum",
                "items": [
                    {"id": "item_1", "dimension": "indice_foco", "min": 1, "max": 5, "weight": 1},
                    {"id": "item_2", "dimension": "indice_foco", "min": 1, "max": 5, "weight": 1, "reverse": True},
                ],
            },
        },
    )
    ref_inst = {"record_id": inst["id"], "revision": 1}
    app = ws.knowledge.apply(
        "pesq-aplicacao-1",
        "assessment",
        "Aplicação IFO-2 — Semana 1",
        {
            "instrument_ref": ref_inst,
            "subject_ref": {"record_id": rafael["id"], "revision": 1},
            "purpose": "Linha de base da Semana 1",
            "application_status": "in_progress",
            "conditions": {"mode": "self_report", "language": "pt-BR"},
            "scoring_eligibility": "calculable",
            "eligibility_reason": "Protocolo completo verificado para escopo descritivo",
        },
    )
    ref_app = {"record_id": app["id"], "revision": 1}
    ws.knowledge.apply(
        "pesq-resp-item1",
        "assessment_response",
        "Resposta IFO-2 Item 1",
        {
            "assessment_ref": ref_app,
            "item_ref": {"record_id": inst["id"], "revision": 1, "fragment": "item_1"},
            "value": 4,
            "source_refs": [ref_relato],
        },
    )
    ws.knowledge.apply(
        "pesq-resp-item2",
        "assessment_response",
        "Resposta IFO-2 Item 2 (Reverso)",
        {
            "assessment_ref": ref_app,
            "item_ref": {"record_id": inst["id"], "revision": 1, "fragment": "item_2"},
            "value": 2,
            "source_refs": [ref_relato],
        },
    )
    scored = finish(ws.store, "pesq-concluir-ifo", app["id"])

    rec = ws.register_entity(
        "pesq-rec-blocos",
        "Isolar blocos de 90 min sem mensageria",
        {
            "entity_kind": "recommendation",
            "suggestion": "Reservar janela 08h30–10h00 com notificações silenciadas",
            "purpose": "Reduzir trocas de contexto",
            "personal_basis_refs": [ref_relato],
            "limitations": ["Amostra de uma única semana; sono variou no período"],
            "recommendation_status": "accepted",
            "origin_refs": [ref_relato],
        },
    )
    trial = ws.register_entity(
        "pesq-trial-semana1",
        "Experimento de Blocos Silenciosos — Semana 1",
        {
            "entity_kind": "trial",
            "recommendation_ref": {"record_id": rec["id"], "revision": 1},
            "trial_description": "Execução durante 5 manhãs consecutivas",
            "trial_status": "completed",
            "origin_refs": [ref_relato],
        },
    )
    ws.register_entity(
        "pesq-outcome-semana1",
        "Desfecho Observado — Semana 1",
        {
            "entity_kind": "outcome",
            "outcome_description": "Índice descritivo atingiu 8.0/10, porém houve menor carga de reuniões na semana (confundidor explícito).",
            "observation_kind": "self_report",
            "observed_time": {"precision": "approximate", "value": "2026-11"},
            "source_refs": [ref_relato],
            "origin_refs": [ref_relato],
        },
    )
    return {
        "scenario_id": "pesquisa_decisao",
        "primary_source_id": src_relato["id"],
        "assessment_id": app["id"],
        "score_result": scored,
        "trial_id": trial["id"],
    }


def _mutate_pesquisa(ws: "DossieWorkspace") -> dict:
    sources = {s["title"]: s for s in ws.store.list()}
    target = sources["Diário de Observação — Semana 1 (Blocos Matinais)"]
    if target["revision"] >= 2:
        return {"status": "already_simulated", "message": "A retificação do diário já foi aplicada."}
    return ws.rectify_source(
        "pesq-retifica-diario-v2",
        target["id"],
        1,
        "Rafael Lima revisou o registro da quinta-feira: nota 3 em continuidade de foco e nota 3 em interrupções externas devido a incidente em produção.",
        "Conferência de log apontou interrupção de plantão na quinta-feira não contabilizada no relato inicial.",
    )
