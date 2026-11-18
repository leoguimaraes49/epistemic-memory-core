#!/usr/bin/env python3
"""Demonstração executável de handoff multiagente sobre o Epistemic Agent Memory SDK.

Fluxo completo em workspace isolado:
  1. Researcher Agent (`agente_pesquisador`) -> ingere fontes primárias (`30_Fontes`)
     e registra entidades versionadas (`10_Entidades`);
  2. Attribution & Claim Verifier Agent (`agente_verificador`) -> bloqueia tentativa
     de troca de interlocutor pelo firewall `atribuicao.py`, registra afirmações
     legítimas e emite comprovante determinístico `lab-assurance-2` (`sum`, `field`, `chain`);
  3. Decision Agent (`agente_decisor`) -> recupera contexto híbrido (`recall_context`),
     sintetiza parecer (`synthesize`), prepara decisão (`prepare_decision`) e mede
     o raio de impacto inicial (`blast_radius`);
  4. Premise Rectification (`retificacao_em_cascata`) -> aplica aditivo retificador
     na proposta primária (`rectify_source`), suspendendo derivados em cascata
     (`needs_revalidation`) e invalidando o comprovante anterior (`stale`).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from apps.agent_memory_sdk.client import (
    EpistemicMemoryClient,
    ErrorCode,
    make_operation_key,
)


def _authorize_disposable_dir(run_dir: Path) -> str | None:
    previous = os.environ.get("EMC_AUTHORIZED_ROOTS")
    resolved = str(run_dir.resolve())
    entries = [p.strip() for p in (previous or "").split(os.pathsep) if p.strip()]
    if resolved not in entries:
        entries.append(resolved)
    os.environ["EMC_AUTHORIZED_ROOTS"] = os.pathsep.join(entries)
    return previous


def _restore_authorized_roots(previous: str | None) -> None:
    if previous is None:
        os.environ.pop("EMC_AUTHORIZED_ROOTS", None)
    else:
        os.environ["EMC_AUTHORIZED_ROOTS"] = previous


def run_multi_agent_handoff(
    workspace_dir: str | Path,
    *,
    enable_embeddings: bool | None = None,
    simulate_failure: bool = False,
) -> dict[str, Any]:
    """Executa o pipeline completo de 3 agentes + retificação em cascata e valida invariantes."""
    enforce_access = "CEREBRO_PESSOAL_ACESSO" in os.environ
    client = EpistemicMemoryClient.from_workspace(
        workspace_dir,
        enable_embeddings=enable_embeddings,
        require_access_env=True if enforce_access else None,
    )
    if simulate_failure or os.environ.get("EMC_SDK_DEMO_FAIL") == "1":
        raise RuntimeError("Falha simulada após inicialização do subdiretório descartável da demonstração.")

    # =========================================================================
    # Etapa 1 — Researcher Agent (ingestão primária via Function-Calling + SDK)
    # =========================================================================
    proposta_helios = {
        "fornecedor": "HeliosGPU",
        "moeda": "BRL",
        "capex_homologacao_brl": 35000,
        "opex_anual_brl": 165000,
        "sla_disponibilidade_bps": 9995,
        "latencia_p99_ms": 32,
        "cadeia_critica": {
            "etapa_a": ["cluster_helios_h100", "requires", "subestacao_redundante"],
            "etapa_b": ["subestacao_redundante", "requires", "laudo_termico_aprovado"],
        },
    }

    tool_src_doc = client.dispatch_tool_call(
        "remember_source",
        json.dumps(
            {
                "title": "Proposta Comercial HeliosGPU #HG-2026-11",
                "content": json.dumps(proposta_helios, ensure_ascii=False, indent=2),
                "source_kind": "document",
                "origin_description": "Cotação técnica assinada pela HeliosGPU",
                "reference_locator": "helios://propostas/HG-2026-11",
                "operation_key": make_operation_key("researcher", "proposta-helios-v1"),
            },
            ensure_ascii=False,
        ),
        call_id="call_researcher_01",
    )
    assert isinstance(tool_src_doc, dict) and tool_src_doc["ok"], tool_src_doc
    src_proposta = tool_src_doc["result"]
    ref_proposta = src_proposta["rev_ref"]

    src_ata = client.remember_source(
        "Ata do Comitê de Arquitetura e FinOps — Barramento Multiagente",
        (
            "Lívia Andrade estabeleceu que a latência p99 máxima admissível no barramento é 40ms. "
            "Renato Barros informou que o teto anual aprovado pela diretoria é 210000 reais."
        ),
        source_kind="conversation",
        operation_key=make_operation_key("researcher", "ata-comite-v1"),
    )
    ref_ata = src_ata["rev_ref"]

    livia = client.register_entity(
        "Lívia Andrade",
        "person",
        [ref_ata],
        fields={"aliases": ["Lívia"], "summary": "Arquiteta-Chefe de Plataformas de IA"},
        operation_key=make_operation_key("researcher", "entity-livia"),
    )
    renato = client.register_entity(
        "Renato Barros",
        "person",
        [ref_ata],
        fields={"aliases": ["Renato"], "summary": "Diretor de Governança Financeira (FinOps)"},
        operation_key=make_operation_key("researcher", "entity-renato"),
    )
    projeto = client.register_entity(
        "Barramento Multiagente Soberano",
        "project",
        [ref_proposta, ref_ata],
        fields={
            "purpose": "Operar inferência local abaixo de 40ms respeitando o teto anual de R$ 210 mil",
            "project_status": "active",
        },
        operation_key=make_operation_key("researcher", "entity-projeto"),
    )

    # =========================================================================
    # Etapa 2 — Attribution & Claim Verifier Agent (firewall + lab-assurance-2)
    # =========================================================================
    # Tentativa adversarial: atribuir o orçamento de Renato Barros (210000) à Lívia Andrade.
    blocked_misattribution = client.dispatch_tool_call(
        "assert_fact",
        {
            "title": "Orçamento atribuído incorretamente à Lívia",
            "subject_ref": livia["rev_ref"],
            "predicate": "reports_value",
            "nature": "third_party_report",
            "asserted_by": "agente_verificador",
            "source_refs": [ref_ata],
            "value": {"type": "number", "content": 210000, "unit": "BRL/ano"},
            "evidence_quote": "Renato Barros informou que o teto anual aprovado pela diretoria é 210000 reais.",
            "operation_key": make_operation_key("verifier", "bad-misattribution"),
        },
        call_id="call_verifier_block_01",
    )
    assert isinstance(blocked_misattribution, dict)
    assert blocked_misattribution["ok"] is False
    assert blocked_misattribution["error_code"] == ErrorCode.ATTRIBUTION_FIREWALL_BLOCKED

    fact_livia = client.assert_fact(
        "Restrição de latência p99 definida por Lívia Andrade",
        subject_ref=livia["rev_ref"],
        predicate="reports_preference",
        nature="third_party_report",
        asserted_by="agente_verificador",
        source_refs=[ref_ata],
        value={"type": "text", "content": "latência p99 máxima admissível de 40ms"},
        evidence_quote="Lívia Andrade estabeleceu que a latência p99 máxima admissível no barramento é 40ms.",
        context_description="Comitê de Arquitetura",
        operation_key=make_operation_key("verifier", "fact-livia-latencia"),
    )
    fact_renato = client.assert_fact(
        "Teto orçamentário anual relatado por Renato Barros",
        subject_ref=renato["rev_ref"],
        predicate="reports_value",
        nature="third_party_report",
        asserted_by="agente_verificador",
        source_refs=[ref_ata],
        value={"type": "number", "content": 210000, "unit": "BRL/ano"},
        evidence_quote="Renato Barros informou que o teto anual aprovado pela diretoria é 210000 reais.",
        context_description="Aprovação orçamentária FinOps",
        operation_key=make_operation_key("verifier", "fact-renato-orcamento"),
    )

    receipt = client.verify_claims(
        [
            {
                "id": "custo_total_ano1_brl",
                "kind": "sum",
                "value": 200000,
                "refs": [
                    {"record_id": src_proposta["id"], "revision": 1, "path": "/capex_homologacao_brl"},
                    {"record_id": src_proposta["id"], "revision": 1, "path": "/opex_anual_brl"},
                ],
            },
            {
                "id": "sla_contratual_bps",
                "kind": "field",
                "value": 9995,
                "refs": [
                    {"record_id": src_proposta["id"], "revision": 1, "path": "/sla_disponibilidade_bps"},
                ],
            },
            {
                "id": "dependencia_infraestrutura",
                "kind": "chain",
                "value": ["cluster_helios_h100", "requires", "laudo_termico_aprovado"],
                "refs": [
                    {"record_id": src_proposta["id"], "revision": 1, "path": "/cadeia_critica/etapa_a"},
                    {"record_id": src_proposta["id"], "revision": 1, "path": "/cadeia_critica/etapa_b"},
                ],
            },
        ],
        context_ids=[src_proposta["id"]],
        operation_key=make_operation_key("verifier", "receipt-helios-v1"),
    )
    assert receipt["status"] == "verified", receipt
    assert receipt["answer_verified"] is True

    # =========================================================================
    # Etapa 3 — Decision Agent (recuperação híbrida + síntese + decisão)
    # =========================================================================
    recalled = client.recall_context(
        "HeliosGPU latência p99 orçamento anual",
        limit=8,
        depth=1,
        include_records=False,
    )

    parecer = client.synthesize(
        "Parecer Integrado — Viabilidade Técnica e Financeira HeliosGPU (Rev 1)",
        content=(
            "Na revisão 1 da proposta #HG-2026-11, o custo total de 1º ano soma R$ 200.000 "
            "(abaixo do teto de R$ 210.000 de Renato Barros) com p99 de 32ms (abaixo do limite "
            "de 40ms de Lívia Andrade) e SLA de 99,95%."
        ),
        scope="Avaliação vinculada à Revisão 1 da Proposta #HG-2026-11 e à Ata do Comitê",
        basis_refs=[
            ref_proposta,
            fact_livia["rev_ref"],
            fact_renato["rev_ref"],
            projeto["rev_ref"],
        ],
        limitations=[
            "Condicionado à emissão do laudo térmico aprovado da subestação redundante.",
            "Qualquer reajuste tarifário do fornecedor invalida automaticamente este parecer.",
        ],
        operation_key=make_operation_key("decision-agent", "parecer-helios-v1"),
    )

    decisao = client.prepare_decision(
        "Contratação de Infraestrutura para o Barramento Multiagente",
        situation="Selecionar topologia de inferência cumprindo p99 <= 40ms e custo de 1º ano <= R$ 210.000.",
        options=[
            {
                "descricao": "Contratar cluster dedicado HeliosGPU conforme proposta #HG-2026-11",
                "origem": "relatada_pelo_usuario",
                "pros": ["Custo de 1º ano R$ 200.000 dentro do teto", "Latência p99 de 32ms"],
                "contras": ["Exige subestação redundante e laudo térmico prévio"],
                "incertezas": ["Data exata da vistoria predial do data center"],
            },
            {
                "descricao": "Postergar migração mantendo pool compartilhado atual",
                "origem": "sugerida_pela_ia",
                "pros": ["Sem desembolso imediato de homologação"],
                "contras": ["Latência p99 oscila acima de 58ms em picos"],
                "incertezas": ["Crescimento da fila de agentes no próximo trimestre"],
            },
        ],
        source_refs=[ref_proposta, ref_ata],
        gaps=["Qual o cronograma vinculante para emissão do laudo térmico aprovado?"],
        operation_key=make_operation_key("decision-agent", "decisao-helios-v1"),
    )

    radius_before = client.blast_radius(src_proposta["id"])
    assert len(radius_before["active_ids"]) >= 4
    assert radius_before["suspended_ids"] == []

    # =========================================================================
    # Etapa 4 — Retificação de Premissa e Cascata Stale-on-Write
    # =========================================================================
    proposta_helios_v2 = dict(
        proposta_helios,
        opex_anual_brl=195000,
        sla_disponibilidade_bps=9950,
    )
    rectification = client.rectify_source(
        src_proposta["id"],
        1,
        json.dumps(proposta_helios_v2, ensure_ascii=False, indent=2),
        (
            "Aditivo comercial da HeliosGPU elevou OpEx anual para R$ 195.000 "
            "(total de 1º ano R$ 230.000 > teto de R$ 210.000) e reduziu SLA para 99,50%."
        ),
        operation_key=make_operation_key("researcher", "retifica-helios-v2"),
    )

    radius_after = client.blast_radius(src_proposta["id"])
    parecer_after = client.read_record(parecer["id"])
    receipt_after = client.read_receipt(receipt["receipt_id"])
    recall_after = client.recall_context("HeliosGPU", limit=10, depth=1, include_records=False)

    assert parecer["id"] in radius_after["suspended_ids"]
    assert parecer_after["validity"] == "needs_revalidation"
    assert parecer_after["record"] is None
    assert receipt_after["status"] == "stale"
    assert parecer["id"] not in {item["id"] for item in recall_after["results"]}

    return {
        "status": "ok",
        "workspace": Path(workspace_dir).resolve().as_posix(),
        "embeddings_active": client.embedder is not None,
        "retrieval_mode": recalled["mode"],
        "handoff": {
            "researcher_agent": {
                "proposal_source": src_proposta["rev_ref"],
                "committee_source": src_ata["rev_ref"],
                "entities_registered": [livia["id"], renato["id"], projeto["id"]],
            },
            "verifier_agent": {
                "firewall_blocked_misattribution": {
                    "ok": blocked_misattribution["ok"],
                    "error_code": blocked_misattribution["error_code"],
                    "message": blocked_misattribution["error"]["message"],
                },
                "verified_assertions": [fact_livia["id"], fact_renato["id"]],
                "assurance_receipt": {
                    "receipt_id": receipt["receipt_id"],
                    "format": receipt["assurance_format"],
                    "status_before_rectification": receipt["status"],
                    "claims_checked": receipt["claims"],
                },
            },
            "decision_agent": {
                "recalled_count": len(recalled["results"]),
                "synthesis_id": parecer["id"],
                "decision_id": decisao["decision"]["id"],
                "analysis_id": decisao["analysis"]["id"],
                "open_question_ids": [q["id"] for q in decisao["questions"]],
                "choice": decisao["choice"],
                "blast_radius_before": {
                    "active_downstream_count": len(radius_before["active_ids"]),
                    "suspended_downstream_count": len(radius_before["suspended_ids"]),
                },
            },
            "cascade_invalidation": {
                "rectified_source_rev_ref": rectification["rev_ref"],
                "newly_suspended_ids": rectification["newly_suspended_ids"],
                "stale_receipt_ids": rectification["stale_receipt_ids"],
                "synthesis_validity_after": parecer_after["validity"],
                "receipt_status_after": receipt_after["status"],
                "excluded_stale_in_search": recall_after["excluded_stale"],
                "diff": rectification["diff"],
            },
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Demonstração de handoff multiagente sobre o Epistemic Agent Memory SDK."
    )
    parser.add_argument(
        "--workspace",
        default=None,
        help=(
            "Diretório pai opcional onde será criado um subdiretório descartável próprio "
            "(emc-sdk-demo-*) para a execução. Se omitido, usa diretório temporário e remove ao final."
        ),
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help=(
            "Remove estritamente o subdiretório descartável emc-sdk-demo-* criado para esta execução, "
            "preservando intacto qualquer arquivo preexistente no diretório --workspace."
        ),
    )
    parser.add_argument(
        "--no-embeddings",
        action="store_true",
        help="Força busca lexical + grafo sem carregar o modelo vetorial ONNX E5.",
    )
    parser.add_argument(
        "--simulate-failure",
        action="store_true",
        help="Simula falha controlada após criar o subdiretório descartável (para auditoria de limpeza segura).",
    )
    args = parser.parse_args(argv)

    enable_emb: bool | None = False if args.no_embeddings else None

    if args.workspace is None:
        in_repo_clone = (REPO_ROOT / "src" / "nucleo.py").is_file()
        if in_repo_clone:
            temp_base: Path | None = REPO_ROOT / "testes_temporarios"
            assert temp_base is not None
            temp_base.mkdir(parents=True, exist_ok=True)
        else:
            temp_base = None
        with tempfile.TemporaryDirectory(prefix="emc-sdk-demo-", dir=temp_base) as tmp_dir:
            prev_auth = _authorize_disposable_dir(Path(tmp_dir))
            try:
                report = run_multi_agent_handoff(
                    tmp_dir,
                    enable_embeddings=enable_emb,
                    simulate_failure=bool(args.simulate_failure),
                )
                report["workspace_cleaned_up"] = True
                print(json.dumps(report, ensure_ascii=False, indent=2))
            finally:
                _restore_authorized_roots(prev_auth)
        return 0

    ws_raw = Path(args.workspace)
    if ws_raw.is_symlink():
        raise ValueError("O caminho informado em --workspace não pode ser um link simbólico.")
    ws_path = ws_raw.resolve()
    if ws_path.exists() and not ws_path.is_dir():
        raise ValueError("O caminho informado em --workspace já existe e não é um diretório.")

    created_parent = not ws_path.exists()
    run_dir: Path | None = None
    prev_auth: str | None = None
    try:
        if created_parent:
            ws_path.mkdir(parents=True, exist_ok=True)
        run_dir = Path(tempfile.mkdtemp(prefix="emc-sdk-demo-", dir=ws_path)).resolve()
        prev_auth = _authorize_disposable_dir(run_dir)
        report = run_multi_agent_handoff(
            run_dir,
            enable_embeddings=enable_emb,
            simulate_failure=bool(args.simulate_failure),
        )
        report["workspace_parent"] = ws_path.as_posix()
        report["run_directory"] = run_dir.as_posix()
        report["workspace_cleaned_up"] = bool(args.cleanup)
        print(json.dumps(report, ensure_ascii=False, indent=2))
    finally:
        _restore_authorized_roots(prev_auth)
        if args.cleanup:
            if (
                run_dir is not None
                and run_dir.exists()
                and not run_dir.is_symlink()
                and run_dir.resolve().parent == ws_path
                and run_dir.name.startswith("emc-sdk-demo-")
            ):
                shutil.rmtree(run_dir)
            if created_parent and ws_path.exists() and not ws_path.is_symlink():
                try:
                    ws_path.rmdir()
                except OSError:
                    pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
