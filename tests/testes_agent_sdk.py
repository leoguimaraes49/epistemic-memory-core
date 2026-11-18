"""Suíte completa de integração e contratos do Epistemic Agent Memory SDK."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from atribuicao import AttributionError
from nucleo import REAL_SYSTEM, Conflict, Invalid
from apps.agent_memory_sdk import (
    EpistemicAccessDeniedError,
    EpistemicMemoryClient,
    ErrorCode,
    make_operation_key,
)


class EpistemicAgentMemorySDKTests(unittest.TestCase):
    def setUp(self) -> None:
        temp_base = REAL_SYSTEM / "testes_temporarios"
        temp_base.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="sdk-test-", dir=temp_base)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.ws_dir = self.base / "ws"
        self.client = EpistemicMemoryClient.from_workspace(
            self.ws_dir,
            enable_embeddings=False,
        )

    def test_make_operation_key_determinism_and_validation(self) -> None:
        k1 = make_operation_key("Agente Pesquisador!", {"b": 2, "a": [1, True]}, "v1")
        k2 = make_operation_key("Agente Pesquisador!", {"a": [1, True], "b": 2}, "v1")
        self.assertEqual(k1, k2)
        self.assertLessEqual(len(k1), 52)
        self.assertRegex(k1, r"^[A-Za-z0-9_-]{16,52}$")

        # bool (True) e int (1) devem produzir chaves distintas
        k_int = make_operation_key("ns", {"flag": 1})
        k_bool = make_operation_key("ns", {"flag": True})
        self.assertNotEqual(k_int, k_bool)

        with self.assertRaises(Invalid):
            make_operation_key("", "x")
        with self.assertRaises(Invalid):
            make_operation_key("ns", float("nan"))
        with self.assertRaises(Invalid):
            make_operation_key("ns", "x", max_length=True)  # type: ignore[arg-type]
        with self.assertRaises(Invalid):
            make_operation_key("ns", "x", max_length=81)

    def test_idempotency_across_restarts_and_conflict_on_key_reuse(self) -> None:
        src1 = self.client.remember_source(
            " Especificação JSON ",
            json.dumps({"orcamento": 100000, "extra": 25000}),
            source_kind="document",
            operation_key="idem-src-01",
        )
        # Replay em nova instância do cliente (simulando retomada de processo)
        reloaded = EpistemicMemoryClient.from_workspace(self.ws_dir, enable_embeddings=False)
        src2 = reloaded.remember_source(
            " Especificação JSON ",
            json.dumps({"orcamento": 100000, "extra": 25000}),
            source_kind="document",
            operation_key="idem-src-01",
        )
        self.assertEqual(src1["id"], src2["id"])
        self.assertEqual(src1["revision"], 1)

        with self.assertRaises(Conflict):
            reloaded.remember_source(
                "Outro conteúdo",
                json.dumps({"orcamento": 999}),
                source_kind="document",
                operation_key="idem-src-01",
            )

        ata = self.client.remember_source(
            "Ata de Alinhamento",
            "Clara Mendes confirmou prioridade máxima para latência sub-40ms.",
            source_kind="conversation",
            operation_key="idem-ata-01",
        )
        ent1 = self.client.register_entity(
            "Clara Mendes",
            "person",
            [ata["rev_ref"]],
            fields={"aliases": ["Clara"]},
            operation_key="idem-ent-clara",
        )
        ent2 = reloaded.register_entity(
            "Clara Mendes",
            "person",
            [ata["rev_ref"]],
            fields={"aliases": ["Clara"]},
            operation_key="idem-ent-clara",
        )
        self.assertEqual(ent1["id"], ent2["id"])

        # assert_fact sem recorded_time explícito usa âncora determinística da fonte
        fact1 = self.client.assert_fact(
            "Prioridade de latência de Clara",
            subject_ref=ent1["rev_ref"],
            predicate="reports_preference",
            nature="user_report",
            source_refs=[ata["rev_ref"]],
            value={"type": "text", "content": "prioridade máxima para latência sub-40ms"},
            evidence_quote="Clara Mendes confirmou prioridade máxima para latência sub-40ms.",
            operation_key="idem-fact-clara",
        )
        fact2 = reloaded.assert_fact(
            "Prioridade de latência de Clara",
            subject_ref=ent1["rev_ref"],
            predicate="reports_preference",
            nature="user_report",
            source_refs=[ata["rev_ref"]],
            value={"type": "text", "content": "prioridade máxima para latência sub-40ms"},
            evidence_quote="Clara Mendes confirmou prioridade máxima para latência sub-40ms.",
            operation_key="idem-fact-clara",
        )
        self.assertEqual(fact1["id"], fact2["id"])

        syn1 = self.client.synthesize(
            "Resumo Inicial",
            content="Orçamento consolidado de R$ 125.000 com prioridade em latência.",
            scope="Revisão 1",
            basis_refs=[src1["rev_ref"], fact1["rev_ref"]],
            limitations=["Aguardando cotação secundária"],
            operation_key="idem-syn-01",
        )
        syn2 = reloaded.synthesize(
            "Resumo Inicial",
            content="Orçamento consolidado de R$ 125.000 com prioridade em latência.",
            scope="Revisão 1",
            basis_refs=[src1["rev_ref"], fact1["rev_ref"]],
            limitations=["Aguardando cotação secundária"],
            operation_key="idem-syn-01",
        )
        self.assertEqual(syn1["id"], syn2["id"])

        dec_opts = [
            {
                "descricao": "Adotar arquitetura local dedicada",
                "origem": "relatada_pelo_usuario",
                "pros": ["Baixa latência"],
                "contras": ["CapEx inicial"],
                "incertezas": ["Prazo de entrega"],
            },
            {
                "descricao": "Manter arquitetura atual",
                "origem": "sugerida_pela_ia",
                "pros": ["Sem migração"],
                "contras": ["Latência maior"],
                "incertezas": ["Demanda futura"],
            },
        ]
        dec1 = self.client.prepare_decision(
            "Escolha de Arquitetura",
            situation="Definir topologia para o próximo ciclo.",
            options=dec_opts,
            source_refs=[src1["rev_ref"], ata["rev_ref"]],
            gaps=["Qual a janela de manutenção aprovada?"],
            operation_key="idem-dec-01",
        )
        dec2 = reloaded.prepare_decision(
            "Escolha de Arquitetura",
            situation="Definir topologia para o próximo ciclo.",
            options=dec_opts,
            source_refs=[src1["rev_ref"], ata["rev_ref"]],
            gaps=["Qual a janela de manutenção aprovada?"],
            operation_key="idem-dec-01",
        )
        self.assertEqual(dec1["decision"]["id"], dec2["decision"]["id"])
        self.assertEqual(dec1["analysis"]["id"], dec2["analysis"]["id"])

        rec1 = self.client.verify_claims(
            [
                {
                    "id": "total",
                    "kind": "sum",
                    "value": 125000,
                    "refs": [
                        {"record_id": src1["id"], "revision": 1, "path": "/orcamento"},
                        {"record_id": src1["id"], "revision": 1, "path": "/extra"},
                    ],
                }
            ],
            operation_key="idem-receipt-01",
        )
        rec2 = reloaded.verify_claims(
            [
                {
                    "id": "total",
                    "kind": "sum",
                    "value": 125000,
                    "refs": [
                        {"record_id": src1["id"], "revision": 1, "path": "/orcamento"},
                        {"record_id": src1["id"], "revision": 1, "path": "/extra"},
                    ],
                }
            ],
            operation_key="idem-receipt-01",
        )
        self.assertEqual(rec1["receipt_id"], rec2["receipt_id"])

        # Replay idempotente também em rectify_source
        rect1 = self.client.rectify_source(
            src1["id"],
            1,
            json.dumps({"orcamento": 110000, "extra": 25000}),
            "Ajuste de escopo",
            operation_key="idem-rect-01",
        )
        rect2 = reloaded.rectify_source(
            src1["id"],
            1,
            json.dumps({"orcamento": 110000, "extra": 25000}),
            "Ajuste de escopo",
            operation_key="idem-rect-01",
        )
        self.assertEqual(rect1["revision"], 2)
        self.assertEqual(rect2["revision"], 2)
        self.assertIn(syn1["id"], rect1["newly_suspended_ids"])
        self.assertIn(syn1["id"], rect2["newly_suspended_ids"])

    def test_openai_and_gemini_tool_schemas_and_dispatch_tool_call(self) -> None:
        openai_tools = self.client.as_openai_tools(strict=True)
        gemini_decls = self.client.as_gemini_declarations()
        self.assertEqual(len(openai_tools), len(gemini_decls))
        self.assertGreaterEqual(len(openai_tools), 10)

        openai_names = {t["function"]["name"] for t in openai_tools}
        gemini_names = {d["name"] for d in gemini_decls}
        self.assertEqual(openai_names, gemini_names)
        # Revisão humana nunca deve estar exposta ao catálogo autônomo do modelo
        self.assertNotIn("register_human_review", openai_names)

        for tool in openai_tools:
            self.assertEqual(tool["type"], "function")
            fn = tool["function"]
            self.assertTrue(fn["strict"])
            self.assertEqual(fn["parameters"]["type"], "object")
            self.assertFalse(fn["parameters"]["additionalProperties"])

        def _assert_no_additional_props(node: object) -> None:
            if isinstance(node, dict):
                self.assertNotIn("additionalProperties", node)
                for val in node.values():
                    _assert_no_additional_props(val)
            elif isinstance(node, list):
                for item in node:
                    _assert_no_additional_props(item)

        for decl in gemini_decls:
            self.assertEqual(set(decl.keys()), {"name", "description", "parameters"})
            self.assertEqual(decl["parameters"]["type"], "OBJECT")
            _assert_no_additional_props(decl["parameters"])

        # Mutação pelo consumidor não pode afetar cópias subsequentes
        openai_tools[0]["function"]["name"] = "corrupted"
        self.assertNotEqual(self.client.as_openai_tools()[0]["function"]["name"], "corrupted")

        # Despacho com string JSON (estilo OpenAI) e retorno como string JSON (as_json=True)
        raw_json = self.client.dispatch_tool_call(
            "remember_source",
            json.dumps({"title": "Fonte via Tool", "content": "Registro auditável via tool call."}),
            call_id="tc_1",
            as_json=True,
        )
        self.assertIsInstance(raw_json, str)
        parsed = json.loads(str(raw_json))
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["call_id"], "tc_1")
        src_id = parsed["result"]["id"]

        # Despacho com dict (estilo Gemini / LangGraph)
        read_resp = self.client.dispatch_tool_call("read_record", {"record_id": src_id})
        assert isinstance(read_resp, dict)
        self.assertTrue(read_resp["ok"])
        self.assertEqual(read_resp["result"]["validity"], "current_within_scope")

        # Códigos de erro determinísticos
        unknown_resp = self.client.dispatch_tool_call("register_human_review", {})
        assert isinstance(unknown_resp, dict)
        self.assertFalse(unknown_resp["ok"])
        self.assertEqual(unknown_resp["error_code"], ErrorCode.UNKNOWN_TOOL)

        bad_json_resp = self.client.dispatch_tool_call("recall_context", "{invalid-json")
        assert isinstance(bad_json_resp, dict)
        self.assertEqual(bad_json_resp["error_code"], ErrorCode.MALFORMED_ARGUMENTS)

        nan_resp = self.client.dispatch_tool_call("recall_context", '{"query": NaN}')
        assert isinstance(nan_resp, dict)
        self.assertEqual(nan_resp["error_code"], ErrorCode.MALFORMED_ARGUMENTS)

        extra_arg_resp = self.client.dispatch_tool_call(
            "recall_context", {"query": "teste", "unexpected_param": 123}
        )
        assert isinstance(extra_arg_resp, dict)
        self.assertEqual(extra_arg_resp["error_code"], ErrorCode.MALFORMED_ARGUMENTS)

        bool_as_int_resp = self.client.dispatch_tool_call(
            "recall_context", {"query": "teste", "limit": True}
        )
        assert isinstance(bool_as_int_resp, dict)
        self.assertEqual(bool_as_int_resp["error_code"], ErrorCode.MALFORMED_ARGUMENTS)

        # Violação clínica/contratual -> VALIDATION_ERROR
        clinical_resp = self.client.dispatch_tool_call(
            "register_entity",
            {
                "title": "Pessoa Teste",
                "entity_kind": "person",
                "origin_refs": [{"record_id": src_id, "revision": 1}],
                "fields": {"diagnosis": "TDAH"},
            },
        )
        assert isinstance(clinical_resp, dict)
        self.assertEqual(clinical_resp["error_code"], ErrorCode.VALIDATION_ERROR)

        # Conflito de revisão -> REVISION_CONFLICT
        conflict_resp = self.client.dispatch_tool_call(
            "rectify_source",
            {
                "record_id": src_id,
                "expected_revision": 99,
                "new_content": "Texto novo",
                "reason": "Revisão errada",
            },
        )
        assert isinstance(conflict_resp, dict)
        self.assertEqual(conflict_resp["error_code"], ErrorCode.REVISION_CONFLICT)

        # Bloqueio por implantacao.lock e por CEREBRO_PESSOAL_ACESSO -> ACCESS_DENIED
        lock_file = self.client.system_root / "estado" / "implantacao.lock"
        lock_file.write_text("maintenance", encoding="utf-8")
        try:
            denied_lock = self.client.dispatch_tool_call("blast_radius", {})
            assert isinstance(denied_lock, dict)
            self.assertEqual(denied_lock["error_code"], ErrorCode.ACCESS_DENIED)
            with self.assertRaises(EpistemicAccessDeniedError):
                self.client.audit()
        finally:
            lock_file.unlink()

        gated_client = EpistemicMemoryClient.from_workspace(
            self.ws_dir, enable_embeddings=False, require_access_env=True
        )
        with patch.dict(os.environ, {"CEREBRO_PESSOAL_ACESSO": "bloqueado"}):
            denied_env = gated_client.dispatch_tool_call("blast_radius", {})
            assert isinstance(denied_env, dict)
            self.assertEqual(denied_env["error_code"], ErrorCode.ACCESS_DENIED)

    def test_attribution_firewall_rejections_and_resolutions(self) -> None:
        ata = self.client.remember_source(
            "Ata com Múltiplos Interlocutores",
            (
                "Eu trabalho com arquitetura distribuída. "
                "Beatriz Nogueira aprovou janela de 30 dias. "
                "Diego Farias estipulou multa contratual de 150000 reais."
            ),
            source_kind="conversation",
        )
        owner = self.client.register_entity(
            "Proprietário Fictício", "person", [ata["rev_ref"]], fields={"aliases": ["Proprietário"]}
        )
        beatriz = self.client.register_entity(
            "Beatriz Nogueira", "person", [ata["rev_ref"]], fields={"aliases": ["Beatriz"]}
        )
        diego = self.client.register_entity(
            "Diego Farias", "person", [ata["rev_ref"]], fields={"aliases": ["Diego"]}
        )
        self.client.set_owner_person(owner["id"])

        # 1. Citação de Diego atribuída a Beatriz -> AttributionError
        with self.assertRaises(AttributionError):
            self.client.assert_fact(
                "Multa trocada",
                subject_ref=beatriz["rev_ref"],
                predicate="reports_value",
                nature="third_party_report",
                source_refs=[ata["rev_ref"]],
                value={"type": "number", "content": 150000},
                evidence_quote="Diego Farias estipulou multa contratual de 150000 reais.",
            )

        # 2. Número trocado na citação de Beatriz -> AttributionError
        with self.assertRaises(AttributionError):
            self.client.assert_fact(
                "Número adulterado",
                subject_ref=beatriz["rev_ref"],
                predicate="reports_preference",
                nature="third_party_report",
                source_refs=[ata["rev_ref"]],
                value={"type": "text", "content": "janela de 90 dias"},
                evidence_quote="Beatriz Nogueira aprovou janela de 30 dias.",
            )

        # 3. Ausência de evidence_quote em afirmação pessoal -> AttributionError
        with self.assertRaises(AttributionError):
            self.client.assert_fact(
                "Sem citação literal",
                subject_ref=beatriz["rev_ref"],
                predicate="reports_preference",
                nature="third_party_report",
                source_refs=[ata["rev_ref"]],
                value={"type": "text", "content": "janela de 30 dias"},
            )

        # 4. Primeira pessoa em conversa vinculada ao proprietário configurado -> aceita
        owner_fact = self.client.assert_fact(
            "Área de atuação do proprietário",
            subject_ref=owner["rev_ref"],
            predicate="reports_preference",
            nature="user_report",
            source_refs=[ata["rev_ref"]],
            value={"type": "text", "content": "arquitetura distribuída"},
            evidence_quote="Eu trabalho com arquitetura distribuída.",
        )
        self.assertEqual(owner_fact["status"], "confirmed")

        # 5. Primeira pessoa em documento externo NÃO pode ser atribuída ao proprietário
        ext_doc = self.client.remember_source(
            "Artigo Técnico Externo",
            "Eu recomendo migração imediata para microkernels.",
            source_kind="document",
        )
        with self.assertRaises(AttributionError):
            self.client.assert_fact(
                "Primeira pessoa externa indevida",
                subject_ref=owner["rev_ref"],
                predicate="reports_preference",
                nature="documented_observation",
                source_refs=[ext_doc["rev_ref"]],
                value={"type": "text", "content": "migração imediata para microkernels"},
                evidence_quote="Eu recomendo migração imediata para microkernels.",
            )

        # 6. Pronome ambíguo ("Ele") bloqueado sem esclarecimento, aceito com fonte separada
        src_pron = self.client.remember_source(
            "Relato com Pronome",
            "Ele revisou a cláusula de rescisão ontem.",
            source_kind="conversation",
        )
        with self.assertRaises(AttributionError) as ctx_amb:
            self.client.assert_fact(
                "Revisão sem resolução de pronome",
                subject_ref=diego["rev_ref"],
                predicate="reports_preference",
                nature="third_party_report",
                source_refs=[src_pron["rev_ref"]],
                value={"type": "text", "content": "revisou a cláusula de rescisão"},
                evidence_quote="Ele revisou a cláusula de rescisão ontem.",
            )
        self.assertTrue(ctx_amb.exception.ambiguous)

        src_clar = self.client.remember_source(
            "Esclarecimento do Usuário",
            "Diego Farias",
            source_kind="conversation",
        )
        resolved = self.client.assert_fact(
            "Revisão resolvida por fonte separada",
            subject_ref=diego["rev_ref"],
            predicate="reports_preference",
            nature="third_party_report",
            source_refs=[src_pron["rev_ref"], src_clar["rev_ref"]],
            value={"type": "text", "content": "revisou a cláusula de rescisão"},
            evidence_quote="Ele revisou a cláusula de rescisão ontem.",
            evidence_source_ref=src_pron["rev_ref"],
            attribution_resolution_ref=src_clar["rev_ref"],
        )
        self.assertEqual(resolved["attribution_status"], "resolved_by_separate_source")

        # 7. check_attribution em resposta narrativa
        bad_narrative = self.client.check_attribution(
            "Beatriz Nogueira estipulou multa contratual de 150000 reais.",
            [{**ata["rev_ref"], "quote": "Diego Farias estipulou multa contratual de 150000 reais."}],
        )
        self.assertEqual(bad_narrative["status"], "rejected")

    def test_hybrid_search_rrf_graph_and_onnx_e5(self) -> None:
        ws_hybrid = self.base / "ws_hybrid"
        hybrid_client = EpistemicMemoryClient.from_workspace(ws_hybrid, enable_embeddings=None)

        src = hybrid_client.remember_source(
            "Arquitetura de Inferência de Baixa Latência",
            "Aceleradores dedicados reduzem o tempo de resposta em filas críticas de agentes.",
            source_kind="document",
        )
        concept = hybrid_client.register_entity(
            "Orquestração Determinística",
            "concept",
            [src["rev_ref"]],
            fields={
                "content": "Controle transacional de memória compartilhada entre agentes",
                "idea_scope": "arquitetura_ia",
            },
        )

        # Se EMC_EMBEDDINGS_DIR apontar para o modelo E5 validado, valida o modo híbrido completo
        emb_dir = os.environ.get("EMC_EMBEDDINGS_DIR", "")
        if emb_dir and (Path(emb_dir) / "model.onnx").is_file():
            self.assertTrue(hybrid_client.embedder is not None)
            res1 = hybrid_client.recall_context("desempenho rápido de GPUs para agentes", limit=6, depth=1)
            self.assertEqual(res1["mode"], "hybrid_lexical_vector_graph")
            self.assertTrue(res1["embeddings_active"])
            self.assertFalse(res1["cache_reused"])
            found_ids = {item["id"] for item in res1["results"]}
            self.assertIn(src["id"], found_ids)
            # Expansão de grafo traz a entidade derivada ligada à fonte
            self.assertIn(concept["id"], found_ids)

            res2 = hybrid_client.recall_context("desempenho rápido de GPUs para agentes", limit=6, depth=1)
            self.assertTrue(res2["cache_reused"])

        # Fallback determinístico lexical + grafo quando enable_embeddings=False
        lex_res = self.client.remember_source(
            " Topologia de Rede Fibra ",
            "Enlace redundante 10G homologado para contingência.",
            source_kind="document",
        )
        lex_search = self.client.recall_context("contingência 10G", limit=5, depth=1, include_records=False)
        self.assertEqual(lex_search["mode"], "lexical_and_graph")
        self.assertFalse(lex_search["embeddings_active"])
        self.assertIn(lex_res["id"], {r["id"] for r in lex_search["results"]})
        self.assertNotIn("record", lex_search["results"][0])

    def test_claim_verification_field_sum_chain_and_supplementation(self) -> None:
        s1 = self.client.remember_source(
            "Planilha de Custos e Etapa 1",
            json.dumps(
                {
                    "fornecedor": "OrionInfra",
                    "licencas": 80000,
                    "suporte": 40000,
                    "flag_ativo": True,
                    "arestas": [["preparar_rede", "precedes", "subir_cluster"]],
                }
            ),
            source_kind="document",
        )
        s2 = self.client.remember_source(
            "Etapa 2 da Implantação",
            json.dumps({"arestas": [["subir_cluster", "precedes", "liberar_trafego"]]}),
            source_kind="document",
        )

        # Fornece apenas s1 em context_ids para testar suplementação seletiva automática de s2
        receipt = self.client.verify_claims(
            [
                {
                    "id": "fornecedor_nome",
                    "kind": "field",
                    "value": "OrionInfra",
                    "refs": [{"record_id": s1["id"], "revision": 1, "path": "/fornecedor"}],
                },
                {
                    "id": "custo_anual",
                    "kind": "sum",
                    "value": 120000,
                    "refs": [
                        {"record_id": s1["id"], "revision": 1, "path": "/licencas"},
                        {"record_id": s1["id"], "revision": 1, "path": "/suporte"},
                    ],
                },
                {
                    "id": "ordem_execucao",
                    "kind": "chain",
                    "value": ["preparar_rede", "precedes", "liberar_trafego"],
                    "refs": [
                        {"record_id": s1["id"], "revision": 1, "path": "/arestas/0"},
                        {"record_id": s2["id"], "revision": 1, "path": "/arestas/0"},
                    ],
                },
            ],
            context_ids=[s1["id"]],
            max_context=4,
        )
        self.assertEqual(receipt["status"], "verified")
        self.assertEqual(receipt["route"], "supplemented")
        self.assertEqual(receipt["assurance_format"], "lab-assurance-2")
        self.assertTrue(receipt["answer_verified"])
        self.assertEqual(self.client.read_receipt(receipt["receipt_id"])["status"], "verified")

        # Booleano contrabandado em sum (True == 1 em Python) deve ser rejeitado estritamente
        bad_bool_sum = self.client.verify_claims(
            [
                {
                    "id": "soma_invalida_bool",
                    "kind": "sum",
                    "value": 80001,
                    "refs": [
                        {"record_id": s1["id"], "revision": 1, "path": "/licencas"},
                        {"record_id": s1["id"], "revision": 1, "path": "/flag_ativo"},
                    ],
                }
            ]
        )
        self.assertEqual(bad_bool_sum["status"], "rejected")

        # Modalidade free_text verifica claims sem certificar narrativa livre
        free_res = self.client.verify_claims(
            [
                {
                    "id": "fornecedor_nome",
                    "kind": "field",
                    "value": "OrionInfra",
                    "refs": [{"record_id": s1["id"], "revision": 1, "path": "/fornecedor"}],
                }
            ],
            answer="O fornecedor analisado nesta etapa é OrionInfra.",
            answer_format="free_text",
        )
        self.assertEqual(free_res["status"], "claims_verified")
        self.assertFalse(free_res["answer_verified"])

    def test_cascade_suspended_stale_transitions_and_blast_radius(self) -> None:
        src_main = self.client.remember_source(
            "Contrato Principal #CT-10",
            json.dumps({"prazo_dias": 30, "multa_brl": 50000}),
            source_kind="document",
        )
        src_conv = self.client.remember_source(
            "Reunião de Conformidade",
            "Eduardo Silva confirmou que o prazo operacional mínimo é 30 dias.",
            source_kind="conversation",
        )
        src_unrelated = self.client.remember_source(
            "Nota Independente",
            "Registro isolado sobre documentação interna.",
            source_kind="document",
        )

        eduardo = self.client.register_entity("Eduardo Silva", "person", [src_conv["rev_ref"]])
        isolated_ent = self.client.register_entity(
            "Tópico Independente",
            "learning_topic",
            [src_unrelated["rev_ref"]],
            fields={"topic_description": "Documentação interna"},
        )
        proj = self.client.register_entity(
            "Programa de Conformidade CT-10",
            "project",
            [src_main["rev_ref"]],
            fields={"purpose": "Acompanhar obrigações do CT-10", "project_status": "active"},
        )

        assertion = self.client.assert_fact(
            "Prazo operacional confirmado por Eduardo Silva",
            subject_ref=eduardo["rev_ref"],
            predicate="reports_preference",
            nature="user_report",
            source_refs=[src_conv["rev_ref"]],
            value={"type": "text", "content": "prazo operacional mínimo de 30 dias"},
            evidence_quote="Eduardo Silva confirmou que o prazo operacional mínimo é 30 dias.",
        )
        reviewed = self.client.register_human_review(
            assertion["id"],
            1,
            "confirmed_by_user",
            src_conv["rev_ref"],
            "prazo operacional mínimo é 30 dias",
            "Confirmação literal registrada pelo operador",
        )
        self.assertEqual(reviewed["revision"], 2)

        syn = self.client.synthesize(
            "Parecer de Conformidade CT-10",
            content="Prazo contratual de 30 dias alinhado à operação.",
            scope="CT-10 Revisão 1",
            basis_refs=[src_main["rev_ref"], proj["rev_ref"], reviewed["rev_ref"]],
            limitations=["Sujeito a aditivos contratuais"],
        )

        receipt = self.client.verify_claims(
            [
                {
                    "id": "prazo_contratual",
                    "kind": "field",
                    "value": 30,
                    "refs": [{"record_id": src_main["id"], "revision": 1, "path": "/prazo_dias"}],
                }
            ]
        )
        self.assertEqual(receipt["status"], "verified")

        before = self.client.blast_radius(src_main["id"])
        self.assertEqual(set(before["active_ids"]), {proj["id"], syn["id"]})
        self.assertEqual(before["suspended_ids"], [])
        self.assertIn(receipt["receipt_id"], before["verified_receipt_ids"])

        # Retifica src_main (rev 1 -> rev 2): proj e syn devem suspender; eduardo, assertion e isolated_ent seguem ativos!
        mut = self.client.rectify_source(
            src_main["id"],
            1,
            json.dumps({"prazo_dias": 90, "multa_brl": 75000}),
            "1º Aditivo alterou prazo para 90 dias e multa para R$ 75.000.",
        )
        self.assertEqual(mut["revision"], 2)
        self.assertEqual(set(mut["newly_suspended_ids"]), {proj["id"], syn["id"]})
        self.assertIn(receipt["receipt_id"], mut["stale_receipt_ids"])
        self.assertTrue(any("90" in line for line in mut["diff"]))

        after = self.client.blast_radius(src_main["id"])
        self.assertEqual(after["active_ids"], [])
        self.assertEqual(set(after["suspended_ids"]), {proj["id"], syn["id"]})
        self.assertEqual(self.client.read_record(syn["id"])["validity"], "needs_revalidation")
        self.assertIsNone(self.client.read_record(syn["id"])["record"])
        self.assertEqual(self.client.read_receipt(receipt["receipt_id"])["status"], "stale")

        # Registros independentes permanecem íntegros e ativos
        self.assertEqual(self.client.read_record(isolated_ent["id"])["validity"], "current_within_scope")
        self.assertEqual(self.client.read_record(assertion["id"])["validity"], "current_within_scope")

        vault_overview = self.client.blast_radius()
        self.assertIn(isolated_ent["id"], vault_overview["active_ids"])
        self.assertIn(syn["id"], vault_overview["suspended_ids"])

    def test_cli_demo_end_to_end_subprocess(self) -> None:
        demo_ws = self.base / "cli_demo_ws"
        env = dict(os.environ, PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "apps" / "agent_memory_sdk" / "cli_demo.py"),
                "--workspace",
                str(demo_ws),
                "--cleanup",
            ],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
        report = json.loads(proc.stdout)
        self.assertEqual(report["status"], "ok")
        self.assertTrue(report["workspace_cleaned_up"])
        self.assertFalse(demo_ws.exists())
        self.assertEqual(
            report["handoff"]["verifier_agent"]["firewall_blocked_misattribution"]["error_code"],
            ErrorCode.ATTRIBUTION_FIREWALL_BLOCKED,
        )
        self.assertEqual(
            report["handoff"]["cascade_invalidation"]["receipt_status_after"],
            "stale",
        )
        self.assertEqual(
            report["handoff"]["cascade_invalidation"]["synthesis_validity_after"],
            "needs_revalidation",
        )


if __name__ == "__main__":
    unittest.main()
