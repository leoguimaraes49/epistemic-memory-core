"""Suíte de integração ponta a ponta do Epistemic HTTP Gateway & Live Lineage Graph Explorer."""
from __future__ import annotations

import concurrent.futures
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from nucleo import REAL_SYSTEM
from apps.http_gateway.server import (
    MAX_BODY_BYTES,
    EpistemicGatewayRuntime,
    create_gateway_server,
)


class HttpGatewayEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        temp_parent = REAL_SYSTEM / "testes_temporarios"
        temp_parent.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="gw-test-", dir=temp_parent)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

        self.runtime = EpistemicGatewayRuntime(
            self.base / "sistema",
            self.base / "cofre",
            enable_embeddings=True,
        )
        self.api_token = "gw-test-secret-token-2026"
        self.server = create_gateway_server(
            self.runtime,
            host="127.0.0.1",
            port=0,
            api_token=self.api_token,
        )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._shutdown_server)

    def _shutdown_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def _request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict | bytes | None = None,
        headers: dict[str, str] | None = None,
        auth: bool = True,
    ) -> tuple[int, dict[str, str], str]:
        req_headers: dict[str, str] = {}
        if auth:
            req_headers["Authorization"] = f"Bearer {self.api_token}"
        if isinstance(body, dict):
            raw_data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        else:
            raw_data = body
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=raw_data,
            headers=req_headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, dict(resp.headers), resp.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            try:
                err_body = err.read().decode("utf-8")
            except ConnectionResetError:
                err_body = ""
            return err.code, dict(err.headers), err_body

    def test_security_hardening_auth_host_payload_cap_and_csp(self) -> None:
        # 1. Bloqueio de bind fora de loopback
        with self.assertRaises(ValueError):
            create_gateway_server(self.runtime, host="0.0.0.0", port=0)

        # 2. HTTP 401 sem token Bearer, com esquema incorreto, token errado ou não-ASCII
        code_no_auth, hdr_401, raw_401 = self._request("/api/v1/health", auth=False)
        self.assertEqual(code_no_auth, 401)
        self.assertIn("Bearer", hdr_401.get("WWW-Authenticate", ""))
        self.assertEqual(json.loads(raw_401)["status"], "unauthorized")

        code_basic, _, _ = self._request(
            "/api/v1/health", auth=False, headers={"Authorization": "Basic dXNlcjpwYXNz"}
        )
        self.assertEqual(code_basic, 401)

        code_bad_tok, _, _ = self._request(
            "/api/v1/health", auth=False, headers={"Authorization": "Bearer token-invalido-xyz-çãõ"}
        )
        self.assertEqual(code_bad_tok, 401)

        # 3. HTTP 403 em cabeçalho Host malicioso (DNS Rebinding) e Cross-Site
        for bad_host in ("evil.attacker.example:8095", "0.0.0.0:8095", "127.0.0.1:99999"):
            code_host, _, raw_host = self._request("/api/v1/health", headers={"Host": bad_host})
            self.assertEqual(code_host, 403, msg=f"Host deveria falhar: {bad_host}")
            self.assertEqual(json.loads(raw_host)["error"], "forbidden_host")

        code_host_root, _, _ = self._request("/", auth=False, headers={"Host": "rebind.evil.test"})
        self.assertEqual(code_host_root, 403)

        code_xsite, _, _ = self._request(
            "/api/v1/sources",
            method="POST",
            body={"title": "X", "content": "Y"},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(code_xsite, 403)

        code_origin, _, _ = self._request(
            "/api/v1/sources",
            method="POST",
            body={"title": "X", "content": "Y"},
            headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(code_origin, 403)

        # 4. HTTP 413 com corpo > 64 KB (Content-Length explícito + JSON limpo)
        oversized = b'{"title":"Overflow","content":"' + (b"A" * (MAX_BODY_BYTES + 2048)) + b'"}'
        code_413, hdr_413, raw_413 = self._request(
            "/api/v1/sources",
            method="POST",
            body=oversized,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(code_413, 413)
        self.assertTrue(int(hdr_413.get("Content-Length", "0")) > 0)
        parsed_413 = json.loads(raw_413)
        self.assertEqual(parsed_413["error"], "payload_too_large")

        # 5. GET / — HTML interativo SVG, CSP estrita e isolamento do token mestre
        code_ui, hdr_ui, html = self._request("/", auth=False)
        self.assertEqual(code_ui, 200)
        csp = hdr_ui.get("Content-Security-Policy", "")
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("default-src 'self'", csp)
        self.assertEqual(hdr_ui.get("X-Frame-Options"), "DENY")
        self.assertEqual(hdr_ui.get("X-Content-Type-Options"), "nosniff")
        self.assertIn('id="lineage-svg"', html)
        self.assertIn("escapeHtml", html)
        self.assertNotIn("__GW_UI_TOKEN_JSON__", html)
        self.assertIn(self.server.ui_token, html)  # type: ignore[attr-defined]
        self.assertNotIn(self.api_token, html)

        # Token de bootstrap da UI funciona em same-origin
        code_ui_api, _, _ = self._request(
            "/api/v1/health",
            auth=False,
            headers={
                "Authorization": f"Bearer {self.server.ui_token}",  # type: ignore[attr-defined]
                "Origin": f"http://127.0.0.1:{self.port}",
            },
        )
        self.assertEqual(code_ui_api, 200)

        # 6. Bloqueio de manutenção quando implantacao.lock está presente
        lock_file = self.base / "sistema" / "estado" / "implantacao.lock"
        lock_file.write_text("manutencao", encoding="utf-8")
        try:
            code_locked, _, raw_locked = self._request("/api/v1/health")
            self.assertEqual(code_locked, 403)
            self.assertEqual(json.loads(raw_locked)["error"], "access_locked")
        finally:
            lock_file.unlink(missing_ok=True)

    def test_full_epistemic_flow_firewalls_receipts_and_blast_radius(self) -> None:
        # Saúde inicial
        c_h0, _, raw_h0 = self._request("/api/v1/health")
        self.assertEqual(c_h0, 200)
        h0 = json.loads(raw_h0)
        self.assertTrue(h0["healthy"])
        self.assertEqual(h0["counts"]["total_records"], 0)

        # 1. Fontes primárias (30_Fontes): Cotação JSON + Ata Conversacional (com título XSS-adversarial p/ teste)
        quote_v1 = {
            "fornecedor": "HyperionCloud",
            "capex_brl": 50000,
            "opex_brl": 170000,
            "sla_bps": 9995,
            "dependencias": {
                "d1": ["cluster_inferencia", "requires", "fibra_redundante"],
                "d2": ["fibra_redundante", "requires", "homologacao_noc"],
            },
        }
        c_s1, _, raw_s1 = self._request(
            "/api/v1/sources",
            method="POST",
            body={
                "operation_key": "gw-src-cotacao-1",
                "title": "Cotação HyperionCloud #HC-01 <tag>",
                "source_kind": "document",
                "content": json.dumps(quote_v1, ensure_ascii=False, indent=2),
            },
        )
        self.assertEqual(c_s1, 200)
        src_quote = json.loads(raw_s1)
        ref_quote = src_quote["rev_ref"]
        self.assertTrue(re.fullmatch(r"[a-f0-9]{64}", src_quote["record"]["sha256"]))

        # Idempotência estrita em fontes e conflito em reuso divergente de chave
        c_s1_dup, _, raw_s1_dup = self._request(
            "/api/v1/sources",
            method="POST",
            body={
                "operation_key": "gw-src-cotacao-1",
                "title": "Cotação HyperionCloud #HC-01 <tag>",
                "source_kind": "document",
                "content": json.dumps(quote_v1, ensure_ascii=False, indent=2),
            },
        )
        self.assertEqual(c_s1_dup, 200)
        self.assertEqual(json.loads(raw_s1_dup)["record"]["id"], ref_quote["record_id"])

        c_s1_conflict, _, _ = self._request(
            "/api/v1/sources",
            method="POST",
            body={
                "operation_key": "gw-src-cotacao-1",
                "title": "Outro Título Divergente",
                "source_kind": "document",
                "content": "{}",
            },
        )
        self.assertEqual(c_s1_conflict, 409)

        c_s2, _, raw_s2 = self._request(
            "/api/v1/sources",
            method="POST",
            body={
                "operation_key": "gw-src-ata-1",
                "title": "Ata Gate de Infraestrutura",
                "source_kind": "conversation",
                "content": (
                    "Lívia Rocha definiu que a latência p99 máxima do gateway é 40ms. "
                    "Bruno Tavares informou que o teto anual aprovado é 240000 reais."
                ),
            },
        )
        self.assertEqual(c_s2, 200)
        ref_ata = json.loads(raw_s2)["rev_ref"]

        # 2. Entidades (10_Entidades): Pessoas e Projeto
        c_e1, _, raw_e1 = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "gw-ent-livia",
                "record_type": "entity",
                "title": "Lívia Rocha",
                "payload": {
                    "entity_kind": "person",
                    "display_name": "Lívia Rocha",
                    "aliases": ["Lívia"],
                    "identity_status": "identified",
                    "origin_refs": [ref_ata],
                },
            },
        )
        self.assertEqual(c_e1, 200)
        ref_livia = json.loads(raw_e1)["rev_ref"]

        c_e2, _, raw_e2 = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "gw-ent-bruno",
                "record_type": "entity",
                "title": "Bruno Tavares",
                "payload": {
                    "entity_kind": "person",
                    "display_name": "Bruno Tavares",
                    "aliases": ["Bruno"],
                    "identity_status": "identified",
                    "origin_refs": [ref_ata],
                },
            },
        )
        self.assertEqual(c_e2, 200)
        ref_bruno = json.loads(raw_e2)["rev_ref"]

        # 3. Firewall de Atribuição (atribuicao.py): tentar atribuir fala de Bruno a Lívia -> HTTP 422
        c_fw, _, raw_fw = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "gw-assert-falsa-atribuicao",
                "record_type": "assertion",
                "title": "Tentativa inválida de atribuir orçamento de Bruno a Lívia",
                "payload": {
                    "subject_ref": ref_livia,
                    "predicate": "reports_value",
                    "nature": "third_party_report",
                    "asserted_by": "teste_adversarial",
                    "source_refs": [ref_ata],
                    "value": {"type": "number", "content": 240000},
                    "attribution_evidence": {
                        "source_ref": ref_ata,
                        "quote": "Bruno Tavares informou que o teto anual aprovado é 240000 reais.",
                    },
                },
            },
        )
        self.assertEqual(c_fw, 422)
        fw_err = json.loads(raw_fw)
        self.assertEqual(fw_err["error"], "attribution_firewall_blocked")
        self.assertEqual(fw_err["error_type"], "AttributionError")

        # Bloqueio de diagnóstico clínico por inferência (conhecimento.py / esquemas.py)
        c_diag, _, _ = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "gw-assert-diag-invalido",
                "record_type": "assertion",
                "title": "Diagnóstico inferido proibido",
                "payload": {
                    "subject_ref": ref_livia,
                    "predicate": "reports_diagnosis",
                    "nature": "inference",
                    "asserted_by": "modelo_externo",
                    "basis_refs": [ref_ata],
                    "value": {"type": "text", "content": "hipótese clínica proibida"},
                },
            },
        )
        self.assertEqual(c_diag, 422)

        # 4. Afirmação válida (20_Afirmacoes) + replay idempotente
        assert_body = {
            "operation_key": "gw-assert-bruno-orcamento",
            "record_type": "assertion",
            "title": "Teto anual relatado por Bruno Tavares",
            "payload": {
                "subject_ref": ref_bruno,
                "predicate": "reports_value",
                "nature": "third_party_report",
                "asserted_by": "microservice_finops",
                "source_refs": [ref_ata],
                "value": {"type": "number", "content": 240000, "unit": "BRL"},
                "attribution_evidence": {
                    "source_ref": ref_ata,
                    "quote": "Bruno Tavares informou que o teto anual aprovado é 240000 reais.",
                },
            },
        }
        c_a1, _, raw_a1 = self._request("/api/v1/knowledge", method="POST", body=assert_body)
        self.assertEqual(c_a1, 200)
        ref_assert_bruno = json.loads(raw_a1)["rev_ref"]

        c_a1_replay, _, raw_a1_replay = self._request("/api/v1/knowledge", method="POST", body=assert_body)
        self.assertEqual(c_a1_replay, 200)
        self.assertEqual(json.loads(raw_a1_replay)["rev_ref"], ref_assert_bruno)

        # 5. Avaliação estruturada descritiva (40_Avaliacoes) + Receita superada (superseded)
        c_inst, _, raw_inst = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "gw-inst-prontidao",
                "record_type": "instrument",
                "title": "Checklist Técnico de Prontidão Operacional",
                "payload": {
                    "instrument_name": "CTPO-1",
                    "instrument_version": "1.0",
                    "purpose": "Verificação técnica de prontidão de engenharia (não clínico)",
                    "constructs": ["prontidao_rede"],
                    "language": "pt-BR",
                    "original_source_refs": [ref_quote],
                    "target_population": "equipes_sre",
                    "age_scope": "adult",
                    "items_source_ref": ref_quote,
                    "instructions_source_ref": ref_quote,
                    "scoring_rule_ref": ref_quote,
                    "missing_response_rule": "require_all_items",
                    "use_conditions": "Checklist estritamente técnico",
                    "administration_modes": ["self_report"],
                    "verification_status": "verified_for_intended_scope",
                    "verification_refs": [ref_quote],
                    "verification_scope": "Auditoria interna de arquitetura",
                    "scoring_spec": {
                        "method": "weighted_sum",
                        "items": [{"id": "chk_1", "dimension": "prontidao", "min": 1, "max": 5, "weight": 2}],
                    },
                },
            },
        )
        self.assertEqual(c_inst, 200)
        ref_inst = json.loads(raw_inst)["rev_ref"]

        c_app, _, raw_app = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "gw-app-prontidao",
                "record_type": "assessment",
                "title": "Checklist SRE — Lívia",
                "payload": {
                    "instrument_ref": ref_inst,
                    "subject_ref": ref_livia,
                    "purpose": "Validação pré-migração",
                    "application_status": "in_progress",
                    "conditions": {"mode": "self_report", "language": "pt-BR"},
                    "scoring_eligibility": "calculable",
                    "eligibility_reason": "Escopo técnico verificado",
                },
            },
        )
        self.assertEqual(c_app, 200)
        ref_app = json.loads(raw_app)["rev_ref"]

        c_resp, _, _ = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "gw-resp-chk1",
                "record_type": "assessment_response",
                "title": "Resposta Item chk_1",
                "payload": {
                    "assessment_ref": ref_app,
                    "item_ref": {"record_id": ref_inst["record_id"], "revision": 1, "fragment": "chk_1"},
                    "value": 5,
                    "source_refs": [ref_ata],
                },
            },
        )
        self.assertEqual(c_resp, 200)

        c_score, _, raw_score = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={"operation_key": "gw-finish-app", "action": "finish_assessment", "assessment_id": ref_app["record_id"]},
        )
        self.assertEqual(c_score, 200)
        score_id = json.loads(raw_score)["record"]["id"]

        c_sup_recipe, _, raw_sup = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "gw-recipe-superseded",
                "record_type": "search_recipe",
                "title": "Receita Antiga de Cotação v0",
                "payload": {
                    "purpose": "Consulta legada substituída",
                    "steps": ["buscar termo HyperionCloud"],
                    "basis_refs": [ref_ata],
                    "acceptance_criteria": ["retornar fonte primária"],
                    "stop_conditions": ["limite 5"],
                    "adoption_status": "superseded",
                },
            },
        )
        self.assertEqual(c_sup_recipe, 200)
        self.assertEqual(json.loads(raw_sup)["record"]["status"], "superseded")

        # 6. Síntese derivada em 2º salto (50_Sinteses)
        c_syn, _, raw_syn = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "gw-syn-parecer-v1",
                "record_type": "synthesis",
                "title": "Parecer Executivo HyperionCloud (Rev 1)",
                "payload": {
                    "synthesis_kind": "knowledge_summary",
                    "content": "Proposta HyperionCloud soma R$ 220.000 no 1º ano, abaixo do teto de R$ 240.000 informado por Bruno Tavares.",
                    "scope": "Cotação #HC-01 Rev 1 + Ata Gate Rev 1",
                    "basis_refs": [ref_quote, ref_assert_bruno],
                    "limitations": ["Qualquer retificação da cotação suspende este parecer."],
                    "coverage_status": "supported_within_scope",
                    "as_of": "2026-11-17",
                },
            },
        )
        self.assertEqual(c_syn, 200)
        synthesis_id = json.loads(raw_syn)["record"]["id"]

        # 7. Comprovante determinístico lab-assurance-2 (field + sum + chain)
        c_ver, _, raw_ver = self._request(
            "/api/v1/verify-claims",
            method="POST",
            body={
                "operation_key": "gw-recibo-hc-v1",
                "claims": [
                    {
                        "id": "sla_contratado_bps",
                        "kind": "field",
                        "value": 9995,
                        "refs": [{"record_id": ref_quote["record_id"], "revision": 1, "path": "/sla_bps"}],
                    },
                    {
                        "id": "custo_ano1_brl",
                        "kind": "sum",
                        "value": 220000,
                        "refs": [
                            {"record_id": ref_quote["record_id"], "revision": 1, "path": "/capex_brl"},
                            {"record_id": ref_quote["record_id"], "revision": 1, "path": "/opex_brl"},
                        ],
                    },
                    {
                        "id": "cadeia_noc",
                        "kind": "chain",
                        "value": ["cluster_inferencia", "requires", "homologacao_noc"],
                        "refs": [
                            {"record_id": ref_quote["record_id"], "revision": 1, "path": "/dependencias/d1"},
                            {"record_id": ref_quote["record_id"], "revision": 1, "path": "/dependencias/d2"},
                        ],
                    },
                ],
            },
        )
        self.assertEqual(c_ver, 200)
        receipt = json.loads(raw_ver)
        self.assertEqual(receipt["format"], "lab-assurance-2")
        self.assertEqual(receipt["status"], "verified")
        self.assertTrue(receipt["claims_verified"])
        self.assertTrue(receipt["answer_verified"])
        receipt_id = receipt["receipt_id"]

        # 8. Busca híbrida antes da retificação (síntese ativa presente)
        c_srch1, _, raw_srch1 = self._request(
            "/api/v1/search",
            method="POST",
            body={"query": "HyperionCloud parecer orçamento", "limit": 12, "depth": 1},
        )
        self.assertEqual(c_srch1, 200)
        srch1 = json.loads(raw_srch1)
        self.assertIn(srch1["mode"], ("hybrid_lexical_vector_graph", "lexical_and_graph"))
        if os.environ.get("EMC_EMBEDDINGS_DIR") and (Path(os.environ["EMC_EMBEDDINGS_DIR"]) / "model.onnx").is_file():
            self.assertEqual(srch1["mode"], "hybrid_lexical_vector_graph")
            self.assertTrue(srch1["embeddings_active"])
        self.assertEqual(srch1["excluded_stale"], 0)
        self.assertIn(synthesis_id, {r["id"] for r in srch1["results"]})

        # 9. Retificar fonte primária (v1 -> v2) e verificar cascata de invalidação (blast radius)
        quote_v2 = dict(quote_v1, opex_brl=215000, sla_bps=9950)
        c_rect, _, raw_rect = self._request(
            "/api/v1/sources/rectify",
            method="POST",
            body={
                "operation_key": "gw-rect-cotacao-v2",
                "record_id": ref_quote["record_id"],
                "expected_revision": 1,
                "reason": "Aditivo tarifário reajustou OpEx anual para R$ 215.000 e SLA para 99,50%.",
                "content": json.dumps(quote_v2, ensure_ascii=False, indent=2),
            },
        )
        self.assertEqual(c_rect, 200)
        rect = json.loads(raw_rect)
        self.assertEqual(rect["update"]["revision"], 2)
        self.assertIn(synthesis_id, rect["newly_suspended_ids"])
        self.assertIn(score_id, rect["newly_suspended_ids"])
        self.assertIn(receipt_id, rect["stale_receipt_ids"])
        self.assertTrue(any("215000" in line for line in rect["diff"]))

        # 10. Verificar /api/v1/graph (30_Fontes, 10_Entidades, 20_Afirmacoes, 50_Sinteses, 40_Avaliacoes + active/suspended/superseded)
        c_graph, _, raw_graph = self._request("/api/v1/graph?include_superseded=true")
        self.assertEqual(c_graph, 200)
        graph = json.loads(raw_graph)
        for cls_name in ("30_Fontes", "10_Entidades", "20_Afirmacoes", "50_Sinteses", "40_Avaliacoes"):
            self.assertGreaterEqual(graph["by_episteme_class"][cls_name], 1, msg=f"Classe vazia: {cls_name}")

        node_statuses = {n["status"] for n in graph["nodes"]}
        self.assertEqual(node_statuses, {"active", "suspended", "superseded"})
        self.assertTrue(any(e["outdated"] and e["to"] == ref_quote["record_id"] for e in graph["edges"]))
        self.assertGreaterEqual(len(graph["superseded_revisions"]), 1)

        # 11. Verificar /api/v1/lineage/<source_id> e /api/v1/lineage/<synthesis_id>
        c_lin_src, _, raw_lin_src = self._request(f"/api/v1/lineage/{ref_quote['record_id']}")
        self.assertEqual(c_lin_src, 200)
        lin_src = json.loads(raw_lin_src)
        self.assertEqual(lin_src["record"]["status"], "active")
        self.assertEqual(lin_src["record"]["revision"], 2)
        self.assertEqual(lin_src["impact"]["impact_status"], "suspended_cascade")
        self.assertIn(synthesis_id, lin_src["impact"]["suspended_ids"])
        self.assertIn(score_id, lin_src["impact"]["suspended_ids"])
        self.assertIn(receipt_id, lin_src["impact"]["stale_receipt_ids"])
        self.assertTrue(lin_src["record"]["revision_diff"])

        c_lin_syn, _, raw_lin_syn = self._request(f"/api/v1/lineage/{synthesis_id}")
        self.assertEqual(c_lin_syn, 200)
        lin_syn = json.loads(raw_lin_syn)
        self.assertEqual(lin_syn["record"]["status"], "suspended")
        up_src_ids = {s["record_id"]: s for s in lin_syn["upstream"]["primary_sources"]}
        self.assertIn(ref_quote["record_id"], up_src_ids)
        self.assertIn(ref_ata["record_id"], up_src_ids)
        self.assertTrue(up_src_ids[ref_quote["record_id"]]["outdated"])
        self.assertFalse(up_src_ids[ref_ata["record_id"]]["outdated"])

        # Registro inexistente em lineage -> HTTP 404
        c_lin_404, _, _ = self._request("/api/v1/lineage/00000000-0000-0000-0000-000000000000")
        self.assertEqual(c_lin_404, 404)

        # 12. Busca híbrida pós-retificação exclui derivados suspensos
        c_srch2, _, raw_srch2 = self._request(
            "/api/v1/search",
            method="POST",
            body={"query": "HyperionCloud parecer orçamento", "limit": 12, "depth": 1},
        )
        self.assertEqual(c_srch2, 200)
        srch2 = json.loads(raw_srch2)
        self.assertGreaterEqual(srch2["excluded_stale"], 2)
        returned_after = {r["id"] for r in srch2["results"]}
        self.assertNotIn(synthesis_id, returned_after)
        self.assertNotIn(score_id, returned_after)
        # Afirmação apoiada apenas na Ata intocada continua ativa!
        self.assertIn(ref_assert_bruno["record_id"], returned_after)

    def test_concurrent_requests_and_cli_demo(self) -> None:
        def worker(idx: int) -> int:
            c_src, _, _ = self._request(
                "/api/v1/sources",
                method="POST",
                body={
                    "operation_key": f"conc-src-{idx}",
                    "title": f"Fonte Concorrente {idx}",
                    "source_kind": "document",
                    "content": f"Indicador operacional {idx * 10} registrado por serviço externo.",
                },
            )
            c_graph, _, _ = self._request("/api/v1/graph")
            return 200 if (c_src == 200 and c_graph == 200) else 500

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(worker, range(6)))
        self.assertEqual(statuses, [200] * 6)

        cli_ws = self.base / "cli_isolated_ws"
        cli_clean_ws = self.base / "cli_cleanup_ws"
        env = dict(os.environ, PYTHONUTF8="1")
        for cli_args in (
            ["--workspace", str(cli_ws), "--no-embeddings", "demo"],
            ["--workspace", str(cli_ws), "--no-embeddings", "health"],
            ["--workspace", str(cli_ws), "--no-embeddings", "graph"],
            ["--workspace", str(cli_clean_ws), "--no-embeddings", "--cleanup", "demo"],
        ):
            proc = subprocess.run(
                [sys.executable, str(ROOT / "apps" / "http_gateway" / "cli.py"), *cli_args],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                timeout=45,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            parsed = json.loads(proc.stdout)
            self.assertEqual(parsed["status"], "ok")
        self.assertFalse(cli_clean_ws.exists())

    def test_attribution_firewall_unquoted_and_single_person_external_doc(self) -> None:
        # 1. Cofre com uma única pessoa (proprietária configurada)
        c_conv, _, raw_conv = self._request(
            "/api/v1/sources",
            method="POST",
            body={
                "operation_key": "attr1-src-conv",
                "title": "Relato Conversacional da Proprietária",
                "source_kind": "conversation",
                "content": "Eu aprovo janela controlada de manutenção aos domingos.",
            },
        )
        self.assertEqual(c_conv, 200)
        ref_conv = json.loads(raw_conv)["rev_ref"]

        c_doc, _, raw_doc = self._request(
            "/api/v1/sources",
            method="POST",
            body={
                "operation_key": "attr1-src-doc",
                "title": "Artigo Técnico Externo em Primeira Pessoa",
                "source_kind": "document",
                "content": "Eu aprovo operação sem redundância em ambientes experimentais.",
            },
        )
        self.assertEqual(c_doc, 200)
        ref_doc = json.loads(raw_doc)["rev_ref"]

        c_owner, _, raw_owner = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "attr1-ent-owner",
                "record_type": "entity",
                "title": "Helena Vasconcelos",
                "payload": {
                    "entity_kind": "person",
                    "display_name": "Helena Vasconcelos",
                    "aliases": ["Helena"],
                    "identity_status": "identified",
                    "origin_refs": [ref_conv],
                },
            },
        )
        self.assertEqual(c_owner, 200)
        ref_owner = json.loads(raw_owner)["rev_ref"]

        cfg_file = self.base / "sistema" / "execucao.json"
        cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
        cfg["owner_person_id"] = ref_owner["record_id"]
        cfg_file.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")

        # (a) Afirmação pessoal sem attribution_evidence -> bloqueada com HTTP 422
        for nature in ("user_report", "third_party_report", "documented_observation"):
            c_unq, _, raw_unq = self._request(
                "/api/v1/knowledge",
                method="POST",
                body={
                    "operation_key": f"attr1-unquoted-{nature}",
                    "record_type": "assertion",
                    "title": f"Relato sem citação ({nature})",
                    "payload": {
                        "subject_ref": ref_owner,
                        "predicate": "reports_preference",
                        "nature": nature,
                        "asserted_by": "cliente_externo",
                        "source_refs": [ref_conv],
                        "value": {"type": "text", "content": "preferência arbitrária sem prova literal"},
                    },
                },
            )
            self.assertEqual(c_unq, 422, msg=f"Deveria bloquear {nature} sem attribution_evidence")
            err_unq = json.loads(raw_unq)
            self.assertEqual(err_unq["error"], "attribution_firewall_blocked")
            self.assertEqual(err_unq["error_type"], "AttributionError")

        # (b) Cofre de 1 pessoa + "Eu ..." em documento externo (source_kind="document") -> bloqueado com HTTP 422
        c_ext_eu, _, raw_ext_eu = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "attr1-doc-primeira-pessoa",
                "record_type": "assertion",
                "title": "Tentativa inválida de atribuir 'Eu' de documento externo à proprietária",
                "payload": {
                    "subject_ref": ref_owner,
                    "predicate": "reports_preference",
                    "nature": "user_report",
                    "asserted_by": "cliente_externo",
                    "source_refs": [ref_doc],
                    "value": {"type": "text", "content": "operação sem redundância"},
                    "attribution_evidence": {
                        "source_ref": ref_doc,
                        "quote": "Eu aprovo operação sem redundância em ambientes experimentais.",
                    },
                },
            },
        )
        self.assertEqual(c_ext_eu, 422)
        err_ext = json.loads(raw_ext_eu)
        self.assertEqual(err_ext["error"], "attribution_firewall_blocked")
        self.assertEqual(err_ext["error_type"], "AttributionError")

        # Controle positivo: "Eu ..." em fonte conversacional da proprietária configurada -> HTTP 200
        c_ok_conv, _, _ = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "attr1-conv-primeira-pessoa-valida",
                "record_type": "assertion",
                "title": "Preferência de janela relatada pela proprietária",
                "payload": {
                    "subject_ref": ref_owner,
                    "predicate": "reports_preference",
                    "nature": "user_report",
                    "asserted_by": "cliente_externo",
                    "source_refs": [ref_conv],
                    "value": {"type": "text", "content": "manutenção aos domingos"},
                    "attribution_evidence": {
                        "source_ref": ref_conv,
                        "quote": "Eu aprovo janela controlada de manutenção aos domingos.",
                    },
                },
            },
        )
        self.assertEqual(c_ok_conv, 200)

    def test_historical_operation_receipts_on_replay_and_restart(self) -> None:
        """Finding #1: lote A -> lote B -> lote C + replay antes e após reiniciar o gateway."""
        # 1. Criar revisão 1 ("lote A", chave k1)
        body_k1 = {
            "operation_key": "k1",
            "title": "Controle de Estoque Auditado",
            "source_kind": "document",
            "content": "lote A",
        }
        c1, _, raw1 = self._request("/api/v1/sources", method="POST", body=body_k1)
        self.assertEqual(c1, 200)
        res_k1 = json.loads(raw1)
        self.assertFalse(res_k1["replayed"])
        self.assertEqual(res_k1["revision"], 1)
        self.assertEqual(res_k1["revision_count_at_operation"], 1)
        self.assertEqual(res_k1["record"]["revision"], 1)
        record_id = res_k1["record"]["id"]
        sha_rev1 = res_k1["sha256"]
        self.assertEqual(res_k1["record"]["sha256"], sha_rev1)
        self.assertEqual(res_k1["current_state"]["current_revision"], 1)
        self.assertEqual(res_k1["current_state"]["current_sha256"], sha_rev1)
        self.assertEqual(res_k1["current_state"]["total_revisions"], 1)

        # Entidade derivada pinada na revisão 1 (para testar histórico de newly_suspended_ids em k2)
        body_ent1 = {
            "operation_key": "knw-ent-rev1",
            "record_type": "entity",
            "title": "Projeto Logístico Lote",
            "payload": {
                "entity_kind": "project",
                "purpose": "Rastreamento da remessa inicial",
                "project_status": "active",
                "identity_status": "identified",
                "origin_refs": [{"record_id": record_id, "revision": 1}],
            },
        }
        ce1, _, raw_e1 = self._request("/api/v1/knowledge", method="POST", body=body_ent1)
        self.assertEqual(ce1, 200)
        ent1_initial = json.loads(raw_e1)
        self.assertFalse(ent1_initial["replayed"])
        ent1_id = ent1_initial["record"]["id"]
        ent1_sha_rev1 = ent1_initial["sha256"]

        # 2. Retificar 1 -> 2 ("lote B", chave k2)
        body_k2 = {
            "operation_key": "k2",
            "record_id": record_id,
            "expected_revision": 1,
            "reason": "Substituição da remessa para lote B",
            "content": "lote B",
        }
        c2, _, raw2 = self._request("/api/v1/sources/rectify", method="POST", body=body_k2)
        self.assertEqual(c2, 200)
        res_k2 = json.loads(raw2)
        self.assertFalse(res_k2["replayed"])
        self.assertEqual(res_k2["from_revision"], 1)
        self.assertEqual(res_k2["to_revision"], 2)
        self.assertEqual(res_k2["revision"], 2)
        self.assertEqual(res_k2["revision_count_at_operation"], 2)
        self.assertEqual(res_k2["old_sha256"], sha_rev1)
        sha_rev2 = res_k2["new_sha256"]
        self.assertNotEqual(sha_rev2, sha_rev1)
        self.assertEqual(res_k2["sha256"], sha_rev2)
        self.assertEqual(res_k2["newly_suspended_ids"], [ent1_id])
        self.assertIn("-lote A", res_k2["diff"])
        self.assertIn("+lote B", res_k2["diff"])
        self.assertFalse(any("lote C" in ln for ln in res_k2["diff"]))

        # Segunda entidade pinada na revisão 2 (será suspensa apenas em k3, não em k2!)
        ce2, _, raw_e2 = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "knw-ent-rev2",
                "record_type": "entity",
                "title": "Projeto Logístico Lote B",
                "payload": {
                    "entity_kind": "project",
                    "purpose": "Rastreamento da segunda remessa",
                    "project_status": "active",
                    "identity_status": "identified",
                    "origin_refs": [{"record_id": record_id, "revision": 2}],
                },
            },
        )
        self.assertEqual(ce2, 200)
        ent2_id = json.loads(raw_e2)["record"]["id"]

        # 3. Retificar 2 -> 3 ("lote C", chave k3)
        body_k3 = {
            "operation_key": "k3",
            "record_id": record_id,
            "expected_revision": 2,
            "reason": "Consolidação final no lote C",
            "content": "lote C",
        }
        c3, _, raw3 = self._request("/api/v1/sources/rectify", method="POST", body=body_k3)
        self.assertEqual(c3, 200)
        res_k3 = json.loads(raw3)
        self.assertFalse(res_k3["replayed"])
        self.assertEqual(res_k3["from_revision"], 2)
        self.assertEqual(res_k3["to_revision"], 3)
        self.assertEqual(res_k3["old_sha256"], sha_rev2)
        sha_rev3 = res_k3["new_sha256"]
        self.assertNotEqual(sha_rev3, sha_rev1)
        self.assertNotEqual(sha_rev3, sha_rev2)
        self.assertEqual(res_k3["newly_suspended_ids"], [ent2_id])

        # Atualizar ent1 na revisão 2 e depois revisão 3 para validar replay histórico também em /api/v1/knowledge
        body_ent1_v2 = {
            "operation_key": "knw-ent-rev1-upd2",
            "record_id": ent1_id,
            "expected_revision": 1,
            "record_type": "entity",
            "title": "Projeto Logístico Lote (Rev 2)",
            "payload": {
                "entity_kind": "project",
                "purpose": "Revalidado na remessa C preliminar",
                "project_status": "active",
                "identity_status": "identified",
                "origin_refs": [{"record_id": record_id, "revision": 3}],
            },
        }
        ce1_v2, _, raw_e1_v2 = self._request("/api/v1/knowledge", method="POST", body=body_ent1_v2)
        self.assertEqual(ce1_v2, 200)
        ent1_v2_out = json.loads(raw_e1_v2)
        ent1_sha_rev2 = ent1_v2_out["sha256"]
        self.assertNotEqual(ent1_sha_rev2, ent1_sha_rev1)

        ce1_v3, _, raw_e1_v3 = self._request(
            "/api/v1/knowledge",
            method="POST",
            body={
                "operation_key": "knw-ent-rev1-upd3",
                "record_id": ent1_id,
                "expected_revision": 2,
                "record_type": "entity",
                "title": "Projeto Logístico Lote (Rev 3)",
                "payload": {
                    "entity_kind": "project",
                    "purpose": "Revalidado na remessa C final",
                    "project_status": "active",
                    "identity_status": "identified",
                    "origin_refs": [{"record_id": record_id, "revision": 3}],
                },
            },
        )
        self.assertEqual(ce1_v3, 200)
        ent1_sha_rev3 = json.loads(raw_e1_v3)["sha256"]

        def assert_replays(request_fn) -> None:
            # Replay k1 (criação v1)
            rc1, _, rraw1 = request_fn("/api/v1/sources", method="POST", body=body_k1)
            self.assertEqual(rc1, 200)
            rep1 = json.loads(rraw1)
            self.assertTrue(rep1["replayed"])
            self.assertEqual(rep1["revision"], 1)
            self.assertEqual(rep1["record"]["revision"], 1)
            self.assertEqual(rep1["sha256"], sha_rev1)
            self.assertEqual(rep1["record"]["sha256"], sha_rev1)
            self.assertNotEqual(rep1["sha256"], sha_rev3)
            self.assertEqual(rep1["revision_count_at_operation"], 1)
            self.assertEqual(rep1["current_state"]["current_revision"], 3)
            self.assertEqual(rep1["current_state"]["current_sha256"], sha_rev3)
            self.assertEqual(rep1["current_state"]["total_revisions"], 3)
            self.assertEqual(rep1["current_state"]["currently_suspended_ids"], [ent2_id])

            # Replay k2 (retificação 1 -> 2)
            rc2, _, rraw2 = request_fn("/api/v1/sources/rectify", method="POST", body=body_k2)
            self.assertEqual(rc2, 200)
            rep2 = json.loads(rraw2)
            self.assertTrue(rep2["replayed"])
            self.assertEqual(rep2["from_revision"], 1)
            self.assertEqual(rep2["to_revision"], 2)
            self.assertEqual(rep2["revision"], 2)
            self.assertEqual(rep2["old_sha256"], sha_rev1)
            self.assertEqual(rep2["new_sha256"], sha_rev2)
            self.assertEqual(rep2["sha256"], sha_rev2)
            self.assertNotEqual(rep2["sha256"], sha_rev3)
            self.assertEqual(rep2["revision_count_at_operation"], 2)
            self.assertIn("-lote A", rep2["diff"])
            self.assertIn("+lote B", rep2["diff"])
            self.assertFalse(any("lote C" in ln for ln in rep2["diff"]))
            self.assertEqual(rep2["newly_suspended_ids"], [ent1_id])
            self.assertEqual(rep2["current_state"]["current_revision"], 3)
            self.assertEqual(rep2["current_state"]["current_sha256"], sha_rev3)
            self.assertEqual(rep2["current_state"]["total_revisions"], 3)
            self.assertEqual(rep2["current_state"]["currently_suspended_ids"], [ent2_id])

            # Replay conhecimento v1 e v2
            rce1, _, rrawe1 = request_fn("/api/v1/knowledge", method="POST", body=body_ent1)
            self.assertEqual(rce1, 200)
            repe1 = json.loads(rrawe1)
            self.assertTrue(repe1["replayed"])
            self.assertEqual(repe1["revision"], 1)
            self.assertEqual(repe1["sha256"], ent1_sha_rev1)
            self.assertEqual(repe1["record"]["sha256"], ent1_sha_rev1)
            self.assertEqual(repe1["current_state"]["current_revision"], 3)
            self.assertEqual(repe1["current_state"]["current_sha256"], ent1_sha_rev3)

            rce2, _, rrawe2 = request_fn("/api/v1/knowledge", method="POST", body=body_ent1_v2)
            self.assertEqual(rce2, 200)
            repe2 = json.loads(rrawe2)
            self.assertTrue(repe2["replayed"])
            self.assertEqual(repe2["from_revision"], 1)
            self.assertEqual(repe2["to_revision"], 2)
            self.assertEqual(repe2["old_sha256"], ent1_sha_rev1)
            self.assertEqual(repe2["new_sha256"], ent1_sha_rev2)
            self.assertEqual(repe2["sha256"], ent1_sha_rev2)
            self.assertEqual(repe2["current_state"]["current_revision"], 3)

        # 4. Replay na mesma instância do servidor
        assert_replays(self._request)

        # 5. Reiniciar completamente EpistemicGatewayRuntime + servidor HTTP sobre o MESMO workspace
        restarted_runtime = EpistemicGatewayRuntime(
            self.base / "sistema",
            self.base / "cofre",
            enable_embeddings=False,
        )
        restarted_token = "gw-restarted-operator-token"
        restarted_srv = create_gateway_server(
            restarted_runtime,
            host="127.0.0.1",
            port=0,
            api_token=restarted_token,
        )
        restarted_port = restarted_srv.server_address[1]
        restarted_thread = threading.Thread(target=restarted_srv.serve_forever, daemon=True)
        restarted_thread.start()
        try:
            def request_restarted(path: str, *, method: str = "GET", body: dict | None = None):
                hdrs = {"Authorization": f"Bearer {restarted_token}", "Content-Type": "application/json"}
                raw_b = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
                req = urllib.request.Request(
                    f"http://127.0.0.1:{restarted_port}{path}",
                    data=raw_b,
                    headers=hdrs,
                    method=method,
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return resp.status, dict(resp.headers), resp.read().decode("utf-8")

            assert_replays(request_restarted)

            # 6. Reconstrução determinística se Store confirmou operação antes de existir linha em gateway_operacoes.sqlite3
            with restarted_runtime._connect_ops() as conn:
                conn.execute("DELETE FROM operation_receipts WHERE operation_key IN ('k1', 'k2')")
            assert_replays(request_restarted)
        finally:
            restarted_srv.shutdown()
            restarted_srv.server_close()
            restarted_thread.join(timeout=3)

    def test_local_trust_boundary_readonly_ui_token_vs_operator_write_token(self) -> None:
        """Finding #3: ui_session_token ('read_only') vs api_token ('read_write')."""
        # 1. Extrair ui_session_token de GET / como qualquer processo local faria
        c_html, _, html = self._request("/", auth=False)
        self.assertEqual(c_html, 200)
        self.assertIn("Desbloquear Escrita (Token de Operador Bearer)", html)
        self.assertIn('id="operator-write-token"', html)
        self.assertNotIn(self.api_token, html)
        m_tok = re.search(r"const\s+GW_UI_TOKEN\s*=\s*\"([a-f0-9]+)\"", html)
        self.assertIsNotNone(m_tok)
        ui_token = m_tok.group(1)  # type: ignore[union-attr]
        self.assertEqual(ui_token, self.server.ui_token)  # type: ignore[attr-defined]

        # 2. Preparar um registro inicial com o token de operador ('read_write')
        c_seed, _, raw_seed = self._request(
            "/api/v1/sources",
            method="POST",
            body={
                "operation_key": "scope-test-src-1",
                "title": "Fonte Escopo Confiança",
                "source_kind": "document",
                "content": json.dumps({"indicador": 42}, ensure_ascii=False),
            },
        )
        self.assertEqual(c_seed, 200)
        source_id = json.loads(raw_seed)["record"]["id"]

        ui_headers = {"Authorization": f"Bearer {ui_token}"}

        # 3. ui_session_token ('read_only') tem sucesso em GET /health, /graph, /lineage/<id> e busca sem mutação
        c_uh, _, raw_uh = self._request("/api/v1/health", auth=False, headers=ui_headers)
        self.assertEqual(c_uh, 200)
        self.assertEqual(json.loads(raw_uh)["auth_scope"], "read_only")

        c_ug, _, raw_ug = self._request("/api/v1/graph?include_superseded=true", auth=False, headers=ui_headers)
        self.assertEqual(c_ug, 200)
        self.assertEqual(len(json.loads(raw_ug)["nodes"]), 1)

        c_ul, _, raw_ul = self._request(f"/api/v1/lineage/{source_id}", auth=False, headers=ui_headers)
        self.assertEqual(c_ul, 200)
        self.assertEqual(json.loads(raw_ul)["record"]["id"], source_id)

        with self.runtime.knowledge.connect() as conn:
            searches_before = conn.execute("SELECT COUNT(*) FROM searches").fetchone()[0]
        with self.runtime.retrieval.connect() as conn:
            hist_before = conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]

        c_us, _, raw_us = self._request(
            "/api/v1/search",
            method="POST",
            auth=False,
            headers=ui_headers,
            body={"query": "Fonte Escopo", "limit": 5, "depth": 1},
        )
        self.assertEqual(c_us, 200)
        srch_ro = json.loads(raw_us)
        self.assertTrue(srch_ro["read_only"])
        self.assertEqual(len(srch_ro["results"]), 1)

        with self.runtime.knowledge.connect() as conn:
            searches_after = conn.execute("SELECT COUNT(*) FROM searches").fetchone()[0]
        with self.runtime.retrieval.connect() as conn:
            hist_after = conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]
        self.assertEqual(searches_after, searches_before)
        self.assertEqual(hist_after, hist_before)

        # 4. TODOS os endpoints de escrita DEVEM rejeitar ui_session_token com HTTP 403 insufficient_scope
        write_attempts = [
            (
                "/api/v1/sources",
                {"operation_key": "unauth-src", "title": "Intruso", "content": "bloqueado"},
            ),
            (
                "/api/v1/sources/rectify",
                {
                    "operation_key": "unauth-rect",
                    "record_id": source_id,
                    "expected_revision": 1,
                    "reason": "Tentativa sem escopo",
                    "content": "{}",
                },
            ),
            (
                "/api/v1/knowledge",
                {
                    "operation_key": "unauth-knw",
                    "record_type": "entity",
                    "title": "Entidade Não Autorizada",
                    "payload": {
                        "entity_kind": "project",
                        "purpose": "Teste",
                        "project_status": "active",
                        "identity_status": "identified",
                        "origin_refs": [{"record_id": source_id, "revision": 1}],
                    },
                },
            ),
            (
                "/api/v1/verify-claims",
                {
                    "operation_key": "unauth-ver",
                    "claims": [
                        {
                            "id": "ind",
                            "kind": "field",
                            "value": 42,
                            "refs": [{"record_id": source_id, "revision": 1, "path": "/indicador"}],
                        }
                    ],
                },
            ),
        ]
        for endpoint, payload in write_attempts:
            code_403, _, raw_403 = self._request(
                endpoint,
                method="POST",
                auth=False,
                headers=ui_headers,
                body=payload,
            )
            self.assertEqual(code_403, 403, msg=f"Endpoint {endpoint} deveria rejeitar ui_session_token com 403")
            err = json.loads(raw_403)
            self.assertEqual(err["status"], "forbidden")
            self.assertEqual(err["error"], "insufficient_scope")
            self.assertEqual(err["required_scope"], "read_write")
            self.assertEqual(err["current_scope"], "read_only")

        # 5. Com o token de operador ('read_write'), leitura e todas as escritas têm sucesso
        c_oh, _, raw_oh = self._request("/api/v1/health")
        self.assertEqual(c_oh, 200)
        self.assertEqual(json.loads(raw_oh)["auth_scope"], "read_write")

        c_ok_knw, _, _ = self._request("/api/v1/knowledge", method="POST", body=write_attempts[2][1])
        self.assertEqual(c_ok_knw, 200)
        c_ok_ver, _, _ = self._request("/api/v1/verify-claims", method="POST", body=write_attempts[3][1])
        self.assertEqual(c_ok_ver, 200)
        c_ok_rect, _, _ = self._request("/api/v1/sources/rectify", method="POST", body=write_attempts[1][1])
        self.assertEqual(c_ok_rect, 200)

    def test_cli_cleanup_preserves_preexisting_files_and_unauthorized_scope_leaves_empty_folder(self) -> None:
        """Findings #2 & #7: --cleanup preserva sentinel.txt; escopo não autorizado mantém pasta vazia."""
        from unittest import mock
        from nucleo import Invalid
        import apps.http_gateway.cli as gw_cli

        # (a) CLI --workspace <dir_com_sentinel> --cleanup demo preserva sentinel.txt em sucesso e em falha!
        existing_project = self.base / "existing_user_project"
        existing_project.mkdir(parents=True, exist_ok=True)
        sentinel = existing_project / "sentinel.txt"
        sentinel.write_text("projeto preexistente intacto", encoding="utf-8")

        env = dict(os.environ, PYTHONUTF8="1")
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "apps" / "http_gateway" / "cli.py"),
                "--workspace",
                str(existing_project),
                "--no-embeddings",
                "--cleanup",
                "demo",
            ],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=45,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
        demo_out = json.loads(proc.stdout)
        self.assertTrue(demo_out["workspace_cleaned_up"])
        self.assertTrue(sentinel.is_file())
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "projeto preexistente intacto")
        self.assertEqual(list(existing_project.iterdir()), [sentinel])

        # Falha forçada durante inicialização e durante execução da demo com --cleanup
        prev_env = dict(os.environ)
        try:
            with mock.patch.object(gw_cli, "EpistemicGatewayRuntime", side_effect=RuntimeError("falha init simulada")):
                with self.assertRaises(RuntimeError):
                    gw_cli.main(["--workspace", str(existing_project), "--no-embeddings", "--cleanup", "demo"])
            self.assertTrue(sentinel.is_file())
            self.assertEqual(list(existing_project.iterdir()), [sentinel])

            with mock.patch.object(gw_cli, "_run_http_demo", side_effect=RuntimeError("falha demo simulada")):
                with self.assertRaises(RuntimeError):
                    gw_cli.main(["--workspace", str(existing_project), "--no-embeddings", "--cleanup", "demo"])
            self.assertTrue(sentinel.is_file())
            self.assertEqual(list(existing_project.iterdir()), [sentinel])
        finally:
            os.environ.clear()
            os.environ.update(prev_env)

        # (b) Finding #7: inicialização programática fora do escopo autorizado falha sem criar NENHUM diretório/arquivo
        with tempfile.TemporaryDirectory(prefix="emc-unauth-gw-") as ext_tmp:
            unauth_folder = Path(ext_tmp)
            saved_auth_roots = os.environ.pop("EMC_AUTHORIZED_ROOTS", None)
            try:
                with self.assertRaises(Invalid):
                    EpistemicGatewayRuntime.from_workspace(unauth_folder, enable_embeddings=False)
                self.assertEqual(list(unauth_folder.iterdir()), [])

                with self.assertRaises(Invalid):
                    EpistemicGatewayRuntime(
                        unauth_folder / "sistema",
                        unauth_folder / "cofre",
                        enable_embeddings=False,
                    )
                self.assertEqual(list(unauth_folder.iterdir()), [])

                # Quando explicitamente autorizado via EMC_AUTHORIZED_ROOTS, inicializa e grava fonte com sucesso
                os.environ["EMC_AUTHORIZED_ROOTS"] = str(unauth_folder)
                ext_rt = EpistemicGatewayRuntime.from_workspace(unauth_folder, enable_embeddings=False)
                created = ext_rt.create_source(
                    {"operation_key": "ext-auth-1", "title": "Fonte Autorizada", "content": "ok"}
                )
                self.assertEqual(created["revision"], 1)
                self.assertEqual(ext_rt.store.read(created["record"]["id"])["payload"]["content"], "ok")
            finally:
                if saved_auth_roots is None:
                    os.environ.pop("EMC_AUTHORIZED_ROOTS", None)
                else:
                    os.environ["EMC_AUTHORIZED_ROOTS"] = saved_auth_roots

    def test_rate_limiting_enforces_429_retry_after_and_window_reset(self) -> None:
        import time

        limited_token = "gw-rate-limit-token"
        limited_srv = create_gateway_server(
            self.runtime,
            host="127.0.0.1",
            port=0,
            api_token=limited_token,
            rate_limit_requests=3,
            rate_limit_window_seconds=0.25,
        )
        limited_port = limited_srv.server_address[1]
        limited_thread = threading.Thread(target=limited_srv.serve_forever, daemon=True)
        limited_thread.start()
        try:
            def call_health():
                req = urllib.request.Request(
                    f"http://127.0.0.1:{limited_port}/api/v1/health",
                    headers={"Authorization": f"Bearer {limited_token}"},
                    method="GET",
                )
                try:
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        return resp.status, dict(resp.headers), resp.read().decode("utf-8")
                except urllib.error.HTTPError as err:
                    return err.code, dict(err.headers), err.read().decode("utf-8")

            for _ in range(3):
                code, _, _ = call_health()
                self.assertEqual(code, 200)

            code_429, hdrs_429, raw_429 = call_health()
            self.assertEqual(code_429, 429)
            self.assertGreaterEqual(int(hdrs_429.get("Retry-After", "0")), 1)
            self.assertEqual(hdrs_429.get("X-RateLimit-Limit"), "3")
            self.assertEqual(hdrs_429.get("X-RateLimit-Remaining"), "0")
            body_429 = json.loads(raw_429)
            self.assertEqual(body_429["status"], "rate_limited")
            self.assertEqual(body_429["error"], "rate_limit_exceeded")

            # POST com corpo JSON sob 429 deve drenar o corpo e retornar JSON limpo + Retry-After
            post_req = urllib.request.Request(
                f"http://127.0.0.1:{limited_port}/api/v1/search",
                data=json.dumps({"query": "rate-limit-check", "padding": "x" * 4096}).encode("utf-8"),
                headers={"Authorization": f"Bearer {limited_token}", "Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as post_ctx:
                urllib.request.urlopen(post_req, timeout=10)
            self.assertEqual(post_ctx.exception.code, 429)
            self.assertGreaterEqual(int(post_ctx.exception.headers.get("Retry-After", "0")), 1)
            self.assertEqual(json.loads(post_ctx.exception.read().decode("utf-8"))["error"], "rate_limit_exceeded")

            time.sleep(0.3)
            code_after, _, _ = call_health()
            self.assertEqual(code_after, 200)

            # Limite máximo de 1024 chaves ativas (fail-closed contra exaustão de memória)
            from apps.http_gateway.server import RateLimiter as GatewayRateLimiter

            cap_limiter = GatewayRateLimiter(max_requests=1, window_seconds=60.0)
            for idx in range(1024):
                ok_key, _, _ = cap_limiter.allow(f"client-{idx}")
                self.assertTrue(ok_key)
            ok_overflow, rem_overflow, retry_overflow = cap_limiter.allow("client-overflow")
            self.assertFalse(ok_overflow)
            self.assertEqual(rem_overflow, 0)
            self.assertGreater(retry_overflow, 0.0)
        finally:
            limited_srv.shutdown()
            limited_srv.server_close()
            limited_thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
