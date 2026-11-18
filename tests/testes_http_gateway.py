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


if __name__ == "__main__":
    unittest.main()
