#!/usr/bin/env python3
"""CLI e Inicializador do Epistemic HTTP Gateway & Live Lineage Graph Explorer."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

APP_ROOT = Path(__file__).resolve().parents[2]
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from apps.http_gateway.server import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    EpistemicGatewayRuntime,
    bootstrap_gateway_workspace,
    create_gateway_server,
)


def seed_sample_graph(runtime: EpistemicGatewayRuntime) -> dict[str, Any]:
    """Popula um grafo demonstrativo completo (fonte -> entidade -> afirmação -> síntese -> recibo)."""
    src_quote = runtime.create_source(
        {
            "operation_key": "cli-seed-cotacao-v1",
            "title": "Cotação Gateway Cloud #GW-2026",
            "source_kind": "document",
            "content": json.dumps(
                {
                    "fornecedor": "VortexCloud",
                    "capex_brl": 35000,
                    "opex_anual_brl": 145000,
                    "sla_bps": 9995,
                    "etapas": {
                        "p1": ["gateway_api", "requires", "malha_mtls"],
                        "p2": ["malha_mtls", "requires", "auditoria_soc2"],
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
        }
    )
    src_ata = runtime.create_source(
        {
            "operation_key": "cli-seed-ata-v1",
            "title": "Ata do Comitê de Engenharia de Plataforma",
            "source_kind": "conversation",
            "content": "Beatriz Nogueira confirmou que o orçamento anual aprovado para o gateway é 200000 reais.",
        }
    )
    ref_quote = src_quote["rev_ref"]
    ref_ata = src_ata["rev_ref"]

    beatriz = runtime.create_or_update_knowledge(
        {
            "operation_key": "cli-seed-ent-beatriz",
            "record_type": "entity",
            "title": "Beatriz Nogueira",
            "payload": {
                "entity_kind": "person",
                "display_name": "Beatriz Nogueira",
                "aliases": ["Beatriz"],
                "identity_status": "identified",
                "origin_refs": [ref_ata],
            },
        }
    )
    assertion = runtime.create_or_update_knowledge(
        {
            "operation_key": "cli-seed-assert-orcamento",
            "record_type": "assertion",
            "title": "Orçamento anual confirmado por Beatriz Nogueira",
            "payload": {
                "subject_ref": beatriz["rev_ref"],
                "predicate": "reports_value",
                "nature": "third_party_report",
                "asserted_by": "http_gateway_cli",
                "source_refs": [ref_ata],
                "value": {"type": "number", "content": 200000, "unit": "BRL"},
                "attribution_evidence": {
                    "source_ref": ref_ata,
                    "quote": "Beatriz Nogueira confirmou que o orçamento anual aprovado para o gateway é 200000 reais.",
                },
                "context_description": "Comitê de Engenharia de Plataforma",
            },
        }
    )
    synthesis = runtime.create_or_update_knowledge(
        {
            "operation_key": "cli-seed-syn-parecer",
            "record_type": "synthesis",
            "title": "Parecer de Viabilidade VortexCloud (Rev 1)",
            "payload": {
                "synthesis_kind": "knowledge_summary",
                "content": "Custo de 1º ano (R$ 180.000) enquadra-se no teto de R$ 200.000 confirmado por Beatriz Nogueira.",
                "scope": "Cotação #GW-2026 Rev 1 + Ata Comitê Rev 1",
                "basis_refs": [ref_quote, assertion["rev_ref"]],
                "limitations": ["Qualquer reajuste da cotação invalida automaticamente este parecer."],
                "coverage_status": "supported_within_scope",
                "as_of": "2026-11-17",
            },
        }
    )
    receipt = runtime.verify_claims(
        {
            "operation_key": "cli-seed-receipt-v1",
            "claims": [
                {
                    "id": "custo_primeiro_ano_brl",
                    "kind": "sum",
                    "value": 180000,
                    "refs": [
                        {"record_id": ref_quote["record_id"], "revision": 1, "path": "/capex_brl"},
                        {"record_id": ref_quote["record_id"], "revision": 1, "path": "/opex_anual_brl"},
                    ],
                },
                {
                    "id": "cadeia_seguranca",
                    "kind": "chain",
                    "value": ["gateway_api", "requires", "auditoria_soc2"],
                    "refs": [
                        {"record_id": ref_quote["record_id"], "revision": 1, "path": "/etapas/p1"},
                        {"record_id": ref_quote["record_id"], "revision": 1, "path": "/etapas/p2"},
                    ],
                },
            ],
        }
    )
    return {
        "quote_source_id": ref_quote["record_id"],
        "ata_source_id": ref_ata["record_id"],
        "person_id": beatriz["record"]["id"],
        "assertion_id": assertion["record"]["id"],
        "synthesis_id": synthesis["record"]["id"],
        "receipt_id": receipt["receipt_id"],
    }


def _run_http_demo(runtime: EpistemicGatewayRuntime, token: str | None) -> dict[str, Any]:
    server = create_gateway_server(runtime, host="127.0.0.1", port=0, api_token=token)
    port = server.server_address[1]
    bearer = server.api_token  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def call(method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        headers = {"Authorization": f"Bearer {bearer}", "Accept": "application/json"}
        raw = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            raw = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=raw, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read().decode("utf-8"))

    try:
        seeded = seed_sample_graph(runtime)
        _, health_before = call("GET", "/api/v1/health")
        _, search_before = call("POST", "/api/v1/search", {"query": "VortexCloud orçamento", "limit": 8})
        current_rev = runtime.store.read(seeded["quote_source_id"])["revision"]
        if current_rev == 1:
            _, rect_out = call(
                "POST",
                "/api/v1/sources/rectify",
                {
                    "operation_key": "cli-demo-rectify-v2",
                    "record_id": seeded["quote_source_id"],
                    "expected_revision": 1,
                    "reason": "Reajuste contratual do fornecedor elevou OpEx anual para R$ 190.000.",
                    "content": json.dumps(
                        {
                            "fornecedor": "VortexCloud",
                            "capex_brl": 35000,
                            "opex_anual_brl": 190000,
                            "sla_bps": 9990,
                            "etapas": {
                                "p1": ["gateway_api", "requires", "malha_mtls"],
                                "p2": ["malha_mtls", "requires", "auditoria_soc2"],
                            },
                        },
                        ensure_ascii=False,
                        indent=2,
                    ),
                },
            )
        else:
            rect_out = {"newly_suspended_ids": [], "stale_receipt_ids": []}
        _, lineage_after = call("GET", f"/api/v1/lineage/{seeded['quote_source_id']}")
        _, graph_after = call("GET", "/api/v1/graph?include_superseded=true")
        return {
            "status": "ok",
            "ephemeral_port": port,
            "seeded": seeded,
            "active_before_rectification": health_before["counts"]["active_records"],
            "search_mode": search_before["mode"],
            "newly_suspended_ids": rect_out["newly_suspended_ids"],
            "stale_receipt_ids": rect_out["stale_receipt_ids"],
            "lineage_impact": lineage_after["impact"],
            "graph_counts_after": graph_after["counts"],
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Epistemic HTTP Gateway & Live Lineage Graph Explorer (REST JSON v1 + SVG UI)."
    )
    parser.add_argument(
        "--workspace",
        default=str(APP_ROOT / "testes_temporarios" / "http-gateway-demo"),
        help="Diretório isolado do workspace (padrão: testes_temporarios/http-gateway-demo)",
    )
    parser.add_argument(
        "--no-embeddings",
        action="store_true",
        help="Desativa explicitamente o carregamento local do modelo vetorial ONNX E5",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Token Bearer da API REST (ou variável EMC_GATEWAY_TOKEN; gerado por sessão se omitido)",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove o workspace temporário ao finalizar comandos não interativos (ex.: demo)",
    )

    sub = parser.add_subparsers(dest="cmd")

    p_serve = sub.add_parser("serve", help="Inicia o servidor HTTP Gateway local (padrão 127.0.0.1:8095)")
    p_serve.add_argument("--host", default=DEFAULT_HOST)
    p_serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_serve.add_argument("--seed-demo", action="store_true", help="Popula registros iniciais de demonstração")

    sub.add_parser("health", help="Exibe JSON de saúde, geração e contagens do workspace")
    sub.add_parser("graph", help="Exporta JSON completo do grafo epistemológico e revisões superadas")

    p_lin = sub.add_parser("lineage", help="Inspeciona linhagem upstream/downstream de um registro")
    p_lin.add_argument("record_id")

    sub.add_parser("demo", help="Executa demonstração ponta a ponta via HTTP real em porta efêmera")

    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 1

    sys_root, vault_root = bootstrap_gateway_workspace(args.workspace)
    runtime = EpistemicGatewayRuntime(
        sys_root,
        vault_root,
        enable_embeddings=not args.no_embeddings,
    )

    if args.cmd == "health":
        print(json.dumps(runtime.health(), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "graph":
        print(json.dumps(runtime.graph(include_superseded=True), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "lineage":
        print(json.dumps(runtime.lineage(args.record_id), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "demo":
        try:
            report = _run_http_demo(runtime, args.token)
        finally:
            cleaned = False
            if args.cleanup:
                ws_resolved = Path(args.workspace).resolve()
                temp_root = (APP_ROOT / "testes_temporarios").resolve()
                if temp_root in ws_resolved.parents:
                    shutil.rmtree(ws_resolved, ignore_errors=True)
                    cleaned = True
        report["workspace_cleaned_up"] = cleaned
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "serve":
        if args.seed_demo:
            seed_sample_graph(runtime)
        max_tries = 1 if args.port == 0 else 20
        last_err: OSError | None = None
        for idx in range(max_tries):
            candidate_port = 0 if args.port == 0 else args.port + idx
            if candidate_port > 65535:
                break
            try:
                srv = create_gateway_server(runtime, host=args.host, port=candidate_port, api_token=args.token)
            except OSError as exc:
                last_err = exc
                continue
            bound_port = srv.server_address[1]
            print(f"Epistemic HTTP Gateway ativo em: http://{args.host}:{bound_port}")
            print(f"Workspace isolado: {Path(args.workspace).resolve()}")
            print(f"Authorization: Bearer {srv.api_token}")  # type: ignore[attr-defined]
            try:
                srv.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                srv.server_close()
            return 0
        raise OSError(f"Nenhuma porta local disponível a partir de {args.port}") from last_err

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
