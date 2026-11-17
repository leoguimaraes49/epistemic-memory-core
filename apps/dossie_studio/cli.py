#!/usr/bin/env python3
"""CLI e inicializador do Epistemic Dossier Studio."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[2]
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from apps.dossie_studio.engine_adapter import DossieWorkspace, bootstrap_environment
from apps.dossie_studio.scenarios import SCENARIO_CATALOG, load_scenario, simulate_premise_change
from apps.dossie_studio.web import create_studio_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Epistemic Dossier Studio — Auditoria de decisões, contratos e premissas sobre o Epistemic Memory Core."
    )
    parser.add_argument(
        "--workspace",
        default=str(APP_ROOT / "testes_temporarios" / "dossie-studio-demo"),
        help="Diretório isolado do dossiê (padrão: testes_temporarios/dossie-studio-demo)",
    )
    parser.add_argument("--embeddings", action="store_true", help="Habilita busca vetorial ONNX E5 local se instalada")

    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("scenarios", help="Lista os cenários práticos disponíveis")

    p_load = sub.add_parser("load", help="Carrega um cenário prático no dossiê")
    p_load.add_argument("scenario_id", choices=sorted(SCENARIO_CATALOG))

    p_mut = sub.add_parser("mutate", help="Simula retificação de premissa e exibe o raio de impacto")
    p_mut.add_argument("scenario_id", choices=sorted(SCENARIO_CATALOG))

    sub.add_parser("status", help="Exibe resumo do grafo epistêmico, registros suspensos e comprovantes")

    p_search = sub.add_parser("search", help="Executa busca auditável no dossiê")
    p_search.add_argument("query")
    p_search.add_argument("--limit", type=int, default=10)

    p_serve = sub.add_parser("serve", help="Inicia a interface web interativa local (127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=8090)
    p_serve.add_argument("--preload", choices=sorted(SCENARIO_CATALOG), help="Pré-carrega um cenário ao subir o servidor")

    args = parser.parse_args(argv)
    if args.cmd == "scenarios":
        print(json.dumps(list(SCENARIO_CATALOG.values()), ensure_ascii=False, indent=2))
        return 0

    sys_root, vault_root = bootstrap_environment(args.workspace)
    ws = DossieWorkspace(sys_root, vault_root, enable_embeddings=args.embeddings)

    if args.cmd == "load":
        out = load_scenario(ws, args.scenario_id)
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "mutate":
        out = simulate_premise_change(ws, args.scenario_id)
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "status":
        print(json.dumps(ws.snapshot(), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "search":
        print(json.dumps(ws.search(args.query, limit=args.limit), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "serve":
        if args.preload:
            load_scenario(ws, args.preload)
        for candidate_port in range(args.port, min(65536, args.port + 20)):
            try:
                srv = create_studio_server(ws, port=candidate_port)
            except OSError:
                continue
            print(f"Epistemic Dossier Studio ativo em: http://127.0.0.1:{candidate_port}")
            print(f"Workspace isolado: {Path(args.workspace).resolve()}")
            try:
                srv.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                srv.server_close()
            return 0
        raise OSError(f"Nenhuma porta disponível a partir de {args.port}")

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
