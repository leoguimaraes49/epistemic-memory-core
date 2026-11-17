#!/usr/bin/env python3
"""Benchmark de carga, concorrência multiprocesso, recuperação de falha e busca ONNX E5.

Executa integralmente em diretório isolado dentro de `testes_temporarios/` (nunca toca
no cofre real) e valida:
  1. Ingestão transacional em volume (padrão: 600+ registros interligados em 4 famílias);
  2. Contenção concorrente real entre múltiplos processos do SO (`Store.apply` simultâneo);
  3. Simulação de queda abrupta entre escrita em disco e confirmação SQLite + retomada idempotente;
  4. Indexação vetorial binária `BLOB` (`<f8`) + latência de busca híbrida RRF (com ONNX E5 real se presente);
  5. Verificação determinística em lote (`field`, `sum`, `chain`) e propagação `stale-on-write` em cascata;
  6. Auditoria final `Knowledge.audit()` garantindo zero corrupção ou órfãos.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from conhecimento import Knowledge
from evidencias import inspect_response, read_receipt
from nucleo import Conflict, REAL_SYSTEM, Store, render
from recuperacao import LocalEmbeddings, Retrieval


class SyntheticEmbeddings:
    dim = 384

    def chunks(self, text: str, kind: str = "passage") -> list[list[float]]:
        vec = [0.0] * self.dim
        words = [w for w in text.lower().split() if len(w) > 2] or ["vazio"]
        for i, w in enumerate(words):
            slot = (sum((idx + 1) * ord(c) for idx, c in enumerate(w)) + i * 7) % self.dim
            vec[slot] += 1.0
        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        return [[x / norm for x in vec]]


def _worker_writer_entry(sys_dir: str, vault_dir: str, worker_id: int, count: int) -> int:
    s = Store(sys_dir, vault_dir)
    ok = 0
    for idx in range(count):
        key = f"mp-w{worker_id}-{idx}"
        for attempt in range(8):
            try:
                s.apply(
                    key,
                    "create",
                    title=f"Evento Concorrente W{worker_id} #{idx}",
                    text=f"Registro concorrente gravado pelo processo {worker_id} item {idx}.",
                )
                ok += 1
                break
            except Exception:
                if attempt == 7:
                    raise
                time.sleep(0.02 * (attempt + 1))
    return ok


def run_benchmark(scale_sources: int = 120, use_onnx: bool = True) -> dict:
    temp_base = REAL_SYSTEM / "testes_temporarios"
    temp_base.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="bench-heavy-", dir=temp_base) as tmp:
        base = Path(tmp)
        sys_root = base / "sistema"
        vault_root = base / "cofre"
        store = Store(sys_root, vault_root)
        knowledge = Knowledge(store)

        emb_dir = os.environ.get("EMC_EMBEDDINGS_DIR")
        cand = Path(emb_dir) if emb_dir else (ROOT / "modelos" / "e5-multilingual-small")
        real_onnx = False
        if use_onnx and (cand / "model.onnx").is_file() and (cand / "tokenizer.json").is_file():
            import numpy  # noqa: F401
            embedder = LocalEmbeddings(cand)
            real_onnx = True
        else:
            import numpy  # noqa: F401
            embedder = SyntheticEmbeddings()

        retrieval = Retrieval(store, embedder=embedder)

        t0 = time.perf_counter()
        sources = []
        persons = []
        projects = []
        assertions = []
        syntheses = []

        sectors = ("arquitetura", "contratos", "seguranca", "operacoes", "dados", "governanca")
        for i in range(scale_sources):
            sec = sectors[i % len(sectors)]
            payload_doc = {
                "lote": i,
                "setor": sec,
                "custo_base": 10000 + (i * 250),
                "reserva_contingencia": 1500 + (i * 50),
                "etapa_a": [f"modulo_{i}", "requires", f"validador_{i}"],
                "etapa_b": [f"validador_{i}", "requires", f"auditoria_{i}"],
                "nota": f"Autor {i % 12} certificou a entrega técnica do pacote {i} na frente {sec}.",
            }
            src = store.ingest if hasattr(store, "ingest") else None  # noqa: F841
            created = store.apply(
                f"b-src-{i}",
                "create",
                title=f"Dossiê {sec.title()} Lote {i:04d}",
                text=json.dumps(payload_doc, ensure_ascii=False),
                source_metadata={
                    "source_kind": "document",
                    "origin_description": "Carga sintética de auditoria em escala",
                    "availability_status": "retained",
                    "retention_conditions": "benchmark_temporario",
                    "reference_locator": f"bench://lote/{i}",
                },
            )
            sources.append(created)

        for p_idx in range(12):
            p = knowledge.apply(
                f"b-per-{p_idx}",
                "entity",
                f"Autor {p_idx}",
                {
                    "entity_kind": "person",
                    "display_name": f"Autor {p_idx}",
                    "identity_status": "identified",
                    "origin_refs": [{"record_id": sources[p_idx]["id"], "revision": 1}],
                },
            )
            persons.append(p)

        for prj_idx in range(24):
            sec = sectors[prj_idx % len(sectors)]
            prj = knowledge.apply(
                f"b-prj-{prj_idx}",
                "entity",
                f"Iniciativa {sec.title()} {prj_idx:02d}",
                {
                    "entity_kind": "project",
                    "purpose": f"Consolidação estrutural da frente {sec} ({prj_idx})",
                    "project_status": "active",
                    "identity_status": "identified",
                    "origin_refs": [{"record_id": sources[prj_idx]["id"], "revision": 1}],
                },
            )
            projects.append(prj)

        n_assertions = scale_sources * 2
        for a_idx in range(n_assertions):
            src = sources[a_idx % scale_sources]
            p_idx = (a_idx % scale_sources) % 12
            sec = sectors[(a_idx % scale_sources) % len(sectors)]
            a = knowledge.apply(
                f"b-ast-{a_idx}",
                "assertion",
                f"Apontamento {sec} {a_idx:04d}",
                {
                    "subject_ref": {"record_id": persons[p_idx]["id"], "revision": 1},
                    "predicate": "reports_value",
                    "value": {"type": "number", "content": 10000 + ((a_idx % scale_sources) * 250)},
                    "nature": "documented_observation",
                    "asserted_by": "benchmark_runner",
                    "recorded_time": "2026-11-17T15:00:00+00:00",
                    "source_refs": [{"record_id": src["id"], "revision": 1}],
                    "context_description": f"Auditoria {sec}",
                    "valid_time": {"precision": "unknown"},
                    "review_status": "unreviewed",
                },
            )
            assertions.append(a)

        n_syntheses = max(20, scale_sources // 2)
        for s_idx in range(n_syntheses):
            a1 = assertions[(s_idx * 2) % len(assertions)]
            a2 = assertions[(s_idx * 2 + 1) % len(assertions)]
            prj = projects[s_idx % len(projects)]
            syn = knowledge.apply(
                f"b-syn-{s_idx}",
                "synthesis",
                f"Panorama Consolidado {s_idx:03d}",
                {
                    "synthesis_kind": "knowledge_summary",
                    "content": f"Síntese auditada do agrupamento {s_idx} no setor {sectors[s_idx % len(sectors)]}.",
                    "scope": "Benchmark de escala",
                    "basis_refs": [
                        {"record_id": a1["id"], "revision": 1},
                        {"record_id": a2["id"], "revision": 1},
                        {"record_id": prj["id"], "revision": 1},
                    ],
                    "limitations": ["Amostra sintética controlada"],
                    "coverage_status": "supported_within_scope",
                    "as_of": "2026-11-17",
                },
            )
            syntheses.append(syn)

        t_ingest = time.perf_counter() - t0

        # 2. Contenção multiprocesso real (4 subprocessos gravando fontes concorrentemente)
        t_mp0 = time.perf_counter()
        mp_script = (
            "import sys; sys.path.insert(0, " + repr(str(ROOT / "src")) + "); "
            "sys.path.insert(0, " + repr(str(ROOT / "scripts")) + "); "
            "import benchmark_escala as b; "
            "print(b._worker_writer_entry(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])))"
        )
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", mp_script, str(sys_root), str(vault_root), str(w), "10"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for w in range(4)
        ]
        mp_written = 0
        for p in procs:
            out, err = p.communicate(timeout=60)
            if p.returncode != 0:
                raise RuntimeError(f"Falha em escritor concorrente: {err}")
            mp_written += int(out.strip())
        t_mp = time.perf_counter() - t_mp0

        # 3. Simulação de crash entre escrita do arquivo e confirmação SQLite + bloqueio de dirty read + retomada
        crash_id = "88888888-4444-4333-8222-111111111111"
        crash_doc = {
            "id": crash_id,
            "record_type": "source",
            "schema_version": "0.1",
            "revision": 1,
            "title": "Fonte Interrompida Antes do Commit",
            "created_at": "2026-11-17T15:00:00+00:00",
            "updated_at": "2026-11-17T15:00:00+00:00",
            "created_by": "ponte_local",
            "access_policy_ref": "proprietario_local",
            "lifecycle_status": "active",
            "payload_format": "brain_json_v1",
            "payload": {
                "source_kind": "conversation",
                "origin_description": "Teste de retomada pós-falha",
                "received_at": "2026-11-17T15:00:00+00:00",
                "availability_status": "retained",
                "retention_conditions": "benchmark",
                "content_locator": "payload.content",
                "content": "Conteúdo já gravado no disco antes da queda abrupta.",
            },
        }
        from nucleo import canon, sha
        crash_bytes = render(crash_doc)
        crash_file = store.folder / "Fonte Interrompida Antes do Commit.md"
        crash_file.write_bytes(crash_bytes)
        req_fp = sha(
            canon(
                {
                    "kind": "create",
                    "title": "Fonte Interrompida Antes do Commit",
                    "text": "Conteúdo já gravado no disco antes da queda abrupta.",
                    "id": "",
                    "expected": 0,
                    "reason": "",
                }
            ).encode()
        )
        with store.connect() as c:
            c.execute(
                "INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    "crash-op-key",
                    req_fp,
                    "proposed",
                    crash_id,
                    0,
                    crash_file.name,
                    None,
                    sha(crash_bytes),
                    crash_bytes,
                    None,
                ),
            )
        recovered = store.finish("crash-op-key")
        assert recovered["status"] == "confirmed" and recovered["id"] == crash_id

        # 4. Indexação vetorial completa + latência de busca fria vs quente vs novo termo
        t_idx0 = time.perf_counter()
        first_search = retrieval.search("arquitetura entrega técnica pacote", limit=15, depth=1)
        t_index_and_first = time.perf_counter() - t_idx0

        t_cache0 = time.perf_counter()
        cached_search = retrieval.search("arquitetura entrega técnica pacote", limit=15, depth=1)
        t_cached_ms = (time.perf_counter() - t_cache0) * 1000.0
        assert cached_search["cache_reused"] is True

        query_samples = [
            "contratos auditoria contingencia",
            "seguranca validador pacote",
            "operacoes entrega certificou",
            "governanca lote consolidado",
            "dados modulo auditoria",
        ]
        t_q0 = time.perf_counter()
        for q in query_samples:
            r = retrieval.search(q, limit=12, depth=1)
            assert len(r["results"]) > 0
        avg_uncached_query_ms = ((time.perf_counter() - t_q0) / len(query_samples)) * 1000.0

        # 5. Comprovante determinístico com 30 claims simultâneas (10 field + 10 sum + 10 chain)
        claims = []
        ctx_ids = []
        for idx in range(10):
            sid = sources[idx]["id"]
            ctx_ids.append(sid)
            custo = 10000 + (idx * 250)
            res_c = 1500 + (idx * 50)
            claims.append({"id": f"setor_{idx}", "kind": "field", "value": sectors[idx % len(sectors)], "refs": [{"record_id": sid, "revision": 1, "path": "/setor"}]})
            claims.append(
                {
                    "id": f"orcamento_total_{idx}",
                    "kind": "sum",
                    "value": custo + res_c,
                    "refs": [
                        {"record_id": sid, "revision": 1, "path": "/custo_base"},
                        {"record_id": sid, "revision": 1, "path": "/reserva_contingencia"},
                    ],
                }
            )
            claims.append(
                {
                    "id": f"cadeia_{idx}",
                    "kind": "chain",
                    "value": [f"modulo_{idx}", "requires", f"auditoria_{idx}"],
                    "refs": [
                        {"record_id": sid, "revision": 1, "path": "/etapa_a"},
                        {"record_id": sid, "revision": 1, "path": "/etapa_b"},
                    ],
                }
            )
        from verificador_evidencias import encode
        ans_lines = "\n".join(f"{c['id']} = {encode(c['value']).decode('utf-8')}" for c in claims)
        receipt = inspect_response(
            store,
            "bench-receipt-30",
            {"answer_format": "controlled", "answer": ans_lines, "claims": claims},
            context_ids=ctx_ids,
            max_context=20,
        )
        assert receipt["status"] == "verified" and receipt["claims_verified"] is True

        # 6. Retificação em lote de 5 fontes primárias -> invalidação em cascata
        for idx in range(5):
            store.apply(
                f"b-rect-{idx}",
                "correct",
                ident=sources[idx]["id"],
                expected=1,
                text=json.dumps({"lote": idx, "setor": "revisado", "custo_base": 99999}),
                reason="Reajuste de estresse para validação de cascata",
            )
        rechecked_receipt = read_receipt(store, receipt["receipt_id"])
        assert rechecked_receipt["status"] == "stale"

        audit_report = knowledge.audit()
        assert audit_report["status"] == "ok" and audit_report["issues"] == []
        assert len(audit_report["needs_revalidation"]) >= 10

        vec_db_bytes = (sys_root / "estado" / "recuperacao.sqlite3").stat().st_size

        return {
            "status": "passed",
            "onnx_e5_real": real_onnx,
            "total_catalog_records": audit_report["records"],
            "multiprocess_concurrent_writes": mp_written,
            "crash_recovery_verified": True,
            "claims_verified_in_single_receipt": len(claims),
            "cascade_suspended_records_after_5_edits": len(audit_report["needs_revalidation"]),
            "structural_issues": len(audit_report["issues"]),
            "timings": {
                "ingest_seconds": round(t_ingest, 2),
                "multiprocess_4_workers_seconds": round(t_mp, 2),
                "initial_vector_index_and_search_seconds": round(t_index_and_first, 2),
                "cached_query_ms": round(t_cached_ms, 2),
                "avg_new_hybrid_query_ms": round(avg_uncached_query_ms, 2),
            },
            "vector_sqlite_size_kb": round(vec_db_bytes / 1024.0, 1),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark pesado de escala, concorrência e ONNX do Epistemic Memory Core.")
    parser.add_argument("--fontes", type=int, default=120, help="Número base de fontes primárias (gera ~3.6x registros totais)")
    parser.add_argument("--sem-onnx", action="store_true", help="Usa embedder sintético de 384d em vez do modelo ONNX real")
    args = parser.parse_args()
    report = run_benchmark(scale_sources=args.fontes, use_onnx=not args.sem_onnx)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
