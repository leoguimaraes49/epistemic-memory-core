#!/usr/bin/env python3
"""Arnês CLI de estresse concorrente multiprocesso, caos de leases e auditoria epistêmica.

Executa integralmente em diretório descartável dentro de `REAL_SYSTEM / 'testes_temporarios'`
(jamais toca no cofre real) e exercita simultaneamente múltiplos processos reais do SO:
  - Escritores concorrentes de fontes primárias + derivações de conhecimento (com colisão de títulos);
  - Retificadores concorrentes + corrida CAS disputada na mesma fonte (`expected=1`);
  - Leitores híbridos concorrentes com modelo real ONNX E5 (`LocalEmbeddings` 384d + RRF + grafo);
  - Verificadores determinísticos de alegações (`field`, `sum`, `chain`) + invalidação de recibos;
  - Caos de expiração de lease, token fencing anti-zumbi, continuações e retomada em `autonomia.Queue`.

Emite relatório JSON estruturado na saída padrão e encerra com código != 0 se qualquer
invariante criptográfica, transacional ou epistêmica for violada.
"""
from __future__ import annotations

import argparse
import copy
import json
import math
import multiprocessing
import os
import random
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from autonomia import DEFAULTS as AUTONOMY_DEFAULTS, Queue, atomic_json, code_hash
from conhecimento import Knowledge, decode as decode_knowledge
from evidencias import inspect_response, read_receipt
from execucao import DEFAULT as EXECUTION_DEFAULTS, Engine
from nucleo import Conflict, Invalid, Locked, REAL_SYSTEM, Store, Uncertain, parse as parse_source, sha
from recuperacao import LocalEmbeddings, Retrieval
from recuperacao_fila import reconcile_lineage, recover_expired
import verificador_evidencias as verifier


class SyntheticEmbeddings:
    """Fallback determinístico de 384 dimensões usado somente quando `--sem-onnx` ou modelo ausente."""

    dim = 384

    def chunks(self, text: str, kind: str = "passage") -> list[list[float]]:
        vec = [0.0] * self.dim
        tokens = [tok for tok in text.lower().split() if len(tok) > 2] or ["vazio"]
        for pos, tok in enumerate(tokens):
            bucket = (sum((idx + 1) * ord(ch) for idx, ch in enumerate(tok)) + pos * 11) % self.dim
            vec[bucket] += 1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [[v / norm for v in vec]]


def _resolve_embedder(use_onnx: bool) -> tuple[object, bool]:
    emb_env = os.environ.get("EMC_EMBEDDINGS_DIR")
    candidate = Path(emb_env) if emb_env else (ROOT / "modelos" / "e5-multilingual-small")
    if use_onnx and (candidate / "model.onnx").is_file() and (candidate / "tokenizer.json").is_file():
        return LocalEmbeddings(candidate), True
    return SyntheticEmbeddings(), False


def _is_transient_contention(exc: BaseException) -> bool:
    if isinstance(exc, (Locked, sqlite3.OperationalError)):
        return True
    if isinstance(exc, Conflict):
        msg = str(exc).lower()
        transient_markers = (
            "base mudou",
            "ocupado",
            "ainda não confirmada",
            "efeito pendente",
            "outra operação",
        )
        return any(marker in msg for marker in transient_markers)
    return False


def _worker_entry(
    worker_id: int,
    role: str,
    ops: int,
    sys_dir: str,
    vault_dir: str,
    config: dict,
    start_barrier: object,
    result_queue: object,
) -> None:
    rng = random.Random(20261117 + worker_id * 97)
    store = Store(sys_dir, vault_dir)
    knowledge = Knowledge(store)

    embedder = None
    onnx_loaded = False
    if role == "hybrid_onnx_reader":
        embedder, onnx_loaded = _resolve_embedder(bool(config["use_onnx"]))
    elif role == "hybrid_fast_reader":
        embedder, onnx_loaded = SyntheticEmbeddings(), False

    # Sincroniza todos os processos antes de iniciar a janela de contenção real
    start_barrier.wait(timeout=45)
    t0 = time.perf_counter()

    ops_completed = 0
    lock_retries = 0
    cas_won = 0
    cas_conflict = 0
    role_metrics: dict[str, int | bool] = {}
    errors: list[str] = []

    def call_with_retry(fn, max_attempts: int = 12):
        nonlocal lock_retries
        for attempt in range(max_attempts):
            try:
                return fn(attempt)
            except Exception as exc:
                if _is_transient_contention(exc) and attempt + 1 < max_attempts:
                    lock_retries += 1
                    time.sleep(0.015 * (attempt + 1) + rng.uniform(0.002, 0.015))
                    continue
                raise

    try:
        if role == "writer_rectifier":
            person_ids: list[str] = config["person_ids"]
            rectify_targets: list[str] = config["rectify_targets_by_worker"].get(str(worker_id), [])
            contested_id: str = config["contested_source_id"]

            # 1. Disputa CAS simultânea na mesma fonte compartilhada (expected=1)
            for attempt in range(8):
                try:
                    store.apply(
                        f"cas-race-w{worker_id}",
                        "correct",
                        ident=contested_id,
                        expected=1,
                        text=json.dumps({"contested_winner": worker_id, "valor": 777000 + worker_id}),
                        reason=f"Disputa CAS concorrente vencida por worker {worker_id}",
                    )
                    cas_won = 1
                    break
                except (Locked, sqlite3.OperationalError):
                    lock_retries += 1
                    time.sleep(0.01 * (attempt + 1))
                except Conflict:
                    cas_conflict = 1
                    break

            # 2. Escritas concorrentes (incluindo títulos idênticos deliberados) + retificações particionadas
            created_sources = 0
            created_assertions = 0
            rectified_count = 0
            for idx in range(ops):
                same_title = (idx % 3 == 0)
                title = (
                    "Nota Concorrente Mesma Chave Nominal"
                    if same_title
                    else f"Pacote Concorrente W{worker_id} Op {idx:03d}"
                )
                doc = {
                    "worker": worker_id,
                    "op": idx,
                    "orcamento": 5000 + worker_id * 100 + idx * 10,
                    "contingencia": 500 + idx * 5,
                    "aresta_1": [f"w{worker_id}_n{idx}_a", "requires", f"w{worker_id}_n{idx}_b"],
                    "aresta_2": [f"w{worker_id}_n{idx}_b", "requires", f"w{worker_id}_n{idx}_c"],
                    "resumo": f"Entrega operacional gravada sob contenção multiprocesso setorial {idx % 4}.",
                }
                src = call_with_retry(
                    lambda _a, i=idx, t=title, d=doc: store.apply(
                        f"stress-src-w{worker_id}-{i}",
                        "create",
                        title=t,
                        text=json.dumps(d, ensure_ascii=False),
                    )
                )
                created_sources += 1
                ops_completed += 1

                if idx % 2 == 0:
                    pid = person_ids[(worker_id + idx) % len(person_ids)]
                    val = doc["orcamento"]
                    call_with_retry(
                        lambda _a, i=idx, s=src, p=pid, v=val: knowledge.apply(
                            f"stress-ast-w{worker_id}-{i}",
                            "assertion",
                            f"Afirmação Concorrente W{worker_id}-{i}",
                            {
                                "subject_ref": {"record_id": p, "revision": 1},
                                "predicate": "reports_value",
                                "value": {"type": "number", "content": v},
                                "nature": "documented_observation",
                                "asserted_by": f"stress_worker_{worker_id}",
                                "recorded_time": "2026-11-17T18:00:00+00:00",
                                "source_refs": [{"record_id": s["id"], "revision": 1}],
                                "context_description": "Ingestão concorrente de estresse",
                                "valid_time": {"precision": "unknown"},
                                "review_status": "unreviewed",
                            },
                        )
                    )
                    created_assertions += 1
                    ops_completed += 1

                if idx < len(rectify_targets):
                    target_sid = rectify_targets[idx]
                    call_with_retry(
                        lambda _a, i=idx, tid=target_sid: store.apply(
                            f"stress-rect-w{worker_id}-{i}",
                            "correct",
                            ident=tid,
                            expected=1,
                            text=json.dumps(
                                {
                                    "lote_seed": i,
                                    "status": "retificado_sob_estresse",
                                    "custo_base": 99000 + i,
                                    "reserva": 1000,
                                },
                                ensure_ascii=False,
                            ),
                            reason=f"Retificação em cascata pelo worker {worker_id}",
                        )
                    )
                    rectified_count += 1
                    ops_completed += 1

            role_metrics = {
                "created_sources": created_sources,
                "created_assertions": created_assertions,
                "rectified_seed_sources": rectified_count,
            }

        elif role in ("hybrid_onnx_reader", "hybrid_fast_reader"):
            retrieval = Retrieval(store, embedder=embedder)
            queries = [
                "governanca arquitetura pacote setorial",
                "auditoria entrega operacional contenção",
                "orcamento contingencia validacao",
                "iniciativa estrutural consolidada",
                "relatorio concorrente revisao",
            ]
            cache_hits = 0
            non_empty = 0
            for idx in range(ops):
                q = queries[idx % len(queries)]
                res = call_with_retry(lambda _a, q_str=q: retrieval.search(q_str, limit=10, depth=1), max_attempts=16)
                if res.get("cache_reused"):
                    cache_hits += 1
                if res.get("results"):
                    non_empty += 1
                expected_mode = "hybrid_lexical_vector_graph"
                if res.get("mode") != expected_mode:
                    errors.append(f"Modo inesperado na busca híbrida: {res.get('mode')}")
                for item in res.get("results", []):
                    if item["revision"] < 1 or item["id"] != item["record"]["id"]:
                        errors.append(f"Item inconsistente retornado pela busca: {item['id']}")
                ops_completed += 1

            role_metrics = {
                "onnx_e5_loaded": onnx_loaded,
                "queries_executed": ops,
                "non_empty_results": non_empty,
                "cache_reused_count": cache_hits,
            }

        elif role == "claim_verifier":
            anchor_sources: list[dict] = config["immutable_anchor_sources"]
            saved_receipts: list[str] = []
            verified_ok = 0
            stale_detected = 0

            for idx in range(ops):
                target = anchor_sources[idx % len(anchor_sources)]
                sid = target["id"]
                base_val = target["custo_base"]
                res_val = target["reserva"]
                chain_val = [f"anc_{target['slot']}_0", "requires", f"anc_{target['slot']}_2"]
                claims = [
                    {
                        "id": "f1",
                        "kind": "field",
                        "refs": [{"record_id": sid, "revision": 1, "path": "/setor"}],
                        "value": target["setor"],
                    },
                    {
                        "id": "s1",
                        "kind": "sum",
                        "refs": [
                            {"record_id": sid, "revision": 1, "path": "/custo_base"},
                            {"record_id": sid, "revision": 1, "path": "/reserva"},
                        ],
                        "value": base_val + res_val,
                    },
                    {
                        "id": "ch1",
                        "kind": "chain",
                        "refs": [
                            {"record_id": sid, "revision": 1, "path": "/step_1"},
                            {"record_id": sid, "revision": 1, "path": "/step_2"},
                        ],
                        "value": chain_val,
                    },
                ]
                rendered = "\n".join(
                    f"{c['id']} = {verifier.encode(c['value']).decode('utf-8')}" for c in claims
                )
                draft = {"answer_format": "controlled", "answer": rendered, "claims": claims}

                verdict = None
                for stale_retry in range(6):
                    verdict = call_with_retry(
                        lambda attempt, i=idx, sr=stale_retry, d=draft, s=sid: inspect_response(
                            store,
                            f"stress-rcpt-w{worker_id}-{i}-s{sr}-a{attempt}",
                            d,
                            context_ids=[s],
                            max_context=8,
                        ),
                        max_attempts=16,
                    )
                    if verdict["status"] == "stale" and verdict.get("route") == "revalidation_required":
                        # Outro processo avançou a geração do cofre no intervalo entre persistir e reler o recibo
                        stale_detected += 1
                        lock_retries += 1
                        saved_receipts.append(verdict["receipt_id"])
                        time.sleep(0.02 * (stale_retry + 1))
                        continue
                    break

                if verdict["status"] == "verified" and verdict["answer_verified"]:
                    verified_ok += 1
                    saved_receipts.append(verdict["receipt_id"])
                elif verdict["status"] == "stale" and verdict.get("route") == "revalidation_required":
                    stale_detected += 1
                else:
                    errors.append(f"Falha inesperada em recibo íntegro {idx}: {verdict}")
                ops_completed += 1

                if saved_receipts and idx % 3 == 2:
                    oldest = saved_receipts[0]
                    rechecked = call_with_retry(lambda _a, rid=oldest: read_receipt(store, rid), max_attempts=12)
                    if rechecked["status"] == "stale":
                        stale_detected += 1
                    elif rechecked["status"] != "verified":
                        errors.append(f"Status inesperado ao reler recibo {oldest}: {rechecked}")

            role_metrics = {
                "receipts_verified": verified_ok,
                "stale_transitions_observed_live": stale_detected,
            }

        elif role == "autonomia_lease_chaos":
            queue = Queue(store)
            engine = Engine(store)
            leases_recovered = 0
            zombie_blocks = 0
            continuations_dispatched = 0
            exhausted_failed = 0
            expired_demands_recovered = 0

            base_clock = time.time()
            lease_cycles = max(3, min(ops, 10))
            for idx in range(lease_cycles):
                step_now = base_clock + idx * 120.0
                enq = call_with_retry(
                    lambda _a, i=idx, t=step_now: queue.enqueue(
                        f"stress-lease-job-w{worker_id}-{i}",
                        "audit_vault" if i % 2 == 0 else "refresh_view",
                        now=t,
                    )
                )
                claimed_1 = call_with_retry(
                    lambda _a, i=idx, t=step_now: queue.claim(f"zombie-worker-{worker_id}-{i}", now=t)
                )
                if not claimed_1:
                    errors.append(f"Queue.claim retornou vazio no ciclo {idx} para {enq['id']}")
                    continue

                # Simula expiração da reserva (lease_until ultrapassado) e reaquisição por novo trabalhador
                after_expiry = float(claimed_1["lease_until"]) + 2.0
                claimed_2 = call_with_retry(
                    lambda _a, i=idx, t=after_expiry: queue.claim(f"healthy-worker-{worker_id}-{i}", now=t)
                )
                if not claimed_2 or claimed_2["id"] != claimed_1["id"] or claimed_2["attempts"] < 2:
                    errors.append(f"Falha ao recuperar lease vencido no ciclo {idx}: {claimed_2}")
                    continue
                leases_recovered += 1

                # Trabalhador zumbi atrasado deve ser barrado por token fencing!
                try:
                    queue.finish(
                        claimed_1["id"],
                        claimed_1["token"],
                        result={"zombie_write": True},
                        now=after_expiry + 0.5,
                    )
                    errors.append(f"Violação crítica: token zumbi aceito em {claimed_1['id']}!")
                except Conflict:
                    zombie_blocks += 1

                # Trabalhador legítimo conclui e publica continuação congelada
                done = call_with_retry(
                    lambda _a, c2=claimed_2, t=after_expiry: queue.finish(
                        c2["id"],
                        c2["token"],
                        result={"ok": True, "cycle": idx},
                        now=t + 1.0,
                    )
                )
                if done["execution_status"] != "completed":
                    errors.append(f"Job deveria concluir como completed: {done}")
                dispatched = call_with_retry(lambda _a: queue.dispatch_continuations(limit=10))
                for child_id in dispatched:
                    # Cancela os filhos gerados para manter a fila enxuta para os próximos ciclos de lease
                    call_with_retry(lambda _a, cid=child_id: queue.cancel(cid))
                continuations_dispatched += len(dispatched)
                ops_completed += 1

            # Testa exaustão de tentativas (max_attempts=3) -> failed após 3 leases vencidos
            t_ex = base_clock + (lease_cycles + 2) * 120.0
            ex_job = call_with_retry(lambda _a: queue.enqueue(f"stress-exhaust-w{worker_id}", "refresh_view", now=t_ex))
            cur_t = t_ex
            for attempt_idx in range(3):
                claimed = call_with_retry(lambda _a, t=cur_t: queue.claim(f"crash-{attempt_idx}", now=t))
                if not claimed or claimed["id"] != ex_job["id"]:
                    errors.append(f"Job de exaustão não obtido na tentativa {attempt_idx}: {claimed}")
                    break
                cur_t = float(claimed["lease_until"]) + 2.0
            with queue.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                queue.recover(conn, cur_t)
            final_ex = queue.get(ex_job["id"])
            if final_ex["execution_status"] == "failed":
                exhausted_failed += 1
            else:
                errors.append(f"Job exaurido deveria estar failed: {final_ex}")
            ops_completed += 1

            # Testa recuperação determinística de demanda expirada (`recover_expired` + `reconcile_lineage`)
            demand_id = call_with_retry(
                lambda _a: engine.start(
                    f"stress-exp-demand-w{worker_id}",
                    "contribution",
                    {
                        "title": f"Contribuição Expirada W{worker_id}",
                        "text": "Relato conversacional preservado aguardando retomada segura.",
                    },
                )
            )
            past_t = time.time() - 2500.0
            exp_job = call_with_retry(
                lambda _a: queue.enqueue(
                    f"demand-exp-w{worker_id}",
                    "plan_demand",
                    now=past_t,
                    payload={"execution_id": demand_id},
                )
            )
            with engine.q.connect() as conn:
                conn.execute(
                    "UPDATE demands SET created=created-2500, deadline=deadline-2500 WHERE id=?",
                    (demand_id,),
                )
            with queue.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                queue.recover(conn, time.time())
            if queue.get(exp_job["id"])["execution_status"] != "failed":
                errors.append("Job expirado não transitou para failed por prazo total excedido")

            recovered_list = call_with_retry(lambda _a: recover_expired(queue, engine, limit=2), max_attempts=16)
            second_pass = call_with_retry(lambda _a: recover_expired(queue, engine, limit=2), max_attempts=16)
            projected = call_with_retry(
                lambda _a: reconcile_lineage(queue, engine, [{"id": demand_id, "status": "superseded"}]),
                max_attempts=12,
            )
            if len(recovered_list) == 1 and second_pass == [] and projected[0]["lineage_verified"]:
                expired_demands_recovered += 1
            else:
                errors.append(
                    f"Falha em recover_expired/reconcile_lineage: rec={recovered_list}, again={second_pass}, proj={projected}"
                )
            ops_completed += 1

            role_metrics = {
                "leases_expired_and_recovered": leases_recovered,
                "zombie_fencing_blocks": zombie_blocks,
                "continuations_dispatched": continuations_dispatched,
                "exhausted_jobs_failed": exhausted_failed,
                "expired_demands_recovered": expired_demands_recovered,
                "lineage_verified": bool(projected and projected[0]["lineage_verified"]),
            }

        else:
            errors.append(f"Papel desconhecido: {role}")

    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")

    elapsed = time.perf_counter() - t0
    result_queue.put(
        {
            "worker_id": worker_id,
            "role": role,
            "elapsed_seconds": round(elapsed, 3),
            "ops_completed": ops_completed,
            "lock_retries": lock_retries,
            "cas_won": cas_won,
            "cas_conflict": cas_conflict,
            "metrics": role_metrics,
            "errors": errors,
        }
    )


def run_stress(workers: int = 6, ops: int = 15, use_onnx: bool = True) -> dict:
    if workers < 1 or ops < 1:
        raise ValueError("workers e ops devem ser inteiros >= 1")

    temp_base = REAL_SYSTEM / "testes_temporarios"
    temp_base.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="stress-caos-", dir=temp_base) as tmp:
        base = Path(tmp)
        sys_root = base / "sistema"
        vault_root = base / "cofre"
        store = Store(sys_root, vault_root)
        knowledge = Knowledge(store)

        # Configura manifesto isolado do manual + execucao.json + autonomia.json para Engine e Queue
        manual_dir = vault_root / "00_Manual"
        manual_dir.mkdir(parents=True, exist_ok=True)
        manual_bytes = b"# Manual ficticio isolado para estresse de caos e concorrencia.\n"
        (manual_dir / "ficticio.md").write_bytes(manual_bytes)
        atomic_json(sys_root / "manual_manifest.json", {"ficticio.md": sha(manual_bytes)})

        exec_cfg = copy.deepcopy(EXECUTION_DEFAULTS)
        exec_cfg.update(enabled=True, retrieval_policy="lexical", auto_adopt_config=False, auto_process_sources=False)
        exec_cfg["model"] = {"enabled": False}
        exec_cfg["embeddings"] = {"enabled": False}
        atomic_json(sys_root / "execucao.json", exec_cfg)

        queue = Queue(store)
        auto_cfg = dict(
            AUTONOMY_DEFAULTS,
            enabled=True,
            content_access="permitido",
            max_jobs_per_hour=120,
            max_pending_jobs=500,
            max_attempts=3,
            job_timeout_seconds=2,
            job_lifetime_seconds=600,
            retry_base_seconds=1,
            approved_code=code_hash(),
        )
        atomic_json(queue.config_path, auto_cfg)

        # Semeia grafo base determinístico:
        # - 6 fontes-semente que serão retificadas sob contenção (gerando cascata stale)
        # - 4 fontes-âncora imutáveis (para testar que seus derivados permanecem 100% válidos + recibos)
        # - 1 fonte disputada para corrida CAS (`expected=1`)
        rectifiable_seeds: list[dict] = []
        immutable_anchors: list[dict] = []
        sectors = ("arquitetura", "seguranca", "governanca", "operacoes")

        for idx in range(6):
            sec = sectors[idx % len(sectors)]
            s = store.apply(
                f"seed-rect-{idx}",
                "create",
                title=f"Fonte Semente Retificável {idx:02d}",
                text=json.dumps(
                    {
                        "lote_seed": idx,
                        "setor": sec,
                        "custo_base": 10000 + idx * 500,
                        "reserva": 1200 + idx * 100,
                    },
                    ensure_ascii=False,
                ),
            )
            rectifiable_seeds.append(s)

        for slot in range(4):
            sec = sectors[slot % len(sectors)]
            custo = 20000 + slot * 750
            reserva = 2500 + slot * 125
            a_src = store.apply(
                f"seed-anchor-{slot}",
                "create",
                title=f"Fonte Âncora Imutável {slot:02d}",
                text=json.dumps(
                    {
                        "slot": slot,
                        "setor": sec,
                        "custo_base": custo,
                        "reserva": reserva,
                        "step_1": [f"anc_{slot}_0", "requires", f"anc_{slot}_1"],
                        "step_2": [f"anc_{slot}_1", "requires", f"anc_{slot}_2"],
                    },
                    ensure_ascii=False,
                ),
            )
            immutable_anchors.append(
                {
                    "id": a_src["id"],
                    "slot": slot,
                    "setor": sec,
                    "custo_base": custo,
                    "reserva": reserva,
                }
            )

        contested = store.apply(
            "seed-contested-cas",
            "create",
            title="Fonte Disputada CAS",
            text=json.dumps({"contested_winner": None, "valor": 1}),
        )

        # Entidades de pessoa apoiadas em fontes-âncora imutáveis (para não ficarem stale)
        person_ids: list[str] = []
        for p_idx in range(4):
            anchor_id = immutable_anchors[p_idx % len(immutable_anchors)]["id"]
            p = knowledge.apply(
                f"seed-person-{p_idx}",
                "entity",
                f"Especialista {p_idx}",
                {
                    "entity_kind": "person",
                    "display_name": f"Especialista {p_idx}",
                    "identity_status": "identified",
                    "origin_refs": [{"record_id": anchor_id, "revision": 1}],
                },
            )
            person_ids.append(p["id"])

        # Grafo de linhagem para validar precisão exata de stale-on-write em cascata:
        # - Para cada fonte retificável: Assertion_R -> Synthesis_R (ambos DEVEM ficar stale após retificação!)
        # - Para cada fonte imutável: Assertion_I -> Synthesis_I (ambos NÃO podem ficar stale!)
        stale_lineage_by_source: dict[str, list[str]] = {}
        active_control_ids: set[str] = set(person_ids)

        for idx, r_src in enumerate(rectifiable_seeds):
            ast = knowledge.apply(
                f"seed-ast-rect-{idx}",
                "assertion",
                f"Afirmação Sensível {idx:02d}",
                {
                    "subject_ref": {"record_id": person_ids[idx % len(person_ids)], "revision": 1},
                    "predicate": "reports_value",
                    "value": {"type": "number", "content": 10000 + idx * 500},
                    "nature": "documented_observation",
                    "asserted_by": "seed_harness",
                    "recorded_time": "2026-11-17T12:00:00+00:00",
                    "source_refs": [{"record_id": r_src["id"], "revision": 1}],
                    "context_description": "Base para teste de cascata stale",
                    "valid_time": {"precision": "unknown"},
                    "review_status": "unreviewed",
                },
            )
            syn = knowledge.apply(
                f"seed-syn-rect-{idx}",
                "synthesis",
                f"Síntese Dependente {idx:02d}",
                {
                    "synthesis_kind": "knowledge_summary",
                    "content": f"Síntese derivada da afirmação {idx} na arquitetura setorial.",
                    "scope": "Teste de cascata",
                    "basis_refs": [{"record_id": ast["id"], "revision": 1}],
                    "limitations": ["Amostra sintética"],
                    "coverage_status": "supported_within_scope",
                    "as_of": "2026-11-17",
                },
            )
            stale_lineage_by_source[r_src["id"]] = [ast["id"], syn["id"]]

        for slot, a_info in enumerate(immutable_anchors):
            ast = knowledge.apply(
                f"seed-ast-imm-{slot}",
                "assertion",
                f"Afirmação Estável {slot:02d}",
                {
                    "subject_ref": {"record_id": person_ids[slot % len(person_ids)], "revision": 1},
                    "predicate": "reports_value",
                    "value": {"type": "number", "content": a_info["custo_base"]},
                    "nature": "documented_observation",
                    "asserted_by": "seed_harness",
                    "recorded_time": "2026-11-17T12:00:00+00:00",
                    "source_refs": [{"record_id": a_info["id"], "revision": 1}],
                    "context_description": "Controle negativo de cascata",
                    "valid_time": {"precision": "unknown"},
                    "review_status": "unreviewed",
                },
            )
            syn = knowledge.apply(
                f"seed-syn-imm-{slot}",
                "synthesis",
                f"Síntese Estável {slot:02d}",
                {
                    "synthesis_kind": "knowledge_summary",
                    "content": f"Síntese estável apoiada em âncora imutável {slot}.",
                    "scope": "Controle de cascata",
                    "basis_refs": [{"record_id": ast["id"], "revision": 1}],
                    "limitations": ["Amostra sintética"],
                    "coverage_status": "supported_within_scope",
                    "as_of": "2026-11-17",
                },
            )
            active_control_ids.update((ast["id"], syn["id"]))

        # Gera comprovante inicial antes do estresse (deve virar stale após mutações!)
        pre_stress_receipt = inspect_response(
            store,
            "pre-stress-baseline-receipt",
            {
                "answer_format": "controlled",
                "answer": f"c1 = {10000}",
                "claims": [
                    {
                        "id": "c1",
                        "kind": "field",
                        "refs": [{"record_id": rectifiable_seeds[0]["id"], "revision": 1, "path": "/custo_base"}],
                        "value": 10000,
                    }
                ],
            },
        )

        # Distribui papéis entre os `--workers` processos
        canonical_roles = [
            "writer_rectifier",
            "writer_rectifier",
            "hybrid_onnx_reader",
            "hybrid_fast_reader",
            "claim_verifier",
            "autonomia_lease_chaos",
        ]
        if workers >= 6:
            assigned_roles = [canonical_roles[i] if i < 6 else canonical_roles[i % 4] for i in range(workers)]
        elif workers == 1:
            assigned_roles = ["writer_rectifier"]
        else:
            # Garante ao menos 1 escritor/retificador e distribui os demais papéis essenciais
            priority_roles = [
                "writer_rectifier",
                "hybrid_onnx_reader",
                "claim_verifier",
                "autonomia_lease_chaos",
                "hybrid_fast_reader",
            ]
            assigned_roles = [priority_roles[i % len(priority_roles)] for i in range(workers)]

        writer_indices = [idx for idx, r in enumerate(assigned_roles) if r == "writer_rectifier"]
        rectify_targets_by_worker: dict[str, list[str]] = {str(w): [] for w in writer_indices}
        for idx, r_src in enumerate(rectifiable_seeds):
            owner_w = writer_indices[idx % len(writer_indices)]
            rectify_targets_by_worker[str(owner_w)].append(r_src["id"])

        worker_config = {
            "use_onnx": use_onnx,
            "person_ids": person_ids,
            "rectify_targets_by_worker": rectify_targets_by_worker,
            "contested_source_id": contested["id"],
            "immutable_anchor_sources": immutable_anchors,
        }

        mp_ctx = multiprocessing.get_context("spawn")
        barrier = mp_ctx.Barrier(workers)
        out_queue = mp_ctx.Queue()
        processes = [
            mp_ctx.Process(
                target=_worker_entry,
                args=(
                    w_id,
                    assigned_roles[w_id],
                    ops,
                    str(sys_root),
                    str(vault_root),
                    worker_config,
                    barrier,
                    out_queue,
                ),
            )
            for w_id in range(workers)
        ]

        wall_t0 = time.perf_counter()
        for proc in processes:
            proc.start()

        worker_reports: list[dict] = []
        for _ in processes:
            worker_reports.append(out_queue.get(timeout=120))

        violations: list[str] = []
        for proc in processes:
            proc.join(timeout=30)
            if proc.is_alive():
                proc.terminate()
                proc.join(5)
                violations.append(f"Processo PID {proc.pid} travou após envio de resultado")
            elif proc.exitcode != 0:
                violations.append(f"Processo PID {proc.pid} encerrou com exitcode={proc.exitcode}")

        wall_elapsed = time.perf_counter() - wall_t0
        worker_reports.sort(key=lambda item: item["worker_id"])

        for wrep in worker_reports:
            for err in wrep["errors"]:
                violations.append(f"worker[{wrep['worker_id']}:{wrep['role']}]: {err}")

        # Se workers < 4 não incluiu autonomia_lease_chaos, executa uma passagem local rápida para telemetria completa
        if not any(w["role"] == "autonomia_lease_chaos" for w in worker_reports):
            local_b = multiprocessing.Barrier(1)
            local_q = mp_ctx.Queue()
            _worker_entry(
                workers,
                "autonomia_lease_chaos",
                min(ops, 4),
                str(sys_root),
                str(vault_root),
                worker_config,
                local_b,
                local_q,
            )
            extra = local_q.get(timeout=15)
            for err in extra["errors"]:
                violations.append(f"fallback_autonomia: {err}")
            worker_reports.append(extra)

        # =====================================================================
        # AUDITORIA CRIPTOGRÁFICA SHA-256 E INVARIANTES EPISÊMICAS PÓS-CAOS
        # =====================================================================
        fresh_store = Store(sys_root, vault_root)
        fresh_k = Knowledge(fresh_store)

        sources_verified = 0
        revision_archives_verified = 0
        unconfirmed_source_ops = 0
        with fresh_store.connect() as conn:
            src_rows = conn.execute("SELECT id, filename, revision, digest FROM records").fetchall()
            unconfirmed_source_ops = conn.execute(
                "SELECT COUNT(*) FROM operations WHERE status != 'confirmed' OR pending IS NOT NULL"
            ).fetchone()[0]
        if unconfirmed_source_ops != 0:
            violations.append(f"Operações pendentes residuais em controle.sqlite3: {unconfirmed_source_ops}")

        rectified_seed_ids: set[str] = set()
        seed_id_set = {s["id"] for s in rectifiable_seeds}
        for sid, fname, rev, expected_digest in src_rows:
            fpath = fresh_store.safe_path(fname)
            raw = fpath.read_bytes()
            if sha(raw) != expected_digest:
                violations.append(f"Divergência SHA-256 em fonte {sid} ({fname})")
            parsed = parse_source(raw)
            if parsed["id"] != sid or parsed["revision"] != rev:
                violations.append(f"Divergência cabeçalho/banco em fonte {sid}")
            sources_verified += 1
            if sid in seed_id_set and rev >= 2:
                rectified_seed_ids.add(sid)
            for old_rev in range(1, rev):
                hist_file = sys_root / "estado" / "revisoes" / sid / f"{old_rev}.md"
                if not hist_file.is_file():
                    violations.append(f"Histórico ausente para fonte {sid} rev {old_rev}")
                else:
                    hist_parsed = parse_source(hist_file.read_bytes())
                    if hist_parsed["id"] != sid or hist_parsed["revision"] != old_rev:
                        violations.append(f"Histórico corrompido para fonte {sid} rev {old_rev}")
                    revision_archives_verified += 1

        managed_verified = 0
        unconfirmed_k_ops = 0
        with fresh_k.connect() as conn:
            k_rows = conn.execute("SELECT id, path, digest, revision FROM managed").fetchall()
            unconfirmed_k_ops = conn.execute(
                "SELECT COUNT(*) FROM operations WHERE status != 'confirmed' OR data IS NOT NULL"
            ).fetchone()[0]
        if unconfirmed_k_ops != 0:
            violations.append(f"Operações pendentes residuais em conhecimento.sqlite3: {unconfirmed_k_ops}")

        for kid, rel_path, expected_digest, rev in k_rows:
            kpath = vault_root / rel_path
            if not kpath.is_file():
                violations.append(f"Arquivo gerenciado ausente: {rel_path}")
                continue
            raw = kpath.read_bytes()
            if sha(raw) != expected_digest:
                violations.append(f"Divergência SHA-256 em conhecimento {kid} ({rel_path})")
            decoded = decode_knowledge(raw)
            if decoded["id"] != kid or decoded["revision"] != rev:
                violations.append(f"Divergência cabeçalho/banco em conhecimento {kid}")
            managed_verified += 1

        audit_res = fresh_k.audit()
        if audit_res["status"] != "ok" or audit_res["issues"] != []:
            violations.append(f"Knowledge.audit() reportou inconsistências: {audit_res}")

        # Valida invariante CAS da fonte disputada: exatamente 1 vencedor (revision == 2)
        total_cas_wins = sum(w["cas_won"] for w in worker_reports)
        contested_note = fresh_store.read(contested["id"])
        if total_cas_wins != 1 or contested_note["revision"] != 2:
            violations.append(
                f"Violação CAS na fonte disputada: wins={total_cas_wins}, revision={contested_note['revision']}"
            )

        # Precisão matemática da invalidação em cascata (`stale-on-write`)
        records_map, _, _ = fresh_k.catalog()
        actual_stale = fresh_k.stale(records_map)
        expected_stale: set[str] = set()
        for r_sid in rectified_seed_ids:
            expected_stale.update(stale_lineage_by_source[r_sid])

        # Verifica que nenhum derivado de fonte não-retificada nem controle negativo ficou stale
        for unrectified_sid in seed_id_set - rectified_seed_ids:
            active_control_ids.update(stale_lineage_by_source[unrectified_sid])

        tp = len(expected_stale & actual_stale)
        fp = len(actual_stale - expected_stale)
        fn = len(expected_stale - actual_stale)
        precision = tp / len(actual_stale) if actual_stale else (1.0 if not expected_stale else 0.0)
        recall = tp / len(expected_stale) if expected_stale else 1.0
        denom = len(expected_stale | actual_stale)
        accuracy = tp / denom if denom else 1.0

        if fp != 0 or fn != 0 or bool(active_control_ids & actual_stale):
            violations.append(
                f"Imprecisão em cascata stale: expected={len(expected_stale)}, actual={len(actual_stale)}, fp={fp}, fn={fn}"
            )

        # Verifica que `Retrieval` exclui 100% dos registros stale e recibo pré-estresse está stale
        final_embedder, final_onnx = _resolve_embedder(use_onnx)
        final_search = Retrieval(fresh_store, embedder=final_embedder).search(
            "arquitetura síntese dependente", limit=30, depth=1
        )
        leaked_stale = [item["id"] for item in final_search["results"] if item["id"] in actual_stale]
        if leaked_stale or final_search["excluded_stale"] != len(actual_stale):
            violations.append(
                f"Vazamento de registros stale na busca híbrida: leaked={leaked_stale}, "
                f"excluded={final_search['excluded_stale']} vs {len(actual_stale)}"
            )

        rechecked_baseline = read_receipt(fresh_store, pre_stress_receipt["receipt_id"])
        if rechecked_baseline["status"] != "stale":
            violations.append(f"Recibo pré-estresse não foi invalidado como stale: {rechecked_baseline}")

        # Verifica recibo determinístico pós-estresse sobre estado quiescente atual
        a0 = immutable_anchors[0]
        post_claims = [
            {"id": "f", "kind": "field", "refs": [{"record_id": a0["id"], "revision": 1, "path": "/setor"}], "value": a0["setor"]},
            {
                "id": "s",
                "kind": "sum",
                "refs": [
                    {"record_id": a0["id"], "revision": 1, "path": "/custo_base"},
                    {"record_id": a0["id"], "revision": 1, "path": "/reserva"},
                ],
                "value": a0["custo_base"] + a0["reserva"],
            },
            {
                "id": "c",
                "kind": "chain",
                "refs": [
                    {"record_id": a0["id"], "revision": 1, "path": "/step_1"},
                    {"record_id": a0["id"], "revision": 1, "path": "/step_2"},
                ],
                "value": ["anc_0_0", "requires", "anc_0_2"],
            },
        ]
        post_ans = "\n".join(f"{c['id']} = {verifier.encode(c['value']).decode('utf-8')}" for c in post_claims)
        post_receipt = inspect_response(
            fresh_store,
            "post-stress-quiescent-receipt",
            {"answer_format": "controlled", "answer": post_ans, "claims": post_claims},
        )
        if post_receipt["status"] != "verified" or not post_receipt["answer_verified"]:
            violations.append(f"Recibo pós-estresse falhou: {post_receipt}")

        # Consolida métricas globais
        total_ops = sum(w["ops_completed"] for w in worker_reports)
        total_lock_retries = sum(w["lock_retries"] for w in worker_reports)
        onnx_active = final_onnx or any(bool(w["metrics"].get("onnx_e5_loaded")) for w in worker_reports)
        auto_worker = next((w["metrics"] for w in worker_reports if w["role"] == "autonomia_lease_chaos"), {})

        sha256_passed = (
            unconfirmed_source_ops == 0
            and unconfirmed_k_ops == 0
            and audit_res["issues"] == []
            and sources_verified > 0
            and managed_verified > 0
        )
        cascade_passed = (
            len(rectified_seed_ids) > 0
            and fp == 0
            and fn == 0
            and not leaked_stale
            and rechecked_baseline["status"] == "stale"
        )
        autonomia_passed = (
            int(auto_worker.get("leases_expired_and_recovered", 0)) >= 1
            and int(auto_worker.get("zombie_fencing_blocks", 0)) >= 1
            and int(auto_worker.get("exhausted_jobs_failed", 0)) >= 1
            and int(auto_worker.get("expired_demands_recovered", 0)) >= 1
            and bool(auto_worker.get("lineage_verified", False))
        )
        if not autonomia_passed:
            violations.append(f"Invariantes de autonomia/lease incompletas: {auto_worker}")

        all_passed = (len(violations) == 0) and sha256_passed and cascade_passed and autonomia_passed

        return {
            "status": "passed" if all_passed else "failed",
            "invariants_all_passed": all_passed,
            "config": {
                "workers": workers,
                "ops_per_worker": ops,
                "onnx_e5_active": onnx_active,
            },
            "telemetry": {
                "elapsed_seconds": round(wall_elapsed, 3),
                "total_operations": total_ops,
                "ops_per_sec": round(total_ops / max(wall_elapsed, 1e-6), 2),
                "lock_retries": total_lock_retries,
                "contested_cas_winner_count": total_cas_wins,
                "contested_cas_conflicts": sum(w["cas_conflict"] for w in worker_reports),
            },
            "sha256_audit": {
                "sources_verified": sources_verified,
                "managed_knowledge_verified": managed_verified,
                "revision_archives_verified": revision_archives_verified,
                "unconfirmed_proposals": unconfirmed_source_ops + unconfirmed_k_ops,
                "catalog_structural_issues": len(audit_res["issues"]),
                "passed": sha256_passed,
            },
            "cascade_stale_accuracy": {
                "rectified_sources": len(rectified_seed_ids),
                "expected_stale_count": len(expected_stale),
                "actual_stale_count": len(actual_stale),
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "accuracy": round(accuracy, 4),
                "retrieval_excluded_stale_matches": (not leaked_stale)
                and (final_search["excluded_stale"] == len(actual_stale)),
                "receipt_stale_invalidation_verified": rechecked_baseline["status"] == "stale",
                "passed": cascade_passed,
            },
            "autonomia_lease_recovery": {
                **auto_worker,
                "passed": autonomia_passed,
            },
            "workers": worker_reports,
            "violations": violations,
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Arnês de estresse multiprocesso, caos de leases e auditoria SHA-256."
    )
    parser.add_argument("--workers", type=int, default=6, help="Número de processos concorrentes (padrão: 6)")
    parser.add_argument("--ops", type=int, default=15, help="Operações por processo trabalhador (padrão: 15)")
    parser.add_argument("--sem-onnx", action="store_true", help="Usa embeddings sintéticos 384d em vez de ONNX E5 real")
    args = parser.parse_args()

    report = run_stress(workers=args.workers, ops=args.ops, use_onnx=not args.sem_onnx)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["invariants_all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
