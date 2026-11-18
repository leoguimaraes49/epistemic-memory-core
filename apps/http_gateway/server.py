"""Servidor HTTP/REST Endurecido e Motor de Linhagem do Epistemic HTTP Gateway.

Permite que aplicações externas em qualquer linguagem (Node.js, Go, Rust, C#,
webhooks, pipelines e microsserviços) integrem-se ao Epistemic Memory Core via
JSON sobre HTTP local (`127.0.0.1`), preservando integralmente:
- Isolamento entre `30_Fontes` (evidência primária) e conhecimento derivado;
- Pinagem explícita por revisão (`RevRef`) e suspensão transitiva *stale-on-write*;
- Firewall determinístico de atribuição de autoria (`atribuicao.py`);
- Validação canônica de esquemas (`conhecimento.py` + `esquemas.py`);
- Comprovantes criptográficos determinísticos `lab-assurance-2` (`evidencias.py`);
- Busca híbrida RRF lexical + expansão de grafo + vetores ONNX E5 locais.
"""
from __future__ import annotations

import copy
import difflib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any

from .ui import render_gateway_html

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8095
MAX_BODY_BYTES = 65536
_MAX_DRAIN_BYTES = 262144
_DRAIN_CHUNK_BYTES = 16384

_ALLOWED_HOST_RE = re.compile(r"^(?:127\.0\.0\.1|localhost|\[::1\])(?::([1-9]\d{0,4}))?$", re.I)

VAULT_FOLDERS = (
    "00_Manual",
    "10_Entidades",
    "20_Afirmacoes",
    "30_Fontes",
    "40_Avaliacoes",
    "50_Sinteses",
    "60_Questoes",
    "70_Operacao",
    "80_Visoes",
)

CANONICAL_EPISTEME_CLASSES = (
    "30_Fontes",
    "10_Entidades",
    "20_Afirmacoes",
    "50_Sinteses",
    "40_Avaliacoes",
)

_EMBEDDER_CACHE_LOCK = threading.Lock()
_EMBEDDER_CACHE: dict[str, "_ThreadSafeEmbedder"] = {}


class _ThreadSafeEmbedder:
    """Serializa o tokenizer/sessão ONNX compartilhada entre threads do servidor HTTP."""

    def __init__(self, inner: Any, model_dir: Path):
        self._inner = inner
        self.model_dir = model_dir
        self._lock = threading.Lock()

    def chunks(self, text: str, kind: str = "passage") -> list[list[float]]:
        with self._lock:
            return self._inner.chunks(text, kind)


def _load_shared_embedder(candidate: Path) -> _ThreadSafeEmbedder | None:
    resolved = candidate.resolve()
    key = resolved.as_posix()
    with _EMBEDDER_CACHE_LOCK:
        cached = _EMBEDDER_CACHE.get(key)
        if cached is not None:
            return cached
    if not ((resolved / "model.onnx").is_file() and (resolved / "tokenizer.json").is_file()):
        return None
    try:
        from recuperacao import LocalEmbeddings

        raw_embedder = LocalEmbeddings(resolved)
    except Exception:
        return None
    wrapped = _ThreadSafeEmbedder(raw_embedder, resolved)
    with _EMBEDDER_CACHE_LOCK:
        _EMBEDDER_CACHE[key] = wrapped
    return wrapped


def bootstrap_gateway_workspace(workspace_dir: str | Path) -> tuple[Path, Path]:
    """Configura `EMC_SYSTEM` e `EMC_VAULT` para processos CLI dedicados."""
    ws = Path(workspace_dir).resolve()
    sys_root = ws / "sistema"
    vault_root = ws / "cofre"
    os.environ["EMC_SYSTEM"] = str(sys_root)
    os.environ["EMC_VAULT"] = str(vault_root)
    return sys_root, vault_root


def is_allowed_host(host_header: str) -> bool:
    """Valida estritamente o cabeçalho `Host` contra ataques de DNS Rebinding."""
    if not isinstance(host_header, str):
        return False
    match = _ALLOWED_HOST_RE.fullmatch(host_header.strip())
    if not match:
        return False
    port_s = match.group(1)
    return port_s is None or 1 <= int(port_s) <= 65535


def _constant_time_token_eq(supplied: str, expected: str) -> bool:
    if not supplied or not expected:
        return False
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


def _extract_detailed_rev_refs(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Extrai todas as referências versionadas (`RevRef`) preservando o campo de origem."""
    import esquemas

    detailed: list[dict[str, Any]] = []
    for field_name in esquemas.LIST_REFS:
        items = payload.get(field_name)
        if isinstance(items, list):
            for ref in items:
                if isinstance(ref, dict) and isinstance(ref.get("record_id"), str):
                    entry: dict[str, Any] = {
                        "field": field_name,
                        "record_id": ref["record_id"],
                        "revision": ref.get("revision"),
                    }
                    if "fragment" in ref:
                        entry["fragment"] = ref["fragment"]
                    detailed.append(entry)
    for field_name in esquemas.SINGLE_REFS:
        ref = payload.get(field_name)
        if isinstance(ref, dict) and isinstance(ref.get("record_id"), str):
            entry = {
                "field": field_name,
                "record_id": ref["record_id"],
                "revision": ref.get("revision"),
            }
            if "fragment" in ref:
                entry["fragment"] = ref["fragment"]
            detailed.append(entry)
    if payload.get("review_status") in ("confirmed_by_user", "disputed_by_user"):
        events = payload.get("review_events")
        if isinstance(events, list) and events and isinstance(events[-1], dict):
            sref = events[-1].get("source_ref")
            if isinstance(sref, dict) and isinstance(sref.get("record_id"), str):
                detailed.append(
                    {
                        "field": "review_events.source_ref",
                        "record_id": sref["record_id"],
                        "revision": sref.get("revision"),
                    }
                )
    return detailed


def _summarize_record(rec: dict[str, Any]) -> str:
    p = rec.get("payload", {})
    rtype = rec.get("record_type")
    if rtype == "source":
        txt = str(p.get("content", ""))
        return txt[:160] + ("..." if len(txt) > 160 else "")
    if rtype == "entity":
        detail = (
            p.get("display_name")
            or p.get("purpose")
            or p.get("situation")
            or p.get("outcome_description")
            or p.get("suggestion")
            or p.get("content")
            or rec.get("title", "")
        )
        return f"[{p.get('entity_kind')}] {detail}"[:180]
    if rtype == "assertion":
        val = (
            p.get("value", {}).get("content")
            if isinstance(p.get("value"), dict)
            else p.get("object_ref", {}).get("record_id", "")[:8]
        )
        return f"{p.get('predicate')} -> {val} ({p.get('nature')}, {p.get('review_status')})"
    if rtype == "synthesis":
        return str(p.get("content", ""))[:160]
    if rtype == "question":
        return f"{p.get('question_text')} [{p.get('resolution_status')}]"
    if rtype == "assessment_score":
        return f"Scores: {json.dumps(p.get('dimension_scores', {}), ensure_ascii=False)} [{p.get('score_validity_status')}]"
    return str(rec.get("title", ""))


class EpistemicGatewayRuntime:
    """Adaptador concorrente e governado sobre Store, Knowledge, Retrieval e Evidencias."""

    def __init__(
        self,
        system_root: str | Path,
        vault_root: str | Path,
        *,
        enable_embeddings: bool = True,
        scope: str = "proprietario_local",
    ):
        from autonomia import atomic_json
        from conhecimento import Knowledge
        from execucao import DEFAULT
        from nucleo import REAL_SYSTEM, Store, config_file
        from recuperacao import Retrieval

        self._lock = threading.RLock()
        self.scope = scope
        self.system_root = Path(system_root).resolve()
        self.vault_root = Path(vault_root).resolve()
        self.system_root.mkdir(parents=True, exist_ok=True)
        self.vault_root.mkdir(parents=True, exist_ok=True)
        for folder in VAULT_FOLDERS:
            (self.vault_root / folder).mkdir(parents=True, exist_ok=True)

        manifest_src = config_file(REPO_ROOT, "manual_manifest.json")
        if not manifest_src.exists():
            manifest_src = config_file(REAL_SYSTEM, "manual_manifest.json")
        manifest = json.loads(manifest_src.read_text(encoding="utf-8"))
        manual_src_dir = REPO_ROOT / "00_Manual"
        for name in manifest:
            dest = self.vault_root / "00_Manual" / name
            if not dest.exists() and (manual_src_dir / name).is_file():
                dest.write_bytes((manual_src_dir / name).read_bytes())

        if not (self.system_root / "manual_manifest.json").exists():
            atomic_json(self.system_root / "manual_manifest.json", manifest)

        self.store = Store(self.system_root, self.vault_root)
        self.knowledge = Knowledge(self.store)

        self.embeddings_requested = bool(enable_embeddings)
        emb_env = os.environ.get("EMC_EMBEDDINGS_DIR")
        self.embeddings_candidate_dir = (
            Path(emb_env).resolve() if emb_env else (REPO_ROOT / "modelos" / "e5-multilingual-small").resolve()
        )
        self.embedder = _load_shared_embedder(self.embeddings_candidate_dir) if self.embeddings_requested else None

        cfg_path = config_file(self.system_root, "execucao.json")
        if not cfg_path.exists():
            cfg = copy.deepcopy(DEFAULT)
            cfg["enabled"] = True
            cfg["embeddings"] = {
                "enabled": self.embedder is not None,
                "folder": self.embeddings_candidate_dir.as_posix(),
            }
            atomic_json(self.system_root / "execucao.json", cfg)

        self.retrieval = Retrieval(self.store, embedder=self.embedder, scope=self.scope)

    @classmethod
    def from_workspace(
        cls,
        workspace_dir: str | Path,
        *,
        enable_embeddings: bool = True,
        scope: str = "proprietario_local",
    ) -> "EpistemicGatewayRuntime":
        ws = Path(workspace_dir).resolve()
        return cls(ws / "sistema", ws / "cofre", enable_embeddings=enable_embeddings, scope=scope)

    def _check_access_gate(self) -> None:
        from nucleo import REAL_SYSTEM

        if (self.system_root / "estado" / "implantacao.lock").exists():
            raise PermissionError("Atualização do serviço em andamento (implantacao.lock ativo).")
        if self.system_root == REAL_SYSTEM and os.environ.get("CEREBRO_PESSOAL_ACESSO") != "permitido":
            raise PermissionError("Acesso ao cofre pessoal desabilitado (defina CEREBRO_PESSOAL_ACESSO=permitido).")

    def _catalog_metadata(
        self,
        records: dict[str, dict[str, Any]],
        paths: dict[str, Path],
    ) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
        """Retorna mapas `(file_sha256, folder_posix, episteme_class)` por `record_id`."""
        from conhecimento import FOLDERS
        from evidencias import digest as canonical_digest
        from nucleo import read_exclusive, sha

        with self.store.connect() as conn:
            src_rows = {row[0]: (row[1], row[2]) for row in conn.execute("SELECT id, filename, digest FROM records")}
        with self.knowledge.connect() as conn:
            knw_rows = {row[0]: (row[1], row[2]) for row in conn.execute("SELECT id, path, digest FROM managed")}

        digests: dict[str, str] = {}
        folders: dict[str, str] = {}
        classes: dict[str, str] = {}

        for ident, rec in records.items():
            rtype = rec["record_type"]
            if rtype == "source":
                folder = "30_Fontes"
                if ident in src_rows:
                    digests[ident] = src_rows[ident][1]
                else:
                    digests[ident] = canonical_digest(rec)
            else:
                if ident in knw_rows:
                    rel_posix = str(knw_rows[ident][0]).replace("\\", "/")
                    folder = PurePosixPath(rel_posix).parent.as_posix()
                    digests[ident] = knw_rows[ident][1]
                elif ident in paths:
                    rel_posix = paths[ident].relative_to(self.vault_root).as_posix()
                    folder = PurePosixPath(rel_posix).parent.as_posix()
                    digests[ident] = sha(read_exclusive(paths[ident]))
                else:
                    folder = FOLDERS.get(rtype, "70_Operacao")
                    digests[ident] = canonical_digest(rec)
            folders[ident] = folder
            classes[ident] = folder.split("/")[0]
        return digests, folders, classes

    @staticmethod
    def _record_status(ident: str, rec: dict[str, Any], stale_ids: set[str]) -> str:
        if ident in stale_ids:
            return "suspended"
        payload = rec.get("payload", {})
        if payload.get("adoption_status") == "superseded" or payload.get("identity_status") == "merged":
            return "superseded"
        return "active"

    def _archived_revisions_for(
        self,
        ident: str,
        rec: dict[str, Any],
        folder: str,
        episteme_class: str,
    ) -> list[dict[str, Any]]:
        from conhecimento import decode
        from nucleo import parse, sha

        rtype = rec["record_type"]
        hist_dir = (
            self.system_root / "estado" / "revisoes" / ident
            if rtype == "source"
            else self.system_root / "estado" / "conhecimento_revisoes" / ident
        )
        if not hist_dir.is_dir():
            return []
        entries: list[dict[str, Any]] = []
        for path in sorted(hist_dir.glob("*.md"), key=lambda p: int(p.stem) if p.stem.isdigit() else 0):
            if not path.stem.isdigit() or path.is_symlink():
                continue
            rev_num = int(path.stem)
            raw = path.read_bytes()
            file_hash = sha(raw)
            title = rec["title"]
            updated_at = None
            try:
                parsed = parse(raw) if rtype == "source" else decode(raw)
                title = parsed.get("title", title)
                updated_at = parsed.get("updated_at")
            except Exception:
                pass
            entries.append(
                {
                    "record_id": ident,
                    "revision": rev_num,
                    "superseded_by_revision": rec["revision"],
                    "status": "superseded",
                    "record_type": rtype,
                    "episteme_class": episteme_class,
                    "folder": folder,
                    "title": title,
                    "updated_at": updated_at,
                    "sha256": file_hash,
                }
            )
        return entries

    def _revision_diff(self, ident: str, rec: dict[str, Any], old_rev: int, new_rev: int) -> list[str]:
        from conhecimento import decode
        from nucleo import parse

        rtype = rec["record_type"]
        hist_file = (
            self.system_root / "estado" / "revisoes" / ident / f"{old_rev}.md"
            if rtype == "source"
            else self.system_root / "estado" / "conhecimento_revisoes" / ident / f"{old_rev}.md"
        )
        if not hist_file.is_file() or hist_file.is_symlink():
            return []
        try:
            old_parsed = parse(hist_file.read_bytes()) if rtype == "source" else decode(hist_file.read_bytes())
        except Exception:
            return []
        if rtype == "source":
            old_lines = str(old_parsed.get("payload", {}).get("content", "")).splitlines()
            new_lines = str(rec.get("payload", {}).get("content", "")).splitlines()
        else:
            old_lines = json.dumps(old_parsed.get("payload", {}), ensure_ascii=False, indent=2, sort_keys=True).splitlines()
            new_lines = json.dumps(rec.get("payload", {}), ensure_ascii=False, indent=2, sort_keys=True).splitlines()
        return list(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=f"revisao_{old_rev}",
                tofile=f"revisao_{new_rev}",
                lineterm="",
            )
        )

    def _reverify_all_receipts(self) -> list[dict[str, Any]]:
        from evidencias import read_json, read_receipt

        resp_dir = self.system_root / "estado" / "comprovantes" / "respostas"
        if not resp_dir.is_dir():
            return []
        out: list[dict[str, Any]] = []
        for path in sorted(resp_dir.glob("*.json")):
            if path.is_symlink():
                continue
            ident = path.stem
            if not re.fullmatch(r"[a-f0-9]{64}", ident):
                continue
            try:
                verdict = read_receipt(self.store, ident, self.scope)
                raw_saved = read_json(path)
                pkt = raw_saved.get("packet", {})
                referenced_ids = sorted(
                    {
                        *(pkt.get("evidence", {}) or {}).keys(),
                        *(
                            ref.get("record_id")
                            for cl in (pkt.get("claims") or [])
                            for ref in (cl.get("refs") or [])
                            if isinstance(ref, dict) and isinstance(ref.get("record_id"), str)
                        ),
                    }
                )
                out.append(
                    {
                        "receipt_id": ident,
                        "format": pkt.get("format", "lab-assurance-2"),
                        "receipt_sha256": pkt.get("receipt_sha256"),
                        "manifest_anchor": raw_saved.get("manifest_anchor"),
                        "referenced_record_ids": referenced_ids,
                        **verdict,
                    }
                )
            except Exception as exc:
                out.append({"receipt_id": ident, "status": "invalid", "reason": str(exc), "referenced_record_ids": []})
        return out

    def health(self) -> dict[str, Any]:
        """Retorna geração criptográfica do cofre, contagens, estado vetorial e problemas estruturais."""
        from nucleo import canon, sha

        with self._lock:
            self._check_access_gate()
            records, paths, issues = self.knowledge.catalog()
            stale_ids = self.knowledge.stale(records)
            generation = sha(canon({"records": records, "issues": issues, "scope": self.scope}).encode())
            digests, folders, classes = self._catalog_metadata(records, paths)

            by_type: dict[str, int] = {}
            by_class: dict[str, int] = {cls_name: 0 for cls_name in CANONICAL_EPISTEME_CLASSES}
            active_count = 0
            suspended_count = 0
            superseded_records_count = 0
            archived_revisions_count = 0

            for ident, rec in records.items():
                rtype = rec["record_type"]
                by_type[rtype] = by_type.get(rtype, 0) + 1
                ep_cls = classes[ident]
                by_class[ep_cls] = by_class.get(ep_cls, 0) + 1
                st = self._record_status(ident, rec, stale_ids)
                if st == "active":
                    active_count += 1
                elif st == "suspended":
                    suspended_count += 1
                else:
                    superseded_records_count += 1
                archived_revisions_count += len(self._archived_revisions_for(ident, rec, folders[ident], ep_cls))

            receipts = self._reverify_all_receipts()
            verified_rc = sum(1 for r in receipts if r.get("status") in ("verified", "claims_verified"))
            stale_rc = sum(1 for r in receipts if r.get("status") == "stale")

            return {
                "status": "ok",
                "service": "epistemic-http-gateway",
                "healthy": len(issues) == 0,
                "generation": generation,
                "scope": self.scope,
                "counts": {
                    "total_records": len(records),
                    "active_records": active_count,
                    "suspended_records": suspended_count,
                    "superseded_records": superseded_records_count,
                    "superseded_revisions": superseded_records_count + archived_revisions_count,
                    "by_record_type": by_type,
                    "by_episteme_class": by_class,
                    "receipts_total": len(receipts),
                    "receipts_verified": verified_rc,
                    "receipts_stale": stale_rc,
                },
                "embeddings": {
                    "requested": self.embeddings_requested,
                    "available": self.embedder is not None,
                    "backend": "onnx-e5-multilingual-small" if self.embedder is not None else None,
                    "retrieval_mode": "hybrid_lexical_vector_graph" if self.embedder is not None else "lexical_and_graph",
                },
                "structural_issues": issues,
            }

    def graph(self, *, include_superseded: bool = False) -> dict[str, Any]:
        """Retorna nós, arestas `RevRef`, resumos SHA-256 e estado `active`/`suspended`/`superseded`."""
        from evidencias import digest as canonical_digest
        from nucleo import canon, sha

        with self._lock:
            self._check_access_gate()
            records, paths, issues = self.knowledge.catalog()
            stale_ids = self.knowledge.stale(records)
            generation = sha(canon({"records": records, "issues": issues, "scope": self.scope}).encode())
            digests, folders, classes = self._catalog_metadata(records, paths)

            nodes: list[dict[str, Any]] = []
            edges: list[dict[str, Any]] = []
            superseded_revisions: list[dict[str, Any]] = []
            by_episteme_class: dict[str, int] = {cls_name: 0 for cls_name in CANONICAL_EPISTEME_CLASSES}
            status_counts = {"active": 0, "suspended": 0, "superseded": 0}

            for ident, rec in sorted(records.items(), key=lambda kv: (kv[1]["record_type"], kv[1]["title"], kv[0])):
                rtype = rec["record_type"]
                folder = folders[ident]
                ep_cls = classes[ident]
                by_episteme_class[ep_cls] = by_episteme_class.get(ep_cls, 0) + 1
                st = self._record_status(ident, rec, stale_ids)
                status_counts[st] = status_counts.get(st, 0) + 1

                rev_refs = _extract_detailed_rev_refs(rec["payload"])
                prev_revs = self._archived_revisions_for(ident, rec, folder, ep_cls)
                superseded_revisions.extend(prev_revs)

                nodes.append(
                    {
                        "id": ident,
                        "record_id": ident,
                        "title": rec["title"],
                        "record_type": rtype,
                        "entity_kind": rec["payload"].get("entity_kind"),
                        "episteme_class": ep_cls,
                        "folder": folder,
                        "revision": rec["revision"],
                        "status": st,
                        "validity": "needs_revalidation" if ident in stale_ids else "current_within_scope",
                        "sha256": digests[ident],
                        "canonical_sha256": canonical_digest(rec),
                        "updated_at": rec.get("updated_at"),
                        "summary": _summarize_record(rec),
                        "rev_refs": rev_refs,
                        "previous_revisions": prev_revs,
                        "is_historical_snapshot": False,
                    }
                )

                for ref in rev_refs:
                    target_id = ref["record_id"]
                    target_rec = records.get(target_id)
                    target_rev = target_rec["revision"] if target_rec is not None else None
                    pinned_rev = ref.get("revision")
                    non_invalidating_trigger = rtype == "question" and ref["field"] == "trigger_refs"
                    outdated = (
                        target_rev is not None
                        and pinned_rev is not None
                        and pinned_rev != target_rev
                        and not non_invalidating_trigger
                    )
                    target_suspended = target_id in stale_ids
                    if outdated:
                        link_status = "outdated_revref"
                    elif target_suspended and rtype != "source":
                        link_status = "target_suspended"
                    else:
                        link_status = "active"
                    rev_ref_obj: dict[str, Any] = {"record_id": target_id, "revision": pinned_rev}
                    if "fragment" in ref:
                        rev_ref_obj["fragment"] = ref["fragment"]
                    edges.append(
                        {
                            "from": ident,
                            "to": target_id,
                            "source": ident,
                            "target": target_id,
                            "field": ref["field"],
                            "rev_ref": rev_ref_obj,
                            "pinned_revision": pinned_rev,
                            "current_target_revision": target_rev,
                            "outdated": outdated,
                            "link_status": link_status,
                        }
                    )

            if include_superseded:
                for hist in superseded_revisions:
                    nodes.append(
                        {
                            "id": f"{hist['record_id']}@v{hist['revision']}",
                            "record_id": hist["record_id"],
                            "title": f"{hist['title']} (Rev {hist['revision']} superada)",
                            "record_type": hist["record_type"],
                            "entity_kind": None,
                            "episteme_class": hist["episteme_class"],
                            "folder": hist["folder"],
                            "revision": hist["revision"],
                            "status": "superseded",
                            "validity": "superseded_revision",
                            "sha256": hist["sha256"],
                            "canonical_sha256": hist["sha256"],
                            "updated_at": hist.get("updated_at"),
                            "summary": f"Revisão histórica v{hist['revision']} substituída pela v{hist['superseded_by_revision']}.",
                            "rev_refs": [],
                            "previous_revisions": [],
                            "is_historical_snapshot": True,
                        }
                    )

            status_counts["superseded_total_with_history"] = status_counts["superseded"] + len(superseded_revisions)
            receipts = self._reverify_all_receipts()

            return {
                "status": "ok",
                "generation": generation,
                "scope": self.scope,
                "counts": status_counts,
                "by_episteme_class": by_episteme_class,
                "issues": issues,
                "nodes": nodes,
                "edges": edges,
                "superseded_revisions": superseded_revisions,
                "receipts": receipts,
            }

    def lineage(self, record_id: str) -> dict[str, Any]:
        """Inspeciona ancestralidade primária (`RevRef`s) e raio de impacto transitivo a jusante."""
        from evidencias import digest as canonical_digest
        from nucleo import canon, sha

        with self._lock:
            self._check_access_gate()
            records, paths, issues = self.knowledge.catalog()
            if record_id not in records:
                raise KeyError(record_id)
            stale_ids = self.knowledge.stale(records)
            generation = sha(canon({"records": records, "issues": issues, "scope": self.scope}).encode())
            digests, folders, classes = self._catalog_metadata(records, paths)

            forward_refs: dict[str, list[dict[str, Any]]] = {}
            reverse_deps: dict[str, list[tuple[str, dict[str, Any]]]] = {rid: [] for rid in records}
            for rid, rdata in records.items():
                drefs = _extract_detailed_rev_refs(rdata["payload"])
                forward_refs[rid] = drefs
                for ref in drefs:
                    tid = ref["record_id"]
                    if tid in reverse_deps and tid != rid:
                        reverse_deps[tid].append((rid, ref))

            rec = records[record_id]
            rec_status = self._record_status(record_id, rec, stale_ids)
            prev_revs = self._archived_revisions_for(record_id, rec, folders[record_id], classes[record_id])
            rev_diff = (
                self._revision_diff(record_id, rec, rec["revision"] - 1, rec["revision"])
                if rec["revision"] > 1
                else []
            )

            # 1. Upstream BFS (fontes primárias e bases intermediárias)
            direct_rev_refs: list[dict[str, Any]] = []
            for ref in forward_refs[record_id]:
                tid = ref["record_id"]
                t_rec = records.get(tid)
                t_rev = t_rec["revision"] if t_rec else None
                outdated = t_rev is not None and ref.get("revision") != t_rev
                direct_rev_refs.append(
                    {
                        "field": ref["field"],
                        "record_id": tid,
                        "pinned_revision": ref.get("revision"),
                        "current_revision": t_rev,
                        "outdated": outdated,
                        "title": t_rec["title"] if t_rec else None,
                        "record_type": t_rec["record_type"] if t_rec else None,
                        "status": self._record_status(tid, t_rec, stale_ids) if t_rec else "missing",
                        "sha256": digests.get(tid),
                    }
                )

            upstream_distances: dict[str, int] = {}
            upstream_pinned: dict[str, set[int]] = {}
            upstream_edges: list[dict[str, Any]] = []
            queue_up: list[tuple[str, int]] = [(record_id, 0)]
            visited_up = {record_id}
            while queue_up:
                curr, dist = queue_up.pop(0)
                for ref in forward_refs.get(curr, []):
                    tid = ref["record_id"]
                    if tid not in records:
                        continue
                    if isinstance(ref.get("revision"), int):
                        upstream_pinned.setdefault(tid, set()).add(ref["revision"])
                    upstream_edges.append(
                        {
                            "from": curr,
                            "to": tid,
                            "field": ref["field"],
                            "pinned_revision": ref.get("revision"),
                            "current_target_revision": records[tid]["revision"],
                            "outdated": ref.get("revision") != records[tid]["revision"],
                        }
                    )
                    if tid not in visited_up:
                        visited_up.add(tid)
                        upstream_distances[tid] = dist + 1
                        queue_up.append((tid, dist + 1))

            upstream_nodes: list[dict[str, Any]] = []
            primary_sources: list[dict[str, Any]] = []
            for uid, dist in sorted(upstream_distances.items(), key=lambda kv: (kv[1], records[kv[0]]["title"])):
                urec = records[uid]
                ust = self._record_status(uid, urec, stale_ids)
                pinned_revs = sorted(upstream_pinned.get(uid, set()))
                pinned_rev = pinned_revs[0] if len(pinned_revs) == 1 else (pinned_revs[-1] if pinned_revs else urec["revision"])
                unode = {
                    "id": uid,
                    "record_id": uid,
                    "title": urec["title"],
                    "record_type": urec["record_type"],
                    "episteme_class": classes[uid],
                    "folder": folders[uid],
                    "revision": urec["revision"],
                    "pinned_revision": pinned_rev,
                    "pinned_revisions": pinned_revs,
                    "outdated": any(pr != urec["revision"] for pr in pinned_revs),
                    "status": ust,
                    "sha256": digests[uid],
                    "hop_distance": dist,
                }
                upstream_nodes.append(unode)
                if urec["record_type"] == "source":
                    primary_sources.append(unode)

            # 2. Downstream BFS (dependentes transitivos / blast radius)
            downstream_distances: dict[str, int] = {}
            downstream_edges: list[dict[str, Any]] = []
            queue_down: list[tuple[str, int]] = [(record_id, 0)]
            visited_down = {record_id}
            while queue_down:
                curr, dist = queue_down.pop(0)
                for dep_id, ref in reverse_deps.get(curr, []):
                    dep_rec = records[dep_id]
                    non_inv = dep_rec["record_type"] == "question" and ref["field"] == "trigger_refs"
                    outdated = ref.get("revision") != records[curr]["revision"] and not non_inv
                    downstream_edges.append(
                        {
                            "from": dep_id,
                            "to": curr,
                            "field": ref["field"],
                            "pinned_revision": ref.get("revision"),
                            "current_target_revision": records[curr]["revision"],
                            "outdated": outdated,
                        }
                    )
                    if dep_id not in visited_down:
                        visited_down.add(dep_id)
                        downstream_distances[dep_id] = dist + 1
                        queue_down.append((dep_id, dist + 1))

            dependents: list[dict[str, Any]] = []
            for did, dist in sorted(downstream_distances.items(), key=lambda kv: (kv[1], records[kv[0]]["record_type"], records[kv[0]]["title"])):
                drec = records[did]
                dst = self._record_status(did, drec, stale_ids)
                causes: list[str] = []
                for ref in forward_refs.get(did, []):
                    tid = ref["record_id"]
                    trec = records.get(tid)
                    if trec and ref.get("revision") != trec["revision"]:
                        if not (drec["record_type"] == "question" and ref["field"] == "trigger_refs"):
                            causes.append(f"RevRef {ref['field']}->{tid[:8]} pinado na v{ref.get('revision')} (atual v{trec['revision']})")
                    elif tid in stale_ids and drec["record_type"] != "source":
                        causes.append(f"Base intermediária {tid[:8]} suspensa")
                dependents.append(
                    {
                        "id": did,
                        "record_id": did,
                        "title": drec["title"],
                        "record_type": drec["record_type"],
                        "episteme_class": classes[did],
                        "folder": folders[did],
                        "revision": drec["revision"],
                        "status": dst,
                        "validity": "needs_revalidation" if did in stale_ids else "current_within_scope",
                        "sha256": digests[did],
                        "hop_distance": dist,
                        "suspension_causes": causes,
                    }
                )

            chain_ids = {record_id, *downstream_distances.keys()}
            all_receipts = self._reverify_all_receipts()
            affected_receipts = [
                rc for rc in all_receipts if chain_ids.intersection(rc.get("referenced_record_ids") or [])
            ]

            suspended_deps = [d["id"] for d in dependents if d["status"] == "suspended"]
            active_deps = [d["id"] for d in dependents if d["status"] == "active"]
            superseded_deps = [d["id"] for d in dependents if d["status"] == "superseded"]
            stale_receipt_ids = [r["receipt_id"] for r in affected_receipts if r.get("status") == "stale"]

            if rec_status == "suspended":
                impact_status = "self_suspended"
            elif suspended_deps or stale_receipt_ids:
                impact_status = "suspended_cascade"
            elif active_deps:
                impact_status = "active_dependents_in_scope"
            else:
                impact_status = "leaf_active"

            return {
                "status": "ok",
                "generation": generation,
                "record": {
                    "id": record_id,
                    "title": rec["title"],
                    "record_type": rec["record_type"],
                    "episteme_class": classes[record_id],
                    "folder": folders[record_id],
                    "revision": rec["revision"],
                    "status": rec_status,
                    "validity": "needs_revalidation" if record_id in stale_ids else "current_within_scope",
                    "sha256": digests[record_id],
                    "canonical_sha256": canonical_digest(rec),
                    "updated_at": rec.get("updated_at"),
                    "summary": _summarize_record(rec),
                    "rev_refs": direct_rev_refs,
                    "previous_revisions": prev_revs,
                    "revision_diff": rev_diff,
                    "payload": rec["payload"],
                },
                "upstream": {
                    "direct_rev_refs": direct_rev_refs,
                    "primary_sources": primary_sources,
                    "upstream_nodes": upstream_nodes,
                    "upstream_edges": upstream_edges,
                },
                "downstream": {
                    "dependents": dependents,
                    "downstream_edges": downstream_edges,
                    "affected_receipts": affected_receipts,
                },
                "impact": {
                    "record_id": record_id,
                    "record_status": rec_status,
                    "impact_status": impact_status,
                    "total_downstream_dependents": len(dependents),
                    "active_dependents_count": len(active_deps),
                    "suspended_dependents_count": len(suspended_deps),
                    "superseded_dependents_count": len(superseded_deps),
                    "blast_radius_ids": [d["id"] for d in dependents],
                    "suspended_ids": suspended_deps,
                    "active_ids": active_deps,
                    "affected_receipts_count": len(affected_receipts),
                    "stale_receipts_count": len(stale_receipt_ids),
                    "stale_receipt_ids": stale_receipt_ids,
                    "max_depth": max(downstream_distances.values(), default=0),
                },
            }

    def create_source(self, data: dict[str, Any]) -> dict[str, Any]:
        """Registra fonte primária em `30_Fontes` com validação canônica e hash SHA-256."""
        from nucleo import Invalid

        with self._lock:
            self._check_access_gate()
            op_key = str(data.get("operation_key") or data.get("key") or ("gw-src-" + secrets.token_hex(8)))
            title = data.get("title")
            content = data.get("content") if "content" in data else data.get("text")
            if not isinstance(title, str) or not isinstance(content, str):
                raise Invalid("campos 'title' e 'content' (texto) são obrigatórios")

            explicit_meta = data.get("source_metadata") if "source_metadata" in data else data.get("metadata")
            source_kind = data.get("source_kind")
            if explicit_meta is not None:
                if not isinstance(explicit_meta, dict):
                    raise Invalid("source_metadata deve ser um objeto JSON")
                metadata: dict[str, Any] | None = dict(explicit_meta)
                if source_kind is not None:
                    metadata.setdefault("source_kind", source_kind)
            elif source_kind is not None and source_kind != "conversation":
                if not isinstance(source_kind, str):
                    raise Invalid("source_kind inválido")
                metadata = {
                    "source_kind": source_kind,
                    "origin_description": str(
                        data.get("origin_description") or "Fonte primária registrada via Epistemic HTTP Gateway"
                    ),
                    "availability_status": str(data.get("availability_status") or "retained"),
                    "retention_conditions": str(data.get("retention_conditions") or "cofre_local_governado"),
                }
                for opt_key in ("reference_locator", "publication_title", "parent_source_ref", "doi", "authors", "published_time", "accessed_at", "limitations"):
                    if opt_key in data and data[opt_key] is not None:
                        metadata[opt_key] = data[opt_key]
            elif any(k in data for k in ("origin_description", "parent_source_ref", "reference_locator")):
                metadata = {
                    "source_kind": str(source_kind or "conversation"),
                    "origin_description": str(
                        data.get("origin_description") or "Relato registrado via Epistemic HTTP Gateway"
                    ),
                    "availability_status": str(data.get("availability_status") or "retained"),
                    "retention_conditions": str(data.get("retention_conditions") or "cofre_local_governado"),
                }
                for opt_key in ("reference_locator", "publication_title", "parent_source_ref", "limitations"):
                    if opt_key in data and data[opt_key] is not None:
                        metadata[opt_key] = data[opt_key]
            else:
                metadata = None

            res = self.store.apply(op_key, "create", title=title, text=content, source_metadata=metadata)
            with self.store.connect() as conn:
                row = conn.execute("SELECT digest FROM records WHERE id=?", (res["id"],)).fetchone()
            file_sha = row[0] if row else None
            return {
                "status": "ok",
                "operation_key": op_key,
                "record": {
                    "id": res["id"],
                    "revision": res["revision"],
                    "title": title.strip(),
                    "record_type": "source",
                    "episteme_class": "30_Fontes",
                    "folder": "30_Fontes",
                    "status": "active",
                    "sha256": file_sha,
                },
                "rev_ref": {"record_id": res["id"], "revision": res["revision"]},
            }

    def rectify_source(self, data: dict[str, Any]) -> dict[str, Any]:
        """Retifica fonte em `30_Fontes`, arquiva revisão anterior e calcula o raio de impacto."""
        from nucleo import Invalid

        with self._lock:
            self._check_access_gate()
            op_key = str(data.get("operation_key") or data.get("key") or ("gw-rect-" + secrets.token_hex(8)))
            record_id = data.get("record_id") or data.get("id")
            expected_rev = data.get("expected_revision") if "expected_revision" in data else data.get("expected")
            new_content = (
                data.get("content")
                if "content" in data
                else (data.get("new_content") if "new_content" in data else data.get("text"))
            )
            reason = data.get("reason")
            source_metadata = data.get("source_metadata")

            if not isinstance(record_id, str) or not record_id.strip():
                raise Invalid("campo 'record_id' é obrigatório")
            if type(expected_rev) is not int or expected_rev < 1:
                raise Invalid("campo 'expected_revision' deve ser um inteiro >= 1")
            if not isinstance(new_content, str):
                raise Invalid("campo 'content' é obrigatório")
            if not isinstance(reason, str):
                raise Invalid("campo 'reason' (motivo formal da retificação) é obrigatório")

            before_records, _, _ = self.knowledge.catalog()
            before_stale = self.knowledge.stale(before_records)

            updated = self.store.apply(
                op_key,
                "correct",
                ident=record_id,
                expected=expected_rev,
                text=new_content,
                reason=reason,
                source_metadata=source_metadata,
            )

            after_records, after_paths, _ = self.knowledge.catalog()
            after_stale = self.knowledge.stale(after_records)
            digests, folders, classes = self._catalog_metadata(after_records, after_paths)

            newly_suspended = sorted(after_stale - before_stale)
            all_suspended = sorted(after_stale)
            receipts = self._reverify_all_receipts()
            stale_receipts = [r["receipt_id"] for r in receipts if r.get("status") == "stale"]
            diff_lines = self._revision_diff(record_id, after_records[record_id], expected_rev, updated["revision"])

            return {
                "status": "ok",
                "operation_key": op_key,
                "update": updated,
                "rev_ref": {"record_id": record_id, "revision": updated["revision"]},
                "sha256": digests.get(record_id),
                "newly_suspended_ids": newly_suspended,
                "newly_suspended_records": [
                    {
                        "id": rid,
                        "title": after_records[rid]["title"],
                        "record_type": after_records[rid]["record_type"],
                        "episteme_class": classes[rid],
                        "folder": folders[rid],
                        "revision": after_records[rid]["revision"],
                        "status": "suspended",
                    }
                    for rid in newly_suspended
                    if rid in after_records
                ],
                "suspended_ids": all_suspended,
                "total_suspended_records": len(after_stale),
                "stale_receipt_ids": stale_receipts,
                "diff": diff_lines,
            }

    def create_or_update_knowledge(self, data: dict[str, Any]) -> dict[str, Any]:
        """Registra ou atualiza conhecimento derivado aplicando `atribuicao.py` e `esquemas.py`."""
        from conhecimento import FOLDERS, decode
        from nucleo import Invalid, NOW, read_exclusive

        with self._lock:
            self._check_access_gate()
            if data.get("review_authorized"):
                raise Invalid("review_authorized não é aceito via payload externo")

            op_key = str(data.get("operation_key") or data.get("key") or ("gw-knw-" + secrets.token_hex(8)))
            action = data.get("action")

            if action == "finish_assessment":
                from avaliacoes import finish

                assessment_id = data.get("assessment_id")
                if not isinstance(assessment_id, str) or not assessment_id.strip():
                    raise Invalid("campo 'assessment_id' é obrigatório para finish_assessment")
                res = finish(self.store, op_key, assessment_id)
                records, paths, _ = self.knowledge.catalog()
                digests, folders, classes = self._catalog_metadata(records, paths)
                rid = res["id"]
                return {
                    "status": "ok",
                    "operation_key": op_key,
                    "record": {
                        "id": rid,
                        "revision": res["revision"],
                        "title": records[rid]["title"],
                        "record_type": records[rid]["record_type"],
                        "episteme_class": classes[rid],
                        "folder": folders[rid],
                        "status": "active",
                        "sha256": digests[rid],
                    },
                    "rev_ref": {"record_id": rid, "revision": res["revision"]},
                }

            if action == "human_review":
                from revisoes import register as register_review

                assertion_id = data.get("assertion_id")
                expected_rev = data.get("expected_revision")
                review_status = data.get("review_status")
                source_ref = data.get("source_ref")
                quote = data.get("quote")
                review_scope = data.get("scope")
                if (
                    not isinstance(assertion_id, str)
                    or type(expected_rev) is not int
                    or not isinstance(review_status, str)
                    or not isinstance(source_ref, dict)
                    or not isinstance(quote, str)
                    or not isinstance(review_scope, str)
                ):
                    raise Invalid("campos obrigatórios ausentes para human_review")
                res = register_review(
                    self.store, op_key, assertion_id, expected_rev, review_status, source_ref, quote, review_scope
                )
                records, paths, _ = self.knowledge.catalog()
                digests, folders, classes = self._catalog_metadata(records, paths)
                rid = res["id"]
                return {
                    "status": "ok",
                    "operation_key": op_key,
                    "record": {
                        "id": rid,
                        "revision": res["revision"],
                        "title": records[rid]["title"],
                        "record_type": "assertion",
                        "episteme_class": classes[rid],
                        "folder": folders[rid],
                        "status": "active",
                        "sha256": digests[rid],
                    },
                    "rev_ref": {"record_id": rid, "revision": res["revision"]},
                }

            kind = data.get("record_type") or data.get("kind")
            title = data.get("title")
            raw_payload = data.get("payload")
            if not isinstance(kind, str) or kind not in FOLDERS:
                raise Invalid("campo 'record_type' inválido ou não reconhecido pelo catálogo")
            if not isinstance(title, str):
                raise Invalid("campo 'title' é obrigatório")
            if not isinstance(raw_payload, dict):
                raise Invalid("campo 'payload' deve ser um objeto JSON")

            payload = copy.deepcopy(raw_payload)
            ident = data.get("record_id") or data.get("id")
            expected = data.get("expected_revision") if "expected_revision" in data else data.get("expected")
            if expected is not None and type(expected) is not int:
                raise Invalid("campo 'expected_revision' deve ser inteiro")

            if kind == "assertion":
                from atribuicao import AttributionError, owner_id, persons, validate_assertion

                payload.setdefault("valid_time", {"precision": "unknown"})
                payload.setdefault("review_status", "unreviewed")
                payload.setdefault("context_description", "Registrado via Epistemic HTTP Gateway")
                prior_status = None
                with self.knowledge.connect() as conn:
                    prior = conn.execute(
                        "SELECT status, path, data FROM operations WHERE key=?", (op_key,)
                    ).fetchone()
                if prior:
                    prior_status = prior[0]
                if "recorded_time" not in payload:
                    prior_ts = None
                    if prior:
                        try:
                            if prior[2] is not None:
                                prior_ts = decode(prior[2])["payload"].get("recorded_time")
                            elif prior[1]:
                                disk_file = self.vault_root / str(prior[1]).replace("\\", "/")
                                if disk_file.is_file():
                                    prior_ts = decode(read_exclusive(disk_file))["payload"].get("recorded_time")
                        except Exception:
                            prior_ts = None
                    payload["recorded_time"] = prior_ts or NOW()

                if prior_status != "confirmed":
                    pre_records, _, _ = self.knowledge.catalog()
                    active_persons = persons(pre_records)
                    subj_ref = payload.get("subject_ref")
                    subj_id = subj_ref.get("record_id") if isinstance(subj_ref, dict) else None
                    nature = payload.get("nature")
                    if subj_id in active_persons and nature in (
                        "user_report",
                        "third_party_report",
                        "documented_observation",
                    ):
                        if not payload.get("attribution_evidence"):
                            raise AttributionError(
                                "relato pessoal ou atribuído a pessoa exige attribution_evidence com citação literal"
                            )
                        attr_verdict = validate_assertion(
                            payload, pre_records, owner_id(self.system_root, pre_records)
                        )
                        if attr_verdict.get("status") not in (
                            "checked_for_known_mentions",
                            "resolved_by_separate_source",
                        ):
                            raise AttributionError(
                                str(attr_verdict.get("reason") or "trecho não comprova menção explícita ao sujeito"),
                                ambiguous=attr_verdict.get("status") == "unresolved",
                            )

            res = self.knowledge.apply(
                op_key,
                kind,
                title,
                payload,
                ident=ident,
                expected=expected,
                review_authorized=False,
            )
            records, paths, _ = self.knowledge.catalog()
            digests, folders, classes = self._catalog_metadata(records, paths)
            rid = res["id"]
            stale_ids = self.knowledge.stale(records)
            return {
                "status": "ok",
                "operation_key": op_key,
                "record": {
                    "id": rid,
                    "revision": res["revision"],
                    "title": records[rid]["title"],
                    "record_type": kind,
                    "episteme_class": classes[rid],
                    "folder": folders[rid],
                    "status": self._record_status(rid, records[rid], stale_ids),
                    "sha256": digests[rid],
                },
                "rev_ref": {"record_id": rid, "revision": res["revision"]},
            }

    def verify_claims(self, data: dict[str, Any]) -> dict[str, Any]:
        """Emite ou revalida comprovantes determinísticos `lab-assurance-2`."""
        from evidencias import inspect_response, read_json, read_receipt, safe_folder
        from nucleo import Invalid
        from verificador_evidencias import encode

        with self._lock:
            self._check_access_gate()
            if "receipt_id" in data and "claims" not in data:
                receipt_id = data.get("receipt_id")
                verdict = read_receipt(self.store, receipt_id, self.scope)
                return {"format": "lab-assurance-2", **verdict}

            op_key = str(data.get("operation_key") or data.get("key") or ("gw-ver-" + secrets.token_hex(8)))
            claims = data.get("claims")
            if not isinstance(claims, list) or not claims or any(not isinstance(c, dict) for c in claims):
                raise Invalid("campo 'claims' deve ser uma lista não vazia de alegações estruturadas")

            answer_format = data.get("answer_format", "controlled")
            if "answer" in data and data["answer"] is not None:
                if not isinstance(data["answer"], str):
                    raise Invalid("campo 'answer' deve ser texto")
                answer = data["answer"]
            else:
                if any("id" not in c or not isinstance(c["id"], str) or "value" not in c for c in claims):
                    raise Invalid("cada alegação exige 'id' (string) e 'value'")
                answer = "\n".join(f"{c['id']} = {encode(c['value']).decode('utf-8')}" for c in claims)

            draft: dict[str, Any] = {
                "answer_format": answer_format,
                "answer": answer,
                "claims": claims,
            }
            if "citations" in data and data["citations"] is not None:
                draft["citations"] = data["citations"]

            max_context = data.get("max_context", 24)
            context_ids = data.get("context_ids")
            expected_gen = data.get("expected_generation")

            verdict = inspect_response(
                self.store,
                op_key,
                draft,
                context_ids=context_ids,
                max_context=max_context,
                expected_generation=expected_gen,
                scope=self.scope,
            )
            enriched: dict[str, Any] = {
                "format": "lab-assurance-2",
                "operation_key": op_key,
                **verdict,
            }
            rec_id = verdict.get("receipt_id")
            if isinstance(rec_id, str):
                saved_path = safe_folder(self.store, "respostas") / f"{rec_id}.json"
                if saved_path.is_file():
                    saved = read_json(saved_path)
                    enriched["manifest_anchor"] = saved.get("manifest_anchor")
                    enriched["receipt_sha256"] = saved.get("packet", {}).get("receipt_sha256")
            return enriched

    def search(self, data: dict[str, Any]) -> dict[str, Any]:
        """Executa busca híbrida lexical + grafo + ONNX E5 filtrando derivados suspensos."""
        from nucleo import Invalid

        with self._lock:
            self._check_access_gate()
            query = data.get("query") if "query" in data else data.get("consulta", "")
            limit = data.get("limit") if "limit" in data else data.get("limite", 12)
            depth = data.get("depth") if "depth" in data else data.get("profundidade", 1)
            if type(limit) is not int or type(depth) is not int:
                raise Invalid("parâmetros 'limit' e 'depth' devem ser inteiros")

            raw = self.retrieval.search(query, limit=limit, depth=depth)
            records, paths, _ = self.knowledge.catalog()
            digests, folders, classes = self._catalog_metadata(records, paths)

            enriched_results = []
            for hit in raw.get("results", []):
                rid = hit["id"]
                rec = records.get(rid, hit.get("record", {}))
                enriched_results.append(
                    {
                        "id": rid,
                        "revision": hit["revision"],
                        "title": hit["title"],
                        "record_type": hit["record_type"],
                        "episteme_class": classes.get(rid, "70_Operacao"),
                        "folder": folders.get(rid, "70_Operacao"),
                        "status": "active",
                        "sha256": digests.get(rid),
                        "summary": _summarize_record(rec) if rec else hit["title"],
                        "record": hit.get("record"),
                    }
                )

            return {
                "status": "ok",
                "mode": raw["mode"],
                "embeddings_active": self.embedder is not None,
                "generation": raw["generation"],
                "cache_reused": raw["cache_reused"],
                "scope": raw["scope"],
                "excluded_stale": raw["excluded_stale"],
                "results": enriched_results,
                "issues": raw["issues"],
                "limits": raw["limits"],
            }


def create_gateway_server(
    runtime: EpistemicGatewayRuntime,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    api_token: str | None = None,
) -> ThreadingHTTPServer:
    """Cria `ThreadingHTTPServer` endurecido vinculado estritamente a interface de loopback."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("Por segurança, o Epistemic HTTP Gateway vincula apenas em loopback local (127.0.0.1 / ::1).")

    resolved_api_token = (api_token or os.environ.get("EMC_GATEWAY_TOKEN") or "").strip() or secrets.token_urlsafe(32)
    ui_session_token = secrets.token_hex(24)

    class GatewayRequestHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _init_request_tracking(self) -> None:
            self._body_consumed = False

        def _drain_small_unread_body(self) -> None:
            """Drena corpos pequenos/moderados antes de fechar em erro >= 400 (evita TCP RST em Windows/macOS BSD)."""
            if getattr(self, "_body_consumed", False):
                return
            self._body_consumed = True
            if self.command in ("GET", "HEAD"):
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except (TypeError, ValueError):
                return
            if length <= 0 or length > _MAX_DRAIN_BYTES:
                return
            prev_timeout = self.connection.gettimeout()
            try:
                self.connection.settimeout(0.5)
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(remaining, _DRAIN_CHUNK_BYTES))
                    if not chunk:
                        break
                    remaining -= len(chunk)
            except OSError:
                pass
            finally:
                try:
                    self.connection.settimeout(prev_timeout)
                except OSError:
                    pass

        def _verify_host(self) -> bool:
            if not is_allowed_host(self.headers.get("Host", "")):
                self._send_json(
                    {
                        "status": "denied",
                        "error": "forbidden_host",
                        "reason": "Cabeçalho Host HTTP não autorizado (proteção DNS Rebinding).",
                    },
                    code=403,
                )
                return False
            return True

        def _verify_cross_site_headers(self) -> bool:
            sec_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
            if sec_site and sec_site not in ("same-origin", "none"):
                self._send_json(
                    {
                        "status": "denied",
                        "error": "cross_site_blocked",
                        "reason": "Requisição cross-site de navegador bloqueada.",
                    },
                    code=403,
                )
                return False
            origin = (self.headers.get("Origin") or "").strip()
            if origin:
                parsed = urllib.parse.urlparse(origin)
                if parsed.scheme not in ("http", "https") or (parsed.hostname or "").lower() not in (
                    "127.0.0.1",
                    "localhost",
                    "::1",
                ):
                    self._send_json(
                        {
                            "status": "denied",
                            "error": "forbidden_origin",
                            "reason": "Cabeçalho Origin HTTP não pertence ao loopback local.",
                        },
                        code=403,
                    )
                    return False
            return True

        def _verify_bearer_auth(self) -> bool:
            if not self._verify_cross_site_headers():
                return False
            auth_header = (self.headers.get("Authorization") or "").strip()
            scheme, sep, raw_token = auth_header.partition(" ")
            supplied = raw_token.strip() if sep else ""
            if scheme.lower() != "bearer" or not supplied:
                self._send_json(
                    {
                        "status": "unauthorized",
                        "error": "missing_bearer_token",
                        "reason": "Autenticação obrigatória via cabeçalho 'Authorization: Bearer <api_token>'.",
                    },
                    code=401,
                )
                return False
            is_api = _constant_time_token_eq(supplied, resolved_api_token)
            is_ui = _constant_time_token_eq(supplied, ui_session_token)
            if not (is_api or is_ui):
                self._send_json(
                    {
                        "status": "unauthorized",
                        "error": "invalid_bearer_token",
                        "reason": "Token Bearer inválido.",
                    },
                    code=401,
                )
                return False
            return True

        def _read_json_body(self) -> dict[str, Any] | None:
            if self.headers.get("Transfer-Encoding"):
                self._body_consumed = True
                self._send_json(
                    {
                        "status": "invalid",
                        "error": "length_required",
                        "reason": "Content-Length explícito obrigatório; Transfer-Encoding não suportado.",
                    },
                    code=411,
                )
                return None

            raw_len = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_len)
            except (TypeError, ValueError):
                self._body_consumed = True
                self._send_json(
                    {"status": "invalid", "error": "invalid_content_length", "reason": "Content-Length inválido."},
                    code=400,
                )
                return None

            if length < 0:
                self._body_consumed = True
                self._send_json(
                    {"status": "invalid", "error": "negative_content_length", "reason": "Content-Length negativo."},
                    code=400,
                )
                return None

            if length > MAX_BODY_BYTES:
                self._drain_small_unread_body()
                self._send_json(
                    {
                        "status": "invalid",
                        "error": "payload_too_large",
                        "reason": f"Corpo excede o limite máximo de 64 KB ({MAX_BODY_BYTES} bytes).",
                        "max_bytes": MAX_BODY_BYTES,
                    },
                    code=413,
                )
                return None

            self._body_consumed = True
            if length == 0:
                return {}

            try:
                raw_bytes = self.rfile.read(length)
                decoded = json.loads(raw_bytes.decode("utf-8"), parse_constant=self._reject_nonfinite_json)
            except (UnicodeDecodeError, ValueError):
                self._send_json(
                    {"status": "invalid", "error": "invalid_json", "reason": "Corpo JSON malformado ou não finito."},
                    code=400,
                )
                return None

            if not isinstance(decoded, dict):
                self._send_json(
                    {"status": "invalid", "error": "json_object_expected", "reason": "Objeto JSON esperado na raiz."},
                    code=400,
                )
                return None
            return decoded

        @staticmethod
        def _reject_nonfinite_json(constant: str) -> Any:
            raise ValueError(f"Constante JSON não finita não permitida: {constant}")

        def do_GET(self) -> None:
            self._init_request_tracking()
            if not self._verify_host():
                return
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path in ("/", "/index.html"):
                html_bytes = render_gateway_html(ui_session_token)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_bytes)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Cache-Control", "no-store")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; "
                    "script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; "
                    "base-uri 'self'; form-action 'none'",
                )
                self.end_headers()
                try:
                    self.wfile.write(html_bytes)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True
                return

            if not self._verify_bearer_auth():
                return

            from nucleo import Conflict, Invalid, Locked, Uncertain

            try:
                if path == "/api/v1/health":
                    self._send_json(runtime.health(), code=200)
                elif path == "/api/v1/graph":
                    qs = urllib.parse.parse_qs(parsed.query)
                    inc_sup = str((qs.get("include_superseded") or ["false"])[0]).lower() in ("1", "true", "yes")
                    self._send_json(runtime.graph(include_superseded=inc_sup), code=200)
                elif path.startswith("/api/v1/lineage/"):
                    raw_id = urllib.parse.unquote(path[len("/api/v1/lineage/") :]).strip("/")
                    if not raw_id:
                        self._send_json(
                            {"status": "invalid", "error": "missing_record_id", "reason": "record_id ausente na URL."},
                            code=400,
                        )
                        return
                    self._send_json(runtime.lineage(raw_id), code=200)
                else:
                    self._send_json(
                        {"status": "not_found", "error": "route_not_found", "reason": f"Rota GET inexistente: {path}"},
                        code=404,
                    )
            except PermissionError as exc:
                self._send_json(
                    {"status": "denied", "error": "access_locked", "reason": str(exc)},
                    code=403,
                )
            except KeyError as exc:
                self._send_json(
                    {"status": "not_found", "error": "record_not_found", "reason": f"Registro não encontrado: {exc}"},
                    code=404,
                )
            except Conflict as exc:
                self._send_json(
                    {"status": "conflict", "error": "epistemic_conflict", "error_type": "Conflict", "reason": str(exc)},
                    code=409,
                )
            except (Locked, Uncertain) as exc:
                self._send_json(
                    {
                        "status": "conflict",
                        "error": "resource_busy_or_uncertain",
                        "error_type": type(exc).__name__,
                        "reason": str(exc),
                    },
                    code=409,
                )
            except (Invalid, ValueError) as exc:
                self._send_json(
                    {
                        "status": "rejected",
                        "error": "validation_error",
                        "error_type": type(exc).__name__,
                        "reason": str(exc),
                    },
                    code=422,
                )

        def do_POST(self) -> None:
            self._init_request_tracking()
            if not self._verify_host():
                return
            if not self._verify_bearer_auth():
                return
            data = self._read_json_body()
            if data is None:
                return

            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            from atribuicao import AttributionError
            from nucleo import Conflict, Invalid, Locked, Uncertain

            try:
                if path == "/api/v1/sources":
                    self._send_json(runtime.create_source(data), code=200)
                elif path == "/api/v1/sources/rectify":
                    self._send_json(runtime.rectify_source(data), code=200)
                elif path == "/api/v1/knowledge":
                    self._send_json(runtime.create_or_update_knowledge(data), code=200)
                elif path == "/api/v1/verify-claims":
                    self._send_json(runtime.verify_claims(data), code=200)
                elif path == "/api/v1/search":
                    self._send_json(runtime.search(data), code=200)
                else:
                    self._send_json(
                        {"status": "not_found", "error": "route_not_found", "reason": f"Endpoint POST inexistente: {path}"},
                        code=404,
                    )
            except PermissionError as exc:
                self._send_json(
                    {"status": "denied", "error": "access_locked", "reason": str(exc)},
                    code=403,
                )
            except AttributionError as exc:
                self._send_json(
                    {
                        "status": "rejected",
                        "error": "attribution_firewall_blocked",
                        "error_type": "AttributionError",
                        "ambiguous": bool(getattr(exc, "ambiguous", False)),
                        "reason": str(exc),
                    },
                    code=422,
                )
            except Conflict as exc:
                self._send_json(
                    {
                        "status": "conflict",
                        "error": "epistemic_conflict",
                        "error_type": "Conflict",
                        "reason": str(exc),
                    },
                    code=409,
                )
            except (Locked, Uncertain) as exc:
                self._send_json(
                    {
                        "status": "conflict",
                        "error": "resource_busy_or_uncertain",
                        "error_type": type(exc).__name__,
                        "reason": str(exc),
                    },
                    code=409,
                )
            except (Invalid, ValueError, KeyError) as exc:
                self._send_json(
                    {
                        "status": "rejected",
                        "error": "schema_validation_failed",
                        "error_type": type(exc).__name__,
                        "reason": str(exc),
                    },
                    code=422,
                )

        def _send_json(self, payload: dict[str, Any], code: int = 200) -> None:
            if code >= 400:
                self._drain_small_unread_body()
                self.close_connection = True
            raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            if code == 401:
                self.send_header("WWW-Authenticate", 'Bearer realm="epistemic-http-gateway"')
            if code >= 400:
                self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(raw)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), GatewayRequestHandler)
    server.daemon_threads = True
    server.api_token = resolved_api_token  # type: ignore[attr-defined]
    server.ui_token = ui_session_token  # type: ignore[attr-defined]
    server.runtime = runtime  # type: ignore[attr-defined]
    return server
