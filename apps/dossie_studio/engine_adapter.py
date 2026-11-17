"""Adaptador estrito de domínio sobre os contratos canônicos do Epistemic Memory Core.

Opera exclusivamente por meio de `Store`, `Knowledge`, `apoio_decisao`,
`evidencias`, `avaliacoes`, `revisoes` e `recuperacao`, preservando todas as
regras epistemológicas e de integridade dos 17 capítulos de `00_Manual/`.
"""
from __future__ import annotations

import copy
import difflib
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


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


def bootstrap_environment(workspace_dir: str | Path) -> tuple[Path, Path]:
    """Configura `EMC_SYSTEM` e `EMC_VAULT` antes da carga inicial em processos dedicados."""
    ws = Path(workspace_dir).resolve()
    sys_root = ws / "sistema"
    vault_root = ws / "cofre"
    os.environ["EMC_SYSTEM"] = str(sys_root)
    os.environ["EMC_VAULT"] = str(vault_root)
    return sys_root, vault_root


class DossieWorkspace:
    """Espaço de trabalho auditável apoiado integralmente nos contratos do motor."""

    def __init__(self, system_root: str | Path, vault_root: str | Path, *, enable_embeddings: bool = False):
        from autonomia import atomic_json
        from conhecimento import Knowledge
        from execucao import DEFAULT
        from nucleo import REAL_SYSTEM, Store, config_file
        from recuperacao import LocalEmbeddings, Retrieval

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
            if not dest.exists():
                dest.write_bytes((manual_src_dir / name).read_bytes())

        if not (self.system_root / "manual_manifest.json").exists():
            atomic_json(self.system_root / "manual_manifest.json", manifest)

        self.store = Store(self.system_root, self.vault_root)
        self.knowledge = Knowledge(self.store)

        embedder = None
        if enable_embeddings:
            emb_dir = os.environ.get("EMC_EMBEDDINGS_DIR")
            candidate = Path(emb_dir) if emb_dir else (REPO_ROOT / "modelos" / "e5-multilingual-small")
            if (candidate / "model.onnx").is_file() and (candidate / "tokenizer.json").is_file():
                embedder = LocalEmbeddings(candidate)

        cfg_path = self.system_root / "execucao.json"
        if not cfg_path.exists():
            cfg = copy.deepcopy(DEFAULT)
            cfg["enabled"] = True
            cfg["embeddings"] = {"enabled": embedder is not None, "folder": str(REPO_ROOT / "modelos" / "e5-multilingual-small")}
            atomic_json(cfg_path, cfg)

        self.embedder = embedder
        self.retrieval = Retrieval(self.store, embedder=self.embedder)

    def ingest_source(
        self,
        operation_key: str,
        title: str,
        content: str,
        *,
        source_kind: str = "document",
        origin_description: str = "Documento registrado no Dossiê Epistêmico",
        extra_metadata: dict | None = None,
    ) -> dict:
        if source_kind == "conversation" and not extra_metadata:
            return self.store.apply(operation_key, "create", title=title, text=content)
        metadata = {
            "source_kind": source_kind,
            "origin_description": origin_description,
            "availability_status": "retained",
            "retention_conditions": "dossie_local_isolado",
        }
        if source_kind in ("document", "publication", "web_page"):
            metadata.setdefault("reference_locator", f"dossie://{operation_key}")
        if source_kind == "publication":
            metadata.setdefault("publication_title", title)
        if extra_metadata:
            metadata.update(extra_metadata)
        return self.store.apply(
            operation_key,
            "create",
            title=title,
            text=content,
            source_metadata=metadata,
        )

    def rectify_source(
        self,
        operation_key: str,
        record_id: str,
        expected_revision: int,
        new_content: str,
        reason: str,
    ) -> dict:
        before_records, _, _ = self.knowledge.catalog()
        before_stale = self.knowledge.stale(before_records)
        updated = self.store.apply(
            operation_key,
            "correct",
            ident=record_id,
            expected=expected_revision,
            text=new_content,
            reason=reason,
        )
        after_records, _, _ = self.knowledge.catalog()
        after_stale = self.knowledge.stale(after_records)
        newly_suspended = sorted(after_stale - before_stale)
        receipts = self.reverify_all_receipts()
        stale_receipts = [r["receipt_id"] for r in receipts if r["status"] == "stale"]
        diff_lines = self.source_revision_diff(record_id, expected_revision, updated["revision"])
        return {
            "update": updated,
            "newly_suspended_ids": newly_suspended,
            "newly_suspended_records": [
                {
                    "id": rid,
                    "title": after_records[rid]["title"],
                    "record_type": after_records[rid]["record_type"],
                    "revision": after_records[rid]["revision"],
                }
                for rid in newly_suspended
                if rid in after_records
            ],
            "total_stale_records": len(after_stale),
            "stale_receipt_ids": stale_receipts,
            "diff": diff_lines,
        }

    def source_revision_diff(self, record_id: str, old_rev: int, new_rev: int) -> list[str]:
        from nucleo import parse

        hist_file = self.system_root / "estado" / "revisoes" / record_id / f"{old_rev}.md"
        old_text = ""
        if hist_file.is_file():
            old_text = str(parse(hist_file.read_bytes())["payload"].get("content", ""))
        current = self.store.read(record_id)
        new_text = str(current["payload"].get("content", "")) if current["revision"] == new_rev else ""
        return list(
            difflib.unified_diff(
                old_text.splitlines(),
                new_text.splitlines(),
                fromfile=f"revisao_{old_rev}",
                tofile=f"revisao_{new_rev}",
                lineterm="",
            )
        )

    def register_person(
        self,
        operation_key: str,
        display_name: str,
        origin_ref: dict,
        *,
        aliases: list[str] | None = None,
        summary: str | None = None,
    ) -> dict:
        payload = {
            "entity_kind": "person",
            "display_name": display_name,
            "identity_status": "identified",
            "origin_refs": [origin_ref],
        }
        if aliases:
            payload["aliases"] = list(aliases)
        if summary:
            payload["summary"] = summary
        return self.knowledge.apply(operation_key, "entity", display_name, payload)

    def register_entity(self, operation_key: str, title: str, payload: dict) -> dict:
        enriched = dict(payload)
        enriched.setdefault("identity_status", "identified")
        return self.knowledge.apply(operation_key, "entity", title, enriched)

    def register_assertion(
        self,
        operation_key: str,
        title: str,
        *,
        subject_ref: dict,
        predicate: str,
        nature: str,
        asserted_by: str,
        refs_list: list[dict],
        value: dict | None = None,
        object_ref: dict | None = None,
        evidence_quote: str | None = None,
        evidence_source: dict | None = None,
        context_description: str = "Dossiê auditável",
        valid_time: dict | None = None,
    ) -> dict:
        from nucleo import NOW

        payload: dict = {
            "subject_ref": subject_ref,
            "predicate": predicate,
            "nature": nature,
            "asserted_by": asserted_by,
            "recorded_time": NOW(),
            "context_description": context_description,
            "valid_time": valid_time or {"precision": "unknown"},
            "review_status": "unreviewed",
        }
        if nature == "inference":
            payload["basis_refs"] = refs_list
        else:
            payload["source_refs"] = refs_list
        if value is not None:
            payload["value"] = value
        if object_ref is not None:
            payload["object_ref"] = object_ref
        if evidence_quote is not None:
            src_ref = evidence_source or refs_list[0]
            payload["attribution_evidence"] = {
                "source_ref": {"record_id": src_ref["record_id"], "revision": src_ref["revision"]},
                "quote": evidence_quote,
            }
        return self.knowledge.apply(operation_key, "assertion", title, payload)

    def register_synthesis(
        self,
        operation_key: str,
        title: str,
        *,
        content: str,
        scope: str,
        basis_refs: list[dict],
        limitations: list[str],
        synthesis_kind: str = "knowledge_summary",
        coverage_status: str = "supported_within_scope",
        as_of: str = "2026-11-17",
    ) -> dict:
        payload = {
            "synthesis_kind": synthesis_kind,
            "content": content,
            "scope": scope,
            "basis_refs": basis_refs,
            "limitations": limitations,
            "coverage_status": coverage_status,
            "as_of": as_of,
        }
        return self.knowledge.apply(operation_key, "synthesis", title, payload)

    def register_decision(
        self,
        operation_key: str,
        title: str,
        situation: str,
        options: list[dict],
        source_refs: list[dict],
        gaps: list[str],
    ) -> dict:
        from apoio_decisao import prepare

        return prepare(self.knowledge, operation_key, title, situation, options, source_refs, gaps)

    def register_human_review(
        self,
        operation_key: str,
        assertion_id: str,
        expected_revision: int,
        review_status: str,
        source_ref: dict,
        quote: str,
        scope: str,
    ) -> dict:
        from revisoes import register

        return register(
            self.store,
            operation_key,
            assertion_id,
            expected_revision,
            review_status,
            source_ref,
            quote,
            scope,
        )

    def issue_controlled_receipt(
        self,
        operation_key: str,
        claims: list[dict],
        *,
        citations: list[dict] | None = None,
        context_ids: list[str] | None = None,
    ) -> dict:
        from evidencias import inspect_response
        from verificador_evidencias import encode

        lines = [f"{c['id']} = {encode(c['value']).decode('utf-8')}" for c in claims]
        draft: dict = {
            "answer_format": "controlled",
            "answer": "\n".join(lines),
            "claims": claims,
        }
        if citations is not None:
            draft["citations"] = citations
        return inspect_response(self.store, operation_key, draft, context_ids=context_ids or [], max_context=24)

    def reverify_all_receipts(self) -> list[dict]:
        from evidencias import read_receipt

        resp_dir = self.system_root / "estado" / "comprovantes" / "respostas"
        if not resp_dir.is_dir():
            return []
        items = []
        for path in sorted(resp_dir.glob("*.json")):
            ident = path.stem
            res = read_receipt(self.store, ident)
            items.append({"receipt_id": ident, **res})
        return items

    def search(self, query: str, limit: int = 12, depth: int = 1) -> dict:
        return self.retrieval.search(query, limit=limit, depth=depth)

    def snapshot(self) -> dict:
        from conhecimento import refs

        records, _, issues = self.knowledge.catalog()
        stale_ids = self.knowledge.stale(records)
        nodes = []
        edges = []
        counts_by_type: dict[str, int] = {}
        for ident, rec in sorted(records.items(), key=lambda kv: (kv[1]["record_type"], kv[1]["title"])):
            rtype = rec["record_type"]
            counts_by_type[rtype] = counts_by_type.get(rtype, 0) + 1
            is_stale = ident in stale_ids
            nodes.append(
                {
                    "id": ident,
                    "title": rec["title"],
                    "record_type": rtype,
                    "entity_kind": rec["payload"].get("entity_kind"),
                    "revision": rec["revision"],
                    "validity": "needs_revalidation" if is_stale else "current_within_scope",
                    "updated_at": rec.get("updated_at"),
                    "summary": self._summarize_record(rec),
                }
            )
            for ref in refs(rec["payload"]):
                target_id = ref.get("record_id")
                if target_id:
                    target_rev = records.get(target_id, {}).get("revision")
                    edges.append(
                        {
                            "from": ident,
                            "to": target_id,
                            "pinned_revision": ref.get("revision"),
                            "current_target_revision": target_rev,
                            "outdated": target_rev is not None and ref.get("revision") != target_rev,
                        }
                    )
        receipts = self.reverify_all_receipts()
        return {
            "status": "ok",
            "total_records": len(records),
            "active_records": len(records) - len(stale_ids),
            "stale_records": len(stale_ids),
            "issues": issues,
            "counts_by_type": counts_by_type,
            "embeddings_active": self.embedder is not None,
            "nodes": nodes,
            "edges": edges,
            "receipts": receipts,
        }

    @staticmethod
    def _summarize_record(rec: dict) -> str:
        p = rec.get("payload", {})
        rtype = rec.get("record_type")
        if rtype == "source":
            txt = str(p.get("content", ""))
            return txt[:160] + ("..." if len(txt) > 160 else "")
        if rtype == "entity":
            return f"[{p.get('entity_kind')}] {p.get('display_name') or p.get('purpose') or p.get('situation') or p.get('outcome_description') or rec['title']}"
        if rtype == "assertion":
            val = p.get("value", {}).get("content") if isinstance(p.get("value"), dict) else p.get("object_ref", {}).get("record_id", "")[:8]
            return f"{p.get('predicate')} -> {val} ({p.get('nature')}, {p.get('review_status')})"
        if rtype == "synthesis":
            return str(p.get("content", ""))[:160]
        if rtype == "question":
            return f"{p.get('question_text')} [{p.get('resolution_status')}]"
        if rtype == "assessment_score":
            return f"Scores: {json.dumps(p.get('dimension_scores', {}), ensure_ascii=False)} [{p.get('score_validity_status')}]"
        return rec.get("title", "")
