"""Suíte determinística de fuzzing adversarial, firewall de atribuição, verificador e caos.

Executa integralmente em diretórios isolados dentro de `REAL_SYSTEM / 'testes_temporarios'`
com semente determinística fixa, concluindo em <20s para CI sem tocar em cofres reais.
"""
from __future__ import annotations

import copy
import json
import multiprocessing
import os
import random
import re
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _candidate_dir in (str(ROOT / "src"), str(ROOT / "tests")):
    if _candidate_dir not in sys.path:
        sys.path.insert(0, _candidate_dir)

from atribuicao import AttributionError, check_answer, validate_assertion, validate_quote
from autonomia import atomic_json
from conhecimento import Knowledge
from evidencias import inspect_response, read_receipt
from nucleo import (
    Conflict,
    Invalid,
    NOW,
    REAL_SYSTEM,
    Store,
    Uncertain,
    canon,
    filename as sanitize_filename,
    render as render_source,
    sha,
)
from recuperacao import Retrieval
import verificador_evidencias as verifier

WINDOWS_DEVICE_RE = re.compile(
    r"^(?:CON|PRN|AUX|NUL|COM[1-9\xb9\xb2\xb3]|LPT[1-9\xb9\xb2\xb3])$",
    re.IGNORECASE,
)
BIDI_AND_INVISIBLE_CHARS = frozenset(
    "\u200b\u200c\u200d\u200e\u200f"
    "\u202a\u202b\u202c\u202d\u202e"
    "\u2060\u2066\u2067\u2068\u2069\ufeff"
)


def _temp_workspace() -> tempfile.TemporaryDirectory[str]:
    base = REAL_SYSTEM / "testes_temporarios"
    base.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(prefix="fuzz-chaos-", dir=base)


def _crash_knowledge_after_flush(sys_dir: str, vault_dir: str, key: str, title: str, payload: dict) -> None:
    """Subprocesso descartável que simula morte abrupta logo após gravar a nota em disco."""
    store = Store(sys_dir, vault_dir)
    knowledge = Knowledge(store)
    real_fsync = os.fsync

    def die_after_fsync(fd: int) -> None:
        real_fsync(fd)
        os._exit(73)

    os.fsync = die_after_fsync
    knowledge.apply(key, "entity", title, payload)


class FuzzPathAndTitleTests(unittest.TestCase):
    """Fuzzing determinístico de caminhos, nomes reservados Windows, Unicode e limites."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = _temp_workspace()
        base = Path(cls._tmp.name)
        cls.store = Store(base / "sistema", base / "cofre")
        cls.knowledge = Knowledge(cls.store)
        cls.origin = cls.store.apply(
            "fuzz-origin",
            "create",
            title="Origem Base de Fuzzing",
            text="Fonte base para entidades derivadas de fuzzing.",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _assert_safe_filename(self, name: str, folder: Path | None = None, file_path: Path | None = None) -> None:
        self.assertTrue(name.endswith(".md"), f"Extensão inesperada: {name!r}")
        stem = name[:-3]
        self.assertGreaterEqual(len(stem), 1, f"Stem vazio em {name!r}")
        self.assertEqual(stem, unicodedata.normalize("NFC", stem), f"Stem fora de NFC: {name!r}")
        self.assertEqual(stem, stem.strip(" ."), f"Espaço ou ponto residual nas bordas: {name!r}")
        self.assertNotIn("/", name)
        self.assertNotIn("\\", name)
        self.assertNotIn("\x00", name)

        first_dot_stem = stem.split(".")[0].strip(" .")
        self.assertIsNone(
            WINDOWS_DEVICE_RE.fullmatch(stem),
            f"Nome reservado Windows no stem completo: {name!r}",
        )
        self.assertIsNone(
            WINDOWS_DEVICE_RE.fullmatch(first_dot_stem),
            f"Nome reservado Windows antes da extensão: {name!r}",
        )

        for ch in name:
            cat = unicodedata.category(ch)
            self.assertNotEqual(cat, "Cc", f"Caractere de controle Cc vazou em {name!r}: {ch!r}")
            self.assertNotIn(ch, BIDI_AND_INVISIBLE_CHARS, f"Caractere Bidi/invisível vazou em {name!r}: {ch!r}")
        self.assertNotIn(
            unicodedata.category(stem[0]),
            ("Mn", "Mc", "Me"),
            f"Marca combinante órfã no início do nome: {name!r}",
        )

        if folder is not None and file_path is not None:
            self.assertFalse(file_path.is_symlink())
            self.assertEqual(file_path.resolve().parent, folder.resolve())

    def test_windows_device_names_bare_and_with_extensions(self) -> None:
        bare_devices = [
            "CON", "con", "PRN", "AUX", "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
            "COM\xb9", "COM\xb2", "LPT\xb3",
        ]
        ext_devices = [
            "CON.txt", "prn.log", "AUX.md", "NUL.json",
            "COM1.tar.gz", "COM9.bak", "LPT1.doc", "LPT9.ini",
            "con .txt", "AUX..md", "NUL:stream",
        ]
        existing: list[str] = []
        for idx, candidate in enumerate(bare_devices + ext_devices):
            generated = sanitize_filename(candidate, f"{idx:08x}-1111-2222-3333-444444444444", existing)
            self._assert_safe_filename(generated)
            existing.append(generated)

        src = self.store.apply(
            "dev-src-con",
            "create",
            title="CON.txt",
            text="Conteúdo seguro para CON.txt.",
        )
        with self.store.connect() as conn:
            fname = conn.execute("SELECT filename FROM records WHERE id=?", (src["id"],)).fetchone()[0]
        self._assert_safe_filename(fname, self.store.folder, self.store.safe_path(fname))
        self.assertEqual(self.store.read(src["id"])["id"], src["id"])

        ent = self.knowledge.apply(
            "dev-ent-aux",
            "entity",
            "AUX.md",
            {
                "entity_kind": "learning_topic",
                "topic_description": "Tópico AUX.md",
                "origin_refs": [{"record_id": self.origin["id"], "revision": 1}],
                "identity_status": "provisional",
            },
        )
        _, paths, _ = self.knowledge.catalog()
        epath = paths[ent["id"]]
        self._assert_safe_filename(epath.name, self.store.vault / "10_Entidades", epath)

    def test_null_bytes_control_chars_rtl_overrides_and_empty_whitespace(self) -> None:
        empty_and_invisible = [
            "",
            " ",
            "   \t\r\n  ",
            "\u00a0\u2003",
            "\x00",
            "\x00\x00",
            "\x7f",
            "\u200b",
            "\u200b\u200c\u200d\ufeff",
            "\u202e",
            "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069",
            "\u0301\u0302\u0303",
        ]
        for idx, raw in enumerate(empty_and_invisible):
            generated = sanitize_filename(raw, f"deadbeef-{idx:04x}", [])
            self._assert_safe_filename(generated)
            with self.assertRaises(Invalid, msg=f"Store deveria rejeitar título invisível/controle {raw!r}"):
                self.store.apply(f"inv-s-{idx}", "create", title=raw, text="Texto válido.")
            with self.assertRaises(Invalid, msg=f"Knowledge deveria rejeitar título invisível/controle {raw!r}"):
                self.knowledge.apply(
                    f"inv-k-{idx}",
                    "entity",
                    raw,
                    {
                        "entity_kind": "learning_topic",
                        "topic_description": "Descrição válida",
                        "origin_refs": [{"record_id": self.origin["id"], "revision": 1}],
                        "identity_status": "provisional",
                    },
                )

        spoofed_titles = [
            "relatorio\u202edm.exe",
            "plano\u2066secreto\u2069final",
            "item\x7fcom_del",
            "nota\u200bzero_width",
            "Relatorio\u200b\u03012026",
            "titulo\x85c1\u2028linha\u2029paragrafo",
        ]
        for idx, spoofed in enumerate(spoofed_titles):
            clean = sanitize_filename(spoofed, f"cafe{idx:04x}", [])
            self._assert_safe_filename(clean)

        combined_spoof = "relatorio\u202edm.exe\x7f\x85\u2028\u2029Relatorio\u200b\u0301"
        try:
            created = self.store.apply("spoof-live", "create", title=combined_spoof, text="Conteúdo íntegro.")
            with self.store.connect() as conn:
                fname = conn.execute("SELECT filename FROM records WHERE id=?", (created["id"],)).fetchone()[0]
            self._assert_safe_filename(fname, self.store.folder, self.store.safe_path(fname))
            self.assertEqual(self.store.read(created["id"])["id"], created["id"])
        except Invalid:
            pass

    def test_traversal_nfc_nfd_combining_emojis_and_length_limits(self) -> None:
        for bad_rel in ("../escape.md", "..\\escape.md", "sub/nota.md", ".", "..", "/abs/nota.md"):
            with self.assertRaises(Invalid):
                self.store.safe_path(bad_rel)

        for idx, trav in enumerate(
            ["../../etc/passwd", "..\\..\\Windows\\System32\\drivers\\etc\\hosts", "....//....//traversal..."]
        ):
            self._assert_safe_filename(sanitize_filename(trav, f"trav-{idx:04x}", []))

        # Combina traversal + emojis + marcas combinantes densas (Zalgo) + 120 chars exatos
        special_120 = ("../../🧠🚀A" + ("\u0300\u0301" * 10) + " " + ("BlocoSeguro." * 10))[:120]
        self.assertEqual(len(special_120), 120)
        created = self.store.apply("trav-emo-120", "create", title=special_120, text=f"Payload {special_120}")
        self.assertEqual(self.store.read(created["id"])["payload"]["content"], f"Payload {special_120}")
        with self.store.connect() as conn:
            fname_sp = conn.execute("SELECT filename FROM records WHERE id=?", (created["id"],)).fetchone()[0]
        self._assert_safe_filename(fname_sp, self.store.folder, self.store.safe_path(fname_sp))
        self.assertLessEqual(len(fname_sp), 110)

        # Colisão Unicode NFD vs NFC
        s_nfd = self.store.apply("nfc-1", "create", title=unicodedata.normalize("NFD", "Café Estratégico"), text="NFD.")
        s_nfc = self.store.apply("nfc-2", "create", title=unicodedata.normalize("NFC", "Café Estratégico"), text="NFC.")
        self.assertNotEqual(s_nfd["id"], s_nfc["id"])
        with self.store.connect() as conn:
            f1 = conn.execute("SELECT filename FROM records WHERE id=?", (s_nfd["id"],)).fetchone()[0]
            f2 = conn.execute("SELECT filename FROM records WHERE id=?", (s_nfc["id"],)).fetchone()[0]
        self.assertNotEqual(f1.casefold(), f2.casefold())
        self._assert_safe_filename(f1, self.store.folder, self.store.safe_path(f1))
        self._assert_safe_filename(f2, self.store.folder, self.store.safe_path(f2))

        # Títulos de 500 caracteres (>120) e caracteres wiki proibidos falham de modo determinístico
        title_500 = "Título Adversarial Extremo " * 20
        self.assertGreater(len(title_500), 500)
        self._assert_safe_filename(sanitize_filename(title_500, "12345678-9999", []))
        with self.assertRaises(Invalid):
            self.store.apply("len-500-s", "create", title=title_500, text="Deve rejeitar >120 chars.")
        for bad_k_title in (title_500, "Colchete [A]", "Pipe A|B", "Hash Tag#1"):
            with self.assertRaises(Invalid):
                self.knowledge.apply(
                    f"badk-{sha(bad_k_title.encode())[:8]}",
                    "entity",
                    bad_k_title,
                    {
                        "entity_kind": "learning_topic",
                        "topic_description": "Teste limites",
                        "origin_refs": [{"record_id": self.origin["id"], "revision": 1}],
                        "identity_status": "provisional",
                    },
                )

    def test_seeded_deterministic_fuzz_corpus(self) -> None:
        rng = random.Random(20261117)
        atoms = [
            "../", "..\\", "CON", "AUX.txt", "LPT1.md", "NUL", "COM9.json",
            "\x00", "\x07", "\x1f", "\x7f", "\x85", "\u2028", "\u2029", "\u202e", "\u200b", "\ufeff",
            "\u0301", "\u0327", "Café", "Cafe\u0301", "🧠", "🚀",
            "   ", "...", "///", "|||", ":::", "???", "***", '"""',
            "Relatório", "Síntese", "2026",
        ]
        seen_names: list[str] = []
        accepted = 0
        rejected = 0
        for i in range(150):
            pieces = [rng.choice(atoms) for _ in range(rng.randint(1, 10))]
            fuzzed_title = "".join(pieces)
            fname = sanitize_filename(fuzzed_title, f"{i:08x}-aaaa-bbbb-cccc", seen_names)
            self._assert_safe_filename(fname)
            seen_names.append(fname)

            if i < 3:
                try:
                    res = self.store.apply(f"rng-s-{i}", "create", title=fuzzed_title, text=f"Amostra {i}")
                    accepted += 1
                    with self.store.connect() as conn:
                        disk_name = conn.execute("SELECT filename FROM records WHERE id=?", (res["id"],)).fetchone()[0]
                    self._assert_safe_filename(disk_name, self.store.folder, self.store.safe_path(disk_name))
                    self.assertEqual(self.store.read(res["id"])["payload"]["content"], f"Amostra {i}")
                except Invalid:
                    rejected += 1

        self.assertEqual(accepted + rejected, 3)
        self.assertGreaterEqual(len(self.store.read_all()), accepted)


class AdversarialAttributionFirewallTests(unittest.TestCase):
    """Firewall epistêmico de atribuição com 4+ interlocutores, homônimos, citações aninhadas e métricas trocadas."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = _temp_workspace()
        base = Path(cls._tmp.name)
        cls.store = Store(base / "sistema", base / "cofre")
        cls.knowledge = Knowledge(cls.store)

        cls.dialogue_5 = (
            "Eu concluí 14 módulos pela manhã. "
            "Bruno Castro revisou 29 contratos; "
            "Carla Ribeiro auditou 43 lotes\n"
            "Diego Nunes validou 67 recibos enquanto Elena Souza arquivou 88 processos."
        )
        cls.nested_text = (
            'Bruno Castro declarou: "Carla Ribeiro bateu 95 pontos no trimestre." '
            'Relato direto:\n"Diego Nunes entregou 51 análises." '
            'Registro coletivo: "Bruno Castro apoiou Elena Souza na entrega."'
        )
        cls.ambig_clause = "Mariana concluiu 54 entrevistas."
        cls.metrics_text = (
            "Ana Martins correu 07:30 e marcou 120 pontos. "
            "Bruno Castro correu 08:15 e marcou 240 pontos; "
            "Carla Ribeiro correu 09:05 e marcou 360 pontos e "
            "Diego Nunes correu 10:40 e marcou 480 pontos."
        )
        master_text = "\n".join([cls.dialogue_5, cls.nested_text, cls.ambig_clause, cls.metrics_text])
        cls.master_source = cls.store.apply(
            "attr-master-source",
            "create",
            title="Fonte Consolidada Multi-Interlocutor",
            text=master_text,
        )
        ref = [{"record_id": cls.master_source["id"], "revision": 1}]

        # Persiste as entidades requeridas pelos testes end-to-end em Knowledge.apply
        cls.speakers: dict[str, str] = {}
        for idx, (full_name, aliases) in enumerate(
            [
                ("Ana Martins", ["Ana"]),
                ("Bruno Castro", ["Bruno"]),
                ("Elena Souza", ["Elena"]),
            ]
        ):
            rec = cls.knowledge.apply(
                f"sp-{idx}",
                "entity",
                full_name,
                {
                    "entity_kind": "person",
                    "display_name": full_name,
                    "aliases": aliases,
                    "origin_refs": ref,
                    "identity_status": "identified",
                },
            )
            cls.speakers[full_name] = rec["id"]

        cls.mariana_l = cls.knowledge.apply(
            "mar-l",
            "entity",
            "Mariana Lopes",
            {
                "entity_kind": "person",
                "display_name": "Mariana Lopes",
                "origin_refs": ref,
                "identity_status": "identified",
            },
        )["id"]
        cls.mariana_a = cls.knowledge.apply(
            "mar-a",
            "entity",
            "Mariana Alves",
            {
                "entity_kind": "person",
                "display_name": "Mariana Alves",
                "origin_refs": ref,
                "identity_status": "identified",
            },
        )["id"]

        cls.owner_id = cls.speakers["Ana Martins"]
        atomic_json(cls.store.root / "execucao.json", {"owner_person_id": cls.owner_id})

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _enriched_records(self) -> tuple[dict, dict[str, str]]:
        records = copy.deepcopy(self.knowledge.catalog()[0])
        roster = dict(self.speakers)
        for extra_id, full_name, aliases in (
            ("sp-carla", "Carla Ribeiro", ["Carla"]),
            ("sp-diego", "Diego Nunes", ["Diego"]),
        ):
            records[extra_id] = {
                "id": extra_id,
                "record_type": "entity",
                "revision": 1,
                "payload": {
                    "entity_kind": "person",
                    "display_name": full_name,
                    "aliases": aliases,
                    "identity_status": "identified",
                },
            }
            roster[full_name] = extra_id
        return records, roster

    def _assertion_payload(
        self,
        subject_id: str,
        value: str | int,
        source_ref: dict,
        quote: str | None = None,
        extra_refs: list[dict] | None = None,
        resolution_ref: dict | None = None,
    ) -> dict:
        refs = [source_ref] + (extra_refs or [])
        payload = {
            "subject_ref": {"record_id": subject_id, "revision": 1},
            "predicate": "reports_value",
            "value": {"type": "number" if isinstance(value, int) else "text", "content": value},
            "nature": "user_report",
            "asserted_by": "teste_fuzz_adversarial",
            "recorded_time": "2026-11-17T12:00:00+00:00",
            "source_refs": refs,
            "context_description": "Diálogo adversarial multi-interlocutor",
            "valid_time": {"precision": "unknown"},
            "review_status": "unreviewed",
        }
        if quote is not None:
            payload["attribution_evidence"] = {"source_ref": source_ref, "quote": quote}
        if resolution_ref is not None:
            payload["attribution_resolution_ref"] = resolution_ref
        return payload

    def test_five_speaker_dialogue_accepts_valid_and_blocks_cross_speaker(self) -> None:
        sref = {"record_id": self.master_source["id"], "revision": 1}
        records, roster = self._enriched_records()

        expected_metrics = [
            ("Ana Martins", "14 módulos"),
            ("Bruno Castro", "29 contratos"),
            ("Carla Ribeiro", "43 lotes"),
            ("Diego Nunes", "67 recibos"),
            ("Elena Souza", "88 processos"),
        ]
        for speaker_name, own_metric in expected_metrics:
            verdict = validate_quote(
                roster[speaker_name],
                self.dialogue_5,
                records,
                owner=self.owner_id,
                value=own_metric,
            )
            self.assertEqual(verdict["status"], "checked_for_known_mentions")

            for other_name, other_metric in expected_metrics:
                if other_name == speaker_name:
                    continue
                with self.assertRaises(AttributionError):
                    validate_quote(
                        roster[speaker_name],
                        self.dialogue_5,
                        records,
                        owner=self.owner_id,
                        value=other_metric,
                    )

        saved = self.knowledge.apply(
            "valid-5sp-elena",
            "assertion",
            "Métrica de Elena Souza",
            self._assertion_payload(self.speakers["Elena Souza"], "88 processos", sref, quote=self.dialogue_5),
        )
        self.assertEqual(saved["status"], "confirmed")
        with self.assertRaises(AttributionError):
            self.knowledge.apply(
                "invalid-5sp-swap",
                "assertion",
                "Métrica trocada",
                self._assertion_payload(self.speakers["Bruno Castro"], "88 processos", sref, quote=self.dialogue_5),
            )

    def test_nested_quotes_and_multi_speaker_ambiguity(self) -> None:
        sref = {"record_id": self.master_source["id"], "revision": 1}
        records, roster = self._enriched_records()

        clause_outer = 'Bruno Castro declarou: "Carla Ribeiro bateu 95 pontos no trimestre."'
        self.assertEqual(
            validate_quote(roster["Bruno Castro"], clause_outer, records, value="95")["status"],
            "checked_for_known_mentions",
        )
        for wrong in ("Carla Ribeiro", "Diego Nunes", "Elena Souza"):
            with self.assertRaises(AttributionError):
                validate_quote(roster[wrong], clause_outer, records, value="95")

        clause_direct = '"Diego Nunes entregou 51 análises."'
        self.assertEqual(
            validate_quote(roster["Diego Nunes"], clause_direct, records, value="51")["status"],
            "checked_for_known_mentions",
        )
        with self.assertRaises(AttributionError):
            validate_quote(roster["Bruno Castro"], clause_direct, records, value="51")

        clause_mixed = 'Registro coletivo: "Bruno Castro apoiou Elena Souza na entrega."'
        for candidate in ("Bruno Castro", "Elena Souza"):
            with self.assertRaises(AttributionError) as ctx:
                self.knowledge.apply(
                    f"mixed-{candidate[:4]}",
                    "assertion",
                    "Citação mista ambígua",
                    self._assertion_payload(self.speakers[candidate], "entrega", sref, quote=clause_mixed),
                )
            self.assertTrue(ctx.exception.ambiguous)

    def test_homonyms_and_partial_first_name_ambiguity(self) -> None:
        sref = {"record_id": self.master_source["id"], "revision": 1}
        records, _ = self._enriched_records()

        records["homonym-1"] = {
            "id": "homonym-1",
            "record_type": "entity",
            "revision": 1,
            "payload": {"entity_kind": "person", "display_name": "João Ferreira", "identity_status": "identified"},
        }
        records["homonym-2"] = {
            "id": "homonym-2",
            "record_type": "entity",
            "revision": 1,
            "payload": {"entity_kind": "person", "display_name": "João Ferreira", "identity_status": "identified"},
        }
        for hid in ("homonym-1", "homonym-2"):
            with self.assertRaises(AttributionError) as ctx:
                validate_quote(hid, "João Ferreira revisou 19 dossiês.", records, value="19")
            self.assertTrue(ctx.exception.ambiguous)

        records["lucas-p"] = {
            "id": "lucas-p",
            "record_type": "entity",
            "revision": 1,
            "payload": {
                "entity_kind": "person",
                "display_name": "Lucas Pereira",
                "aliases": ["Lucas"],
                "identity_status": "identified",
            },
        }
        records["lucas-g"] = {
            "id": "lucas-g",
            "record_type": "entity",
            "revision": 1,
            "payload": {
                "entity_kind": "person",
                "display_name": "Lucas Gomes",
                "aliases": ["Lucas"],
                "identity_status": "identified",
            },
        }
        for lid in ("lucas-p", "lucas-g"):
            with self.assertRaises(AttributionError) as ctx:
                validate_quote(lid, "Lucas aprovou 31 pareceres.", records, value="31")
            self.assertTrue(ctx.exception.ambiguous)

        self.assertEqual(
            validate_quote("lucas-p", "Lucas Pereira aprovou 77 pareceres.", records, value="77")["status"],
            "checked_for_known_mentions",
        )
        with self.assertRaises(AttributionError):
            validate_quote("lucas-g", "Lucas Pereira aprovou 77 pareceres.", records, value="77")

        with self.assertRaises(AttributionError) as ctx:
            self.knowledge.apply(
                "mar-unresolved",
                "assertion",
                "Mariana sem sobrenome",
                self._assertion_payload(self.mariana_l, "54", sref, quote=self.ambig_clause),
            )
        self.assertTrue(ctx.exception.ambiguous)

        clear_clarif = self.store.apply(
            "clarif-clear",
            "create",
            title="Esclarecimento Unívoco",
            text="Refiro-me exclusivamente a Mariana Lopes.",
        )
        clear_ref = {"record_id": clear_clarif["id"], "revision": 1}
        resolved = self.knowledge.apply(
            "mar-resolved",
            "assertion",
            "Mariana esclarecida",
            self._assertion_payload(
                self.mariana_l,
                "54",
                sref,
                quote=self.ambig_clause,
                extra_refs=[clear_ref],
                resolution_ref=clear_ref,
            ),
        )
        self.assertEqual(resolved["status"], "confirmed")

    def test_swapped_numeric_metrics_and_seeded_swap_fuzzing(self) -> None:
        sref = {"record_id": self.master_source["id"], "revision": 1}
        records, roster = self._enriched_records()

        truth = {
            "Ana Martins": ("07:30", 120, "Ana Martins correu 07:30 e marcou 120 pontos."),
            "Bruno Castro": ("08:15", 240, "Bruno Castro correu 08:15 e marcou 240 pontos"),
            "Carla Ribeiro": ("09:05", 360, "Carla Ribeiro correu 09:05 e marcou 360 pontos"),
            "Diego Nunes": ("10:40", 480, "Diego Nunes correu 10:40 e marcou 480 pontos."),
        }

        rng = random.Random(20261118)
        names = list(truth.keys())
        for _ in range(40):
            victim = rng.choice(names)
            donor = rng.choice([n for n in names if n != victim])
            swapped_time, swapped_score, victim_clause = truth[donor][0], truth[donor][1], truth[victim][2]

            with self.assertRaises(AttributionError):
                validate_quote(roster[victim], victim_clause, records, owner=self.owner_id, value=swapped_score)
            with self.assertRaises(AttributionError):
                validate_quote(roster[victim], victim_clause, records, owner=self.owner_id, value=swapped_time)

            legacy_payload = self._assertion_payload(roster[victim], swapped_score, sref, quote=None)
            with self.assertRaises(AttributionError):
                validate_assertion(legacy_payload, records, owner=self.owner_id)

        cit_bruno = {
            "record_id": self.master_source["id"],
            "revision": 1,
            "quote": "Bruno Castro correu 08:15 e marcou 240 pontos",
        }
        ans_check = check_answer("Você marcou 240 pontos.", [cit_bruno], records, owner=self.owner_id)
        self.assertEqual(ans_check["status"], "rejected")
        resp_verdict = inspect_response(
            self.store,
            "swap-ans-block",
            {"answer": "Você marcou 240 pontos.", "citations": [cit_bruno]},
        )
        self.assertEqual(resp_verdict["status"], "rejected")


class AdversarialClaimVerifierTests(unittest.TestCase):
    """Fuzzing e provas adversariais contra `verificador_evidencias.py` e `evidencias.py`."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = _temp_workspace()
        base = Path(cls._tmp.name)
        cls.store = Store(base / "sistema", base / "cofre")
        cls.knowledge = Knowledge(cls.store)
        cls.huge_a = (1 << 220) + 1234567890123456789
        cls.huge_b = (1 << 220) + 9876543210987654321
        cls.hops = 32
        cls.master_doc = {
            "ab": ["A", "requires", "B"],
            "ba": ["B", "requires", "A"],
            "bc": ["B", "requires", "C"],
            "ca": ["C", "requires", "A"],
            "cb": ["C", "requires", "B"],
            "cd": ["C", "requires", "D"],
            "aa": ["A", "precedes", "A"],
            "deep_edges": [[f"node_{i}", "precedes", f"node_{i + 1}"] for i in range(cls.hops)],
            "over_65": [[f"n_{i}", "requires", f"n_{i + 1}"] for i in range(65)],
            "b_true": True,
            "b_false": False,
            "one": 1,
            "zero": 0,
            "two": 2,
            "nested_bool": {"ok": True, "items": [False, 1]},
            "big_a": cls.huge_a,
            "big_b": cls.huge_b,
            "ieee_edge": (1 << 53) + 1,
            "arr": [10, 20, 30],
            "a/b": "barra",
            "m~n": "til",
            "~1": "literal_til_um",
            "~2": "chave_que_exige_escape_02",
            "": "chave_vazia",
        }
        cls.master_src = cls.store.apply(
            "verifier-master-src",
            "create",
            title="Fonte Estruturada Consolidada",
            text=json.dumps(cls.master_doc),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _manifest_and_evidence(self) -> tuple[dict, dict]:
        sid = self.master_src["id"]
        rec = self.store.read(sid)
        manifest = {
            "records": {sid: {"revision": 1, "sha256": verifier.sha(rec)}},
            "stale_ids": [],
            "policy": {"transitive_predicates": ["requires", "precedes"], "max_claims": 64},
        }
        return manifest, {sid: rec}

    def test_cyclic_and_self_loop_chains_are_rejected(self) -> None:
        sid = self.master_src["id"]
        manifest, evidence = self._manifest_and_evidence()

        cyclic_cases = [
            ("cyc-2", ["/ab", "/ba"], ["A", "requires", "A"]),
            ("cyc-3", ["/ab", "/bc", "/ca"], ["A", "requires", "A"]),
            ("cyc-lasso", ["/ab", "/bc", "/cb", "/bc", "/cd"], ["A", "requires", "D"]),
            ("cyc-self", ["/aa", "/aa"], ["A", "precedes", "A"]),
        ]
        for key, paths, claimed_val in cyclic_cases:
            claim = {
                "id": key,
                "kind": "chain",
                "refs": [{"record_id": sid, "revision": 1, "path": p} for p in paths],
                "value": claimed_val,
            }
            res = verifier.assess_claim(claim, evidence, manifest)
            self.assertNotEqual(res["status"], "verified_as_recorded", f"Ciclo aceito em {key}: {res}")

        verdict = inspect_response(
            self.store,
            "cyc-e2e-2",
            {
                "answer_format": "controlled",
                "answer": 'c1 = ["A","requires","A"]',
                "claims": [
                    {
                        "id": "c1",
                        "kind": "chain",
                        "refs": [
                            {"record_id": sid, "revision": 1, "path": "/ab"},
                            {"record_id": sid, "revision": 1, "path": "/ba"},
                        ],
                        "value": ["A", "requires", "A"],
                    }
                ],
            },
        )
        self.assertEqual(verdict["status"], "rejected")
        self.assertFalse(verdict["claims_verified"])

    def test_deep_acyclic_chain_bigint_and_rfc6901_controlled_bundle(self) -> None:
        sid = self.master_src["id"]
        manifest, evidence = self._manifest_and_evidence()

        # Excesso de 65 referências recusado
        over_res = verifier.assess_claim if False else None  # noqa: F841
        with self.assertRaises(verifier.Refusal):
            verifier.assess_claim(
                {
                    "id": "over",
                    "kind": "chain",
                    "refs": [{"record_id": sid, "revision": 1, "path": f"/over_65/{i}"} for i in range(65)],
                    "value": ["n_0", "requires", "n_65"],
                },
                evidence,
                manifest,
            )

        # Pacote controlado consolidando cadeia profunda 32 saltos + inteiros 220-bit + escapes RFC 6901
        expected_chain = ["node_0", "precedes", f"node_{self.hops}"]
        exact_sum = self.huge_a + self.huge_b
        claims = [
            {
                "id": "deep",
                "kind": "chain",
                "refs": [{"record_id": sid, "revision": 1, "path": f"/deep_edges/{i}"} for i in range(self.hops)],
                "value": expected_chain,
            },
            {
                "id": "bigsum",
                "kind": "sum",
                "refs": [
                    {"record_id": sid, "revision": 1, "path": "/big_a"},
                    {"record_id": sid, "revision": 1, "path": "/big_b"},
                ],
                "value": exact_sum,
            },
            {"id": "p1", "kind": "field", "refs": [{"record_id": sid, "revision": 1, "path": "/a~1b"}], "value": "barra"},
            {"id": "p2", "kind": "field", "refs": [{"record_id": sid, "revision": 1, "path": "/~01"}], "value": "literal_til_um"},
            {"id": "p3", "kind": "field", "refs": [{"record_id": sid, "revision": 1, "path": "/"}], "value": "chave_vazia"},
        ]
        rendered = "\n".join(f"{c['id']} = {verifier.encode(c['value']).decode('utf-8')}" for c in claims)
        verdict = inspect_response(
            self.store,
            "consolidated-valid-controlled",
            {"answer_format": "controlled", "answer": rendered, "claims": claims},
        )
        self.assertEqual(verdict["status"], "verified")
        self.assertTrue(verdict["answer_verified"])

    def test_boolean_smuggling_overflow_and_malformed_rfc6901_pointers(self) -> None:
        sid = self.master_src["id"]
        manifest, evidence = self._manifest_and_evidence()

        smuggled_sums = [
            ("sum-true-int", ["/b_true", "/two"], 3),
            ("sum-false-int", ["/b_false", "/two"], 2),
            ("sum-both-bool", ["/b_true", "/b_false"], 1),
            ("sum-both-true", ["/b_true", "/b_true"], 2),
            ("sum-int-claimed-bool", ["/one", "/zero"], True),
            ("sum-zero-claimed-false", ["/zero", "/zero"], False),
        ]
        for key, paths, val in smuggled_sums:
            assessed = verifier.assess_claim(
                {"id": key, "kind": "sum", "refs": [{"record_id": sid, "revision": 1, "path": p} for p in paths], "value": val},
                evidence,
                manifest,
            )
            self.assertNotEqual(assessed["status"], "verified_as_recorded")

        self.assertEqual(
            verifier.assess_claim(
                {"id": "f", "kind": "field", "refs": [{"record_id": sid, "revision": 1, "path": "/ieee_edge"}], "value": float((1 << 53) + 1)},
                evidence,
                manifest,
            )["status"],
            "unsupported_value",
        )
        for bad_rev in (0, -1, 1 << 100, True, 1.0):
            self.assertNotEqual(
                verifier.assess_claim(
                    {"id": "r", "kind": "field", "refs": [{"record_id": sid, "revision": bad_rev, "path": "/one"}], "value": 1},
                    evidence,
                    manifest,
                )["status"],
                "verified_as_recorded",
            )

        giant_ev = {"g1": {"id": "g1", "record_type": "source", "revision": 1, "payload": {"content": '{"giant": ' + ("9" * 6000) + "}"}}}
        giant_man = {"records": {"g1": {"revision": 1, "sha256": ""}}, "stale_ids": [], "policy": manifest["policy"]}
        self.assertEqual(
            verifier.assess_claim(
                {"id": "g", "kind": "field", "refs": [{"record_id": "g1", "revision": 1, "path": "/giant"}], "value": 0},
                giant_ev,
                giant_man,
            )["status"],
            "unstructured_source",
        )
        for raw_bad in ('{"k": 1, "k": 2}', '{"k": NaN}', '{"k": Infinity}'):
            with self.assertRaises(verifier.Refusal):
                verifier.strict(raw_bad)

        for ptr, expected_val in [
            ("/arr/0", 10),
            ("/arr/2", 30),
            ("/a~1b", "barra"),
            ("/m~0n", "til"),
            ("/~01", "literal_til_um"),
            ("/~02", "chave_que_exige_escape_02"),
            ("/", "chave_vazia"),
        ]:
            self.assertEqual(verifier.pointer(self.master_doc, ptr), expected_val)

        malformed_pointers = [
            "", "arr/0", "/" + ("a/" * 260), "/~2", "/~", "/a~b",
            "/arr/-1", "/arr/-0", "/arr/-", "/arr/99", "/arr/abc",
            "/arr/00", "/arr/01", "/arr/\u00b2", "/arr/\u0660", "/arr/\uff10",
        ]
        for bad_ptr in malformed_pointers:
            with self.assertRaises(verifier.Refusal, msg=f"pointer() deveria recusar {bad_ptr!r} com Refusal"):
                verifier.pointer(self.master_doc, bad_ptr)

        e2e_bad = inspect_response(
            self.store,
            "adversarial-rejected-bundle",
            {
                "answer": "Alegações inválidas combinadas.",
                "claims": [
                    {
                        "id": "bool_sum",
                        "kind": "sum",
                        "refs": [
                            {"record_id": sid, "revision": 1, "path": "/b_true"},
                            {"record_id": sid, "revision": 1, "path": "/two"},
                        ],
                        "value": 3,
                    },
                    {
                        "id": "nested_bool",
                        "kind": "field",
                        "refs": [{"record_id": sid, "revision": 1, "path": "/nested_bool"}],
                        "value": {"ok": 1, "items": [0, 1]},
                    },
                    {"id": "ptr_sup2", "kind": "field", "refs": [{"record_id": sid, "revision": 1, "path": "/arr/\u00b2"}], "value": 10},
                    {"id": "ptr_zero", "kind": "field", "refs": [{"record_id": sid, "revision": 1, "path": "/arr/00"}], "value": 10},
                    {"id": "ptr_tilde", "kind": "field", "refs": [{"record_id": sid, "revision": 1, "path": "/~2"}], "value": "x"},
                ],
            },
        )
        self.assertEqual(e2e_bad["status"], "rejected")
        self.assertEqual(len(e2e_bad["claims"]), 5)

    def test_stale_vault_generation_invalidation(self) -> None:
        sid = self.master_src["id"]
        draft = {
            "answer_format": "controlled",
            "answer": "m = 1",
            "claims": [{"id": "m", "kind": "field", "refs": [{"record_id": sid, "revision": 1, "path": "/one"}], "value": 1}],
        }

        r1 = inspect_response(self.store, "gen-r1", draft)
        self.assertEqual(r1["status"], "verified")
        self.knowledge.apply(
            "gen-ent",
            "entity",
            "Tópico Novo",
            {
                "entity_kind": "learning_topic",
                "topic_description": "Muda geração global",
                "origin_refs": [{"record_id": sid, "revision": 1}],
                "identity_status": "provisional",
            },
        )
        recheck_1 = read_receipt(self.store, r1["receipt_id"])
        self.assertEqual(recheck_1["status"], "stale")
        self.assertFalse(recheck_1["answer_verified"])

        with self.assertRaises(Conflict):
            inspect_response(self.store, "gen-mismatch", draft, expected_generation=r1["generation"])


class ChaosCrashAndAntiDirtyReadTests(unittest.TestCase):
    """Simulação de morte abrupta de processos, arquivos truncados, órfãos e adulteração SHA-256."""

    def setUp(self) -> None:
        self._tmp = _temp_workspace()
        base = Path(self._tmp.name)
        self.store = Store(base / "sistema", base / "cofre")
        self.knowledge = Knowledge(self.store)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _make_proposed_source(self, key: str, ident: str, title: str, text: str) -> tuple[Path, bytes]:
        doc = {
            "id": ident,
            "record_type": "source",
            "schema_version": "0.1",
            "revision": 1,
            "title": title,
            "created_at": "2026-11-17T12:00:00+00:00",
            "updated_at": "2026-11-17T12:00:00+00:00",
            "created_by": "ponte_local",
            "access_policy_ref": "proprietario_local",
            "lifecycle_status": "active",
            "payload_format": "brain_json_v1",
            "payload": {
                "source_kind": "conversation",
                "origin_description": "Simulação de queda abrupta",
                "received_at": "2026-11-17T12:00:00+00:00",
                "availability_status": "retained",
                "retention_conditions": "fuzz_chaos_suite",
                "content_locator": "payload.content",
                "content": text,
            },
        }
        raw = render_source(doc)
        fname = sanitize_filename(title, ident, [])
        fp = sha(canon({"kind": "create", "title": title, "text": text, "id": "", "expected": 0, "reason": ""}).encode())
        with self.store.connect() as conn:
            conn.execute(
                "INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?)",
                (key, fp, "proposed", ident, 0, fname, None, sha(raw), raw, None),
            )
        return self.store.folder / fname, raw

    def test_store_proposed_orphan_and_truncated_states_fail_closed(self) -> None:
        orphan_id = "11111111-2222-4333-8444-555555555555"
        path, raw = self._make_proposed_source(
            "chaos-orphan-ok",
            orphan_id,
            "Fonte Órfã Completa",
            "Conteúdo gravado antes da queda da transação final.",
        )
        path.write_bytes(raw)
        with self.assertRaises(Invalid):
            self.store.read(orphan_id)
        self.assertEqual(self.store.list(), [])
        self.assertNotIn(orphan_id, self.knowledge.catalog()[0])

        confirmed = self.store.finish("chaos-orphan-ok")
        self.assertEqual(confirmed, {"status": "confirmed", "id": orphan_id, "revision": 1})
        self.assertEqual(self.store.read(orphan_id)["payload"]["content"], "Conteúdo gravado antes da queda da transação final.")

        trunc_id = "22222222-3333-4444-8555-666666666666"
        tpath, traw = self._make_proposed_source(
            "chaos-trunc-create",
            trunc_id,
            "Fonte Criada Parcialmente",
            "Texto que nunca terminou de ir ao disco.",
        )
        tpath.write_bytes(traw[:48])
        with self.assertRaises(Uncertain):
            self.store.finish("chaos-trunc-create")
        self.assertEqual(self.store.status("chaos-trunc-create")["status"], "proposed")
        tpath.unlink()
        with self.store.connect() as conn:
            conn.execute("DELETE FROM operations WHERE key='chaos-trunc-create'")

        v1_bytes = path.read_bytes()
        self.store.apply(
            "chaos-corr",
            "correct",
            ident=orphan_id,
            expected=1,
            text='{"valor": 200}',
            reason="Teste de queda em retificação",
        )
        v2_bytes = path.read_bytes()
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE operations SET status='proposed', pending=?, result=NULL WHERE key='chaos-corr'",
                (v2_bytes,),
            )
            conn.execute("UPDATE records SET revision=1, digest=? WHERE id=?", (sha(v1_bytes), orphan_id))

        path.write_bytes(v2_bytes[:60])
        for blocked in (
            lambda: self.store.read(orphan_id),
            self.store.list,
            self.knowledge.catalog,
            lambda: Retrieval(self.store).search("Fonte"),
            lambda: self.store.finish("chaos-corr"),
        ):
            with self.assertRaises(Conflict):
                blocked()

        path.unlink()
        with self.assertRaises(Uncertain):
            self.store.finish("chaos-corr")

    def test_knowledge_subprocess_crash_and_tampered_or_truncated_files_fail_closed(self) -> None:
        origin = self.store.apply("k-crash-orig", "create", title="Origem Caos", text="Fonte primária íntegra.")
        payload = {
            "entity_kind": "learning_topic",
            "topic_description": "Entidade interrompida antes do commit SQLite",
            "origin_refs": [{"record_id": origin["id"], "revision": 1}],
            "identity_status": "provisional",
        }

        stray = self.store.vault / "10_Entidades" / "Rascunho Externo Solto.md"
        stray.parent.mkdir(parents=True, exist_ok=True)
        stray.write_text("# Rascunho livre fora do envelope canônico\n", encoding="utf-8")
        _, _, issues = self.knowledge.catalog()
        self.assertEqual(len(issues), 1)
        stray.unlink()

        ctx = multiprocessing.get_context("spawn")
        proc = ctx.Process(
            target=_crash_knowledge_after_flush,
            args=(str(self.store.root), str(self.store.vault), "k-crashed-op", "Entidade Interrompida", payload),
        )
        proc.start()
        proc.join(20)
        if proc.is_alive():
            proc.terminate()
            proc.join(5)
        self.assertEqual(proc.exitcode, 73)

        fresh_k = Knowledge(self.store)
        for blocked_call in (
            fresh_k.catalog,
            fresh_k.audit,
            lambda: fresh_k.search("Entidade"),
            lambda: Retrieval(self.store).search("Entidade"),
        ):
            with self.assertRaises(Conflict):
                blocked_call()

        with self.assertRaises(Conflict):
            fresh_k.apply("k-crashed-op", "entity", "Entidade Interrompida", dict(payload, topic_description="Adulterada"))

        reconciled = fresh_k.apply("k-crashed-op", "entity", "Entidade Interrompida", payload)
        self.assertEqual(reconciled["status"], "confirmed")
        self.assertEqual(fresh_k.read(reconciled["id"])["validity"], "current_within_scope")

        prop_id = "77777777-8888-4999-8aaa-bbbbbbbbbbbb"
        prop_rel = "10_Entidades/Proposta Truncada.md"
        prop_file = self.store.vault / prop_rel
        req = {"kind": "entity", "title": "Proposta Truncada", "payload": payload, "id": None, "expected": None}
        req_json = json.dumps(req, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        req_fp = sha(req_json.encode())
        full_bytes = render_source(
            {
                "id": prop_id,
                "record_type": "entity",
                "schema_version": "0.1",
                "revision": 1,
                "title": "Proposta Truncada",
                "created_at": NOW(),
                "updated_at": NOW(),
                "created_by": "extensao_conhecimento",
                "access_policy_ref": "proprietario_local",
                "lifecycle_status": "active",
                "payload_format": "brain_json_v1",
                "payload": payload,
            }
        )
        prop_file.write_bytes(full_bytes[:42])
        with fresh_k.connect() as conn:
            conn.execute(
                "INSERT INTO operations VALUES(?,?,?,?,?,?)",
                ("op-k-trunc", req_fp, "proposed", prop_rel, full_bytes, json.dumps({"status": "confirmed", "id": prop_id, "revision": 1})),
            )
            conn.execute("INSERT INTO prepared_requests VALUES(?,?,?,0)", ("op-k-trunc", req_fp, req_json))

        with self.assertRaises(Conflict):
            fresh_k.catalog()
        with self.assertRaises((Uncertain, Conflict)):
            fresh_k.apply("op-k-trunc", "entity", "Proposta Truncada", payload)

        prop_file.unlink()
        with fresh_k.connect() as conn:
            conn.execute("DELETE FROM operations WHERE key='op-k-trunc'")
            conn.execute("DELETE FROM prepared_requests WHERE key='op-k-trunc'")

        _, paths, _ = fresh_k.catalog()
        mpath = paths[reconciled["id"]]
        good_bytes = mpath.read_bytes()

        mpath.write_bytes(good_bytes.replace(b"Entidade interrompida", b"Entidade adulterada!!"))
        with self.assertRaises(Conflict):
            fresh_k.catalog()

        mpath.write_bytes(good_bytes[:30])
        with self.assertRaises(Conflict):
            fresh_k.catalog()

        mpath.unlink()
        with self.assertRaises(Conflict):
            fresh_k.catalog()

        mpath.write_bytes(good_bytes)
        self.assertEqual(fresh_k.read(reconciled["id"])["validity"], "current_within_scope")


if __name__ == "__main__":
    unittest.main(verbosity=2)
