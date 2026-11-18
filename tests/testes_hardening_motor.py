"""Suíte de hardening do motor: linhagem determinística, resiliência vetorial, RFC-6901 e sanitização."""
import array
import json
import math
import os
import struct
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(ROOT / 'src'))

import recuperacao
import verificador_evidencias as ve
from conhecimento import Knowledge
from evidencias import inspect_response
from nucleo import Conflict, Invalid, REAL_SYSTEM, Store, Uncertain, filename, render
from recuperacao import LocalEmbeddings, Retrieval, _pack_vector, _score_vectors, _unpack_vector


class DeterministicEmbeddings:
    dim = 16

    def chunks(self, text, kind='passage'):
        tokens = [t for t in text.lower().split() if t]
        vec = [0.0] * self.dim
        for idx, tok in enumerate(tokens or ['vazio']):
            slot = sum((i + 1) * ord(ch) for i, ch in enumerate(tok)) % self.dim
            vec[slot] += 1.0 + 0.05 * (idx % 4)
        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        return [[x / norm for x in vec]]


class LineageAndBlastRadiusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hardening-lin-', dir=REAL_SYSTEM / 'testes_temporarios')
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.store = Store(base / 'sistema', base / 'cofre')
        self.k = Knowledge(self.store)

    def test_multi_hop_lineage_diamond_dag_rectification_and_deletion(self):
        s1 = self.store.apply('s1', 'create', title='Fonte Primária Alfa', text='Carla estuda arquitetura distribuída às 08h.')
        s2 = self.store.apply('s2', 'create', title='Fonte Primária Beta', text='Meta anual dedicada ao laboratório.')
        s_child = self.store.apply(
            's-child', 'create', title='Turno Derivado', text='Recorte conversacional.',
            source_metadata={'source_kind': 'conversation_turn', 'parent_source_ref': {'record_id': s1['id'], 'revision': 1}},
        )

        ref_s1 = {'record_id': s1['id'], 'revision': 1}
        ref_s2 = {'record_id': s2['id'], 'revision': 1}

        person = self.k.apply('p1', 'entity', 'Carla', {
            'entity_kind': 'person', 'display_name': 'Carla',
            'identity_status': 'identified', 'origin_refs': [ref_s1],
        })
        project = self.k.apply('prj1', 'entity', 'Projeto Laboratório', {
            'entity_kind': 'project', 'purpose': 'Conduzir laboratório',
            'project_status': 'active', 'identity_status': 'identified', 'origin_refs': [ref_s2],
        })
        goal = self.k.apply('g1', 'entity', 'Meta Laboratório', {
            'entity_kind': 'goal', 'desired_outcome': 'Dominar consenso',
            'goal_status': 'active', 'identity_status': 'identified', 'origin_refs': [ref_s2],
        })

        a1 = self.k.apply('a1', 'assertion', 'Horário de Carla', {
            'subject_ref': {'record_id': person['id'], 'revision': 1},
            'predicate': 'reports_preference',
            'value': {'type': 'text', 'content': '08h'},
            'nature': 'third_party_report',
            'asserted_by': 'auditor_teste',
            'recorded_time': '2026-11-17T10:00:00+00:00',
            'source_refs': [ref_s1],
            'attribution_evidence': {'source_ref': ref_s1, 'quote': 'Carla estuda arquitetura distribuída às 08h.'},
            'context_description': 'Rotina matinal',
            'valid_time': {'precision': 'unknown'},
            'review_status': 'unreviewed',
        })
        a2 = self.k.apply('a2', 'assertion', 'Vínculo de Meta', {
            'subject_ref': {'record_id': project['id'], 'revision': 1},
            'predicate': 'pursues_goal',
            'object_ref': {'record_id': goal['id'], 'revision': 1},
            'nature': 'documented_observation',
            'asserted_by': 'auditor_teste',
            'recorded_time': '2026-11-17T10:00:00+00:00',
            'source_refs': [ref_s2],
            'context_description': 'Planejamento',
            'valid_time': {'precision': 'unknown'},
            'review_status': 'unreviewed',
        })
        syn1 = self.k.apply('syn1', 'synthesis', 'Síntese Nível 1', {
            'synthesis_kind': 'knowledge_summary', 'content': 'Resumo intermediário.',
            'scope': 'estudo', 'basis_refs': [{'record_id': a1['id'], 'revision': 1}, {'record_id': a2['id'], 'revision': 1}],
            'limitations': ['Escopo local'], 'coverage_status': 'provisional', 'as_of': '2026-11-17',
        })
        syn2 = self.k.apply('syn2', 'synthesis', 'Síntese Executiva Nível 2', {
            'synthesis_kind': 'knowledge_summary', 'content': 'Consolidação de segundo salto.',
            'scope': 'estudo', 'basis_refs': [{'record_id': syn1['id'], 'revision': 1}],
            'limitations': ['Segundo salto'], 'coverage_status': 'provisional', 'as_of': '2026-11-17',
        })
        q1 = self.k.apply('q1', 'question', 'Questão Histórica', {
            'question_text': 'Mantém estudo aos sábados?', 'purpose': 'Detalhar rotina',
            'trigger_refs': [ref_s1], 'information_needed': 'agenda', 'impact': 'baixo',
            'question_status': 'open', 'resolution_status': 'unresolved',
        })

        # 1) Introspecção upstream a partir da síntese de topo (3 saltos até 30_Fontes, com diamante A1->Person->S1 e A1->S1)
        lin_syn2 = self.k.lineage(syn2['id'])
        self.assertEqual(lin_syn2['status'], 'ok')
        self.assertFalse(lin_syn2['cycles_detected'])
        self.assertEqual(lin_syn2['cycle_edges'], [])
        self.assertEqual(lin_syn2['target']['status'], 'active')
        self.assertTrue(lin_syn2['target']['sha256_valid'])
        self.assertEqual([x['id'] for x in lin_syn2['upstream']['direct']], [syn1['id']])
        self.assertEqual({x['id'] for x in lin_syn2['upstream']['sources']}, {s1['id'], s2['id']})
        self.assertEqual(
            {x['id'] for x in lin_syn2['upstream']['intermediate']},
            {syn1['id'], a1['id'], a2['id'], person['id'], project['id'], goal['id']},
        )
        for item in lin_syn2['upstream']['all']:
            self.assertTrue(item['revision_valid'])
            self.assertFalse(item['outdated'])
            self.assertTrue(item['sha256_valid'])
            self.assertEqual(len(item['sha256']), 64)

        # 2) Antes da retificação, blast radius de S1 tem todos os dependentes ativos
        lin_s1_before = self.k.lineage(s1['id'])
        self.assertEqual(lin_s1_before['blast_radius']['suspended_count'], 0)
        self.assertEqual(
            set(lin_s1_before['blast_radius']['active_ids']),
            {s_child['id'], person['id'], a1['id'], q1['id'], syn1['id'], syn2['id']},
        )

        # 3) Retifica S1 -> cascata suspende Person, A1, Syn1 e Syn2; Q1 e S_child permanecem ativos; Goal e A2 intactos
        self.store.apply('s1-rect', 'correct', ident=s1['id'], expected=1, text='Carla estuda arquitetura distribuída às 19h.', reason='Mudança de turno')
        lin_s1_after = self.k.lineage(s1['id'])
        self.assertEqual(lin_s1_after['target']['revision'], 2)
        self.assertEqual(set(lin_s1_after['blast_radius']['suspended_ids']), {person['id'], a1['id'], syn1['id'], syn2['id']})
        self.assertEqual(set(lin_s1_after['blast_radius']['active_ids']), {s_child['id'], q1['id']})

        lin_syn2_after = self.k.lineage(syn2['id'])
        self.assertEqual(lin_syn2_after['target']['status'], 'suspended')
        s1_up = next(x for x in lin_syn2_after['upstream']['sources'] if x['id'] == s1['id'])
        s2_up = next(x for x in lin_syn2_after['upstream']['sources'] if x['id'] == s2['id'])
        self.assertEqual(s1_up['pinned_revision'], 1)
        self.assertEqual(s1_up['current_revision'], 2)
        self.assertFalse(s1_up['revision_valid'])
        self.assertTrue(s1_up['outdated'])
        self.assertTrue(s1_up['sha256_valid'])
        self.assertTrue(s2_up['revision_valid'])
        self.assertFalse(s2_up['outdated'])

        # 4) Exclusão controlada de S2 -> aparece como excluded/unavailable na linhagem upstream de A2
        self.store.delete('del-s2', s2['id'], 1)
        lin_a2 = self.k.lineage(a2['id'])
        self.assertEqual(lin_a2['target']['status'], 'suspended')
        s2_deleted = next(x for x in lin_a2['upstream']['sources'] if x['id'] == s2['id'])
        self.assertEqual(s2_deleted['status'], 'excluded')
        self.assertIsNone(s2_deleted['current_revision'])
        self.assertIsNone(s2_deleted['sha256'])
        self.assertFalse(s2_deleted['sha256_valid'])
        self.assertFalse(s2_deleted['revision_valid'])

        for bad_id in ('', '   ', None, s2['id'], 'inexistente-000'):
            with self.assertRaises(Invalid):
                self.k.lineage(bad_id)

    def test_lineage_cycle_safe_traversal_on_cyclic_graph(self):
        fake_records = {
            'n1': {
                'id': 'n1', 'title': 'Nó 1', 'record_type': 'synthesis', 'revision': 1,
                'payload': {'basis_refs': [{'record_id': 'n2', 'revision': 1}]},
            },
            'n2': {
                'id': 'n2', 'title': 'Nó 2', 'record_type': 'synthesis', 'revision': 1,
                'payload': {'basis_refs': [{'record_id': 'n3', 'revision': 1}]},
            },
            'n3': {
                'id': 'n3', 'title': 'Nó 3', 'record_type': 'synthesis', 'revision': 1,
                'payload': {'basis_refs': [{'record_id': 'n1', 'revision': 1}, {'record_id': 'n3', 'revision': 1}]},
            },
        }
        with patch.object(self.k, 'catalog', return_value=(fake_records, {}, [])):
            res = self.k.lineage('n1')
        self.assertEqual(res['status'], 'ok')
        self.assertTrue(res['cycles_detected'])
        self.assertTrue(len(res['cycle_edges']) >= 1)
        self.assertEqual({x['id'] for x in res['upstream']['all']}, {'n2', 'n3'})
        self.assertEqual({x['id'] for x in res['downstream']['all']}, {'n2', 'n3'})


class CliLineageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hardening-cli-', dir=REAL_SYSTEM / 'testes_temporarios')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.sys_dir = self.base / 'sistema'
        self.vault_dir = self.base / 'cofre'
        self.store = Store(self.sys_dir, self.vault_dir)
        self.k = Knowledge(self.store)

    def _run_cli(self, *args, extra_env=None):
        env = dict(
            os.environ,
            EMC_SYSTEM=str(self.sys_dir),
            EMC_VAULT=str(self.vault_dir),
            CEREBRO_PESSOAL_ACESSO='permitido',
            CEREBRO_AUTOTESTE='1',
            PYTHONUTF8='1',
        )
        if extra_env:
            env.update(extra_env)
        proc = subprocess.run(
            [sys.executable, str(ROOT / 'src' / 'cli.py'), *args],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
        return json.loads(proc.stdout)

    def test_cli_linhagem_active_suspended_invalid_and_denied(self):
        src = self.store.apply('cli-s1', 'create', title='Fonte CLI', text='Relato base para linhagem CLI.')
        ent = self.k.apply('cli-e1', 'entity', 'Conceito CLI', {
            'entity_kind': 'concept', 'content': 'Conceito', 'idea_scope': 'local',
            'identity_status': 'identified', 'origin_refs': [{'record_id': src['id'], 'revision': 1}],
        })
        syn = self.k.apply('cli-syn1', 'synthesis', 'Síntese CLI', {
            'synthesis_kind': 'knowledge_summary', 'content': 'Síntese sobre conceito.',
            'scope': 'cli', 'basis_refs': [{'record_id': ent['id'], 'revision': 1}],
            'limitations': ['Teste CLI'], 'coverage_status': 'provisional', 'as_of': '2026-11-17',
        })

        out_before = self._run_cli('linhagem', src['id'])
        self.assertEqual(out_before['status'], 'ok')
        self.assertEqual(out_before['blast_radius']['active_count'], 2)
        self.assertEqual(out_before['blast_radius']['suspended_count'], 0)

        self.store.apply('cli-s1-rect', 'correct', ident=src['id'], expected=1, text='Relato retificado.', reason='Teste')
        out_after = self._run_cli('linhagem', src['id'])
        self.assertEqual(out_after['blast_radius']['active_count'], 0)
        self.assertEqual(set(out_after['blast_radius']['suspended_ids']), {ent['id'], syn['id']})

        out_missing = self._run_cli('linhagem', 'nao-existe')
        self.assertEqual(out_missing['status'], 'invalid')

        out_denied = self._run_cli('linhagem', src['id'], extra_env={'CEREBRO_PESSOAL_ACESSO': 'bloqueado'})
        self.assertEqual(out_denied['status'], 'denied')


class VectorResilienceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hardening-vec-', dir=REAL_SYSTEM / 'testes_temporarios')
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.store = Store(base / 'sistema', base / 'cofre')

    def test_unpack_vector_rejects_corrupt_truncated_nan_inf_bool_and_dim_mismatch(self):
        valid_blob = _pack_vector([0.25, -0.5, 0.75, 1.0])
        unpacked = _unpack_vector(valid_blob, expected_dim=4)
        self.assertIsNotNone(unpacked)
        self.assertEqual(list(unpacked), [0.25, -0.5, 0.75, 1.0])
        self.assertEqual(list(_unpack_vector('[0.25, -0.5, 0.75, 1]', expected_dim=4)), [0.25, -0.5, 0.75, 1.0])

        corrupt_inputs = [
            b'',
            b'\x01\x02\x03',
            b'\xff' * 15,
            struct.pack('<4d', 1.0, float('nan'), 0.0, 0.0),
            struct.pack('<4d', 1.0, float('inf'), 0.0, 0.0),
            struct.pack('<4d', 1.0, float('-inf'), 0.0, 0.0),
            '',
            '{json_invalido',
            '[]',
            'null',
            '42',
            '{"a": 1}',
            '[true, 0.5, 0.2, 0.1]',
            '[false, 0.5, 0.2, 0.1]',
            '[NaN, 0.5, 0.2, 0.1]',
            '[Infinity, 0.5, 0.2, 0.1]',
            '["texto", 1, 2, 3]',
            None,
            12345,
        ]
        for raw in corrupt_inputs:
            with self.subTest(raw=raw):
                self.assertIsNone(_unpack_vector(raw, expected_dim=4))
        # Mismatch de dimensão
        self.assertIsNone(_unpack_vector(valid_blob, expected_dim=8))
        self.assertIsNone(_unpack_vector('[1.0, 2.0]', expected_dim=4))

    def test_corrupt_sqlite_vectors_self_heal_during_search_and_fallback_cleanly(self):
        emb = DeterministicEmbeddings()
        ret = Retrieval(self.store, embedder=emb)
        docs = [
            self.store.apply(f'v-{i}', 'create', title=f'Documento Vetorial {i}', text=f' Topico especial {i} consenso distribuido.')
            for i in range(6)
        ]
        first = ret.search('consenso distribuido especial', limit=6)
        self.assertEqual(len(first['results']), 6)

        corruptions = [
            (docs[0]['id'], b'\x00\x01\x02'),  # truncado
            (docs[1]['id'], struct.pack(f'<{emb.dim}d', float('nan'), *([0.1] * (emb.dim - 1)))),  # NaN em dimensão exata
            (docs[2]['id'], struct.pack(f'<{emb.dim}d', float('inf'), *([0.1] * (emb.dim - 1)))),  # Inf em dimensão exata
            (docs[3]['id'], _pack_vector([1.0, 0.0])),  # dimensão incorreta (2 != 16)
            (docs[4]['id'], '{json_corrompido'),  # JSON inválido
            (docs[5]['id'], None),  # NULL no SQLite
        ]
        with ret.connect() as c:
            for doc_id, bad_blob in corruptions:
                c.execute('UPDATE vectors SET value=? WHERE id=?', (bad_blob, doc_id))
            c.execute('DELETE FROM cache')

        # Mesmo diretamente em _score_vectors (com e sem numpy), nenhuma linha corrompida derruba ou contamina o score
        rows_with_one_good = corruptions + [('valid-doc', _pack_vector([1.0] + [0.0] * (emb.dim - 1)))]
        queries = [[1.0] + [0.0] * (emb.dim - 1)]
        self.assertEqual(_score_vectors(rows_with_one_good, queries), {'valid-doc': 1.0})
        with patch.dict(sys.modules, {'numpy': None}):
            self.assertEqual(_score_vectors(rows_with_one_good, queries), {'valid-doc': 1.0})

        # Retrieval.search detecta os blobs inválidos, reindexa automaticamente e devolve todos os 6 resultados íntegros
        healed = ret.search('consenso distribuido especial', limit=6)
        self.assertEqual(len(healed['results']), 6)
        with ret.connect() as c:
            repaired_rows = c.execute('SELECT id, value FROM vectors').fetchall()
        self.assertEqual(len(repaired_rows), 6)
        for _, raw_val in repaired_rows:
            vec = _unpack_vector(raw_val, expected_dim=emb.dim)
            self.assertIsNotNone(vec)
            self.assertEqual(len(vec), emb.dim)

    def test_real_onnx_e5_self_healing_when_model_available(self):
        emb_env = os.environ.get('EMC_EMBEDDINGS_DIR')
        emb_path = Path(emb_env) if emb_env else (ROOT / 'modelos' / 'e5-multilingual-small')
        if not (emb_path / 'model.onnx').is_file():
            self.skipTest('Modelo ONNX E5 local não configurado no ambiente')
        s = Store(Path(self.tmp.name) / 'sys_e5', Path(self.tmp.name) / 'vault_e5')
        embedder = LocalEmbeddings(emb_path)
        ret = Retrieval(s, embedder=embedder)
        d1 = s.apply('e5-1', 'create', title='Segurança de Sistemas', text='Criptografia e verificação de integridade com hashes.')
        ret.search('integridade criptografica', limit=3)
        with ret.connect() as c:
            c.execute('UPDATE vectors SET value=? WHERE id=?', (b'corrupt-blob', d1['id']))
            c.execute('DELETE FROM cache')
        res = ret.search('integridade criptografica', limit=3)
        self.assertEqual(res['results'][0]['id'], d1['id'])


class EvidenceVerifierHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hardening-ev-', dir=REAL_SYSTEM / 'testes_temporarios')
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.store = Store(base / 'sistema', base / 'cofre')
        self.k = Knowledge(self.store)

    def test_rfc6901_tilde_escapes_negative_leading_zero_and_unicode_digit_indices(self):
        doc = {
            'a/b': {'c~d': {'~1': 42, '': 'vazio'}},
            'items': [10, 20, 30],
        }
        self.assertEqual(ve.pointer(doc, '/a~1b/c~0d/~01'), 42)
        self.assertEqual(ve.pointer(doc, '/a~1b/c~0d/'), 'vazio')
        self.assertEqual(ve.pointer(doc, '/items/0'), 10)
        self.assertEqual(ve.pointer(doc, '/items/2'), 30)

        # Escapes ~ malformados exigem invalid_path
        for bad_escape in ('', 'sem-barra', '/~', '/~2', '/a~b', '/~~0', '/' + 'a' * 505, None, 12):
            with self.subTest(path=bad_escape):
                with self.assertRaises(ve.Refusal) as ctx:
                    ve.pointer(doc, bad_escape)
                self.assertEqual(str(ctx.exception), 'invalid_path')

        # Índices negativos, zeros à esquerda, dígitos Unicode não-ASCII, chaves não inteiras e fora de faixa
        for bad_idx in ('/items/-1', '/items/-', '/items/00', '/items/01', '/items/\u00b2', '/items/\u0660', '/items/abc', '/items/3', '/items/999'):
            with self.subTest(path=bad_idx):
                with self.assertRaises(ve.Refusal) as ctx:
                    ve.pointer(doc, bad_idx)
                self.assertEqual(str(ctx.exception), 'missing_value')

    def test_boolean_rejected_in_sum_claims_and_search_bounds(self):
        src = self.store.apply('bool-src', 'create', title='Fonte JSON Booleana', text=json.dumps({
            'flag_true': True,
            'flag_false': False,
            'num_one': 1,
            'num_zero': 0,
            'arr': [10, 20],
        }))
        ref = lambda p: {'record_id': src['id'], 'revision': 1, 'path': p}

        # True + 1 jamais pode ser aceito como 2 em claim sum
        res_bool_op = inspect_response(self.store, 'sum-bool-op', {
            'answer': 'c1 = 2',
            'answer_format': 'controlled',
            'claims': [{'id': 'c1', 'kind': 'sum', 'refs': [ref('/flag_true'), ref('/num_one')], 'value': 2}],
            'citations': [],
        })
        self.assertEqual(res_bool_op['status'], 'rejected')
        self.assertIn('not_integer_operands', res_bool_op['errors'])

        # False + 0 jamais pode ser aceito como 0
        res_false_op = inspect_response(self.store, 'sum-false-op', {
            'answer': 'c1 = 0',
            'answer_format': 'controlled',
            'claims': [{'id': 'c1', 'kind': 'sum', 'refs': [ref('/flag_false'), ref('/num_zero')], 'value': 0}],
            'citations': [],
        })
        self.assertEqual(res_false_op['status'], 'rejected')
        self.assertIn('not_integer_operands', res_false_op['errors'])

        # 1 + 0 com value=True jamais pode ser aceito
        res_bool_val = inspect_response(self.store, 'sum-bool-val', {
            'answer': 'c1 = true',
            'answer_format': 'controlled',
            'claims': [{'id': 'c1', 'kind': 'sum', 'refs': [ref('/num_one'), ref('/num_zero')], 'value': True}],
            'citations': [],
        })
        self.assertEqual(res_bool_val['status'], 'rejected')

        # Superscript '²' via inspect_response mantém evidence_integrity_checked=True e rejeita limpo
        res_sup = inspect_response(self.store, 'ptr-sup', {
            'answer': 'c1 = 10',
            'answer_format': 'controlled',
            'claims': [{'id': 'c1', 'kind': 'field', 'refs': [ref('/arr/\u00b2')], 'value': 10}],
            'citations': [],
        })
        self.assertEqual(res_sup['status'], 'rejected')
        self.assertIn('missing_value', res_sup['errors'])

        # Knowledge.search e Knowledge.contribution rejeitam booleanos disfarçados de int
        with self.assertRaises(Invalid):
            self.k.search('json', limit=True)
        with self.assertRaises(Invalid):
            self.k.search('json', depth=False)
        res_contrib = self.k.contribution('bool-ph', 'Contrib', 'Texto base', [{
            'tipo': 'entity', 'titulo': 'Tema',
            'payload': {
                'entity_kind': 'learning_topic', 'topic_description': 'Tópico',
                'identity_status': 'provisional',
                'origin_refs': [{'record_id': '$fonte', 'revision': True}],
            },
        }])
        self.assertEqual(res_contrib['status'], 'partial')

    def test_cyclic_chain_claims_are_rejected(self):
        src = self.store.apply('chain-src', 'create', title='Grafo Cíclico', text=json.dumps({
            'edges': [
                ['A', 'requires', 'B'],
                ['B', 'requires', 'A'],
                ['B', 'requires', 'C'],
                ['C', 'requires', 'B'],
                ['B', 'requires', 'D'],
                ['C', 'requires', 'D'],
                ['X', 'precedes', 'X'],
            ],
        }))
        ref = lambda idx: {'record_id': src['id'], 'revision': 1, 'path': f'/edges/{idx}'}

        # Ciclo direto A -> B -> A
        cyc1 = inspect_response(self.store, 'cyc-1', {
            'answer': 'c1 = ["A","requires","A"]',
            'answer_format': 'controlled',
            'claims': [{'id': 'c1', 'kind': 'chain', 'refs': [ref(0), ref(1)], 'value': ['A', 'requires', 'A']}],
            'citations': [],
        })
        self.assertEqual(cyc1['status'], 'rejected')
        self.assertIn('cyclic_chain', cyc1['errors'])

        # Ciclo interno A -> B -> C -> B -> D
        cyc2 = inspect_response(self.store, 'cyc-2', {
            'answer': 'c1 = ["A","requires","D"]',
            'answer_format': 'controlled',
            'claims': [{'id': 'c1', 'kind': 'chain', 'refs': [ref(0), ref(2), ref(3), ref(4)], 'value': ['A', 'requires', 'D']}],
            'citations': [],
        })
        self.assertEqual(cyc2['status'], 'rejected')
        self.assertIn('cyclic_chain', cyc2['errors'])

        # Auto-laço X -> X
        cyc3 = inspect_response(self.store, 'cyc-3', {
            'answer': 'c1 = ["X","precedes","X"]',
            'answer_format': 'controlled',
            'claims': [{'id': 'c1', 'kind': 'chain', 'refs': [ref(6), ref(6)], 'value': ['X', 'precedes', 'X']}],
            'citations': [],
        })
        self.assertEqual(cyc3['status'], 'rejected')
        self.assertIn('cyclic_chain', cyc3['errors'])

        # Cadeia acíclica legítima A -> B -> C -> D continua aceita
        valid_chain = inspect_response(self.store, 'chain-ok', {
            'answer': 'c1 = ["A","requires","D"]',
            'answer_format': 'controlled',
            'claims': [{'id': 'c1', 'kind': 'chain', 'refs': [ref(0), ref(2), ref(5)], 'value': ['A', 'requires', 'D']}],
            'citations': [],
        })
        self.assertEqual(valid_chain['status'], 'verified')


class FilenameAndCatalogHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hardening-fs-', dir=REAL_SYSTEM / 'testes_temporarios')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.store = Store(self.base / 'sistema', self.base / 'cofre')
        self.k = Knowledge(self.store)

    def test_unicode_nfc_control_chars_rtl_and_windows_device_extensions(self):
        reserved_with_ext = [
            'CON.txt', 'prn.md', 'Aux.json', 'NUL.tar.gz', 'CLOCK$.log',
            'COM0.txt', 'COM1.json', 'COM9.bak', 'LPT0.log', 'LPT1.txt', 'LPT9.md',
            'COM\xb2.txt', 'LPT\xb3.doc', 'CON .txt',
        ]
        for bad in reserved_with_ext:
            with self.subTest(name=bad):
                self.assertEqual(filename(bad, '12345678-aaaa', []), 'Fonte.md')

        # Remoção de RTL override (Cf), DEL/C1 (Cc), marcas combinantes órfãs e pontos/espaços finais
        spoof = filename('relatorio_\u202edm.exe . . ', '12345678-bbbb', [])
        self.assertNotIn('\u202e', spoof)
        self.assertEqual(spoof, 'relatorio_dm.exe.md')
        self.assertEqual(filename('a\x7f\x85b...', '12345678-cccc', []), 'a b.md')
        self.assertEqual(filename('\u200b\u202e\ufeff', '12345678-dddd', []), 'Fonte.md')
        self.assertEqual(filename('\u0301\u0302\u0303', '12345678-eeee', []), 'Fonte.md')
        self.assertEqual(filename('\u0301 Café  ...', '12345678-ffff', []), 'Café.md')
        tr36_name = filename('Relato\u200b\u0301rio2026', '12345678-9999', [])
        self.assertEqual(tr36_name, unicodedata.normalize('NFC', tr36_name))
        self.assertEqual(tr36_name, 'Relatório2026.md')

        # Normalização NFC evita colisão silenciosa entre NFD (macOS) e NFC (Windows/Linux)
        nfd_title = unicodedata.normalize('NFD', 'Experiência')
        nfc_existing = [unicodedata.normalize('NFC', 'Experiência.md')]
        disambiguated = filename(nfd_title, 'abcdef12-3456', nfc_existing)
        self.assertEqual(disambiguated, 'Experiência — abcdef12.md')
        self.assertEqual(unicodedata.normalize('NFC', disambiguated), disambiguated)

        # Store.apply e Knowledge.apply preservam títulos com \x85, \u2028 e \u2029 sem quebrar cabeçalho JSON
        s_sep = self.store.apply('sep-s1', 'create', title='Título\x85com\u2028separador\u2029Unicode', text='Conteúdo.')
        self.assertEqual(self.store.read(s_sep['id'])['title'], 'Título\x85com\u2028separador\u2029Unicode')
        e_sep = self.k.apply('sep-e1', 'entity', 'Entidade\x85com\u2028separador\u2029Unicode', {
            'entity_kind': 'concept', 'content': 'X', 'idea_scope': 'local',
            'identity_status': 'identified', 'origin_refs': [{'record_id': s_sep['id'], 'revision': 1}],
        })
        self.assertEqual(self.k.read(e_sep['id'])['record']['title'], 'Entidade\x85com\u2028separador\u2029Unicode')

        # Store.apply e Knowledge.apply rejeitam títulos/textos nulos ou só invisíveis
        src = self.store.apply('valid-src', 'create', title='Fonte Válida', text='Conteúdo válido.')
        for bad_title in ('', '   ', '\x00', 'abc\x00def', '\u200b', '\u202e', '\u0301\u0302', '\x7f'):
            with self.subTest(bad_title=bad_title):
                with self.assertRaises(Invalid):
                    self.store.apply('bad-s', 'create', title=bad_title, text='Texto ok')
                with self.assertRaises(Invalid):
                    self.k.apply('bad-k', 'entity', bad_title, {
                        'entity_kind': 'concept', 'content': 'X', 'idea_scope': 'local',
                        'identity_status': 'provisional', 'origin_refs': [{'record_id': src['id'], 'revision': 1}],
                    })
        for bad_path in ('', '../fora.md', 'sub/arq.md', 'sub\\arq.md', 'arq\x00.md', '.', '..'):
            with self.assertRaises(Invalid):
                self.store.safe_path(bad_path)

    def test_orphan_tmp_files_do_not_break_catalog_updates_or_deletes(self):
        s1 = self.store.apply('tmp-s1', 'create', title='Fonte com Tmp', text='Versão 1.')
        self.store.apply('tmp-s1-c', 'correct', ident=s1['id'], expected=1, text='Versão 2.', reason='Teste tmp')
        # Injeta arquivos .tmp órfãos em 30_Fontes, 10_Entidades e estado/revisoes/<id>
        (self.store.folder / 'Fonte com Tmp.md.tmp-orphan1').write_bytes(b'lixo parcial')
        ent_dir = self.store.vault / '10_Entidades'
        ent_dir.mkdir(parents=True, exist_ok=True)
        (ent_dir / 'Entidade.md.tmp-orphan2').write_bytes(b'rascunho interrompido')
        hist_dir = self.store.hist / s1['id']
        (hist_dir / '1.md.tmp-orphan3').write_bytes(b'historico interrompido')

        ent = self.k.apply('tmp-e1', 'entity', 'Entidade', {
            'entity_kind': 'concept', 'content': 'Conceito estável', 'idea_scope': 'local',
            'identity_status': 'identified', 'origin_refs': [{'record_id': s1['id'], 'revision': 2}],
        })
        records, _, issues = self.k.catalog()
        self.assertEqual(issues, [])
        self.assertIn(ent['id'], records)

        # Exclusão controlada limpa inclusive órfãos 1.md.tmp-* no diretório de histórico
        deleted = self.store.delete('tmp-del', s1['id'], 2)
        self.assertEqual(deleted['status'], 'confirmed')
        self.assertFalse(hist_dir.exists())

    def test_catalog_fails_closed_on_truncated_proposed_and_truncated_or_deleted_managed(self):
        src = self.store.apply('cat-s1', 'create', title='Base', text='Texto base.')
        payload = {
            'entity_kind': 'concept', 'content': 'Conceito A', 'idea_scope': 'local',
            'identity_status': 'identified', 'origin_refs': [{'record_id': src['id'], 'revision': 1}],
        }
        ent = self.k.apply('cat-e1', 'entity', 'Conceito Integro', payload)
        ent_path = self.store.vault / '10_Entidades' / 'Conceito Integro.md'
        original_bytes = ent_path.read_bytes()

        # 1) Arquivo não gerenciado avulso continua reportado em issues sem derrubar o catálogo
        stray = self.store.vault / '10_Entidades' / 'Avulso.md'
        stray.write_bytes(b'nota sem envelope')
        _, _, issues = self.k.catalog()
        self.assertEqual(len(issues), 1)
        stray.unlink()

        # 2) Arquivo proposto truncado bloqueia leitura suja com Conflict e levanta Uncertain no replay
        prop_id = '11111111-2222-4333-8444-555555555555'
        prop_rel = '10_Entidades/Proposta Truncada.md'
        prop_path = self.store.vault / prop_rel
        prop_path.write_bytes(b'---\nid: "truncado')
        prop_payload = {
            'entity_kind': 'concept', 'content': 'Proposta', 'idea_scope': 'local',
            'identity_status': 'provisional', 'origin_refs': [{'record_id': src['id'], 'revision': 1}],
        }
        prop_req = {'kind': 'entity', 'title': 'Proposta Truncada', 'payload': prop_payload, 'id': None, 'expected': None}
        from conhecimento import _request_json
        from nucleo import sha
        fp = sha(_request_json(prop_req).encode())
        full_prop_bytes = render({
            'id': prop_id, 'record_type': 'entity', 'schema_version': '0.1', 'revision': 1,
            'title': 'Proposta Truncada', 'created_at': '2026-11-17T00:00:00+00:00',
            'updated_at': '2026-11-17T00:00:00+00:00', 'created_by': 'extensao_conhecimento',
            'access_policy_ref': 'proprietario_local', 'lifecycle_status': 'active',
            'payload_format': 'brain_json_v1', 'payload': prop_payload,
        })
        with self.k.connect() as c:
            c.execute(
                'INSERT INTO operations VALUES(?,?,?,?,?,?)',
                ('prop-trunc', fp, 'proposed', prop_rel, full_prop_bytes, json.dumps({'status': 'confirmed', 'id': prop_id, 'revision': 1})),
            )
            c.execute('INSERT INTO prepared_requests VALUES(?,?,?,0)', ('prop-trunc', fp, _request_json(prop_req)))

        with self.assertRaises(Conflict):
            self.k.catalog()
        with self.assertRaises(Uncertain):
            self.k.apply('prop-trunc', 'entity', 'Proposta Truncada', prop_payload)

        # Limpa proposta simulada
        prop_path.unlink()
        with self.k.connect() as c:
            c.execute("DELETE FROM operations WHERE key='prop-trunc'")
            c.execute("DELETE FROM prepared_requests WHERE key='prop-trunc'")

        # 3) Arquivo gerenciado truncado em disco levanta Conflict
        ent_path.write_bytes(b'---\ntruncado')
        with self.assertRaises(Conflict):
            self.k.catalog()

        # 4) Arquivo gerenciado removido externamente em disco levanta Conflict
        ent_path.unlink()
        with self.assertRaises(Conflict):
            self.k.catalog()

        # Restaura bytes originais -> catálogo volta a ficar íntegro
        ent_path.write_bytes(original_bytes)
        records_ok, _, issues_ok = self.k.catalog()
        self.assertIn(ent['id'], records_ok)
        self.assertEqual(issues_ok, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
