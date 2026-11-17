"""Suíte de auditoria de segurança, portabilidade e escala com volume realista de dados."""
import concurrent.futures
import copy
import json
import math
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(ROOT / 'src'))

import autonomia
import melhorias
import nucleo
import recuperacao
import supervisor
from conhecimento import Knowledge
from execucao import DEFAULT
from nucleo import Conflict, REAL_SYSTEM, Store, filename
from recuperacao import Retrieval


class DeterministicHashEmbeddings:
    """Embedder determinístico de 32 dimensões para testes de escala e paridade vetorial."""

    dim = 32

    def chunks(self, text, kind='passage'):
        tokens = [t for t in text.lower().split() if len(t) > 2]
        vec = [0.0] * self.dim
        for idx, tok in enumerate(tokens or ['vazio']):
            h = hash(tok) if False else sum((i + 1) * ord(ch) for i, ch in enumerate(tok))
            slot = h % self.dim
            vec[slot] += 1.0 + (0.1 * ((idx % 3) + 1))
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [[v / norm for v in vec]]


class AuditAndScaleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='audit-scale-', dir=REAL_SYSTEM / 'testes_temporarios')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_windows_reserved_device_names_all_ports(self):
        reserved = [
            'CON', 'prn', 'Aux', 'NUL',
            *(f'COM{i}' for i in range(1, 10)),
            *(f'lpt{i}' for i in range(1, 10)),
            'COM\xb2', 'LPT\xb3',
        ]
        for bad in reserved:
            with self.subTest(name=bad):
                safe = filename(bad, '12345678-aaaa', set())
                self.assertEqual(safe, 'Fonte.md')

    def test_posix_normalized_paths_and_legacy_backslash_dirty_read_block(self):
        s = Store(self.base / 'sys1', self.base / 'vault1')
        k = Knowledge(s)
        src = s.apply('s1', 'create', title='Origem', text='Texto base de controle.')
        ent = k.apply(
            'e1', 'entity', 'Entidade Teste',
            {'entity_kind': 'concept', 'content': 'Conceito A', 'idea_scope': 'local',
             'identity_status': 'identified',
             'origin_refs': [{'record_id': src['id'], 'revision': 1}]},
        )
        with k.connect() as c:
            stored_path = c.execute('SELECT path FROM managed WHERE id=?', (ent['id'],)).fetchone()[0]
        self.assertIn('/', stored_path)
        self.assertNotIn('\\', stored_path)

        # Simula operação pendente legada gravada com barra invertida do Windows
        ghost_id = '99999999-1111-4222-8333-444444444444'
        ghost_rec = {
            'id': ghost_id, 'record_type': 'entity', 'schema_version': '0.1', 'revision': 1,
            'title': 'Pendente Legado', 'created_at': '2026-11-17T00:00:00+00:00',
            'updated_at': '2026-11-17T00:00:00+00:00', 'created_by': 'extensao_conhecimento',
            'access_policy_ref': 'proprietario_local', 'lifecycle_status': 'active',
            'payload_format': 'brain_json_v1',
            'payload': {'entity_kind': 'concept', 'content': 'X', 'idea_scope': 'local',
                        'identity_status': 'identified',
                        'origin_refs': [{'record_id': src['id'], 'revision': 1}]},
        }
        ghost_file = s.vault / '10_Entidades' / 'Pendente Legado.md'
        ghost_bytes = nucleo.render(ghost_rec)
        ghost_file.write_bytes(ghost_bytes)
        with k.connect() as c:
            c.execute(
                'INSERT INTO operations VALUES(?,?,?,?,?,?)',
                ('legacy-win-op', 'fp', 'proposed', r'10_Entidades\Pendente Legado.md', ghost_bytes, '{}'),
            )
        with self.assertRaisesRegex(Conflict, 'ainda não confirmada'):
            k.catalog()

    def test_melhorias_adopt_and_rollback_with_nested_config_directory(self):
        s = Store(self.base / 'sys_cfg', self.base / 'vault_cfg')
        k = Knowledge(s)
        cfg_dir = s.root / 'config'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        initial_cfg = copy.deepcopy(DEFAULT)
        initial_cfg.update(enabled=True, auto_adopt_config=True, message_codec='pretty')
        autonomia.atomic_json(cfg_dir / 'execucao.json', initial_cfg)
        self.assertFalse((s.root / 'execucao.json').exists())

        src = s.apply('cfg-src', 'create', title='Base Candidata', text='Observação de tamanho de payload.')
        comp = melhorias.evaluate(s, 'eval-compact', {'kind': 'message_codec', 'value': 'compact'})
        self.assertTrue(comp['eligible'])

        cand = k.apply(
            'cand-compact', 'improvement_candidate', 'Compactar JSON',
            {
                'purpose': 'Reduzir bytes serializados',
                'problem': 'Indentação desnecessária',
                'basis_refs': [{'record_id': src['id'], 'revision': 1}],
                'acceptance_criteria': ['roundtrip igual e menor tamanho'],
                'comparison': comp,
                'comparison_refs': [{'record_id': src['id'], 'revision': 1}],
                'adoption_status': 'tested',
                'rollback_plan': 'Restaurar pretty',
            },
        )
        adopted = melhorias.adopt(s, 'adopt-nested', cand['id'])
        self.assertEqual(adopted['status'], 'adopted')
        saved_after = json.loads((cfg_dir / 'execucao.json').read_text(encoding='utf-8'))
        self.assertEqual(saved_after['message_codec'], 'compact')
        self.assertFalse((s.root / 'execucao.json').exists())

        rolled = melhorias.rollback(s, 'adopt-nested')
        self.assertEqual(rolled['status'], 'rolled_back')
        saved_rb = json.loads((cfg_dir / 'execucao.json').read_text(encoding='utf-8'))
        self.assertEqual(saved_rb['message_codec'], 'pretty')

    def test_worker_health_liveness_and_supervisor_special_path_escaping(self):
        w_file = self.base / 'worker.json'
        autonomia.atomic_json(w_file, {'pid': os.getpid(), 'status': 'idle', 'updated_at': nucleo.NOW()})
        live = autonomia.worker_health(w_file)
        self.assertTrue(live['pid_alive'])
        self.assertEqual(live['health'], 'idle')

        autonomia.atomic_json(w_file, {'pid': 99999999, 'status': 'running', 'updated_at': nucleo.NOW()})
        dead = autonomia.worker_health(w_file)
        if dead['pid_alive'] is False:
            self.assertEqual(dead['health'], 'not_running')

        tricky_dir = self.base / "pasta d'agua com espaco"
        tricky_dir.mkdir(parents=True, exist_ok=True)
        (tricky_dir / 'src').mkdir(exist_ok=True)
        (tricky_dir / 'src' / 'autonomia.py').write_text('# stub\n', encoding='utf-8')
        pids = supervisor.workers(root=tricky_dir)
        self.assertIsInstance(pids, list)

    def test_vector_blob_storage_and_legacy_json_compatibility(self):
        s = Store(self.base / 'sys_vec', self.base / 'vault_vec')
        a = s.apply('va', 'create', title='Arquitetura Distribuída', text='Consenso raft replicação tolerância a falhas.')
        b = s.apply('vb', 'create', title='Culinária Tropical', text='Receita doce de maracujá fresco.')
        ret = Retrieval(s, embedder=DeterministicHashEmbeddings())

        res1 = ret.search('consenso tolerância falhas', limit=5)
        self.assertEqual(res1['results'][0]['id'], a['id'])

        with ret.connect() as c:
            raw_val = c.execute('SELECT value FROM vectors WHERE id=?', (a['id'],)).fetchone()[0]
            self.assertIsInstance(raw_val, bytes)
            self.assertEqual(len(raw_val), 32 * 8)
            # Converte uma linha para JSON texto legado e garante compatibilidade mista
            legacy_json = json.dumps(list(recuperacao._unpack_vector(raw_val)))
            c.execute('UPDATE vectors SET value=? WHERE id=?', (legacy_json, b['id']))
            c.execute('DELETE FROM cache')

        res2 = ret.search('consenso tolerância falhas', limit=5)
        self.assertEqual([r['id'] for r in res2['results']], [r['id'] for r in res1['results']])

    def test_template_initializer_creates_all_canonical_folders(self):
        dest = self.base / 'novo_cofre_limpo'
        # Usa Store permitido sob testes_temporarios verificando VAULT_DIRS diretamente
        proc = subprocess.run(
            [sys.executable, str(ROOT / 'scripts' / 'iniciar-template.py'), '--destino', str(dest), '--nome', 'Cofre Auditoria'],
            cwd=str(ROOT),
            env=dict(os.environ, EMC_SYSTEM=str(self.base / 'sys_tpl'), EMC_VAULT=str(dest), PYTHONUTF8='1'),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
        for expected_dir in ('00_Manual', '10_Entidades', '20_Afirmacoes', '30_Fontes', '40_Avaliacoes', '50_Sinteses', '60_Questoes', '70_Operacao', '80_Visoes'):
            self.assertTrue((dest / expected_dir).is_dir(), msg=f'Pasta ausente: {expected_dir}')

    def test_multi_hundred_records_scale_cascade_and_concurrent_queries(self):
        """Popula 135 registros interligados, executa buscas concorrentes e valida cascata multi-salto."""
        s = Store(self.base / 'sys_scale', self.base / 'vault_scale')
        k = Knowledge(s)
        emb = DeterministicHashEmbeddings()
        ret = Retrieval(s, embedder=emb)

        domains = ('infraestrutura', 'juridico', 'financas', 'seguranca', 'produto')
        sources = []
        persons = []
        projects = []
        assertions = []
        syntheses = []

        # 30 fontes primárias
        for i in range(30):
            dom = domains[i % len(domains)]
            person_name = f'Especialista {i % 10}'
            src = s.apply(
                f'scale-src-{i}', 'create',
                title=f'Relatório {dom.title()} #{i:03d}',
                text=f'{person_name} registrou indicador {100 + i} no domínio {dom} com meta trimestral.',
            )
            sources.append(src)

        # 10 pessoas + 10 projetos (20 entidades)
        for p_idx in range(10):
            p_rec = k.apply(
                f'scale-person-{p_idx}', 'entity', f'Especialista {p_idx}',
                {
                    'entity_kind': 'person',
                    'display_name': f'Especialista {p_idx}',
                    'identity_status': 'identified',
                    'origin_refs': [{'record_id': sources[p_idx]['id'], 'revision': 1}],
                },
            )
            persons.append(p_rec)

        for prj_idx in range(10):
            dom = domains[prj_idx % len(domains)]
            prj = k.apply(
                f'scale-proj-{prj_idx}', 'entity', f'Programa {dom.title()} {prj_idx}',
                {
                    'entity_kind': 'project',
                    'purpose': f'Evolução contínua da frente {dom} ({prj_idx})',
                    'project_status': 'active',
                    'identity_status': 'identified',
                    'origin_refs': [{'record_id': sources[prj_idx]['id'], 'revision': 1}],
                },
            )
            projects.append(prj)

        # 60 afirmações com atribuição literal verificada
        for a_idx in range(60):
            src = sources[a_idx % 30]
            p_idx = (a_idx % 30) % 10
            dom = domains[(a_idx % 30) % len(domains)]
            quote = f'Especialista {p_idx} registrou indicador {100 + (a_idx % 30)} no domínio {dom} com meta trimestral.'
            a_rec = k.apply(
                f'scale-assert-{a_idx}', 'assertion', f'Métrica {dom} {a_idx:03d}',
                {
                    'subject_ref': {'record_id': persons[p_idx]['id'], 'revision': 1},
                    'predicate': 'reports_value',
                    'value': {'type': 'number', 'content': 100 + (a_idx % 30)},
                    'nature': 'third_party_report',
                    'asserted_by': 'scale_harness',
                    'recorded_time': '2026-11-17T12:00:00+00:00',
                    'source_refs': [{'record_id': src['id'], 'revision': 1}],
                    'attribution_evidence': {'source_ref': {'record_id': src['id'], 'revision': 1}, 'quote': quote},
                    'context_description': f'Ciclo {dom}',
                    'valid_time': {'precision': 'unknown'},
                    'review_status': 'unreviewed',
                },
            )
            assertions.append(a_rec)

        # 25 sínteses derivadas em 2º salto (apontando para afirmações + projetos) -> Total = 135 registros
        for s_idx in range(25):
            base_a1 = assertions[s_idx * 2]
            base_a2 = assertions[s_idx * 2 + 1]
            base_prj = projects[s_idx % len(projects)]
            syn = k.apply(
                f'scale-syn-{s_idx}', 'synthesis', f'Síntese Executiva {s_idx:02d}',
                {
                    'synthesis_kind': 'knowledge_summary',
                    'content': f'Consolidação dos indicadores do bloco {s_idx} para {domains[s_idx % 5]}.',
                    'scope': 'Bloco trimestral fictício',
                    'basis_refs': [
                        {'record_id': base_a1['id'], 'revision': 1},
                        {'record_id': base_a2['id'], 'revision': 1},
                        {'record_id': base_prj['id'], 'revision': 1},
                    ],
                    'limitations': ['Dados sintéticos de escala'],
                    'coverage_status': 'provisional',
                    'as_of': '2026-11-17',
                },
            )
            syntheses.append(syn)

        records, _, issues = k.catalog()
        self.assertEqual(len(records), 135)
        self.assertEqual(issues, [])
        self.assertEqual(len(k.stale(records)), 0)

        # Indexação inicial + consultas concorrentes em múltiplas threads
        initial_hit = ret.search('infraestrutura indicador trimestral', limit=15, depth=1)
        self.assertEqual(len(initial_hit['results']), 15)
        self.assertEqual(initial_hit['excluded_stale'], 0)

        queries = [f'{d} indicador meta' for d in domains] + ['infraestrutura indicador trimestral'] * 3
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            outputs = list(pool.map(lambda q: ret.search(q, limit=10, depth=1), queries))
        for out in outputs:
            self.assertTrue(out['results'])

        # Retifica 3 fontes-base (0, 1, 2) e verifica propagação transitiva exata (fonte -> afirmação -> síntese)
        for idx in (0, 1, 2):
            dom = domains[idx % len(domains)]
            s.apply(
                f'scale-rect-{idx}', 'correct', ident=sources[idx]['id'], expected=1,
                text=f'Especialista {idx} retificou indicador para {900 + idx} no domínio {dom} após auditoria.',
                reason='Auditoria de carga e propagação em cascata',
            )

        after_records, _, _ = k.catalog()
        stale_after = k.stale(after_records)
        # Cada fonte i in (0,1,2) sustenta assertions[i] e assertions[i+30] (6 afirmações) + sínteses dependentes
        for idx in (0, 1, 2):
            self.assertIn(assertions[idx]['id'], stale_after)
            self.assertIn(assertions[idx + 30]['id'], stale_after)
        self.assertIn(syntheses[0]['id'], stale_after)
        self.assertIn(syntheses[1]['id'], stale_after)
        # Fontes não tocadas (ex.: índice 4 e síntese 3 apoiada nas fontes 3, 6 e 7) continuam 100% vigentes
        self.assertNotIn(assertions[4]['id'], stale_after)
        self.assertNotIn(syntheses[3]['id'], stale_after)

        post_search = ret.search('infraestrutura indicador', limit=20, depth=1)
        self.assertEqual(post_search['excluded_stale'], len(stale_after))
        for item in post_search['results']:
            self.assertNotIn(item['id'], stale_after)


if __name__ == '__main__':
    unittest.main()
