"""Testes do laboratório determinístico de evolução: novas classes, reversão e auditoria de cadeia."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(ROOT / 'src'))
if str(ROOT / 'tests') not in sys.path:
    sys.path.insert(0, str(ROOT / 'tests'))

from autonomia import atomic_json
from conhecimento import Knowledge
from execucao import DEFAULT, config as load_exec_config
import melhorias
from nucleo import Conflict, Invalid, REAL_SYSTEM, Store, canon, sha


class EvolutionLabTests(unittest.TestCase):
    def setUp(self):
        temp_parent = REAL_SYSTEM / 'testes_temporarios'
        temp_parent.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix='evol-lab-', dir=temp_parent)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.store = Store(self.base / 'sistema', self.base / 'cofre')
        self.k = Knowledge(self.store)
        self.cfg_dir = self.store.root / 'config'
        self.cfg_dir.mkdir(parents=True, exist_ok=True)
        self.cfg_path = self.cfg_dir / 'execucao.json'
        self.initial = copy.deepcopy(DEFAULT)
        self.initial.update(
            enabled=True,
            auto_adopt_config=True,
            message_codec='pretty',
            retrieval_policy='hybrid',
            embeddings={'enabled': False, 'folder': 'modelos/e5-multilingual-small', 'vector_storage': 'json'},
            max_actions=64,
            max_model_calls=3,
            max_seconds=1800,
        )
        self.write_config(self.initial)

    def write_config(self, cfg):
        atomic_json(self.cfg_path, cfg)

    def read_config(self):
        return json.loads(self.cfg_path.read_text(encoding='utf-8'))

    def eval_and_record(self, key_prefix, candidate):
        ev = melhorias.evaluate(self.store, 'eval-' + key_prefix, candidate)
        rec = melhorias.record(self.store, 'rec-' + key_prefix, ev)
        return ev, rec['candidate_record']

    def test_retrieval_policy_favorable_unfavorable_optimal_and_rollback(self):
        # Sem embeddings habilitados, sair de hybrid -> lexical elimina sobrecarga sem perder âncoras lexicais.
        ev_lex, cand_lex = self.eval_and_record(
            'ret-lex',
            {'kind': 'retrieval_policy', 'value': 'lexical', 'reason': 'Alinhar política aos canais ativos'},
        )
        self.assertEqual(ev_lex['status'], 'completed')
        self.assertTrue(ev_lex['eligible'])
        self.assertTrue(ev_lex['checks']['lexical_anchors_preserved'])
        self.assertTrue(ev_lex['checks']['semantic_channel_backed'])
        self.assertEqual(self.k.read(cand_lex['id'])['record']['payload']['adoption_status'], 'tested')

        adopted = melhorias.adopt(self.store, 'adopt-ret-lex', cand_lex['id'])
        self.assertEqual(adopted['status'], 'adopted')
        after_lex = self.read_config()
        self.assertEqual(after_lex['retrieval_policy'], 'lexical')
        self.assertFalse(after_lex['embeddings']['enabled'])
        self.assertEqual(load_exec_config(self.store)['retrieval_policy'], 'lexical')

        # Já ótimo (lexical com embeddings desabilitados): não fabrica adoção no-op.
        ev_noop, cand_noop = self.eval_and_record('ret-noop', {'kind': 'retrieval_policy', 'value': 'lexical'})
        self.assertFalse(ev_noop['eligible'])
        self.assertEqual(self.k.read(cand_noop['id'])['record']['payload']['adoption_status'], 'rejected')
        with self.assertRaises(Invalid):
            melhorias.adopt(self.store, 'adopt-ret-noop', cand_noop['id'])

        # Desfavorável: propor hybrid mantendo embeddings desabilitados é rejeitado.
        ev_bad, cand_bad = self.eval_and_record('ret-unbacked', {'kind': 'retrieval_policy', 'value': 'hybrid'})
        self.assertFalse(ev_bad['eligible'])
        self.assertFalse(ev_bad['checks']['semantic_channel_backed'])
        self.assertEqual(self.k.read(cand_bad['id'])['record']['payload']['adoption_status'], 'rejected')
        with self.assertRaises(Invalid):
            melhorias.adopt(self.store, 'adopt-ret-bad', cand_bad['id'])

        # Reversão atômica restaura exatamente o estado anterior.
        rolled = melhorias.rollback(self.store, 'adopt-ret-lex')
        self.assertEqual(rolled['status'], 'rolled_back')
        self.assertEqual(self.read_config(), self.initial)
        self.assertEqual(self.k.read(cand_lex['id'])['record']['revision'], 3)
        self.assertEqual(self.k.read(cand_lex['id'])['record']['payload']['adoption_status'], 'rolled_back')

        # Quando embeddings estão habilitados no config, lexical -> hybrid melhora revocação RRF e é elegível.
        cfg_emb = copy.deepcopy(self.initial)
        cfg_emb['embeddings']['enabled'] = True
        cfg_emb['retrieval_policy'] = 'lexical'
        self.write_config(cfg_emb)

        ev_hyb, cand_hyb = self.eval_and_record('ret-hyb', {'kind': 'retrieval_policy', 'value': 'hybrid'})
        self.assertTrue(ev_hyb['eligible'])
        self.assertGreater(ev_hyb['comparison']['selected_hits_at_1'], ev_hyb['comparison']['previous_hits_at_1'])
        melhorias.adopt(self.store, 'adopt-ret-hyb', cand_hyb['id'])
        self.assertEqual(self.read_config()['retrieval_policy'], 'hybrid')

        # Com embeddings ativos, regredir de hybrid -> lexical perde revocação semântica e é rejeitado.
        ev_reg = melhorias.evaluate(self.store, 'eval-ret-reg', {'kind': 'retrieval_policy', 'value': 'lexical'})
        self.assertFalse(ev_reg['eligible'])
        melhorias.rollback(self.store, 'adopt-ret-hyb')
        self.assertEqual(self.read_config(), cfg_emb)

    def test_vector_storage_favorable_lossy_rejection_optimal_and_rollback(self):
        # Rejeita formato float32 com perda de precisão de 64 bits mesmo ocupando menos bytes.
        ev_f32, cand_f32 = self.eval_and_record('vec-f32', {'kind': 'vector_storage', 'value': 'packed_f32'})
        self.assertEqual(ev_f32['status'], 'completed')
        self.assertLess(ev_f32['comparison']['selected_bytes'], ev_f32['comparison']['previous_bytes'])
        self.assertFalse(ev_f32['checks']['lossless_roundtrip'])
        self.assertFalse(ev_f32['eligible'])
        with self.assertRaises(Invalid):
            melhorias.adopt(self.store, 'adopt-vec-f32', cand_f32['id'])

        # Adota packed_f64 quando estado atual usa json verboso, preservando permissões e pasta do modelo.
        ev_f64, cand_f64 = self.eval_and_record(
            'vec-f64',
            {'kind': 'vector_storage', 'value': 'packed_f64', 'reason': 'Armazenamento binário IEEE-754 sem perda'},
        )
        self.assertTrue(ev_f64['eligible'])
        self.assertEqual(ev_f64['comparison']['selected_bytes'], 384 * 8)
        self.assertLess(ev_f64['comparison']['selected_bytes'], ev_f64['comparison']['previous_bytes'])
        self.assertTrue(ev_f64['checks']['lossless_roundtrip'])
        self.assertTrue(ev_f64['checks']['cosine_preserved'])

        adopted = melhorias.adopt(self.store, 'adopt-vec-f64', cand_f64['id'])
        self.assertEqual(adopted['status'], 'adopted')
        after_cfg = self.read_config()
        self.assertEqual(after_cfg['embeddings']['vector_storage'], 'packed_f64')
        self.assertFalse(after_cfg['embeddings']['enabled'])
        self.assertEqual(after_cfg['embeddings']['folder'], 'modelos/e5-multilingual-small')
        self.assertEqual(load_exec_config(self.store)['embeddings']['vector_storage'], 'packed_f64')

        # Já em packed_f64: não fabrica adoção no-op e rejeita regressão para json.
        ev_opt = melhorias.evaluate(self.store, 'eval-vec-opt', {'kind': 'vector_storage', 'value': 'packed_f64'})
        self.assertFalse(ev_opt['eligible'])
        ev_json = melhorias.evaluate(self.store, 'eval-vec-json', {'kind': 'vector_storage', 'value': 'json'})
        self.assertFalse(ev_json['eligible'])

        rolled = melhorias.rollback(self.store, 'adopt-vec-f64')
        self.assertEqual(rolled['status'], 'rolled_back')
        self.assertEqual(self.read_config(), self.initial)

    def test_batch_limits_favorable_starvation_budget_expansion_optimal_and_rollback(self):
        # Rejeita limites que estrangulam demandas canônicas ou ampliam franquia de modelo.
        ev_starve = melhorias.evaluate(
            self.store, 'eval-lim-starve', {'kind': 'batch_limits', 'value': {'max_actions': 6, 'max_seconds': 90}}
        )
        self.assertEqual(ev_starve['status'], 'completed')
        self.assertFalse(ev_starve['checks']['all_workloads_viable'])
        self.assertFalse(ev_starve['eligible'])

        ev_expand_calls = melhorias.evaluate(
            self.store, 'eval-lim-calls', {'kind': 'batch_limits', 'value': {'max_model_calls': 6}}
        )
        self.assertFalse(ev_expand_calls['checks']['model_budget_not_expanded'])
        self.assertFalse(ev_expand_calls['eligible'])

        for invalid_val in ({'max_actions': True}, {'max_actions': 0}, {'max_actions': 99}, {'enabled': True}, {}):
            res = melhorias.evaluate(
                self.store, 'eval-lim-inv-' + sha(canon(str(invalid_val)).encode())[:12],
                {'kind': 'batch_limits', 'value': invalid_val},
            )
            self.assertEqual(res['status'], 'limited')
            self.assertFalse(res['eligible'])

        # Adoção favorável 1: reduz de (64, 1800) -> (32, 600).
        ev_step1, cand_step1 = self.eval_and_record(
            'lim-step1',
            {'kind': 'batch_limits', 'value': {'max_actions': 32, 'max_seconds': 600}, 'reason': 'Conter exposição'},
        )
        self.assertTrue(ev_step1['eligible'])
        melhorias.adopt(self.store, 'adopt-lim-1', cand_step1['id'])
        self.assertEqual(self.read_config()['max_actions'], 32)
        self.assertEqual(self.read_config()['max_seconds'], 600)

        # Adoção favorável 2: reduz até a fronteira Pareto canônica (24, 450).
        ev_step2, cand_step2 = self.eval_and_record(
            'lim-step2',
            {'kind': 'batch_limits', 'value': {'max_actions': 24, 'max_seconds': 450}},
        )
        self.assertTrue(ev_step2['eligible'])
        melhorias.adopt(self.store, 'adopt-lim-2', cand_step2['id'])
        self.assertEqual(self.read_config()['max_actions'], 24)
        self.assertEqual(self.read_config()['max_seconds'], 450)

        # Na fronteira ótima: mesma proposta é no-op inelegível; ampliar de volta por candidata também é inelegível.
        ev_noop = melhorias.evaluate(
            self.store, 'eval-lim-noop', {'kind': 'batch_limits', 'value': {'max_actions': 24, 'max_seconds': 450}}
        )
        self.assertFalse(ev_noop['eligible'])
        ev_widen = melhorias.evaluate(
            self.store, 'eval-lim-widen', {'kind': 'batch_limits', 'value': {'max_actions': 32, 'max_seconds': 600}}
        )
        self.assertFalse(ev_widen['checks']['limits_not_expanded'])
        self.assertFalse(ev_widen['eligible'])

        # Se model.enabled=True, não permite esvaziar chamadas necessárias para reparo de formato/atribuição.
        cfg_with_model = self.read_config()
        cfg_with_model['model'] = dict(cfg_with_model['model'], enabled=True)
        self.write_config(cfg_with_model)
        ev_starve_model = melhorias.evaluate(
            self.store, 'eval-lim-model-starve', {'kind': 'batch_limits', 'value': {'max_model_calls': 1}}
        )
        self.assertFalse(ev_starve_model['checks']['all_workloads_viable'])
        self.assertFalse(ev_starve_model['eligible'])

        # Restaura config pré-teste de model.enabled e executa reversão LIFO das duas adoções.
        cfg_with_model['model'] = dict(cfg_with_model['model'], enabled=False)
        self.write_config(cfg_with_model)
        melhorias.rollback(self.store, 'adopt-lim-2')
        self.assertEqual(self.read_config()['max_actions'], 32)
        self.assertEqual(self.read_config()['max_seconds'], 600)
        melhorias.rollback(self.store, 'adopt-lim-1')
        self.assertEqual(self.read_config(), self.initial)

    def test_concurrent_config_drift_blocks_adoption_and_rollback_across_all_new_classes(self):
        cases = (
            ('ret', {'kind': 'retrieval_policy', 'value': 'lexical'}),
            ('vec', {'kind': 'vector_storage', 'value': 'packed_f64'}),
            ('lim', {'kind': 'batch_limits', 'value': {'max_actions': 32, 'max_seconds': 600}}),
        )
        for tag, candidate in cases:
            with self.subTest(tag=tag):
                self.write_config(copy.deepcopy(self.initial))
                _, cand = self.eval_and_record('drift-pre-' + tag, candidate)
                drifted = self.read_config()
                drifted['owner_person_id'] = 'pessoa-concorrente-' + tag
                self.write_config(drifted)
                with self.assertRaises(Conflict):
                    melhorias.adopt(self.store, 'adopt-drift-' + tag, cand['id'])
                self.assertEqual(self.read_config(), drifted)

                # Restaura base avaliada, adota e testa bloqueio de rollback diante de edição externa.
                self.write_config(copy.deepcopy(self.initial))
                melhorias.adopt(self.store, 'adopt-ok-' + tag, cand['id'])
                adopted_cfg = self.read_config()
                external_edit = copy.deepcopy(adopted_cfg)
                external_edit['owner_person_id'] = 'edicao-pos-adocao-' + tag
                self.write_config(external_edit)
                with self.assertRaises(Conflict):
                    melhorias.rollback(self.store, 'adopt-ok-' + tag)
                self.assertEqual(self.read_config(), external_edit)

                # Reconciliando a edição externa, o rollback conclui de forma limpa.
                self.write_config(adopted_cfg)
                melhorias.rollback(self.store, 'adopt-ok-' + tag)
                self.assertEqual(self.read_config(), self.initial)

    def test_audit_adoption_chain_and_diagnostics_detect_drift_tampering_and_broken_chains(self):
        # Estado inicial limpo sem adoções.
        empty_audit = melhorias.audit_adoption_chain(self.store)
        self.assertTrue(empty_audit['healthy'])
        self.assertEqual(empty_audit['status'], 'healthy')
        self.assertEqual(empty_audit['journal_count'], 0)
        self.assertTrue(empty_audit['chain_valid'])
        self.assertFalse(empty_audit['external_drift'])

        # Cadeia multi-classe com adoções e reversões LIFO.
        _, c_codec = self.eval_and_record('chain-codec', {'kind': 'message_codec', 'value': 'compact'})
        melhorias.adopt(self.store, 'z-step1-codec', c_codec['id'])

        _, c_vec = self.eval_and_record('chain-vec', {'kind': 'vector_storage', 'value': 'packed_f64'})
        melhorias.adopt(self.store, 'm-step2-vec', c_vec['id'])

        _, c_lim = self.eval_and_record(
            'chain-lim', {'kind': 'batch_limits', 'value': {'max_actions': 32, 'max_seconds': 600}}
        )
        melhorias.adopt(self.store, 'a-step3-lim', c_lim['id'])
        melhorias.rollback(self.store, 'a-step3-lim')

        _, c_ret = self.eval_and_record('chain-ret', {'kind': 'retrieval_policy', 'value': 'lexical'})
        melhorias.adopt(self.store, 'b-step4-ret', c_ret['id'])

        audit_ok = melhorias.audit_adoption_chain(self.store)
        self.assertTrue(audit_ok['healthy'])
        self.assertTrue(audit_ok['chain_valid'])
        self.assertTrue(audit_ok['config_matches_chain'])
        self.assertFalse(audit_ok['external_drift'])
        self.assertEqual(audit_ok['counts_by_status'], {'adopted': 3, 'rolled_back': 1})
        self.assertEqual(len(audit_ok['chain']), 5)  # 4 adopts + 1 rollback

        diag_ok = melhorias.diagnostics_summary(self.store)
        self.assertTrue(diag_ok['healthy'])
        self.assertEqual(
            diag_ok['supported_evaluators'],
            ['message_codec', 'retrieval_policy', 'vector_storage', 'batch_limits'],
        )
        self.assertEqual(diag_ok['config']['active_tunables']['message_codec'], 'compact')
        self.assertEqual(diag_ok['config']['active_tunables']['retrieval_policy'], 'lexical')
        self.assertEqual(diag_ok['config']['active_tunables']['vector_storage'], 'packed_f64')
        self.assertEqual(diag_ok['evaluations']['total'], 4)
        self.assertEqual(diag_ok['evaluations']['stale_for_current_config'], 4)

        # 1) Deriva externa direta em execucao.json após adoção.
        expected_cfg = self.read_config()
        drifted_cfg = copy.deepcopy(expected_cfg)
        drifted_cfg['max_actions'] = 40
        drifted_cfg['message_codec'] = 'pretty'
        self.write_config(drifted_cfg)

        audit_drift = melhorias.audit_adoption_chain(self.store)
        self.assertFalse(audit_drift['healthy'])
        self.assertEqual(audit_drift['status'], 'degraded')
        self.assertTrue(audit_drift['chain_valid'])
        self.assertFalse(audit_drift['config_matches_chain'])
        self.assertTrue(audit_drift['external_drift'])
        self.assertEqual(audit_drift['drifted_keys'], ['max_actions', 'message_codec'])
        self.assertTrue(any(i['code'] == 'external_config_drift' for i in audit_drift['issues']))

        # 2) Cadeia quebrada: nova adoção aplicada sobre configuração editada externamente.
        _, c_after_gap = self.eval_and_record('chain-gap', {'kind': 'message_codec', 'value': 'compact'})
        melhorias.adopt(self.store, 'x-step5-after-gap', c_after_gap['id'])
        audit_gap = melhorias.audit_adoption_chain(self.store)
        self.assertFalse(audit_gap['healthy'])
        self.assertFalse(audit_gap['chain_valid'])
        self.assertTrue(any(i['code'] == 'broken_chain' for i in audit_gap['issues']))

        # 3) Adulteração criptográfica de journal em estado/adocoes/ e avaliação em estado/melhorias/.
        journal_path = self.store.root / 'estado' / 'adocoes' / 'x-step5-after-gap.json'
        tampered = json.loads(journal_path.read_text(encoding='utf-8'))
        tampered['after']['model']['enabled'] = True
        tampered['intent_hash'] = sha(canon(melhorias._intent(tampered)).encode())
        atomic_json(journal_path, tampered)

        eval_path = self.store.root / 'estado' / 'melhorias' / 'eval-chain-gap.json'
        bad_eval = json.loads(eval_path.read_text(encoding='utf-8'))
        bad_eval['eligible'] = False
        atomic_json(eval_path, bad_eval)
        # Alinha current_raw ao estado anterior de bad_eval para acionar verificação determinística.
        self.write_config(drifted_cfg)

        diag_tampered = melhorias.diagnostics_summary(self.store)
        self.assertFalse(diag_tampered['healthy'])
        self.assertEqual(diag_tampered['status'], 'degraded')
        self.assertTrue(any(i['code'] == 'invalid_journal' for i in diag_tampered['adoption_audit']['issues']))
        self.assertEqual(diag_tampered['evaluations']['invalid_files'], 1)

    def test_lifo_closed_cycle_and_reparse_guard_in_audit_and_diagnostics(self):
        # Ciclo LIFO completo: adopt A -> adopt B -> rollback B -> rollback A retorna ao hash inicial exato.
        _, cand_a = self.eval_and_record('lifo-a', {'kind': 'vector_storage', 'value': 'packed_f64'})
        melhorias.adopt(self.store, 'z-lifo-first', cand_a['id'])

        _, cand_b = self.eval_and_record('lifo-b', {'kind': 'retrieval_policy', 'value': 'lexical'})
        melhorias.adopt(self.store, 'a-lifo-second', cand_b['id'])

        melhorias.rollback(self.store, 'a-lifo-second')
        melhorias.rollback(self.store, 'z-lifo-first')

        audit = melhorias.audit_adoption_chain(self.store)
        self.assertTrue(audit['healthy'])
        self.assertTrue(audit['chain_valid'])
        self.assertTrue(audit['config_matches_chain'])
        self.assertEqual(audit['expected_config_hash'], sha(canon(self.initial).encode()))
        self.assertEqual([step['action'] for step in audit['chain']], ['adopt', 'adopt', 'rollback', 'rollback'])

        # Reparse/symlink simulado em estado é recusado tanto por audit_adoption_chain quanto por diagnostics_summary.
        import types
        from unittest.mock import patch
        bad_dir = self.store.root / 'estado'
        original_lstat = Path.lstat

        def fake_reparse(path, *args, **kwargs):
            info = original_lstat(path, *args, **kwargs)
            if path == bad_dir:
                return types.SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
            return info

        with patch.object(Path, 'lstat', fake_reparse):
            with self.assertRaises(Invalid):
                melhorias.audit_adoption_chain(self.store)
            with self.assertRaises(Invalid):
                melhorias.diagnostics_summary(self.store)


class IsolatedSandboxEvolutionTests(unittest.TestCase):
    """Prova em sandbox AST isolado que nenhum avaliador novo amplia permissões ou depende de Store real."""

    def test_ast_isolated_evaluators_and_permission_non_escalation(self):
        from testes_melhorias_seguranca import Fixture, Invalid as IsolatedInvalid

        with Fixture() as env:
            cfg = env.config()
            cfg.update(
                retrieval_policy='hybrid',
                embeddings={'enabled': False, 'vector_storage': 'json'},
                max_actions=64,
                max_model_calls=3,
                max_seconds=1800,
            )
            env.set_config(cfg)

            # Avalia, registra e adota cada nova classe dentro do módulo isolado por AST.
            for idx, cand_spec in enumerate((
                {'kind': 'retrieval_policy', 'value': 'lexical'},
                {'kind': 'vector_storage', 'value': 'packed_f64'},
                {'kind': 'batch_limits', 'value': {'max_actions': 24, 'max_seconds': 450}},
            )):
                ev = env.m.evaluate(env.sources, f'iso-ev-{idx}', cand_spec)
                self.assertTrue(ev['eligible'])
                cand_id = env.m.record(env.sources, f'iso-rec-{idx}', ev)['candidate_record']['id']
                res = env.m.adopt(env.sources, f'iso-ad-{idx}', cand_id)
                self.assertEqual(res['status'], 'adopted')

            summary = env.m.diagnostics_summary(env.sources)
            self.assertTrue(summary['healthy'])
            self.assertEqual(summary['adoption_audit']['counts_by_status'], {'adopted': 3})
            self.assertFalse(env.config()['model']['enabled'])
            self.assertFalse(env.config()['embeddings']['enabled'])

            # Mesmo recomputando intent_hash num journal interrompido, ampliar franquia ou habilitar provedor falha.
            env.m.rollback(env.sources, 'iso-ad-2')
            ev2 = env.m.evaluate(
                env.sources, 'iso-ev-esc', {'kind': 'batch_limits', 'value': {'max_actions': 24, 'max_seconds': 450}}
            )
            esc_id = env.m.record(env.sources, 'iso-rec-esc', ev2)['candidate_record']['id']
            env.arm('adopt_intent', 'after')
            with self.assertRaises(OSError):
                env.m.adopt(env.sources, 'iso-esc', esc_id)

            clean_journal = json.loads(env.journal('iso-esc').read_text(encoding='utf-8'))
            for mutate_after in (
                lambda after: after['embeddings'].update(enabled=True),
                lambda after: after['model'].update(enabled=True),
                lambda after: after.update(max_model_calls=8),
            ):
                journal = copy.deepcopy(clean_journal)
                mutate_after(journal['after'])
                journal['intent_hash'] = sha(canon(env.m._intent(journal)).encode())
                env.journal('iso-esc').write_text(canon(journal), encoding='utf-8')
                with self.assertRaises(IsolatedInvalid):
                    env.m.adopt(env.sources, 'iso-esc', esc_id)


if __name__ == '__main__':
    unittest.main(verbosity=2)
