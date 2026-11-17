"""Suíte de integração de ponta a ponta do aplicativo Epistemic Dossier Studio."""
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(ROOT / 'src'))

from nucleo import REAL_SYSTEM
from apps.dossie_studio import cli as studio_cli
from apps.dossie_studio.engine_adapter import DossieWorkspace
from apps.dossie_studio.scenarios import load_scenario, simulate_premise_change
from apps.dossie_studio.web import create_studio_server


class DossieStudioScenarioTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='dossie-app-', dir=REAL_SYSTEM / 'testes_temporarios')
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.ws = DossieWorkspace(base / 'sistema', base / 'cofre', enable_embeddings=False)

    def test_engenharia_cotacao_receipt_and_cascade_invalidation(self):
        loaded = load_scenario(self.ws, 'engenharia_cotacao')
        receipt = loaded['receipt']
        self.assertEqual(receipt['status'], 'verified')
        self.assertTrue(receipt['claims_verified'])
        self.assertTrue(receipt['answer_verified'])

        snap_before = self.ws.snapshot()
        self.assertEqual(snap_before['stale_records'], 0)

        mut = simulate_premise_change(self.ws, 'engenharia_cotacao')
        self.assertEqual(mut['update']['revision'], 2)
        self.assertIn(loaded['synthesis_id'], mut['newly_suspended_ids'])
        self.assertIn(receipt['receipt_id'], mut['stale_receipt_ids'])
        self.assertTrue(any('216000' in line for line in mut['diff']))

        search_after = self.ws.search('NebulaCloud', limit=10)
        returned_ids = {r['id'] for r in search_after['results']}
        self.assertNotIn(loaded['synthesis_id'], returned_ids)
        self.assertGreaterEqual(search_after['excluded_stale'], 1)

    def test_juridico_contrato_parent_source_and_human_review_cascade(self):
        loaded = load_scenario(self.ws, 'juridico_contrato')
        self.assertEqual(loaded['receipt']['status'], 'verified')

        mut = simulate_premise_change(self.ws, 'juridico_contrato')
        self.assertEqual(mut['update']['revision'], 2)
        self.assertIn(loaded['synthesis_id'], mut['newly_suspended_ids'])
        self.assertIn(loaded['receipt']['receipt_id'], mut['stale_receipt_ids'])

    def test_pesquisa_decisao_reverse_item_score_and_cascade(self):
        loaded = load_scenario(self.ws, 'pesquisa_decisao')
        score_res = loaded['score_result']
        self.assertEqual(score_res['status'], 'confirmed')
        score_rec = self.ws.knowledge.read(score_res['id'])['record']
        self.assertEqual(score_rec['payload']['dimension_scores']['indice_foco'], 8)
        self.assertNotIn('diagnosis', score_rec['payload'])

        mut = simulate_premise_change(self.ws, 'pesquisa_decisao')
        self.assertEqual(mut['update']['revision'], 2)
        self.assertGreaterEqual(mut['total_stale_records'], 2)
        self.assertEqual(self.ws.knowledge.read(score_res['id'])['validity'], 'needs_revalidation')

    def test_web_studio_security_and_interactive_flows(self):
        server = create_studio_server(self.ws, host='127.0.0.1', port=0)
        port = server.server_address[1]
        token = server.csrf_token
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join(timeout=3)))

        def req(path, method='GET', body=None, headers=None):
            r = urllib.request.Request(
                f'http://127.0.0.1:{port}{path}',
                data=json.dumps(body).encode('utf-8') if isinstance(body, dict) else body,
                headers=headers or {},
                method=method,
            )
            try:
                with urllib.request.urlopen(r, timeout=60) as resp:
                    return resp.status, resp.read().decode('utf-8')
            except urllib.error.HTTPError as err:
                return err.code, err.read().decode('utf-8')

        code_rebind, _ = req('/api/snapshot', headers={'Host': 'evil.rebind.test:8090'})
        self.assertEqual(code_rebind, 403)

        code_no_csrf, _ = req('/api/scenario/load', method='POST', body={'scenario_id': 'engenharia_cotacao'})
        self.assertEqual(code_no_csrf, 403)

        auth_headers = {'X-Dossie-Token': token, 'Origin': f'http://127.0.0.1:{port}'}
        code_fw, raw_fw = req('/api/test-attribution-firewall', method='POST', body={}, headers=auth_headers)
        self.assertEqual(code_fw, 200)
        fw_data = json.loads(raw_fw)
        self.assertTrue(fw_data['firewall_triggered'])
        self.assertEqual(fw_data['verdict'], 'BLOCKED_BY_ATTRIBUTION_FIREWALL')

        code_load, _ = req('/api/scenario/load', method='POST', body={'scenario_id': 'engenharia_cotacao'}, headers=auth_headers)
        self.assertEqual(code_load, 200)

        code_mut, raw_mut = req('/api/scenario/mutate', method='POST', body={'scenario_id': 'engenharia_cotacao'}, headers=auth_headers)
        self.assertEqual(code_mut, 200)
        self.assertGreaterEqual(json.loads(raw_mut)['mutation']['total_stale_records'], 1)

    def test_cli_commands_end_to_end(self):
        cli_ws = Path(self.tmp.name) / 'cli_ws'
        # Subprocess isolated CLI test because bootstrap_environment sets EMC_SYSTEM/EMC_VAULT
        import subprocess
        env = dict(__import__('os').environ, PYTHONUTF8='1')
        for args in (
            ['scenarios'],
            ['--workspace', str(cli_ws), 'load', 'juridico_contrato'],
            ['--workspace', str(cli_ws), 'status'],
            ['--workspace', str(cli_ws), 'search', 'Horizonte'],
            ['--workspace', str(cli_ws), 'mutate', 'juridico_contrato'],
        ):
            proc = subprocess.run(
                [sys.executable, str(ROOT / 'apps' / 'dossie_studio' / 'cli.py'), *args],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            parsed = json.loads(proc.stdout)
            self.assertTrue(parsed)


if __name__ == '__main__':
    unittest.main()
