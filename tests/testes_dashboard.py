import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import autonomia
import autoteste
import dashboard


class DashboardDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'estado').mkdir()
        self.execution = {'status': 'ok', 'enabled': True, 'embeddings_enabled': False}
        self.exec_patch = patch.object(dashboard.p, 'estado_execucao', side_effect=lambda: self.execution)
        self.root_patch = patch.object(autoteste, 'REAL_SYSTEM', self.root)
        self.fp_patch = patch.object(autoteste, 'fingerprint', return_value='current')
        for item in (self.exec_patch, self.root_patch, self.fp_patch):
            item.start()
            self.addCleanup(item.stop)

    def write_report(self, **changes):
        report = {'status': 'passed', 'fingerprint': 'current', 'checked_at': 'today',
                  'suites': [{'status': 'passed'}, {'status': 'failed'}]}
        report.update(changes)
        (self.root / 'estado' / 'autoteste.json').write_text(json.dumps(report), encoding='utf8')

    def test_absent_report_is_not_approval(self):
        result = dashboard.dashboard_diagnostic()
        self.assertEqual(result['tests']['status'], 'not_run')
        self.assertFalse(result['embeddings_enabled'])

    def test_report_and_matching_fingerprint_are_reported(self):
        self.write_report(status='failed')
        self.execution['embeddings_enabled'] = True
        result = dashboard.dashboard_diagnostic()
        self.assertEqual((result['tests']['status'], result['tests']['passed'], result['tests']['suites']), ('failed', 1, 2))
        self.assertTrue(result['embeddings_enabled'])

    def test_old_fingerprint_is_stale(self):
        self.write_report(fingerprint='old')
        self.assertEqual(dashboard.dashboard_diagnostic()['tests']['status'], 'stale')

    def test_broken_report_is_unknown(self):
        (self.root / 'estado' / 'autoteste.json').write_text('{', encoding='utf8')
        self.assertEqual(dashboard.dashboard_diagnostic()['tests']['status'], 'unknown')

    def test_disabled_runtime_does_not_claim_vector_search(self):
        self.execution.update(enabled=False, embeddings_enabled=True)
        self.assertFalse(dashboard.dashboard_diagnostic()['embeddings_enabled'])

    def test_access_error_propagates_without_exposing_results(self):
        self.execution = {'status': 'blocked', 'error': 'access disabled'}
        self.assertEqual(dashboard.dashboard_diagnostic(), self.execution)

    def test_page_does_not_hardcode_success_or_hide_search_errors(self):
        self.assertNotIn('100% OK', dashboard.HTML_PAGE)
        self.assertNotIn('ONNX Local E5 Ativo', dashboard.HTML_PAGE)
        self.assertNotIn("fluxo.records || '257'", dashboard.HTML_PAGE)
        self.assertIn("Busca indisponível:", dashboard.HTML_PAGE)
        self.assertIn('Epistemic Memory Core', dashboard.HTML_PAGE)

    def test_all_official_suites_are_hashed_in_code_files(self):
        code_set = set(autonomia.CODE_FILES)
        missing = [f'tests/{name}' for name in autoteste.SUITES if f'tests/{name}' not in code_set]
        self.assertEqual(missing, [])


class DashboardHttpSecurityTests(unittest.TestCase):
    def setUp(self):
        self.server = dashboard.ThreadingHTTPServer(('127.0.0.1', 0), dashboard.DashboardHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._shutdown)

    def _shutdown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def _request(self, path, method='GET', body=None, headers=None):
        req = urllib.request.Request(
            f'http://127.0.0.1:{self.port}{path}',
            data=body,
            headers=headers or {},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, dict(resp.headers), resp.read().decode('utf-8')
        except urllib.error.HTTPError as err:
            try:
                err_body = err.read().decode('utf-8')
            except ConnectionResetError:
                err_body = ''
            return err.code, dict(err.headers), err_body

    def test_blocks_dns_rebinding_host_header(self):
        code, _, raw = self._request('/api/fontes', headers={'Host': 'evil.attacker.example:8080'})
        self.assertEqual(code, 403)
        self.assertEqual(json.loads(raw)['status'], 'denied')

    def test_blocks_post_without_csrf_token_or_with_cross_site_headers(self):
        payload = json.dumps({'consulta': 'teste'}).encode('utf-8')
        code_no_tok, _, _ = self._request('/api/buscar', method='POST', body=payload, headers={'Content-Type': 'application/json'})
        self.assertEqual(code_no_tok, 403)

        code_xsite, _, _ = self._request(
            '/api/buscar', method='POST', body=payload,
            headers={
                'Content-Type': 'application/json',
                'X-EMC-Token': dashboard.SESSION_TOKEN,
                'Sec-Fetch-Site': 'cross-site',
            },
        )
        self.assertEqual(code_xsite, 403)

        code_bad_origin, _, _ = self._request(
            '/api/buscar', method='POST', body=payload,
            headers={
                'Content-Type': 'application/json',
                'X-EMC-Token': dashboard.SESSION_TOKEN,
                'Origin': 'https://evil.example',
            },
        )
        self.assertEqual(code_bad_origin, 403)

    def test_accepts_authenticated_same_origin_post_and_enforces_size_limit(self):
        with patch.object(dashboard.p, 'buscar_contexto', return_value={'status': 'ok', 'results': []}):
            payload = json.dumps({'consulta': 'arquitetura', 'limite': 5}).encode('utf-8')
            code_ok, headers, raw = self._request(
                '/api/buscar', method='POST', body=payload,
                headers={
                    'Content-Type': 'application/json',
                    'X-EMC-Token': dashboard.SESSION_TOKEN,
                    'Origin': f'http://127.0.0.1:{self.port}',
                },
            )
            self.assertEqual(code_ok, 200)
            self.assertEqual(json.loads(raw)['status'], 'ok')
            self.assertEqual(headers.get('X-Frame-Options'), 'DENY')

        huge = b'{"x":"' + (b'a' * (dashboard.MAX_POST_BYTES + 100)) + b'"}'
        code_big, _, _ = self._request(
            '/api/buscar', method='POST', body=huge,
            headers={'Content-Type': 'application/json', 'X-EMC-Token': dashboard.SESSION_TOKEN},
        )
        self.assertEqual(code_big, 413)

    def test_index_html_injects_session_token_and_csp_headers(self):
        code, headers, html = self._request('/')
        self.assertEqual(code, 200)
        self.assertIn(dashboard.SESSION_TOKEN, html)
        self.assertNotIn('__EMC_CSRF_TOKEN__', html)
        self.assertIn("frame-ancestors 'none'", headers.get('Content-Security-Policy', ''))

    def test_rate_limiting_enforces_429_and_window_recovery(self):
        import time

        self.server.rate_limiter = dashboard.RateLimiter(max_requests=2, window_seconds=0.25)
        code1, _, _ = self._request('/')
        code2, _, _ = self._request('/')
        self.assertEqual((code1, code2), (200, 200))

        code_429, headers_429, raw_429 = self._request('/')
        self.assertEqual(code_429, 429)
        self.assertGreaterEqual(int(headers_429.get('Retry-After', '0')), 1)
        self.assertEqual(headers_429.get('X-RateLimit-Limit'), '2')
        self.assertEqual(headers_429.get('X-RateLimit-Remaining'), '0')
        self.assertEqual(json.loads(raw_429)['error'], 'rate_limit_exceeded')

        # POST com corpo JSON sob 429 deve drenar o corpo e responder JSON limpo
        post_payload = json.dumps({'consulta': 'limite', 'padding': 'x' * 4096}).encode('utf-8')
        post_code, post_headers, post_raw = self._request(
            '/api/buscar',
            method='POST',
            body=post_payload,
            headers={
                'Content-Type': 'application/json',
                'X-EMC-Token': dashboard.SESSION_TOKEN,
                'Origin': f'http://127.0.0.1:{self.port}',
            },
        )
        self.assertEqual(post_code, 429)
        self.assertGreaterEqual(int(post_headers.get('Retry-After', '0')), 1)
        self.assertEqual(json.loads(post_raw)['error'], 'rate_limit_exceeded')

        time.sleep(0.3)
        code_ok, _, _ = self._request('/')
        self.assertEqual(code_ok, 200)

        # Limite de 1024 chaves ativas falha fechado e recupera após expiração da janela
        cap = dashboard.RateLimiter(max_requests=1, window_seconds=0.15)
        for idx in range(1024):
            self.assertTrue(cap.allow(f'k-{idx}')[0])
        allowed_extra, rem_extra, retry_extra = cap.allow('k-overflow')
        self.assertFalse(allowed_extra)
        self.assertEqual(rem_extra, 0)
        self.assertGreater(retry_extra, 0.0)
        time.sleep(0.2)
        self.assertTrue(cap.allow('k-overflow')[0])

    def test_run_dashboard_validates_rate_limit_before_binding_socket(self):
        with patch.object(dashboard, 'ThreadingHTTPServer') as srv_cls:
            with self.assertRaises(ValueError):
                dashboard.run_dashboard(port=0, rate_limit_requests=0)
            srv_cls.assert_not_called()


if __name__ == '__main__':
    unittest.main()
