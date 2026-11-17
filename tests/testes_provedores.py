import hashlib,json,os,stat,subprocess,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from nucleo import REAL_SYSTEM,Invalid,Conflict
from provedores import TextModel,parse_json,_resolve_executable,_signed_by_openai


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=REAL_SYSTEM/'testes_temporarios');self.root=Path(self.tmp.name)
        self.executable=self.root/'client.exe';self.executable.write_bytes(b'ficticio')
        self.cfg={'enabled':True,'executable':str(self.executable),'model':'gpt-6.1-terra'}
    def tearDown(self):self.tmp.cleanup()
    def child(self,events,seen):
        class Child:
            returncode=0
            pid=0
            def __init__(child,args,**kwargs):
                seen.append((args,kwargs))
                for event in events:kwargs['stdout'].write((json.dumps(event)+'\n').encode())
                kwargs['stdout'].flush()
            def communicate(child,*args,**kwargs):return (None,None)
            def poll(child):return 0
        return Child
    def test_completed_call_is_cached_and_usage_is_recorded(self):
        seen=[];events=[{'type':'item.completed','item':{'type':'agent_message','text':'{"ok":true}'}},
                        {'type':'turn.completed','usage':{'input_tokens':10,'output_tokens':2}}]
        with patch('provedores.subprocess.Popen',self.child(events,seen)):
            model=TextModel(self.root/'state',self.cfg,1)
            self.assertEqual(model.call('prompt fictício'),{'ok':True})
            self.assertEqual(model.call('prompt fictício'),{'ok':True});self.assertEqual(len(seen),1)
            self.assertEqual(model.summary()['usage']['input_tokens'],10)
            with self.assertRaises(Invalid):model.call('outra chamada')
    def test_failed_call_is_not_retried_automatically(self):
        seen=[]
        with patch('provedores.subprocess.Popen',self.child([],seen)):
            model=TextModel(self.root/'state',self.cfg,3)
            with self.assertRaises(Invalid):model.call('prompt')
            with self.assertRaises(Conflict):model.call('prompt')
        self.assertEqual(len(seen),1)
    def test_cached_answer_survives_missing_client_without_another_call(self):
        events = [{'type': 'item.completed', 'item': {'type': 'agent_message', 'text': 'null'}},
                  {'type': 'turn.completed', 'usage': {'input_tokens': 3}}]
        model = TextModel(self.root/'state', self.cfg, 1)
        with patch('provedores.subprocess.Popen', self.child(events, [])):
            self.assertIsNone(model.call('consulta fictícia'))
        self.executable.unlink()
        with patch('provedores.subprocess.Popen') as spawn:
            resumed = TextModel(self.root/'state', self.cfg, 1)
            self.assertIsNone(resumed.call('consulta fictícia'))
            self.assertEqual(resumed.summary(), {'calls': 1, 'completed': 1, 'usage': {'input_tokens': 3}})
            with self.assertRaises(Invalid):
                TextModel(self.root/'state', dict(self.cfg, enabled=False), 1).call('consulta fictícia')
            spawn.assert_not_called()

    def test_existing_failed_call_is_still_blocked_when_executable_disappears(self):
        model = TextModel(self.root/'state', self.cfg, 2)
        with patch('provedores.subprocess.Popen', self.child([], [])):
            with self.assertRaises(Invalid):
                model.call('consulta fictícia')
        self.executable.unlink()
        with patch('provedores.subprocess.Popen') as spawn:
            with self.assertRaises(Conflict):
                model.call('consulta fictícia')
            spawn.assert_not_called()
        self.assertEqual(model.summary()['calls'], 1)

    def test_reservation_is_checked_again_after_client_lookup(self):
        model = TextModel(self.root/'state', self.cfg, 2)
        def concurrent_reservation(config, deadline):
            key = hashlib.sha256((self.cfg['model'] + '\0consulta fictícia').encode()).hexdigest()
            with model.connect() as connection:
                connection.execute('INSERT INTO calls(key, state) VALUES(?, ?)', (key, 'reserved'))
            return self.executable

        with patch('provedores._resolve_executable', side_effect=concurrent_reservation), patch('provedores.subprocess.Popen') as spawn:
            with self.assertRaises(Conflict):
                model.call('consulta fictícia')
            spawn.assert_not_called()
        self.assertEqual(model.summary()['calls'], 1)
    def test_untrusted_tool_call_is_rejected(self):
        seen=[];events=[{'type':'item.completed','item':{'type':'command_execution'}},{'type':'turn.completed'}]
        with patch('provedores.subprocess.Popen',self.child(events,seen)):
            with self.assertRaises(Invalid):TextModel(self.root/'state',self.cfg,1).call('prompt')
    def test_no_paid_key_or_user_plugins_are_forwarded(self):
        seen=[];events=[{'type':'item.completed','item':{'type':'agent_message','text':'{}'}},{'type':'turn.completed'}]
        with patch.dict('os.environ',{'OPENAI_API_KEY':'ficticio'}),patch('provedores.subprocess.Popen',self.child(events,seen)):
            TextModel(self.root/'state',self.cfg,1).call('prompt')
        args,kwargs=seen[0];self.assertNotIn('OPENAI_API_KEY',kwargs['env']);self.assertIn('--ignore-user-config',args)
        self.assertIn('multi_agent',args);self.assertIn('web_search="disabled"',args)
    def test_disabled_provider_does_not_spawn_a_process(self):
        with patch('provedores.subprocess.Popen') as spawn:
            with self.assertRaises(Invalid):TextModel(self.root/'state',dict(self.cfg,enabled=False),1).call('prompt')
            spawn.assert_not_called()
    def test_duplicate_or_non_json_fields_are_rejected(self):
        for value in ('{"x":1,"x":2}','{"x":NaN}','{"x":Infinity}'):
            with self.assertRaises(Invalid):parse_json(value)


class ClientResolutionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=REAL_SYSTEM/'testes_temporarios')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()/'Codex'/'bin'
        self.root.mkdir(parents=True)
        self.missing = self.root/'00000000'/'codex.exe'
        self.config = {'enabled': True, 'model': 'fixture', 'executable': str(self.missing),
                       'windows_codex_fallback': True}
        patcher = patch('provedores._windows_codex_root', return_value=self.root)
        self.windows_root = patcher.start()
        self.addCleanup(patcher.stop)

    def binary(self, version, timestamp):
        executable = self.root/version/'codex.exe'
        executable.parent.mkdir()
        executable.write_bytes(b'ficticio')
        os.utime(executable, (timestamp, timestamp))
        return executable

    def test_newest_valid_signature_is_selected_inside_configured_installation(self):
        valid = self.binary('aaaaaaaa', 1)
        unsigned = self.binary('bbbbbbbb', 2)
        self.binary('unversioned', 3)
        with patch('provedores._signed_by_openai', side_effect=lambda path, timeout: path == valid) as signature:
            self.assertEqual(_resolve_executable(self.config, time.time()+60), valid)
            self.assertEqual([call.args[0] for call in signature.call_args_list], [unsigned, valid])

    def test_disabled_or_unrelated_fallback_and_unsigned_candidates_reserve_no_call(self):
        self.binary('aaaaaaaa', 1)
        for config in (dict(self.config, windows_codex_fallback=False),
                       dict(self.config, executable=str(self.root.parent/'00000000'/'codex.exe')),
                       self.config):
            with self.subTest(config=config), patch('provedores._signed_by_openai', return_value=False) as signature:
                with patch('provedores.subprocess.Popen') as spawn:
                    model = TextModel(self.root.parent/'state', config, 1)
                    with self.assertRaisesRegex(Invalid, 'autenticação não foi avaliada'):
                        model.call('consulta fictícia')
                    self.assertEqual(model.summary()['calls'], 0)
                    spawn.assert_not_called()
                self.assertEqual(signature.called, config is self.config)

    def test_non_windows_has_no_discovery_and_expired_call_has_no_signature_check(self):
        self.binary('aaaaaaaa', 1)
        with patch('provedores._signed_by_openai') as signature:
            with self.assertRaises(Invalid):
                _resolve_executable(self.config, time.time()-1)
            self.windows_root.return_value = None
            with self.assertRaises(Invalid):
                _resolve_executable(self.config, time.time()+60)
            signature.assert_not_called()

    def test_replaced_candidate_is_rejected_even_after_signature_passes(self):
        def replaced(path, timeout):
            path.write_bytes(b'outro arquivo ficticio')
            return True
        self.binary('aaaaaaaa', 1)
        with patch('provedores._signed_by_openai', side_effect=replaced):
            with self.assertRaises(Invalid):
                _resolve_executable(self.config, time.time()+60)

    def test_redirected_version_directory_is_never_considered(self):
        executable = self.binary('aaaaaaaa', 1)
        original_lstat = Path.lstat
        def lstat(path):
            if path == executable.parent:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
            return original_lstat(path)
        with patch.object(Path, 'lstat', lstat), patch('provedores._signed_by_openai') as signature:
            with self.assertRaises(Invalid):
                _resolve_executable(self.config, time.time()+60)
            signature.assert_not_called()

    def test_windows_signature_uses_system_modules_and_fails_closed(self):
        executable = self.binary('aaaaaaaa', 1)
        with patch.dict(os.environ, {'PSModulePath': 'fixture'}), patch('provedores.subprocess.run') as run:
            run.return_value = subprocess.CompletedProcess([], 0, b'verified\r\n', b'')
            self.assertTrue(_signed_by_openai(executable, 2))
            env = run.call_args.kwargs['env']
            self.assertFalse(any(key.upper() == 'PSMODULEPATH' for key in env))
            self.assertEqual(env['EMC_CODEX_SIGNATURE_CANDIDATE'], str(executable))
            run.side_effect = subprocess.TimeoutExpired('fixture', 2)
            self.assertFalse(_signed_by_openai(executable, 2))


if __name__=='__main__':unittest.main(verbosity=2)
