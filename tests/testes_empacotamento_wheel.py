"""Testes de empacotamento wheel (.whl) a partir de árvore limpa e execução isolada fora do clone."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _export_clean_source_tree(repo_root: Path, dest_dir: Path) -> str:
    """Exporta apenas arquivos rastreados do pacote para dest_dir (usando git archive HEAD quando limpo)."""
    git_dir = repo_root / ".git"
    if git_dir.exists() and shutil.which("git"):
        status = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
        )
        if not status.stdout.strip():
            archive = subprocess.run(
                ["git", "-C", str(repo_root), "archive", "--format=tar", "HEAD"],
                capture_output=True,
                check=True,
            )
            with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as tar:
                tar.extractall(dest_dir, filter="data")
            return "git_archive_head"

        ls_files = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "-z"],
            capture_output=True,
            check=True,
        )
        rel_paths = {p.decode("utf-8") for p in ls_files.stdout.split(b"\x00") if p}
        for new_pkg_file in ("setup.py", "src/recursos_pacote.py"):
            if (repo_root / new_pkg_file).is_file():
                rel_paths.add(new_pkg_file)
        for rel in sorted(rel_paths):
            src_path = repo_root / rel
            if src_path.is_file() and not src_path.is_symlink():
                out_path = dest_dir / rel
                out_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_path, out_path)
        return "git_tracked_working_tree"

    # Fallback para execução em tarball sem diretório .git.
    for top_file in ("pyproject.toml", "setup.py", "README.md", "LICENSE"):
        src_path = repo_root / top_file
        if src_path.is_file():
            shutil.copy2(src_path, dest_dir / top_file)
    for folder, pattern in (("00_Manual", "*.md"), ("config", "*.json"), ("src", "*.py"), ("apps", "*.py")):
        base = repo_root / folder
        if base.is_dir():
            for item in base.rglob(pattern):
                if item.is_file() and "__pycache__" not in item.parts:
                    rel = item.relative_to(repo_root)
                    out_path = dest_dir / rel
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, out_path)
    return "filesystem_tracked_subset"


def _has_local_wheel_backend(python_exe: str, env: dict[str, str]) -> bool:
    probe = (
        "import importlib.util, re, setuptools.build_meta as bm; "
        "reqs = bm.get_requires_for_build_wheel() or []; "
        "missing = [r for r in reqs if importlib.util.find_spec(re.split(r'[<>=!~;\\s\\[]', r.strip())[0]) is None]; "
        "raise SystemExit(1 if missing else 0)"
    )
    proc = subprocess.run(
        [python_exe, "-c", probe],
        env=env,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def _prepare_wheel_build_command(
    dist_dir: Path,
    src_export: Path,
    *,
    python_exe: str = sys.executable,
    base_prefix: Path | None = None,
    environ: dict[str, str] | None = None,
    find_spec_fn=importlib.util.find_spec,
    backend_probe_fn=_has_local_wheel_backend,
) -> tuple[list[str], dict[str, str]]:
    """Monta comando pip wheel usando --no-build-isolation somente quando setuptools está disponível localmente."""
    build_env = dict(os.environ if environ is None else environ)
    build_env.pop("PYTHONPATH", None)
    resolved_base = Path(sys.base_prefix if base_prefix is None else base_prefix)

    can_disable_isolation = False
    if find_spec_fn("setuptools") is not None and backend_probe_fn(python_exe, build_env):
        can_disable_isolation = True
    else:
        candidates = (
            resolved_base / "Lib" / "site-packages",
            resolved_base / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages",
            resolved_base / "lib" / f"python{sys.version_info.major}" / "site-packages",
        )
        for base_sp in candidates:
            if (base_sp / "setuptools").is_dir():
                candidate_env = dict(build_env)
                candidate_env["PYTHONPATH"] = str(base_sp)
                if backend_probe_fn(python_exe, candidate_env):
                    build_env = candidate_env
                    can_disable_isolation = True
                    break

    cmd = [python_exe, "-m", "pip", "wheel"]
    if can_disable_isolation:
        cmd.append("--no-build-isolation")
    cmd.extend(["--no-deps", "-w", str(dist_dir), str(src_export)])
    return cmd, build_env


def _create_dir_redirection(link_path: Path, target_dir: Path) -> None:
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link_path), str(target_dir)],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        os.symlink(target_dir, link_path, target_is_directory=True)


def _remove_dir_redirection(link_path: Path) -> None:
    if not link_path.exists() and not link_path.is_symlink() and not getattr(link_path, "is_junction", lambda: False)():
        return
    if os.name == "nt" and not link_path.is_symlink():
        os.rmdir(link_path)
    else:
        link_path.unlink()


class WheelPackagingTests(unittest.TestCase):
    def test_wheel_bundles_manual_resources_and_runs_store_engine_sdk_and_gateway_outside_clone(self):
        expected_manifest = json.loads((REPO_ROOT / "config" / "manual_manifest.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(expected_manifest), 18)

        # Garante que 00_Manual/ na árvore-fonte continua sem qualquer arquivo Python adicionado.
        self.assertEqual(list((REPO_ROOT / "00_Manual").glob("*.py")), [])

        with tempfile.TemporaryDirectory(prefix="emc-wheel-e2e-") as tmp_str:
            tmp_root = Path(tmp_str).resolve()
            src_export = tmp_root / "clean_source"
            dist_dir = tmp_root / "dist"
            wheel_site = tmp_root / "wheel_site"
            external_cwd = tmp_root / "external_cwd"
            for directory in (src_export, dist_dir, wheel_site, external_cwd):
                directory.mkdir(parents=True, exist_ok=True)

            export_mode = _export_clean_source_tree(REPO_ROOT, src_export)
            self.assertIn(export_mode, ("git_archive_head", "git_tracked_working_tree", "filesystem_tracked_subset"))
            self.assertFalse((src_export / ".git").exists())
            temp_artifacts = [
                p.name for p in (src_export / "testes_temporarios").glob("*") if p.name != ".gitkeep"
            ] if (src_export / "testes_temporarios").exists() else []
            self.assertEqual(temp_artifacts, [])

            build_cmd, build_env = _prepare_wheel_build_command(dist_dir, src_export)
            build_proc = subprocess.run(
                build_cmd,
                cwd=str(external_cwd),
                env=build_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                build_proc.returncode,
                0,
                f"Falha ao construir wheel:\nSTDOUT:\n{build_proc.stdout}\nSTDERR:\n{build_proc.stderr}",
            )

            wheels = list(dist_dir.glob("epistemic_memory_core-*.whl"))
            self.assertEqual(len(wheels), 1)
            whl_path = wheels[0]
            self.assertIn("0.5.9", whl_path.name)

            # 1) Inspeciona o arquivo .whl (ZIP) confirmando manifesto, configs e todos os capítulos de 00_Manual/*.md.
            with zipfile.ZipFile(whl_path, "r") as zf:
                names = set(zf.namelist())
                self.assertIn("recursos_pacote.py", names)
                self.assertIn("emc_resources/__init__.py", names)
                self.assertIn("emc_resources/config/manual_manifest.json", names)
                self.assertIn("emc_resources/config/execucao.json", names)
                self.assertIn("emc_resources/config/autonomia.json", names)

                bundled_manifest = json.loads(
                    zf.read("emc_resources/config/manual_manifest.json").decode("utf-8")
                )
                self.assertEqual(bundled_manifest, expected_manifest)

                bundled_md = [n for n in names if n.startswith("emc_resources/manual/") and n.endswith(".md")]
                self.assertGreaterEqual(len(bundled_md), 18)
                for chapter_name in expected_manifest:
                    arc_member = f"emc_resources/manual/{chapter_name}"
                    self.assertIn(arc_member, names)

                zf.extractall(wheel_site)

            # Confirma novamente que o build não poluiu 00_Manual/ no repositório original.
            self.assertEqual(list((REPO_ROOT / "00_Manual").glob("*.py")), [])

            # 2) Executa subprocesso fora do clone usando SOMENTE o wheel descompactado (+ dependências stdlib/.venv).
            probe_script = textwrap.dedent(
                """
                import json
                import os
                import sys
                import threading
                import urllib.request
                from pathlib import Path

                repo_root = Path(sys.argv[1]).resolve()
                wheel_site = Path(sys.argv[2]).resolve()
                run_root = Path(sys.argv[3]).resolve()

                # Remove qualquer referência residual ao repositório para provar autonomia total do wheel.
                cleaned_path = []
                for entry in sys.path:
                    if not entry:
                        continue
                    resolved = Path(entry).resolve()
                    if resolved == repo_root or repo_root in resolved.parents:
                        continue
                    cleaned_path.append(entry)
                sys.path[:] = [str(wheel_site)] + [p for p in cleaned_path if Path(p).resolve() != wheel_site]

                # Configura EMC_SYSTEM/EMC_VAULT ANTES de importar nucleo para que
                # REAL_SYSTEM/REAL_VAULT resolvam para o workspace autorizado (necessário
                # para Coordinator que valida root == REAL_SYSTEM/'estado'/'coordenacao').
                auth_root = run_root / "authorized"
                auth_root.mkdir(exist_ok=True)
                core_ws = auth_root / "core_ws"
                os.environ["EMC_SYSTEM"] = str(core_ws / "sistema")
                os.environ["EMC_VAULT"] = str(core_ws / "cofre")
                os.environ["EMC_AUTHORIZED_ROOTS"] = str(auth_root)

                import nucleo
                import execucao
                import ponte_pessoal
                import recursos_pacote
                from apps.agent_memory_sdk.client import EpistemicMemoryClient
                from apps.http_gateway import EpistemicGatewayRuntime, create_gateway_server

                for mod in (nucleo, execucao, ponte_pessoal, recursos_pacote):
                    mod_path = Path(mod.__file__).resolve()
                    assert wheel_site in mod_path.parents, f"Módulo importado fora do wheel: {mod_path}"
                assert wheel_site in Path(EpistemicMemoryClient.__module__.replace('.', '/')).parents or (
                    wheel_site in Path(sys.modules[EpistemicMemoryClient.__module__].__file__).resolve().parents
                )
                assert wheel_site in Path(sys.modules[EpistemicGatewayRuntime.__module__].__file__).resolve().parents

                # Verifica carregamento via importlib.resources sem árvore de repositório.
                assert recursos_pacote._REPO_ROOT is None, f"_REPO_ROOT deveria ser None no wheel: {recursos_pacote._REPO_ROOT}"
                manifest = recursos_pacote.load_manual_manifest()
                assert len(manifest) >= 18
                first_chapter = sorted(manifest)[0]
                raw_md = recursos_pacote.read_manual_bytes(first_chapter)
                assert nucleo.sha(raw_md) == manifest[first_chapter]
                default_exec = recursos_pacote.read_default_config("execucao.json")
                assert isinstance(default_exec, dict) and "retrieval_policy" in default_exec

                for bad_name in ("../execucao.json", "inexistente.md", "sub/capitulo.md"):
                    try:
                        recursos_pacote.read_manual_bytes(bad_name)
                        raise AssertionError(f"Deveria recusar nome inválido: {bad_name}")
                    except nucleo.Invalid:
                        pass

                # Finding #7: diretório não autorizado fora do escopo permanece 100% vazio.
                unauth_ws = run_root / "unauth_empty"
                unauth_ws.mkdir()
                saved_roots = os.environ.pop("EMC_AUTHORIZED_ROOTS", None)
                try:
                    for fn in (
                        lambda: nucleo.Store(unauth_ws / "sistema", unauth_ws / "cofre"),
                    ):
                        try:
                            fn()
                            raise AssertionError("Deveria recusar escopo não autorizado")
                        except nucleo.Invalid:
                            pass
                    assert list(unauth_ws.iterdir()) == [], f"Pasta não autorizada foi tocada: {list(unauth_ws.iterdir())}"
                finally:
                    if saved_roots is not None:
                        os.environ["EMC_AUTHORIZED_ROOTS"] = saved_roots

                # A) Store + Engine diretos (sem bootstrap prévio de manual em disco).
                core_ws = auth_root / "core_ws"
                store = nucleo.Store(core_ws / "sistema", core_ws / "cofre")
                src_created = store.apply(
                    "wheel-core-src-1",
                    "create",
                    title="Fonte Wheel Core",
                    text="Registro criado e lido diretamente via wheel fora do clone.",
                )
                src_read = store.read(src_created["id"])
                assert src_read["payload"]["content"] == "Registro criado e lido diretamente via wheel fora do clone."
                engine = execucao.Engine(store)
                assert len(engine.manual) == len(manifest)
                mcp_manual = ponte_pessoal.ler_manual(first_chapter)
                assert mcp_manual["status"] == "ok" and len(mcp_manual["content"]) > 20, mcp_manual
                mcp_bad = ponte_pessoal.ler_manual("../Comece aqui.md")
                assert mcp_bad["status"] == "denied", mcp_bad

                # B) EpistemicMemoryClient (Agent Memory SDK) fora do clone.
                sdk_ws = auth_root / "sdk_ws"
                client = EpistemicMemoryClient.from_workspace(sdk_ws, enable_embeddings=False)
                sdk_res = client.remember_source(
                    title="Fonte Wheel SDK",
                    content="Memória governada criada pelo SDK instalado via wheel.",
                    operation_key="wheel-sdk-op-1",
                )
                sdk_id = sdk_res.get("record_id") or sdk_res.get("id")
                assert sdk_id, f"Resposta inesperada do SDK: {sdk_res}"
                sdk_note = client.store.read(sdk_id)
                assert sdk_note["payload"]["content"] == "Memória governada criada pelo SDK instalado via wheel."

                # C) HTTP Gateway fora do clone (criação POST + leitura GET real em loopback).
                gw_ws = auth_root / "gw_ws"
                gw_runtime = EpistemicGatewayRuntime.from_workspace(gw_ws, enable_embeddings=False)
                server = create_gateway_server(
                    gw_runtime,
                    host="127.0.0.1",
                    port=0,
                    api_token="wheel-gateway-operator-token",
                )
                port = server.server_address[1]
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    post_body = json.dumps(
                        {
                            "operation_key": "wheel-gw-op-1",
                            "title": "Fonte Wheel Gateway",
                            "content": "Fonte persistida via HTTP Gateway empacotado em wheel.",
                        }
                    ).encode("utf-8")
                    req_post = urllib.request.Request(
                        f"http://127.0.0.1:{port}/api/v1/sources",
                        data=post_body,
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": "Bearer wheel-gateway-operator-token",
                        },
                        method="POST",
                    )
                    with urllib.request.urlopen(req_post, timeout=10) as resp:
                        assert resp.status in (200, 201), resp.status
                        created_payload = json.loads(resp.read().decode("utf-8"))
                    gw_record_id = (created_payload.get("record_id")
                                    or created_payload.get("id")
                                    or (created_payload.get("rev_ref") or {}).get("record_id")
                                    or (created_payload.get("record") or {}).get("id"))
                    assert gw_record_id, f"record_id não encontrado na resposta: {created_payload}"

                    req_get = urllib.request.Request(
                        f"http://127.0.0.1:{port}/api/v1/lineage/{gw_record_id}",
                        headers={"Authorization": f"Bearer {server.ui_token}"},
                        method="GET",
                    )
                    with urllib.request.urlopen(req_get, timeout=10) as resp_get:
                        assert resp_get.status == 200
                        lineage_payload = json.loads(resp_get.read().decode("utf-8"))
                    gw_note = gw_runtime.store.read(gw_record_id)
                    assert gw_note["payload"]["content"] == "Fonte persistida via HTTP Gateway empacotado em wheel."
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

                print(json.dumps({
                    "status": "ok",
                    "manifest_chapters": len(manifest),
                    "core_source_id": src_created["id"],
                    "sdk_source_id": sdk_id,
                    "gateway_source_id": gw_record_id,
                    "lineage_target": lineage_payload.get("record_id", gw_record_id),
                }))
                """
            )

            env = dict(os.environ)
            env["PYTHONPATH"] = str(wheel_site)
            env["CEREBRO_PESSOAL_ACESSO"] = "permitido"
            env.pop("EMC_SYSTEM", None)
            env.pop("EMC_VAULT", None)
            env.pop("EMC_AUTHORIZED_ROOTS", None)

            run_proc = subprocess.run(
                [sys.executable, "-c", probe_script, str(REPO_ROOT), str(wheel_site), str(external_cwd)],
                cwd=str(external_cwd),
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                run_proc.returncode,
                0,
                f"Subprocesso externo do wheel falhou:\nSTDOUT:\n{run_proc.stdout}\nSTDERR:\n{run_proc.stderr}",
            )
            summary = json.loads(run_proc.stdout.strip().splitlines()[-1])
            self.assertEqual(summary["status"], "ok")
            self.assertEqual(summary["manifest_chapters"], len(expected_manifest))

    def test_wheel_build_command_resilient_with_or_without_setuptools_in_base_prefix(self):
        with tempfile.TemporaryDirectory(prefix="emc-wheel-cmd-") as tmp_str:
            tmp_root = Path(tmp_str).resolve()
            dist_dir = tmp_root / "dist"
            src_dir = tmp_root / "src"
            fake_base = tmp_root / "fake_base_prefix"
            for d in (dist_dir, src_dir, fake_base):
                d.mkdir(parents=True, exist_ok=True)

            # 1) setuptools ausente tanto em sys.executable quanto em sys.base_prefix (ex.: runner Python 3.12 PEP 632 limpo):
            # não passa --no-build-isolation nem injeta PYTHONPATH quebrado.
            cmd_clean, env_clean = _prepare_wheel_build_command(
                dist_dir,
                src_dir,
                base_prefix=fake_base,
                environ={"PYTHONPATH": "residual", "PATH": os.environ.get("PATH", "")},
                find_spec_fn=lambda _name: None,
                backend_probe_fn=lambda _exe, _env: False,
            )
            self.assertNotIn("--no-build-isolation", cmd_clean)
            self.assertNotIn("PYTHONPATH", env_clean)

            # 2) setuptools ausente no venv mas presente em sys.base_prefix com backend válido:
            # injeta PYTHONPATH=base_sp e usa --no-build-isolation.
            fake_sp = fake_base / "Lib" / "site-packages"
            (fake_sp / "setuptools").mkdir(parents=True, exist_ok=True)
            cmd_base, env_base = _prepare_wheel_build_command(
                dist_dir,
                src_dir,
                base_prefix=fake_base,
                environ={"PATH": os.environ.get("PATH", "")},
                find_spec_fn=lambda _name: None,
                backend_probe_fn=lambda _exe, env: env.get("PYTHONPATH") == str(fake_sp),
            )
            self.assertIn("--no-build-isolation", cmd_base)
            self.assertEqual(env_base.get("PYTHONPATH"), str(fake_sp))

            # 3) setuptools presente diretamente em sys.executable (ex.: CI após pip install "setuptools>=68"):
            # usa --no-build-isolation sem precisar de PYTHONPATH.
            cmd_venv, env_venv = _prepare_wheel_build_command(
                dist_dir,
                src_dir,
                base_prefix=fake_base,
                environ={"PYTHONPATH": "residual", "PATH": os.environ.get("PATH", "")},
                find_spec_fn=lambda name: object() if name == "setuptools" else None,
                backend_probe_fn=lambda _exe, _env: True,
            )
            self.assertIn("--no-build-isolation", cmd_venv)
            self.assertNotIn("PYTHONPATH", env_venv)

    def test_ponte_pessoal_ler_manual_rejects_symlinks_junctions_and_honors_local_manifest(self):
        src_dir = str(REPO_ROOT / "src")
        if src_dir not in sys.path:
            sys.path.insert(0, src_dir)
        import ponte_pessoal

        chapter = "indice-manual-cerebro.md"
        canonical_bytes = (REPO_ROOT / "00_Manual" / chapter).read_bytes()
        canonical_manifest = json.loads((REPO_ROOT / "config" / "manual_manifest.json").read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory(prefix="emc-manual-redir-") as tmp_str:
            tmp_root = Path(tmp_str).resolve()
            outside_with_chapter = tmp_root / "outside_with_chapter"
            outside_empty = tmp_root / "outside_empty"
            outside_cfg = tmp_root / "outside_cfg"
            for d in (outside_with_chapter, outside_empty, outside_cfg):
                d.mkdir(parents=True, exist_ok=True)
            (outside_with_chapter / chapter).write_bytes(canonical_bytes)
            (outside_cfg / "manual_manifest.json").write_text(
                json.dumps(canonical_manifest), encoding="utf-8"
            )

            orig_sys = ponte_pessoal.REAL_SYSTEM
            orig_vault = ponte_pessoal.REAL_VAULT
            try:
                # Caso 1: Workspace limpo estilo wheel (sem manual_manifest.json nem 00_Manual em disco) -> ok via recursos_pacote.
                ws_clean_sys = tmp_root / "clean_sys"
                ws_clean_vault = tmp_root / "clean_vault"
                ws_clean_sys.mkdir()
                ws_clean_vault.mkdir()
                ponte_pessoal.REAL_SYSTEM = ws_clean_sys
                ponte_pessoal.REAL_VAULT = ws_clean_vault
                ok_res = ponte_pessoal.ler_manual(chapter)
                self.assertEqual(ok_res["status"], "ok", ok_res)

                # Caso 2: Junction / symlink em <vault>/00_Manual apontando para pasta externa (com capítulo válido OU vazia) -> denied!
                for idx, target_dir in enumerate((outside_with_chapter, outside_empty)):
                    v_dir = tmp_root / f"vault_redir_{idx}"
                    v_dir.mkdir()
                    redir_manual = v_dir / "00_Manual"
                    _create_dir_redirection(redir_manual, target_dir)
                    try:
                        ponte_pessoal.REAL_SYSTEM = ws_clean_sys
                        ponte_pessoal.REAL_VAULT = v_dir
                        res = ponte_pessoal.ler_manual(chapter)
                        self.assertEqual(
                            res["status"],
                            "denied",
                            f"Redirecionamento em vault/00_Manual ({target_dir.name}) deveria ser negado: {res}",
                        )
                    finally:
                        _remove_dir_redirection(redir_manual)

                # Caso 3: <vault>/00_Manual ausente, mas <system>/00_Manual redirecionado via junction/symlink -> denied!
                s_dir = tmp_root / "sys_redir_manual"
                s_dir.mkdir()
                redir_sys_manual = s_dir / "00_Manual"
                _create_dir_redirection(redir_sys_manual, outside_with_chapter)
                try:
                    ponte_pessoal.REAL_SYSTEM = s_dir
                    ponte_pessoal.REAL_VAULT = ws_clean_vault
                    res_sys = ponte_pessoal.ler_manual(chapter)
                    self.assertEqual(res_sys["status"], "denied", res_sys)
                finally:
                    _remove_dir_redirection(redir_sys_manual)

                # Caso 4: <system>/config redirecionado via junction/symlink -> denied!
                s_cfg_dir = tmp_root / "sys_redir_cfg"
                s_cfg_dir.mkdir()
                redir_cfg = s_cfg_dir / "config"
                _create_dir_redirection(redir_cfg, outside_cfg)
                try:
                    ponte_pessoal.REAL_SYSTEM = s_cfg_dir
                    ponte_pessoal.REAL_VAULT = ws_clean_vault
                    res_cfg = ponte_pessoal.ler_manual(chapter)
                    self.assertEqual(res_cfg["status"], "denied", res_cfg)
                finally:
                    _remove_dir_redirection(redir_cfg)

                # Caso 5: Symlink de arquivo individual (quando o SO permite criar symlink de arquivo sem privilégio elevado).
                v_file_sym = tmp_root / "vault_file_sym"
                (v_file_sym / "00_Manual").mkdir(parents=True)
                file_link = v_file_sym / "00_Manual" / chapter
                symlink_created = False
                try:
                    os.symlink(outside_with_chapter / chapter, file_link)
                    symlink_created = True
                except OSError:
                    symlink_created = False
                if symlink_created:
                    try:
                        ponte_pessoal.REAL_SYSTEM = ws_clean_sys
                        ponte_pessoal.REAL_VAULT = v_file_sym
                        res_file_sym = ponte_pessoal.ler_manual(chapter)
                        self.assertEqual(res_file_sym["status"], "denied", res_file_sym)
                    finally:
                        file_link.unlink()

                # Caso 6: manual_manifest.json local em REAL_SYSTEM tem precedência sobre recursos_pacote.
                s_local_manifest = tmp_root / "sys_local_manifest"
                s_local_manifest.mkdir()
                reduced_manifest = {k: v for k, v in canonical_manifest.items() if k != chapter}
                (s_local_manifest / "manual_manifest.json").write_text(
                    json.dumps(reduced_manifest), encoding="utf-8"
                )
                ponte_pessoal.REAL_SYSTEM = s_local_manifest
                ponte_pessoal.REAL_VAULT = ws_clean_vault
                res_omitted = ponte_pessoal.ler_manual(chapter)
                self.assertEqual(res_omitted["status"], "denied", res_omitted)

                tampered_manifest = dict(canonical_manifest, **{chapter: "0" * 64})
                (s_local_manifest / "manual_manifest.json").write_text(
                    json.dumps(tampered_manifest), encoding="utf-8"
                )
                res_tampered = ponte_pessoal.ler_manual(chapter)
                self.assertEqual(res_tampered["status"], "invalid", res_tampered)
            finally:
                ponte_pessoal.REAL_SYSTEM = orig_sys
                ponte_pessoal.REAL_VAULT = orig_vault


if __name__ == "__main__":
    unittest.main(verbosity=2)
