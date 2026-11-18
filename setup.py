"""Empacota recursos normativos (00_Manual/*.md e config/*.json) em emc_resources durante build_py."""
from __future__ import annotations

from pathlib import Path
import shutil
from setuptools import setup
from setuptools.command.build_py import build_py as _build_py


class build_py(_build_py):
    def initialize_options(self):
        super().initialize_options()
        self._emc_resource_outputs = []

    def run(self):
        super().run()
        self._emc_resource_outputs = []
        if getattr(self, "editable_mode", False):
            return
        repo_root = Path(__file__).resolve().parent
        pkg_root = Path(self.build_lib) / "emc_resources"
        manual_dst = pkg_root / "manual"
        config_dst = pkg_root / "config"
        manual_dst.mkdir(parents=True, exist_ok=True)
        config_dst.mkdir(parents=True, exist_ok=True)

        for init_path, content in (
            (pkg_root / "__init__.py", '"""Recursos empacotados do Epistemic Memory Core."""\n'),
            (manual_dst / "__init__.py", ""),
            (config_dst / "__init__.py", ""),
        ):
            init_path.write_text(content, encoding="utf-8")
            self._emc_resource_outputs.append(str(init_path))

        manual_src = repo_root / "00_Manual"
        if manual_src.is_dir():
            for md_file in sorted(manual_src.glob("*.md")):
                if md_file.is_file() and not md_file.is_symlink():
                    target = manual_dst / md_file.name
                    shutil.copy2(md_file, target)
                    self._emc_resource_outputs.append(str(target))

        config_src = repo_root / "config"
        if config_src.is_dir():
            for json_file in sorted(config_src.glob("*.json")):
                if json_file.is_file() and not json_file.is_symlink():
                    target = config_dst / json_file.name
                    shutil.copy2(json_file, target)
                    self._emc_resource_outputs.append(str(target))

    def get_outputs(self, include_bytecode=True):
        outputs = list(super().get_outputs(include_bytecode=include_bytecode))
        seen = set(outputs)
        for item in getattr(self, "_emc_resource_outputs", ()):
            if item not in seen:
                outputs.append(item)
                seen.add(item)
        return outputs


setup(cmdclass={"build_py": build_py})
