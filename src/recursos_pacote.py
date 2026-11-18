"""Acesso unificado aos capítulos normativos (00_Manual) e configurações padrão na árvore local ou wheel."""
from __future__ import annotations

import copy
import importlib.resources
import json
import os
import uuid
from pathlib import Path

from nucleo import Conflict, Invalid, sha

_SRC_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SRC_DIR.parent if _SRC_DIR.name == "src" else None


def _validate_resource_name(name: str, suffix: str | None = None) -> str:
    if (
        not isinstance(name, str)
        or not name
        or "\x00" in name
        or "/" in name
        or "\\" in name
        or name in (".", "..")
        or any(0xD800 <= ord(ch) <= 0xDFFF for ch in name)
        or Path(name).name != name
    ):
        raise Invalid("nome de recurso inválido ou fora do escopo")
    if suffix is not None and not name.endswith(suffix):
        raise Invalid("extensão de recurso inválida")
    return name


def _atomic_write_bytes(dest: Path, data: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f"{dest.name}.tmp-{uuid.uuid4().hex}")
    try:
        with tmp.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, dest)
    except BaseException:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        raise


def load_manual_manifest() -> dict[str, str]:
    """Carrega manual_manifest.json da árvore do repositório ou do pacote emc_resources."""
    raw_text: str | None = None
    if _REPO_ROOT is not None:
        cfg_dir = _REPO_ROOT / "config"
        if cfg_dir.is_symlink():
            raise Invalid("diretório de configuração redirecionado")
        candidate = cfg_dir / "manual_manifest.json"
        if candidate.is_symlink():
            raise Invalid("manifesto do manual redirecionado")
        if candidate.is_file():
            if candidate.resolve().parent != cfg_dir.resolve():
                raise Invalid("manifesto do manual fora do escopo")
            raw_text = candidate.read_text(encoding="utf-8")

    if raw_text is None:
        try:
            res = importlib.resources.files("emc_resources").joinpath("config", "manual_manifest.json")
            raw_text = res.read_text(encoding="utf-8")
        except (FileNotFoundError, ModuleNotFoundError, TypeError, OSError) as error:
            raise Invalid("manifesto do manual indisponível no pacote instalado") from error

    try:
        parsed = json.loads(raw_text)
    except ValueError as error:
        raise Invalid("manifesto do manual contém JSON inválido") from error

    if not isinstance(parsed, dict) or not parsed:
        raise Invalid("manifesto do manual inválido")

    manifest: dict[str, str] = {}
    for key, digest in parsed.items():
        _validate_resource_name(key, ".md")
        if not isinstance(digest, str) or len(digest) != 64:
            raise Invalid("hash inválido no manifesto do manual")
        manifest[key] = digest
    return manifest


def read_manual_bytes(name: str) -> bytes:
    """Lê os bytes exatos de 00_Manual/<name> (repositório ou wheel) e valida o SHA-256 canônico."""
    _validate_resource_name(name, ".md")
    manifest = load_manual_manifest()
    expected_digest = manifest.get(name)
    if expected_digest is None:
        raise Invalid("capítulo do manual desconhecido")

    raw: bytes | None = None
    if _REPO_ROOT is not None:
        manual_dir = _REPO_ROOT / "00_Manual"
        if manual_dir.is_symlink():
            raise Invalid("manual fora do escopo")
        candidate = manual_dir / name
        if candidate.is_symlink():
            raise Invalid("manual fora do escopo")
        if candidate.is_file():
            if candidate.resolve().parent != manual_dir.resolve():
                raise Invalid("manual fora do escopo")
            raw = candidate.read_bytes()

    if raw is None:
        try:
            res = importlib.resources.files("emc_resources").joinpath("manual", name)
            raw = res.read_bytes()
        except (FileNotFoundError, ModuleNotFoundError, TypeError, OSError) as error:
            raise Invalid("capítulo do manual indisponível no pacote instalado") from error

    if sha(raw) != expected_digest:
        raise Conflict("manual divergente do manifesto")
    return raw


def read_default_config(name: str) -> dict:
    """Carrega config/<name> JSON da árvore local ou de emc_resources/config/."""
    _validate_resource_name(name, ".json")
    raw_text: str | None = None
    if _REPO_ROOT is not None:
        cfg_dir = _REPO_ROOT / "config"
        if cfg_dir.is_symlink():
            raise Invalid("configuração redirecionada")
        candidate = cfg_dir / name
        if candidate.is_symlink():
            raise Invalid("configuração redirecionada")
        if candidate.is_file():
            if candidate.resolve().parent != cfg_dir.resolve():
                raise Invalid("configuração fora do escopo")
            raw_text = candidate.read_text(encoding="utf-8")

    if raw_text is None:
        try:
            res = importlib.resources.files("emc_resources").joinpath("config", name)
            raw_text = res.read_text(encoding="utf-8")
        except (FileNotFoundError, ModuleNotFoundError, TypeError, OSError) as error:
            raise Invalid("configuração padrão indisponível") from error

    try:
        parsed = json.loads(raw_text)
    except ValueError as error:
        raise Invalid("configuração padrão contém JSON inválido") from error

    if not isinstance(parsed, dict):
        raise Invalid("configuração padrão deve ser objeto JSON")
    return copy.deepcopy(parsed)


def bootstrap_manual_tree(system_root: Path, vault_root: Path) -> dict[str, str]:
    """Materializa manual_manifest.json e capítulos 00_Manual/*.md ausentes no workspace."""
    sys_dir = Path(system_root)
    vlt_dir = Path(vault_root)
    if sys_dir.is_symlink() or vlt_dir.is_symlink():
        raise Invalid("raiz de destino redirecionada")

    manifest = load_manual_manifest()
    sys_resolved = sys_dir.resolve()
    vlt_resolved = vlt_dir.resolve()
    manual_dir = vlt_resolved / "00_Manual"
    if manual_dir.is_symlink():
        raise Invalid("manual fora do escopo")

    missing_chapters: dict[str, bytes] = {}
    for name in manifest:
        dest = manual_dir / name
        if dest.is_symlink():
            raise Invalid("manual fora do escopo")
        if not dest.exists():
            missing_chapters[name] = read_manual_bytes(name)

    manifest_dest = sys_resolved / "manual_manifest.json"
    if manifest_dest.is_symlink():
        raise Invalid("manifesto do manual redirecionado")

    sys_resolved.mkdir(parents=True, exist_ok=True)
    manual_dir.mkdir(parents=True, exist_ok=True)
    if manual_dir.resolve().parent != vlt_resolved:
        raise Invalid("manual fora do escopo")

    if not manifest_dest.exists():
        serialized = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        _atomic_write_bytes(manifest_dest, serialized)

    for name, raw in missing_chapters.items():
        dest = manual_dir / name
        if dest.is_symlink() or dest.resolve().parent != manual_dir.resolve():
            raise Invalid("manual fora do escopo")
        if not dest.exists():
            _atomic_write_bytes(dest, raw)

    return dict(manifest)
