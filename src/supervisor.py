"""Verifica o trabalhador já configurado; nunca altera autorização ou código."""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from nucleo import REAL_SYSTEM, config_file

SYSTEM = REAL_SYSTEM
NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def workers(root=None):
    target_root = Path(SYSTEM if root is None else root).resolve()
    if os.name != 'nt':
        target_script = str((target_root / 'src' / 'autonomia.py').resolve())
        result = subprocess.run(
            ['ps', '-eo', 'pid=,args='],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            raise RuntimeError('inventário de processos indisponível')
        pids = []
        exact_pat = re.compile(re.escape(target_script) + r'["\'\s]+serve(?:\s|$)')
        root_pat = re.compile(re.escape(str(target_root)) + r'.*autonomia\.py["\'\s]+serve(?:\s|$)')
        for line in result.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                pid = int(parts[0])
                if pid != os.getpid() and (exact_pat.search(parts[1]) or root_pat.search(parts[1])):
                    pids.append(pid)
        return pids

    shell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
    script = r'''$ErrorActionPreference='Stop'
$escaped = [regex]::Escape($env:EMC_SUPERVISOR_ROOT)
$items = @(Get-CimInstance Win32_Process | Where-Object {
  $_.Name -match '^python(?:w|3(?:\.\d+)?)?\.exe$' -and $_.CommandLine -match "(?i)$escaped.*autonomia\.py[`"'\s]+serve(?:\s|$)"
})
@($items | ForEach-Object { [int]$_.ProcessId }) | ConvertTo-Json -Compress'''
    env = {k: v for k, v in os.environ.items() if k.upper() != 'PSMODULEPATH'}
    env['EMC_SUPERVISOR_ROOT'] = str(target_root)
    result = subprocess.run([str(shell),'-NoProfile','-NonInteractive','-Command',script],
        env=env,capture_output=True,text=True,timeout=20,creationflags=NO_WINDOW)
    if result.returncode:
        raise RuntimeError('inventário de processos indisponível')
    text = result.stdout.strip()
    if not text:
        return []
    found = json.loads(text)
    return found if isinstance(found,list) else [found]


def start(root):
    stamp = time.strftime('%Y%m%d-%H%M%S') + '-' + str(os.getpid())
    state = root / 'estado'
    state.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONPATH=str(root / 'src'))
    with (state / ('supervisor-worker-' + stamp + '.stdout.log')).open('ab') as out, \
         (state / ('supervisor-worker-' + stamp + '.stderr.log')).open('ab') as err:
        subprocess.Popen([sys.executable,
                          str(root / 'src' / 'autonomia.py'),'serve'],cwd=root,env=env,
                         stdin=subprocess.DEVNULL,stdout=out,stderr=err,creationflags=NO_WINDOW)


def check(root,find=workers,launch=start):
    root=Path(root)
    if (root/'estado'/'implantacao.lock').exists():return 'maintenance'
    cfg_path = config_file(root, 'autonomia.json')
    config=json.loads(cfg_path.read_text(encoding='utf-8-sig'))
    if config.get('enabled') is not True or config.get('content_access')!='permitido':return 'disabled'
    if find():return 'running'
    # Revalidar após a consulta de processos; o trabalhador também usa trava exclusiva.
    if (root/'estado'/'implantacao.lock').exists():return 'maintenance'
    updated=json.loads(cfg_path.read_text(encoding='utf-8-sig'))
    if updated.get('enabled') is not True or updated.get('content_access')!='permitido':return 'disabled'
    launch(root)
    return 'start_requested'


if __name__=='__main__':
    check(SYSTEM)
