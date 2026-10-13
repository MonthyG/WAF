#!/usr/bin/env python3
"""Opt-in Docker integration test; creates/deletes only its own temporary stack."""
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import shutil
import subprocess
import tempfile

source=Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='waf-local-lifecycle-') as directory:
    root=Path(directory)
    for name in ['scripts','slave/src']:
        shutil.copytree(source/name,root/name)
    for name in ['package.json','compose.yaml','slave/package.json','console/package.json']:
        (root/name).parent.mkdir(parents=True,exist_ok=True)
        shutil.copy(source/name,root/name)
    (root/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
    def run(*args):
        subprocess.run(args,cwd=root,check=True)
    run('bash','scripts/local-env.sh')
    before=(root/'.local/dev.env').read_bytes()
    try:
        run('npm','run','local:up')
        run('npm','run','doctor')
        run('npm','run','local:up')
        assert (root/'.local/dev.env').read_bytes()==before, 'Startup rotated secrets'
        # Reproduce the reported password failure: tests must stop before Vitest starts.
        settings=dict(line.split('=',1) for line in before.decode().splitlines() if '=' in line)
        url=urlsplit(settings['DATABASE_URL'])
        wrong=urlunsplit((url.scheme,'waf:intentionally-wrong@'+url.netloc.split('@',1)[1],url.path,url.query,url.fragment))
        envfile=root/'.local/dev.env'
        envfile.write_text(before.decode().replace(settings['DATABASE_URL'],wrong))
        result=subprocess.run(['npm','test'],cwd=root,capture_output=True,text=True)
        envfile.write_bytes(before)
        assert result.returncode != 0 and 'stored database password' in result.stderr
        assert 'vitest run' not in result.stdout, 'Tests started despite failed authentication'
        assert 'intentionally-wrong' not in result.stderr, 'Diagnostic exposed a password'
        print('PASS wrong-password preflight: integration runner never started, password not logged')
        print('PASS isolated lifecycle: fresh startup, authenticated services, migrations, repeat startup; credentials preserved')
    finally:
        # This project was created above only for this test. Never targets the main checkout.
        run('bash','scripts/local.sh','exec','docker','compose','--env-file','.local/dev.env','down','-v')
