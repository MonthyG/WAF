#!/usr/bin/env python3
"""Regression checks for checkout replacement, occupied ports and secret preservation."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parent

class LocalSetupTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='waf-setup-')
        self.root = Path(self.temp.name)
        shutil.copytree(SOURCE, self.root / 'scripts')
        self.env = self.root / '.local/dev.env'

    def tearDown(self):
        self.temp.cleanup()

    def run_script(self, name, env=None):
        return subprocess.run(['bash', str(self.root / 'scripts' / name)], env=env,
                              capture_output=True, text=True, check=True)

    def settings(self):
        return dict(line.split('=', 1) for line in self.env.read_text().splitlines() if '=' in line)

    def test_fresh_settings_avoid_occupied_ports_and_remain_stable(self):
        sockets=[]
        try:
            for port in [15432, 18123, 16379, 14222]:
                sock=socket.socket()
                try: sock.bind(('127.0.0.1', port)); sockets.append(sock)
                except OSError: sock.close()  # Already occupied by a real service.
            self.run_script('local-env.sh')
            values=self.settings()
            for name, preferred in [('WAF_POSTGRES_PORT',15432),('WAF_CLICKHOUSE_PORT',18123),('WAF_REDIS_PORT',16379),('WAF_NATS_PORT',14222)]:
                self.assertNotEqual(int(values[name]), preferred)
            self.assertIn(':'+values['WAF_POSTGRES_PORT']+'/', values['DATABASE_URL'])
            self.assertTrue(values['CLICKHOUSE_URL'].endswith(':'+values['WAF_CLICKHOUSE_PORT']))
            self.assertNotEqual(values['COMPOSE_PROJECT_NAME'], 'cloudinside-waf')
            before=self.env.read_bytes()
            self.run_script('local-env.sh')
            self.assertEqual(before, self.env.read_bytes())
            self.assertEqual(self.env.stat().st_mode & 0o777, 0o600)
        finally:
            for sock in sockets: sock.close()

    def test_existing_installation_preserves_credentials_and_project(self):
        self.env.parent.mkdir()
        original='WAF_DB_PASSWORD=keepme\nWAF_MASTER_KEY=keepkey\nDATABASE_URL=postgres://waf:keepme@127.0.0.1:15432/waf\n'
        self.env.write_text(original)
        self.run_script('local-env.sh')
        self.assertTrue(self.env.read_text().startswith(original))
        self.assertEqual(self.settings()['COMPOSE_PROJECT_NAME'], 'cloudinside-waf')
        self.assertEqual(self.settings()['WAF_POSTGRES_PORT'], '15432')

    def test_existing_file_without_trailing_newline(self):
        self.env.parent.mkdir()
        self.env.write_text('WAF_DB_PASSWORD=keepme')
        self.run_script('local-env.sh')
        self.assertEqual(self.settings()['WAF_DB_PASSWORD'], 'keepme')
        self.assertEqual(self.settings()['COMPOSE_PROJECT_NAME'], 'cloudinside-waf')

    def test_explicit_fresh_start_preserves_old_settings(self):
        self.run_script('local-env.sh')
        before=self.env.read_bytes()
        project=self.settings()['COMPOSE_PROJECT_NAME']
        self.run_script('local-fresh.sh')
        backups=list(self.env.parent.glob('settings-backup.*/dev.env'))
        self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].read_bytes(),before)
        self.assertNotEqual(self.settings()['COMPOSE_PROJECT_NAME'],project)

    def test_node_18_fails_before_downloading(self):
        fake=self.root/'fake-bin'
        fake.mkdir()
        node=fake/'node'
        node.write_text('#!/bin/sh\necho 18\n')
        node.chmod(0o755)
        environment=dict(os.environ,PATH=str(fake)+':'+os.environ['PATH'])
        result=subprocess.run(['bash',str(self.root/'scripts/setup.sh')],env=environment,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('requires Node.js 24',result.stderr)
        self.assertFalse((self.root/'.local/toolchains').exists())

if __name__ == '__main__': unittest.main()
