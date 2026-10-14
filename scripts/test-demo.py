#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parent.parent

class DemoTest(unittest.TestCase):
    def test_busy_default_ports_and_real_blocking(self):
        held=[]
        try:
            for port in (8080,9090,9080):
                sock=socket.socket()
                try: sock.bind(('127.0.0.1',port)); sock.listen(); held.append(sock)
                except OSError: sock.close()
            with tempfile.TemporaryFile(mode='w+') as log:
                process=subprocess.Popen(['bash','scripts/dev.sh'],cwd=ROOT,env={**os.environ,'WAF_DEMO_MODE':'block'},stdout=log,stderr=subprocess.STDOUT)
                try:
                    until=time.monotonic()+15
                    while time.monotonic()<until:
                        log.seek(0); output=log.read()
                        match=re.search(r'Demo ready: http://(127\.0\.0\.1:\d+)',output)
                        if match: break
                        if process.poll() is not None: self.fail(output)
                        time.sleep(.1)
                    else: self.fail('Demo did not become ready: '+output)
                    self.assertNotEqual(match[1],'127.0.0.1:8080')
                    def request(path):
                        req=urllib.request.Request('http://'+match[1]+path,headers={'Host':'shop.localhost'})
                        try:
                            with urllib.request.urlopen(req,timeout=5) as res: return res.status
                        except urllib.error.HTTPError as res: return res.code
                    self.assertEqual(request('/'),200)
                    self.assertEqual(request('/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'),403)
                finally:
                    process.send_signal(signal.SIGTERM)
                    process.wait(timeout=5)
                with socket.socket() as probe:
                    self.assertNotEqual(probe.connect_ex(tuple([match[1].split(':')[0],int(match[1].split(':')[1])])),0)
                for sock in held: self.assertGreaterEqual(sock.fileno(),0)
        finally:
            for sock in held: sock.close()

    def test_explicit_busy_port_fails_without_polling(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); sock.listen()
            result=subprocess.run(['bash','scripts/dev.sh'],cwd=ROOT,env={**os.environ,'WAF_DEMO_PORT':str(sock.getsockname()[1])},capture_output=True,text=True,timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('is unavailable',result.stderr)
            self.assertNotIn('Failed to connect',result.stderr)

    def test_child_exit_stops_launcher(self):
        with tempfile.TemporaryDirectory(prefix='waf-demo-test-') as directory:
            root=Path(directory)
            (root/'scripts').mkdir()
            for script in ('env.sh','dev.sh','demo-config.py'): shutil.copy(ROOT/'scripts'/script,root/'scripts'/script)
            (root/'waf-node/bin').mkdir(parents=True)
            (root/'waf-node/configs').mkdir()
            shutil.copy(ROOT/'waf-node/configs/local.json',root/'waf-node/configs/local.json')
            (root/'waf-node/bin/waf-origin').symlink_to(ROOT/'waf-node/bin/waf-origin')
            proxy=root/'waf-node/bin/waf-proxy'
            proxy.write_text('#!/bin/sh\ncase "$*" in *-check*) exit 0;; esac\nexit 7\n'); proxy.chmod(0o755)
            result=subprocess.run(['bash','scripts/dev.sh'],cwd=root,capture_output=True,text=True,timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('child process exited',result.stderr)
            self.assertNotIn('Failed to connect',result.stderr)

if __name__=='__main__': unittest.main()
