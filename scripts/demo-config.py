#!/usr/bin/env python3
"""Create a private local-demo config without changing the user's source config."""
import json
import os
from pathlib import Path
import socket
import sys

config = json.loads(Path(sys.argv[1]).read_text())
reserved = []
def address(name, preferred):
    explicit = os.environ.get(name)
    try:
        port = int(explicit) if explicit else preferred
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError:
        raise SystemExit(f'{name} must be a port between 1 and 65535')
    sock = socket.socket()
    try:
        sock.bind(('127.0.0.1', port))
    except OSError:
        if explicit:
            sock.close()
            raise SystemExit(f'{name}={port} is unavailable. Choose another port; the existing service was not stopped.')
        sock.bind(('127.0.0.1', 0))
    reserved.append(sock)
    return '127.0.0.1:' + str(sock.getsockname()[1])

config['listen'] = address('WAF_DEMO_PORT', 8080)
config['management_listen'] = address('WAF_DEMO_MANAGEMENT_PORT', 9090)
origin = address('WAF_DEMO_ORIGIN_PORT', 9080)
# make dev always uses its own test origin, not a customer application.
config.pop('origins', None)
config['origin'] = 'http://' + origin
if os.environ.get('WAF_DEMO_MODE'):
    config['mode'] = os.environ['WAF_DEMO_MODE']
if config.get('mode') not in ('off', 'detect', 'block'):
    raise SystemExit('WAF_DEMO_MODE must be off, detect, or block')
hostname = config.get('hostname', '')
if not hostname or any(c.isspace() for c in hostname):
    raise SystemExit('Demo hostname must be nonempty and contain no whitespace')
Path(sys.argv[2]).write_text(json.dumps(config))
for value in [config['listen'], config['management_listen'], origin, hostname, config['mode']]:
    print(value)
for sock in reserved:
    sock.close()
