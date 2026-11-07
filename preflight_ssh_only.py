#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline dependency check for the SSH-only entry.

This process does not contact a router, open a device session, or
download or install packages. Import failure is a hard stop.
A successful import on one operating system says nothing about another.
"""

import importlib.util
import os
import platform
import ssl
import sys


ROOT = os.path.dirname(os.path.abspath(__file__))
REQUIRED = ('requests', 'urllib3', 'ssh2')


def collect_facts():
    specs = {}
    for name in REQUIRED:
        try:
            specs[name] = importlib.util.find_spec(name) is not None
        except ValueError:
            specs[name] = False
    stdlib_telnet = False
    try:
        spec = importlib.util.find_spec('telnetlib')
        origin = getattr(spec, 'origin', '') or ''
        stdlib_telnet = bool(spec) and 'xmir_base' not in origin.replace('\\', '/')
    except Exception:
        stdlib_telnet = False
    vendor = os.path.isfile(os.path.join(ROOT, 'xmir_base', 'telnetlib', 'telnetlib.py'))
    return {
        'version': tuple(sys.version_info[:3]),
        'implementation': platform.python_implementation(),
        'system': platform.system(),
        'machine': platform.machine(),
        'openssl': ssl.OPENSSL_VERSION,
        'specs': specs,
        'stdlib_telnetlib': stdlib_telnet,
        'telnetlib_vendor': vendor,
    }


def _needs_wheel_warning(facts):
    version = facts['version']
    system = facts['system']
    machine = facts['machine']
    intel_mac = system == 'Darwin' and machine in ('x86_64', 'i386')
    return version >= (3, 15) or intel_mac


def evaluate(facts):
    blockers = []
    notes = []
    version = facts['version']
    if version < (3, 8, 0):
        blockers.append('Python 3.8 or newer is required.')
    if facts.get('implementation') not in (None, '', 'CPython'):
        notes.append('The pinned ssh2-python wheels are built for CPython.')
    if _needs_wheel_warning(facts):
        notes.append(
            'ssh2-python==1.2.0.post1 publishes no cp315 wheel and no macOS x86_64 wheel. '
            'Its macOS wheels are arm64 only, for CPython 3.11 and 3.12. '
            'The sdist vendors libssh2 1.11.1 and builds that copy with cmake. '
            'The python.org 3.15 framework has no OpenSSL headers, so install_ssh_only_venv.sh builds '
            'OpenSSL 3.5.9 from the upstream tarball inside the tool directory and does not use the framework libraries. '
            'A Linux build of that prefix linked libssh2. That is not a macOS result.'
        )
    specs = facts.get('specs') or {}
    missing = [name for name in REQUIRED if not specs.get(name)]
    if missing:
        blockers.append(
            'Missing importable packages: ' + ', '.join(missing) + '. '
            'Install from requirements-ssh-only.txt yourself. This preflight does not install them.'
        )
    if version >= (3, 13, 0) and not facts.get('stdlib_telnetlib') and not facts.get('telnetlib_vendor'):
        blockers.append('Python 3.13+ needs the vendored xmir_base/telnetlib package, and it is missing.')
    return blockers, notes


def main():
    facts = collect_facts()
    blockers, notes = evaluate(facts)
    print(f"python={facts['version']} impl={facts['implementation']} system={facts['system']} machine={facts['machine']}")
    print(f"ssl={facts['openssl']}")
    for note in notes:
        print(f'NOTE: {note}')
    if blockers:
        for item in blockers:
            print(f'BLOCKER: {item}')
        return 1
    print('Preflight imports succeeded. This does not prove the router sequence.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
