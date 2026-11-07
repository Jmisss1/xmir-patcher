#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ast
import io
import os
import socket
import ssl
import subprocess
import sys
import threading
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _mod(name):
    if name in sys.modules and hasattr(sys.modules[name], '__file__'):
        return sys.modules[name]
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        sys.modules[name] = module
    return module


def _install_import_stubs():
    ssh2 = _mod('ssh2')
    ssh2.session = _mod('ssh2.session')
    ssh2.error_codes = _mod('ssh2.error_codes')
    ssh2.error_codes.LIBSSH2_ERROR_EAGAIN = -37
    ssh2.utils = _mod('ssh2.utils')
    ssh2.utils.wait_socket = lambda *args, **kwargs: None
    ssh2.exceptions = _mod('ssh2.exceptions')
    ssh2.exceptions.Timeout = type('Timeout', (Exception,), {})
    ssh2.exceptions.SocketRecvError = type('SocketRecvError', (Exception,), {})
    requests = _mod('requests')
    exceptions = _mod('requests.exceptions')
    for name in ('ConnectionError', 'ConnectTimeout', 'HTTPError', 'Timeout', 'RequestException', 'ReadTimeout'):
        setattr(exceptions, name, type(name, (Exception,), {}))
    requests.exceptions = exceptions


_install_import_stubs()

import connect7  # noqa: E402
import gateway  # noqa: E402
import preflight_ssh_only  # noqa: E402
import ssh_only  # noqa: E402
import ssh_only_build  # noqa: E402


PASSWORD = 'TestOnly99'


class Sock:
    def getsockname(self):
        return ('192.168.31.10', 50000)


class Raw:
    def __init__(self):
        self._connection = types.SimpleNamespace(sock = Sock())


class FakeResp:
    def __init__(self, chunks = None):
        self.raw = Raw()
        self._chunks = chunks if chunks is not None else [b'\x89PNG' + b'x']

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size = 8192):
        for chunk in self._chunks:
            yield chunk

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeGw:
    def __init__(self, ping = True):
        self.ip_addr = '192.168.31.1'
        self.ssh_only = False
        self.keep_secrets_local = False
        self._secret_root = None
        self._secret_web = None
        self._ping = ping
        self.calls = []
        self._diag_fail_on = None
        self._diag_count = 0

    def api_request(self, path, params = None, **kwargs):
        self.calls.append(('api', path))
        if path == 'API/xqsystem/upload_log' and self._diag_fail_on == 'timeout':
            raise connect7.requests.exceptions.ReadTimeout('timed out')
        if path == 'API/xqsystem/get_icon' and params is None:
            return FakeResp()
        if path == 'API/xqsystem/get_icon':
            return FakeResp(chunks = [b'ok'])
        if path == 'API/xqsystem/upload_log':
            return '{"code":1512}'
        if path == 'API/xqnetwork/diag_get_paras':
            return {'code': 0, 'iperf_test_thr': '800008'}
        raise AssertionError(path)

    def set_diag_iperf_test_thr(self, value, timeout = None):
        self._diag_count += 1
        if self._diag_fail_on == self._diag_count:
            raise RuntimeError('diag failed')
        self.calls.append(('diag', str(value)))
        return True

    def get_diag_iperf_test_thr(self, timeout = None):
        self.calls.append(('get_diag',))
        return '800008'

    def ping(self, verbose = 0, contimeout = None):
        self.calls.append(('ping', contimeout))
        return self._ping

    def run_cmd(self, command, **kwargs):
        self.calls.append(('run', command))
        return ''

    def post_connect(self, *args, **kwargs):
        self.calls.append(('post_connect',))
        raise AssertionError('post_connect')


class SequenceTests(unittest.TestCase):
    def _installer(self, allowed_peer = None, srv_timeout = 3, api = 'API/xqsystem/get_icon'):
        self.seen = {
            'peer': allowed_peer,
            'timeout': srv_timeout,
            'body': connect7.payload_body,
        }

    def test_import_does_not_autorun(self):
        self.assertFalse(connect7.autorun_invoked)
        self.assertFalse(connect7.should_autorun('connect7', {}))
        self.assertTrue(connect7.should_autorun('__main__', {}))
        self.assertTrue(connect7.should_autorun('connect7', {'inited_gw': object()}))

    def test_success_allowlist(self):
        gw = FakeGw(ping = True)
        gate = ssh_only.execute(gw, PASSWORD, installer = self._installer)
        kinds = [item[0] for item in gw.calls]
        self.assertNotIn('post_connect', kinds)
        self.assertEqual(self.seen['peer'], '192.168.31.1')
        self.assertEqual(self.seen['timeout'], 3)
        body = self.seen['body']
        for banned in ('telnet', 'bdata', 'uart_en', 'bootmenu', 'dropbearmulti', 'reboot', 'firewall'):
            self.assertNotIn(banned, body.lower())
        self.assertIn('nvram set ssh_en=1 ; nvram set boot_wait=on ; nvram set bootdelay=3 ; nvram commit', body)
        self.assertIn('rm -f /tmp/psw.txt', body)
        self.assertIn(PASSWORD, body)
        self.assertNotIn("echo -e 'root\\nroot'", body)
        self.assertEqual(gate.run_cmds, [ssh_only.CLEANUP])
        self.assertEqual([item for item in gw.calls if item[0] == 'run'], [('run', ssh_only.CLEANUP)])
        self.assertIsNone(gw._secret_root)
        self.assertNotIn(PASSWORD, connect7.payload_body)

    def test_ssh_failure_stops_without_fallback(self):
        gw = FakeGw(ping = False)
        with self.assertRaises(connect7.ExploitNotWorked):
            ssh_only.execute(gw, PASSWORD, installer = self._installer)
        self.assertNotIn(('run', ssh_only.CLEANUP), gw.calls)
        self.assertFalse(any(item[0] == 'post_connect' for item in gw.calls))
        self.assertEqual([item[1] for item in gw.calls if item[0] == 'diag'], ['990000', '990001', '990002'])

    def test_timeout_stops_immediately(self):
        gw = FakeGw(ping = True)
        gw._diag_fail_on = 'timeout'
        with self.assertRaises(connect7.requests.exceptions.ReadTimeout):
            ssh_only.execute(gw, PASSWORD, installer = self._installer)
        self.assertEqual([item[1] for item in gw.calls if item[0] == 'diag'], ['990000'])
        self.assertFalse(any(item[0] in ('ping', 'run', 'post_connect') for item in gw.calls))

    def test_diag_error_does_not_send_later_commands(self):
        gw = FakeGw(ping = True)
        gw._diag_fail_on = 2
        with self.assertRaises(RuntimeError):
            ssh_only.execute(gw, PASSWORD, installer = self._installer)
        self.assertEqual([item[1] for item in gw.calls if item[0] == 'diag'], ['990000'])
        self.assertFalse(any(item[0] in ('ping', 'run', 'post_connect') for item in gw.calls))

    def test_prohibited_commands_never_reach_transport(self):
        gw = FakeGw(ping = True)
        gate = ssh_only.install_gate(gw, ssh_only.MutationGate())
        prohibited = [
            'reboot',
            'nvram set uart_en=1; nvram set boot_wait=on; nvram commit',
            'bdata set telnet_en=1 ; bdata commit',
            '/etc/init.d/telnet restart',
            'mtd write firmware.bin firmware',
            ssh_only.CLEANUP,
        ]
        for command in prohibited:
            with self.assertRaises(ssh_only.MutationRejected):
                gw.run_cmd(command)
        self.assertFalse(any(item[0] == 'run' for item in gw.calls))
        gate.cleanup_open = True
        gw.run_cmd(ssh_only.CLEANUP)
        self.assertEqual([item for item in gw.calls if item[0] == 'run'], [('run', ssh_only.CLEANUP)])
        with self.assertRaises(ssh_only.MutationRejected):
            gw.run_cmd('reboot')
        with self.assertRaises(ssh_only.MutationRejected):
            gw.run_cmd(ssh_only.CLEANUP)
        self.assertEqual([item for item in gw.calls if item[0] == 'run'], [('run', ssh_only.CLEANUP)])
        with self.assertRaises(ssh_only.MutationRejected):
            gw.set_diag_iperf_test_thr('25')
        with self.assertRaises(ssh_only.MutationRejected):
            gw.api_request('API/xqsystem/reboot', {'client': 'web'})
        self.assertNotIn(('diag', '25'), gw.calls)

    def test_restricted_run_exploit_rejects_telnet_remap(self):
        gw = FakeGw()
        gw.ssh_only = True
        ssh_only.install_gate(gw, ssh_only.MutationGate())
        connect7.gw = gw
        connect7.payload_func_list = ['test', 'unlock_ssh', 'run_ssh']
        with self.assertRaises(connect7.ExploitError):
            connect7.run_exploit('bdata set telnet_en=1 ; bdata commit')
        self.assertEqual(gw.calls, [])


class GatewayGuardTests(unittest.TestCase):
    def _fake_type(self, opened):
        origin = gateway.Gateway

        class Fake(origin):
            def __init__(self, timeout = 4, verbose = 2, detect_device = True, detect_ssh = True, load_cfg = True):
                self._cfg = {}
                self.device_name = 'RD23'
                self.rom_version = '1.0.97'
                self.rom_channel = 'release'
                self.mac_address = 'aa'
                self.device_info = {'countrycode': 'CN'}
                self.status = 1
                self.opened = opened
                self.events = []

            def load_memcfg(self):
                return self._cfg

            def get_memcfg_param(self, key, defvalue = None):
                return self._cfg.get(key, defvalue)

            def set_memcfg_param(self, key, value):
                self._cfg[key] = value
                self.events.append(('mem', key))

            def tcp_port_open(self, port, contimeout = 2):
                self.events.append(('tcp', port))
                return self.opened.get(port, False)

            def web_login(self, timeout = 4):
                self.events.append('web_login')

            def run_cmd(self, *args, **kwargs):
                self.events.append(('run', args))
                raise AssertionError('run_cmd')

            def detect_ssh(self, *args, **kwargs):
                self.events.append('detect_ssh')
                raise AssertionError('detect_ssh')

            def get_telnet(self, *args, **kwargs):
                self.events.append('telnet')
                raise AssertionError('get_telnet')

            def install_dropbearmulti(self, *args, **kwargs):
                self.events.append('dropbearmulti')
                raise AssertionError('dropbearmulti')

        return Fake

    def test_existing_telnet_makes_no_writes(self):
        Fake = self._fake_type({22: False, 23: True})
        with patch.object(gateway, 'Gateway', Fake):
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    gateway.create_gateway(ssh_only = True, try_telnet = True)
        self.assertEqual(caught.exception.code, 3)

    def test_existing_ssh_makes_no_writes(self):
        Fake = self._fake_type({22: True, 23: True})
        with patch.object(gateway, 'Gateway', Fake):
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    gateway.create_gateway(ssh_only = True, try_telnet = True)
        self.assertEqual(caught.exception.code, 2)

    def test_closed_ports_reach_login_without_service_writes(self):
        Fake = self._fake_type({22: False, 23: False})
        with patch.object(gateway, 'Gateway', Fake):
            with redirect_stdout(io.StringIO()):
                gw = gateway.create_gateway(ssh_only = True, try_telnet = True)
        self.assertEqual(gw.events, [('mem', 'ssh_port'), ('tcp', 22), ('tcp', 23), 'web_login'])
        self.assertEqual(set(gw._cfg), {'ssh_port'})
        self.assertTrue(gw.ssh_only)
        self.assertTrue(gw.keep_secrets_local)

    def test_caller_supplied_password_is_refused_and_not_logged(self):
        Fake = self._fake_type({22: False, 23: False})
        secret = 'CallerSecret99'
        buf = io.StringIO()
        with patch.object(gateway, 'Gateway', Fake):
            with redirect_stdout(buf):
                with self.assertRaises(SystemExit) as caught:
                    gateway.create_gateway(ssh_only = True, web_login = secret)
        self.assertEqual(caught.exception.code, 2)
        self.assertNotIn(secret, buf.getvalue())

    def test_local_secret_is_not_written_to_shared_memory(self):
        gw = gateway.Gateway.__new__(gateway.Gateway)
        gw.keep_secrets_local = True
        gw._secret_web = PASSWORD
        gw.nonce_key = 'nonce'
        gw.mac_address = 'aa:bb'
        gw.encryptmode = 0
        gw.web_scheme = 'http'
        gw.stok = None
        gw.mem_writes = []

        def reject_mem(key, value):
            gw.mem_writes.append((key, value))
            raise AssertionError('shared memory write')

        gw.set_memcfg_param = reject_mem
        gw.api_request = lambda path, data = None, **kwargs: '{"code":0,"token":"abc"}'
        stok = gw.web_login()
        self.assertEqual(stok, 'abc')
        self.assertEqual(gw.mem_writes, [])
        self.assertEqual(gw._secret_web, PASSWORD)
        gw._secret_root = PASSWORD
        self.assertEqual(gw.passw, PASSWORD)

    def test_failed_local_login_clears_secret_without_shared_memory(self):
        gw = gateway.Gateway.__new__(gateway.Gateway)
        gw.keep_secrets_local = True
        gw._secret_web = PASSWORD
        gw.nonce_key = 'nonce'
        gw.mac_address = 'aa:bb'
        gw.encryptmode = 0
        gw.web_scheme = 'http'
        gw.stok = None
        gw.set_memcfg_param = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('shared memory write'))
        gw.api_request = lambda path, data = None, **kwargs: 'not-json'
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                gw.web_login()
        self.assertIsNone(gw._secret_web)


class PromptTests(unittest.TestCase):
    def test_argv_is_rejected(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit) as caught:
                ssh_only.main(['ssh_only.py', PASSWORD])
        self.assertEqual(caught.exception.code, 2)
        self.assertNotIn(PASSWORD, buf.getvalue())

    def test_prompt_requires_match_and_charset(self):
        answers = iter([PASSWORD, PASSWORD])
        self.assertEqual(ssh_only.prompt_new_root_password(lambda prompt: next(answers)), PASSWORD)
        bad = iter(['short', 'short'])
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                ssh_only.prompt_new_root_password(lambda prompt: next(bad))
        mismatch = iter([PASSWORD, PASSWORD + 'x'])
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                ssh_only.prompt_new_root_password(lambda prompt: next(mismatch))


class ListenerTests(unittest.TestCase):
    def _client(self, port, path):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(('127.0.0.1', port), timeout = 2) as raw:
            with ctx.wrap_socket(raw, server_hostname = 'miwifi.com') as ssock:
                ssock.sendall(f'GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'.encode())
                data = b''
                while True:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        return data

    def test_source_filter_and_close(self):
        connect7.srv_port = 18766
        ret = [None]
        connect7.srvInitEvent.clear()
        thread = threading.Thread(
            target = connect7.wait_req_and_send_resp,
            args = ('/payload.sh', b'PAYLOAD', '127.0.0.1', ret, 3, '192.0.2.9'),
        )
        thread.start()
        self.assertTrue(connect7.srvInitEvent.wait(5))
        data = self._client(connect7.srv_port, '/payload.sh')
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertIn(b'403', data)
        self.assertNotIn(b'PAYLOAD', data)
        self.assertEqual(ret[0], -20)
        with self.assertRaises(OSError):
            socket.create_connection(('127.0.0.1', connect7.srv_port), timeout = 1).close()

    def test_allowed_source_receives_one_response(self):
        connect7.srv_port = 18767
        ret = [None]
        connect7.srvInitEvent.clear()
        thread = threading.Thread(
            target = connect7.wait_req_and_send_resp,
            args = ('/payload.sh', b'PAYLOAD', '127.0.0.1', ret, 3, '127.0.0.1'),
        )
        thread.start()
        self.assertTrue(connect7.srvInitEvent.wait(5))
        data = self._client(connect7.srv_port, '/payload.sh')
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertIn(b'200', data)
        self.assertIn(b'PAYLOAD', data)
        self.assertEqual(ret[0], 1)

    def test_listener_times_out_quickly(self):
        connect7.srv_port = 18768
        ret = [None]
        connect7.srvInitEvent.clear()
        started = threading.Event()
        def run():
            started.set()
            connect7.wait_req_and_send_resp('/payload.sh', b'PAYLOAD', '127.0.0.1', ret, 1, '127.0.0.1')
        thread = threading.Thread(target = run)
        begin = __import__('time').monotonic()
        thread.start()
        self.assertTrue(connect7.srvInitEvent.wait(5))
        thread.join(5)
        elapsed = __import__('time').monotonic() - begin
        self.assertFalse(thread.is_alive())
        self.assertEqual(ret[0], -1)
        self.assertLess(elapsed, 4)


class PreflightTests(unittest.TestCase):
    def test_source_has_no_network_or_install(self):
        path = os.path.join(ROOT, 'preflight_ssh_only.py')
        with open(path, encoding = 'utf-8') as handle:
            tree = ast.parse(handle.read())
        banned = {'socket', 'requests', 'urlopen', 'pip', 'connect7', 'gateway', 'subprocess'}
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.add(node.module.split('.')[0])
            elif isinstance(node, ast.Name):
                found.add(node.id)
            elif isinstance(node, ast.Attribute):
                found.add(node.attr)
        self.assertTrue(banned.isdisjoint(found))

    def test_evaluate_reports_intel_mac_python315_without_claiming_success(self):
        facts = {
            'version': (3, 15, 0),
            'implementation': 'CPython',
            'system': 'Darwin',
            'machine': 'x86_64',
            'openssl': 'LibreSSL 3.3.6',
            'specs': {'requests': False, 'urllib3': False, 'ssh2': False},
            'stdlib_telnetlib': False,
            'telnetlib_vendor': True,
        }
        blockers, notes = preflight_ssh_only.evaluate(facts)
        self.assertTrue(blockers)
        self.assertTrue(any('does not install' in item for item in blockers))
        self.assertTrue(any('x86_64' in item or 'cp315' in item for item in notes))

    def test_evaluate_allows_importable_linux_312(self):
        facts = {
            'version': (3, 12, 3),
            'implementation': 'CPython',
            'system': 'Linux',
            'machine': 'x86_64',
            'openssl': 'OpenSSL 3.0.13',
            'specs': {'requests': True, 'urllib3': True, 'ssh2': True},
            'stdlib_telnetlib': True,
            'telnetlib_vendor': True,
        }
        blockers, notes = preflight_ssh_only.evaluate(facts)
        self.assertEqual(blockers, [])
        self.assertEqual(notes, [])

    def test_live_preflight_does_not_pass_in_this_environment(self):
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, 'preflight_ssh_only.py')],
            capture_output = True,
            text = True,
            cwd = ROOT,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn('BLOCKER', proc.stdout)
        self.assertNotIn('192.168.31.', proc.stdout)


class OpenSSLPrefixTests(unittest.TestCase):
    def test_missing_framework_headers_use_tool_prefix(self):
        framework = "/Library/Frameworks/Python.framework/Versions/3.15"
        prefix = ssh_only_build.choose_openssl_root("/tool", framework, headers_present = False)
        self.assertEqual(prefix, "/tool/.ssh-only-dist/openssl-prefix")
        self.assertNotIn("Python.framework", prefix)
        still = ssh_only_build.choose_openssl_root("/tool", framework, headers_present = True)
        self.assertEqual(still, prefix)

    def test_framework_library_is_refused(self):
        framework = "/Library/Frameworks/Python.framework/Versions/3.15"
        prefix = "/tool/.ssh-only-dist/openssl-prefix"
        dep = framework + "/lib/libcrypto.3.dylib"
        with self.assertRaises(ssh_only_build.BuildPlanError):
            ssh_only_build.classify_dependency(dep, [prefix], framework, {"libcrypto.3.dylib"})

    def test_isolated_openssl_and_libssh2_are_rewritten(self):
        framework = "/Library/Frameworks/Python.framework/Versions/3.15"
        prefix = "/tool/.ssh-only-dist/openssl-prefix"
        build_src = "/tool/.ssh-only-dist/src/ssh2_python-1.2.0.post1/build_dir/src"
        names = {"libcrypto.3.dylib", "libssl.3.dylib", "libssh2.1.dylib"}
        roots = [prefix, build_src]
        crypto = ssh_only_build.classify_dependency(
            prefix + "/lib/libcrypto.3.dylib", roots, framework, names)
        sshlib = ssh_only_build.classify_dependency(
            build_src + "/libssh2.1.dylib", roots, framework, names)
        zlib = ssh_only_build.classify_dependency(
            "/usr/lib/libz.1.dylib", roots, framework, names)
        self.assertEqual(crypto, ("rewrite-loader", "libcrypto.3.dylib"))
        self.assertEqual(sshlib, ("rewrite-loader", "libssh2.1.dylib"))
        self.assertEqual(zlib, ("keep", "libz.1.dylib"))

    def test_rpath_without_a_prefix_file_stops(self):
        with self.assertRaises(ssh_only_build.BuildPlanError):
            ssh_only_build.classify_dependency(
                "@rpath/libcrypto.3.dylib",
                ["/tool/.ssh-only-dist/openssl-prefix"],
                "/Library/Frameworks/Python.framework/Versions/3.15",
                set(),
            )

    def test_hash_mismatch_stops_offline(self):
        import tempfile
        handle = tempfile.NamedTemporaryFile(delete = False)
        handle.write(b"not-the-tarball")
        handle.close()
        try:
            with self.assertRaises(ssh_only_build.BuildPlanError):
                ssh_only_build.verify_sha256(handle.name, ssh_only_build.OPENSSL_SHA256)
        finally:
            os.remove(handle.name)

    def test_intel_mac_configure_target(self):
        self.assertEqual(
            ssh_only_build.configure_target("Darwin", "x86_64"),
            "darwin64-x86_64-cc",
        )

    def test_installer_does_not_point_at_framework_openssl(self):
        path = os.path.join(ROOT, "install_ssh_only_venv.sh")
        with open(path, encoding = "utf-8") as handle:
            text = handle.read()
        self.assertNotIn('OPENSSL_ROOT_DIR="$FW"', text)
        self.assertIn('OPENSSL_ROOT_DIR="$PREFIX"', text)
        self.assertIn(ssh_only_build.OPENSSL_SHA256, text)
        self.assertNotIn("OpenSSL headers are not in", text)
        self.assertNotIn("python ssh_only.py", text)
        self.assertNotIn("$ROOT/ssh_only.py", text)


if __name__ == '__main__':
    unittest.main()
