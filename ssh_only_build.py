#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Isolated OpenSSL prefix selection for the ssh2-python build.

The python.org CPython 3.15 framework on the measured Mac has libssl and
libcrypto dylibs and does not have include/openssl/ssl.h or crypto.h.
Those libraries are not a usable build prefix. libssh2 is built against
one OpenSSL tree: the headers and libraries produced from the pinned
openssl-3.5.9 tarball inside the tool directory.
"""

import hashlib
import os


class BuildPlanError(Exception):
    pass


OPENSSL_VERSION = "3.5.9"
OPENSSL_SHA256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
OPENSSL_URL = (
    "https://github.com/openssl/openssl/releases/download/"
    "openssl-3.5.9/openssl-3.5.9.tar.gz"
)
FRAMEWORK_MARK = "Python.framework"


def openssl_prefix(tool_root):
    return os.path.join(os.path.abspath(tool_root), ".ssh-only-dist", "openssl-prefix")


def configure_target(system, machine):
    targets = {
        ("Darwin", "x86_64"): "darwin64-x86_64-cc",
        ("Darwin", "arm64"): "darwin64-arm64-cc",
        ("Linux", "x86_64"): "linux-x86_64",
    }
    try:
        return targets[(system, machine)]
    except KeyError:
        raise BuildPlanError("no OpenSSL Configure target for %s %s" % (system, machine))


def assert_isolated_prefix(prefix, framework_root):
    prefix = os.path.abspath(prefix)
    framework_root = os.path.abspath(framework_root) if framework_root else ""
    if FRAMEWORK_MARK in prefix:
        raise BuildPlanError("refusing a Python.framework OpenSSL prefix")
    if framework_root and (prefix == framework_root or prefix.startswith(framework_root + os.sep)):
        raise BuildPlanError("refusing to use the Python framework as the OpenSSL prefix")
    return prefix


def choose_openssl_root(tool_root, framework_root, headers_present):
    """Select the libssh2 OpenSSL tree.

    headers_present records whether the framework has openssl headers.
    The measured Mac does not. Either way the framework is not selected:
    its libraries are not paired with another tree's headers.
    """
    del headers_present
    prefix = openssl_prefix(tool_root)
    return assert_isolated_prefix(prefix, framework_root)


def verify_sha256(path, expected):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    got = digest.hexdigest()
    if got != expected:
        raise BuildPlanError("hash mismatch for %s" % os.path.basename(path))
    return got


def _is_framework_path(dep, framework_root):
    if FRAMEWORK_MARK in dep:
        return True
    if not framework_root or not dep.startswith("/"):
        return False
    root = os.path.abspath(framework_root)
    path = os.path.abspath(dep)
    return path == root or path.startswith(root + os.sep)


def _under_prefix(dep, prefix):
    if not dep.startswith("/"):
        return False
    root = os.path.abspath(prefix)
    path = os.path.abspath(dep)
    return path == root or path.startswith(root + os.sep)


def _under_any(dep, roots):
    return any(_under_prefix(dep, root) for root in roots)


def classify_dependency(dep, allowed_roots, framework_root, available_basenames):
    """Decide how one Mach-O dependency is handled.

    OpenSSL and libssh2 must come from the tool prefix or the libssh2 build
    directory. A Python.framework path is refused. SDK libz and libSystem stay.
    """
    if _is_framework_path(dep, framework_root):
        raise BuildPlanError("refusing Python.framework library %s" % dep)
    base = os.path.basename(dep)
    needs_tool = base.startswith("libssl") or base.startswith("libcrypto") or "libssh2" in base
    if needs_tool:
        if dep.startswith("@loader_path/"):
            return ("keep", base)
        if _under_any(dep, allowed_roots) or dep.startswith("@rpath/"):
            if base not in available_basenames:
                raise BuildPlanError("tool directory is missing %s" % base)
            return ("rewrite-loader", base)
        raise BuildPlanError("refusing OpenSSL or libssh2 outside the tool directory: %s" % dep)
    if base.startswith("libz") or base.startswith("libSystem") or dep.startswith("/usr/lib/"):
        return ("keep", base)
    raise BuildPlanError("unexpected library dependency: %s" % dep)


def library_source(basename, roots):
    for root in roots:
        for candidate in (
            os.path.join(root, "lib", basename),
            os.path.join(root, basename),
            os.path.join(root, "src", basename),
        ):
            if os.path.isfile(candidate):
                return candidate
    raise BuildPlanError("tool directory is missing %s" % basename)


def apply_darwin_fixup(prefix, framework_root, build_src):
    """Copy libssh2 and its OpenSSL libs beside the extension and retarget them.

    Refuses a dependency that points into Python.framework. Uses otool and
    install_name_tool from the Command Line Tools.
    """
    import glob
    import shutil
    import subprocess
    import sysconfig
    site = os.path.join(sysconfig.get_path("purelib"), "ssh2")
    os.makedirs(site, exist_ok=True)
    dylibs = [
        path for path in glob.glob(os.path.join(build_src, "libssh2*.dylib"))
        if ".dSYM" not in path
    ]
    if not dylibs:
        raise BuildPlanError("cmake did not produce a libssh2 dylib")
    roots = [prefix, build_src]
    available = set()
    for root in roots:
        if os.path.isdir(root):
            for dirpath, _dirs, files in os.walk(root):
                available.update(files)
    copied = {}

    def otool_deps(path):
        output = subprocess.check_output(["otool", "-L", path], text=True)
        return [line.strip().split()[0] for line in output.splitlines()[1:]]

    def ensure(basename):
        if basename in copied:
            return copied[basename]
        source = library_source(basename, roots)
        dest = os.path.join(site, basename)
        shutil.copy2(source, dest)
        subprocess.check_call(["install_name_tool", "-id", "@loader_path/%s" % basename, dest])
        copied[basename] = dest
        return dest

    def relink(binary):
        for dep in otool_deps(binary):
            action, base = classify_dependency(dep, roots, framework_root, available)
            if action == "rewrite-loader":
                ensure(base)
                subprocess.check_call([
                    "install_name_tool", "-change", dep, "@loader_path/%s" % base, binary,
                ])

    queue = [ensure(os.path.basename(dylibs[0]))]
    seen = set()
    while queue:
        binary = queue.pop()
        if binary in seen:
            continue
        seen.add(binary)
        known = set(copied.values())
        relink(binary)
        for path in copied.values():
            if path not in known:
                queue.append(path)
    for extension in glob.glob(os.path.join(site, "*.so")):
        relink(extension)
