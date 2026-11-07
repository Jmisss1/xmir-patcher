#!/usr/bin/env bash
# Isolated dependency install for the SSH-only entry.
# Downloads pinned artifacts, builds vendored libssh2 with the venv's cmake,
# rewrites macOS library names with Command Line Tools, runs preflight, and stops.
# It does not run ssh_only.py and does not contact a router.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${1:-/Library/Frameworks/Python.framework/Versions/3.15/bin/python3}"
VENV="$ROOT/venv-ssh-only"
CACHE="$ROOT/.ssh-only-dist"
SRC="$CACHE/src"

if [[ ! -x "$PYTHON" ]]; then
  echo "BLOCKER: Python executable not found: $PYTHON" >&2
  exit 1
fi
case "$PYTHON" in
  *PythonT.framework*)
    echo "BLOCKER: Refusing the free-threaded PythonT framework. Use Python.framework .../bin/python3." >&2
    exit 1
    ;;
esac

"$PYTHON" - << 'PY'
import ssl, sys
print(f"python={sys.version.split()[0]} exe={sys.executable}")
print(f"ssl={ssl.OPENSSL_VERSION}")
if sys.version_info[:2] != (3, 15):
    raise SystemExit("BLOCKER: this installer is for the measured CPython 3.15 framework, not another runtime.")
if "LibreSSL" in ssl.OPENSSL_VERSION:
    raise SystemExit("BLOCKER: this interpreter is linked to LibreSSL. Use /Library/Frameworks/Python.framework/Versions/3.15/bin/python3.")
if "t" in getattr(sys, "abiflags", ""):
    raise SystemExit("BLOCKER: refusing a free-threaded build.")
PY

FW="$(cd "$(dirname "$PYTHON")/.." && pwd)"
if [[ ! -f "$FW/include/openssl/ssl.h" || ! -f "$FW/include/openssl/crypto.h" ]]; then
  echo "BLOCKER: OpenSSL headers are not in $FW/include/openssl." >&2
  echo "The python.org framework is expected to ship them next to its libssl. This script does not install Homebrew." >&2
  exit 1
fi
shopt -s nullglob
ssl_libs=("$FW"/lib/libssl*.dylib)
crypto_libs=("$FW"/lib/libcrypto*.dylib)
shopt -u nullglob
if [[ ${#ssl_libs[@]} -eq 0 || ${#crypto_libs[@]} -eq 0 ]]; then
  echo "BLOCKER: libssl/libcrypto dylibs are not in $FW/lib." >&2
  exit 1
fi

if [[ -e "$VENV" ]]; then
  echo "BLOCKER: $VENV already exists. Remove that directory to repeat a clean install." >&2
  exit 1
fi

mkdir -p "$CACHE"
download() {
  local url="$1" name="$2" sha="$3" dest="$CACHE/$name"
  if [[ ! -f "$dest" ]]; then
    curl -fsSL "$url" -o "$dest"
  fi
  "$PYTHON" - "$dest" "$sha" << 'PY'
import hashlib, pathlib, sys
path, expected = pathlib.Path(sys.argv[1]), sys.argv[2]
got = hashlib.sha256(path.read_bytes()).hexdigest()
if got != expected:
    raise SystemExit(f"BLOCKER: hash mismatch for {path.name}: {got}")
print(f"hash ok {path.name}")
PY
}

download \
  "https://files.pythonhosted.org/packages/ef/55/6dc6d6bb953bdfc52519a0059592c52b6e3b8ad51cf8256dffceb55b0610/setuptools-84.2.1-py3-none-any.whl" \
  "setuptools-84.2.1-py3-none-any.whl" \
  "ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2"
download \
  "https://files.pythonhosted.org/packages/2e/29/69cfbb602cd91690c55d38ba9fe53e6a7e76a6fa647bf38f19c138d25449/wheel-0.48.0-py3-none-any.whl" \
  "wheel-0.48.0-py3-none-any.whl" \
  "3217dcc807155e45db462d7ef2431f5ddda0d7273b700d05a67b271ceb1287ab"
if [[ "$(uname -s)" == "Darwin" ]]; then
  download \
    "https://files.pythonhosted.org/packages/3f/02/86b484e16c91de4bdf90dfab37a33c3e5512bc30d3a494759976df0943b9/cmake-4.4.4-py3-none-macosx_10_10_universal2.whl" \
    "cmake-4.4.4-py3-none-macosx_10_10_universal2.whl" \
    "883962a72b1b3a16ff445427f24c8caca9797dd9e563bbe208cbcd89e877f9d3"
fi
download \
  "https://files.pythonhosted.org/packages/e3/ab/8105fdee39bee50e505c9c97e117353e19ab18c250307ec29a7dee46e46c/ssh2_python-1.2.0.post1.tar.gz" \
  "ssh2_python-1.2.0.post1.tar.gz" \
  "f981465ace35f96e0935b36091b61d17689d9e0e4f29b33a50882b92c45ddcbd"
download \
  "https://files.pythonhosted.org/packages/a0/f4/c67b0b3f1b9245e8d266f0f112c500d50e5b4e83cb6f3b71b6528104182a/requests-2.34.2-py3-none-any.whl" \
  "requests-2.34.2-py3-none-any.whl" \
  "2a0d60c172f83ac6ab31e4554906c0f3b3588d37b5cb939b1c061f4907e278e0"
download \
  "https://files.pythonhosted.org/packages/a7/c2/fe1e52489ae3122415c51f387e221dd0773709bad6c6cdaa599e8a2c5185/urllib3-2.5.0-py3-none-any.whl" \
  "urllib3-2.5.0-py3-none-any.whl" \
  "e6b01673c0fa6a13e374b50871808eb3bf7046c4b125b216f6bf1cc604cff0dc"
download \
  "https://files.pythonhosted.org/packages/32/d1/a3652fe2c19134d0d15922177821d863cbd7e842d53a21bbe7e8e3a1b5ac/certifi-2026.10.23-py3-none-any.whl" \
  "certifi-2026.10.23-py3-none-any.whl" \
  "e9b54de76e530bb6cf0ccd036787103acb58fd42ba930ea8bf948ddbaa2f61d1"
download \
  "https://files.pythonhosted.org/packages/fc/ad/d07d7862a62ffa6d79d68074d14823243dd235a77c45262acbf6adeb28bf/charset_normalizer-3.5.2-py3-none-any.whl" \
  "charset_normalizer-3.5.2-py3-none-any.whl" \
  "b6b751274acb69d77b3323d6b7dbaa3c7fdfc1eb829b7eb61d262f32e1af9685"
download \
  "https://files.pythonhosted.org/packages/58/a2/bb081bab032533a855d44de1d56f8e8426114ff1ba5d1f07a438a0a654f8/idna-3.20-py3-none-any.whl" \
  "idna-3.20-py3-none-any.whl" \
  "ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c"

"$PYTHON" -m venv "$VENV"
"$VENV/bin/python" -m pip install --no-index --find-links "$CACHE" \
  "setuptools==84.2.1" "wheel==0.48.0"
if [[ "$(uname -s)" == "Darwin" ]]; then
  "$VENV/bin/python" -m pip install --no-index --find-links "$CACHE" "cmake==4.4.4"
  if [[ ! -x "$VENV/bin/cmake" ]]; then
    echo "BLOCKER: the cmake wheel did not provide $VENV/bin/cmake." >&2
    exit 1
  fi
elif ! command -v cmake >/dev/null 2>&1; then
  echo "BLOCKER: cmake is not on PATH. On macOS the cmake wheel is installed into the venv; this host is not macOS." >&2
  exit 1
fi

if "$VENV/bin/python" -c 'import Cython' >/dev/null 2>&1; then
  echo "BLOCKER: Cython is installed in the venv. The sdist must use its shipped C files." >&2
  exit 1
fi

rm -rf "$SRC"
mkdir -p "$SRC"
tar -xzf "$CACHE/ssh2_python-1.2.0.post1.tar.gz" -C "$SRC"
export PATH="$VENV/bin:${PATH}"
export OPENSSL_ROOT_DIR="$FW"
export CMAKE_PREFIX_PATH="$FW"
(
  cd "$SRC/ssh2_python-1.2.0.post1"
  "$VENV/bin/python" -m pip install --no-build-isolation --no-deps .
)

if [[ "$(uname -s)" == "Darwin" ]]; then
  command -v otool >/dev/null
  command -v install_name_tool >/dev/null
  (
    cd "$SRC/ssh2_python-1.2.0.post1"
    "$VENV/bin/python" - "$FW" << 'PY'
import glob, os, subprocess, sys, sysconfig
framework = sys.argv[1]
site = sysconfig.get_path("purelib")
dylibs = [p for p in glob.glob("build_dir/src/libssh2*.dylib") if not p.endswith(".dSYM")]
if not dylibs:
    raise SystemExit("BLOCKER: cmake did not produce build_dir/src/libssh2*.dylib")
src = dylibs[0]
name = os.path.basename(src)
dest_dir = os.path.join(site, "ssh2")
dest = os.path.join(dest_dir, name)
os.makedirs(dest_dir, exist_ok=True)
subprocess.check_call(["cp", "-f", src, dest])
subprocess.check_call(["install_name_tool", "-id", f"@loader_path/{name}", dest])

def deps(path):
    out = subprocess.check_output(["otool", "-L", path], text=True)
    rows = []
    for line in out.splitlines()[1:]:
        rows.append(line.strip().split()[0])
    return rows

for dep in deps(dest):
    base = os.path.basename(dep)
    if base.startswith("libcrypto") or base.startswith("libssl"):
        local = os.path.join(framework, "lib", base)
        if dep.startswith("@rpath/") or not os.path.exists(dep):
            if not os.path.exists(local):
                raise SystemExit(f"BLOCKER: {dep} is not in the Python framework")
            copied = os.path.join(dest_dir, base)
            subprocess.check_call(["cp", "-f", local, copied])
            subprocess.check_call(["install_name_tool", "-id", f"@loader_path/{base}", copied])
            subprocess.check_call(["install_name_tool", "-change", dep, f"@loader_path/{base}", dest])
for so in glob.glob(os.path.join(dest_dir, "*.so")):
    for dep in deps(so):
        if "libssh2" in os.path.basename(dep):
            subprocess.check_call(["install_name_tool", "-change", dep, f"@loader_path/{name}", so])
print("darwin library names rewritten")
PY
  )
fi

"$VENV/bin/python" -m pip install --no-index --find-links "$CACHE" --no-deps \
  "requests==2.34.2" "urllib3==2.5.0" "certifi==2026.10.23" \
  "charset-normalizer==3.5.2" "idna==3.20"

(
  cd "$ROOT"
  "$VENV/bin/python" "$ROOT/preflight_ssh_only.py"
)
echo "Dependencies are installed in $VENV. Preflight finished. Do not run ssh_only.py from this installer."
