"""
node_update.py: signed updates for NodeGuard Node on a NAS or Raspberry Pi.

Boxes fetch a new copy of the program from the network server every day. So that a
broken-into server can't push bad code to every box, each release is signed with a
key that lives only on the owner's own computer (deploy/sign_node.py, run by
"Update servers"). A box remembers the first key it sees and from then on installs
only releases signed by that key. Ed25519 via the cryptography library (plain Python if it
isn't installed).

  python3 node_update.py install <download.tgz> <program folder> <state folder>
      exit 0: updated   10: already up to date   20: refused (not signed by the trusted key)
"""

import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile

# ---------- Ed25519 (RFC 8032), small and slow but only used once a day ----------
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def _xrecover(y):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * I % P
    if (x * x - xx) % P:
        raise ValueError("not a point")
    return x


_BY = 4 * pow(5, P - 2, P) % P
B = (_xrecover(_BY) if _xrecover(_BY) % 2 == 0 else P - _xrecover(_BY), _BY, 1, 0)
B = (B[0], B[1], 1, B[0] * B[1] % P)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _enc(p):
    x, y, z, _t = p
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _dec(s):
    y = int.from_bytes(s, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= P:
        raise ValueError("bad point")
    x = _xrecover(y)
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


def _h(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _secret(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _py_public_key(seed: bytes) -> bytes:
    return _enc(_mul(_secret(seed)[0], B))


def _py_sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _secret(seed)
    pub = _enc(_mul(a, B))
    r = _h(prefix + msg) % L
    R = _enc(_mul(r, B))
    s = (r + _h(R + pub + msg) * a) % L
    return R + s.to_bytes(32, "little")


def _py_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        if len(sig) != 64 or len(pub) != 32:
            return False
        R, s = _dec(sig[:32]), int.from_bytes(sig[32:], "little")
        if s >= L:
            return False
        A = _dec(pub)
        k = _h(sig[:32] + pub + msg) % L
        return _enc(_mul(s, B)) == _enc(_add(R, _mul(k, A)))
    except (ValueError, TypeError):
        return False



# The trusted library does the work wherever it's installed (desktop apps, servers, the Docker image);
# the plain-Python version below is only a fallback for small boxes without it, and is checked
# against the library and RFC 8032's test vectors in the tests.
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Priv, Ed25519PublicKey as _Pub
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.exceptions import InvalidSignature as _BadSig
    LIBRARY = True
except Exception:          # noqa: BLE001  (not installed)
    LIBRARY = False


def _lib_public(seed):
    return _Priv.from_private_bytes(seed).public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)


def _lib_sign(seed, msg):
    return _Priv.from_private_bytes(seed).sign(msg)


def _lib_verify(pub, msg, sig):
    try:
        if len(sig) != 64 or len(pub) != 32:
            return False
        _Pub.from_public_bytes(pub).verify(sig, msg)
        return True
    except (_BadSig, ValueError, TypeError):
        return False


def public_key(seed: bytes) -> bytes:
    return _lib_public(seed) if LIBRARY else _py_public_key(seed)


def sign(seed: bytes, msg: bytes) -> bytes:
    return _lib_sign(seed, msg) if LIBRARY else _py_sign(seed, msg)


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    return _lib_verify(pub, msg, sig) if LIBRARY else _py_verify(pub, msg, sig)


# ---------- releases ----------
def manifest_bytes(m: dict) -> bytes:
    return json.dumps({"files": m["files"], "version": m["version"]}, sort_keys=True, separators=(",", ":")).encode()


def make_manifest(seed: bytes, folder: str, files, version: str) -> dict:
    m = {"files": {}, "version": version}
    for f in files:
        with open(os.path.join(folder, f), "rb") as fh:
            m["files"][f] = hashlib.sha256(fh.read()).hexdigest()
    m["pub"] = public_key(seed).hex()
    m["sig"] = sign(seed, manifest_bytes(m)).hex()
    return m


def check_manifest(m: dict, folder: str, trusted_pub: str = None):
    """(ok, why). Every listed file must match, and the signature must be by trusted_pub
    (or by the key the manifest names, when no key is trusted yet)."""
    try:
        pub = bytes.fromhex(trusted_pub or m["pub"])
        if not verify(pub, manifest_bytes(m), bytes.fromhex(m["sig"])):
            return False, "the signature doesn't match the trusted key"
        for f, h in m["files"].items():
            if "/" in f or "\\" in f or f.startswith("."):
                return False, f"odd file name {f}"
            with open(os.path.join(folder, f), "rb") as fh:
                if hashlib.sha256(fh.read()).hexdigest() != h:
                    return False, f"{f} was changed after signing"
        return True, "ok"
    except (OSError, ValueError, KeyError, TypeError) as e:
        return False, f"bad release ({e})"


PIN_FILE = "update-key.txt"


def pinned_key(*folders):
    """The owner's update key, built into this copy by GitHub (so even a first install trusts only
    that key, never whatever a server offers). None when this copy wasn't built with one."""
    k = os.environ.get("NODEGUARD_UPDATE_KEY", "").strip().lower()
    if not k:
        for d in list(folders) + [os.path.dirname(os.path.abspath(__file__))]:
            p = os.path.join(d, PIN_FILE)
            if os.path.exists(p):
                with open(p) as f:
                    k = f.read().strip().lower()
                if k:
                    break
    return k if len(k) == 64 and all(c in "0123456789abcdef" for c in k) else None


def install(tgz: str, program: str, state: str) -> int:
    """Unpack a downloaded release and put it in place, if it's trusted."""
    trust_file = os.path.join(state, "release-key.txt")
    trusted = pinned_key(program)
    if not trusted and os.path.exists(trust_file):
        with open(trust_file) as f:
            trusted = f.read().strip() or None
    tmp = tempfile.mkdtemp()
    try:
        with tarfile.open(tgz) as t:
            for mem in t.getmembers():
                if not mem.isfile() or not mem.name.startswith("nodeguard-node/") or ".." in mem.name \
                        or mem.name.count("/") != 1:
                    continue
                with t.extractfile(mem) as src, open(os.path.join(tmp, os.path.basename(mem.name)), "wb") as dst:
                    shutil.copyfileobj(src, dst)
        new_ver = _read(os.path.join(tmp, "VERSION"))
        man = None
        if os.path.exists(os.path.join(tmp, "RELEASE.json")):
            with open(os.path.join(tmp, "RELEASE.json")) as f:
                man = json.load(f)
        if trusted:
            if not man:
                print("NodeGuard Node: update refused, it isn't signed (keeping this version)", flush=True)
                return 20
            ok, why = check_manifest(man, tmp, trusted)
            if not ok:
                print(f"NodeGuard Node: update refused: {why} (keeping this version)", flush=True)
                return 20
        elif man:
            ok, why = check_manifest(man, tmp)
            if not ok:
                print(f"NodeGuard Node: update refused: {why}", flush=True)
                return 20
            os.makedirs(state, exist_ok=True)
            with open(trust_file, "w") as f:      # first signed release: remember its key
                f.write(man["pub"] + "\n")
        if new_ver and new_ver == _read(os.path.join(program, "VERSION")):
            return 10
        os.makedirs(program, exist_ok=True)
        for name in os.listdir(tmp):
            if name == "network.json" and os.path.exists(os.path.join(program, name)):
                continue                           # the network a box joined never changes by update
            if name == PIN_FILE:
                continue                           # nor the key it trusts: a release can't swap it
            shutil.copyfile(os.path.join(tmp, name), os.path.join(program, name) + ".new")
            os.replace(os.path.join(program, name) + ".new", os.path.join(program, name))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _read(p):
    try:
        with open(p) as f:
            return f.read().strip()
    except OSError:
        return None


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "install":
        sys.exit(install(sys.argv[2], sys.argv[3], sys.argv[4]))
    print(__doc__)
    sys.exit(2)
