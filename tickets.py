"""
tickets.py: short-lived access passes for storage nodes.

The cloud signs every pass with its private Ed25519 key. Nodes only hold the
matching PUBLIC key: they can check a pass, but can never create one. That is
what makes it safe to let anyone run a node: a node operator can't forge
access to other people's data.

Pass = account . expiry . scope . signature
  scope "rw":  read and write new shards (what customers' devices get)
  scope "all": also delete and repair shards (only the cloud itself uses these)

Node logins to the cloud (heartbeats, relay, audits) don't use passes: each
node has its own key, issued when it registers (see cloud.py).

Signatures use the cryptography library when it's installed; a plain-Python Ed25519 (RFC 8032)
is the fallback, so a small box with nothing installed still works.
Nodes cache passes they've already checked, so each pass costs one check.
"""

import hashlib
import hmac
import time

DEFAULT_TTL = 3600

# ---------- Ed25519 (RFC 8032), pure Python ----------
_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _inv(x):
    return pow(x, _p - 2, _p)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * _I) % _p
    if x % 2 != 0:
        x = _p - x
    return x


_By = 4 * _inv(5) % _p
_Bx = _xrecover(_By)
_B = (_Bx, _By, 1, _Bx * _By % _p)        # extended coordinates (X, Y, Z, T)
_ZERO = (0, 1, 1, 0)


def _add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _p
    b = (y1 + x1) * (y2 + x2) % _p
    c = t1 * 2 * _d * t2 % _p
    dd = z1 * 2 * z2 % _p
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _p, g * h % _p, f * g % _p, e * h % _p)


def _mul(s, P):
    Q = _ZERO
    while s:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _encode(P):
    x, y, z, _t = P
    zi = _inv(z)
    x, y = x * zi % _p, y * zi % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decode(s):
    if len(s) != 32:
        raise ValueError("bad point")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _p:
        raise ValueError("bad point")
    x = _xrecover(y)
    if (x * x * -1 + y * y - 1 - _d * x * x * y * y) % _p != 0:
        raise ValueError("point not on curve")
    if x == 0 and sign:
        raise ValueError("bad point")
    if (x & 1) != sign:
        x = _p - x
    return (x, y, 1, x * y % _p)


def _h(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _py_public_key(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _encode(_mul(a, _B))


def _py_sign(seed: bytes, msg: bytes, pub: bytes = None) -> bytes:
    a, prefix = _expand(seed)
    A = pub or _encode(_mul(a, _B))
    r = _h(prefix + msg) % _L
    R = _encode(_mul(r, _B))
    k = _h(R + A + msg) % _L
    return R + int.to_bytes((r + k * a) % _L, 32, "little")


def _py_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        if len(sig) != 64:
            return False
        A = _decode(pub)
        R = _decode(sig[:32])
        s = int.from_bytes(sig[32:], "little")
        if s >= _L:
            return False
        k = _h(sig[:32] + pub + msg) % _L
        left = _mul(s, _B)
        right = _add(R, _mul(k, A))
        # compare in affine form
        return _encode(left) == _encode(right)
    except ValueError:
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


def sign(seed: bytes, msg: bytes, pub: bytes = None) -> bytes:
    return _lib_sign(seed, msg) if LIBRARY else _py_sign(seed, msg, pub)


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    return _lib_verify(pub, msg, sig) if LIBRARY else _py_verify(pub, msg, sig)


# ---------- network keys ----------
def seed_from_secret(secret: bytes) -> bytes:
    """Every cloud instance derives the same signing key from the network secret."""
    return hashlib.blake2b(secret, digest_size=32, person=b"vault-tkt-v2").digest()


def login_key(secret: bytes) -> bytes:
    """What your extra storage servers get instead of the network secret: it lets their machines log
    in to the cloud, but it can't make passes to anyone's data (those need the signing key above)."""
    return hashlib.blake2b(secret, digest_size=32, person=b"vault-login-v1").hexdigest().encode()


def cloud_public_key(secret: bytes) -> str:
    return public_key(seed_from_secret(secret)).hex()


class Issuer:
    """Cloud side: signs passes (and reuses recent ones, signing costs a few ms)."""

    def __init__(self, secret: bytes):
        self.seed = seed_from_secret(secret)
        self.pub = public_key(self.seed)
        self._recent = {}

    def issue(self, account: str, ttl: int = DEFAULT_TTL, scope: str = "rw") -> str:
        key = (account, ttl, scope)
        hit = self._recent.get(key)
        now = time.time()
        if hit and hit[1] - now > ttl * 0.5:
            return hit[0]
        exp = int(now) + ttl
        msg = f"{account}|{exp}|{scope}".encode()
        t = f"{account}.{exp}.{scope}.{sign(self.seed, msg, self.pub).hex()}"
        if len(self._recent) > 10000:
            self._recent.clear()
        self._recent[key] = (t, exp)
        return t


class Checker:
    """Node side: checks passes with the cloud's public key only."""

    def __init__(self, pub_hex: str):
        self.pub = bytes.fromhex(pub_hex)
        self._ok = {}

    def check(self, ticket: str):
        """(account, scope) if the pass is genuine and unexpired, else None."""
        try:
            account, exp, scope, sig = ticket.split(".")
            exp = int(exp)
        except (ValueError, AttributeError):
            return None
        if exp < time.time():
            return None
        hit = self._ok.get(ticket)
        if hit:
            return hit
        try:
            raw_sig = bytes.fromhex(sig) if len(sig) == 128 else b""
        except ValueError:
            return None
        if verify(self.pub, f"{account}|{exp}|{scope}".encode(), raw_sig):
            if len(self._ok) > 50000:
                self._ok.clear()
            self._ok[ticket] = (account, scope)
            return (account, scope)
        return None


# ---------- node logins (old style, for nodes you run yourself with the network secret) ----------
def issue(secret: bytes, account: str, ttl: int = DEFAULT_TTL) -> str:
    exp = int(time.time()) + ttl
    sig = hmac.new(secret, f"{account}|{exp}".encode(), hashlib.sha256).hexdigest()
    return f"{account}.{exp}.{sig}"


def check(secret: bytes, ticket: str):
    """Returns the id if an HMAC login is valid and unexpired, else None."""
    try:
        account, exp, sig = ticket.split(".")
        if int(exp) < time.time():
            return None
    except (ValueError, AttributeError):
        return None
    good = hmac.new(secret, f"{account}|{exp}".encode(), hashlib.sha256).hexdigest()
    return account if hmac.compare_digest(good, sig) else None
