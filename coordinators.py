"""
coordinators.py: talk to whichever NodeGuard coordinator is up.

The network can run several coordinators (the "cloud": the directory of machines and of where
each block's pieces live). Every one of them answers every request, because they share one
database. Apps and nodes start from one address (the join code or settings), learn the others
from it, and move to another when one stops answering.

The list of coordinators is signed with the network's key, the same key nodes already use to
check access passes, so nobody can slip a fake coordinator into it (a node deletes pieces when a
coordinator says they're no longer needed, so this matters).

    c = Coordinators("https://net.nodeguard.co.uk", cloud_key=hex_or_None, cache="coords.json")
    body = c.call(lambda base: fetch(base + "/nodes/heartbeat"))   # tries each in turn
"""

import json
import os
import threading
import time
import urllib.error
import urllib.request

import tickets

REFRESH = 600             # look for new coordinators every 10 minutes
MAX_AGE = 30 * 86400      # forget a signed list older than this
GIVE_UP_FOR = 60          # after a coordinator fails, try the others first for a minute


class NoCoordinator(OSError):
    """None of the coordinators answered."""


def signed_list(seed: bytes, urls) -> dict:
    """What a coordinator publishes: its live coordinators, signed with the network key."""
    payload = json.dumps({"urls": sorted(set(urls)), "t": int(time.time())}, sort_keys=True, separators=(",", ":"))
    return {"payload": payload, "sig": tickets.sign(seed, payload.encode()).hex()}


def check_list(signed, cloud_key: str):
    """The coordinator addresses in a signed list, or None if the signature or age is wrong."""
    try:
        if not tickets.verify(bytes.fromhex(cloud_key), signed["payload"].encode(), bytes.fromhex(signed["sig"])):
            return None
        body = json.loads(signed["payload"])
        if time.time() - float(body["t"]) > MAX_AGE:
            return None
        return [u.rstrip("/") for u in body["urls"] if _usable(u)]
    except (KeyError, ValueError, TypeError):
        return None


def _usable(url):
    """Only HTTPS addresses (plain HTTP just for a test network on this computer)."""
    return isinstance(url, str) and (url.startswith("https://") or url.startswith(("http://127.0.0.1", "http://localhost")))


def _retryable(e):
    """Is this "that coordinator is down" (try another) rather than a real answer?"""
    if isinstance(e, urllib.error.HTTPError):
        return e.code in (502, 503, 504)
    return isinstance(e, (OSError, TimeoutError))


class Coordinators:
    def __init__(self, primary: str, cloud_key: str = None, cache: str = None, opener=None):
        self.primary = primary.rstrip("/")
        self.cloud_key = cloud_key
        self.cache = cache
        self._open = opener or urllib.request.urlopen
        self.others = []
        self.failed = {}                  # url -> when it last failed
        self.preferred = self.primary
        self.checked = 0
        self.lock = threading.Lock()
        self._load()

    # ---------- the list ----------
    def _load(self):
        if not self.cache:
            return
        try:
            with open(self.cache) as f:
                d = json.load(f)
        except (OSError, ValueError):
            return
        key = self.cloud_key or d.get("cloud_key")
        if key and d.get("signed"):
            urls = check_list(d["signed"], key)
            if urls is not None:
                self.cloud_key = key
                self.others = [u for u in urls if u != self.primary]

    def _save(self, signed):
        if not self.cache:
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.cache)), exist_ok=True)
            tmp = self.cache + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"cloud_key": self.cloud_key, "signed": signed}, f)
            os.replace(tmp, self.cache)
        except OSError:
            pass

    def urls(self):
        """Every coordinator, best first: the one that worked last, then the rest, failed ones last."""
        now = time.time()
        allu = [self.preferred] + [u for u in [self.primary] + self.others if u != self.preferred]
        seen, out = set(), []
        for u in allu:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return sorted(out, key=lambda u: now - self.failed.get(u, 0) < GIVE_UP_FOR)

    def refresh(self, force=False):
        """Ask a coordinator for the signed list of live coordinators (every 10 minutes)."""
        if not force and time.time() - self.checked < REFRESH:
            return
        self.checked = time.time()
        for base in self.urls():
            try:
                with self._open(urllib.request.Request(base + "/network"), timeout=8) as r:
                    info = json.loads(r.read() or b"{}")
            except Exception:        # noqa: BLE001  (that one's down: try the next)
                continue
            if not self.cloud_key and info.get("cloud_key"):
                self.cloud_key = info["cloud_key"]          # an app's first contact: trust the address it was given
            signed = info.get("coordinators")
            if not (signed and self.cloud_key):
                return
            urls = check_list(signed, self.cloud_key)
            if urls is not None:
                with self.lock:
                    self.others = [u for u in urls if u != self.primary]
                self._save(signed)
            return

    # ---------- using them ----------
    def call(self, fn):
        """fn(base_url) on the first coordinator that answers. A real answer (including an error
        like "not found") comes straight back; only "can't reach it" moves on to the next."""
        try:
            self.refresh()
        except Exception:            # noqa: BLE001
            pass
        last = None
        for base in self.urls():
            try:
                out = fn(base)
            except Exception as e:   # noqa: BLE001
                if not _retryable(e):
                    raise
                last = e
                self.failed[base] = time.time()
                continue
            self.preferred = base
            self.failed.pop(base, None)
            return out
        raise NoCoordinator(f"no NodeGuard coordinator answered ({last})")

    def request(self, method, path, body=None, headers=None, timeout=15, opener=None):
        """Send one request to whichever coordinator answers; returns the response body."""
        data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
        op = opener or self._open

        def go(base):
            req = urllib.request.Request(base + path, data=data, method=method, headers=headers or {})
            with op(req, timeout=timeout) as r:
                return r.read()
        return self.call(go)
