"""
node.py: a Vault storage node.

A node stores shards: small encrypted pieces of company data. It cannot read
them (it never has the keys) and it only ever sees a fraction of any file.
Nodes can run on company machines, partner machines or cloud servers.

Anyone can run a node (community / operator mode). It joins with the
network's join code and the operator's token, so earnings go to the right person:

  python3 node.py --dir node_data --join NETWORK_CODE --operator op_... --relay --zone london

Nodes you run yourself can instead use the network secret:

  python3 node.py --dir node_data --port 9601 --cloud https://CLOUD:9600 \
                  --secret NETWORK_SECRET --url https://THIS_MACHINE:9601

A node holds only the cloud's PUBLIC key, so it can check access passes but
never create them. Customer devices' passes can read and add shards; only the
cloud's own passes can delete or rewrite them.

HTTP API (every request needs an X-Vault-Ticket header issued by the cloud):
  PUT    /shards/<id>   store a shard (X-Shard-Hash header must match the body)
  GET    /shards/<id>   fetch a shard
  HEAD   /shards/<id>   does it exist?
  DELETE /shards/<id>   remove it (cloud passes only)
  GET    /shards/<id>/proof?leaf=N   proof of storage: one 4 KB part + Merkle path (cloud passes only)
  GET    /health        space used / free, shard count (no ticket needed)

The node sends a heartbeat to the cloud every few seconds so the cloud knows
it's alive and how much space it has.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import proofs  # noqa: E402
import tickets  # noqa: E402
import tls  # noqa: E402
import httpsafe  # noqa: E402

SHARD_ID = re.compile(r"^[0-9a-f]{8,96}$")
MAX_SHARD = 64 * 1024 * 1024
HEARTBEAT = 3.0
NODE_VERSION = "3"          # 3: understands passes bound to one machine ("all@<id>", "read@<id>")
# stale-shard cleanup: how often to check, and how old a shard must be before it
# can be removed (so shards mid-upload are never touched)
AUDIT_EVERY = float(os.environ.get("VAULT_AUDIT_SECONDS", 600))
AUDIT_GRACE = float(os.environ.get("VAULT_AUDIT_GRACE", 3600))


def shard_hash(data: bytes) -> str:
    return hashlib.blake2b(data, digest_size=16).hexdigest()


def parse_join(code: str) -> dict:
    """Network join code -> {"cloud": url, "cloud_key": hex, optional "ca": pem}."""
    return json.loads(base64.urlsafe_b64decode(code.strip().encode()))


def make_join(cloud: str, cloud_key: str, ca: str = None) -> str:
    d = {"cloud": cloud, "cloud_key": cloud_key}
    if ca:
        d["ca"] = ca
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode()


class Limiter:
    """Caps how fast this machine sends data to others (so sharing never fills someone's
    home internet). rate is in bytes per second; 0 means no limit. Can change while running."""

    def __init__(self, rate=0):
        self.rate = rate
        self.next = time.monotonic()
        self.lock = threading.Lock()

    def take(self, n):
        if not self.rate or n <= 0:
            return 0.0
        with self.lock:
            now = time.monotonic()
            start = max(now, self.next)
            self.next = start + n / self.rate
            wait = start - now
        if wait > 0:
            time.sleep(min(wait, 30))
        return wait


# ---------- resting: when the owner doesn't want this machine busy ----------
# A resting machine stays online (so its pieces stay readable, nothing has to be moved and its
# reliability doesn't drop), but gets no new pieces and sends what's asked of it slowly.
REST_MBPS = float(os.environ.get("VAULT_REST_MBPS", "1"))


def on_battery():
    """True when this computer is running on its battery. False on mains power, with no battery,
    or when it can't be told (so a desktop never rests by mistake)."""
    try:
        if sys.platform == "win32":
            import ctypes

            class Power(ctypes.Structure):
                _fields_ = [("ac", ctypes.c_ubyte), ("flag", ctypes.c_ubyte), ("percent", ctypes.c_ubyte),
                            ("saver", ctypes.c_ubyte), ("life", ctypes.c_ulong), ("full", ctypes.c_ulong)]
            st = Power()
            if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(st)):
                return False
            return st.ac == 0 and st.flag not in (128, 255)        # 0: unplugged; 128: no battery
        if sys.platform == "darwin":
            out = subprocess.run(["pmset", "-g", "batt"], capture_output=True, text=True, timeout=5).stdout
            return "'Battery Power'" in out
        base = "/sys/class/power_supply"
        mains, battery = [], False
        for n in os.listdir(base):
            try:
                kind = open(os.path.join(base, n, "type")).read().strip()
            except OSError:
                continue
            if kind == "Battery":
                battery = True
            elif kind == "Mains":
                try:
                    mains.append(open(os.path.join(base, n, "online")).read().strip() == "1")
                except OSError:
                    pass
        return battery and bool(mains) and not any(mains)
    except Exception:       # noqa: BLE001  (never let a power check stop sharing)
        return False


def parse_hours(spec):
    """"22-7" -> (22, 7): share fully from 22:00 to 07:00. "" or None -> None (all day)."""
    if not spec:
        return None
    m = re.fullmatch(r"\s*(\d{1,2})\s*-\s*(\d{1,2})\s*", str(spec))
    if not m or not (0 <= int(m.group(1)) <= 23 and 0 <= int(m.group(2)) <= 23):
        raise ValueError("sharing hours look like 22-7 (from 10pm to 7am)")
    start, end = int(m.group(1)), int(m.group(2))
    return None if start == end else (start, end)


def in_hours(spec, now=None):
    h = parse_hours(spec)
    if not h:
        return True
    hour = time.localtime(now).tm_hour
    start, end = h
    return start <= hour < end if start < end else (hour >= start or hour < end)


def rest_reason(policy, now=None, battery=on_battery):
    """Why this machine should rest right now, or None. policy: {"hours": "22-7", "battery": True}."""
    if policy.get("battery") and battery():
        return "on battery"
    try:
        if policy.get("hours") and not in_hours(policy["hours"], now):
            return "outside sharing hours"
    except ValueError:
        pass
    return None


def rest_loop(node, policy, stop, every=30.0):
    """policy: a dict, or a function returning one (read again each time, so changes apply)."""
    while not stop.is_set():
        try:
            node.set_rest(rest_reason(policy() if callable(policy) else policy))
        except Exception:       # noqa: BLE001
            pass
        stop.wait(every)


class Node:
    def __init__(self, folder, secret: bytes = None, capacity: int = 0, cloud_key: str = None):
        self.folder = folder
        self.secret = secret
        os.makedirs(folder, exist_ok=True)
        self.cred_path = os.path.join(folder, "node_login.json")
        self.cred = None
        if os.path.exists(self.cred_path):
            with open(self.cred_path) as f:
                self.cred = json.load(f)
            self.id = self.cred["id"]
            cloud_key = cloud_key or self.cred.get("cloud_key")
        else:
            idp = os.path.join(folder, "node_id")
            if not os.path.exists(idp):
                with open(idp, "w") as f:
                    f.write(uuid.uuid4().hex[:16])
            with open(idp) as f:
                self.id = f.read().strip()
        if not cloud_key and secret:
            cloud_key = tickets.cloud_public_key(secret)
        self.checker = tickets.Checker(cloud_key) if cloud_key else None
        self.served = 0          # bytes sent to others (reported in heartbeats)
        self.limiter = Limiter()
        self.speed = 0           # the owner's own upload limit, bytes per second (0 = none)
        self.rest = None         # why it's resting right now ("on battery", "outside sharing hours"), or None
        self.capacity = capacity or shutil.disk_usage(folder).free
        self._lock = threading.Lock()
        self._used, self._count = self._scan()

    def _scan(self):
        used = count = 0
        for d, _s, names in os.walk(self.folder):
            for n in names:
                if SHARD_ID.match(n):
                    used += os.path.getsize(os.path.join(d, n))
                    count += 1
        return used, count

    def path(self, sid):
        return os.path.join(self.folder, sid[:2], sid)

    def owner_path(self, sid):
        return self.path(sid) + ".owner"

    def put(self, sid, data, owner):
        p = self.path(sid)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        existed = os.path.exists(p)
        old = os.path.getsize(p) if existed else 0
        tmp = p + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, p)
        with open(self.owner_path(sid), "w") as f:
            f.write(owner)
        with self._lock:
            self._used += len(data) - old
            self._count += 0 if existed else 1

    def get(self, sid):
        with open(self.path(sid), "rb") as f:
            return f.read()

    def owner(self, sid):
        try:
            with open(self.owner_path(sid)) as f:
                return f.read().strip()
        except OSError:
            return None

    def delete(self, sid):
        p = self.path(sid)
        size = os.path.getsize(p)
        os.remove(p)
        try:
            os.remove(self.owner_path(sid))
        except OSError:
            pass
        with self._lock:
            self._used -= size
            self._count -= 1

    def health(self):
        with self._lock:
            return {"id": self.id, "used": self._used, "shards": self._count,
                    "free": max(0, self.capacity - self._used), "resting": bool(self.rest)}

    # ---------- speed and resting ----------
    def set_speed(self, rate):
        """The owner's upload limit in bytes per second (0 = no limit). Takes effect at once."""
        self.speed = max(0, rate or 0)
        self._apply()

    def set_rest(self, reason):
        if reason != self.rest:
            self.rest = reason
            self._apply()
            print(f"resting: {reason}" if reason else "sharing fully again", flush=True)

    def _apply(self):
        rest = REST_MBPS * 125_000
        self.limiter.rate = (min(self.speed, rest) if self.speed else rest) if self.rest else self.speed

    # ---------- logging in to the cloud ----------
    def register(self, cloud: str, operator: str, name: str, zone: str, tier: str = "hot"):
        """First start in operator mode: get this node's own login from the cloud."""
        body = json.dumps({"operator": operator, "name": name, "zone": zone, "tier": tier,
                           "capacity": self.capacity}).encode()
        req = urllib.request.Request(cloud.rstrip("/") + "/nodes/register", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        with tls.urlopen(req, timeout=20) as r:
            cred = json.loads(r.read())
        tmp = self.cred_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cred, f)
        os.replace(tmp, self.cred_path)
        self.cred = cred
        self.id = cred["id"]
        self.checker = tickets.Checker(cred["cloud_key"])
        return cred

    def cloud_headers(self, ttl=120):
        if self.cred:
            return {"X-Node-Key": f"{self.cred['id']}:{self.cred['key']}"}
        return {"X-Vault-Ticket": tickets.issue(self.secret, "node:" + self.id, ttl)}


def make_handler(node: Node, delay=0.0):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def handle_one_request(self):
            if delay:
                time.sleep(delay)      # test-only: simulate a far-away machine
            super().handle_one_request()

        def _reply(self, code, body=b"", ctype="application/octet-stream", headers=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, code, obj):
            self._reply(code, json.dumps(obj).encode(), "application/json")

        def _auth(self):
            """(account, scope) for a genuine pass from the cloud, else None. The cloud's own passes
            name the one machine they're for ("all@<id>", "read@<id>"): one shown to another machine
            is refused, so a machine can't reuse a pass it was given against anyone else's pieces."""
            if not node.checker:
                return None
            got = node.checker.check(self.headers.get("X-Vault-Ticket", ""))
            if not got:
                return None
            account, scope = got
            if "@" in scope:
                scope, who = scope.split("@", 1)
                if who != node.id:
                    return None
            return account, scope

        def _sid(self):
            sid = self.path.split("/shards/", 1)[-1].split("?")[0]
            return sid if self.path.startswith("/shards/") and SHARD_ID.match(sid) else None

        def do_GET(self):
            if self.path == "/health":
                return self._json(200, node.health())
            if self.path.startswith("/shards/") and "/proof" in self.path:
                sid = self.path[len("/shards/"):].split("/proof")[0]
                auth = self._auth()
                if not auth or auth[1] not in ("all", "read"):
                    return self._json(401, {"error": "only the cloud asks for proofs"})
                if not SHARD_ID.match(sid):
                    return self._json(404, {"error": "bad shard id"})
                owner = node.owner(sid)
                if owner and owner != auth[0]:
                    return self._json(403, {"error": "shard belongs to another account"})
                try:
                    leaf = int(self.path.split("leaf=")[1].split("&")[0])
                    data = node.get(sid)
                except (IndexError, ValueError):
                    return self._json(400, {"error": "leaf=N needed"})
                except OSError:
                    return self._json(404, {"error": "no such shard"})
                if not 0 <= leaf < proofs.leaf_count(len(data)):
                    return self._json(400, {"error": "no such part"})
                return self._json(200, proofs.prove(data, leaf))
            sid = self._sid()
            if not sid:
                return self._json(404, {"error": "not found"})
            auth = self._auth()
            if not auth:
                return self._json(401, {"error": "missing or invalid ticket"})
            owner = node.owner(sid)
            if owner and owner != auth[0]:      # each customer's pass opens only their own shards
                return self._json(403, {"error": "shard belongs to another account"})
            try:
                data = node.get(sid)
            except OSError:
                return self._json(404, {"error": "no such shard"})
            with node._lock:
                node.served += len(data)
            node.limiter.take(len(data))          # the owner's upload speed limit, if they set one
            self._reply(200, data, headers={"X-Shard-Hash": shard_hash(data)})

        def do_HEAD(self):
            sid = self._sid()
            auth = self._auth() if sid else None
            if not sid or not auth:
                return self._reply(404 if not sid else 401)
            owner = node.owner(sid)
            if owner and owner != auth[0]:
                return self._reply(403)
            p = node.path(sid)
            if not os.path.exists(p):
                return self._reply(404)
            self.send_response(200)
            self.send_header("Content-Length", str(os.path.getsize(p)))
            self.end_headers()

        def do_PUT(self):
            sid = self._sid()
            if not sid:
                return self._json(404, {"error": "bad shard id"})
            auth = self._auth()
            if not auth:
                return self._json(401, {"error": "missing or invalid ticket"})
            account, scope = auth
            if scope == "read":
                return self._json(403, {"error": "this pass can only read"})
            n = int(self.headers.get("Content-Length", 0))
            if n > MAX_SHARD:
                return self._json(413, {"error": "shard too large"})
            data = self.rfile.read(n)
            if shard_hash(data) != self.headers.get("X-Shard-Hash"):
                return self._json(400, {"error": "shard damaged in transit"})
            prev = node.owner(sid)
            if prev and prev != account:
                return self._json(403, {"error": "shard belongs to another account"})
            if prev and scope != "all":
                # a stored shard is never changed by a device's pass (only the cloud's repair
                # can rewrite one), so a leaked pass can't be used to overwrite data
                try:
                    same = shard_hash(node.get(sid)) == shard_hash(data)
                except OSError:
                    same = False
                if not same:
                    return self._json(409, {"error": "shard already exists"})
            if node.health()["free"] < n:
                return self._json(507, {"error": "node full"})
            node.put(sid, data, account)
            self._json(201, {"stored": len(data)})

        def do_DELETE(self):
            sid = self._sid()
            auth = self._auth()
            if not sid or not auth:
                return self._json(401, {"error": "missing or invalid ticket"})
            account, scope = auth
            if scope != "all":
                return self._json(403, {"error": "only the cloud can delete shards"})
            owner = node.owner(sid)
            if owner is None:
                return self._json(404, {"error": "no such shard"})
            if owner != account:
                return self._json(403, {"error": "shard belongs to another account"})
            node.delete(sid)
            self._json(200, {"deleted": sid})

    return httpsafe.harden(H)


def device_label():
    """What kind of machine this is, for the NodeGuard team's list of who has joined (no personal details)."""
    if os.environ.get("VAULT_DEVICE"):
        return os.environ["VAULT_DEVICE"][:80]
    import platform
    return {"Darwin": "Mac", "Windows": "Windows", "Linux": "Linux"}.get(platform.system(), platform.system() or "Unknown")


class _OneCoordinator:
    """Used only if coordinators.py is missing (an older install): the one address, no failover."""

    def __init__(self, url):
        self.primary = url.rstrip("/")

    def request(self, method, path, body=None, headers=None, timeout=15):
        data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
        with tls.urlopen(urllib.request.Request(self.primary + path, data=data, method=method, headers=headers or {}),
                         timeout=timeout) as r:
            return r.read()


def _coords(cloud, cloud_key=None, cache=None):
    """A coordinator address, or the list of them (coordinators.Coordinators), either works."""
    if not isinstance(cloud, str):
        return cloud
    try:
        import coordinators
    except ImportError:
        return _OneCoordinator(cloud)
    return coordinators.Coordinators(cloud, cloud_key=cloud_key, cache=cache, opener=tls.urlopen)


def heartbeat_loop(node: Node, cloud, url: str, name: str, stop: threading.Event, zone="default", country=""):
    coords = _coords(cloud)
    while not stop.is_set():
        body = json.dumps(dict(node.health(), url=url, name=name, zone=zone, served=node.served,
                               version=NODE_VERSION, country=country, device=device_label(),
                               lab_ip=os.environ.get("VAULT_LAB_IP") or None)).encode()
        try:
            coords.request("POST", "/nodes/heartbeat", body, timeout=5,
                           headers=dict(node.cloud_headers(60), **{"Content-Type": "application/json"}))
        except Exception:
            pass  # no coordinator reachable: keep serving, retry next beat
        stop.wait(HEARTBEAT)


def audit_loop(node: Node, cloud, stop: threading.Event):
    """Every so often, ask the cloud which of our shards are no longer ours to
    keep (deleted files, or shards moved while we were offline) and remove them."""
    coords = _coords(cloud)
    while not stop.wait(AUDIT_EVERY):
        try:
            now = time.time()
            old = []
            for d, _s, names in os.walk(node.folder):
                for nm in names:
                    if SHARD_ID.match(nm) and now - os.path.getmtime(os.path.join(d, nm)) > AUDIT_GRACE:
                        old.append(nm)
            removed = 0
            for i in range(0, len(old), 1000):
                body = json.dumps({"shards": old[i:i + 1000]}).encode()
                answer = coords.request("POST", f"/nodes/{node.id}/audit", body, timeout=30,
                                        headers=dict(node.cloud_headers(), **{"Content-Type": "application/json"}))
                for sid in json.loads(answer)["orphans"]:
                    try:
                        node.delete(sid)
                        removed += 1
                    except OSError:
                        pass
            if removed:
                print(f"cleanup: removed {removed} stale shards", flush=True)
        except Exception:
            pass   # cloud unreachable: try again next round


def relay_loop(node: Node, cloud, port: int, stop: threading.Event):
    """For nodes behind a firewall: keep asking the cloud for requests meant for
    this node, run them against our own local server, and send the answers back.
    Any coordinator will do: the queue of requests is shared between them."""
    import base64
    coords = _coords(cloud)
    while not stop.is_set():
        try:
            auth = node.cloud_headers()
            job = json.loads(coords.request("GET", f"/relay-poll/{node.id}", headers=auth, timeout=40))["job"]
            if not job:
                continue
            body = base64.b64decode(job["body"])
            local = urllib.request.Request(f"http://127.0.0.1:{port}{job['path']}", method=job["method"],
                                           data=body if job["method"] in ("PUT", "POST") else None,
                                           headers=job["headers"])
            try:
                with urllib.request.urlopen(local, timeout=30) as lr:
                    status, hdrs, data = lr.status, dict(lr.headers), lr.read()
            except urllib.error.HTTPError as e:
                status, hdrs, data = e.code, dict(e.headers), e.read()
            keep = {k: v for k, v in hdrs.items() if k.lower() in ("content-type", "x-shard-hash")}
            reply = json.dumps({"id": job["id"], "response": {"status": status, "headers": keep,
                                                               "body": base64.b64encode(data).decode()}}).encode()
            coords.request("POST", f"/relay-reply/{node.id}", reply, timeout=30,
                           headers=dict(auth, **{"Content-Type": "application/json"}))
        except Exception:
            stop.wait(1.0)   # cloud unreachable: back off briefly and retry


def serve(folder, port, secret: bytes = None, cloud=None, url=None, name=None, capacity=0, host="0.0.0.0",
          relay=False, relay_workers=4, zone="default", delay_ms=0, tls_cert=None, tls_key=None,
          operator=None, cloud_key=None, tier="hot", country="", max_send_mbps=0, rest=None):
    """rest: when to rest, {"hours": "22-7", "battery": True}, or a function returning that."""
    node = Node(folder, secret, capacity, cloud_key)
    node.set_speed(max_send_mbps * 125_000)            # megabits per second -> bytes per second
    if not secret and not node.cred:
        if not (cloud and operator):
            raise ValueError("a new node needs the network secret, or a join code plus an operator token")
        node.register(cloud, operator, name or "node", zone, tier)
    srv = ThreadingHTTPServer((host, port), make_handler(node, delay_ms / 1000.0))
    srv.daemon_threads = True
    # relay nodes only listen on this machine, so their local server stays plain HTTP;
    # everything they send to the cloud goes over HTTPS when the cloud uses it
    srv.https = False if relay else tls.wrap_server(srv, tls_cert, tls_key, tls13_only=True)
    stop = threading.Event()
    coords = None
    if cloud:
        key = (node.cred or {}).get("cloud_key") or cloud_key or (tickets.cloud_public_key(secret) if secret else None)
        coords = _coords(cloud, cloud_key=key, cache=os.path.join(folder, "coordinators.json"))
        node.coords = coords
    if relay:
        if not cloud:
            raise ValueError("relay mode needs --cloud")
        url = f"{cloud.rstrip('/')}/relay/{node.id}"   # others reach us through a coordinator (any of them)
        for _ in range(relay_workers):
            threading.Thread(target=relay_loop, args=(node, coords, port, stop), daemon=True).start()
    if rest:
        threading.Thread(target=rest_loop, args=(node, rest, stop), daemon=True).start()
    if cloud:
        threading.Thread(target=audit_loop, args=(node, coords, stop), daemon=True).start()
        default_url = f"{'https' if srv.https else 'http'}://127.0.0.1:{port}"
        threading.Thread(target=heartbeat_loop,
                         args=(node, coords, url or default_url, name or node.id, stop, zone,
                               (country or "").upper()[:2]),
                         daemon=True).start()
    return node, srv, stop


def main():
    ap = argparse.ArgumentParser(description="Vault storage node")
    ap.add_argument("--dir", required=True)
    ap.add_argument("--port", type=int, default=9601)
    ap.add_argument("--host", default=os.environ.get("VAULT_HOST"), help="address to listen on")
    ap.add_argument("--cloud", help="cloud control layer URL, e.g. http://1.2.3.4:9600")
    ap.add_argument("--secret", default=os.environ.get("VAULT_NETWORK_SECRET"),
                    help="network secret (only for nodes you run yourself)")
    ap.add_argument("--login-key", default=os.environ.get("VAULT_NODE_LOGIN_KEY"),
                    help="your extra storage servers: a login for the cloud (instead of the network secret)")
    ap.add_argument("--cloud-key", default=os.environ.get("VAULT_CLOUD_KEY"), help="the cloud's public key (with --login-key)")
    ap.add_argument("--join", default=os.environ.get("VAULT_JOIN"), help="network join code (operator mode)")
    ap.add_argument("--operator", default=os.environ.get("VAULT_OPERATOR"),
                    help="operator token: who gets paid for this node (operator mode)")
    ap.add_argument("--url", help="address other machines use to reach this node")
    ap.add_argument("--name")
    ap.add_argument("--capacity-gb", type=float, default=0)
    ap.add_argument("--relay", action="store_true",
                    help="this machine is behind a firewall/router: reach it through the cloud")
    ap.add_argument("--zone", default=os.environ.get("VAULT_ZONE", "default"),
                    help="where this machine is, e.g. london-office or aws-eu-west-2")
    ap.add_argument("--country", default=os.environ.get("VAULT_COUNTRY", ""),
                    help="2-letter country code where this machine physically is, e.g. GB (for data-residency rules)")
    ap.add_argument("--tier", default=os.environ.get("VAULT_TIER", "hot"), choices=["hot", "cold"],
                    help="hot: fast, always-on (SSD, good connection). cold: archive disks, slower, earns less")
    ap.add_argument("--tls-cert", default=os.environ.get("VAULT_TLS_CERT"))
    ap.add_argument("--tls-key", default=os.environ.get("VAULT_TLS_KEY"))
    ap.add_argument("--max-send-mbps", type=float, default=float(os.environ.get("VAULT_MAX_SEND_MBPS", "0")),
                    help="limit how fast this machine sends data to others, in megabits per second (0 = no limit)")
    ap.add_argument("--share-hours", default=os.environ.get("VAULT_SHARE_HOURS", ""),
                    help="share fully only between these hours, e.g. 22-7 (10pm to 7am); outside them it rests")
    ap.add_argument("--rest-on-battery", action="store_true", default=os.environ.get("VAULT_REST_ON_BATTERY") == "1",
                    help="rest while this computer runs on its battery")
    ap.add_argument("--delay-ms", type=int, default=0, help=argparse.SUPPRESS)   # testing only
    a = ap.parse_args()
    try:
        parse_hours(a.share_hours)
    except ValueError as e:
        sys.exit(str(e))
    cloud_key = None
    if a.join:
        j = parse_join(a.join)
        a.cloud = a.cloud or j["cloud"]
        cloud_key = j["cloud_key"]
        if j.get("ca") and not os.environ.get("VAULT_CA_FILE"):
            os.makedirs(a.dir, exist_ok=True)
            ca = os.path.join(a.dir, "network-ca.pem")
            with open(ca, "w") as f:
                f.write(j["ca"])
            os.environ["VAULT_CA_FILE"] = ca
    if a.login_key and not a.secret:
        if not a.cloud_key:
            sys.exit("--login-key needs --cloud-key (the cloud's public key)")
        a.secret, cloud_key = a.login_key, a.cloud_key
    if not a.secret and not a.operator and not os.path.exists(os.path.join(a.dir, "node_login.json")):
        sys.exit("give --join and --operator (anyone's node), or --secret (your own nodes)")
    node, srv, _ = serve(a.dir, a.port, a.secret.encode() if a.secret else None, a.cloud, a.url, a.name,
                         int(a.capacity_gb * 1e9), host=a.host or ("127.0.0.1" if a.relay else "0.0.0.0"), relay=a.relay,
                         zone=a.zone, delay_ms=a.delay_ms, tls_cert=a.tls_cert, tls_key=a.tls_key,
                         operator=a.operator, cloud_key=cloud_key, tier=a.tier, country=a.country,
                         max_send_mbps=a.max_send_mbps,
                         rest={"hours": a.share_hours, "battery": a.rest_on_battery}
                         if a.share_hours or a.rest_on_battery else None)
    print(f"node {node.id} serving {a.dir} on port {a.port} (zone {a.zone}, "
          f"{'relay' if a.relay else 'HTTPS' if srv.https else 'HTTP, no TLS'})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
