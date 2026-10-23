"""
node_app.py: NodeGuard Node. Share spare disk space with the NodeGuard network and earn
storage or money.

Double-click "NodeGuard Node" (the installed app, or NodeGuard Node.bat / .command). A window opens:
  1. (only if this copy doesn't have the network built in) paste the network's join code
  2. sign up (name and email), or paste an operator token you already have
  3. choose a folder, how much space to share, an upload speed limit and your city
  4. press Start sharing. It starts with the computer and keeps running when the window is closed.

No router or firewall settings needed: the node connects out to the network.
Everything it stores is encrypted by the data's owner; this computer can't read it.

  python3 node_app.py                 open the window (starts the node if it's set up)
  python3 node_app.py --background    run without a window (used when the computer starts)
  python3 node_app.py --headless      a NAS / Raspberry Pi / server with no screen: the page is
                                      opened from another computer at home, behind a password
                                      (first time: the setup code it prints, then choose one)
  python3 node_app.py --reset-password   forget that password (prints a new setup code)
"""

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import node as nodemod  # noqa: E402
import tls  # noqa: E402

APP_PORT = int(os.environ.get("VAULT_NODE_APP_PORT", "9596"))
_old_home = os.path.join(os.path.expanduser("~"), "VaultNode")
HOME = os.environ.get("VAULT_NODE_HOME") or (
    _old_home if os.path.exists(os.path.join(_old_home, "config.json"))
    else os.path.join(os.path.expanduser("~"), "NodeGuard", "Node"))
CONFIG = os.path.join(HOME, "config.json")
PASSWORD_FILE = os.path.join(HOME, "ui-password.json")     # headless: the page's password (hashed)
CODE_FILE = os.path.join(HOME, "setup-code.txt")          # headless: one-time code to set it
SESSIONS_FILE = os.path.join(HOME, "ui-sessions.json")    # headless: signed-in browsers (hashed)
DATA_DIR = os.environ.get("NODEGUARD_DATA")               # headless: where shared space goes (Docker: /data)
# a copy of the app can carry its network's join code, so people don't have to paste one
BUILT_IN = os.path.join(HERE, "network.json")
CITIES = ["london", "manchester", "birmingham", "leeds", "bristol", "glasgow", "edinburgh", "cardiff", "belfast",
          "dublin", "paris", "amsterdam", "frankfurt", "madrid", "barcelona", "milan", "stockholm", "new-york",
          "chicago", "los-angeles", "toronto", "singapore", "sydney"]
# the country each city is in (sent to the network as "self-reported"; only an admin can confirm it)
CITY_COUNTRY = {"london": "GB", "manchester": "GB", "birmingham": "GB", "leeds": "GB", "bristol": "GB",
                "glasgow": "GB", "edinburgh": "GB", "cardiff": "GB", "belfast": "GB", "dublin": "IE",
                "paris": "FR", "amsterdam": "NL", "frankfurt": "DE", "madrid": "ES", "barcelona": "ES",
                "milan": "IT", "stockholm": "SE", "new-york": "US", "chicago": "US", "los-angeles": "US",
                "toronto": "CA", "singapore": "SG", "sydney": "AU"}
SPEEDS = [0, 2, 5, 10, 20, 50, 100]     # upload limits offered, in megabits per second (0 = no limit)
# when to share fully ("" = all day); outside these hours the computer rests (stays online, no new data, sends slowly)
HOURS = ["", "22-7", "18-8", "9-17"]


def rest_policy():
    """Read each time the node checks, so a change in Settings applies within half a minute."""
    cfg = load_config()
    return {"hours": cfg.get("hours") or "", "battery": cfg.get("battery", True) is not False}


# the NodeGuard network, used when this copy doesn't carry a join code: nobody has to paste one
DEFAULT_NET = os.environ.get("NODEGUARD_NET", "https://net.nodeguard.co.uk").rstrip("/")


def built_in_network():
    try:
        with open(BUILT_IN) as f:
            n = json.load(f)
        nodemod.parse_join(n["join"])
        return n
    except (OSError, ValueError, KeyError):
        pass
    if DEFAULT_NET.startswith("https://"):
        return {"name": "NodeGuard", "net": DEFAULT_NET}
    return None


def join_for(net):
    """The join code for a network known only by its address (its key is public; HTTPS proves who it is)."""
    info = _cloud("GET", net["net"] + "/network", timeout=10)
    return nodemod.make_join(net["net"], info["cloud_key"], info.get("ca"))


def api_base():
    """The NodeGuard app server next to this network (accounts live there), or None for other networks."""
    if os.environ.get("NODEGUARD_APP"):
        return os.environ["NODEGUARD_APP"].rstrip("/")
    u = app_url()
    return u[: -len("/app/")] if u and u.endswith("/app/") else None


SIGNIN = {}          # a sign-in in progress: device_code, user_code, url


def signin_start():
    api = api_base()
    if not api:
        raise ValueError("this network doesn't use NodeGuard accounts")
    try:
        r = _cloud("POST", api + "/v1/device/start", {"name": machine_name()}, timeout=15)
    except Exception as e:
        raise ValueError(f"can't reach NodeGuard ({e.__class__.__name__}); check your internet")
    SIGNIN.clear()
    SIGNIN.update(device=r["device_code"], code=r["user_code"], url=r["url"])
    if not HEADLESS["on"]:
        try:
            import webbrowser
            webbrowser.open(r["url"])
        except Exception:
            pass
    return {"user_code": r["user_code"], "url": r["url"]}


def signin_status():
    if not SIGNIN:
        return {"state": "none"}
    try:
        r = _cloud("POST", api_base() + "/v1/device/poll", {"device_code": SIGNIN["device"]}, timeout=15)
    except urllib.error.HTTPError as e:
        if e.code == 410:
            SIGNIN.clear()
            return {"state": "expired"}
        return {"state": "pending"}
    except Exception:
        return {"state": "pending"}
    if not r.get("session"):
        return {"state": "pending"}
    SIGNIN.clear()
    cfg = load_config()
    cfg.update(session=r["session"], email=r.get("email"))
    save_config(cfg)
    return {"state": "done", "email": r.get("email")}


def set_payout(payout, share=None):
    cfg = load_config()
    if not (cfg.get("join") and cfg.get("operator")):
        raise ValueError("start sharing first")
    payout = payout if payout in ("cash", "both") else "credit"
    share = float(share or 0.5) if payout == "both" else None
    j = nodemod.parse_join(cfg["join"])
    try:
        _cloud("POST", j["cloud"] + "/operator/payout", {"payout": payout, "share": share}, headers={"X-Dash-Token": cfg["operator"]})
    except urllib.error.HTTPError as e:
        raise ValueError(f"the network said {e.code}")
    cfg["payout"], cfg["share"] = payout, share
    save_config(cfg)
    return {"ok": True, "payout": payout}


def set_profile(public_name=None, on_board=None):
    cfg = load_config()
    if not (cfg.get("join") and cfg.get("operator")):
        raise ValueError("start sharing first")
    j = nodemod.parse_join(cfg["join"])
    try:
        return _cloud("POST", j["cloud"] + "/operator/profile", {"public_name": public_name, "on_board": on_board},
                      headers={"X-Dash-Token": cfg["operator"]})
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error")
        except ValueError:
            msg = None
        raise ValueError(msg or f"the network said {e.code}")


def app_url():
    """Where people use the storage they earn (the NodeGuard app next to this network)."""
    if os.environ.get("NODEGUARD_APP"):
        return os.environ["NODEGUARD_APP"].rstrip("/") + "/app/"
    net = built_in_network() or {}
    if net.get("app"):
        return net["app"]
    try:
        cloud = nodemod.parse_join(load_config().get("join") or net.get("join") or "")["cloud"]
    except Exception:
        cloud = net.get("net", "")
    return cloud.replace("://net.", "://app.", 1) + "/app/" if "://net." in cloud else None


def default_folder():
    return DATA_DIR or os.path.join(HOME, "data")


def machine_name():
    return (os.environ.get("NODEGUARD_NODE_NAME") or socket.gethostname())[:60]


def load_config():
    try:
        with open(CONFIG) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_config(cfg):
    os.makedirs(HOME, exist_ok=True)
    tmp = CONFIG + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _use_join(join):
    j = nodemod.parse_join(join)
    if j.get("ca"):
        os.makedirs(HOME, exist_ok=True)
        ca = os.path.join(HOME, "network-ca.pem")
        with open(ca, "w") as f:
            f.write(j["ca"])
        os.environ["VAULT_CA_FILE"] = ca
        tls._client_ctx = None
        tls._opener = None
    return j


def _cloud(method, url, body=None, headers=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=dict({"Content-Type": "application/json"}, **(headers or {})))
    with tls.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


# ---------- start with the computer ----------
def _launch_command():
    if getattr(sys, "frozen", False):          # the installed app: run itself
        return [sys.executable]
    exe = sys.executable
    if os.name == "nt":
        w = os.path.join(os.path.dirname(exe), "pythonw.exe")
        exe = w if os.path.exists(w) else exe
    return [exe, os.path.abspath(__file__)]


def autostart_path():
    if os.name == "nt":
        return os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs",
                            "Startup", "NodeGuard Node.vbs")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/LaunchAgents/uk.co.nodeguard.node.plist")
    return os.path.expanduser("~/.config/autostart/nodeguard-node.desktop")


def set_autostart(on: bool):
    path = autostart_path()
    for old in (path.replace("NodeGuard Node", "Vault Node").replace("uk.co.nodeguard.node", "com.vault.node")
                .replace("nodeguard-node", "vault-node"),):
        if old != path and os.path.exists(old):
            try:
                os.remove(old)
            except OSError:
                pass
    if not on:
        try:
            os.remove(path)
        except OSError:
            pass
        return False
    cmd = _launch_command() + ["--background"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.name == "nt":
        quoted = " ".join(f'""{c}""' for c in cmd)
        content = f'Set s = CreateObject("WScript.Shell")\r\ns.Run "{quoted}", 0, False\r\n'
    elif sys.platform == "darwin":
        args = "".join(f"<string>{c}</string>" for c in cmd)
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>uk.co.nodeguard.node</string>
<key>ProgramArguments</key><array>{args}</array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><false/>
</dict></plist>
"""
    else:
        exec_line = " ".join(f'"{c}"' for c in cmd)
        content = f"[Desktop Entry]\nType=Application\nName=NodeGuard Node\nExec={exec_line}\nX-GNOME-Autostart-enabled=true\n"
    with open(path, "w") as f:
        f.write(content)
    return True


# ---------- the node, running inside this app ----------
class Runner:
    def __init__(self):
        self.node = self.srv = self.stop = None
        self.error = None
        self.started = None
        self.lock = threading.Lock()

    @property
    def running(self):
        return self.srv is not None

    def start(self, cfg):
        with self.lock:
            if self.srv:
                return
            j = _use_join(cfg["join"])
            folder = cfg["folder"]
            os.makedirs(folder, exist_ok=True)
            try:
                self.node, self.srv, self.stop = nodemod.serve(
                    folder, free_port(), None, j["cloud"], name=cfg.get("name") or machine_name(),
                    capacity=int(float(cfg["gb"]) * 1e9), host="127.0.0.1", relay=True, zone=cfg["zone"],
                    operator=cfg["operator"], cloud_key=j["cloud_key"], tier=cfg.get("tier") or "hot",
                    country=CITY_COUNTRY.get(cfg.get("zone"), ""), max_send_mbps=float(cfg.get("mbps") or 0),
                    rest=rest_policy)
            except Exception as e:
                self.error = f"couldn't connect to the network: {e}"
                self.srv = None
                raise
            self.error = None
            self.started = time.time()
            threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def halt(self):
        with self.lock:
            if self.srv:
                self.stop.set()
                self.srv.shutdown()
                self.srv.server_close()
            self.srv = self.node = self.stop = None


RUN = Runner()
UPDATER = {"u": None}     # keeps the installed app up to date (desktop_update.py)
APP_TOKEN = secrets.token_hex(16)     # stops other websites from controlling this app
STATE = {"quit": None}
HEADLESS = {"on": False}
PLACEHOLDER_PASSWORDS = {"", "choose-a-password", "changeme", "password"}
PROXY_AUTH = os.environ.get("NODEGUARD_NODE_AUTH") == "proxy"


# ---------- headless: the page is opened from other computers at home, behind a password ----------
def _pw_hash(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000).hex()


class Gate:
    """Who may use the page of a headless box. The password is either set in the page the
    first time (with the one-time setup code the box prints) or given as
    NODEGUARD_NODE_PASSWORD (Docker). Signed-in browsers get a cookie for 30 days."""
    SESSION_DAYS = 30

    def __init__(self):
        self.sessions = None          # sha256(cookie) -> expiry, kept across restarts (updates)
        self.fails = {}
        self.lock = threading.Lock()

    def _load(self):
        if self.sessions is None:
            try:
                with open(SESSIONS_FILE) as f:
                    self.sessions = {k: float(v) for k, v in json.load(f).items()}
            except (OSError, ValueError, AttributeError):
                self.sessions = {}
        return self.sessions

    def _save(self):
        try:
            tmp = SESSIONS_FILE + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(self.sessions, f)
            os.replace(tmp, SESSIONS_FILE)
        except OSError:
            pass

    @staticmethod
    def env_password():
        pw = os.environ.get("NODEGUARD_NODE_PASSWORD", "")
        return pw if pw.strip().lower() not in PLACEHOLDER_PASSWORDS else ""

    def has_password(self):
        return bool(self.env_password()) or os.path.exists(PASSWORD_FILE)

    def check(self, pw):
        pw = str(pw or "")
        if self.env_password():
            return hmac.compare_digest(pw.encode(), self.env_password().encode())
        try:
            with open(PASSWORD_FILE) as f:
                rec = json.load(f)
            return hmac.compare_digest(_pw_hash(pw, bytes.fromhex(rec["salt"])), rec["hash"])
        except (OSError, ValueError, KeyError):
            return False

    def set_password(self, pw):
        os.makedirs(HOME, exist_ok=True)
        salt = os.urandom(16)
        tmp = PASSWORD_FILE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"salt": salt.hex(), "hash": _pw_hash(pw, salt)}, f)
        os.replace(tmp, PASSWORD_FILE)
        try:
            os.remove(CODE_FILE)
        except OSError:
            pass

    def setup_code(self):
        try:
            with open(CODE_FILE) as f:
                code = f.read().strip()
            if code:
                return code
        except OSError:
            pass
        os.makedirs(HOME, exist_ok=True)
        code = f"{secrets.randbelow(10 ** 4):04d}-{secrets.randbelow(10 ** 4):04d}"
        fd = os.open(CODE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(code + "\n")
        return code

    def allow_try(self, ip, limit=10, window=600):
        now = time.time()
        with self.lock:
            recent = [t for t in self.fails.get(ip, []) if now - t < window]
            self.fails[ip] = recent
            return len(recent) < limit

    def failed(self, ip):
        with self.lock:
            self.fails.setdefault(ip, []).append(time.time())

    def new_session(self):
        tok = secrets.token_urlsafe(32)
        with self.lock:
            now = time.time()
            self.sessions = {k: v for k, v in self._load().items() if v > now}
            self.sessions[hashlib.sha256(tok.encode()).hexdigest()] = now + self.SESSION_DAYS * 86400
            self._save()
        return tok

    def valid(self, cookie_header):
        for part in (cookie_header or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "ngn" and v:
                exp = self._load().get(hashlib.sha256(v.encode()).hexdigest())
                if exp and exp > time.time():
                    return True
        return False

    def end(self, cookie_header):
        for part in (cookie_header or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "ngn":
                with self.lock:
                    self._load().pop(hashlib.sha256(v.encode()).hexdigest(), None)
                    self._save()

    def reset(self):
        """Forget the password and every signed-in browser; a new setup code is made."""
        for f in (PASSWORD_FILE, SESSIONS_FILE, CODE_FILE):
            try:
                os.remove(f)
            except OSError:
                pass
        self.sessions = {}
        return self.setup_code()


GATE = Gate()


def lan_host(host):
    """Headless: the page answers to addresses and home-network names only, never to a
    public website's name (which is how DNS-rebinding tricks reach home devices)."""
    host = (host or "").strip().lower()
    h = host[1:host.find("]")] if host.startswith("[") else host.split(":")[0]
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    extra = {x.strip().lower() for x in os.environ.get("NODEGUARD_NODE_HOSTS", "").split(",") if x.strip()}
    return bool(h) and (h == "localhost" or "." not in h or h in extra
                        or h.endswith((".local", ".lan", ".home", ".internal", ".home.arpa")))


def home_network(ip):
    """Headless: only computers on the same home network may open the page (unless
    NODEGUARD_NODE_ALLOW_ANY=1, for people who put it behind their own HTTPS proxy)."""
    if os.environ.get("NODEGUARD_NODE_ALLOW_ANY") == "1":
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_private or a.is_loopback or a.is_link_local


# ---------- folder backup: NodeGuard Sync, running inside this app ----------
# One download does both: sharing spare space, and keeping a folder backed up (encrypted here first).
# A separately installed NodeGuard Sync keeps working: if one is already running, this app just opens it.
FOLDER = {"srv": None}


def _sync():
    import sync
    return sync


def folder_backup_available():
    """The folder backup engine (sync.py) ships with the NodeGuard apps; the open-source node runs without it."""
    import importlib.util
    try:
        return importlib.util.find_spec("sync") is not None
    except (ImportError, ValueError):
        return False


def folder_backup_url():
    return f"http://127.0.0.1:{_sync().APP_PORT}/"


def _folder_backup_elsewhere():
    if FOLDER["srv"]:
        return False
    try:
        info = json.loads(urllib.request.urlopen(folder_backup_url() + "api/ping", timeout=1).read() or b"{}")
        return info.get("app") == "nodeguard-sync"
    except Exception:
        return False


def folder_backup_start():
    """Start the folder backup engine in this app (once). Signed-in account and server come from this app."""
    if FOLDER["srv"] or _folder_backup_elsewhere():
        return
    s = _sync()
    s.set_autostart = lambda on: bool(load_config().get("autostart"))      # this app already starts with the computer
    cfg = s.load_json(s.CONFIG, {})
    api = api_base()
    if api and not cfg.get("api"):
        os.makedirs(s.HOME, exist_ok=True)
        s.save_json(s.CONFIG, dict(cfg, api=api))
    srv = ThreadingHTTPServer(("127.0.0.1", s.APP_PORT), s.H)
    srv.daemon_threads = True
    FOLDER["srv"] = srv
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=s.resume_from_keystore, daemon=True).start()


def folder_backup_resume():
    """At start: carry on backing up a folder that was set up before."""
    if not folder_backup_available():
        return
    try:
        s = _sync()
        if s.load_json(s.CONFIG, {}).get("workspace"):
            folder_backup_start()
    except Exception as e:
        print(f"folder backup didn't start: {e}", flush=True)


def folder_backup_status():
    try:
        s = _sync()
        if FOLDER["srv"]:
            st = s.status()
        elif _folder_backup_elsewhere():
            st = json.loads(urllib.request.urlopen(folder_backup_url() + "api/status", timeout=2).read())
        else:
            cfg = s.load_json(s.CONFIG, {})
            return {"configured": bool(cfg.get("workspace")), "folder": cfg.get("folder"), "running": False,
                    "mode": cfg.get("mode") or "folder", "drive_available": s.drive_available()}
        c = st.get("config") or {}
        return {"configured": bool(st.get("configured")), "folder": c.get("folder"), "running": bool(st.get("running")),
                "unlocked": bool(st.get("unlocked")), "paused": bool(st.get("paused")), "state": st.get("state"),
                "last": st.get("last"), "error": st.get("error"), "mode": st.get("mode") or "folder",
                "drive_available": bool(st.get("drive_available")), "drive": st.get("drive")}
    except Exception as e:
        return {"configured": False, "error": str(e)}


def status():
    cfg = load_config()
    net = built_in_network()
    out = {"configured": bool(cfg.get("join") and cfg.get("operator")), "running": RUN.running, "error": RUN.error,
           "paused": bool(cfg.get("paused")),
           "config": dict({k: cfg.get(k) for k in ("folder", "gb", "zone", "name", "autostart", "tier", "mbps", "linked", "email", "payout", "share")},
                          hours=cfg.get("hours") or "", battery=cfg.get("battery", True) is not False),
           "resting": RUN.node.rest if RUN.node else None, "hours_choices": HOURS,
           "app_url": app_url(),
           "update": UPDATER["u"].status() if UPDATER["u"] else None, "auto_update": cfg.get("auto_update", True) is not False,
           "account": {"available": bool(api_base()), "email": cfg.get("email") if cfg.get("session") else None},
           "signin": {"user_code": SIGNIN.get("code"), "url": SIGNIN.get("url")} if SIGNIN else None,
           "cities": CITIES, "speeds": SPEEDS, "home": HOME, "built_in": bool(net),
           "network_name": (net or {}).get("name") or "NodeGuard"}
    folder = cfg.get("folder") or default_folder()
    probe = os.path.abspath(folder)
    while not os.path.exists(probe) and os.path.dirname(probe) != probe:   # nearest folder that exists
        probe = os.path.dirname(probe)
    out["disk_free_gb"] = round(shutil.disk_usage(probe).free / 1e9, 1)
    out["default_folder"] = default_folder()
    out["headless"] = HEADLESS["on"]
    out["folder_backup"] = None if HEADLESS["on"] or not folder_backup_available() else folder_backup_status()
    if RUN.node:
        out["local"] = dict(RUN.node.health(), served=RUN.node.served, uptime_s=int(time.time() - RUN.started))
    if out["configured"]:
        try:
            j = nodemod.parse_join(cfg["join"])
            d = _cloud("GET", j["cloud"] + "/dash/data", headers={"X-Dash-Token": cfg["operator"]}, timeout=5)
            me = RUN.node.id if RUN.node else None
            rates = d.get("rates") or {}
            o = d.get("operator", {})
            out["network"] = {"totals": d.get("totals"), "payout": o.get("payout"),
                              "pool": o.get("pool"), "currency": rates.get("currency", "USD"),
                              "stripe": bool(o.get("stripe")), "stripe_ready": bool(o.get("stripe_ready")),
                              "payouts_live": o.get("payouts_live", True), "storage_share": o.get("storage_share"),
                              "payout_hold_until": o.get("payout_hold_until"),
                              "estimate": d.get("estimate"), "invite": d.get("invite"), "bonus_due": d.get("bonus_due", 0),
                              "online_reward": d.get("online_reward"), "bonus_gb": d.get("bonus_gb", 0),
                              "public_name": o.get("public_name"), "on_board": bool(o.get("on_board")),
                              "ledger": [{k: e.get(k) for k in ("t", "kind", "amount", "period", "status", "detail")}
                                         for e in (d.get("ledger") or [])[:24]],
                              "min_payout": rates.get("min_payout", 5), "credit_bonus": rates.get("credit_bonus", 1.5),
                              "this_node": next((n for n in d.get("nodes", []) if n["id"] == me), None),
                              "nodes": len(d.get("nodes", [])), "dashboard": j["cloud"] + "/dashboard"}
        except Exception:
            out["network"] = None
    return out


def _with_font(page):
    """The page with the Inter typeface built in (uifont.py), so text reads the same on every computer."""
    try:
        import uifont
        return uifont.with_font(page)
    except ImportError:
        return page


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>NodeGuard</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 84 84'%3E%3Crect x='3' y='3' width='78' height='78' rx='18' fill='%23FFFFFF' stroke='%23DCE1DC'/%3E%3Ccircle cx='42' cy='42' r='16.5' fill='none' stroke='%230E1116' stroke-width='4'/%3E%3Cpath fill='%230E1116' d='M42 34a5 5 0 0 1 2.8 9.1L46.6 51h-9.2l1.8-7.9A5 5 0 0 1 42 34z'/%3E%3Ccircle cx='42' cy='14.3' r='3.2' fill='%23C8F374'/%3E%3Ccircle cx='66' cy='28.2' r='3.2' fill='%23C8F374'/%3E%3Ccircle cx='66' cy='55.8' r='3.2' fill='%23C8F374'/%3E%3Ccircle cx='42' cy='69.7' r='3.2' fill='%23C8F374'/%3E%3Ccircle cx='18' cy='55.8' r='3.2' fill='%23C8F374'/%3E%3Ccircle cx='18' cy='28.2' r='3.2' fill='%23C8F374'/%3E%3C/svg%3E">
<style>
:root{--paper:#F5F5F1;--panel:#FFFFFF;--ink:#0E1116;--muted:#4A5058;--line:#DADAD2;--guard:#0E1116;--guard-ink:#FFFFFF;--brass:#5E8C12;--ok:#2E7D4F;--bad:#B3412E;--soft:#E7F6C8;
  --serif:"Inter NG Display","Inter NG","Segoe UI",system-ui,sans-serif;--sans:"Inter NG","Segoe UI",system-ui,-apple-system,Roboto,sans-serif;accent-color:var(--guard)}
@media (prefers-color-scheme:dark){:root{--paper:#0E1116;--panel:#1D2029;--ink:#E4E9E6;--muted:#B8BEC6;--line:#2A2E38;--guard:#C8F374;--guard-ink:#0E1116;--brass:#C8F374;--ok:#5DBB83;--bad:#E07A66;--soft:#26301A}}
*{box-sizing:border-box}html,body{margin:0}body{background:var(--paper);color:var(--ink);font:500 15.5px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
main{max-width:680px;margin:0 auto;padding:28px 18px 48px}
header{display:flex;align-items:center;gap:14px;margin-bottom:6px}
header svg{width:52px;height:52px;flex:none;color:var(--guard)}
h1{font-family:var(--serif);font-weight:700;letter-spacing:-.02em;font-size:28px;margin:0;line-height:1.15}
h2{font-family:var(--serif);font-weight:700;letter-spacing:-.015em;font-size:19px;margin:0 0 4px}
.lead{color:var(--muted);margin:6px 0 18px;max-width:58ch}.muted{color:var(--muted)}.small{font-size:13px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px;margin:14px 0}
.promise{display:grid;gap:8px;margin:12px 0 0;padding:0;list-style:none}.promise li{display:flex;gap:10px;align-items:flex-start;font-size:14px}
.promise svg{width:18px;height:18px;flex:none;margin-top:2px;color:var(--guard)}
label.f{display:block;font-size:13px;color:var(--muted);margin:14px 0 5px}
input[type=text],input[type=email],input[type=password],select,textarea{font:inherit;width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--panel);color:var(--ink)}
textarea{font:12.5px/1.4 ui-monospace,Menlo,Consolas,monospace;height:76px;resize:vertical}
input:focus-visible,select:focus-visible,textarea:focus-visible,button:focus-visible{outline:2px solid var(--guard);outline-offset:2px}
input[type=range]{width:100%}
.check{display:flex;gap:10px;align-items:flex-start;margin-top:14px;font-size:14px}.check input{margin-top:3px}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:4px}
.seg button{border:0;border-radius:0;padding:8px 14px;background:transparent}.seg button.on{background:var(--soft);color:var(--guard);font-weight:600}
button{font:inherit;padding:10px 16px;border-radius:10px;border:1px solid var(--line);background:var(--panel);color:var(--ink);cursor:pointer}
button.primary{background:var(--guard);border-color:var(--guard);color:var(--guard-ink);font-weight:600}
a.btn-link{display:inline-block;font:inherit;padding:10px 16px;border-radius:10px;text-decoration:none;font-weight:600}
a.btn-link.primary{background:var(--guard);color:var(--guard-ink)}
button.quiet{border-color:transparent;background:transparent;color:var(--muted);padding-left:6px;padding-right:6px}
button:disabled{opacity:.6;cursor:default}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.sp{flex:1}
.pay{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:6px}
.pay label{border:1px solid var(--line);border-radius:12px;padding:12px 14px;cursor:pointer;display:block}
.pay label:has(input:checked){border-color:var(--guard);background:var(--soft)}
.pay b{display:block;font-size:14.5px}.pay span{font-size:13px;color:var(--muted)}.pay input{position:absolute;opacity:0}
.status{display:flex;align-items:center;gap:16px}
.status svg{width:76px;height:76px;flex:none;color:var(--guard)}
.status .dot{fill:var(--line);transition:fill .5s}.status.on .dot{fill:var(--brass)}
.status h2{font-size:22px}
.figs{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border:1px solid var(--line);border-radius:12px;margin-top:16px;overflow:hidden}
.fig{padding:12px 14px;border-left:1px solid var(--line)}.fig:first-child{border-left:0}
.fig .k{font-size:12.5px;color:var(--muted)}.fig .v{font-family:var(--serif);font-size:22px;font-weight:600;font-variant-numeric:tabular-nums}
.fig.m .v{color:var(--brass)}
.err{color:var(--bad);font-size:14px;min-height:1.3em;margin-top:8px}
.hide{display:none!important}a{color:var(--guard)}
.upd{border-color:var(--guard);background:var(--soft)}
.progress{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin:6px 0 6px}.progress i{height:5px;border-radius:5px;background:var(--line)}.progress i.on{background:var(--guard)}
h2.big{font-size:26px;line-height:1.2;margin:4px 0 8px}h2.big:focus{outline:none}
.choice{display:grid;gap:12px;margin-top:6px}
.choice label{position:relative;display:block;border:1.5px solid var(--line);border-radius:14px;padding:16px 18px 16px 50px;background:var(--panel);cursor:pointer}
.choice label:has(input:checked){border-color:var(--guard);background:var(--soft)}
.choice input{position:absolute;left:18px;top:20px;width:18px;height:18px}
.choice b{display:block;font-family:var(--serif);font-size:20px;margin-bottom:4px}
.choice .what{display:block;font-size:15px}.choice select{width:auto;display:inline-block;padding:4px 8px;font-size:14px}.choice .when{display:block;font-size:13px;color:var(--muted);margin-top:6px}
.choice .tag{position:absolute;right:14px;top:14px;font-size:12px;font-weight:600;color:var(--brass);background:color-mix(in srgb,var(--brass) 14%,transparent);padding:3px 8px;border-radius:99px}
.code{font:600 26px/1.2 ui-monospace,Menlo,Consolas,monospace;letter-spacing:.14em;padding:10px 14px;border:1px dashed var(--line);border-radius:10px;display:inline-block;background:var(--panel)}
.spin{display:inline-block;width:11px;height:11px;border:2px solid var(--line);border-top-color:var(--guard);border-radius:50%;margin-right:8px;vertical-align:-1px;animation:sp 1s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}@media (prefers-reduced-motion:reduce){.spin{animation:none}}
.signed{display:flex;gap:12px;align-items:center}.signed svg{width:26px;height:26px;color:var(--ok);flex:none}
.outcome{margin:10px 0 2px;padding:12px 14px;border-radius:10px;background:var(--soft);font-size:15px}
.outcome b{font-family:var(--serif);font-size:20px;color:var(--guard)}
.choice .eg{display:block;font-size:13.5px;margin-top:8px;padding-top:8px;border-top:1px dashed var(--line);color:var(--muted)}.choice .eg .n{color:var(--ink);font-weight:600}
.gbhead{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:6px}.gbhead label{font-size:14px;color:var(--muted)}
.gbbig{font-family:var(--serif);font-size:20px}.gbbig b{font-size:30px;font-weight:600}
.presets{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.presets button{padding:6px 12px;font-size:13.5px;border-radius:99px}.presets button.on{border-color:var(--guard);color:var(--guard);background:var(--soft)}
.est{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0 4px}
.est div{flex:1 1 200px;background:var(--soft);border-radius:12px;padding:12px 14px}.est .k{display:block;font-size:13px;color:var(--muted)}
.est .v{display:block;font-family:var(--serif);font-size:26px;font-weight:600;color:var(--guard);margin:2px 0}.est .s{display:block;font-size:13px;color:var(--muted)}
.est p{flex-basis:100%;margin:0;font-size:13px;color:var(--muted)}
.perks{display:flex;flex-wrap:wrap;gap:10px;margin:4px 0 6px}.perks div{flex:1 1 170px;background:var(--soft);border-radius:12px;padding:12px 14px}
.perks b{display:block;font-family:var(--serif);font-size:19px;line-height:1.25;color:var(--guard);margin:2px 0}.perks span{display:block;font-size:13px;color:var(--muted)}
.shares{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.shares a{font-size:14px;padding:7px 14px;border:1px solid var(--line);border-radius:99px;color:var(--ink);text-decoration:none;background:var(--card)}
.shares a:hover,.shares a:focus-visible{border-color:var(--guard);color:var(--guard)}
.miles{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.miles span{font-size:13px;border-radius:99px;padding:4px 11px;border:1px solid var(--line);color:var(--muted)}
.miles span.got{border-color:transparent;background:var(--soft);color:var(--guard)}.miles span.got::before{content:"\2713  "}
.miles span.next{border-style:dashed}
.friends{list-style:none;margin:0;padding:0}.friends .dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--line)}.friends .dot.on{background:var(--guard)}.friends li{padding:8px 0;border-top:1px solid var(--line);font-size:14px}
.friends .fr{display:flex;gap:8px;align-items:center}.friends .fr .sp{flex:1}
.bar{height:6px;background:var(--line);border-radius:99px;overflow:hidden;margin-top:6px}.bar i{display:block;height:100%;background:var(--guard);border-radius:99px;width:0}
.openapp{border-color:var(--guard);background:var(--soft)}
.openapp .row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}.openapp .sp{flex:1;min-width:220px}
details.invite,details.adv{margin-top:14px}details summary{cursor:pointer;color:var(--guard);font-size:14.5px}
details.invite input{margin-top:8px}
@media (max-width:560px){.figs{grid-template-columns:1fr 1fr}.fig:nth-child(3){border-left:0}.fig:nth-child(n+3){border-top:1px solid var(--line)}.pay{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){.status .dot{transition:none}}
</style></head><body><main>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
 <symbol id="seal" viewBox="0 0 84 84"><circle cx="42" cy="42" r="17" fill="none" stroke="currentColor" stroke-width="4"/><path fill="currentColor" d="M42 34a5 5 0 0 1 2.8 9.1L46.6 51h-9.2l1.8-7.9A5 5 0 0 1 42 34z"/></symbol>
 <symbol id="tick" viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
</svg>
<header><svg viewBox="0 0 84 84" aria-hidden="true"><use href="#seal"/><g fill="var(--brass)"><circle cx="42" cy="12" r="4"/><circle cx="68" cy="27" r="4"/><circle cx="68" cy="57" r="4"/><circle cx="42" cy="72" r="4"/><circle cx="16" cy="57" r="4"/><circle cx="16" cy="27" r="4"/></g></svg><div><h1>NodeGuard</h1><div class="muted small" id="netname"></div></div></header>

<div id="upd" class="card upd hide"><div class="row"><div class="sp"><b id="updTitle"></b><div class="muted small" id="updText"></div></div><button class="primary" id="updBtn">Update now</button></div></div>
<div id="setup" class="hide">
 <div class="progress" aria-hidden="true"><i></i><i></i><i></i><i></i></div>
 <p class="muted small" id="stepOf"></p>

 <section id="s1" class="step">
  <h2 class="big">Lend your spare space. Get storage or money back.</h2>
  <p class="lead">NodeGuard keeps people's files on ordinary computers like this one, instead of giant data centres. Set aside some space you aren't using, and you're rewarded for as long as it's shared.</p>
  <div class="card"><h2>Is it safe?</h2>
   <ul class="promise">
    <li><svg><use href="#tick"/></svg><span>Everything stored here is encrypted before it arrives, in small pieces. Nobody can read it on this computer, including you.</span></li>
    <li><svg><use href="#tick"/></svg><span>It only uses the space you choose, and only as much upload speed as you allow.</span></li>
    <li><svg><use href="#tick"/></svg><span>No router or firewall changes. You can pause or stop any time.</span></li>
   </ul></div>
  <div class="row"><button class="primary" data-next="2">Get started</button></div>
 </section>

 <section id="s2" class="step hide">
  <h2 class="big">Your NodeGuard account</h2>
  <div id="acctOut">
   <p class="lead">Sign in, or create a free account. It's where your rewards go, and how you can add more computers later.</p>
   <div class="row"><button class="primary" id="signin">Continue in your browser</button></div>
   <div id="waiting" class="card hide">
    <p style="margin:0">Your browser has opened NodeGuard. Sign in or create your account there, then choose <b>Connect this computer</b>.</p>
    <p class="muted small" style="margin:10px 0 4px">Check the code there matches:</p>
    <div class="code" id="userCode"></div>
    <p class="muted small" style="margin:10px 0 0"><span class="spin" aria-hidden="true"></span>Waiting for you... Browser didn't open? <a id="signinLink" target="_blank" rel="noopener">Open it here</a>.</p>
   </div>
  </div>
  <div id="acctIn" class="hide">
   <div class="card signed"><svg><use href="#tick"/></svg><div><div class="muted small">Signed in as</div><b id="acctEmail"></b></div></div>
   <div class="row"><button class="primary" data-next="3">Continue</button><span class="sp"></span><button class="quiet small" id="otherAcct" type="button">Use a different account</button></div>
  </div>
  <div id="acctLegacy" class="hide">
   <p class="lead">This network doesn't use NodeGuard accounts. Tell it who you are.</p>
   <label class="f" for="name">Your name</label><input type="text" id="name" autocomplete="name">
   <label class="f" for="email">Email</label><input type="email" id="email" autocomplete="email">
   <div class="row" style="margin-top:16px"><button class="primary" id="legacyNext">Continue</button></div>
  </div>
  <div class="err" id="err2"></div>
 </section>

 <section id="s3" class="step hide">
  <h2 class="big">How would you like to be rewarded?</h2>
  <p class="lead">You can change this later in Settings.</p>
  <div class="choice">
   <label><input type="radio" name="payout" value="credit" checked>
    <span class="tag">Best value</span><b>Free NodeGuard storage</b>
    <span class="what">Get <strong>1 GB of storage for every 2 GB</strong> you share, for your own files. Share 2 TB and your 1 TB plan (normally £10 a month) is free.</span>
    <span class="eg">Sharing 1 TB: <span class="n">500 GB of storage</span>, worth £5 a month</span></label>
   <label><input type="radio" name="payout" value="cash">
    <b>Money</b>
    <span class="what"><strong>£1.50 for each TB</strong> you hold for a month, plus £2 for each TB you send to people. Paid monthly to your bank.</span>
    <span class="eg">Sharing 1 TB, once full: <span class="n">£1.50 a month</span>, or £2.25 as a founding machine</span></label>
   <label><input type="radio" name="payout" value="both">
    <b>Both</b>
    <span class="what">Split your space: part earns <strong>storage</strong>, the rest earns <strong>money</strong>.</span>
    <span class="when">Take <select id="share" aria-label="Part taken as storage"><option value="0.25">a quarter</option><option value="0.5" selected>half</option><option value="0.75">three quarters</option></select> as storage, the rest as money.</span></label>
  </div>
  <details class="invite"><summary>Got an invite code from a friend?</summary>
   <input type="text" id="invite" placeholder="NG-ABC234" spellcheck="false" autocomplete="off" aria-label="Invite code">
   <p class="muted small" style="margin:6px 0 0">You both get a bonus once this computer has shared for 30 days.</p></details>
  <div class="row" style="margin-top:18px"><button class="primary" data-next="4">Continue</button><span class="sp"></span><button class="quiet small" data-next="2" type="button">Back</button></div>
 </section>

 <section id="s4" class="step hide">
  <h2 class="big">How much would you like to share?</h2>
  <div class="card">
   <div class="gbhead"><label for="gb">Space to share</label><span class="gbbig"><b id="gbv"></b> GB</span></div>
   <input type="range" id="gb" min="5" max="2000" step="5">
   <div class="presets" id="presets"></div>
   <p class="muted small" id="free" style="margin:4px 0 0"></p>
   <div class="est" id="outcome" aria-live="polite"></div>
   <label class="f" for="mbps">Upload speed limit</label><select id="mbps"></select>
   <label class="f" for="zone">Your city</label><select id="zone"></select>
   <label class="check"><input type="checkbox" id="auto" checked><span>Start when this computer starts (recommended: you're rewarded while it's on)</span></label>
   <details class="adv"><summary>More options</summary>
    <label class="f" for="folder">Folder for the shared space</label><input type="text" id="folder" spellcheck="false">
    <label class="check"><input type="checkbox" id="archive"><span>This is an archive computer: a big but slower disk, for rarely used data (earns at a lower rate).</span></label>
    <div id="joinCard" class="hide"><label class="f" for="join">Join code for a different network</label><textarea id="join" spellcheck="false"></textarea></div>
    <button class="quiet small" id="otherNet" type="button" style="padding-left:0">Joining a network other than NodeGuard?</button>
   </details>
  </div>
  <div class="row"><button class="primary" id="go">Start sharing</button><span class="sp"></span><button class="quiet small" data-next="3" type="button">Back</button></div>
  <div class="err" id="err"></div>
 </section>
</div>

<div id="run" class="hide">
 <div class="card openapp" id="openCard"><div class="row"><div class="sp"><h2 style="margin:0 0 4px">Your files, earnings and invites</h2>
   <p class="muted small" style="margin:0">Everything is in the NodeGuard app, on this computer, your phone and the web. This window just looks after this computer's sharing.</p></div>
   <button class="primary" id="openApp2">Open NodeGuard</button></div></div>
 <div class="card" id="folderCard"><div class="row"><div class="sp"><h2 style="margin:0 0 4px" id="folderTitle">Back up a folder</h2>
   <p class="muted small" style="margin:0" id="folderSub">Keep a folder on this computer backed up to NodeGuard by itself, like Dropbox. Files are encrypted here first.</p></div>
   <button id="folderBtn">Set up</button></div></div>
 <div class="card">
  <div class="status" id="st"><svg viewBox="0 0 84 84" aria-hidden="true"><use href="#seal"/>
    <circle class="dot" cx="42" cy="12" r="3.6"/><circle class="dot" cx="68" cy="27" r="3.6"/><circle class="dot" cx="68" cy="57" r="3.6"/>
    <circle class="dot" cx="42" cy="72" r="3.6"/><circle class="dot" cx="16" cy="57" r="3.6"/><circle class="dot" cx="16" cy="27" r="3.6"/></svg>
   <div class="sp"><h2 id="stText"></h2><div class="muted small" id="stSub"></div></div>
   <button id="toggle"></button></div>
  <div class="err" id="runErr"></div>
  <div class="figs" id="figs"></div>
  <div class="miles" id="miles"></div></div>
 <div class="card" id="inviteCard"><h2>Invite friends, earn more</h2>
  <div class="perks" id="perks"></div>
  <label class="f" for="inviteLink">Your invite link</label>
  <div class="row"><input type="text" id="inviteLink" readonly style="flex:1;min-width:220px"><button id="copyInvite">Copy</button></div>
  <div class="shares" id="shares"></div>
  <p class="muted small" style="margin:10px 0 0">Or they can type your code <code id="inviteCode"></code> when they set up NodeGuard.</p>
  <div id="friendsBox" class="hide"><h3 class="small" style="margin:16px 0 6px">Your friends</h3><ul id="friends" class="friends"></ul></div>
  <p class="small" id="inviteEarned" style="margin:12px 0 0"></p></div>
 <div class="card"><h2>What you've earned</h2><div class="figs" id="earn"></div><p class="muted small" id="earnNote"></p>
  <p id="estimate" class="small" style="margin:12px 0 0"></p>
  <div id="onlineBox" class="hide" style="margin-top:14px;border-top:1px solid var(--line);padding-top:14px">
   <div class="row"><b class="sp" id="onlineTitle"></b><span class="muted small" id="onlineDays"></span></div>
   <div class="bar"><i id="onlineBar"></i></div><p class="muted small" id="onlineText" style="margin:6px 0 0"></p></div>
  <div id="payBox" class="hide" style="margin-top:14px;border-top:1px solid var(--line);padding-top:14px">
   <div class="row"><div class="sp"><b id="payTitle"></b><div class="muted small" id="payText"></div></div><button class="primary" id="payBtn">Set up payouts</button></div></div>
  <details id="histBox" class="hide" style="margin-top:14px"><summary>Month by month</summary><table id="hist" class="small" style="width:100%;border-collapse:collapse;margin-top:8px"></table></details></div>
 <div class="card" id="linkCard"><h2 id="linkTitle">Earn NodeGuard storage</h2>
  <div id="linkedYes" class="hide"><p class="muted" style="margin:0">Linked to <b id="linkedTo"></b>. While this computer shares space and stays online, that account gets extra storage: about 1 GB for every 2 GB shared. You can see it in NodeGuard, under Settings.</p></div>
  <div id="linkedEmail" class="hide"><p class="muted" style="margin:0">The storage you earn goes to your NodeGuard account for <b id="linkEmailTo"></b>: about 1 GB for every 2 GB shared, while this computer stays online. Sign in to NodeGuard with that email to use it (new accounts are free).</p>
   <div class="row" style="margin-top:12px"><a class="btn-link primary" id="openApp" target="_blank" rel="noopener">Open NodeGuard</a><span class="sp"></span><button class="quiet small" type="button" id="useCode">Use a different account</button></div></div>
  <div id="linkedNo"><p class="muted" style="margin:0">Use what you share to get more NodeGuard storage. In NodeGuard, open Settings, then Earn storage, and choose <b>Get a link code</b>. Paste it here.</p>
   <div class="row" style="margin-top:12px"><input type="text" id="lcode" placeholder="NGL-ABCD-EFGH" spellcheck="false" style="flex:1;min-width:200px"><button id="linkBtn">Link</button></div></div></div>
 <div class="card"><h2>Settings</h2>
  <p class="muted small" id="acctLine" style="margin:0 0 4px"></p>
  <label class="f">Rewarded with</label>
  <div class="seg" role="radiogroup" aria-label="Rewarded with"><button type="button" data-pay="credit">Storage</button><button type="button" data-pay="cash">Money</button><button type="button" data-pay="both">Both</button></div>
  <div id="shareRow" class="hide muted small" style="margin-top:6px">Take <select id="share2" style="width:auto;display:inline-block;padding:4px 8px"><option value="0.25">a quarter</option><option value="0.5">half</option><option value="0.75">three quarters</option></select> as storage, the rest as money.</div>
  <label class="f" for="gb2">Space: <b id="gbv2"></b> GB</label><input type="range" id="gb2" min="5" max="2000" step="5">
  <label class="f" for="mbps2">Upload speed limit</label><select id="mbps2"></select>
  <label class="f" for="hours2">When to share</label><select id="hours2"></select>
  <label class="check"><input type="checkbox" id="batt2"><span>Rest while this computer is on battery</span></label>
  <p class="muted small" style="margin:2px 0 8px">Resting keeps this computer online, so it still counts as reliable, but it gets no new data and sends slowly (1 Mbit/s).</p>
  <label class="check"><input type="checkbox" id="auto2"><span>Start when this computer starts</span></label>
  <label class="check"><input type="checkbox" id="board"><span>Show me on the public leaderboard at nodeguard.co.uk/live <span class="muted">(only a nickname, your city and the space you share)</span></span></label>
  <div id="boardRow" class="hide row" style="margin:4px 0 6px 30px"><input type="text" id="nick" maxlength="24" placeholder="Nickname, e.g. DiskDave" style="flex:1;min-width:180px"><button type="button" id="nickSave">Save nickname</button></div>
  <label class="check" id="autoUpdRow"><input type="checkbox" id="autoUpd"><span>Install updates by themselves (recommended) <span class="muted" id="verLine"></span></span></label>
  <div class="row" style="margin-top:16px"><button id="save">Save</button><span class="sp"></span><button class="quiet" id="reset">Change network or folder</button><button class="quiet" id="quit">Quit</button><button class="quiet hide" id="signout">Sign out</button></div>
  <p class="muted small" id="where"></p></div>
</div>
</main>
<script>
"use strict";
const T = "__TOKEN__", $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtB = n => { n = +n || 0; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1000 && i < 4) { n /= 1000; i++; } return (i ? n.toFixed(n >= 100 ? 0 : 1) : n) + " " + u[i]; };
let S = null, mode = "new";
const UI = {};
const sym = () => ({ USD: "$", GBP: "£", EUR: "€" }[(S && S.network && S.network.currency) || "GBP"] || "");
const money = v => { v = +v || 0; return sym() + v.toFixed(v > 0 && v < 1 ? 3 : 2); };
const speedName = m => +m ? m + " Mbit/s" : "No limit";
const hourRange = h => { const [a, b] = String(h).split("-").map(Number), t = x => x === 0 ? "midnight" : x === 12 ? "midday" : x < 12 ? x + "am" : (x - 12) + "pm"; return `${t(a)} to ${t(b)}`; };
const hourName = h => !h ? "All the time" : ({ "22-7": "Only at night", "18-8": "Evenings and nights", "9-17": "Working hours" }[h] || "Custom") + ` (${hourRange(h)})`;
const post = (p, b) => fetch(p, { method: "POST", headers: { "Content-Type": "application/json", "X-App-Token": T }, body: JSON.stringify(b || {}) })
  .then(async r => { const j = await r.json(); if (!r.ok) throw new Error(j.error); return j; });
const fig = (k, v, cls = "") => `<div class="fig ${cls}"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`;
function ago(s) { s = +s || 0; return s < 120 ? "just now" : s < 7200 ? Math.round(s / 60) + " min" : s < 172800 ? Math.round(s / 3600) + " hours" : Math.round(s / 86400) + " days"; }
async function load() {
  const resp = await fetch("/api/status");
  if (resp.status === 401) return location.reload();
  S = await resp.json();
  $("#netname").textContent = S.network_name && S.network_name !== "NodeGuard" ? `Sharing space on the ${S.network_name} network` : "Sharing this computer's spare space";
  if (S.headless) {          // a NAS or Raspberry Pi: always on, started by its service
    document.querySelectorAll("#auto, #auto2").forEach(x => x.closest("label").classList.add("hide"));
    $("#quit").classList.add("hide"); $("#signout").classList.remove("hide");
  }
  const U = S.update;
  $("#upd").classList.toggle("hide", !(U && (U.available || U.busy)));
  if (U && (U.available || U.busy)) {
    $("#updTitle").textContent = U.busy ? "Updating NodeGuard Node..." : "A new version of NodeGuard Node is ready";
    $("#updText").textContent = U.busy ? "It closes and opens again by itself in a moment." : `Version ${U.available} (you have ${U.current}). It takes a few seconds and carries on sharing afterwards.`;
    $("#updBtn").classList.toggle("hide", !!U.busy);
  }
  $("#autoUpdRow").classList.toggle("hide", !(U && U.can_update));
  if (U && U.current) $("#verLine").textContent = `(you have version ${U.current})`;
  if (document.activeElement !== $("#autoUpd")) $("#autoUpd").checked = S.auto_update !== false;
  const speeds = S.speeds.map(m => `<option value="${m}">${speedName(m)}</option>`).join("");
  if (!S.configured) {
    const first = $("#setup").classList.contains("hide");
    $("#setup").classList.remove("hide"); $("#run").classList.add("hide");
    if (!UI.showJoin) $("#joinCard").classList.toggle("hide", S.built_in);
    if (!S.built_in) $("details.adv").open = true;     // another network: its join code is needed
    if (first) showStep(UI.step || 1);
    if (!$("#folder").value) {
      $("#folder").value = S.default_folder;
      $("#zone").innerHTML = S.cities.map(c => `<option value="${c}">${c.replace(/-/g, " ").replace(/\b\w/g, x => x.toUpperCase())}</option>`).join("");
      $("#mbps").innerHTML = speeds; $("#mbps").value = "10";
      const max = Math.max(10, Math.floor(S.disk_free_gb * 0.8 / 5) * 5);
      $("#gb").max = max; $("#gb").value = Math.min(100, max); $("#gbv").textContent = $("#gb").value;
      $("#free").textContent = `${S.disk_free_gb} GB free on this disk. Choose space you won't need: you can change it later.`;
      presets(max);
      document.querySelectorAll("input[name=payout]").forEach(r => r.onchange = outcome);
      $("#share").onchange = () => { document.querySelector("input[name=payout][value=both]").checked = true; outcome(); };
    }
    return;
  }
  $("#setup").classList.add("hide"); $("#run").classList.remove("hide");
  const L = S.local || {}, N = S.network || {}, me = N.this_node, on = S.running;
  $("#st").classList.toggle("on", on);
  $("#stText").textContent = on ? (S.resting ? "Resting" : "Sharing") : S.paused ? "Paused" : "Not sharing";
  $("#stSub").textContent = on && S.resting ? (S.resting === "on battery" ? "On battery, so it's resting: still online, but taking no new data and sending slowly. It shares fully again when you plug in."
      : `Outside your sharing hours (${hourRange(S.config.hours)}), so it's resting: still online, but taking no new data and sending slowly.`) :
    on ? ((L.uptime_s || 0) < 120 ? "Just started storing data for the network" : `Storing data for the network for ${ago(L.uptime_s)}`) +
      (N.nodes > 1 ? `, one of ${N.nodes} machines you run` : "") :
    S.paused ? "Nothing is being stored or sent until you resume." : "Trying to connect...";
  $("#toggle").textContent = on ? "Pause" : "Resume"; $("#toggle").className = on ? "" : "primary";
  $("#runErr").textContent = S.error || "";
  $("#figs").innerHTML = fig("Storing", fmtB(L.used)) + fig("Pieces", (L.shards ?? 0).toLocaleString()) + fig("Sent to others", fmtB(L.served)) +
    fig("Reliability", me && me.score != null ? Math.round(me.score) + "/100" : "New");
  if (me) {       // milestones: what this machine has done, and the next one to aim for
    const held = me.stored || 0, days = me.age_days || 0, friends = ((N.invite || {}).friends || []).length;
    const M = [[me.join_rank && me.join_rank <= 50, `Founding machine #${me.join_rank}`, true],
      [days >= 1, "First day online"], [days >= 7, "A week online"], [days >= 30, "A month online"], [days >= 90, "Three months online"],
      [held >= 1e9, "Holding 1 GB for others"], [held >= 10e9, "Holding 10 GB"], [held >= 100e9, "Holding 100 GB"],
      [friends >= 1, "First friend joined"], [friends >= 5, "Five friends joined"]];
    const got = M.filter(m => m[0]), next = M.filter(m => !m[0] && !m[2]).slice(0, 2);
    $("#miles").innerHTML = got.map(m => `<span class="got">${esc(m[1])}</span>`).join("") + next.map(m => `<span class="next" title="Next milestone">Next: ${esc(m[1])}</span>`).join("");
  }
  const t = N.totals, vetted = N.pool === "vetted-b2b", credit = N.payout === "credit";
  const storeGb = Math.round((+S.config.gb || 0) * 0.5);
  $("#earn").innerHTML = credit ? fig("Storage you get", storeGb >= 1000 ? (storeGb / 1000).toFixed(1) + " TB" : storeGb + " GB", "m") + fig("You share", S.config.gb + " GB") +
      fig("Data you hold", fmtB(t ? t.stored : 0)) + fig("Delivered", fmtB(t ? t.egress : 0)) :
    t ? (N.payout === "both" ? fig("Storage you get", Math.round((+S.config.gb || 0) * 0.5 * (N.storage_share || 0.5)) + " GB", "m") : "") + fig("Earned", money(t.earned), "m") +
    (vetted ? "" : fig("Held back for now", money(t.held), "m")) + fig("Data you hold", fmtB(t.stored)) + fig("Delivered", fmtB(t.egress)) : fig("Earned", "Not yet");
  $("#earnNote").textContent = !S.network ? "Can't reach the network right now; this computer keeps trying by itself." :
    (credit ? "You get about 1 GB of NodeGuard storage for every 2 GB you share, while this computer stays online (more if it's always on, less if it's often off). It starts from its first full day." :
     vetted ? "Vetted partner: invoiced monthly and paid by bank transfer." : `Paid monthly through Stripe once you've earned ${money(N.min_payout)}.`) +
    (vetted || credit ? "" : " New machines have part of their pay held back for their first 6 months, released as they prove reliable.");
  if (!document.activeElement || !document.activeElement.closest("#run .card:last-child")) {
    $("#mbps2").innerHTML = speeds; $("#mbps2").value = String(S.config.mbps || 0);
    const hrs = [...new Set((S.hours_choices || [""]).concat([S.config.hours || ""]))];
    $("#hours2").innerHTML = hrs.map(h => `<option value="${esc(h)}">${esc(hourName(h))}</option>`).join(""); $("#hours2").value = S.config.hours || "";
    $("#batt2").checked = S.config.battery !== false;
    $("#gb2").max = Math.max(+S.config.gb, Math.floor((S.disk_free_gb + (L.used || 0) / 1e9) * 0.9 / 5) * 5);
    $("#gb2").value = S.config.gb; $("#gbv2").textContent = S.config.gb; $("#auto2").checked = !!S.config.autostart;
  }
  const E = N.estimate;
  const stGb = (+S.config.gb || 0) / 2;
  $("#estimate").textContent = credit ? `Sharing ${S.config.gb} GB earns about ${stGb >= 1000 ? (stGb / 1000).toFixed(1) + " TB" : Math.round(stGb) + " GB"} of NodeGuard storage while this computer stays online, worth about £${(stGb / 100).toFixed(2)} a month at our prices.` :
    !E ? "" : E.month_full < 0.01 ? "" :
    `At today's rates: about ${money(E.month_now)} a month for what this computer holds now, and up to ${money(E.month_full)} a month once your ${S.config.gb} GB fills up. ` +
    `How fast it fills depends on how much people store.` + (credit ? ` Taken as storage, that's worth ${N.credit_bonus || 1.5} times as much.` : "");
  const cash = !credit && !vetted && S.network;
  $("#payBox").classList.toggle("hide", !cash);
  if (cash && N.payouts_live === false) {
    $("#payTitle").textContent = "Money payouts start later in the beta";
    $("#payText").textContent = "Everything you earn is counted from today, and paid to your bank once payouts switch on. We'll email you when it's time to add your details.";
    $("#payBtn").classList.add("hide");
  } else if (cash) {
    const held = N.payout_hold_until && N.payout_hold_until * 1000 > Date.now();
    $("#payTitle").textContent = held ? "Payouts paused for a safety check" : N.stripe_ready ? "Payouts are set up" : "Set up payouts";
    $("#payText").textContent = held ? `Your payout details were changed, so payouts wait until ${new Date(N.payout_hold_until * 1000).toLocaleDateString()}. If you didn't change them, email NodeGuard straight away.` :
      N.stripe_ready ? "Each month's earnings go to your bank automatically, through Stripe, once they reach " + money(N.min_payout) + "." :
      "To be paid in money, give Stripe your bank details (NodeGuard never sees them). Until then, what you earn is kept for you.";
    $("#payBtn").classList.toggle("hide", !!N.stripe_ready);
    $("#payBtn").textContent = N.stripe ? "Finish setting up payouts" : "Set up payouts";
  }
  const kinds = { cash: "Money", credit: "NodeGuard storage", invoice: "Invoice", bonus: "Bonus", "bonus-storage": "Invite storage", forfeit: "Held-back pay lost" };
  const states = { paid: "Paid to your bank", due: "Being paid", "awaiting-onboarding": "Waiting for your payout details", failed: "Waiting for your payout details", held: "Paused for a safety check",
    applied: "Added to your storage", "next-payout": "Comes with your next payout", included: "Included in that payout", forfeited: "Lost: a machine kept losing data" };
  const hist = (N.ledger || []);
  $("#histBox").classList.toggle("hide", !hist.length);
  $("#hist").innerHTML = hist.map(e => `<tr style="border-top:1px solid var(--line)"><td style="padding:6px 6px 6px 0">${esc(e.period || new Date(e.t * 1000).toISOString().slice(0, 7))}</td>` +
    `<td>${esc(kinds[e.kind] || e.kind)}</td><td style="text-align:right;font-variant-numeric:tabular-nums">${e.kind === "bonus-storage" ? Math.round(e.amount) + " GB" : money(e.amount)}</td><td class="muted" style="padding-left:10px">${esc(states[e.status] || e.status)}</td></tr>`).join("");
  const I = N.invite;
  $("#inviteCard").classList.toggle("hide", !I);
  if (I) {
    const storageSide = credit, gb = g => g >= 1000 ? (g / 1000).toFixed(1) + " TB" : Math.round(g) + " GB";
    $("#perks").innerHTML =
      `<div><span>A friend shares space</span><b>${storageSide ? gb(I.storage_gb) + " each" : money(I.bonus).replace(/\.00$/, "") + " each"}</b><span>once they've been online ${I.days} days</span></div>` +
      (I.share ? `<div><span>Plus, from us</span><b>${Math.round(I.share * 100)}% of what they earn</b><span>for ${I.share_months} months, on top of their pay</span></div>` : "") +
      (I.customer_share ? `<div><span>Bring a paying customer</span><b>${Math.round(I.customer_share * 100)}% of what they pay</b><span>for their first ${I.customer_months === 12 ? "year" : I.customer_months + " months"}</span></div>` : "");
    if (document.activeElement !== $("#inviteLink")) $("#inviteLink").value = I.link || "";
    $("#inviteCode").textContent = I.code;
    const msg = `I'm sharing spare disk space on NodeGuard, a UK network for safe, encrypted storage. Join with my link and we both get a bonus once you've been sharing for a month: ${I.link}`;
    const u = encodeURIComponent;
    $("#shares").innerHTML = [["WhatsApp", `https://wa.me/?text=${u(msg)}`], ["Email", `mailto:?subject=${u("Join me on NodeGuard")}&body=${u(msg)}`],
      ["X", `https://twitter.com/intent/tweet?text=${u(msg)}`], ["Reddit", `https://www.reddit.com/submit?url=${u(I.link)}&title=${u("Share spare disk space and earn storage or money: NodeGuard beta (UK)")}`],
      ["Facebook", `https://www.facebook.com/sharer/sharer.php?u=${u(I.link)}`]].map(([n, h]) => `<a href="${esc(h)}" target="_blank" rel="noopener">${n}</a>`).join("");
    $("#friendsBox").classList.toggle("hide", !I.friends.length);
    $("#friends").innerHTML = I.friends.map(f => {
      const days = Math.min(I.days, Math.floor((Date.now() / 1000 - f.joined) / 86400));
      const text = f.state === "paid" ? "Bonus earned" : f.state === "same home" ? "Same home as you, so no bonus" : !f.machines ? "Hasn't started sharing yet" : `Day ${days} of ${I.days}${f.online ? "" : ", offline right now"}`;
      return `<li><div class="fr"><span class="dot ${f.online ? "on" : ""}"></span><b>${esc(f.name || "A friend")}</b><span class="sp"></span><span class="muted">${esc(text)}</span></div>` +
        (f.state === "waiting" && f.machines ? `<div class="bar"><i style="width:${Math.round(days * 100 / I.days)}%"></i></div>` : "") + `</li>`;
    }).join("");
    const parts = [];
    if (I.earned) parts.push(money(I.earned) + " in invite bonuses");
    if (I.earned_gb) parts.push(gb(I.earned_gb) + " of storage");
    if (I.earned_share) parts.push(money(I.earned_share) + " from friends' earnings");
    if (I.earned_customers) parts.push(money(I.earned_customers) + " from customers you brought");
    $("#inviteEarned").textContent = parts.length ? "From invites so far: " + parts.join(", ") + "." : I.friends.length ? "" : "Share your link: most people join because a friend asked them.";
  }
  if (document.activeElement !== $("#nick") && document.activeElement !== $("#board")) {
    $("#board").checked = !!N.on_board; if (N.public_name) $("#nick").value = N.public_name;
    $("#boardRow").classList.toggle("hide", !N.on_board && !UI.nickOpen);
  }
  if (UI.justSetUp && S.running && S.app_url) { UI.justSetUp = false; post("/api/open-app").then(r => { if (r.url) window.open(r.url, "_blank", "noopener"); }).catch(() => {}); }
  $("#openCard").classList.toggle("hide", !S.app_url);
  const FB = S.folder_backup;
  $("#folderCard").classList.toggle("hide", !FB || !S.account || !S.account.available);
  if (FB) {
    const where = FB.folder ? FB.folder.split(/[\\/]/).filter(Boolean).pop() : "";
    const drive = FB.configured ? FB.mode === "drive" : FB.drive_available;
    $("#folderTitle").textContent = drive ? "NodeGuard Drive" : "Back up a folder";
    $("#folderSub").textContent = !FB.configured ? (drive ? "See all your NodeGuard files in File Explorer. They download only when you open them, so they don't fill up this computer."
        : "Keep a folder on this computer backed up to NodeGuard by itself, like Dropbox. Files are encrypted here first.")
      : FB.paused ? (drive ? "NodeGuard Drive is paused." : `Backing up "${where}" is paused.`)
      : FB.unlocked === false ? (drive ? "NodeGuard Drive is set up. Open it and enter your passphrase to carry on." : `"${where}" is set up. Open it and enter your passphrase to carry on backing up.`)
      : drive ? `Your files are in File Explorer, under NodeGuard Drive.${FB.drive && FB.drive.cloud != null ? ` ${FB.drive.here} on this computer, ${FB.drive.cloud} only in NodeGuard.` : ""}`
      : `Backing up "${where}". Anything you put in it is saved to NodeGuard.`;
    $("#folderBtn").textContent = FB.configured ? "Open" : "Set up";
  }
  const OR = N.online_reward;
  $("#onlineBox").classList.toggle("hide", !OR || !OR.eligible);
  if (OR && OR.eligible) {
    const pctDone = Math.min(100, Math.round(OR.online_days * 100 / OR.need_days));
    $("#onlineTitle").textContent = `Founding node: ${money(OR.amount).replace(/\.00$/, "")} this month for staying online`;
    $("#onlineDays").textContent = `${Math.min(OR.online_days, OR.need_days)} of ${OR.need_days} days`;
    $("#onlineBar").style.width = pctDone + "%";
    $("#onlineText").textContent = !OR.big_enough ? `Share at least ${OR.min_gb} GB to qualify (in Settings below).` :
      pctDone >= 100 ? "Done for this month: it comes with your next payout." : `Keep this computer on: it needs to be online about ${OR.need_days} days this month. For the first ${OR.first} machines, for ${OR.months} months.`;
  }
  $("#linkTitle").textContent = credit || S.config.linked ? "Your NodeGuard storage" : "Rather have storage than money?";
  const byEmail = !S.config.linked && S.config.payout === "credit" && S.config.email && !UI.useCode;
  $("#linkedYes").classList.toggle("hide", !S.config.linked); $("#linkedNo").classList.toggle("hide", !!S.config.linked || !!byEmail);
  $("#linkedEmail").classList.toggle("hide", !byEmail);
  if (byEmail) {
    $("#linkEmailTo").textContent = S.config.email;
    $("#openApp").classList.toggle("hide", !S.app_url); if (S.app_url) $("#openApp").href = S.app_url;
  }
  if (S.config.linked) $("#linkedTo").textContent = S.config.linked;
  const payNow = S.network && S.network.payout ? S.network.payout : (S.config.payout || "credit");
  document.querySelectorAll("[data-pay]").forEach(b => b.classList.toggle("on", b.dataset.pay === payNow));
  $("#shareRow").classList.toggle("hide", payNow !== "both");
  if (payNow === "both" && document.activeElement !== $("#share2")) $("#share2").value = String((S.network && S.network.storage_share) || S.config.share || 0.5);
  $("#acctLine").textContent = S.config.email ? `Signed in as ${S.config.email}` : "";
  $("#where").textContent = `Folder: ${S.config.folder} · City: ${S.config.zone}${S.config.tier === "cold" ? " · Archive computer" : ""}`;
}
$("#gb").oninput = () => { $("#gbv").textContent = $("#gb").value; outcome(); };
$("#useCode").onclick = () => { UI.useCode = true; $("#linkedEmail").classList.add("hide"); $("#linkedNo").classList.remove("hide"); $("#lcode").focus(); };
$("#otherNet").onclick = () => { UI.showJoin = true; $("#joinCard").classList.remove("hide"); $("#join").focus(); };
$("#gb2").oninput = () => $("#gbv2").textContent = $("#gb2").value;
// ---------- first-time setup, one step at a time ----------
UI.step = 1;
function showStep(n) {
  UI.step = n;
  [1, 2, 3, 4].forEach(i => $("#s" + i).classList.toggle("hide", i !== n));
  document.querySelectorAll(".progress i").forEach((x, i) => x.classList.toggle("on", i < n));
  $("#stepOf").textContent = `Step ${n} of 4`;
  if (n === 2) showAccount();
  if (n === 4) outcome();
  const h = $("#s" + n + " h2"); if (h) { h.setAttribute("tabindex", "-1"); h.focus(); }
}
document.querySelectorAll("[data-next]").forEach(b => b.onclick = () => showStep(+b.dataset.next));
function showAccount() {
  const a = S.account || {};
  $("#err2").textContent = "";
  $("#acctLegacy").classList.toggle("hide", !!a.available);
  $("#acctOut").classList.toggle("hide", !a.available || !!a.email);
  $("#acctIn").classList.toggle("hide", !a.available || !a.email);
  if (a.email) $("#acctEmail").textContent = a.email;
}
async function pollSignin() {
  clearTimeout(UI.pollT);
  try {
    const r = await post("/api/signin/status");
    if (r.state === "done") { $("#waiting").classList.add("hide"); await load(); showStep(2); return; }
    if (r.state === "expired") { $("#waiting").classList.add("hide"); $("#err2").textContent = "That sign-in timed out. Press Continue in your browser to try again."; return; }
  } catch (e) { /* keep waiting */ }
  UI.pollT = setTimeout(pollSignin, 2000);
}
$("#signin").onclick = async () => {
  $("#err2").textContent = ""; $("#signin").disabled = true;
  try {
    const r = await post("/api/signin/start");
    $("#userCode").textContent = r.user_code; $("#signinLink").href = r.url; $("#waiting").classList.remove("hide");
    if (S.headless) window.open(r.url, "_blank", "noopener");
    pollSignin();
  } catch (e) { $("#err2").textContent = e.message; }
  $("#signin").disabled = false;
};
$("#otherAcct").onclick = async () => { await post("/api/signout"); await load(); showStep(2); };
$("#legacyNext").onclick = () => {
  if (!$("#name").value.trim() || !/@/.test($("#email").value)) return $("#err2").textContent = "Enter your name and email.";
  showStep(3);
};
function outcome() {
  const gb = +$("#gb").value, pay = (document.querySelector("input[name=payout]:checked") || {}).value || "credit", sh = pay === "both" ? +$("#share").value : pay === "credit" ? 1 : 0;
  const size = g => g >= 1000 ? (g / 1000).toFixed(g % 1000 ? 1 : 0) + " TB" : Math.round(g) + " GB";
  const gbp = v => "£" + (v >= 10 ? v.toFixed(0) : v.toFixed(2));
  const store = gb * sh / 2, cashGb = gb * (1 - sh), month = cashGb / 1000 * 1.5;
  let html = "";
  if (sh > 0) html += `<div><span class="k">Storage for your files</span><span class="v">${size(store)}</span><span class="s">worth ${gbp(store / 1000 * 10)} a month at our prices</span></div>`;
  if (sh < 1) html += `<div><span class="k">Money, once your space fills</span><span class="v">${gbp(month)}<small style="font-size:15px"> a month</small></span><span class="s">${gbp(month * 12)} a year, or ${gbp(month * 1.5)} a month as a founding machine</span></div>`;
  html += `<p>${sh > 0 ? "Storage counts from this computer's first full day online, while it stays on. " : ""}${sh < 1 ? "Money grows as people store more and fill your space, plus £2 for each TB you send." : ""}</p>`;
  $("#outcome").innerHTML = html;
  document.querySelectorAll("#presets button").forEach(b => b.classList.toggle("on", +b.dataset.gb === gb));
}
function presets(max) {
  $("#presets").innerHTML = [100, 250, 500, 1000, 2000, 4000].filter(g => g <= max).map(g => `<button type="button" data-gb="${g}">${g >= 1000 ? g / 1000 + " TB" : g + " GB"}</button>`).join("");
  document.querySelectorAll("#presets button").forEach(b => b.onclick = () => { $("#gb").value = b.dataset.gb; $("#gbv").textContent = b.dataset.gb; outcome(); });
}
$("#go").onclick = async () => {
  $("#err").textContent = ""; $("#go").disabled = true; $("#go").textContent = "Connecting...";
  const a = S.account || {};
  try {
    UI.justSetUp = true;
    await post("/api/setup", { join: $("#join").value.trim(), mode: a.available ? "account" : "new", name: $("#name").value.trim(), email: $("#email").value.trim(),
      invite: $("#invite").value.trim(), share: +$("#share").value,
      payout: document.querySelector("input[name=payout]:checked").value, folder: $("#folder").value.trim(), gb: +$("#gb").value, mbps: +$("#mbps").value,
      zone: $("#zone").value, tier: $("#archive").checked ? "cold" : "hot", autostart: $("#auto").checked });
    await load();
  } catch (e) { $("#err").textContent = e.message; }
  $("#go").disabled = false; $("#go").textContent = "Start sharing";
};
$("#openApp2").onclick = async () => {
  try { const r = await post("/api/open-app"); if (r.url) window.open(r.url, "_blank", "noopener"); } catch (e) { $("#runErr").textContent = e.message; }
};
$("#toggle").onclick = async () => { $("#toggle").disabled = true; try { await post(S.running ? "/api/stop" : "/api/start"); } catch (e) { $("#runErr").textContent = e.message; } $("#toggle").disabled = false; load(); };
$("#linkBtn").onclick = async () => { $("#runErr").textContent = ""; $("#linkBtn").disabled = true;
  try { const r = await post("/api/link", { code: $("#lcode").value }); $("#lcode").value = ""; await load(); } catch (e) { $("#runErr").textContent = e.message; }
  $("#linkBtn").disabled = false; };
document.querySelectorAll("[data-pay]").forEach(b => b.onclick = async () => {
  if (b.classList.contains("on")) return;
  const to = b.dataset.pay;
  if (!confirm(to === "cash" ? "Switch to money? From now on your computers earn money instead of NodeGuard storage." :
      to === "both" ? "Switch to both? From now on half of what you share earns storage and half earns money (you can change the split)." :
      "Switch to NodeGuard storage? From now on your computers earn storage instead of money.")) return;
  try { await post("/api/payout", { payout: to, share: 0.5 }); } catch (e) { $("#runErr").textContent = e.message; }
  load();
});
$("#updBtn").onclick = async () => { $("#updBtn").disabled = true; try { await post("/api/update/install"); } catch (e) { $("#updText").textContent = e.message; } $("#updBtn").disabled = false; load(); };
$("#autoUpd").onchange = e => post("/api/update/auto", { on: e.target.checked }).catch(() => {});
$("#share2").onchange = async e => { try { await post("/api/payout", { payout: "both", share: +e.target.value }); } catch (err) { $("#runErr").textContent = err.message; } load(); };
$("#folderBtn").onclick = async () => { try { const r = await post("/api/folder-backup"); if (r.url) window.open(r.url, "_blank", "noopener"); } catch (e) { $("#runErr").textContent = e.message; } };
$("#save").onclick = async () => { try { await post("/api/settings", { gb: +$("#gb2").value, mbps: +$("#mbps2").value, hours: $("#hours2").value, battery: $("#batt2").checked, autostart: $("#auto2").checked }); $("#save").textContent = "Saved"; setTimeout(() => $("#save").textContent = "Save", 1500); } catch (e) { $("#runErr").textContent = e.message; } load(); };
$("#reset").onclick = async () => { if (confirm("Stop sharing and change the network or folder? What's stored is kept until you delete the folder.")) { await post("/api/reset"); location.reload(); } };
$("#quit").onclick = async () => { if (!confirm("Quit NodeGuard Node? This computer stops sharing until you open it again" + (S.config.autostart ? " or restart the computer." : "."))) return;
  await post("/api/quit").catch(() => {}); document.querySelector("main").innerHTML = `<header><h1>NodeGuard Node has quit</h1></header><p class="lead">You can close this window.</p>`; };
$("#payBtn").onclick = async () => {
  $("#payBtn").disabled = true; $("#runErr").textContent = "";
  try { const r = await post("/api/payout-setup"); window.open(r.url, "_blank", "noopener"); $("#payText").textContent = "Stripe opened in a new tab. Come back here when you've finished."; }
  catch (e) { $("#runErr").textContent = e.message; }
  $("#payBtn").disabled = false;
};
$("#board").onchange = async e => {
  $("#runErr").textContent = "";
  $("#boardRow").classList.toggle("hide", !e.target.checked && !$("#nick").value);
  if (e.target.checked && !$("#nick").value.trim()) { UI.nickOpen = true; $("#boardRow").classList.remove("hide"); $("#nick").focus(); e.target.checked = false; return; }
  try { await post("/api/profile", { on_board: e.target.checked }); } catch (err) { $("#runErr").textContent = err.message; e.target.checked = !e.target.checked; }
  load();
};
$("#nick").onfocus = () => { UI.nickOpen = true; };
$("#nickSave").onclick = async () => {
  $("#runErr").textContent = "";
  try { await post("/api/profile", { public_name: $("#nick").value.trim(), on_board: true }); $("#nickSave").textContent = "Saved"; setTimeout(() => $("#nickSave").textContent = "Save nickname", 1500); }
  catch (err) { $("#runErr").textContent = err.message; }
  load();
};
$("#copyInvite").onclick = async () => { try { await navigator.clipboard.writeText($("#inviteLink").value || $("#inviteCode").textContent); $("#copyInvite").textContent = "Copied"; } catch (e) { $("#copyInvite").textContent = "Select and copy it"; } setTimeout(() => $("#copyInvite").textContent = "Copy", 1800); };
// after coming back from Stripe: ask once whether the details are in
window.addEventListener("focus", () => { if (S && S.network && S.network.stripe && !S.network.stripe_ready) post("/api/payout-status").then(load).catch(() => {}); });
$("#signout").onclick = async () => { await fetch("/logout", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }); location.reload(); };
load(); setInterval(() => S && S.configured && load(), 4000);
</script></body></html>"""


STYLE = PAGE[PAGE.index("<style>"):PAGE.index("</style>") + 8]
LOGIN = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>NodeGuard Node</title>__STYLE__</head><body><main>
<header><svg viewBox="0 0 84 84" aria-hidden="true"><circle cx="42" cy="42" r="17" fill="none" stroke="currentColor" stroke-width="4"/><path fill="currentColor" d="M42 34a5 5 0 0 1 2.8 9.1L46.6 51h-9.2l1.8-7.9A5 5 0 0 1 42 34z"/></svg>
<div><h1>NodeGuard Node</h1><div class="muted small">__NAME__</div></div></header>
<div class="card"><form id="f">
 <div id="create"><h2>Choose a password</h2>
  <p class="muted small" style="margin:0">Anyone at home who opens this page needs it. Type the setup code shown when NodeGuard Node was installed
   (on a Raspberry Pi or Linux computer, run <b>sudo nodeguard-node code</b> to see it again; on a NAS or home server such as CasaOS, Unraid, TrueNAS or Synology, open NodeGuard Node's <b>Logs</b> and look for <b>Setup code</b>).</p>
  <label class="f" for="code">Setup code</label><input type="text" id="code" inputmode="numeric" autocomplete="one-time-code" placeholder="1234-5678"></div>
 <div id="signin"><h2>Sign in</h2><p class="muted small" style="margin:0">Type this box's NodeGuard Node password.</p></div>
 <label class="f" for="pw">Password</label><input type="password" id="pw" autocomplete="current-password">
 <div id="again"><label class="f" for="pw2">Type it again</label><input type="password" id="pw2" autocomplete="new-password"></div>
 <div class="row" style="margin-top:16px"><button class="primary" id="go"></button></div><div class="err" id="err" role="alert"></div>
</form></div></main>
<script>
"use strict";
const create = "__MODE__" === "create", $ = s => document.querySelector(s);
$("#create").hidden = $("#again").hidden = !create; $("#signin").hidden = create;
$("#go").textContent = create ? "Save password and open" : "Sign in";
if (create) $("#pw").autocomplete = "new-password";
$("#f").onsubmit = async ev => {
  ev.preventDefault(); $("#err").textContent = "";
  if (create && $("#pw").value !== $("#pw2").value) { $("#err").textContent = "The two passwords are different. Type them again."; return; }
  const r = await fetch("/login", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: $("#pw").value, code: create ? $("#code").value.trim() : undefined }) });
  if (r.ok) return location.reload();
  $("#err").textContent = (await r.json().catch(() => ({}))).error || "That didn't work. Try again.";
};
($("#" + (create ? "code" : "pw"))).focus();
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "img-src data:; font-src data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _local(self):
        if HEADLESS["on"]:
            return lan_host(self.headers.get("Host")) and home_network(self.client_address[0])
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")      # blocks DNS-rebinding tricks

    def _signed_in(self):
        # NODEGUARD_NODE_AUTH=proxy: a home-server app store (Umbrel) already asks for its own login in front of this page
        return not HEADLESS["on"] or PROXY_AUTH or GATE.valid(self.headers.get("Cookie"))

    def _same_origin(self):
        """Headless: a page on another site can't post to this box (the cookie is also SameSite)."""
        origin = self.headers.get("Origin")
        if not origin or origin == "null":
            return origin is None
        return origin.split("://", 1)[-1].lower() == (self.headers.get("Host") or "").lower()

    def do_GET(self):
        if not self._local():
            return self._send(403, {"error": "This page only opens from your home network." if HEADLESS["on"] else "local use only"})
        if self.path in ("/", "/index.html"):
            if not self._signed_in():
                page = (LOGIN.replace("__STYLE__", _with_font(STYLE)).replace("__MODE__", "signin" if GATE.has_password() else "create")
                        .replace("__NAME__", machine_name().replace("&", "&amp;").replace("<", "&lt;")))
                return self._send(200, page.encode(), "text/html; charset=utf-8")
            return self._send(200, _with_font(PAGE).replace("__TOKEN__", APP_TOKEN).encode(), "text/html; charset=utf-8")
        if self.path == "/api/status" and not self._signed_in():
            return self._send(401, {"error": "sign in first"})
        if self.path == "/api/status":
            return self._send(200, status())
        if self.path == "/api/ping":
            return self._send(200, {"app": "nodeguard-node", "version": my_version(), "pid": os.getpid()})
        self._send(404, {"error": "not found"})

    def _login(self, b):
        ip = self.client_address[0]
        if not GATE.allow_try(ip):
            return self._send(429, {"error": "Too many tries. Wait 10 minutes and try again."})
        pw = str(b.get("password") or "")
        if not GATE.has_password():
            if not hmac.compare_digest(str(b.get("code") or "").strip().encode(), GATE.setup_code().strip().encode()):
                GATE.failed(ip)
                return self._send(403, {"error": "That setup code isn't right. Check it and type it again."})
            if len(pw) < 8:
                return self._send(400, {"error": "Choose a password of at least 8 characters."})
            GATE.set_password(pw)
        elif not GATE.check(pw):
            GATE.failed(ip)
            return self._send(403, {"error": "Wrong password."})
        body = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", f"ngn={GATE.new_session()}; HttpOnly; SameSite=Strict; Path=/; "
                                       f"Max-Age={Gate.SESSION_DAYS * 86400}")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self._local() or (HEADLESS["on"] and not self._same_origin()):
            return self._send(403, {"error": "not allowed"})
        n = min(int(self.headers.get("Content-Length", 0) or 0), 1 << 16)
        try:
            b = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(b, dict):
                raise ValueError
        except ValueError:
            return self._send(400, {"error": "bad request"})
        if HEADLESS["on"] and self.path == "/login":
            return self._login(b)
        if HEADLESS["on"] and self.path == "/logout":
            GATE.end(self.headers.get("Cookie"))
            return self._send(200, {"ok": True})
        if not self._signed_in():
            return self._send(401, {"error": "sign in first"})
        if self.headers.get("X-App-Token") != APP_TOKEN:
            return self._send(403, {"error": "not allowed"})
        if HEADLESS["on"] and self.path in ("/api/quit", "/api/autostart"):
            return self._send(400, {"error": "this box runs NodeGuard Node as a service: it's always on"})
        try:
            if self.path == "/api/setup":
                return self._send(200, setup(b))
            if self.path == "/api/start":
                cfg = load_config()
                cfg["paused"] = False
                save_config(cfg)
                RUN.start(cfg)
                return self._send(200, {"ok": True})
            if self.path == "/api/stop":
                RUN.halt()
                cfg = load_config()
                cfg["paused"] = True                       # stays paused after a restart too
                save_config(cfg)
                return self._send(200, {"ok": True})
            if self.path == "/api/settings":
                return self._send(200, settings(b))
            if self.path == "/api/link":
                return self._send(200, link(b.get("code", "")))
            if self.path == "/api/update/check":
                return self._send(200, UPDATER["u"].check() if UPDATER["u"] else {"can_update": False})
            if self.path == "/api/update/install":
                if not UPDATER["u"]:
                    raise ValueError("this copy can't update itself: download the new version from nodeguard.co.uk")
                return self._send(200, UPDATER["u"].install())
            if self.path == "/api/update/auto":
                cfg = load_config()
                cfg["auto_update"] = bool(b.get("on"))
                save_config(cfg)
                return self._send(200, {"ok": True})
            if self.path == "/api/open-app":
                url = app_url()
                if not url:
                    raise ValueError("this network has no NodeGuard app")
                url = url + "#home"
                if HEADLESS["on"]:
                    return self._send(200, {"url": url})          # a box with no screen: the browser opens it
                w = STATE.get("windows")
                opened = w.open(url, "node", size=(1280, 860)) if w and not os.environ.get("BROWSER") == "true" else False
                return self._send(200, {"opened": True} if opened else {"url": url})
            if self.path == "/api/folder-backup":
                if HEADLESS["on"]:
                    raise ValueError("folder backup is for computers with a screen")
                if not folder_backup_available():
                    raise ValueError("folder backup comes with the NodeGuard app from nodeguard.co.uk")
                folder_backup_start()
                url = folder_backup_url()
                w = STATE.get("windows")
                opened = w.open(url, "sync", size=(640, 820)) if w and not os.environ.get("BROWSER") == "true" else False
                return self._send(200, {"opened": True} if opened else {"url": url})
            if self.path == "/api/signin/start":
                return self._send(200, signin_start())
            if self.path == "/api/signin/status":
                return self._send(200, signin_status())
            if self.path == "/api/signout":
                SIGNIN.clear()
                cfg = load_config()
                for k in ("session", "email"):
                    cfg.pop(k, None)
                save_config(cfg)
                return self._send(200, {"ok": True})
            if self.path == "/api/payout":
                return self._send(200, set_payout(b.get("payout"), b.get("share")))
            if self.path == "/api/profile":
                return self._send(200, set_profile(b.get("public_name"), b.get("on_board")))
            if self.path == "/api/payout-setup":
                return self._send(200, payout_call("stripe-onboard"))
            if self.path == "/api/payout-status":
                return self._send(200, payout_call("stripe-status"))
            if self.path == "/api/autostart":
                cfg = load_config()
                cfg["autostart"] = set_autostart(bool(b.get("on")))
                save_config(cfg)
                return self._send(200, {"ok": True})
            if self.path == "/api/reset":
                RUN.halt()
                cfg = load_config()
                cfg.pop("join", None)
                save_config(cfg)
                return self._send(200, {"ok": True})
            if self.path == "/api/quit":
                self._send(200, {"ok": True})
                if STATE["quit"]:
                    threading.Timer(0.3, STATE["quit"]).start()
                return
        except Exception as e:
            return self._send(400, {"error": str(e)})
        self._send(404, {"error": "not found"})


def link(code):
    """Earn NodeGuard storage: tie this computer's sharing to someone's NodeGuard account."""
    cfg = load_config()
    if not (cfg.get("join") and cfg.get("operator")):
        raise ValueError("start sharing first")
    code = str(code or "").strip()
    if len("".join(c for c in code if c.isalnum())) < 8:
        raise ValueError("paste the whole code, like NGL-ABCD-EFGH")
    j = nodemod.parse_join(cfg["join"])
    try:
        r = _cloud("POST", j["cloud"] + "/operator/link", {"code": code}, headers={"X-Dash-Token": cfg["operator"]})
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error")
        except ValueError:
            msg = None
        raise ValueError(msg or f"the network said {e.code}")
    cfg["linked"] = r.get("label") or "your NodeGuard account"
    save_config(cfg)
    return {"ok": True, "linked": cfg["linked"]}


def payout_call(what):
    """Getting paid in money: Stripe takes the bank details (NodeGuard never sees them)."""
    cfg = load_config()
    if not (cfg.get("join") and cfg.get("operator")):
        raise ValueError("start sharing first")
    j = nodemod.parse_join(cfg["join"])
    try:
        return _cloud("POST", j["cloud"] + "/operator/" + what, {}, headers={"X-Dash-Token": cfg["operator"]}, timeout=30)
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error")
        except ValueError:
            msg = None
        raise ValueError(msg or f"the network said {e.code}")


def settings(b):
    """Change space, speed limit or start-with-computer while running."""
    cfg = load_config()
    if "mbps" in b:
        m = float(b["mbps"] or 0)
        if m < 0 or m > 10000:
            raise ValueError("choose a speed limit from the list")
        cfg["mbps"] = m
        if RUN.node:
            RUN.node.set_speed(m * 125_000)             # takes effect at once
    if "hours" in b:
        h = str(b["hours"] or "").strip()
        nodemod.parse_hours(h)                          # raises with a plain message if it's not like 22-7
        cfg["hours"] = h
    if "battery" in b:
        cfg["battery"] = bool(b["battery"])
    restart = False
    if "gb" in b:
        gb = float(b["gb"] or 0)
        if gb < 1:
            raise ValueError("share at least 1 GB")
        if gb != float(cfg.get("gb") or 0):
            cfg["gb"] = gb
            restart = True
    if "autostart" in b and not HEADLESS["on"]:
        cfg["autostart"] = set_autostart(bool(b["autostart"]))
    save_config(cfg)
    if RUN.node and ("hours" in b or "battery" in b):
        RUN.node.set_rest(nodemod.rest_reason(rest_policy()))     # at once, not at the next check
    if restart and RUN.running:
        RUN.halt()
        RUN.start(cfg)
    return {"ok": True}


def setup(b):
    net = built_in_network()
    join = (b.get("join") or "").strip() or (net or {}).get("join", "")
    if not join and net and net.get("net"):
        try:
            join = join_for(net)
        except Exception as e:
            raise ValueError(f"can't reach NodeGuard at {net['net']} ({e.__class__.__name__}); check your internet")
    try:
        j = _use_join(join)
    except Exception:
        raise ValueError("that join code doesn't look right: copy it again, all of it")
    try:
        _cloud("GET", j["cloud"] + "/health", timeout=8)
    except Exception as e:
        raise ValueError(f"can't reach the network at {j['cloud']} ({e.__class__.__name__}); check your internet")
    if b.get("mode") == "account":                 # signed in with a NodeGuard account
        cfg0 = load_config()
        if not cfg0.get("session") or not api_base():
            raise ValueError("sign in to your NodeGuard account first")
        try:
            r = _cloud("POST", api_base() + "/v1/node/operator", {"payout": b.get("payout") if b.get("payout") in ("cash", "both") else "credit",
                                                                 "share": b.get("share"),
                                                                 "invite": (b.get("invite") or "").strip() or None},
                       headers={"X-Node-Session": cfg0["session"]}, timeout=30)
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error")
            except ValueError:
                msg = None
            raise ValueError(msg or f"sign-up didn't work (NodeGuard said {e.code})")
        op = r["operator_token"]
        b = dict(b, email=r.get("email") or cfg0.get("email"))
    elif b.get("mode") == "have":
        op = (b.get("operator") or "").strip()
        if not op.startswith("op_"):
            raise ValueError("operator tokens start with op_")
    else:
        if not b.get("name") or "@" not in (b.get("email") or ""):
            raise ValueError("enter your name and email")
        try:
            op = _cloud("POST", j["cloud"] + "/operators",
                        {"name": b["name"], "email": b["email"], "invite": (b.get("invite") or "").strip() or None,
                         "payout": "cash" if b.get("payout") == "cash" else "credit"})["token"]
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error")
            except ValueError:
                msg = None
            raise ValueError(msg or f"sign-up didn't work (the network said {e.code})")
        except Exception as e:
            raise ValueError(f"sign-up didn't work: {e}")
    gb = float(b.get("gb") or 50)
    if gb <= 0:
        raise ValueError("choose some space to share")
    cfg = load_config()
    if b.get("mode") != "have":
        cfg.update(email=str(b.get("email") or "").strip().lower()[:120],
                   payout=b.get("payout") if b.get("payout") in ("cash", "both") else "credit",
                   share=float(b.get("share") or 0.5) if b.get("payout") == "both" else None)
    cfg.update(join=join, operator=op, folder=b.get("folder") or default_folder(), gb=gb,
               zone=(b.get("zone") or "default").strip().lower()[:40], name=machine_name(),
               tier="cold" if b.get("tier") == "cold" else "hot", mbps=float(b.get("mbps") or 0), paused=False)
    RUN.halt()
    RUN.start(cfg)                       # registers with the network on first start
    # a headless box is started by its service (systemd, Docker), not a login item
    cfg["autostart"] = False if HEADLESS["on"] else set_autostart(bool(b.get("autostart")))
    save_config(cfg)
    return {"ok": True, "node": RUN.node.id}


def device_kind(headless=False):
    """"Windows, app 1.0.3", "Raspberry Pi, app 1.0.3" and so on: what the NodeGuard team sees in its list
    of who has joined, to help people and to know which apps are out there."""
    import platform
    kind = {"Darwin": "Mac", "Windows": "Windows"}.get(platform.system(), "Linux")
    if headless:
        try:
            with open("/proc/device-tree/model") as f:
                model = f.read().strip("\x00 \n")
            kind = "Raspberry Pi" if "raspberry" in model.lower() else (model[:40] or "Linux box")
        except OSError:
            kind = "NAS (Docker)" if os.path.exists("/.dockerenv") else "Linux box"
    return f"{kind}, app {my_version()}"


def main(argv=None):
    ap = argparse.ArgumentParser(description="NodeGuard Node")
    ap.add_argument("--background", action="store_true", help="don't open a window")
    ap.add_argument("--headless", action="store_true",
                    help="a box with no screen (NAS, Raspberry Pi): open the page from another computer at home")
    ap.add_argument("--listen", default=os.environ.get("NODEGUARD_NODE_LISTEN", "0.0.0.0"),
                    help="headless: the address the page listens on (default: every network this box is on)")
    ap.add_argument("--reset-password", action="store_true", help="headless: forget the page's password")
    a = ap.parse_args(argv)
    os.environ.setdefault("VAULT_DEVICE", device_kind(a.headless))
    if a.reset_password:
        code = GATE.reset()
        print(f"Password forgotten. Open the page again and use this setup code to choose a new one: {code}")
        return 0
    if a.headless:
        return headless(a.listen)
    url = f"http://127.0.0.1:{APP_PORT}/"
    import appwindow
    windows = appwindow.Windows(os.path.join(HOME, "window"))
    STATE["windows"] = windows
    try:      # already running? just show it (unless it's an older copy, which this one replaces)
        info = json.loads(urllib.request.urlopen(url + "api/ping", timeout=2).read() or b"{}")
        if info.get("version") == my_version():
            if not a.background:
                open_first(windows, url)
            return 0
        replace_older(info)
    except Exception:
        pass
    cfg0 = load_config()
    if cfg0.get("autostart") and not a.background:
        cfg0["autostart"] = set_autostart(True)      # point "start with the computer" at this copy
        save_config(cfg0)
    srv = None
    for _ in range(20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", APP_PORT), H)
            break
        except OSError:          # the older copy is still letting go of the port
            time.sleep(0.5)
    if srv is None:
        raise SystemExit(f"NodeGuard Node can't start: something else is using port {APP_PORT}")
    srv.daemon_threads = True

    def quit_all():
        RUN.halt()
        threading.Thread(target=srv.shutdown, daemon=True).start()
    STATE["quit"] = quit_all
    try:          # installed apps keep themselves up to date (signed updates only)
        import desktop_update
        UPDATER["u"] = desktop_update.Updater("Node", api_base, HOME, quit_all)
        UPDATER["u"].run_in_background(auto=lambda: load_config().get("auto_update", True) is not False)
    except Exception:
        UPDATER["u"] = None
    start_if_set_up()
    folder_backup_resume()
    print(f"NodeGuard Node: {url}", flush=True)
    if not a.background:       # closing the window leaves the node running; Quit stops it
        threading.Timer(0.4, lambda: open_first(windows, url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        RUN.halt()
    return 0


def my_version():
    """This copy's version: the installed app's number, or "source" when run from the project folder."""
    try:
        with open(os.path.join(HERE, "app-version.json")) as f:
            return str(json.load(f)["version"])
    except (OSError, ValueError, KeyError):
        return "source"


def _pid_on_port(port):
    """Which process is listening on our port (an older NodeGuard Node that doesn't say its own)."""
    try:
        if os.name == "nt":
            out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True, timeout=10,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[1].endswith(f":{port}") and parts[3].upper() == "LISTENING":
                    return int(parts[4])
        else:
            out = subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"], capture_output=True, text=True,
                                 timeout=10).stdout.split()
            return int(out[0]) if out else None
    except Exception:
        return None
    return None


def replace_older(info):
    """An older copy of NodeGuard Node (or one started from the project folder) is still running in the
    background: stop it, so this one, the newest, takes over. Its settings and shared space carry on."""
    if info.get("app") != "nodeguard-node":
        return
    pid = info.get("pid") or _pid_on_port(APP_PORT)
    if not pid or pid == os.getpid():
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        else:
            import signal
            os.kill(pid, signal.SIGTERM)
    except Exception:
        pass


def remote_settings_once():
    """Apply what the owner set for this computer in the NodeGuard app (on their phone or the web):
    how much space to share, and paused or sharing. Newest change wins, whichever device it came from."""
    cfg = load_config()
    base = api_base()
    if RUN.node and cfg.get("node_id") != RUN.node.id:
        cfg["node_id"] = RUN.node.id
        save_config(cfg)
    node = cfg.get("node_id")
    if not (cfg.get("session") and base and node):
        return None
    try:
        want = _cloud("POST", base + "/v1/node/settings", {"node": node}, headers={"X-Node-Session": cfg["session"]})
    except Exception:
        return None
    t = want.get("t")
    if not t or t <= float(cfg.get("remote_t") or 0):
        return None
    if want.get("gb") and float(want["gb"]) != float(cfg.get("gb") or 0):
        settings({"gb": float(want["gb"])})
        cfg = load_config()
    if want.get("paused") is True and not cfg.get("paused"):
        RUN.halt()
        cfg["paused"] = True
    elif want.get("paused") is False and cfg.get("paused"):
        cfg["paused"] = False
        save_config(cfg)
        RUN.start(cfg)
        cfg = load_config()
    cfg["remote_t"] = t
    save_config(cfg)
    return want


def remote_settings_loop():
    every = float(os.environ.get("VAULT_NODE_REMOTE_SECONDS", "30"))
    while True:
        time.sleep(every)
        try:
            remote_settings_once()
        except Exception:
            pass


def open_first(windows, local_url):
    """Opening NodeGuard shows the NodeGuard app (files, photos, earnings). The small window that looks
    after this computer's sharing only opens first while it still needs setting up; after that it's
    reached from the app (the account menu: This computer's sharing) or by opening NodeGuard again
    with the app already showing."""
    cfg = load_config()
    app = app_url()
    if cfg.get("join") and cfg.get("operator") and app and not os.environ.get("NODEGUARD_OPEN_SHARING"):
        if windows.open(app + "#home", "node", size=(1280, 860)):
            return
    windows.open(local_url, "node", size=(760, 900))


def start_if_set_up(forever=False):
    threading.Thread(target=remote_settings_loop, daemon=True).start()
    cfg = load_config()
    if cfg.get("join") and cfg.get("operator") and not cfg.get("paused"):
        def autostart_node():
            attempt = 0
            while forever or attempt < 60:  # at start-up the internet may not be up yet: keep trying
                try:
                    RUN.start(cfg)
                    return
                except Exception:
                    attempt += 1
                    time.sleep(min(60, 5 * attempt))
        threading.Thread(target=autostart_node, daemon=True).start()


def headless(listen):
    """NAS / Raspberry Pi: no window. The page listens on the home network, behind a password."""
    HEADLESS["on"] = True
    os.makedirs(HOME, exist_ok=True)
    code = None if GATE.has_password() or PROXY_AUTH else GATE.setup_code()
    srv = ThreadingHTTPServer((listen, APP_PORT), H)
    srv.daemon_threads = True
    start_if_set_up(forever=True)
    print(f"NodeGuard Node is running. On a computer at home, open http://<this box's address>:{APP_PORT}", flush=True)
    if code:
        if os.environ.get("NODEGUARD_NODE_PASSWORD", "").strip().lower() in PLACEHOLDER_PASSWORDS - {""}:
            print("NODEGUARD_NODE_PASSWORD is still the example password, so it isn't used.", flush=True)
        print(f"Setup code (to choose the page's password): {code}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        RUN.halt()
    return 0


if __name__ == "__main__":
    sys.exit(main())
