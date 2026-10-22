"""
appwindow.py: open a page as its own app window (no address bar or tabs), the way
installed web apps do, using Microsoft Edge or Google Chrome already on the computer.

Each window gets its own profile folder, so its sign-in and settings are kept apart
from the person's normal browsing (and test people stay apart from each other).
If neither browser is installed, the page opens in the normal browser instead.
"""

import os
import shutil
import subprocess
import sys
import threading
import time
import webbrowser


def find_browser():
    if os.environ.get("NODEGUARD_BROWSER"):
        return os.environ["NODEGUARD_BROWSER"]
    if sys.platform == "win32":
        roots = [os.environ.get(k) for k in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA")]
        rel = [r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe",
               r"BraveSoftware\Brave-Browser\Application\brave.exe"]
        for r in rel:                       # Edge first: it's on every Windows 10 and 11 computer
            for root in roots:
                if root and os.path.exists(os.path.join(root, r)):
                    return os.path.join(root, r)
        return None
    if sys.platform == "darwin":
        apps = ["Google Chrome.app/Contents/MacOS/Google Chrome", "Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                "Brave Browser.app/Contents/MacOS/Brave Browser", "Chromium.app/Contents/MacOS/Chromium"]
        for a in apps:
            for root in ("/Applications", os.path.expanduser("~/Applications")):
                if os.path.exists(os.path.join(root, a)):
                    return os.path.join(root, a)
        return None
    for name in ("google-chrome", "google-chrome-stable", "microsoft-edge", "chromium", "chromium-browser", "brave-browser"):
        p = shutil.which(name)
        if p:
            return p
    return None


def _profile_alive(profile):
    """Is a browser still running with this profile? (it keeps a lock file while it is)"""
    if sys.platform == "win32":
        lock = os.path.join(profile, "lockfile")
        if not os.path.exists(lock):
            return False
        try:
            os.remove(lock)                # only possible once the browser has let go of it
            return False
        except OSError:
            return True
    return os.path.lexists(os.path.join(profile, "SingletonLock"))


class Windows:
    """The app windows this program opened; tells you when the last one closes."""

    def __init__(self, profiles_dir):
        self.dir = profiles_dir
        self.procs = {}
        self.untracked = False           # opened in a normal browser: we can't tell when it closes
        self.lock = threading.Lock()

    def open(self, url, name="main", size=(1360, 880)):
        exe = find_browser()
        if not exe:
            webbrowser.open(url)
            self.untracked = True
            return False
        profile = os.path.join(self.dir, "".join(c if c.isalnum() or c in "-_" else "-" for c in name.lower())[:40] or "main")
        os.makedirs(profile, exist_ok=True)
        args = [exe, f"--app={url}", f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
                f"--window-size={size[0]},{size[1]}", "--disable-sync", "--disable-features=Translate,MediaRouter"]
        kw = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if sys.platform == "win32":
            kw["creationflags"] = 0x08000000          # no console window
        with self.lock:
            self.procs[profile] = (subprocess.Popen(args, **kw), time.time())
        return True

    def any_open(self):
        with self.lock:
            items = list(self.procs.items())
        for profile, (proc, started) in items:
            if proc.poll() is None or _profile_alive(profile) or time.time() - started < 8:
                return True
        return False

    def watch(self, on_all_closed, every=2.0, grace=3):
        """Call on_all_closed once every window has been closed for a few seconds."""
        def loop():
            quiet = 0
            while True:
                time.sleep(every)
                if self.untracked or not self.procs:
                    continue
                quiet = 0 if self.any_open() else quiet + 1
                if quiet >= grace:
                    on_all_closed()
                    return
        threading.Thread(target=loop, daemon=True).start()
