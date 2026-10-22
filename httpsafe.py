"""
httpsafe.py: every server's request handlers run through this, so a malformed or
hostile request gets a clean 400 (never a crash, a hung connection or a stack
trace), and a request that hits a bug gets a plain 500 with nothing internal in it.
"""

import functools
import json
import os
import sys
import time

BAD_INPUT = (KeyError, ValueError, TypeError, AttributeError, IndexError, UnicodeError, OverflowError)
GONE = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError)


def _reply(handler, code, msg):
    if getattr(handler, "_replied", False):
        return
    try:
        body = json.dumps({"error": msg}).encode()
        handler.send_response(code)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(body)
    except Exception:
        pass
    handler.close_connection = True


def _wrap(fn):
    @functools.wraps(fn)
    def run(self, *a, **kw):
        self._replied = False
        try:
            return fn(self, *a, **kw)
        except GONE:
            self.close_connection = True          # the other side went away: nothing to do
        except BAD_INPUT as e:
            _reply(self, 400, "bad request")
            print(f"{time.strftime('%H:%M:%S')} bad request {self.command} {self.path[:80]!r}: "
                  f"{type(e).__name__}", file=sys.stderr, flush=True)
            if os.environ.get("VAULT_TRACE"):
                import traceback
                traceback.print_exc()
        except Exception as e:                    # a bug: say so plainly, log one line, keep serving
            _reply(self, 500, "internal error")
            print(f"{time.strftime('%H:%M:%S')} error {self.command} {self.path[:80]!r}: "
                  f"{type(e).__name__}: {str(e)[:200]}", file=sys.stderr, flush=True)
    return run


def harden(cls):
    """Wrap every do_* method of a BaseHTTPRequestHandler subclass, and note when a reply
    has started so an error after that doesn't send a second one."""
    for name in list(vars(cls)):
        if name.startswith("do_"):
            setattr(cls, name, _wrap(getattr(cls, name)))
    orig = cls.send_response

    def send_response(self, *a, **kw):
        self._replied = True
        return orig(self, *a, **kw)
    cls.send_response = send_response
    return cls


def _quiet_handle_error(self, request, client_address):
    """A client that hangs up mid-answer isn't an error worth a stack trace."""
    if isinstance(sys.exc_info()[1], GONE):
        return
    _orig_handle_error(self, request, client_address)


import socketserver  # noqa: E402
_orig_handle_error = socketserver.BaseServer.handle_error
socketserver.BaseServer.handle_error = _quiet_handle_error
