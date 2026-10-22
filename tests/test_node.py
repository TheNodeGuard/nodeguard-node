"""
Checks for NodeGuard Node that need no network: signatures, proofs of storage, and a node
storing, returning and protecting pieces. Run with:  python3 tests/test_node.py
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import node as nodemod  # noqa: E402
import proofs  # noqa: E402
import tickets  # noqa: E402

R = []


def ok(c, m):
    R.append(bool(c))
    print(("PASS " if c else "FAIL ") + m, flush=True)


# signatures (Ed25519): the built-in code and the cryptography library agree
seed = hashlib.sha256(b"test seed").digest()
pub = tickets._py_public_key(seed)
sig = tickets._py_sign(seed, b"hello", pub)
ok(tickets._py_verify(pub, b"hello", sig) and not tickets._py_verify(pub, b"hellO", sig), "built-in signatures sign and check")
if tickets.LIBRARY:
    ok(tickets._lib_public(seed) == pub and tickets._lib_sign(seed, b"hello") == sig, "the cryptography library gives the same answers")

# proofs of storage
data = os.urandom(50_000)
r = proofs.root(data)
p = proofs.prove(data, 3)
ok(proofs.verify(r, 3, p), "a proof for a stored part checks out")
bad = dict(p, leaf=("1" if p["leaf"][0] == "0" else "0") + p["leaf"][1:])
ok(not proofs.verify(r, 3, bad), "a changed part doesn't")

# a node, with a made-up network secret
secret = b"a test network secret, not a real one"
issuer = tickets.Issuer(secret)
tmp = tempfile.mkdtemp(prefix="ng-node-test-")
try:
    node, srv, stop = nodemod.serve(tmp, 0, secret, host="127.0.0.1", capacity=100_000_000)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"

    def call(method, path, body=None, ticket=None, headers=None):
        h = dict(headers or {})
        if ticket:
            h["X-Vault-Ticket"] = ticket
        req = urllib.request.Request(base + path, data=body, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    health = json.loads(call("GET", "/health")[1])
    ok("free" in json.dumps(health) or health, "health answers without a pass")
    piece = os.urandom(20_000)
    sid = hashlib.sha256(piece).hexdigest()[:48]
    want = nodemod.shard_hash(piece)
    user = issuer.issue("acct1", scope="rw")
    st, _ = call("PUT", "/shards/" + sid, piece, user, {"X-Shard-Hash": want})
    ok(st in (200, 201, 204), f"a device's pass can store a piece ({st})")
    st, _ = call("PUT", "/shards/" + sid, piece, None, {"X-Shard-Hash": want})
    ok(st in (401, 403), f"no pass, no storing ({st})")
    st, body = call("GET", "/shards/" + sid, None, user)
    ok(st == 200 and body == piece, "it comes back exactly")
    other = issuer.issue("acct2", scope="rw")
    st, _ = call("GET", "/shards/" + sid, None, other)
    ok(st in (401, 403, 404), f"another account can't read it ({st})")
    forged = user[:-4] + ("0000" if not user.endswith("0000") else "1111")
    st, _ = call("GET", "/shards/" + sid, None, forged)
    ok(st in (401, 403), f"a forged pass is refused ({st})")
    st, _ = call("DELETE", "/shards/" + sid, None, user)
    ok(st in (401, 403), f"a device's pass can't delete ({st})")
    wrong = issuer.issue("acct1", scope="all@someone-else")
    st, _ = call("DELETE", "/shards/" + sid, None, wrong)
    ok(st in (401, 403), f"a pass made for another machine is refused ({st})")
    mine = issuer.issue("acct1", scope="all@" + node.id)
    st, _ = call("DELETE", "/shards/" + sid, None, mine)
    ok(st in (200, 204), f"the network's pass for this machine can delete ({st})")
    srv.shutdown()
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{sum(R)}/{len(R)} passed")
sys.exit(0 if R and all(R) else 1)
