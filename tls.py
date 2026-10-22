"""
tls.py: HTTPS for every part of Vault.

Servers (cloud, nodes, S3 gateway, platform API) turn on HTTPS with a
certificate and key:   --tls-cert cert.pem --tls-key key.pem
(or VAULT_TLS_CERT / VAULT_TLS_KEY). In production use a real certificate, e.g.
from Let's Encrypt.

Clients check every server's certificate. They trust the normal public
certificate authorities, plus an extra private one if VAULT_CA_FILE points to
it (that's how the test lab works: it creates its own private authority).

`make_lab_certs()` creates a private certificate authority and a certificate
for local testing, using the `openssl` command if it's installed.
"""

import os
import shutil
import ssl
import subprocess
import urllib.request

_client_ctx = None


def client_context():
    """SSL context that verifies certificates (public CAs + VAULT_CA_FILE)."""
    global _client_ctx
    if _client_ctx is None:
        ctx = ssl.create_default_context()
        ca = os.environ.get("VAULT_CA_FILE")
        if ca:
            ctx.load_verify_locations(ca)
        _client_ctx = ctx
    return _client_ctx


def server_context(cert, key, tls13_only=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # TLS 1.3 everywhere we control (cloud, nodes): it's what post-quantum key exchange
    # needs. Gateways for other people's software (S3, website API) also accept 1.2.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3 if tls13_only else ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def wrap_server(srv, cert=None, key=None, tls13_only=False):
    """Turn an http.server instance into an HTTPS server if a cert is given."""
    cert = cert or os.environ.get("VAULT_TLS_CERT")
    key = key or os.environ.get("VAULT_TLS_KEY")
    if cert and key:
        srv.socket = server_context(cert, key, tls13_only).wrap_socket(srv.socket, server_side=True)
        return True
    return False


def pq_status():
    """Is post-quantum (hybrid X25519 + ML-KEM-768) key exchange available for HTTPS here?
    OpenSSL 3.5 and newer offer it by default in TLS 1.3, so connections between two
    such machines are protected against "record now, decrypt with a quantum computer later"."""
    v = ssl.OPENSSL_VERSION_INFO
    hybrid = (v[0], v[1]) >= (3, 5)
    return {"openssl": ssl.OPENSSL_VERSION, "hybrid_ml_kem": hybrid,
            "note": "hybrid ML-KEM key exchange on by default" if hybrid else
                    "upgrade to OpenSSL 3.5+ (e.g. Ubuntu 25.04+, Debian 13) for post-quantum HTTPS"}


_opener = None


def urlopen(req, timeout=15):
    """urllib.urlopen with certificate checking for https:// URLs."""
    global _opener
    if _opener is None:
        _opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=client_context()))
    return _opener.open(req, timeout=timeout)


def make_lab_certs(folder, hosts=("127.0.0.1", "localhost"), ca=None):
    """Create a private CA and one server certificate valid for `hosts`.
    Pass ca=(ca_cert_file, ca_key_file) to sign with an existing private CA instead.
    Returns (ca_file, cert_file, key_file) or None if openssl isn't available."""
    openssl = shutil.which("openssl")
    if not openssl:
        return None
    os.makedirs(folder, exist_ok=True)
    ca_key, ca_crt = os.path.join(folder, "ca.key"), os.path.join(folder, "ca.pem")
    key, csr, crt = (os.path.join(folder, n) for n in ("server.key", "server.csr", "server.pem"))
    ext = os.path.join(folder, "ext.cnf")
    sans = ",".join(("IP:" if h.replace(".", "").isdigit() else "DNS:") + h for h in hosts)
    with open(ext, "w") as f:
        f.write(f"subjectAltName={sans}\nbasicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
                "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    run = lambda *a: subprocess.run([openssl, *a], check=True, capture_output=True)
    if ca:
        ca_crt, ca_key = ca
    else:
        _make_ca(run, ca_key, ca_crt)
    run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", key,
        "-out", csr, "-subj", "/CN=vault-lab")
    run("x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial", "-days", "30",
        "-out", crt, "-extfile", ext)
    return ca_crt, crt, key


def _make_ca(run, ca_key, ca_crt):
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "30",
        "-keyout", ca_key, "-out", ca_crt, "-subj", "/CN=Vault Lab CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash")
