# NodeGuard Node for home servers and NAS boxes (Synology, QNAP, Unraid, TrueNAS, Umbrel, CasaOS, Raspberry Pi).
# Official image: ghcr.io/thenodeguard/nodeguard-node. To build your own: docker build -f docker/Dockerfile .
FROM python:3.12-alpine
LABEL org.opencontainers.image.title="NodeGuard Node" \
      org.opencontainers.image.description="Share spare disk space on the NodeGuard network and earn storage or money" \
      org.opencontainers.image.url="https://nodeguard.co.uk" \
      org.opencontainers.image.vendor="NodeGuard"
ENV VAULT_NODE_HOME=/config NODEGUARD_DATA=/data NODEGUARD_NET=https://net.nodeguard.co.uk PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir "cryptography>=42" || echo "no ready-made cryptography for this machine: the built-in signature code is used"
COPY node_app.py node.py tls.py proofs.py tickets.py httpsafe.py appwindow.py node_update.py /opt/nodeguard/
COPY start-node.sh update-key.tx[t] /opt/nodeguard/
COPY docker/start.sh /usr/local/bin/nodeguard-start
RUN chmod 0755 /usr/local/bin/nodeguard-start
EXPOSE 9596
VOLUME ["/config", "/data"]
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s CMD wget -qO- http://127.0.0.1:9596/api/ping >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/nodeguard-start"]
