#!/bin/sh
# Start NodeGuard Node in a container. Each start it fetches the newest version from the network
# (node_update checks it's signed by NodeGuard before using it); if it can't, it uses the copy in this image.
CONFIG="${VAULT_NODE_HOME:-/config}"
mkdir -p "$CONFIG/app" "${NODEGUARD_DATA:-/data}"
B="${NG_BUNDLE:-/opt/nodeguard}"
T="$CONFIG/app/node_update.py"; [ -f "$T" ] || T="$B/node_update.py"
TMP="$(mktemp -d)"
if wget -qO "$TMP/n.tgz" "${NODEGUARD_NET:-https://net.nodeguard.co.uk}/node/nodeguard-node.tar.gz" 2>/dev/null; then
  python3 "$T" install "$TMP/n.tgz" "$CONFIG/app" "$CONFIG" || echo "Couldn't use the download: starting the version in this image."
fi
rm -rf "$TMP"
[ -f "$CONFIG/app/node_app.py" ] || cp "$B"/*.py "$CONFIG/app/"
exec python3 "$CONFIG/app/node_app.py" --headless "$@"
