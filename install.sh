#!/bin/sh
# NodeGuard Node for a Raspberry Pi or any Linux computer that's always on.
#   curl -fsSL https://net.nodeguard.co.uk/node/install.sh | sudo bash
#   ... | sudo bash -s -- --data /mnt/usb/nodeguard     keep what it stores on another disk
# It shares space with the NodeGuard network and earns storage or money.
set -e
BASE="https://net.nodeguard.co.uk"
HOME_DIR=/var/lib/nodeguard-node
DATA="$HOME_DIR/data"
while [ $# -gt 0 ]; do
  case "$1" in
    --data) DATA="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ "$(id -u)" != "0" ]; then
  echo "Run it with sudo:   curl -fsSL $BASE/node/install.sh | sudo bash"
  exit 1
fi
echo "Installing NodeGuard Node..."
if ! command -v python3 >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq python3
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q python3
  elif command -v apk >/dev/null 2>&1; then apk add -q python3
  else echo "Please install Python 3 first, then run this again."; exit 1; fi
fi
id nodeguard >/dev/null 2>&1 || useradd --system --home-dir "$HOME_DIR" --shell /usr/sbin/nologin nodeguard 2>/dev/null \
  || adduser -S -h "$HOME_DIR" nodeguard 2>/dev/null || true
mkdir -p /opt/nodeguard-node "$HOME_DIR" "$DATA"
chown -R nodeguard "$HOME_DIR" "$DATA" 2>/dev/null || true

# updates: fetched again when it starts and once a day. Only releases signed with the
# same key as the first one are installed (kept as it is if anything's wrong).
cat > /usr/local/bin/nodeguard-node-update <<EOF
#!/bin/sh
TMP=\$(mktemp -d)
if (command -v curl >/dev/null 2>&1 && curl -fsSL "$BASE/node/nodeguard-node.tar.gz" -o "\$TMP/n.tgz") \
   || wget -qO "\$TMP/n.tgz" "$BASE/node/nodeguard-node.tar.gz"; then
  TOOL=/opt/nodeguard-node/node_update.py
  if [ ! -f "\$TOOL" ]; then
    mkdir -p "\$TMP/x" && tar xzf "\$TMP/n.tgz" -C "\$TMP/x" && TOOL="\$TMP/x/nodeguard-node/node_update.py"
  fi
  python3 "\$TOOL" install "\$TMP/n.tgz" /opt/nodeguard-node "$HOME_DIR"
  RC=\$?
  [ \$RC -eq 0 ] && [ "\$1" = "--restart" ] && systemctl restart nodeguard-node
fi
rm -rf "\$TMP"
exit 0
EOF
chmod 755 /usr/local/bin/nodeguard-node-update
/usr/local/bin/nodeguard-node-update
[ -f /opt/nodeguard-node/node_app.py ] || { echo "Couldn't download NodeGuard Node from $BASE. Check the internet and try again."; exit 1; }
chown -R nodeguard "$HOME_DIR" 2>/dev/null || true

cat > /usr/local/bin/nodeguard-node <<EOF
#!/bin/sh
# nodeguard-node code        show the setup code again
# nodeguard-node password    forget the password (a new setup code is shown)
# nodeguard-node status      is it running?
[ "\$(id -u)" = "0" ] || exec sudo "\$0" "\$@"
case "\$1" in
  code) cat "$HOME_DIR/setup-code.txt" 2>/dev/null || echo "A password is already set. To choose a new one: sudo nodeguard-node password" ;;
  password) su -s /bin/sh nodeguard -c "VAULT_NODE_HOME=$HOME_DIR python3 /opt/nodeguard-node/node_app.py --reset-password" ;;
  *) systemctl --no-pager status nodeguard-node ;;
esac
EOF
chmod 755 /usr/local/bin/nodeguard-node

cat > /etc/systemd/system/nodeguard-node.service <<EOF
[Unit]
Description=NodeGuard Node (shares space with the NodeGuard network)
After=network-online.target
Wants=network-online.target

[Service]
User=nodeguard
Environment=VAULT_NODE_HOME=$HOME_DIR
Environment=NODEGUARD_DATA=$DATA
ExecStartPre=+/usr/local/bin/nodeguard-node-update
ExecStart=/usr/bin/env python3 /opt/nodeguard-node/node_app.py --headless
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/nodeguard-node-update.service <<EOF
[Unit]
Description=Update NodeGuard Node
[Service]
Type=oneshot
ExecStart=/usr/local/bin/nodeguard-node-update --restart
EOF
cat > /etc/systemd/system/nodeguard-node-update.timer <<EOF
[Unit]
Description=Update NodeGuard Node once a day
[Timer]
OnCalendar=daily
RandomizedDelaySec=3h
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now nodeguard-node-update.timer >/dev/null 2>&1 || true
systemctl enable nodeguard-node >/dev/null 2>&1
systemctl restart nodeguard-node
i=0
while [ ! -f "$HOME_DIR/setup-code.txt" ] && [ ! -f "$HOME_DIR/ui-password.json" ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -n "$IP" ] || IP=$(hostname)
echo ""
echo "NodeGuard Node is running, and starts by itself whenever this computer starts."
echo ""
echo "  On any computer or phone at home, open:   http://$IP:9596"
if [ -f "$HOME_DIR/setup-code.txt" ]; then
  echo "  Setup code:                               $(cat "$HOME_DIR/setup-code.txt")"
fi
echo ""
echo "  Shared space is kept in $DATA"
echo "  Show the setup code again:   sudo nodeguard-node code"
