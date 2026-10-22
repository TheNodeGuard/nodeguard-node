#!/bin/sh
# NodeGuard Node (Linux)
cd "$(dirname "$0")"
exec python3 node_app.py "$@"
