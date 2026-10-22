# NodeGuard Node

NodeGuard Node shares spare disk space with the [NodeGuard](https://nodeguard.co.uk) storage network. While your machine is switched on, you earn extra storage or money.

This is the part people install on a Raspberry Pi, a Linux machine, a NAS or Docker. It's open source so you can read exactly what runs on your machine.

## What it does, and what it can't do

- It stores **encrypted pieces** of other people's files. The files are encrypted on their own devices before anything leaves, so your node never has the keys and can't read them.
- Each node only holds a small part of any file. One machine never has a whole file.
- It only **connects outwards** to the network. You don't need to open anything on your router.
- Every request must carry a pass signed by the network. Your node checks the pass with the network's **public** key, so it can check passes but never make them.
- Only the network can delete or check pieces, and each of those passes is tied to one machine.

## Install

**Raspberry Pi or Linux** (starts by itself, updates itself once a day):

```sh
curl -fsSL https://net.nodeguard.co.uk/node/install.sh | sudo bash
```

Then open `http://<the machine's address>:9596` on any computer at home and sign in. The script in this repo is [install.sh](install.sh), so you can read it first.

**NAS or Docker:** use [docker-compose.yml](docker-compose.yml), or the image:

```sh
docker run -d --name nodeguard-node --restart unless-stopped -p 9596:9596 \
  -v ./nodeguard-config:/config -v /path/for/shared/space:/data \
  ghcr.io/thenodeguard/nodeguard-node
```

**Windows or Mac:** download the app from [nodeguard.co.uk](https://nodeguard.co.uk).

**From this code** (Python 3, no other packages needed):

```sh
python3 node_app.py              # opens its page in your browser
python3 node_app.py --headless   # for a machine without a screen: open http://<address>:9596 from another computer
```

`pip install cryptography` makes signature checks faster. Without it, the built-in code in `tickets.py` is used.

## Updates

Official releases are signed with NodeGuard's release key, which is kept offline. `node_update.py` only installs a release signed by the same key as the version you already have. If anything doesn't match, it keeps your current version. This repo being public doesn't let anyone push an update to your machine.

If you run your own modified copy, it won't replace itself with an official release unless you choose to update.

## What's in this repo

| File | What it is |
| --- | --- |
| `node_app.py` | The app: its page, signing in, choosing how much space to share, starting and stopping the node |
| `node.py` | The storage node: stores, returns and checks pieces, and tells the network it's online |
| `tickets.py` | Checking the network's signed passes (Ed25519) |
| `proofs.py` | Proofs of storage, so the network can check pieces are really kept |
| `node_update.py` | Signed updates |
| `tls.py`, `httpsafe.py` | Secure connections and safe web serving |
| `appwindow.py` | Opens the app's page in its own window on computers with a screen |
| `install.sh`, `docker-compose.yml`, `docker/` | Installing on Linux, a NAS or Docker |
| `tests/` | Checks you can run: `python3 tests/test_node.py` |

The rest of NodeGuard (the network's servers, accounts, payments, and the NodeGuard storage app) is run by NodeGuard and isn't part of this repo.

## Contributing

Bug reports and fixes are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). For security problems, please see [SECURITY.md](SECURITY.md) and don't open a public issue.

## Licence

[GNU Affero General Public License v3.0](LICENSE). You can use, read, change and share this code. If you run a changed version as a service for other people, you must share your changes under the same licence.
