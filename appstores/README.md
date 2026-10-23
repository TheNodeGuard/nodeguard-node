# NodeGuard Node in home-server app stores

Ready-made listings so people can install NodeGuard Node with one click from the app store
built into their home server. Each folder holds what that store needs.

| Store | Files | How it gets listed |
|---|---|---|
| Umbrel | `umbrel/nodeguard-node/` | A pull request to [getumbrel/umbrel-apps](https://github.com/getumbrel/umbrel-apps) |
| CasaOS (and ZimaOS) | `casaos/NodeGuard/` | A pull request to [IceWhaleTech/CasaOS-AppStore](https://github.com/IceWhaleTech/CasaOS-AppStore) |
| Unraid | `unraid/nodeguard-node.xml` | This repo is the template repo. Add it to Community Applications through the Unraid forums |
| TrueNAS SCALE | `truenas/custom-app.yaml` | Works today as a Custom App. For the catalogue, open an app request on [truenas/apps](https://github.com/truenas/apps) |

Pictures for the listings are in `assets/`: the icon (`nodeguard-node.png`, 512x512, and `.svg`) and
three gallery images (1440x900).

The image is `ghcr.io/thenodeguard/nodeguard-node`, built for Intel/AMD, arm64 (Raspberry Pi 4/5)
and armv7. Umbrel pins one exact build: when a new version should go to Umbrel users, update
`version` in `umbrel-app.yml` and the image line in its `docker-compose.yml` to the newest build
(each build prints its exact name in the Docker image workflow's summary on GitHub).

On Umbrel, NodeGuard Node uses Umbrel's own sign-in (`NODEGUARD_NODE_AUTH=proxy`). Everywhere
else the page is protected by `NODEGUARD_NODE_PASSWORD`, or, if that's empty, by a setup code printed
in the container's logs.

## Submitting (for the NodeGuard team)

### Umbrel
1. Open https://github.com/getumbrel/umbrel-apps and click **Fork**.
2. In your fork, click **Add file**, then **Create new file**, and name it `nodeguard-node/umbrel-app.yml`.
   Paste the contents of `umbrel/nodeguard-node/umbrel-app.yml`. Commit.
3. Do the same for `nodeguard-node/docker-compose.yml`.
4. Click **Contribute**, then **Open pull request**. Title: `App Submission: NodeGuard Node`.
5. In the description, drag in `assets/nodeguard-node.svg` (the icon) and the three `gallery-*.png`
   images, and say it's been tested on umbrelOS. Umbrel's team replies on the pull request.

### CasaOS
1. Open https://github.com/IceWhaleTech/CasaOS-AppStore and click **Fork**.
2. In your fork, open the `Apps` folder, click **Add file**, then **Upload files**.
3. Upload `casaos/NodeGuard/docker-compose.yml` into a new folder `Apps/NodeGuard/`, together with
   `assets/nodeguard-node.png` renamed to `icon.png`, `gallery-1.png` renamed to `thumbnail.png`,
   and the gallery images renamed `screenshot-1.png`, `screenshot-2.png` and `screenshot-3.png`.
4. Click **Contribute**, then **Open pull request**. Title: `Add NodeGuard Node`.

### Unraid
1. Go to https://forums.unraid.net and make an account.
2. In **Docker Containers**, start a topic called `[Support] NodeGuard Node`, describing the app and
   linking to https://github.com/TheNodeGuard/nodeguard-node.
3. Follow the forum's pinned post on adding templates to **Community Applications**: you give it this
   repository's address and the support topic's address.

### TrueNAS SCALE
1. It already works: Apps, Discover Apps, Custom App, Install via YAML, then paste `truenas/custom-app.yaml`.
2. For the built-in catalogue, open an issue on https://github.com/truenas/apps titled
   `App request: NodeGuard Node`, linking to this folder.
