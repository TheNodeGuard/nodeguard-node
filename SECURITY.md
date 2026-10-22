# Security

If you find a security problem in NodeGuard Node, please tell us privately first:

- On GitHub, open the **Security** tab of this repo and choose **Report a vulnerability**.

Please don't open a public issue, and give us a reasonable time to fix it before you talk about it publicly. We'll reply as soon as we can and keep you updated.

Useful things to include: what you found, how to repeat it, and what someone could do with it.

## How a node is protected

- Files are encrypted on the owner's device before they're sent. Nodes only hold encrypted pieces and never get the keys.
- Every request to a node needs a pass signed by the network. Nodes hold only the network's public key, so they can check passes but can't make them.
- Passes that delete or check pieces name the one machine they're for, so a pass can't be reused against another node.
- Updates are only installed if they're signed with the same release key as the version already installed.
