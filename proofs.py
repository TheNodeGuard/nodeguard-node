"""
proofs.py: proof that a node still holds a shard, without downloading it.

When a shard is stored, the uploader computes a Merkle root over its 4 KB
parts and gives it to the cloud. Later the cloud picks a random part and asks
the node for it plus the sibling hashes up to the root. Only a node that still
has that part can answer, and every part could be the one asked for, so a node
that quietly dropped data fails sooner or later. Each check costs about 4 KB
instead of the whole shard.
"""

import hashlib

LEAF = 4096


def _h(prefix: bytes, data: bytes) -> bytes:
    return hashlib.blake2b(prefix + data, digest_size=16).digest()


def leaves(data: bytes):
    return [data[i:i + LEAF] for i in range(0, max(len(data), 1), LEAF)]


def _levels(data: bytes):
    level = [_h(b"\x00", x) for x in leaves(data)]
    out = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(_h(b"\x01", level[i] + level[i + 1]) if i + 1 < len(level) else level[i])
        level = nxt
        out.append(level)
    return out


def root(data: bytes) -> str:
    return _levels(data)[-1][0].hex()


def leaf_count(size: int) -> int:
    return max(1, (size + LEAF - 1) // LEAF)


def prove(data: bytes, index: int) -> dict:
    """What a node sends back: the asked-for part and the sibling hashes."""
    levels = _levels(data)
    path, i = [], index
    for level in levels[:-1]:
        sib = i ^ 1
        path.append(level[sib].hex() if sib < len(level) else "")
        i //= 2
    return {"leaf": leaves(data)[index].hex(), "path": path}


def verify(root_hex: str, index: int, proof: dict) -> bool:
    try:
        h = _h(b"\x00", bytes.fromhex(proof["leaf"]))
        i = index
        for sib in proof["path"]:
            if sib:
                s = bytes.fromhex(sib)
                h = _h(b"\x01", h + s) if i % 2 == 0 else _h(b"\x01", s + h)
            i //= 2
        return h.hex() == root_hex
    except (KeyError, ValueError, TypeError):
        return False
