"""S4 rider (v2): a bounded proof that an exposed ``/.git`` is reconstructable.

Runs only after a ``vcs_exposure`` signature matched on ``/.git/HEAD``. It reads
the ref HEAD names, fetches one loose commit object and inflates it with a size
cap, and keeps only the proof string and the commit's tree-hash prefix. It never
downloads the tree or any blob: reconstructing the source is the operator's call
(the agent's ``git_reconstruct`` part). At most two requests beyond the HEAD the
caller already read, each body capped, so a zlib bomb inflates to at most 64 KiB.
"""

from __future__ import annotations

import re
import zlib
from typing import Optional

from recon.route_exposure import prober as prober_mod

MAX_OBJECT_BYTES = 64 * 1024
_HEX40 = re.compile(rb"\b([0-9a-f]{40})\b")
_REF_LINE = re.compile(rb"ref:\s*(refs/[\w./-]+)")
#: A commit object is ``commit <size>\0tree <hash>\n...``: the tree field follows the
#: NUL header terminator, not a newline, so match it by the trailing newline instead.
_TREE_LINE = re.compile(rb"tree ([0-9a-f]{40})\n")


def _inflate(data: bytes) -> bytes:
    """Inflate at most MAX_OBJECT_BYTES, so a tiny object that expands to gigabytes
    (the hostile lab's zlib bomb) stops at the cap instead of filling memory."""
    try:
        return zlib.decompressobj().decompress(data, MAX_OBJECT_BYTES)
    except (zlib.error, Exception):  # noqa: BLE001 - a corrupt object is just "no proof"
        return b""


def _commit_hash(probe, git_root: str, head_body: bytes) -> Optional[str]:
    """The commit hash HEAD points at: a direct 40-hex HEAD, or the ref it names."""
    direct = _HEX40.search(head_body or b"")
    ref = _REF_LINE.search(head_body or b"")
    if ref and not direct:
        answer = probe.send("GET", f"{git_root}/{ref.group(1).decode('ascii', 'replace')}",
                            max_bytes=MAX_OBJECT_BYTES)
        if answer is None or not answer.ok or not (200 <= (answer.status_code or 0) < 300):
            return None
        direct = _HEX40.search(answer.content or b"")
    return direct.group(1).decode("ascii") if direct else None


def walk(probe, git_root: str, head_body: bytes) -> dict:
    """``{"git_walk_proof": "head>ref>commit", "git_tree_prefix": "<8 hex>"}`` when a
    loose commit object inflates to a ``commit`` header, else ``{}``. ``git_root`` is
    the URL up to and including ``/.git``. Never raises."""
    try:
        commit = _commit_hash(probe, git_root, head_body)
        if not commit:
            return {}
        obj = probe.send("GET", f"{git_root}/objects/{commit[:2]}/{commit[2:]}",
                         max_bytes=MAX_OBJECT_BYTES)
        if obj is None or not obj.ok or not (200 <= (obj.status_code or 0) < 300):
            return {}
        inflated = _inflate(obj.content or b"")
        if not inflated.startswith(b"commit "):
            return {}
        tree = _TREE_LINE.search(inflated)
        proof = {"git_walk_proof": "head>ref>commit"}
        if tree:
            proof["git_tree_prefix"] = tree.group(1).decode("ascii")[:8]
        return proof
    except Exception:  # noqa: BLE001 - one route's git walk never breaks the scan
        return {}
