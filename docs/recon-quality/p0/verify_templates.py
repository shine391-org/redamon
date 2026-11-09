#!/usr/bin/env python3
"""Verify the frozen P0 archive offline without extracting or updating templates."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    baseline = json.loads(Path(__file__).with_name("baseline.json").read_text())
    expected = baseline["templates"]
    with args.archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != expected["archive_sha256"]:
        raise SystemExit("archive digest mismatch")
    entries = []
    with tarfile.open(args.archive) as archive:
        for member in archive:
            if member.isfile():
                stream = archive.extractfile(member)
                if stream is None:
                    raise SystemExit(f"missing file payload: {member.name}")
                with stream:
                    entries.append({"path": member.name.removeprefix("./"), "size": member.size,
                                    "sha256": hashlib.sha256(stream.read()).hexdigest()})
    entries.sort(key=lambda entry: entry["path"])
    tree = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if tree != expected["tree_sha256"] or len(entries) != expected["file_count"]:
        raise SystemExit("template tree mismatch")
    print(json.dumps({"archive_sha256": digest, "tree_sha256": tree, "file_count": len(entries)}))


if __name__ == "__main__":
    main()
