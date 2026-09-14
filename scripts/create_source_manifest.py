#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a checksum manifest for an immutable raw source directory.")
    parser.add_argument("source_dir", type=Path)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not args.source_dir.is_dir():
        parser.error(f"Source directory not found: {args.source_dir}")

    files = []
    for path in sorted(p for p in args.source_dir.rglob("*") if p.is_file() and p.name != ".gitkeep"):
        files.append({
            "relative_path": str(path.relative_to(args.source_dir)),
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
        })

    manifest = {
        "dataset": args.dataset,
        "version": args.version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_root": str(args.source_dir.resolve()),
        "file_count": len(files),
        "files": files,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.output} with {len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
