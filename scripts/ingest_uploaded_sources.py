#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ATTACK_MEMBER = "enterprise-attack/enterprise-attack-19.1.json"
SIGMA_PREFIX = "sigma/"


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_target(root: Path, member: str) -> Path:
    rel = PurePosixPath(member)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(f"Unsafe archive member: {member}")
    target = root.joinpath(*rel.parts)
    target.resolve().relative_to(root.resolve())
    return target


def extract_attack(archive: Path, raw_root: Path) -> dict:
    destination = raw_root / "mitre_attack" / "enterprise-attack-19.1.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        if ATTACK_MEMBER not in zf.namelist():
            raise FileNotFoundError(f"{ATTACK_MEMBER} is missing from {archive}")
        with zf.open(ATTACK_MEMBER) as src, destination.open("wb") as dst:
            shutil.copyfileobj(src, dst)
    return {
        "source": "mitre_attack_enterprise",
        "archive": str(archive),
        "archive_sha256": sha256_file(archive),
        "selected_member": ATTACK_MEMBER,
        "extracted_path": str(destination),
        "extracted_sha256": sha256_file(destination),
        "version": "19.1",
    }


def extract_sigma(archive: Path, raw_root: Path) -> dict:
    destination = raw_root / "sigma" / "repository"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    commit = None
    origin = None
    extracted = 0
    skipped_git = 0
    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
        ref_name = "sigma/.git/refs/heads/master"
        if ref_name in names:
            commit = zf.read(ref_name).decode("utf-8", errors="replace").strip()
        config_name = "sigma/.git/config"
        if config_name in names:
            config = zf.read(config_name).decode("utf-8", errors="replace")
            for line in config.splitlines():
                if line.strip().startswith("url ="):
                    origin = line.split("=", 1)[1].strip()
                    break
        for info in zf.infolist():
            name = info.filename
            if not name.startswith(SIGMA_PREFIX):
                continue
            relative = name[len(SIGMA_PREFIX):]
            if not relative or relative.startswith(".git/"):
                skipped_git += 1
                continue
            target = safe_target(destination, relative)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted += 1
    return {
        "source": "sigma_rules_repository",
        "archive": str(archive),
        "archive_sha256": sha256_file(archive),
        "extracted_path": str(destination),
        "origin": origin,
        "commit": commit,
        "files_extracted": extracted,
        "git_members_skipped": skipped_git,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack-zip", type=Path, required=True)
    parser.add_argument("--sigma-zip", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    args = parser.parse_args()

    raw_root = args.project_root / "data" / "raw"
    raw_root.mkdir(parents=True, exist_ok=True)
    source_archives = raw_root / "source_archives"
    source_archives.mkdir(parents=True, exist_ok=True)

    attack_copy = source_archives / "enterprise-attack.zip"
    sigma_copy = source_archives / "sigma.zip"
    shutil.copy2(args.attack_zip, attack_copy)
    shutil.copy2(args.sigma_zip, sigma_copy)

    manifest = {
        "manifest_version": "1.0.0",
        "pipeline_version": "0.2.0",
        "ingested_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sources": [extract_attack(attack_copy, raw_root), extract_sigma(sigma_copy, raw_root)],
    }
    manifest_path = args.project_root / "reports" / "source_intake_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
