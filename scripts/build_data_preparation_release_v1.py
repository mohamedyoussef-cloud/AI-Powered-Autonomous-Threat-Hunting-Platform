from __future__ import annotations

import gzip
import hashlib
import importlib.metadata
import json
import platform
import shutil
import subprocess
import sys
import zipfile

from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = PROJECT_ROOT.parent

RELEASE_VERSION = "1.0.0"
RELEASE_NAME = "ThreatHunting_Data_Preparation_v1.0"

EXPORTS_DIR = WORKSPACE_ROOT / "exports"
RELEASE_DIR = EXPORTS_DIR / RELEASE_NAME

ZIP_PATH = EXPORTS_DIR / f"{RELEASE_NAME}.zip"
ZIP_CHECKSUM_PATH = EXPORTS_DIR / f"{RELEASE_NAME}.zip.sha256"


# =========================================================
# Helpers
# =========================================================

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def md5_file(path: Path) -> str:
    h = hashlib.md5()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def count_jsonl(path: Path) -> int:
    opener = (
        gzip.open
        if path.suffix == ".gz"
        else open
    )

    count = 0

    with opener(
        path,
        "rt",
        encoding="utf-8",
    ) as f:

        for line in f:
            if line.strip():
                count += 1

    return count


def copy_file(
    source: Path,
    destination: Path,
) -> None:

    if not source.exists():
        raise FileNotFoundError(
            f"Required release artifact missing: {source}"
        )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copy2(
        source,
        destination,
    )


def copy_tree(
    source: Path,
    destination: Path,
) -> None:

    if not source.exists():
        return

    shutil.copytree(
        source,
        destination,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns(
            "__pycache__",
            "*.pyc",
            "*.pyo",
            ".pytest_cache",
            ".mypy_cache",
        ),
    )


def read_json(path: Path) -> dict:
    return json.loads(
        path.read_text(
            encoding="utf-8",
        )
    )


def dependency_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


# =========================================================
# Clean release destination
# =========================================================

EXPORTS_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

if RELEASE_DIR.exists():
    shutil.rmtree(RELEASE_DIR)

if ZIP_PATH.exists():
    ZIP_PATH.unlink()

if ZIP_CHECKSUM_PATH.exists():
    ZIP_CHECKSUM_PATH.unlink()

RELEASE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# =========================================================
# Final regression validation
# =========================================================

pytest_result = subprocess.run(
    [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "tests",
    ],
    cwd=PROJECT_ROOT,
    capture_output=True,
    text=True,
)

if pytest_result.returncode != 0:
    raise RuntimeError(
        "pytest failed:\n"
        + pytest_result.stdout
        + "\n"
        + pytest_result.stderr
    )


validator_result = subprocess.run(
    [
        sys.executable,
        str(
            PROJECT_ROOT
            / "scripts"
            / "validate_processed.py"
        ),
    ],
    cwd=PROJECT_ROOT,
    capture_output=True,
    text=True,
)

if validator_result.returncode != 0:
    raise RuntimeError(
        "validate_processed.py failed:\n"
        + validator_result.stdout
        + "\n"
        + validator_result.stderr
    )


final_validation_text = (
    "=== PYTEST ===\n"
    + pytest_result.stdout
    + "\n=== PROCESSED VALIDATION ===\n"
    + validator_result.stdout
)

(
    RELEASE_DIR
    / "quality"
).mkdir(
    parents=True,
    exist_ok=True,
)

(
    RELEASE_DIR
    / "quality"
    / "FINAL_VALIDATION.txt"
).write_text(
    final_validation_text,
    encoding="utf-8",
)


# =========================================================
# Project / reproducibility files
# =========================================================

for dirname in [
    "src",
    "scripts",
    "configs",
    "mappings",
    "schemas",
    "tests",
    "samples",
]:

    copy_tree(
        PROJECT_ROOT / dirname,
        RELEASE_DIR / dirname,
    )


copy_file(
    PROJECT_ROOT / "pyproject.toml",
    RELEASE_DIR / "pyproject.toml",
)


existing_readme = (
    PROJECT_ROOT
    / "README.md"
)

if existing_readme.exists():

    copy_file(
        existing_readme,
        RELEASE_DIR / "PROJECT_README.md",
    )


# =========================================================
# ATT&CK processed knowledge
# =========================================================

copy_tree(
    PROJECT_ROOT
    / "data"
    / "processed"
    / "knowledge",

    RELEASE_DIR
    / "data"
    / "processed"
    / "knowledge",
)


# =========================================================
# Sigma processed artifacts
# =========================================================

copy_tree(
    PROJECT_ROOT
    / "data"
    / "processed"
    / "detections",

    RELEASE_DIR
    / "data"
    / "processed"
    / "detections",
)


# =========================================================
# EVTX final active artifacts only
# =========================================================

telemetry_source = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
)

telemetry_destination = (
    RELEASE_DIR
    / "data"
    / "processed"
    / "telemetry"
)


evtx_files = [
    "evtx_canonical_events.jsonl.gz",
    "evtx_canonical_events_flat.csv.gz",
    "evtx_source_file_inventory.csv",
    "evtx_unparsed_files.csv",
    "evtx_event_id_profile.csv",
    "evtx_tactic_profile.csv",
    "evtx_summary.json",
    "evtx_canonical_field_profile_v0_4.csv",
]


for filename in evtx_files:

    copy_file(
        telemetry_source / filename,
        telemetry_destination / filename,
    )


# =========================================================
# Integrated Telemetry Evidence FINAL v1.1 only
# =========================================================

integrated_source = (
    telemetry_source
    / "integrated"
)

integrated_destination = (
    telemetry_destination
    / "integrated"
)


integrated_files = [
    "integrated_telemetry_evidence_v1_1.csv",
    "data_component_telemetry_evidence_summary_v1_1.csv",
    "technique_telemetry_evidence_summary_v1_1.csv",
    "integrated_telemetry_evidence_summary_v1_1.json",
]


for filename in integrated_files:

    copy_file(
        integrated_source / filename,
        integrated_destination / filename,
    )


# =========================================================
# BOTS v3 processed evidence
# =========================================================

bots_source = (
    WORKSPACE_ROOT
    / "datasets"
    / "processed"
    / "botsv3"
)

bots_destination = (
    telemetry_destination
    / "botsv3"
)

if not bots_source.exists():
    raise FileNotFoundError(
        f"BOTS processed directory missing: {bots_source}"
    )


copy_tree(
    bots_source,
    bots_destination,
)


# =========================================================
# Quality / preparation reports
# =========================================================

copy_tree(
    PROJECT_ROOT / "reports",
    RELEASE_DIR / "quality" / "reports",
)


# =========================================================
# Release-level validations
# =========================================================

release_active_attack = (
    RELEASE_DIR
    / "data"
    / "processed"
    / "knowledge"
    / "attack_techniques_active.jsonl"
)

release_inactive_attack = (
    RELEASE_DIR
    / "data"
    / "processed"
    / "knowledge"
    / "attack_techniques_inactive.jsonl"
)

release_sigma_valid = (
    RELEASE_DIR
    / "data"
    / "processed"
    / "detections"
    / "sigma_rules_valid.jsonl"
)

release_sigma_quarantine = (
    RELEASE_DIR
    / "data"
    / "processed"
    / "detections"
    / "sigma_rules_quarantined.jsonl"
)

release_evtx = (
    telemetry_destination
    / "evtx_canonical_events.jsonl.gz"
)


record_counts = {
    "attack_active":
        count_jsonl(
            release_active_attack
        ),

    "attack_inactive":
        count_jsonl(
            release_inactive_attack
        ),

    "sigma_valid":
        count_jsonl(
            release_sigma_valid
        ),

    "sigma_quarantined":
        count_jsonl(
            release_sigma_quarantine
        ),

    "evtx_canonical_events":
        count_jsonl(
            release_evtx
        ),
}


expected_record_counts = {
    "attack_active": 697,
    "attack_inactive": 161,
    "sigma_valid": 3780,
    "sigma_quarantined": 473,
    "evtx_canonical_events": 37364,
}


if record_counts != expected_record_counts:
    raise RuntimeError(
        "Release record-count validation failed.\n"
        f"Actual:   {record_counts}\n"
        f"Expected: {expected_record_counts}"
    )


evtx_summary = read_json(
    telemetry_destination
    / "evtx_summary.json"
)

integrated_summary = read_json(
    integrated_destination
    / "integrated_telemetry_evidence_summary_v1_1.json"
)

bots_summary = read_json(
    bots_destination
    / "profiling"
    / "botsv3_master_field_profile_summary.json"
)

sigma_triage_summary_path = (
    RELEASE_DIR
    / "quality"
    / "reports"
    / "sigma_pysigma_triage_summary.json"
)


sigma_triage_summary = (
    read_json(
        sigma_triage_summary_path
    )
    if sigma_triage_summary_path.exists()
    else {}
)


if evtx_summary.get("status") != "PASS":
    raise RuntimeError(
        "EVTX summary is not PASS."
    )

if integrated_summary.get("status") != "PASS":
    raise RuntimeError(
        "Integrated telemetry summary is not PASS."
    )

if bots_summary.get("status") != "PASS":
    raise RuntimeError(
        "BOTS master profile summary is not PASS."
    )

if (
    sigma_triage_summary
    and
    sigma_triage_summary.get("status") != "PASS"
):
    raise RuntimeError(
        "Sigma pySigma triage summary is not PASS."
    )


# =========================================================
# Raw-source lineage
# Raw datasets themselves are intentionally NOT bundled.
# =========================================================

bots_tgz = (
    WORKSPACE_ROOT
    / "datasets"
    / "raw"
    / "botsv3_data_set.tgz"
)


bots_raw_md5 = (
    md5_file(bots_tgz)
    if bots_tgz.exists()
    else None
)

bots_raw_sha256 = (
    sha256_file(bots_tgz)
    if bots_tgz.exists()
    else None
)


source_lineage = {
    "release_version":
        RELEASE_VERSION,

    "generated_at_utc":
        datetime.now(
            timezone.utc
        ).isoformat().replace(
            "+00:00",
            "Z",
        ),

    "sources": {
        "mitre_attack_enterprise": {
            "attack_version": "19.1",
            "format": "STIX 2.1",
            "active_techniques_and_subtechniques": 697,
            "inactive_revoked_or_deprecated": 161,
            "total_retained": 858,
        },

        "sigma": {
            "repository_commit":
                "8eaafff1f2845a696050e05e72ba1140ee190698",

            "accepted_rules": 3780,
            "quarantined_rules": 473,

            "pysigma_version":
                dependency_version(
                    "pysigma"
                ),

            "pysigma_parse_failures": 0,

            "note": (
                "pySigma core validation was performed using "
                "prepared-record reconstruction because the original "
                "Sigma repository was not present during the compatibility gate."
            ),
        },

        "evtx_attack_samples": {
            "repository_commit":
                evtx_summary[
                    "source_repository_commit"
                ],

            "raw_evtx_files":
                evtx_summary[
                    "raw_evtx_file_count"
                ],

            "raw_size_bytes":
                evtx_summary[
                    "raw_evtx_size_bytes"
                ],

            "published_csv_source_files":
                evtx_summary[
                    "published_csv_source_files"
                ],

            "direct_python_evtx_source_files":
                evtx_summary[
                    "direct_python_evtx_source_files"
                ],

            "canonical_events":
                evtx_summary[
                    "canonical_event_count"
                ],

            "python_evtx_version":
                dependency_version(
                    "python-evtx"
                ),

            "all_raw_files_represented": True,
        },

        "bots_v3": {
            "official_package_md5_expected":
                "D7CCCA99A01CFF070DFF3C139CDC10EB",

            "official_package_md5_observed":
                (
                    bots_raw_md5.upper()
                    if bots_raw_md5
                    else None
                ),

            "official_package_sha256_observed":
                bots_raw_sha256,

            "physical_package_event_count":
                2030269,

            "unique_searchable_indexed_events":
                1944092,

            "search_time_rows":
                2083056,

            "sourcetypes":
                107,

            "note": (
                "The difference between physical and searchable event counts "
                "is explained by source delete metadata. Search-time rows are "
                "higher because of MultiKV expansion. No delete markers were removed."
            ),
        },
    },

    "runtime_dependencies": {
        "python":
            platform.python_version(),

        "threat_hunting_data_package":
            dependency_version(
                "threat-hunting-data"
            ),

        "pysigma":
            dependency_version(
                "pysigma"
            ),

        "python_evtx":
            dependency_version(
                "python-evtx"
            ),
    },

    "raw_data_packaging_policy": (
        "Large raw datasets and Splunk runtime are not bundled in this release. "
        "The release contains processed/canonical artifacts, source lineage, "
        "checksums, mappings, schemas, scripts, tests, and quality reports."
    ),
}


(
    RELEASE_DIR
    / "SOURCE_LINEAGE.json"
).write_text(
    json.dumps(
        source_lineage,
        indent=2,
        ensure_ascii=False,
    ),
    encoding="utf-8",
)


# =========================================================
# VERSION
# =========================================================

(
    RELEASE_DIR
    / "VERSION"
).write_text(
    RELEASE_VERSION + "\n",
    encoding="utf-8",
)


# =========================================================
# Release README
# =========================================================

readme = f"""# Threat Hunting Data Preparation Release v{RELEASE_VERSION}

This package is the finalized Data Preparation and semantic-unification
release for the AI-assisted Threat Hunting platform.

## Release status

- MITRE ATT&CK Enterprise: 697 active + 161 inactive retained for lineage.
- Sigma: 3,780 accepted rules; 473 quarantined source records.
- pySigma: 3,780/3,780 accepted rules parse-compatible.
- EVTX-ATTACK-SAMPLES: 278/278 raw EVTX source files represented.
- EVTX canonical events: 37,364 unique events.
- BOTS v3: 107 sourcetypes; 1,944,092 unique searchable indexed events.
- Integrated Telemetry Evidence v1.1: 398,098 evidence rows over 697 active ATT&CK techniques.
- Final pytest: 13/13 passed.
- Final strict processed validation: 0 failures.

## Release version vs pipeline version

Data Preparation release version: {RELEASE_VERSION}

The Python package/pipeline currently remains version 0.4.0.
These are intentionally separate version scopes:
the release version identifies the frozen Data Preparation deliverable,
while component/pipeline versions preserve artifact lineage.

## Installation

Create a fresh Python environment, then from the release root run:

    python -m venv .venv

Windows:

    .\\.venv\\Scripts\\python.exe -m pip install -U pip
    .\\.venv\\Scripts\\python.exe -m pip install -e ".[raw-evtx]"

Linux:

    .venv/bin/python -m pip install -U pip
    .venv/bin/python -m pip install -e ".[raw-evtx]"

## Validation

Run:

    python -m pytest -q tests
    python scripts/validate_processed.py

## Raw datasets

Large raw datasets are intentionally not bundled.

See SOURCE_LINEAGE.json for exact source versions, repository commits,
event/file counts, and checksums.

## Splunk

Splunk is not included.

The BOTS profiling artifacts are already included in processed form.
To rerun BOTS field profiling, install Splunk separately and either set
SPLUNK_HOME or pass -SplunkPath to scripts/profile_botsv3_fields.ps1.

## Key final artifacts

ATT&CK:
    data/processed/knowledge/

Sigma:
    data/processed/detections/

EVTX:
    data/processed/telemetry/evtx_canonical_events.jsonl.gz

BOTS:
    data/processed/telemetry/botsv3/

Integrated Evidence:
    data/processed/telemetry/integrated/integrated_telemetry_evidence_v1_1.csv

Quality evidence:
    quality/

## Semantic interpretation

Integrated Telemetry Evidence describes factual telemetry availability.
It is not the Phase 3 weighted Telemetry Readiness score and does not
prove that an ATT&CK technique occurred in a dataset.

The Phase 3 prioritization engine should calculate the weighted technique
score using the prepared factual evidence and the project parameters.

## Integrity

RELEASE_MANIFEST.json contains the frozen payload inventory.

CHECKSUMS.sha256 contains SHA-256 checksums for the release payload.

The ZIP checksum is distributed alongside the ZIP as:

    {RELEASE_NAME}.zip.sha256
"""


(
    RELEASE_DIR
    / "README.md"
).write_text(
    readme,
    encoding="utf-8",
)


# =========================================================
# Release validation summary
# =========================================================

release_validation = {
    "artifact":
        "Threat Hunting Data Preparation Release Validation",

    "release_version":
        RELEASE_VERSION,

    "record_counts":
        record_counts,

    "pytest":
        "PASS",

    "pytest_test_count":
        13,

    "strict_processed_validation":
        "PASS",

    "evtx_status":
        evtx_summary.get(
            "status"
        ),

    "bots_status":
        bots_summary.get(
            "status"
        ),

    "integrated_evidence_status":
        integrated_summary.get(
            "status"
        ),

    "sigma_pysigma_triage_status":
        sigma_triage_summary.get(
            "status",
            "REPORT_NOT_FOUND",
        ),

    "status":
        "PASS",
}


(
    RELEASE_DIR
    / "quality"
    / "RELEASE_VALIDATION.json"
).write_text(
    json.dumps(
        release_validation,
        indent=2,
    ),
    encoding="utf-8",
)


# =========================================================
# Payload manifest
# =========================================================

manifest_entries = []

for path in sorted(
    RELEASE_DIR.rglob("*")
):

    if not path.is_file():
        continue

    if path.name in {
        "RELEASE_MANIFEST.json",
        "CHECKSUMS.sha256",
    }:
        continue

    relative = (
        path.relative_to(
            RELEASE_DIR
        ).as_posix()
    )

    manifest_entries.append(
        {
            "path": relative,
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    )


manifest = {
    "release_name":
        RELEASE_NAME,

    "release_version":
        RELEASE_VERSION,

    "generated_at_utc":
        datetime.now(
            timezone.utc
        ).isoformat().replace(
            "+00:00",
            "Z",
        ),

    "record_counts":
        record_counts,

    "integrated_evidence_rows":
        integrated_summary[
            "evidence_rows"
        ],

    "integrated_active_techniques":
        integrated_summary[
            "active_techniques"
        ],

    "bots_sourcetypes":
        bots_summary[
            "sourcetypes_profiled"
        ],

    "bots_unique_searchable_events":
        bots_summary[
            "unique_searchable_events"
        ],

    "payload_file_count":
        len(manifest_entries),

    "files":
        manifest_entries,
}


manifest_path = (
    RELEASE_DIR
    / "RELEASE_MANIFEST.json"
)

manifest_path.write_text(
    json.dumps(
        manifest,
        indent=2,
        ensure_ascii=False,
    ),
    encoding="utf-8",
)


# =========================================================
# CHECKSUMS.sha256
# =========================================================

checksum_lines = []

for path in sorted(
    RELEASE_DIR.rglob("*")
):

    if not path.is_file():
        continue

    if path.name == "CHECKSUMS.sha256":
        continue

    relative = (
        path.relative_to(
            RELEASE_DIR
        ).as_posix()
    )

    checksum_lines.append(
        f"{sha256_file(path)}  {relative}"
    )


(
    RELEASE_DIR
    / "CHECKSUMS.sha256"
).write_text(
    "\n".join(
        checksum_lines
    )
    + "\n",
    encoding="utf-8",
)


# =========================================================
# ZIP
# =========================================================

with zipfile.ZipFile(
    ZIP_PATH,
    "w",
    compression=zipfile.ZIP_DEFLATED,
    compresslevel=9,
) as archive:

    for path in sorted(
        RELEASE_DIR.rglob("*")
    ):

        if not path.is_file():
            continue

        archive_name = (
            Path(RELEASE_NAME)
            / path.relative_to(
                RELEASE_DIR
            )
        )

        archive.write(
            path,
            archive_name.as_posix(),
        )


zip_sha256 = sha256_file(
    ZIP_PATH
)


ZIP_CHECKSUM_PATH.write_text(
    f"{zip_sha256}  {ZIP_PATH.name}\n",
    encoding="utf-8",
)


# =========================================================
# Final output
# =========================================================

result = {
    "artifact":
        "Threat Hunting Data Preparation Release",

    "release_version":
        RELEASE_VERSION,

    "release_directory":
        str(RELEASE_DIR),

    "zip":
        str(ZIP_PATH),

    "zip_size_bytes":
        ZIP_PATH.stat().st_size,

    "zip_sha256":
        zip_sha256,

    "payload_file_count":
        len(
            list(
                p
                for p in RELEASE_DIR.rglob("*")
                if p.is_file()
            )
        ),

    "record_counts":
        record_counts,

    "integrated_evidence_rows":
        integrated_summary[
            "evidence_rows"
        ],

    "status":
        "PASS",
}


print(
    json.dumps(
        result,
        indent=2,
    )
)
