#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import yaml
    import jsonschema
except ImportError as exc:
    print(f"Missing dependency: {exc}. Run: pip install -e .", file=sys.stderr)
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parents[1]

required = [
    "configs/dataset_registry.yaml",
    "configs/pipeline_contract.yaml",
    "configs/quality_rules.yaml",
    "mappings/field_mapping.yaml",
    "schemas/attack_technique.schema.json",
    "schemas/sigma_rule_record.schema.json",
    "schemas/canonical_event.schema.json",
    "schemas/hunt_finding.schema.json",
    "schemas/finding_feature_record.schema.json",
]

missing = [rel for rel in required if not (ROOT / rel).exists()]
if missing:
    print("Missing required files:")
    for item in missing:
        print(f"- {item}")
    raise SystemExit(1)

for rel in required:
    path = ROOT / rel
    if path.suffix == ".json":
        json.loads(path.read_text(encoding="utf-8"))
    elif path.suffix in {".yaml", ".yml"}:
        yaml.safe_load(path.read_text(encoding="utf-8"))

print("Bootstrap check passed.")
print(f"Project root: {ROOT}")
print("Next input: place source datasets under data/raw/ and complete docs/USER_INPUT_CHECKLIST.md")
