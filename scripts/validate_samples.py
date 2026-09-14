#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threat_hunting_data.schema_validation import load_schema, validate_record

pairs = [
    ("samples/canonical_process_event.json", "schemas/canonical_event.schema.json"),
    ("samples/canonical_finding.json", "schemas/hunt_finding.schema.json"),
    ("samples/process_feature_record.json", "schemas/finding_feature_record.schema.json"),
]

failed = False
for record_rel, schema_rel in pairs:
    record = json.loads((ROOT / record_rel).read_text(encoding="utf-8"))
    schema = load_schema(ROOT / schema_rel)
    errors = validate_record(record, schema)
    if errors:
        failed = True
        print(f"FAIL {record_rel}")
        for error in errors:
            print(f"  - {error}")
    else:
        print(f"PASS {record_rel}")

raise SystemExit(1 if failed else 0)
