#!/usr/bin/env python3
from __future__ import annotations

import gzip
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
STRICT_CHECKS = [
    (ROOT / 'schemas/attack_technique.schema.json', ROOT / 'data/processed/knowledge/attack_techniques_active.jsonl'),
    (ROOT / 'schemas/attack_technique.schema.json', ROOT / 'data/processed/knowledge/attack_techniques_inactive.jsonl'),
    (ROOT / 'schemas/sigma_rule_record.schema.json', ROOT / 'data/processed/detections/sigma_rules_valid.jsonl'),
]
QUARANTINE_PATH = ROOT / 'data/processed/detections/sigma_rules_quarantined.jsonl'
GZIP_CHECKS = [
    (ROOT / 'schemas/canonical_event.schema.json', ROOT / 'data/processed/telemetry/evtx_canonical_events.jsonl.gz'),
]


def main() -> None:
    failures = []
    counts = {}
    for schema_path, data_path in STRICT_CHECKS:
        schema = json.loads(schema_path.read_text(encoding='utf-8'))
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        count = 0
        with data_path.open(encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                if not line.strip():
                    continue
                count += 1
                record = json.loads(line)
                errors = list(validator.iter_errors(record))
                if errors:
                    failures.append({
                        'file': str(data_path.relative_to(ROOT)),
                        'line': line_no,
                        'errors': [e.message for e in errors[:5]],
                    })
        counts[str(data_path.relative_to(ROOT))] = count


    for schema_path, data_path in GZIP_CHECKS:
        schema = json.loads(schema_path.read_text(encoding='utf-8'))
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        count = 0
        with gzip.open(data_path, 'rt', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                if not line.strip():
                    continue
                count += 1
                record = json.loads(line)
                errors = list(validator.iter_errors(record))
                if errors:
                    failures.append({
                        'file': str(data_path.relative_to(ROOT)),
                        'line': line_no,
                        'errors': [e.message for e in errors[:5]],
                    })
        counts[str(data_path.relative_to(ROOT))] = count

    quarantine_count = 0
    quarantine_invalid = 0
    with QUARANTINE_PATH.open(encoding='utf-8') as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            quarantine_count += 1
            record = json.loads(line)
            validation = record.get('validation') or {}
            lineage = record.get('lineage') or {}
            if validation.get('status') == 'valid':
                failures.append({
                    'file': str(QUARANTINE_PATH.relative_to(ROOT)),
                    'line': line_no,
                    'errors': ['quarantined_record_has_valid_status'],
                })
            if not lineage.get('source_record_id') or not lineage.get('source_dataset'):
                failures.append({
                    'file': str(QUARANTINE_PATH.relative_to(ROOT)),
                    'line': line_no,
                    'errors': ['quarantined_record_missing_lineage'],
                })
            if not validation.get('sigma_valid', False):
                quarantine_invalid += 1
    counts[str(QUARANTINE_PATH.relative_to(ROOT))] = quarantine_count

    result = {
        'validated_record_counts': counts,
        'strict_failure_count': len(failures),
        'quarantine_structurally_invalid_count': quarantine_invalid,
        'failures': failures[:100],
    }
    report = ROOT / 'reports/processed_schema_validation.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    if failures:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
