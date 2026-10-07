from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection


DANGEROUS_PIPE_COMMANDS = {
    "delete", "drop", "shutdown", "restart", "remove", "truncate", "purge"
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception as exc:
                raise RuntimeError(f"Invalid JSONL at {path}:{line_no}: {exc}") from exc


def write_jsonl(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def dangerous_commands(spl: str) -> list[str]:
    commands = re.findall(r"\|\s*([A-Za-z_][A-Za-z0-9_]*)", spl or "")
    found = sorted({cmd.lower() for cmd in commands if cmd.lower() in DANGEROUS_PIPE_COMMANDS})
    return found


def main():
    ap = argparse.ArgumentParser(
        description="Compile validated baseline Sigma rules to Splunk SPL without mutating Sigma."
    )
    ap.add_argument(
        "--rules-dir",
        default=r"D:\ThreatHunting\project\data\processed\phase3\sigma_baseline\rules",
    )
    ap.add_argument(
        "--index-file",
        default=r"D:\ThreatHunting\project\data\processed\phase3\sigma_baseline\baseline_sigma_results_index_v1.jsonl",
    )
    ap.add_argument(
        "--output-dir",
        default=r"D:\ThreatHunting\project\data\processed\phase3\splunk_compilation",
    )
    ap.add_argument("--splunk-index", default="botsv3")
    ap.add_argument("--earliest", default="0")
    args = ap.parse_args()

    rules_dir = Path(args.rules_dir)
    index_file = Path(args.index_file)
    out_dir = Path(args.output_dir)

    if not rules_dir.is_dir():
        raise SystemExit(f"RULES_DIR_NOT_FOUND: {rules_dir}")
    if not index_file.is_file():
        raise SystemExit(f"INDEX_FILE_NOT_FOUND: {index_file}")

    index_rows = list(read_jsonl(index_file))
    if len(index_rows) != 540:
        raise SystemExit(f"EXPECTED_540_INDEX_ROWS_GOT_{len(index_rows)}")

    by_rule_file = {}
    for row in index_rows:
        rule_file = row.get("rule_file")
        if not rule_file:
            raise SystemExit("INDEX_ROW_MISSING_RULE_FILE")
        if rule_file in by_rule_file:
            raise SystemExit(f"DUPLICATE_RULE_FILE_IN_INDEX: {rule_file}")
        by_rule_file[rule_file] = row

    rule_files = sorted(rules_dir.glob("*.yml"))
    if len(rule_files) != 540:
        raise SystemExit(f"EXPECTED_540_RULE_FILES_GOT_{len(rule_files)}")

    disk_names = {p.name for p in rule_files}
    index_names = set(by_rule_file)
    missing = sorted(index_names - disk_names)
    unexpected = sorted(disk_names - index_names)
    if missing or unexpected:
        raise SystemExit(
            f"RULE_INDEX_MISMATCH missing={len(missing)} unexpected={len(unexpected)}"
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    spl_dir = out_dir / "spl"
    scoped_dir = out_dir / "scoped_spl"
    spl_dir.mkdir(exist_ok=True)
    scoped_dir.mkdir(exist_ok=True)

    backend = SplunkBackend()

    compiled_rows = []
    error_rows = []
    class_counts = Counter()
    mode_counts = Counter()
    query_count_hist = Counter()
    compile_success = 0
    compile_fail = 0
    nonempty_success = 0
    dangerous_total = 0

    print("===== SIGMA -> SPL FULL-POPULATION COMPILATION =====")
    print(f"INPUT_INDEX_ROWS          : {len(index_rows)}")
    print(f"INPUT_RULE_FILES          : {len(rule_files)}")
    print("SIGMA_MUTATION            : False")
    print(f"SPLUNK_INDEX_SCOPE        : {args.splunk_index}")
    print()

    for i, p in enumerate(rule_files, 1):
        meta = by_rule_file[p.name]
        sigma_text = p.read_text(encoding="utf-8")
        sigma_hash = "sha256:" + sha256_bytes(sigma_text.encode("utf-8"))

        expected_hash = meta.get("rule_sha256")
        source_hash_match = expected_hash in (None, "", sigma_hash)

        base = {
            "rule_file": p.name,
            "rule_id": meta.get("rule_id"),
            "technique_id": meta.get("technique_id"),
            "technique_name": meta.get("technique_name"),
            "analytic_id": meta.get("analytic_id"),
            "path_id": meta.get("path_id"),
            "plan_id": meta.get("plan_id"),
            "generation_unit_id": meta.get("generation_unit_id"),
            "keyword_mode": meta.get("keyword_mode"),
            "keywords": meta.get("keywords") or [],
            "grounded_event_ids": meta.get("grounded_event_ids") or [],
            "grounded_log_sources": meta.get("grounded_log_sources") or [],
            "baseline_production_ready": meta.get("production_ready"),
            "sigma_sha256": sigma_hash,
            "sigma_hash_matches_index": source_hash_match,
            "sigma_mutated_before_compile": False,
        }

        mode = meta.get("keyword_mode") or "UNKNOWN"
        mode_counts[mode] += 1

        try:
            collection = SigmaCollection.from_yaml(sigma_text)
            queries = backend.convert(collection)
            queries = [q for q in queries if isinstance(q, str)]
            query_count_hist[len(queries)] += 1

            if not queries:
                raise RuntimeError("Splunk backend returned no query")

            compile_success += 1
            if any(q.strip() for q in queries):
                nonempty_success += 1

            joined = "\n\n".join(q.strip() for q in queries if q.strip())
            bad_cmds = dangerous_commands(joined)
            dangerous_total += len(bad_cmds)

            if not source_hash_match:
                classification = "COMPILED_PROVENANCE_HASH_MISMATCH"
                execution_candidate = False
            elif bad_cmds:
                classification = "COMPILED_BLOCKED_DANGEROUS_COMMAND"
                execution_candidate = False
            elif mode == "GROUNDED_LITERAL_KEYWORDS":
                classification = "COMPILED_LITERAL_RUNTIME_CANDIDATE"
                execution_candidate = True
            elif mode == "GROUNDED_DESCRIPTION_FALLBACK":
                classification = "COMPILED_DESCRIPTION_FALLBACK_NOT_EXECUTION_READY"
                execution_candidate = False
            else:
                classification = "COMPILED_UNKNOWN_MODE_REVIEW_REQUIRED"
                execution_candidate = False

            class_counts[classification] += 1

            scoped = (
                f'search index={args.splunk_index} earliest={args.earliest} ({joined})'
                if joined
                else ""
            )

            record = {
                **base,
                "compile_success": True,
                "query_count": len(queries),
                "spl_queries": queries,
                "spl": joined,
                "scoped_spl": scoped,
                "dangerous_pipe_commands": bad_cmds,
                "classification": classification,
                "runtime_execution_candidate": execution_candidate,
                "runtime_result_status": "NOT_EXECUTED",
                "runtime_note": (
                    "Raw BOTS v3 runtime execution must be interpreted separately from compilation "
                    "because current Splunk 9.4.13 raw-event searchability is incomplete."
                ),
                "error": None,
            }
            compiled_rows.append(record)

            stem = p.stem
            (spl_dir / f"{stem}.spl").write_text(joined + "\n", encoding="utf-8", newline="\n")
            (scoped_dir / f"{stem}.spl").write_text(scoped + "\n", encoding="utf-8", newline="\n")

        except Exception as exc:
            compile_fail += 1
            classification = "COMPILE_FAIL"
            class_counts[classification] += 1
            error = f"{type(exc).__name__}: {exc}"
            record = {
                **base,
                "compile_success": False,
                "query_count": 0,
                "spl_queries": [],
                "spl": None,
                "scoped_spl": None,
                "dangerous_pipe_commands": [],
                "classification": classification,
                "runtime_execution_candidate": False,
                "runtime_result_status": "NOT_EXECUTED",
                "error": error,
            }
            compiled_rows.append(record)
            error_rows.append(record)

        if i <= 5 or i % 50 == 0 or i == len(rule_files):
            print(
                f"PROGRESS {i}/{len(rule_files)} "
                f"{p.name} "
                f"MODE {mode} "
                f"CLASS {compiled_rows[-1]['classification']}"
            )

    compiled_path = out_dir / "compiled_queries.jsonl"
    errors_path = out_dir / "compilation_errors.jsonl"
    summary_path = out_dir / "summary.json"
    manifest_path = out_dir / "manifest.json"

    write_jsonl(compiled_path, compiled_rows)
    write_jsonl(errors_path, error_rows)

    literal_candidates = class_counts["COMPILED_LITERAL_RUNTIME_CANDIDATE"]
    desc_fallback = class_counts["COMPILED_DESCRIPTION_FALLBACK_NOT_EXECUTION_READY"]

    summary = {
        "status": "PASS" if compile_fail == 0 and compile_success == 540 else "FAIL",
        "input_rules": len(rule_files),
        "compile_success": compile_success,
        "compile_fail": compile_fail,
        "nonempty_spl": nonempty_success,
        "sigma_mutation_used": False,
        "keyword_mode_counts": dict(sorted(mode_counts.items())),
        "classification_counts": dict(sorted(class_counts.items())),
        "runtime_execution_candidates": literal_candidates,
        "description_fallback_not_execution_ready": desc_fallback,
        "dangerous_pipe_command_count": dangerous_total,
        "query_count_histogram": {str(k): v for k, v in sorted(query_count_hist.items())},
        "splunk_index_scope": args.splunk_index,
        "runtime_execution_performed": False,
        "runtime_environment_note": (
            "Compilation is evaluated independently from runtime findings. "
            "BOTS v3 bucket manifest contains 2,030,269 events; current Splunk 9.4.13 "
            "raw-event search visibility is incomplete, so zero-result raw searches are not "
            "treated as conclusive negative findings."
        ),
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    manifest = {
        "artifact": "splunk_sigma_compilation",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "pysigma_version": metadata.version("pySigma"),
        "pysigma_backend_splunk_version": metadata.version("pysigma-backend-splunk"),
        "input_index_file": str(index_file),
        "input_index_sha256": "sha256:" + sha256_file(index_file),
        "input_rules_dir": str(rules_dir),
        "input_rule_count": len(rule_files),
        "input_rule_aggregate_sha256": "sha256:" + sha256_bytes(
            "\n".join(
                f"{p.name}:{sha256_file(p)}" for p in rule_files
            ).encode("utf-8")
        ),
        "output_compiled_queries": str(compiled_path),
        "output_compilation_errors": str(errors_path),
        "output_summary": str(summary_path),
        "output_spl_dir": str(spl_dir),
        "output_scoped_spl_dir": str(scoped_dir),
        "sigma_mutation_used": False,
        "automatic_repair_used": False,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print()
    print("===== SUMMARY =====")
    print(f"COMPILE_SUCCESS           : {compile_success}/540")
    print(f"COMPILE_FAIL              : {compile_fail}/540")
    print(f"NONEMPTY_SPL              : {nonempty_success}/540")
    print(f"LITERAL_RUNTIME_CANDIDATE : {literal_candidates}")
    print(f"DESCRIPTION_FALLBACK      : {desc_fallback}")
    print(f"DANGEROUS_COMMANDS        : {dangerous_total}")
    print(f"STATUS                    : {summary['status']}")
    print(f"OUTPUT_DIR                : {out_dir}")


if __name__ == "__main__":
    main()
