"""
Post Task 46 runtime handoff adapter.

This module is intentionally read-only.

It consumes the validated Post Task 46 handoff artifacts and exposes
runtime lineage without re-running compilation or Splunk execution.

Architecture:

    Detection Plan
        ↓
    Sigma / Compiled SPL
        ↓
    Runtime Queue
        ↓
    Runtime Result
        ↓
    Candidate Disposition

Important:
- No database writes.
- No runtime execution.
- No mutation of handoff artifacts.
- Zero-result runtime visibility remains INCONCLUSIVE.
- Deferred candidates remain NOT_EXECUTED / DEFERRED.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_HANDOFF_ROOT = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "post_task46_handoff"
)


@dataclass(frozen=True)
class RuntimeArtifact:
    technique_id: str
    technique_name: str
    analytic_id: str
    rule_id: str
    path_id: str
    plan_id: str | None
    classification: str
    keyword_mode: str | None
    compiled_spl: str | None
    runtime_execution_candidate: bool
    queue_present: bool
    result_present: bool
    execution_status: str
    match_count: int
    disposition: str | None
    zero_result_interpretation: str | None


class PostTask46RuntimeAdapter:
    """
    Read-only adapter over the Post Task 46 runtime handoff.

    The adapter builds lineage from:
      - compiled_queries.jsonl
      - runtime_execution_queue_v1.jsonl
      - runtime_execution_results_v1.jsonl
      - runtime_candidate_dispositions_v1.jsonl
    """

    def __init__(self, handoff_root: Path | str | None = None) -> None:
        self.root = Path(handoff_root or DEFAULT_HANDOFF_ROOT)

        self.compiled_path = (
            self.root / "Splunk" / "Compilation" / "compiled_queries.jsonl"
        )
        self.queue_path = (
            self.root
            / "Splunk"
            / "Runtime_Execution"
            / "runtime_execution_queue_v1.jsonl"
        )
        self.results_path = (
            self.root
            / "Splunk"
            / "Runtime_Execution"
            / "runtime_results_v1"
            / "runtime_execution_results_v1.jsonl"
        )
        self.dispositions_path = (
            self.root
            / "Hunt_Findings"
            / "Validated_Findings"
            / "runtime_candidate_dispositions_v1.jsonl"
        )

        self._loaded = False
        self._compiled: dict[str, dict[str, Any]] = {}
        self._queue: dict[str, dict[str, Any]] = {}
        self._results: dict[str, dict[str, Any]] = {}
        self._dispositions: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _load_jsonl(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []

        rows: list[dict[str, Any]] = []

        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()

                if not line:
                    continue

                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSONL at {path}:{line_number}: {exc}"
                    ) from exc

                if not isinstance(value, dict):
                    raise ValueError(
                        f"Expected JSON object at {path}:{line_number}"
                    )

                rows.append(value)

        return rows

    def load(self) -> None:
        """Load the handoff into memory without modifying source files."""

        if self._loaded:
            return

        compiled = self._load_jsonl(self.compiled_path)
        queue = self._load_jsonl(self.queue_path)
        results = self._load_jsonl(self.results_path)
        dispositions = self._load_jsonl(self.dispositions_path)

        self._compiled = {
            row["rule_id"]: row
            for row in compiled
            if row.get("rule_id")
        }

        self._queue = {
            row["rule_id"]: row
            for row in queue
            if row.get("rule_id")
        }

        self._results = {
            row["rule_id"]: row
            for row in results
            if row.get("rule_id")
        }

        self._dispositions = {
            row["path_id"]: row
            for row in dispositions
            if row.get("path_id")
        }

        self._loaded = True

    def get(self, rule_id: str) -> RuntimeArtifact | None:
        """
        Return the complete runtime lineage for one Sigma rule.

        Missing queue/result is represented explicitly instead of being
        interpreted as a runtime failure.
        """

        self.load()

        compiled = self._compiled.get(rule_id)

        if not compiled:
            return None

        queue = self._queue.get(rule_id)
        result = self._results.get(rule_id)

        path_id = compiled.get("path_id", "")

        disposition = self._dispositions.get(path_id)

        if result:
            execution_status = result.get(
                "execution_status",
                "UNKNOWN",
            )
            match_count = int(result.get("match_count") or 0)
            zero_interpretation = result.get(
                "zero_result_interpretation"
            )
        elif queue:
            execution_status = queue.get(
                "execution_result_status",
                "PENDING",
            )
            match_count = 0
            zero_interpretation = queue.get(
                "zero_result_interpretation"
            )
        else:
            execution_status = "NOT_EXECUTED"
            match_count = 0
            zero_interpretation = None

        return RuntimeArtifact(
            technique_id=compiled.get("technique_id", ""),
            technique_name=compiled.get("technique_name", ""),
            analytic_id=compiled.get("analytic_id", ""),
            rule_id=compiled.get("rule_id", ""),
            path_id=path_id,
            plan_id=compiled.get("plan_id"),
            classification=compiled.get("classification", ""),
            keyword_mode=compiled.get("keyword_mode"),
            compiled_spl=(
                compiled.get("spl")
                or compiled.get("scoped_spl")
            ),
            runtime_execution_candidate=bool(
                compiled.get("runtime_execution_candidate")
            ),
            queue_present=queue is not None,
            result_present=result is not None,
            execution_status=execution_status,
            match_count=match_count,
            disposition=(
                disposition.get("disposition")
                if disposition
                else None
            ),
            zero_result_interpretation=zero_interpretation,
        )

    def all(self) -> list[RuntimeArtifact]:
        """Return all compiled rules with their runtime lineage."""

        self.load()

        artifacts: list[RuntimeArtifact] = []

        for rule_id in self._compiled:
            artifact = self.get(rule_id)

            if artifact is not None:
                artifacts.append(artifact)

        return artifacts

    def summary(self) -> dict[str, Any]:
        """Return a read-only operational summary."""

        self.load()

        compiled_count = len(self._compiled)

        runtime_candidates = sum(
            bool(row.get("runtime_execution_candidate"))
            for row in self._compiled.values()
        )

        queued_count = sum(
            rule_id in self._queue
            for rule_id in self._compiled
        )

        result_count = sum(
            rule_id in self._results
            for rule_id in self._compiled
        )

        status_counts: dict[str, int] = {}

        for row in self._results.values():
            status = row.get("execution_status", "UNKNOWN")
            status_counts[status] = status_counts.get(status, 0) + 1

        deferred_count = max(runtime_candidates - queued_count, 0)

        return {
            "source": "post_task46_handoff",
            "compiled_rules": compiled_count,
            "runtime_candidates": runtime_candidates,
            "queued_runtime_candidates": queued_count,
            "runtime_results": result_count,
            "deferred_runtime_candidates": deferred_count,
            "execution_status_counts": status_counts,
            "handoff_root": str(self.root),
        }


_adapter: PostTask46RuntimeAdapter | None = None


def get_post_task46_runtime_adapter() -> PostTask46RuntimeAdapter:
    """Return the process-local read-only adapter."""

    global _adapter

    if _adapter is None:
        _adapter = PostTask46RuntimeAdapter()

    return _adapter
