from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]


REQUIREMENTS_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "knowledge"
    / "attack_data_component_requirements_v2.jsonl"
)

TECHNIQUES_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "knowledge"
    / "attack_techniques_active.jsonl"
)

EVIDENCE_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "canonical"
    / "canonical_telemetry_evidence_v2.jsonl"
)

INVENTORY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "canonical"
    / "canonical_telemetry_inventory_v1.jsonl"
)

ENVIRONMENT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "environment_profile_product_v2.json"
)

PLATFORM_POLICY_FILE = (
    PROJECT_ROOT
    / "config"
    / "ingestion"
    / "platform_discovery_policy_v2.json"
)

SOURCE_POLICY_FILE = (
    PROJECT_ROOT
    / "config"
    / "telemetry"
    / "source_identity_policy_v2.json"
)


OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "resolved"
)

REPORT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "telemetry"
)

COMPONENT_JSONL = (
    OUTPUT_DIR
    / "attack_data_component_evidence_v2.jsonl"
)

COMPONENT_CSV = (
    OUTPUT_DIR
    / "attack_data_component_evidence_v2.csv"
)

TECHNIQUE_JSONL = (
    OUTPUT_DIR
    / "technique_telemetry_evidence_v2.jsonl"
)

TECHNIQUE_CSV = (
    OUTPUT_DIR
    / "technique_telemetry_evidence_v2.csv"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "generic_attack_telemetry_evidence_v2_summary.json"
)


def read_jsonl(path):
    rows = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:

        for line_number, line in enumerate(
            f,
            start=1,
        ):

            line = line.strip()

            if not line:
                continue

            try:
                value = json.loads(line)

            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL at "
                    f"{path}:{line_number}: {exc}"
                ) from exc

            if not isinstance(value, dict):
                raise RuntimeError(
                    f"Expected object at "
                    f"{path}:{line_number}"
                )

            rows.append(value)

    return rows


def read_json(path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def normalize_event_id(value):
    if value is None:
        return None

    text = str(
        value
    ).strip()

    if not text:
        return None

    try:
        return str(
            int(float(text))
        )
    except ValueError:
        return text.lower()


def build_alias_map(policy):
    result = {}

    for canonical, aliases in (
        policy.get(
            "alias_groups",
            {}
        ).items()
    ):

        canonical_key = (
            str(canonical)
            .strip()
            .lower()
        )

        result[
            canonical_key
        ] = canonical_key

        for alias in aliases:

            key = re.sub(
                r"[^a-z0-9]+",
                "",
                str(alias).lower(),
            )

            if key:
                result[key] = (
                    canonical_key
                )

    return result


def tokens(
    value,
    alias_map,
    noise_tokens,
):
    if not value:
        return set()

    raw_tokens = re.findall(
        r"[a-z0-9]+",
        str(value).lower(),
    )

    result = set()

    for token in raw_tokens:

        if token.isdigit():
            continue

        compact = re.sub(
            r"[^a-z0-9]+",
            "",
            token,
        )

        normalized = alias_map.get(
            compact,
            compact,
        )

        if (
            normalized
            and normalized
            not in noise_tokens
        ):
            result.add(
                normalized
            )

    return result


def compact(value):
    return re.sub(
        r"[^a-z0-9]+",
        "",
        str(value or "").lower(),
    )


def source_match_score(
    required_value,
    candidate_value,
    alias_map,
    noise_tokens,
    alias_group_names,
):
    if (
        not required_value
        or not candidate_value
    ):
        return 0.0, "none"

    req_compact = compact(
        required_value
    )

    cand_compact = compact(
        candidate_value
    )

    if (
        req_compact
        and req_compact == cand_compact
    ):
        return 1.0, "identity_exact"

    req_tokens = tokens(
        required_value,
        alias_map,
        noise_tokens,
    )

    cand_tokens = tokens(
        candidate_value,
        alias_map,
        noise_tokens,
    )

    if not req_tokens or not cand_tokens:
        return 0.0, "none"

    overlap = (
        req_tokens
        & cand_tokens
    )

    if not overlap:
        return 0.0, "none"

    coverage = (
        len(overlap)
        / len(req_tokens)
    )

    precision = (
        len(overlap)
        / len(cand_tokens)
    )

    score = (
        0.65 * coverage
        + 0.35 * precision
    )

    if (
        overlap
        & alias_group_names
    ):
        score = max(
            score,
            0.82,
        )

    if (
        len(cand_tokens) == 1
        and next(
            iter(cand_tokens)
        ) in req_tokens
    ):
        score = max(
            score,
            0.72,
        )

    return (
        round(
            min(score, 1.0),
            4,
        ),
        "token_overlap",
    )


def derive_platforms(
    values,
    explicit_hint,
    platform_rules,
):
    result = set()

    if explicit_hint:
        result.add(
            str(
                explicit_hint
            ).strip()
        )

    source_type = str(
        values.get(
            "source_type"
        )
        or ""
    ).lower()

    source_name = str(
        values.get(
            "source_name"
        )
        or ""
    ).lower()

    for rule in platform_rules:

        field = rule.get(
            "field"
        )

        if field == "source_type":
            value = source_type

        elif field == "source_name":
            value = source_name

        else:
            continue

        if not value:
            continue

        for pattern in rule.get(
            "patterns",
            []
        ):

            if (
                str(pattern).lower()
                in value
            ):
                result.add(
                    rule[
                        "platform"
                    ]
                )
                break

    result.discard(
        "PRE"
    )

    return sorted(
        item
        for item in result
        if item
    )


def make_source_candidate(
    *,
    candidate_id,
    dataset_name,
    identity,
    identity_kind,
    platforms,
    reference,
    alias_map,
    noise_tokens,
):
    identity = str(
        identity or ""
    ).strip()

    if not identity:
        return None

    return {
        "candidate_id": (
            candidate_id
        ),

        "dataset_name": (
            dataset_name
        ),

        "identity": (
            identity
        ),

        "identity_kind": (
            identity_kind
        ),

        "platforms": sorted(
            set(
                platforms
                or []
            )
        ),

        "reference": reference,

        "tokens": sorted(
            tokens(
                identity,
                alias_map,
                noise_tokens,
            )
        ),
    }


def best_source_match(
    requirement_source,
    candidates,
    alias_map,
    noise_tokens,
    alias_group_names,
    minimum_score,
):
    best = None

    for candidate in candidates:

        score, method = (
            source_match_score(
                requirement_source,
                candidate[
                    "identity"
                ],
                alias_map,
                noise_tokens,
                alias_group_names,
            )
        )

        if score < minimum_score:
            continue

        item = {
            **candidate,
            "match_score": score,
            "match_method": method,
        }

        if (
            best is None
            or item[
                "match_score"
            ]
            > best[
                "match_score"
            ]
        ):
            best = item

    return best


def main():
    required_files = [
        REQUIREMENTS_FILE,
        TECHNIQUES_FILE,
        EVIDENCE_FILE,
        INVENTORY_FILE,
        ENVIRONMENT_FILE,
        PLATFORM_POLICY_FILE,
        SOURCE_POLICY_FILE,
    ]

    for path in required_files:

        if not path.exists():
            raise FileNotFoundError(
                f"Missing required input: "
                f"{path}"
            )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    components = read_jsonl(
        REQUIREMENTS_FILE
    )

    techniques = read_jsonl(
        TECHNIQUES_FILE
    )

    evidence = read_jsonl(
        EVIDENCE_FILE
    )

    inventory = read_jsonl(
        INVENTORY_FILE
    )

    environment = read_json(
        ENVIRONMENT_FILE
    )

    platform_policy = read_json(
        PLATFORM_POLICY_FILE
    )

    source_policy = read_json(
        SOURCE_POLICY_FILE
    )

    validation_errors = []

    if len(components) != 109:
        validation_errors.append(
            f"Expected 109 data components, "
            f"found {len(components)}"
        )

    if len(techniques) != 697:
        validation_errors.append(
            f"Expected 697 ATT&CK techniques, "
            f"found {len(techniques)}"
        )

    observed_platforms = set(
        environment.get(
            "observed_platforms",
            []
        )
    )

    unknown_platforms = set(
        environment.get(
            "unknown_platform_presence",
            []
        )
    )

    platform_rules = (
        platform_policy.get(
            "rules",
            []
        )
    )

    alias_map = build_alias_map(
        source_policy
    )

    noise_tokens = set(
        str(value).lower()
        for value in source_policy.get(
            "noise_tokens",
            []
        )
    )

    alias_group_names = set(
        source_policy.get(
            "alias_groups",
            {}
        ).keys()
    )

    source_min_score = float(
        source_policy[
            "source_activity_min_score"
        ]
    )

    exact_min_score = float(
        source_policy[
            "exact_event_source_min_score"
        ]
    )

    # -------------------------------------------------
    # Build generic observed-source candidate universe.
    # -------------------------------------------------

    source_candidates = []

    for row in inventory:

        platforms = derive_platforms(
            {
                "source_type": (
                    row.get(
                        "source_type"
                    )
                ),
                "source_name": (
                    row.get(
                        "source_name"
                    )
                ),
            },
            row.get(
                "platform_hint"
            ),
            platform_rules,
        )

        for field in [
            "source_type",
            "source_name",
        ]:

            candidate = (
                make_source_candidate(
                    candidate_id=(
                        row.get(
                            "record_id"
                        )
                    ),
                    dataset_name=(
                        row.get(
                            "dataset_name"
                        )
                    ),
                    identity=(
                        row.get(field)
                    ),
                    identity_kind=field,
                    platforms=platforms,
                    reference=(
                        row.get(
                            "record_id"
                        )
                    ),
                    alias_map=alias_map,
                    noise_tokens=noise_tokens,
                )
            )

            if candidate:
                source_candidates.append(
                    candidate
                )

    operational_fields = [
        row
        for row in evidence
        if (
            row.get(
                "evidence_role"
            ) == "operational"
            and row.get(
                "evidence_kind"
            ) == "field_observation"
            and row.get(
                "observed"
            ) is True
        )
    ]

    for row in operational_fields:

        source_type = row.get(
            "telemetry_source_type"
        )

        platforms = derive_platforms(
            {
                "source_type": (
                    source_type
                ),
                "source_name": None,
            },
            row.get(
                "platform_hint"
            ),
            platform_rules,
        )

        candidate = make_source_candidate(
            candidate_id=(
                row.get(
                    "evidence_id"
                )
            ),
            dataset_name=(
                row.get(
                    "dataset_name"
                )
            ),
            identity=source_type,
            identity_kind=(
                "field_evidence_source_type"
            ),
            platforms=platforms,
            reference=(
                row.get(
                    "evidence_id"
                )
            ),
            alias_map=alias_map,
            noise_tokens=noise_tokens,
        )

        if candidate:
            source_candidates.append(
                candidate
            )

    exact_events = [
        row
        for row in evidence
        if (
            row.get(
                "evidence_role"
            ) == "operational"
            and row.get(
                "evidence_kind"
            ) == "exact_event_observation"
            and row.get(
                "observed"
            ) is True
        )
    ]

    exact_event_index = defaultdict(
        list
    )

    for row in exact_events:

        event_id = normalize_event_id(
            row.get(
                "event_id"
            )
        )

        if not event_id:
            continue

        platforms = derive_platforms(
            {
                "source_type": (
                    row.get(
                        "telemetry_source_type"
                    )
                ),
                "source_name": None,
            },
            row.get(
                "platform_hint"
            ),
            platform_rules,
        )

        identity_parts = [
            row.get(
                "provider"
            ),
            row.get(
                "channel"
            ),
            row.get(
                "telemetry_source_type"
            ),
        ]

        identity = " ".join(
            str(value)
            for value in identity_parts
            if value
        )

        exact_event_index[
            event_id
        ].append({
            "evidence_id": (
                row.get(
                    "evidence_id"
                )
            ),

            "dataset_name": (
                row.get(
                    "dataset_name"
                )
            ),

            "event_id": (
                event_id
            ),

            "provider": (
                row.get(
                    "provider"
                )
            ),

            "channel": (
                row.get(
                    "channel"
                )
            ),

            "canonical_category": (
                row.get(
                    "canonical_category"
                )
            ),

            "canonical_action": (
                row.get(
                    "canonical_action"
                )
            ),

            "identity": identity,

            "platforms": platforms,
        })

        candidate = make_source_candidate(
            candidate_id=(
                row.get(
                    "evidence_id"
                )
            ),
            dataset_name=(
                row.get(
                    "dataset_name"
                )
            ),
            identity=identity,
            identity_kind=(
                "exact_event_identity"
            ),
            platforms=platforms,
            reference=(
                row.get(
                    "evidence_id"
                )
            ),
            alias_map=alias_map,
            noise_tokens=noise_tokens,
        )

        if candidate:
            source_candidates.append(
                candidate
            )

    # De-duplicate candidates.
    dedup = {}

    for candidate in source_candidates:

        key = (
            candidate.get(
                "dataset_name"
            ),
            candidate.get(
                "identity"
            ),
            tuple(
                candidate.get(
                    "platforms",
                    []
                )
            ),
        )

        if key not in dedup:
            dedup[key] = candidate

    source_candidates = list(
        dedup.values()
    )

    # -------------------------------------------------
    # Resolve all 109 ATT&CK Data Components.
    # -------------------------------------------------

    component_rows = []

    total_exact_requirement_matches = 0
    total_source_requirement_matches = 0

    for component in components:

        component_id = component[
            "component_id"
        ]

        component_name = component[
            "component_name"
        ]

        requirements = component.get(
            "operational_requirements",
            []
        )

        requirement_results = []

        for requirement in requirements:

            requirement_type = (
                requirement[
                    "requirement_type"
                ]
            )

            required_source = (
                requirement.get(
                    "log_source_name"
                )
            )

            source_match = (
                best_source_match(
                    required_source,
                    source_candidates,
                    alias_map,
                    noise_tokens,
                    alias_group_names,
                    source_min_score,
                )
                if required_source
                else None
            )

            exact_matches = []

            if requirement_type == (
                "exact_event"
            ):

                for event_id in (
                    requirement.get(
                        "exact_event_ids"
                    )
                    or []
                ):

                    normalized_id = (
                        normalize_event_id(
                            event_id
                        )
                    )

                    for candidate in (
                        exact_event_index.get(
                            normalized_id,
                            []
                        )
                    ):

                        if required_source:

                            score, method = (
                                source_match_score(
                                    required_source,
                                    candidate[
                                        "identity"
                                    ],
                                    alias_map,
                                    noise_tokens,
                                    alias_group_names,
                                )
                            )

                            if (
                                score
                                < exact_min_score
                            ):
                                continue

                        else:

                            score = 1.0
                            method = (
                                "event_id_only"
                            )

                        exact_matches.append({
                            **candidate,

                            "source_match_score": (
                                score
                            ),

                            "source_match_method": (
                                method
                            ),
                        })

                if exact_matches:

                    status = (
                        "exact_event_observed"
                    )

                    total_exact_requirement_matches += 1

                elif source_match:

                    status = (
                        "source_available_"
                        "event_requirement_unverified"
                    )

                    total_source_requirement_matches += 1

                else:

                    status = (
                        "required_source_not_observed"
                    )

            elif requirement_type == (
                "source_activity"
            ):

                if source_match:

                    status = (
                        "source_available_"
                        "activity_unverified"
                    )

                    total_source_requirement_matches += 1

                else:

                    status = (
                        "required_source_not_observed"
                    )

            else:

                status = (
                    "requirement_unspecified"
                )

            matched_platforms = set()

            datasets = set()

            exact_evidence_ids = []

            for match in exact_matches:

                matched_platforms.update(
                    match.get(
                        "platforms",
                        []
                    )
                )

                if match.get(
                    "dataset_name"
                ):
                    datasets.add(
                        match[
                            "dataset_name"
                        ]
                    )

                if match.get(
                    "evidence_id"
                ):
                    exact_evidence_ids.append(
                        match[
                            "evidence_id"
                        ]
                    )

            if source_match:

                matched_platforms.update(
                    source_match.get(
                        "platforms",
                        []
                    )
                )

                if source_match.get(
                    "dataset_name"
                ):
                    datasets.add(
                        source_match[
                            "dataset_name"
                        ]
                    )

            requirement_results.append({
                "requirement_id": (
                    requirement.get(
                        "requirement_id"
                    )
                ),

                "requirement_type": (
                    requirement_type
                ),

                "log_source_name": (
                    required_source
                ),

                "channel": (
                    requirement.get(
                        "channel"
                    )
                ),

                "exact_event_ids": (
                    requirement.get(
                        "exact_event_ids"
                    )
                    or []
                ),

                "evidence_status": (
                    status
                ),

                "matched_platforms": sorted(
                    matched_platforms
                ),

                "matched_datasets": sorted(
                    datasets
                ),

                "source_match": (
                    source_match
                ),

                "exact_event_matches": (
                    exact_matches
                ),

                "exact_event_evidence_ids": (
                    sorted(
                        set(
                            exact_evidence_ids
                        )
                    )
                ),
            })

        if not requirements:

            best_status = (
                "requirement_unspecified"
            )

        elif any(
            row[
                "evidence_status"
            ]
            == "exact_event_observed"
            for row in requirement_results
        ):

            best_status = (
                "exact_event_observed"
            )

        elif any(
            row[
                "evidence_status"
            ].startswith(
                "source_available_"
            )
            for row in requirement_results
        ):

            best_status = (
                "source_available_"
                "requirement_unverified"
            )

        else:

            best_status = (
                "not_observed"
            )

        exact_event_evidence = any(
            row[
                "evidence_status"
            ]
            == "exact_event_observed"
            for row in requirement_results
        )

        any_source_evidence = any(
            (
                row[
                    "evidence_status"
                ]
                == "exact_event_observed"
                or row[
                    "evidence_status"
                ].startswith(
                    "source_available_"
                )
            )
            for row in requirement_results
        )

        component_platforms = sorted({
            platform
            for row in requirement_results
            for platform in row[
                "matched_platforms"
            ]
        })

        evidence_datasets = sorted({
            dataset
            for row in requirement_results
            for dataset in row[
                "matched_datasets"
            ]
        })

        component_rows.append({
            "resolver_version": "2.0",

            "component_id": (
                component_id
            ),

            "component_name": (
                component_name
            ),

            "operational_requirement_status": (
                component[
                    "operational_requirement_status"
                ]
            ),

            "requirement_count": (
                len(requirements)
            ),

            "exact_event_requirement_count": (
                component[
                    "exact_event_requirement_count"
                ]
            ),

            "source_activity_requirement_count": (
                component[
                    "source_activity_requirement_count"
                ]
            ),

            "best_evidence_status": (
                best_status
            ),

            "exact_event_evidence": (
                exact_event_evidence
            ),

            "any_source_evidence": (
                any_source_evidence
            ),

            "matched_platforms": (
                component_platforms
            ),

            "evidence_datasets": (
                evidence_datasets
            ),

            "requirement_results": (
                requirement_results
            ),

            "semantics": (
                "Exact-event evidence verifies only "
                "the specified telemetry primitive. "
                "Source availability does not prove "
                "that the ATT&CK-described activity "
                "occurred."
            ),
        })

    component_map = {
        row[
            "component_id"
        ]: row
        for row in component_rows
    }

    # Exact-event overclaim validation.
    for component in component_rows:

        for result in component[
            "requirement_results"
        ]:

            if (
                result[
                    "evidence_status"
                ]
                == "exact_event_observed"
                and not result[
                    "exact_event_matches"
                ]
            ):

                validation_errors.append(
                    f"{component['component_id']}: "
                    f"exact-event status without "
                    f"exact-event evidence"
                )

    # -------------------------------------------------
    # Resolve every one of the 697 techniques.
    #
    # Evidence must be grounded in a platform that is
    # observed for THIS technique in the environment.
    # Unscoped telemetry is retained but cannot prove
    # current-environment readiness.
    # -------------------------------------------------

    technique_rows = []

    for technique in techniques:

        technique_id = technique[
            "technique_id"
        ]

        platforms = set(
            technique.get(
                "platforms"
            )
            or []
        )

        runtime_platforms = (
            platforms - {"PRE"}
        )

        observed_matches = sorted(
            runtime_platforms
            & observed_platforms
        )

        unknown_matches = sorted(
            runtime_platforms
            & unknown_platforms
        )

        if observed_matches:

            environment_scope = (
                "current_environment_evaluable"
            )

            target_platforms = set(
                observed_matches
            )

        elif unknown_matches:

            environment_scope = (
                "environment_presence_unknown"
            )

            target_platforms = set()

        elif (
            "PRE" in platforms
            and not runtime_platforms
        ):

            environment_scope = (
                "pre_attack_scope"
            )

            target_platforms = set()

        elif "PRE" in platforms:

            environment_scope = (
                "pre_attack_scope"
            )

            target_platforms = set()

        else:

            environment_scope = (
                "environment_presence_unknown"
            )

            target_platforms = set()

        component_ids = list(
            technique.get(
                "data_components"
            )
            or []
        )

        component_evaluations = []

        grounded_any_count = 0
        grounded_exact_count = 0
        source_only_count = 0
        unspecified_count = 0

        technique_evidence_datasets = set()

        for component_id in component_ids:

            component = component_map.get(
                component_id
            )

            if component is None:

                validation_errors.append(
                    f"{technique_id}: "
                    f"unknown data component "
                    f"{component_id}"
                )

                continue

            grounded_any = False
            grounded_exact = False

            unscoped_support = False

            matched_platforms = set()

            datasets = set()

            for result in component[
                "requirement_results"
            ]:

                positive = (
                    result[
                        "evidence_status"
                    ]
                    == "exact_event_observed"
                    or result[
                        "evidence_status"
                    ].startswith(
                        "source_available_"
                    )
                )

                if not positive:
                    continue

                result_platforms = set(
                    result[
                        "matched_platforms"
                    ]
                )

                if not result_platforms:

                    unscoped_support = True
                    continue

                intersection = (
                    result_platforms
                    & target_platforms
                )

                if not intersection:
                    continue

                grounded_any = True

                matched_platforms.update(
                    intersection
                )

                datasets.update(
                    result[
                        "matched_datasets"
                    ]
                )

                if (
                    result[
                        "evidence_status"
                    ]
                    == "exact_event_observed"
                ):
                    grounded_exact = True

            if (
                component[
                    "operational_requirement_status"
                ]
                == "requirement_unspecified"
            ):
                unspecified_count += 1

            if (
                environment_scope
                == "current_environment_evaluable"
            ):

                if grounded_any:
                    grounded_any_count += 1

                if grounded_exact:
                    grounded_exact_count += 1

                if (
                    grounded_any
                    and not grounded_exact
                ):
                    source_only_count += 1

            technique_evidence_datasets.update(
                datasets
            )

            component_evaluations.append({
                "component_id": (
                    component_id
                ),

                "component_name": (
                    component[
                        "component_name"
                    ]
                ),

                "global_best_evidence_status": (
                    component[
                        "best_evidence_status"
                    ]
                ),

                "current_environment_grounded": (
                    grounded_any
                ),

                "current_environment_exact_event": (
                    grounded_exact
                ),

                "current_environment_platform_matches": (
                    sorted(
                        matched_platforms
                    )
                ),

                "unscoped_support_retained": (
                    unscoped_support
                ),

                "requirement_unspecified": (
                    component[
                        "operational_requirement_status"
                    ]
                    == "requirement_unspecified"
                ),
            })

        referenced_count = len(
            component_ids
        )

        if environment_scope == (
            "environment_presence_unknown"
        ):

            telemetry_status = (
                "not_assessed_"
                "environment_presence_unknown"
            )

        elif environment_scope == (
            "pre_attack_scope"
        ):

            telemetry_status = (
                "pre_attack_scope"
            )

        elif referenced_count == 0:

            telemetry_status = (
                "requirement_unspecified"
            )

        elif (
            grounded_any_count
            == referenced_count
        ):

            telemetry_status = (
                "full_component_evidence"
            )

        elif grounded_any_count > 0:

            telemetry_status = (
                "partial"
            )

        elif (
            unspecified_count
            == referenced_count
        ):

            telemetry_status = (
                "requirement_unspecified"
            )

        else:

            telemetry_status = (
                "not_observed"
            )

        if referenced_count:

            component_coverage = round(
                (
                    grounded_any_count
                    / referenced_count
                )
                * 100.0,
                6,
            )

            exact_coverage = round(
                (
                    grounded_exact_count
                    / referenced_count
                )
                * 100.0,
                6,
            )

        else:

            component_coverage = None
            exact_coverage = None

        technique_rows.append({
            "resolver_version": "2.0",

            "technique_id": (
                technique_id
            ),

            "technique_name": (
                technique.get(
                    "name"
                )
            ),

            "platforms": sorted(
                platforms
            ),

            "tactics": (
                technique.get(
                    "tactics"
                )
                or []
            ),

            "environment_scope": (
                environment_scope
            ),

            "observed_platform_matches": (
                observed_matches
            ),

            "unknown_platform_matches": (
                unknown_matches
            ),

            "data_components_referenced": (
                referenced_count
            ),

            "data_components_with_any_evidence": (
                grounded_any_count
            ),

            "data_components_with_exact_event_evidence": (
                grounded_exact_count
            ),

            "data_components_source_only": (
                source_only_count
            ),

            "data_components_requirement_unspecified": (
                unspecified_count
            ),

            "component_evidence_coverage_pct": (
                component_coverage
            ),

            "exact_event_component_coverage_pct": (
                exact_coverage
            ),

            "telemetry_evidence_status": (
                telemetry_status
            ),

            "evidence_sources": sorted(
                technique_evidence_datasets
            ),

            "component_evaluations": (
                component_evaluations
            ),

            "occurrence_claim": False,

            "interpretation": (
                "Telemetry evidence represents "
                "environment-grounded observability. "
                "It does not establish that this "
                "ATT&CK technique occurred."
            ),
        })

    # -------------------------------------------------
    # Validation
    # -------------------------------------------------

    if len(component_rows) != 109:
        validation_errors.append(
            f"Expected 109 component outputs, "
            f"found {len(component_rows)}"
        )

    if len(technique_rows) != 697:
        validation_errors.append(
            f"Expected 697 technique outputs, "
            f"found {len(technique_rows)}"
        )

    component_ids = [
        row[
            "component_id"
        ]
        for row in component_rows
    ]

    technique_ids = [
        row[
            "technique_id"
        ]
        for row in technique_rows
    ]

    if len(component_ids) != len(
        set(component_ids)
    ):
        validation_errors.append(
            "Duplicate component IDs"
        )

    if len(technique_ids) != len(
        set(technique_ids)
    ):
        validation_errors.append(
            "Duplicate technique IDs"
        )

    if any(
        row[
            "occurrence_claim"
        ]
        is not False
        for row in technique_rows
    ):
        validation_errors.append(
            "Technique occurrence overclaim"
        )

    scope_counter = Counter(
        row[
            "environment_scope"
        ]
        for row in technique_rows
    )

    current_rows = [
        row
        for row in technique_rows
        if row[
            "environment_scope"
        ]
        == "current_environment_evaluable"
    ]

    current_status_counter = Counter(
        row[
            "telemetry_evidence_status"
        ]
        for row in current_rows
    )

    component_status_counter = Counter(
        row[
            "best_evidence_status"
        ]
        for row in component_rows
    )

    validation_status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    # -------------------------------------------------
    # Write component outputs
    # -------------------------------------------------

    with COMPONENT_JSONL.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as f:

        for row in component_rows:

            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )

    component_csv_fields = [
        "component_id",
        "component_name",
        "operational_requirement_status",
        "requirement_count",
        "exact_event_requirement_count",
        "source_activity_requirement_count",
        "best_evidence_status",
        "exact_event_evidence",
        "any_source_evidence",
        "matched_platforms",
        "evidence_datasets",
    ]

    with COMPONENT_CSV.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=component_csv_fields,
        )

        writer.writeheader()

        for row in component_rows:

            writer.writerow({
                "component_id": (
                    row[
                        "component_id"
                    ]
                ),

                "component_name": (
                    row[
                        "component_name"
                    ]
                ),

                "operational_requirement_status": (
                    row[
                        "operational_requirement_status"
                    ]
                ),

                "requirement_count": (
                    row[
                        "requirement_count"
                    ]
                ),

                "exact_event_requirement_count": (
                    row[
                        "exact_event_requirement_count"
                    ]
                ),

                "source_activity_requirement_count": (
                    row[
                        "source_activity_requirement_count"
                    ]
                ),

                "best_evidence_status": (
                    row[
                        "best_evidence_status"
                    ]
                ),

                "exact_event_evidence": (
                    row[
                        "exact_event_evidence"
                    ]
                ),

                "any_source_evidence": (
                    row[
                        "any_source_evidence"
                    ]
                ),

                "matched_platforms": (
                    " | ".join(
                        row[
                            "matched_platforms"
                        ]
                    )
                ),

                "evidence_datasets": (
                    " | ".join(
                        row[
                            "evidence_datasets"
                        ]
                    )
                ),
            })

    # -------------------------------------------------
    # Write technique outputs
    # -------------------------------------------------

    with TECHNIQUE_JSONL.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as f:

        for row in technique_rows:

            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )

    technique_csv_fields = [
        "technique_id",
        "technique_name",
        "platforms",
        "tactics",
        "environment_scope",
        "observed_platform_matches",
        "unknown_platform_matches",
        "data_components_referenced",
        "data_components_with_any_evidence",
        "data_components_with_exact_event_evidence",
        "data_components_source_only",
        "data_components_requirement_unspecified",
        "component_evidence_coverage_pct",
        "exact_event_component_coverage_pct",
        "telemetry_evidence_status",
        "evidence_sources",
        "occurrence_claim",
    ]

    with TECHNIQUE_CSV.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=technique_csv_fields,
        )

        writer.writeheader()

        for row in technique_rows:

            csv_row = {
                key: row.get(
                    key
                )
                for key in technique_csv_fields
            }

            for field in [
                "platforms",
                "tactics",
                "observed_platform_matches",
                "unknown_platform_matches",
                "evidence_sources",
            ]:

                csv_row[field] = (
                    " | ".join(
                        row.get(
                            field
                        )
                        or []
                    )
                )

            writer.writerow(
                csv_row
            )

    report = {
        "component": (
            "generic_attack_telemetry_evidence_resolver"
        ),

        "version": "2.0",

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "attack_data_components": (
            len(component_rows)
        ),

        "attack_techniques": (
            len(technique_rows)
        ),

        "source_candidates": (
            len(source_candidates)
        ),

        "operational_exact_event_records": (
            len(exact_events)
        ),

        "exact_requirement_matches": (
            total_exact_requirement_matches
        ),

        "source_requirement_matches": (
            total_source_requirement_matches
        ),

        "component_evidence_status_counts": (
            dict(
                sorted(
                    component_status_counter.items()
                )
            )
        ),

        "technique_environment_scope_counts": (
            dict(
                sorted(
                    scope_counter.items()
                )
            )
        ),

        "current_environment_technique_count": (
            len(current_rows)
        ),

        "current_environment_telemetry_status_counts": (
            dict(
                sorted(
                    current_status_counter.items()
                )
            )
        ),

        "semantics": {
            "exact_event_observed": (
                "A canonical exact-event record "
                "matches an explicit ATT&CK "
                "event requirement and compatible "
                "source identity."
            ),

            "source_available_requirement_unverified": (
                "The requested telemetry source "
                "is available, but the descriptive "
                "ATT&CK activity requirement has "
                "not been asserted as observed."
            ),

            "platform_grounding": (
                "Technique evidence counts only "
                "when matched telemetry can be "
                "grounded to an observed platform "
                "supported by that technique."
            ),

            "occurrence_claim": False,

            "broad_capability_is_attck_proof": False,
        },

        "validation_errors": (
            validation_errors
        ),

        "status": (
            validation_status
        ),
    }

    REPORT_OUTPUT.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        "Generic ATT&CK Telemetry "
        "Evidence Resolver v2.0"
    )

    print(
        "-----------------------------------------"
    )

    print(
        f"Data components          : "
        f"{len(component_rows)}"
    )

    print(
        f"ATT&CK techniques        : "
        f"{len(technique_rows)}"
    )

    print(
        f"Source candidates        : "
        f"{len(source_candidates)}"
    )

    print(
        f"Operational exact events : "
        f"{len(exact_events)}"
    )

    print()

    print(
        "Component evidence:"
    )

    for key, value in sorted(
        component_status_counter.items()
    ):

        print(
            f"  {key:<42} {value}"
        )

    print()

    print(
        "Technique environment scope:"
    )

    for key, value in sorted(
        scope_counter.items()
    ):

        print(
            f"  {key:<42} {value}"
        )

    print()

    print(
        "Current-environment telemetry:"
    )

    for key, value in sorted(
        current_status_counter.items()
    ):

        print(
            f"  {key:<30} {value}"
        )

    print()

    print(
        f"Exact requirement matches: "
        f"{total_exact_requirement_matches}"
    )

    print(
        f"Source requirement matches: "
        f"{total_source_requirement_matches}"
    )

    print()

    print(
        "Source availability implies activity: NO"
    )

    print(
        "Broad capability implies ATT&CK DC : NO"
    )

    print(
        "Technique occurrence claimed       : NO"
    )

    print()

    print(
        f"Validation               : "
        f"{validation_status}"
    )

    if validation_errors:

        print()

        for error in validation_errors:

            print(
                " - " + error
            )

    print()

    print(
        f"Component JSONL : {COMPONENT_JSONL}"
    )

    print(
        f"Technique JSONL : {TECHNIQUE_JSONL}"
    )

    print(
        f"Report          : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()