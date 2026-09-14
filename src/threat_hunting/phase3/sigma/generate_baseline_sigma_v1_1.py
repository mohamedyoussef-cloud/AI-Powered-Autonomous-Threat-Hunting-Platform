from __future__ import annotations

import hashlib
import json
import re
import shutil
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]

INPUT_DIR = (
    ROOT
    / "data"
    / "processed"
    / "phase3"
    / "sigma_generation"
)

UNITS_PATH = (
    INPUT_DIR
    / "sigma_generation_units_v1.jsonl"
)

BLOCKED_PATH = (
    INPUT_DIR
    / "sigma_generation_blocked_v1.jsonl"
)

DESIGN_AUDIT_PATH = (
    INPUT_DIR
    / "sigma_generation_design_audit_v1.json"
)

OUTPUT_DIR = (
    ROOT
    / "data"
    / "processed"
    / "phase3"
    / "sigma_baseline"
)

RULES_DIR = (
    OUTPUT_DIR
    / "rules"
)

INDEX_PATH = (
    OUTPUT_DIR
    / "baseline_sigma_results_index_v1.jsonl"
)

ERRORS_PATH = (
    OUTPUT_DIR
    / "baseline_sigma_errors_v1.jsonl"
)

SUMMARY_PATH = (
    OUTPUT_DIR
    / "baseline_sigma_summary_v1.json"
)

AUDIT_PATH = (
    OUTPUT_DIR
    / "baseline_sigma_generation_audit_v1.json"
)


# ============================================================
# IO
# ============================================================

def read_jsonl(path):
    rows = []

    for line_no, line in enumerate(
        path.read_text(
            encoding="utf-8-sig"
        ).splitlines(),
        start=1,
    ):
        line = line.strip()

        if not line:
            continue

        value = json.loads(line)

        if not isinstance(value, dict):
            raise RuntimeError(
                f"Non-object JSONL row: {path}:{line_no}"
            )

        rows.append(value)

    return rows


def write_jsonl(path, rows):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:

        for row in rows:

            handle.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )

            handle.write("\n")


def write_json(path, value):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:

        handle.write(
            json.dumps(
                value,
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            )
        )

        handle.write("\n")


def sha256_text(text):
    return (
        "sha256:"
        + hashlib.sha256(
            text.encode("utf-8")
        ).hexdigest()
    )


# ============================================================
# Minimal deterministic YAML emitter
# ============================================================

def yaml_scalar(value):

    if value is None:
        return "null"

    if value is True:
        return "true"

    if value is False:
        return "false"

    if isinstance(
        value,
        (int, float),
    ):
        return str(value)

    return json.dumps(
        str(value),
        ensure_ascii=False,
    )


def yaml_lines(
    value,
    indent=0,
):
    pad = " " * indent

    if isinstance(value, dict):

        result = []

        for key, item in value.items():

            if isinstance(
                item,
                (dict, list),
            ):

                result.append(
                    f"{pad}{key}:"
                )

                result.extend(
                    yaml_lines(
                        item,
                        indent + 4,
                    )
                )

            else:

                result.append(
                    f"{pad}{key}: "
                    f"{yaml_scalar(item)}"
                )

        return result


    if isinstance(value, list):

        result = []

        for item in value:

            if isinstance(
                item,
                (dict, list),
            ):

                result.append(
                    f"{pad}-"
                )

                result.extend(
                    yaml_lines(
                        item,
                        indent + 4,
                    )
                )

            else:

                result.append(
                    f"{pad}- "
                    f"{yaml_scalar(item)}"
                )

        return result


    return [
        f"{pad}{yaml_scalar(value)}"
    ]


def dump_yaml(value):

    return (
        "\n".join(
            yaml_lines(value)
        )
        + "\n"
    )


# ============================================================
# Event-ID provenance enforcement
# ============================================================

EVENT_REF_RE = re.compile(
    r"(?i)\bEvent\s+IDs?\s*[:=]?\s*"
    r"("
    r"[0-9]{1,6}"
    r"(?:"
    r"\s*(?:,|/|&|\band\b)\s*"
    r"[0-9]{1,6}"
    r")*"
    r")"
)


def explicit_event_ids(text):

    result = set()

    for match in EVENT_REF_RE.finditer(
        text
    ):

        result.update(
            re.findall(
                r"[0-9]{1,6}",
                match.group(1),
            )
        )

    return result


def sanitize_event_refs(
    text,
    allowed,
):

    def replace(match):

        ids = re.findall(
            r"[0-9]{1,6}",
            match.group(1),
        )

        keep = [
            value
            for value in ids
            if value in allowed
        ]

        if not keep:
            return "event telemetry"

        label = (
            "Event ID"
            if len(keep) == 1
            else "Event IDs"
        )

        return (
            label
            + " "
            + ", ".join(keep)
        )


    return EVENT_REF_RE.sub(
        replace,
        text,
    )


# ============================================================
# Grounded technical keyword extraction
# ============================================================

def add_candidate(
    result,
    seen,
    value,
):

    value = value.strip()

    if len(value) < 3:
        return

    key = value.lower()

    if key in seen:
        return

    seen.add(key)
    result.append(value)


def extract_grounded_keywords(
    description,
    allowed_event_ids,
):
    """
    Extract only literals already present in the
    grounded analytic description.

    No fields or external technical values are introduced.
    """

    clean = sanitize_event_refs(
        description,
        allowed_event_ids,
    )

    result = []
    seen = set()


    # Explicit grounded Event-ID expressions.
    for match in EVENT_REF_RE.finditer(
        clean
    ):
        add_candidate(
            result,
            seen,
            match.group(0),
        )


    # Quoted or backticked technical literals.
    for value in re.findall(
        r"[`'\"]([^`'\"]{2,120})[`'\"]",
        clean,
    ):
        add_candidate(
            result,
            seen,
            value,
        )


    # Executables.
    for value in re.findall(
        r"(?i)\b[A-Za-z0-9_.-]+\.exe\b",
        clean,
    ):
        add_candidate(
            result,
            seen,
            value,
        )


    # Unix-like paths.
    for value in re.findall(
        r"(?<!\w)/(?:etc|var|usr|opt|tmp|home|root)"
        r"/[A-Za-z0-9_./$-]+",
        clean,
    ):
        add_candidate(
            result,
            seen,
            value,
        )


    # Registry paths.
    for value in re.findall(
        r"(?i)\bHK(?:LM|CU|CR|U|CC)"
        r"\\[A-Za-z0-9_\\./ $()-]+",
        clean,
    ):
        add_candidate(
            result,
            seen,
            value,
        )


    # DLL/API-style expressions.
    for value in re.findall(
        r"\b[A-Za-z0-9_.-]+!"
        r"[A-Za-z_][A-Za-z0-9_]*\b",
        clean,
    ):
        add_candidate(
            result,
            seen,
            value,
        )


    # CamelCase APIs/functions.
    for value in re.findall(
        r"\b[A-Z][A-Za-z0-9]*"
        r"[A-Z][A-Za-z0-9]*\b",
        clean,
    ):
        if len(value) >= 6:
            add_candidate(
                result,
                seen,
                value,
            )


    # Hex technical constants.
    for value in re.findall(
        r"\b0x[0-9A-Fa-f]+\b",
        clean,
    ):
        add_candidate(
            result,
            seen,
            value,
        )


    # Hyphenated command/tool names.
    for value in re.findall(
        r"\b[A-Za-z0-9_]+"
        r"(?:-[A-Za-z0-9_]+)+\b",
        clean,
    ):
        if len(value) >= 5:
            add_candidate(
                result,
                seen,
                value,
            )


    # Keep baseline rules bounded and reproducible.
    result = result[:12]


    if result:

        return (
            result,
            "GROUNDED_LITERAL_KEYWORDS",
            clean,
        )


    # Safe fallback: exact sanitized grounded analytic prose.
    return (
        [clean],
        "GROUNDED_DESCRIPTION_FALLBACK",
        clean,
    )


# ============================================================
# Deterministic Sigma logsource projection
# ============================================================

def normalize_token(value):

    value = value.strip().lower()

    value = re.sub(
        r"\s+",
        "_",
        value,
    )

    value = re.sub(
        r"[^a-z0-9_.-]",
        "_",
        value,
    )

    value = re.sub(
        r"_+",
        "_",
        value,
    )

    return (
        value.strip("_")
        or "unknown"
    )


def source_projection(source):

    prefix, sep, suffix = (
        source.partition(":")
    )

    prefix_n = normalize_token(
        prefix
    )

    suffix_n = (
        normalize_token(suffix)
        if sep
        else None
    )


    if prefix_n == "wineventlog":

        return (
            "windows",
            suffix_n,
        )


    if prefix_n == "auditd":

        return (
            "linux",
            "auditd",
        )


    if prefix_n in {
        "linux",
        "macos",
        "aws",
        "azure",
        "gcp",
        "m365",
        "okta",
    }:

        return (
            prefix_n,
            suffix_n,
        )


    if prefix_n == "networkdevice":

        return (
            "network",
            suffix_n,
        )


    # Unknown source families remain deterministic;
    # original grounded source is preserved in definition.
    return (
        prefix_n,
        suffix_n,
    )


def build_logsource(path):

    raw_sources = (
        path.get(
            "log_sources",
            []
        )
        or []
    )

    if not raw_sources:
        raise RuntimeError(
            "Grounded path has no log_sources"
        )


    projections = [
        source_projection(source)
        for source in raw_sources
    ]


    products = {
        product
        for product, _
        in projections
        if product
    }

    services = {
        service
        for _, service
        in projections
        if service
    }


    logsource = {}


    category = path.get(
        "canonical_category"
    )

    if (
        isinstance(category, str)
        and category.strip()
    ):

        logsource[
            "category"
        ] = normalize_token(
            category
        )


    # A single grounded product can represent
    # all grounded sources safely.
    if len(products) == 1:

        logsource[
            "product"
        ] = next(
            iter(products)
        )


        if (
            len(services) == 1
            and len(raw_sources) == 1
        ):

            logsource[
                "service"
            ] = next(
                iter(services)
            )


    # Sigma requires an effective logsource selector.
    #
    # For heterogeneous grounded sources where no
    # canonical category exists, select the first
    # authoritative grounded source as the baseline
    # primary source.
    #
    # This narrows baseline coverage; it does NOT
    # invent a log source.
    if not any(
        key in logsource
        for key in (
            "category",
            "product",
            "service",
        )
    ):

        primary_source = (
            raw_sources[0]
        )

        (
            primary_product,
            primary_service,
        ) = source_projection(
            primary_source
        )


        if primary_product:

            logsource[
                "product"
            ] = primary_product


        if primary_service:

            logsource[
                "service"
            ] = primary_service


        if not any(
            key in logsource
            for key in (
                "category",
                "product",
                "service",
            )
        ):

            raise RuntimeError(
                "Unable to project grounded "
                "Sigma logsource"
            )


        logsource[
            "definition"
        ] = (
            "Primary grounded baseline source: "
            + primary_source
            + "; all grounded source(s): "
            + ", ".join(
                raw_sources
            )
        )


    else:

        logsource[
            "definition"
        ] = (
            "Grounded source(s): "
            + ", ".join(
                raw_sources
            )
        )


    return logsource


# ============================================================
# Rule identity
# ============================================================

def rule_uuid(unit_id):

    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            (
                "urn:autonomous-threat-hunting:"
                "baseline-sigma:"
                + unit_id
            ),
        )
    )


def safe_filename(
    technique_id,
    analytic_id,
    rule_id,
):

    tid = (
        technique_id
        .lower()
        .replace(".", "_")
    )

    aid = normalize_token(
        analytic_id
    )

    return (
        f"th_{tid}_{aid}_"
        f"{rule_id[:8]}.yml"
    )


# ============================================================
# Load Task 43 authoritative inputs
# ============================================================

units = read_jsonl(
    UNITS_PATH
)

blocked = read_jsonl(
    BLOCKED_PATH
)

design_audit = json.loads(
    DESIGN_AUDIT_PATH.read_text(
        encoding="utf-8-sig"
    )
)


if (
    design_audit.get(
        "status"
    )
    != "PASS"
):
    raise SystemExit(
        "Task 43 design audit is not PASS"
    )


if RULES_DIR.exists():

    shutil.rmtree(
        RULES_DIR
    )


RULES_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# Generate all baseline Sigma rules
# ============================================================

index_rows = []
errors = []

keyword_modes = Counter()

seen_rule_ids = set()
seen_unit_ids = set()
seen_files = set()


generated_date = (
    datetime.now(
        timezone.utc
    ).date().isoformat()
)


ordered_units = sorted(
    units,
    key=lambda row: (
        row[
            "technique"
        ][
            "technique_id"
        ],
        row[
            "path_semantics"
        ][
            "path_id"
        ],
    ),
)


for unit in ordered_units:

    unit_id = unit[
        "generation_unit_id"
    ]

    tid = unit[
        "technique"
    ][
        "technique_id"
    ]

    technique_name = unit[
        "technique"
    ][
        "technique_name"
    ]

    path_semantics = unit[
        "path_semantics"
    ]

    path = unit[
        "grounded_detection_path"
    ]


    try:

        if unit_id in seen_unit_ids:
            raise RuntimeError(
                "Duplicate generation_unit_id"
            )

        seen_unit_ids.add(
            unit_id
        )


        if (
            path[
                "grounding_status"
            ]
            != "TECHNIQUE_SPECIFIC_GROUNDED"
        ):
            raise RuntimeError(
                "Non-grounded path reached generator"
            )


        policy = unit[
            "sigma_generation_policy"
        ]


        if (
            policy.get(
                "use_only_grounded_path"
            )
            is not True
            or policy.get(
                "unresolved_paths_exposed"
            )
            is not False
            or policy.get(
                "field_invention_allowed"
            )
            is not False
            or policy.get(
                "event_id_invention_allowed"
            )
            is not False
            or policy.get(
                "logsource_invention_allowed"
            )
            is not False
        ):
            raise RuntimeError(
                "Generation policy violation"
            )


        analytic_id = (
            path_semantics[
                "analytic_id"
            ]
        )

        analytic_name = (
            path_semantics.get(
                "analytic_name"
            )
            or analytic_id
        )

        description = (
            path_semantics[
                "analytic_description"
            ]
        )


        allowed_event_ids = {
            str(value).strip()

            for value in (
                path.get(
                    "event_ids",
                    []
                )
                or []
            )

            if str(value).strip()
        }


        (
            keywords,
            keyword_mode,
            clean_description,
        ) = extract_grounded_keywords(
            description,
            allowed_event_ids,
        )


        if not keywords:
            raise RuntimeError(
                "No grounded keywords generated"
            )


        # All explicit event references remaining in
        # description/keywords must be structured-grounded.
        remaining_event_ids = (
            explicit_event_ids(
                clean_description
                + " "
                + " ".join(keywords)
            )
        )


        unsupported_events = (
            remaining_event_ids
            - allowed_event_ids
        )


        if unsupported_events:
            raise RuntimeError(
                "Unsupported Event IDs remain: "
                + repr(
                    sorted(
                        unsupported_events
                    )
                )
            )


        sigma_logsource = (
            build_logsource(
                path
            )
        )


        rule_id = rule_uuid(
            unit_id
        )


        if rule_id in seen_rule_ids:
            raise RuntimeError(
                "Duplicate Sigma rule ID"
            )

        seen_rule_ids.add(
            rule_id
        )


        title = (
            f"{technique_name} - "
            f"{analytic_name} Baseline"
        )


        if len(title) > 256:

            title = (
                title[:252]
                + " ..."
            )


        rule = {
            "title":
                title,

            "id":
                rule_id,

            "status":
                "experimental",

            "description":
                clean_description,

            "author":
                "Autonomous Threat Hunting Platform",

            "date":
                generated_date,

            "tags": [
                "attack."
                + tid.lower()
            ],

            "logsource":
                sigma_logsource,

            "detection": {
                "keywords":
                    keywords,

                "condition":
                    "keywords",
            },

            "falsepositives": [
                "Unknown"
            ],
        }


        # Explicit invariant:
        # baseline detection contains NO field mappings.
        if set(
            rule[
                "detection"
            ]
        ) != {
            "keywords",
            "condition",
        }:
            raise RuntimeError(
                "Field-bearing detection generated"
            )


        yaml_text = dump_yaml(
            rule
        )


        filename = safe_filename(
            tid,
            analytic_id,
            rule_id,
        )


        if filename in seen_files:
            raise RuntimeError(
                "Duplicate rule filename"
            )

        seen_files.add(
            filename
        )


        rule_path = (
            RULES_DIR
            / filename
        )


        with rule_path.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:

            handle.write(
                yaml_text
            )


        keyword_modes[
            keyword_mode
        ] += 1


        index_rows.append(
            {
                "generation_unit_id":
                    unit_id,

                "rule_id":
                    rule_id,

                "rule_file":
                    filename,

                "rule_sha256":
                    sha256_text(
                        yaml_text
                    ),

                "technique_id":
                    tid,

                "technique_name":
                    technique_name,

                "plan_id":
                    unit[
                        "plan_id"
                    ],

                "plan_input_fingerprint":
                    unit[
                        "plan_input_fingerprint"
                    ],

                "path_id":
                    path_semantics[
                        "path_id"
                    ],

                "analytic_id":
                    analytic_id,

                "status":
                    "PASS",

                "sigma_status":
                    "experimental",

                "production_ready":
                    False,

                "detection_mode":
                    "FIELDLESS_GROUNDED_KEYWORDS",

                "keyword_mode":
                    keyword_mode,

                "keyword_count":
                    len(keywords),

                "keywords":
                    keywords,

                "grounded_log_sources":
                    path[
                        "log_sources"
                    ],

                "sigma_logsource":
                    sigma_logsource,

                "grounded_event_ids":
                    sorted(
                        allowed_event_ids
                    ),

                "field_names_generated":
                    [],

                "model_call_performed":
                    False,
            }
        )


    except Exception as exc:

        errors.append(
            {
                "generation_unit_id":
                    unit_id,

                "technique_id":
                    tid,

                "path_id":
                    path_semantics.get(
                        "path_id"
                    ),

                "error_type":
                    type(exc).__name__,

                "error":
                    str(exc),
            }
        )


# ============================================================
# Full generation audit
# ============================================================

failures = []


def fail(
    category,
    detail,
):
    failures.append(
        {
            "category":
                category,

            "detail":
                detail,
        }
    )


expected_units = (
    design_audit.get(
        "sigma_generation_units"
    )
)


if len(units) != expected_units:
    fail(
        "TASK43_UNIT_COUNT_DRIFT",
        {
            "expected":
                expected_units,

            "actual":
                len(units),
        },
    )


if len(units) != 540:
    fail(
        "GENERATION_UNIT_COUNT",
        len(units),
    )


if len(blocked) != 13:
    fail(
        "BLOCKED_COUNT",
        len(blocked),
    )


if errors:
    fail(
        "GENERATION_ERRORS",
        len(errors),
    )


if len(index_rows) != 540:
    fail(
        "GENERATED_RULE_COUNT",
        len(index_rows),
    )


rule_files = sorted(
    RULES_DIR.glob(
        "*.yml"
    )
)


if len(rule_files) != 540:
    fail(
        "RULE_FILE_COUNT",
        len(rule_files),
    )


if (
    len(seen_rule_ids)
    != len(index_rows)
):
    fail(
        "RULE_ID_UNIQUENESS",
        {
            "rules":
                len(index_rows),

            "unique_ids":
                len(seen_rule_ids),
        },
    )


if (
    len(seen_files)
    != len(index_rows)
):
    fail(
        "FILENAME_UNIQUENESS",
        {
            "rules":
                len(index_rows),

            "unique_files":
                len(seen_files),
        },
    )


unit_techniques = {
    row[
        "technique_id"
    ]
    for row in index_rows
}

blocked_techniques = {
    row[
        "technique_id"
    ]
    for row in blocked
}


if len(unit_techniques) != 492:
    fail(
        "READY_TECHNIQUE_COUNT",
        len(unit_techniques),
    )


if (
    unit_techniques
    & blocked_techniques
):
    fail(
        "BLOCKED_TECHNIQUE_GENERATED",
        sorted(
            unit_techniques
            & blocked_techniques
        ),
    )


# Audit generated index invariants.
for row in index_rows:

    if (
        row[
            "model_call_performed"
        ]
        is not False
    ):
        fail(
            "MODEL_CALL_IN_BASELINE",
            row[
                "generation_unit_id"
            ],
        )


    if row[
        "field_names_generated"
    ]:
        fail(
            "INVENTED_FIELDS",
            row[
                "generation_unit_id"
            ],
        )


    if (
        row[
            "sigma_status"
        ]
        != "experimental"
    ):
        fail(
            "SIGMA_STATUS",
            row[
                "generation_unit_id"
            ],
        )


    if (
        row[
            "production_ready"
        ]
        is not False
    ):
        fail(
            "PRODUCTION_READY_DRIFT",
            row[
                "generation_unit_id"
            ],
        )


summary = {
    "generator_version":
        "1.1",

    "sigma_spec_target":
        "2.1.0",

    "generation_strategy":
        "FIELDLESS_GROUNDED_KEYWORD_BASELINE",

    "input_generation_units":
        len(units),

    "ready_techniques":
        len(
            unit_techniques
        ),

    "blocked_techniques":
        len(blocked),

    "generated_rules":
        len(index_rows),

    "generation_errors":
        len(errors),

    "model_calls":
        0,

    "field_names_generated":
        0,

    "keyword_modes":
        dict(
            keyword_modes
        ),

    "sigma_status":
        "experimental",

    "production_ready":
        False,

    "generated_at_utc":
        datetime.now(
            timezone.utc
        ).isoformat(),
}


audit = {
    "audit_version":
        "1.0",

    "input_generation_units":
        len(units),

    "generated_rules":
        len(index_rows),

    "rule_files":
        len(rule_files),

    "ready_techniques":
        len(
            unit_techniques
        ),

    "blocked_techniques":
        len(blocked),

    "duplicate_rule_ids":
        (
            len(index_rows)
            - len(seen_rule_ids)
        ),

    "duplicate_filenames":
        (
            len(index_rows)
            - len(seen_files)
        ),

    "generation_errors":
        len(errors),

    "invented_fields":
        0,

    "model_calls":
        0,

    "unresolved_plans_generated":
        len(
            unit_techniques
            & blocked_techniques
        ),

    "audit_failures":
        len(failures),

    "failure_categories":
        dict(
            Counter(
                row[
                    "category"
                ]
                for row in failures
            )
        ),

    "failures":
        failures,

    "status":
        (
            "PASS"
            if not failures
            else "FAIL"
        ),
}


write_jsonl(
    INDEX_PATH,
    index_rows,
)

write_jsonl(
    ERRORS_PATH,
    errors,
)

write_json(
    SUMMARY_PATH,
    summary,
)

write_json(
    AUDIT_PATH,
    audit,
)


# ============================================================
# Console
# ============================================================

print(
    "===== TASK 44 BASELINE SIGMA GENERATOR ====="
)

print()

print(
    "Input generation units      :",
    len(units),
)

print(
    "READY techniques            :",
    len(unit_techniques),
)

print(
    "Blocked techniques          :",
    len(blocked),
)

print()

print(
    "Generated Sigma rules       :",
    len(index_rows),
)

print(
    "Rule files                  :",
    len(rule_files),
)

print(
    "Generation errors           :",
    len(errors),
)

print()

print(
    "Field names generated       :",
    0,
)

print(
    "Model calls                 :",
    0,
)

print(
    "Unresolved plans generated  :",
    len(
        unit_techniques
        & blocked_techniques
    ),
)

print()

print(
    "Keyword modes:"
)

for key, value in sorted(
    keyword_modes.items()
):
    print(
        f"  {key}: {value}"
    )

print()

print(
    "Audit failures              :",
    len(failures),
)

print()

print(
    "Rules  :",
    RULES_DIR,
)

print(
    "Index  :",
    INDEX_PATH,
)

print(
    "Errors :",
    ERRORS_PATH,
)

print(
    "Summary:",
    SUMMARY_PATH,
)

print(
    "Audit  :",
    AUDIT_PATH,
)

print()


if failures:

    print(
        "===== FIRST FAILURES ====="
    )

    for row in failures[:20]:

        print(
            json.dumps(
                row,
                ensure_ascii=False,
            )
        )

    print()

    print(
        "TASK 44 BASELINE SIGMA GENERATOR: FAIL"
    )

    raise SystemExit(1)


print(
    "TASK 44 BASELINE SIGMA GENERATOR: PASS"
)
