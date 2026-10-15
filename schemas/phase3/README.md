# Phase 3 data contracts

Versioned schema definitions for hypothesis outputs, eligibility decisions and detection plans.

## Contents
- [`detection_eligibility/`](detection_eligibility/) — jSON Schema for the gating output of the detection eligibility stage.
- [`detection_plan/`](detection_plan/) — plan-record formats, including versioned revisions and semantic-output structure.
- [`hypothesis_engine/`](hypothesis_engine/) — contracts for pre-attack, collection-gap, environmental-resolution and runtime hunt hypotheses.
- [`environment_profile.schema.json`](environment_profile.schema.json) — structured environment profile.schema records
- [`hypothesis_output.schema.json`](hypothesis_output.schema.json) — structured hypothesis output.schema records

## Interpretation and usage

Use the schema version matching each recorded artifact; do not silently coerce earlier structures into newer output formats.

[Related overview](../../docs/README.md)
