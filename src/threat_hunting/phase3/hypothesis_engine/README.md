# ATT&CK hypothesis generation

Dispatch and validation of distinct hypothesis families with versioned schemas and batch execution tools.

## Contents
- [`__init__.py`](__init__.py) — Python package initialization
- [`build_output_schemas_v1.py`](build_output_schemas_v1.py) — implementation of build output schemas v1
- [`dry_run_v1.py`](dry_run_v1.py) — implementation of dry run v1
- [`output_validator_v1.py`](output_validator_v1.py) — implementation of output validator v1
- [`run_hypothesis_engine_v1.py`](run_hypothesis_engine_v1.py) — implementation of run hypothesis engine v1
- [`run_parallel_v1.py`](run_parallel_v1.py) — implementation of run parallel v1
- **Additional tracked files:** 1 (see directory listing for complete inventory).

## Interpretation and usage

The actual research hypothesis records are in `artifacts/hypotheses/`. These operations can be evaluated without a live LLM service.

[Related overview](../../../README.md)
