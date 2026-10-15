# Runtime data and model boundary

Local SQLite state and optionally installed inference assets sit under the backend data directory.

## Contents
- [`ml_triage/`](ml_triage/) — the source tree for the locked XGBoost three-class GUIDE alert model bundle and preprocessing/evaluation metadata.

## Interpretation and usage

Application databases and credentials must remain untracked. Only vetted model contracts/evaluation evidence are committed; the frozen XGBoost weights require separate distribution.

[Related overview](../../README.md)
