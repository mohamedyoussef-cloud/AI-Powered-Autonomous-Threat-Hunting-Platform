# Infrastructure and deployment notes

Compose and deployment guidance for the research platform, not a guarantee of production readiness.

## Contents
- [`docker-compose.yml`](docker-compose.yml) — tracked research asset
- [`deployment-notes.md`](deployment-notes.md) — documentation for deployment-notes

## Interpretation and usage

Review container/service configuration before public exposure. The optional external Qwen inference provider, the frozen ML bundle and real SIEM credentials are separate deployment dependencies.

[Related overview](../docs/README.md)
