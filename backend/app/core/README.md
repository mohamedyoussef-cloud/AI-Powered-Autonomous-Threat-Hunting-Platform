# Backend core infrastructure

Application settings, SQLAlchemy initialization and shared security helpers.

## Contents
- [`config.py`](config.py) — implementation of config
- [`database.py`](database.py) — implementation of database
- [`security.py`](security.py) — implementation of security
- **Additional tracked files:** 1 (see directory listing for complete inventory).

## Interpretation and usage

Configure secrets and database locations with environment variables. Local demo authentication settings are not suitable for Internet-facing deployment without hardening.

[Related overview](../../README.md)
