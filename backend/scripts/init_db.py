#!/usr/bin/env python3
"""
scripts/init_db.py
---------------------
Creates every table declared across app/models/*.py. Safe to re-run
(create_all is a no-op for tables that already exist).

Usage:
    python scripts/init_db.py
"""
from __future__ import annotations

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.core.database import Base, engine  # noqa: E402
# Import every model module so their tables register on Base.metadata
# before create_all runs — SQLAlchemy only knows about classes that have
# actually been imported somewhere.
from app.models import attack, sigma, finding, pipeline, generator, campaign  # noqa: E402,F401


def main() -> int:
    print(f"Creating tables at: {engine.url}")
    Base.metadata.create_all(bind=engine)
    table_names = sorted(Base.metadata.tables.keys())
    print(f"Tables ready ({len(table_names)}):")
    for t in table_names:
        print(f"  - {t}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
