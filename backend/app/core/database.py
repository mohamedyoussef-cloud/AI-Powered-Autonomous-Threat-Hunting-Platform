"""
core/database.py
-------------------
SQLAlchemy engine/session setup. Uses the classic sessionmaker + declarative
base pattern (SQLAlchemy 2.0 style) so it's easy to reason about and test.
"""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import get_settings

settings = get_settings()

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency — yields a request-scoped session and always
    closes it, even if the request handler raises."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

from app.models.execution import TelemetryEvent, HuntExecution, CampaignEvent, AnalystVerdict  # noqa: E402,F401


def init_schema() -> None:
    """Create any missing tables and add columns introduced after first deploy.
    Safe to call on every startup (idempotent, never drops data)."""
    from sqlalchemy import inspect, text
    Base.metadata.create_all(bind=engine)
    insp = inspect(engine)
    additions = {
        "hunt_findings": {
            "triage_json": "TEXT DEFAULT '{}'",
            "analyst_verdict": "VARCHAR(24)",
        },
        "campaigns": {"rule_source": "VARCHAR(24) DEFAULT 'auto'"},
        "campaign_rules": {
            "source_rule_id": "VARCHAR(128)",
            "source_kind": "VARCHAR(24) DEFAULT 'template'",
            "executable": "BOOLEAN DEFAULT 1",
            "validation_json": "TEXT DEFAULT '{}'",
        },
    }
    with engine.begin() as conn:
        for table, cols in additions.items():
            if not insp.has_table(table):
                continue
            have = {c["name"] for c in insp.get_columns(table)}
            for name, ddl in cols.items():
                if name not in have:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
