"""
models/finding.py
--------------------
Mirrors the HuntFinding canonical schema (src/schemas/hunt_finding.py).
"""
from __future__ import annotations

from sqlalchemy import Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class HuntFinding(Base):
    __tablename__ = "hunt_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_title: Mapped[str] = mapped_column(String(256), default="")

    compiled_query: Mapped[str] = mapped_column(Text, default="")
    event_references: Mapped[str] = mapped_column(Text, default="")  # comma-joined
    time_start: Mapped[str] = mapped_column(String(64), default="")
    time_end: Mapped[str] = mapped_column(String(64), default="")

    hosts: Mapped[str] = mapped_column(String(1024), default="")
    users: Mapped[str] = mapped_column(String(1024), default="")
    processes: Mapped[str] = mapped_column(Text, default="")
    ips: Mapped[str] = mapped_column(String(1024), default="")

    attack_technique_ids: Mapped[str] = mapped_column(String(512), default="", index=True)
    narrative: Mapped[str] = mapped_column(Text, default="")

    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    threat_probability: Mapped[float | None] = mapped_column(Float, nullable=True)

    label: Mapped[str] = mapped_column(String(32), default="unknown", index=True)
    verification_status: Mapped[str] = mapped_column(String(32), default="unverified", index=True)

    source_dataset: Mapped[str] = mapped_column(String(32), default="", index=True)  # evtx | bots
    triage_json: Mapped[str] = mapped_column(Text, default="{}")
    analyst_verdict: Mapped[str | None] = mapped_column(String(24), nullable=True)
