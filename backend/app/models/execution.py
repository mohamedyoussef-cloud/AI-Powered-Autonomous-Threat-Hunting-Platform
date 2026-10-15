"""
models/execution.py
-------------------
Persistence for what actually happened during a hunt:

  TelemetryEvent   normalized events available to the local hunt backend
  HuntExecution    one row per (rule x connector) run: query, status, hits, timing
  CampaignEvent    ordered pipeline/timeline log per campaign (drives the live workflow view)
  AnalystVerdict   analyst decisions on findings (also the ML feedback labels)
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(512), index=True)        # file / dataset label
    source_kind: Mapped[str] = mapped_column(String(32), default="evtx")  # evtx | jsonl | api
    product: Mapped[str] = mapped_column(String(32), default="windows", index=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    service: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    event_id: Mapped[str] = mapped_column(String(16), default="", index=True)
    host: Mapped[str] = mapped_column(String(256), default="")
    timestamp: Mapped[str] = mapped_column(String(64), default="")
    fields_json: Mapped[str] = mapped_column(Text, default="{}")


class HuntExecution(Base):
    __tablename__ = "hunt_executions"

    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    rule_pk: Mapped[int | None] = mapped_column(ForeignKey("campaign_rules.id", ondelete="SET NULL"), nullable=True, index=True)
    technique_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    connector: Mapped[str] = mapped_column(String(32), default="local", index=True)
    # queued | running | completed | skipped | blocked | failed
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    status_reason: Mapped[str] = mapped_column(Text, default="")
    native_query: Mapped[str] = mapped_column(Text, default="")
    events_scanned: Mapped[int] = mapped_column(Integer, default=0)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    validation_json: Mapped[str] = mapped_column(Text, default="{}")
    started_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class CampaignEvent(Base):
    __tablename__ = "campaign_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    # hypotheses | detection | translate | execute | score | review
    stage: Mapped[str] = mapped_column(String(24), index=True)
    level: Mapped[str] = mapped_column(String(12), default="info")  # info | warn | error
    message: Mapped[str] = mapped_column(Text, default="")
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now, index=True)


class AnalystVerdict(Base):
    __tablename__ = "analyst_verdicts"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(128), index=True)
    campaign_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    # true_positive | false_positive | benign_expected | needs_review
    verdict: Mapped[str] = mapped_column(String(24), index=True)
    analyst: Mapped[str] = mapped_column(String(256), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    features_json: Mapped[str] = mapped_column(Text, default="{}")  # snapshot for ML retraining
    model_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now, index=True)
