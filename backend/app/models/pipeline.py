"""
models/pipeline.py
---------------------
Persists the data-prep pipeline's own run/quality reports, so the
"Pipeline Status & Data Quality" dashboard has real history to show
instead of just the latest run's JSON file.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_timestamp: Mapped[dt.datetime] = mapped_column(DateTime, index=True)
    mode: Mapped[str] = mapped_column(String(16), default="sample")   # sample | real | auto
    overall_status: Mapped[str] = mapped_column(String(32), index=True)
    total_duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)


class PipelineStageResult(Base):
    __tablename__ = "pipeline_stage_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    pipeline_run_id: Mapped[int] = mapped_column(Integer, index=True)
    stage_name: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32))
    returncode: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)


class QualityGateResult(Base):
    __tablename__ = "quality_gate_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    pipeline_run_id: Mapped[int] = mapped_column(Integer, index=True)
    gate_name: Mapped[str] = mapped_column(String(64))
    passed: Mapped[bool] = mapped_column(Boolean)
    measured: Mapped[float] = mapped_column(Float, default=0.0)
    threshold: Mapped[float] = mapped_column(Float, default=0.0)
    message: Mapped[str] = mapped_column(Text, default="")


class SourceSummary(Base):
    """Denormalized per-source counters, refreshed by the loader script
    each time it runs — cheap to query for dashboard headline numbers
    without aggregating the full event tables on every request."""
    __tablename__ = "source_summaries"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)  # attack|sigma|evtx|bots
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    last_loaded_at: Mapped[dt.datetime] = mapped_column(DateTime)
    extra_json: Mapped[str] = mapped_column(Text, default="{}")   # small free-form counters blob
