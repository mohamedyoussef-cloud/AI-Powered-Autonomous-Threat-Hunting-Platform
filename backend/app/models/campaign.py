from __future__ import annotations
import datetime as dt
from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base

class Campaign(Base):
    __tablename__ = "campaigns"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="draft", index=True)
    mode: Mapped[str] = mapped_column(String(32), default="simulation")
    target_platform: Mapped[str] = mapped_column(String(32), default="windows")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=lambda: dt.datetime.now(dt.UTC))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    total_hypotheses: Mapped[int] = mapped_column(Integer, default=0)
    total_rules: Mapped[int] = mapped_column(Integer, default=0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    rule_source: Mapped[str] = mapped_column(String(24), default="auto")  # auto | corpus | template | llm_qwen3

class CampaignHypothesis(Base):
    __tablename__ = "campaign_hypotheses"
    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    technique_id: Mapped[str] = mapped_column(String(32), index=True)
    technique_name: Mapped[str] = mapped_column(String(256), default="")
    route: Mapped[str] = mapped_column(String(64), default="")
    hypothesis_text: Mapped[str] = mapped_column(Text, default="")
    priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Detection Plan linkage
    detection_plan_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    detection_objective: Mapped[str | None] = mapped_column(Text, nullable=True)
    observable_behaviors: Mapped[str | None] = mapped_column(Text, nullable=True)
    known_limitations: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(32), default="selected")

class CampaignRule(Base):
    __tablename__ = "campaign_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    hypothesis_id: Mapped[int | None] = mapped_column(ForeignKey("campaign_hypotheses.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(String(256), default="")
    generated_yaml: Mapped[str] = mapped_column(Text, default="")
    generation_method: Mapped[str] = mapped_column(String(64), default="template_v0")

    # Rule lifecycle:
    # draft -> validated -> approved -> active -> retired
    validation_status: Mapped[str] = mapped_column(String(32), default="draft", index=True)
    status: Mapped[str] = mapped_column(String(32), default="generated")

    lifecycle_updated_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lifecycle_updated_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    lifecycle_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_kind: Mapped[str] = mapped_column(String(24), default="template")  # corpus | template
    executable: Mapped[bool] = mapped_column(default=True)
    validation_json: Mapped[str] = mapped_column(Text, default="{}")

class CampaignFinding(Base):
    __tablename__ = "campaign_findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str] = mapped_column(String(128), index=True)
    match_type: Mapped[str] = mapped_column(String(32), default="technique")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
