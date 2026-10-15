"""
models/generator.py
----------------------
Persists Sigma Rule Generator submissions. The generation logic itself
(services/rule_generator.py) is currently a deterministic template
engine, NOT the real Mistral-7B Hypothesis Engine described in the
platform's architecture — that's an explicit, labeled placeholder so the
schema/API/UI contract is ready the day the real LLM is wired in behind
the same endpoint.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class GeneratedRuleRequest(Base):
    __tablename__ = "generated_rule_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=lambda: dt.datetime.now(dt.UTC))

    hypothesis_text: Mapped[str] = mapped_column(Text)
    target_technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    target_platform: Mapped[str] = mapped_column(String(32), default="windows")

    generated_yaml: Mapped[str] = mapped_column(Text, default="")
    generation_method: Mapped[str] = mapped_column(String(32), default="template_v0")  # vs. "llm_v1" later
    status: Mapped[str] = mapped_column(String(32), default="draft")   # draft | validated | rejected
