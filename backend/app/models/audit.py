from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RuleLifecycleAudit(Base):
    __tablename__ = "rule_lifecycle_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    campaign_id: Mapped[int] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        index=True,
    )

    rule_id: Mapped[int] = mapped_column(
        ForeignKey("campaign_rules.id", ondelete="CASCADE"),
        index=True,
    )

    previous_status: Mapped[str] = mapped_column(
        String(32),
        default="draft",
    )

    new_status: Mapped[str] = mapped_column(
        String(32),
        index=True,
    )

    changed_by: Mapped[str] = mapped_column(
        String(256),
    )

    source: Mapped[str] = mapped_column(
        String(64),
        default="analyst",
    )

    reason: Mapped[str] = mapped_column(
        Text,
        default="",
    )

    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        index=True,
    )
