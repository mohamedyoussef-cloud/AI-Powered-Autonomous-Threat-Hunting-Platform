"""
models/sigma.py
------------------
Mirrors the SigmaRule canonical schema (src/schemas/sigma_rule.py) plus
the quarantine categorization added in the merged v2 pipeline.
"""
from __future__ import annotations

from sqlalchemy import Boolean, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class SigmaRule(Base):
    __tablename__ = "sigma_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(256), index=True)
    status: Mapped[str] = mapped_column(String(32), default="experimental", index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    author: Mapped[str] = mapped_column(String(256), default="")
    level: Mapped[str] = mapped_column(String(16), default="medium", index=True)

    logsource_product: Mapped[str | None] = mapped_column(String(64), nullable=True)
    logsource_category: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    logsource_service: Mapped[str | None] = mapped_column(String(64), nullable=True)

    condition_expression: Mapped[str] = mapped_column(Text, default="")
    raw_yaml: Mapped[str] = mapped_column(Text, default="")

    tag_validation_result: Mapped[str] = mapped_column(String(32), default="unvalidated")
    yaml_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    sigma_schema_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    compilation_backend: Mapped[str | None] = mapped_column(String(32), nullable=True)
    compiled_query: Mapped[str | None] = mapped_column(Text, nullable=True)

    quarantine_category: Mapped[str] = mapped_column(String(32), default="accepted_core", index=True)
    is_training_ready: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    split_id: Mapped[str | None] = mapped_column(String(16), nullable=True)      # train | val | test
    leakage_group: Mapped[str | None] = mapped_column(String(256), nullable=True)

    technique_links: Mapped[list["SigmaRuleTechnique"]] = relationship(
        back_populates="rule", cascade="all, delete-orphan"
    )


class SigmaRuleTechnique(Base):
    """Many-to-many join: a rule can tag several techniques, and (in
    principle) several rules can share a technique — this is exactly
    what powers the ATT&CK Coverage Matrix query."""
    __tablename__ = "sigma_rule_techniques"

    id: Mapped[int] = mapped_column(primary_key=True)
    sigma_rule_id: Mapped[int] = mapped_column(ForeignKey("sigma_rules.id"), index=True)
    attack_technique_id: Mapped[int] = mapped_column(ForeignKey("attack_techniques.id"), index=True)

    rule: Mapped["SigmaRule"] = relationship(back_populates="technique_links")
    technique = relationship("AttackTechnique", back_populates="rule_links")
