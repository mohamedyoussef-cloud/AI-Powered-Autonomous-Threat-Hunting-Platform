"""
models/attack.py
-------------------
Mirrors the AttackKnowledgeBase canonical schema from the data-prep
pipeline (src/schemas/attack_knowledge.py), now as real relational
tables instead of in-memory dataclasses.
"""
from __future__ import annotations

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id: Mapped[int] = mapped_column(primary_key=True)
    stix_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    attack_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)  # e.g. T1059.001
    name: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text, default="")
    tactics: Mapped[str] = mapped_column(String(512), default="")   # comma-joined; see .tactics_list
    platforms: Mapped[str] = mapped_column(String(512), default="")
    version: Mapped[str] = mapped_column(String(16), default="")
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    is_sub_technique: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_attack_id: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)

    rule_links: Mapped[list["SigmaRuleTechnique"]] = relationship(back_populates="technique")

    @property
    def tactics_list(self) -> list[str]:
        return [t for t in self.tactics.split(",") if t]

    @property
    def platforms_list(self) -> list[str]:
        return [p for p in self.platforms.split(",") if p]


class Mitigation(Base):
    __tablename__ = "mitigations"

    id: Mapped[int] = mapped_column(primary_key=True)
    mitigation_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text, default="")
    technique_relationship: Mapped[str] = mapped_column(String(1024), default="")  # comma-joined attack_ids
