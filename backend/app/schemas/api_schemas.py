"""
schemas/api_schemas.py
-------------------------
Pydantic response/request models for the API. Kept separate from the
SQLAlchemy models (app/models/) on purpose — the DB shape and the wire
shape are allowed to diverge (e.g. comma-joined columns become real
lists here).
"""
from __future__ import annotations

import datetime as dt
from pydantic import BaseModel, ConfigDict


class TechniqueOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    attack_id: str
    name: str
    tactics: list[str]
    platforms: list[str]
    is_deprecated: bool
    is_revoked: bool
    is_sub_technique: bool
    parent_attack_id: str | None
    rule_count: int = 0


class CoverageCell(BaseModel):
    attack_id: str
    name: str
    tactic: str
    rule_count: int
    is_sub_technique: bool


class CoverageMatrixOut(BaseModel):
    tactics: list[str]
    cells: list[CoverageCell]
    total_active_techniques: int
    total_covered: int
    coverage_pct: float


class SigmaRuleListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    rule_id: str
    title: str
    status: str
    level: str
    logsource_product: str | None
    logsource_category: str | None
    quarantine_category: str
    is_training_ready: bool
    technique_ids: list[str] = []


class SigmaRuleDetail(SigmaRuleListItem):
    description: str
    author: str
    condition_expression: str
    raw_yaml: str
    tag_validation_result: str
    yaml_valid: bool
    sigma_schema_valid: bool
    compilation_backend: str | None
    compiled_query: str | None
    split_id: str | None
    leakage_group: str | None


class PaginatedSigmaRules(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[SigmaRuleListItem]


class FindingListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    finding_id: str
    case_id: str
    rule_id: str
    rule_title: str
    label: str
    verification_status: str
    risk_score: float | None
    source_dataset: str
    time_start: str
    attack_technique_ids: list[str] = []


class FindingDetail(FindingListItem):
    compiled_query: str
    event_references: list = []
    hosts: list[str] = []
    users: list[str] = []
    processes: list = []
    ips: list[str] = []
    narrative: str
    threat_probability: float | None
    time_end: str
    triage: dict = {}
    analyst_verdict: str | None = None
    verdicts: list[dict] = []


class PaginatedFindings(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[FindingListItem]


class StageResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    stage_name: str
    status: str
    returncode: int
    duration_seconds: float


class QualityGateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    gate_name: str
    passed: bool
    measured: float
    threshold: float
    message: str


class PipelineStatusOut(BaseModel):
    run_timestamp: dt.datetime
    mode: str
    overall_status: str
    total_duration_seconds: float
    stages: list[StageResultOut]
    quality_gates: list[QualityGateOut]


class SourceSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    source_id: str
    record_count: int
    last_loaded_at: dt.datetime


class GenerateRuleRequest(BaseModel):
    hypothesis_text: str
    target_technique_id: str | None = None
    target_platform: str = "windows"
    provider: str = "template"


class GenerateRuleResponse(BaseModel):
    id: int
    generated_yaml: str
    generation_method: str
    status: str
    warning: str
    provider: str = "template"
    gate: dict = {}


class DatasetOut(BaseModel):
    source_id: str
    name: str
    version: str
    license: str
    location: str
    intended_platform_use: str
    format_spec: str
    raw_status: str            # frozen | not_ingested
    file_count: int
    total_size_bytes: int
    combined_sha256: str | None
    health_status: str          # e.g. "8/9 rules accepted", "858 techniques (161 revoked)"
    record_count: int | None
    excluded: bool = False


class ConnectionOut(BaseModel):
    connection_id: str
    name: str
    category: str               # data_source | ai_llm | detection_backend
    status: str                 # live | not_configured | partial
    detail: str
