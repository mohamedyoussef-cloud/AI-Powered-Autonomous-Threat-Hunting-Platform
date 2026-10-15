from __future__ import annotations
from datetime import datetime
from pydantic import Field, BaseModel, ConfigDict

class CampaignCreate(BaseModel):
    name: str
    description: str = ""
    target_platform: str = "windows"
    mode: str = "simulation"
    rule_source: str = "auto"
    technique_ids: list[str] = []

class CampaignRunRequest(BaseModel):
    technique_ids: list[str] | None = None

class CampaignOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: str
    status: str
    mode: str
    target_platform: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    total_hypotheses: int
    total_rules: int
    total_findings: int
    risk_score: float
    rule_source: str | None = "auto"

class CampaignHypothesisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    technique_id: str
    technique_name: str
    route: str
    hypothesis_text: str
    priority_score: float | None

    # Detection Plan linkage
    detection_plan_id: str | None = None
    detection_objective: str | None = None
    observable_behaviors: list[str] = Field(default_factory=list)
    known_limitations: list[str] = Field(default_factory=list)

    status: str

class CampaignRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    hypothesis_id: int | None
    rule_id: str
    title: str
    generated_yaml: str
    generation_method: str
    validation_status: str
    status: str
    lifecycle_updated_at: str | None = None
    lifecycle_updated_by: str | None = None
    lifecycle_reason: str | None = None
    source_rule_id: str | None = None
    source_kind: str | None = None
    executable: bool | None = True
    validation_json: str | None = None

class CampaignFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    finding_id: str
    match_type: str
    confidence: float

class CampaignRuntimeEvidenceItemOut(BaseModel):
    source: str
    source_rule_id: str
    technique_id: str | None = None
    technique_name: str | None = None
    analytic_id: str | None = None
    path_id: str | None = None
    plan_id: str | None = None
    classification: str | None = None
    keyword_mode: str | None = None
    runtime_execution_candidate: bool = False
    queue_present: bool = False
    result_present: bool = False
    execution_status: str
    match_count: int = 0
    disposition: str | None = None
    zero_result_interpretation: str | None = None


class CampaignRuntimeEvidenceSummaryOut(BaseModel):
    source: str
    compiled_rules: int
    runtime_candidates: int
    queued_runtime_candidates: int
    runtime_results: int
    deferred_runtime_candidates: int
    execution_status_counts: dict[str, int]


class CampaignRuntimeEvidenceOut(BaseModel):
    summary: CampaignRuntimeEvidenceSummaryOut
    rules: list[CampaignRuntimeEvidenceItemOut] = []


class CampaignDetail(CampaignOut):
    hypotheses: list[CampaignHypothesisOut] = []
    rules: list[CampaignRuleOut] = []
    findings: list[CampaignFindingOut] = []
    runtime_evidence: CampaignRuntimeEvidenceOut | None = None
