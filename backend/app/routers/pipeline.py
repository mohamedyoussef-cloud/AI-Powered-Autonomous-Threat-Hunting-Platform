"""
routers/pipeline.py
----------------------
Powers the Pipeline Status & Data Quality dashboard.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.pipeline import PipelineRun, PipelineStageResult, QualityGateResult, SourceSummary
from app.schemas.api_schemas import PipelineStatusOut, StageResultOut, QualityGateOut, SourceSummaryOut

router = APIRouter(prefix="/pipeline", tags=["pipeline"])


@router.get("/status", response_model=PipelineStatusOut)
def latest_status(db: Session = Depends(get_db)):
    run = db.query(PipelineRun).order_by(PipelineRun.run_timestamp.desc()).first()
    if not run:
        raise HTTPException(status_code=404, detail="No pipeline run has been loaded yet")

    stages = (
        db.query(PipelineStageResult)
        .filter(PipelineStageResult.pipeline_run_id == run.id)
        .all()
    )
    gates = (
        db.query(QualityGateResult)
        .filter(QualityGateResult.pipeline_run_id == run.id)
        .all()
    )

    return PipelineStatusOut(
        run_timestamp=run.run_timestamp,
        mode=run.mode,
        overall_status=run.overall_status,
        total_duration_seconds=run.total_duration_seconds,
        stages=[StageResultOut.model_validate(s) for s in stages],
        quality_gates=[QualityGateOut.model_validate(g) for g in gates],
    )


@router.get("/sources", response_model=list[SourceSummaryOut])
def source_summaries(db: Session = Depends(get_db)):
    return db.query(SourceSummary).order_by(SourceSummary.source_id).all()
