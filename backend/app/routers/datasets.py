"""
routers/datasets.py
----------------------
Powers the Dataset Manager screen — a real-data-backed catalog, not a
static list. Reads directly from the data-prep pipeline's own source
registry and parse reports every request (cheap file I/O), so it's
always in sync with the pipeline without needing a database reload step.
"""
from __future__ import annotations

from fastapi import APIRouter

from app.schemas.api_schemas import DatasetOut, ConnectionOut
from app.services.dataset_catalog import load_catalog, load_connections

router = APIRouter(prefix="/datasets", tags=["datasets"])


@router.get("", response_model=list[DatasetOut])
def list_datasets():
    return load_catalog()


@router.get("/connections", response_model=list[ConnectionOut])
def list_connections():
    return load_connections()
