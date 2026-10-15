"""
FastAPI application entry point.
Serves both the API and the built React frontend.
"""

from __future__ import annotations

from app.models.audit import RuleLifecycleAudit

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import get_settings
from app.core.database import init_schema
from app.routers import (
    attack,
    sigma,
    findings,
    pipeline,
    generator,
    datasets,
    hypotheses,
    detection_plans,
    technique_intelligence,
    campaigns,
    auth,
    integration,
    admin_control,
    source_control,
    operations,
    context,
    ml_triage,
)

settings = get_settings()
init_schema()  # create/upgrade tables; idempotent, never drops data

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers
app.include_router(attack.router, prefix=settings.API_PREFIX)
app.include_router(sigma.router, prefix=settings.API_PREFIX)
app.include_router(findings.router, prefix=settings.API_PREFIX)
app.include_router(pipeline.router, prefix=settings.API_PREFIX)
app.include_router(generator.router, prefix=settings.API_PREFIX)
app.include_router(datasets.router, prefix=settings.API_PREFIX)
app.include_router(hypotheses.router, prefix=settings.API_PREFIX)
app.include_router(detection_plans.router, prefix=settings.API_PREFIX)
app.include_router(technique_intelligence.router, prefix=settings.API_PREFIX)
app.include_router(campaigns.router, prefix=settings.API_PREFIX)
app.include_router(auth.router, prefix=settings.API_PREFIX)
app.include_router(integration.router, prefix=settings.API_PREFIX)
app.include_router(admin_control.router, prefix=settings.API_PREFIX)
app.include_router(source_control.router, prefix=settings.API_PREFIX)
app.include_router(ml_triage.router, prefix=settings.API_PREFIX)
app.include_router(context.router, prefix=settings.API_PREFIX)
app.include_router(operations.router, prefix=settings.API_PREFIX)


@app.on_event("startup")
def _warm_ml_triage():
    """Load the frozen ML bundle in the background so the first finding is not delayed."""
    import threading
    from app.services.ml_triage import get_engine
    threading.Thread(target=get_engine().ensure_loaded, daemon=True, name="ml-triage-warmup").start()


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
    }


# ------------------------------------------------------------------
# React frontend
# ------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"

# Serve Vite-built assets
if STATIC_DIR.exists():
    app.mount(
        "/assets",
        StaticFiles(directory=STATIC_DIR / "assets"),
        name="assets",
    )


# React SPA fallback
@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    # Never intercept API routes
    if full_path.startswith("api/"):
        return {"detail": "Not Found"}

    # Root and React routes
    if INDEX_FILE.exists():
        return FileResponse(INDEX_FILE)

    return {
        "detail": "Frontend build not found",
        "expected": str(INDEX_FILE),
    }
