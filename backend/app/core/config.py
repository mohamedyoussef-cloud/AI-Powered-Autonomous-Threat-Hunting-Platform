"""
core/config.py
-----------------
Centralized application settings, loaded from environment variables with
sane local-dev defaults. Nothing here is a secret you'd actually ship —
in production these all come from the deployment environment.
"""
from __future__ import annotations

import os
from functools import lru_cache


class Settings:
    PROJECT_NAME: str = "ThreatHunt Platform API"
    VERSION: str = "3.1.0"

    DATABASE_URL: str = os.environ.get(
        "DATABASE_URL",
        "sqlite:///./app/data/threathunt_v3.db",
    )

    # Where the data-preparation pipeline's outputs live, so the loader
    # script (scripts/load_pipeline_data.py) knows where to read from.
    PIPELINE_DATA_ROOT: str = os.environ.get(
        "PIPELINE_DATA_ROOT",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data")),
    )

    CORS_ORIGINS: list[str] = os.environ.get(
        "CORS_ORIGINS", "http://localhost:5173,http://localhost:3000"
    ).split(",")

    # Team Phase 3 hypothesis-engine outputs. This is read-only integration data.
    TEAM_PHASE3_ROOT: str = os.environ.get("TEAM_PHASE3_ROOT", "")

    API_PREFIX: str = "/api"

    # Pagination defaults
    DEFAULT_PAGE_SIZE: int = 25
    MAX_PAGE_SIZE: int = 200


@lru_cache
def get_settings() -> Settings:
    return Settings()
