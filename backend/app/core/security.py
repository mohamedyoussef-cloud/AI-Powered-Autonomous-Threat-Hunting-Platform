"""core/security.py -- role guards built on the existing JWT auth router."""
from __future__ import annotations

from fastapi import Depends, HTTPException

from app.routers.auth import get_current_user


def require_user(user=Depends(get_current_user)):
    return user


def require_analyst(user=Depends(get_current_user)):
    if user["role"] not in ("Administrator", "Analyst"):
        raise HTTPException(403, "Analyst or Administrator role required")
    return user


def require_admin(user=Depends(get_current_user)):
    if user["role"] != "Administrator":
        raise HTTPException(403, "Administrator role required")
    return user
