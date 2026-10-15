"""
services/triage.py
------------------
Explainable, deterministic finding triage. Every score ships with the
features and weights that produced it so an analyst can see WHY, and so the
same feature vector can later be fed to (or replaced by) the trained ML
classifier without changing the API.

  score = 100 * sigmoid(bias + sum(weight_i * feature_i))   -> risk 0..100
  threat_probability = score / 100 (calibrated later against analyst verdicts)

Analyst verdicts are folded back in via `prior_for_rule()` so a rule that
analysts keep marking false-positive is automatically down-weighted.
"""
from __future__ import annotations

import math
import re
from typing import Any

from sqlalchemy.orm import Session

from app.models.execution import AnalystVerdict

LEVEL_W = {"critical": 1.6, "high": 1.1, "medium": 0.5, "low": 0.0, "informational": -0.4}
SUSPICIOUS_PARENTS = ("winword.exe", "excel.exe", "outlook.exe", "wmiprvse.exe", "mshta.exe", "w3wp.exe", "cscript.exe", "wscript.exe")
LOLBINS = ("powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
           "wmic.exe", "pcalua.exe", "msiexec.exe", "cscript.exe", "wscript.exe", "schtasks.exe", "appcmd.exe")
OBFUSCATION = re.compile(r"(-enc(odedcommand)?\b|frombase64string|\bfor\s*/l\b|\^.\^|`.`|invoke-expression|\biex\b|-nop\b|-w\s+hidden|downloadstring|bypass)", re.I)
BIAS = -1.2


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def extract_features(event: dict[str, Any], rule_level: str, technique_count: int, rule_specificity: float) -> dict[str, float]:
    img = str(event.get("Image", "")).lower()
    cmd = str(event.get("CommandLine", "") or event.get("ScriptBlockText", ""))
    parent = str(event.get("ParentImage", "")).lower()
    user = str(event.get("User", "")).lower()
    return {
        "rule_level": LEVEL_W.get(rule_level.lower(), 0.5),
        "rule_specificity": rule_specificity,                                  # 0..1, fewer tags => higher
        "lolbin_image": 1.0 if any(img.endswith(b) for b in LOLBINS) else 0.0,
        "suspicious_parent": 1.0 if any(parent.endswith(p) for p in SUSPICIOUS_PARENTS) else 0.0,
        "obfuscation_markers": min(1.0, len(OBFUSCATION.findall(cmd)) / 2),
        "long_command_line": 1.0 if len(cmd) > 200 else 0.0,
        "system_context": 0.4 if "system" in user else 0.0,
        "multi_technique_rule": 0.3 if technique_count > 3 else 0.0,
    }


WEIGHTS = {
    "rule_level": 1.0, "rule_specificity": 0.8, "lolbin_image": 0.5, "suspicious_parent": 1.4,
    "obfuscation_markers": 1.5, "long_command_line": 0.4, "system_context": -0.2, "multi_technique_rule": -0.5,
}


def prior_for_rule(db: Session, rule_source_id: str | None) -> tuple[float, dict[str, int]]:
    """Log-odds adjustment from analyst history for findings produced by this rule."""
    if not rule_source_id:
        return 0.0, {}
    from app.models.finding import HuntFinding
    rows = (
        db.query(AnalystVerdict.verdict)
        .join(HuntFinding, HuntFinding.finding_id == AnalystVerdict.finding_id)
        .filter(HuntFinding.rule_id == rule_source_id).all()
    )
    counts = {"true_positive": 0, "false_positive": 0}
    for (v,) in rows:
        if v in counts:
            counts[v] += 1
    n = counts["true_positive"] + counts["false_positive"]
    if n < 3:
        return 0.0, counts
    ratio = (counts["true_positive"] + 1) / (n + 2)   # Laplace smoothed precision
    return round(math.log(ratio / (1 - ratio)), 3), counts


def score_finding(db: Session, event: dict[str, Any], rule_level: str, technique_count: int,
                  rule_source_id: str | None = None) -> dict[str, Any]:
    specificity = 1.0 if technique_count <= 1 else max(0.0, 1 - 0.15 * (technique_count - 1))
    feats = extract_features(event, rule_level, technique_count, specificity)
    prior, hist = prior_for_rule(db, rule_source_id)
    contributions = {k: round(WEIGHTS[k] * v, 3) for k, v in feats.items()}
    logit = BIAS + sum(contributions.values()) + prior
    p = _sigmoid(logit)
    risk = round(p * 100, 1)
    label = "high" if risk >= 80 else "medium" if risk >= 55 else "low"
    top = sorted(contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)[:4]
    return {
        "model": "explainable_logistic_v1", "risk_score": risk, "threat_probability": round(p, 3),
        "label": label, "features": feats, "contributions": contributions, "bias": BIAS,
        "analyst_prior": prior, "analyst_history": hist,
        "route": "auto_escalate" if risk >= 80 else "analyst_review" if risk >= 40 else "low_priority",
        "top_factors": [{"factor": k, "impact": v} for k, v in top if v],
    }


# ----------------------------------------------------------------------------
# ML triage merge (xgboost_te_v3_1). The heuristic score is always computed so
# there is a safe fallback and an explainable reference; the ML result is never
# presented unless it was genuinely produced by the model.
# ----------------------------------------------------------------------------
_ML_ROUTE_MAP = {
    "PRIORITY_ESCALATION": "auto_escalate",          # prioritisation only; no autonomous action
    "NEEDS_REVIEW": "analyst_review",
    "BENIGN_REVIEW_QUEUE": "low_priority",           # never auto-closed
    "FALSE_POSITIVE_REVIEW_QUEUE": "low_priority",   # never auto-closed/suppressed
}


def apply_ml(triage: dict[str, Any], ml: dict[str, Any]) -> dict[str, Any]:
    """Merge an ml_triage result into the heuristic triage dict (same API shape).

    risk_score semantics when ML is active: 100 * P(TRUE_POSITIVE). A high
    FALSE_POSITIVE / BENIGN_POSITIVE probability therefore never raises risk.
    """
    heuristic = {k: triage.get(k) for k in ("model", "risk_score", "threat_probability", "route", "label")}
    triage["ml"] = ml
    if not ml.get("available"):
        triage["triage_source"] = "heuristic_fallback"
        return triage
    p_tp = float(ml["probability_true_positive"])
    risk = round(p_tp * 100, 1)
    triage.update({
        "triage_source": "ml_model", "model": ml["model_version"], "risk_score": risk,
        "threat_probability": round(p_tp, 3),
        "label": "high" if risk >= 80 else "medium" if risk >= 55 else "low",
        "route": _ML_ROUTE_MAP.get(ml["route"], "analyst_review"),
        "ml_route": ml["route"], "predicted_class": ml["predicted_class"],
        "top_factors": [],                      # heuristic factors do not explain the ML score
        "heuristic_reference": heuristic,
    })
    return triage
