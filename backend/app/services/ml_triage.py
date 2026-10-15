"""
services/ml_triage.py
---------------------
Runtime integration of the frozen XGBoost TE-v3.1 triage model
(ml_triage_production_v1) behind the existing triage seam.

Contract (see ML_INTEGRATION_GUIDE.md):
  * artifacts are read-only, integrity-checked against bundle_manifest.json
  * model loaded once per process (lazy, thread-safe), never retrained here
  * feature building replicates build_features_v2.py / build_target_encoding_v3_1.py
  * unseen categorical -> missing; unseen TE key -> global train prior
  * probabilities: identity calibration + row normalisation
  * decision: argmax(p * [1.9, 1.0, 1.2]); TP routes to PRIORITY_ESCALATION only
    if P(TP) >= 0.5, otherwise NEEDS_REVIEW. BP/FP are never auto-closed.
  * analyst verdict/history is NEVER a model input
  * if the live finding cannot satisfy the feature contract (coverage gate) the
    result is an explicit ML-unavailable status and the caller falls back to the
    heuristic triage, marked triage_source="heuristic_fallback".

IMPORTANT: the model was trained on Microsoft GUIDE (Defender alerts). Most of its
inputs (AlertTitle, DetectorId, ThreatFamily, ...) do not exist for Sigma/EVTX
findings. The adapter below only fills fields whose meaning is genuinely
equivalent and never invents the rest; the coverage gate then decides.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger("ml_triage")

MODEL_VERSION = "xgboost_te_v3_1"
CLASSES = ["TRUE_POSITIVE", "BENIGN_POSITIVE", "FALSE_POSITIVE"]
MULTIPLIERS = (1.9, 1.0, 1.2)          # locked decision policy
TP_THRESHOLD = 0.5                      # locked routing threshold
BEST_ITERATION = 59                     # locked; iteration_range = (0, 60)
MISSING = "__MISSING__"
BATCH_LIMIT = 500

# Raw GUIDE inputs the model consumes, grouped for the coverage report.
CATEGORICAL_RAW = ["Category", "MitreTechniques", "EntityType", "EvidenceRole", "ResourceType", "Roles",
                   "OSFamily", "OSVersion", "AntispamDirection", "CountryCode", "State", "City"]
IDENTITY_RAW = ["AlertTitle", "DetectorId", "ApplicationName", "ThreatFamily"]   # TE / frequency only
SEMANTIC_FIELDS = CATEGORICAL_RAW + IDENTITY_RAW                                   # 16 coverage fields
PRESENCE_RAW = {"IpAddress": "has_ip_address", "Url": "has_url", "Sha256": "has_sha256", "DeviceId": "has_device",
                "AccountSid": "has_account_sid", "AccountUpn": "has_account_upn",
                "AccountObjectId": "has_account_object_id", "NetworkMessageId": "has_network_message",
                "EmailClusterId": "has_email_cluster", "RegistryKey": "has_registry_key",
                "FileName": "has_file_name", "FolderPath": "has_folder_path"}
FREQUENCY_RAW = ["AlertTitle", "DetectorId", "DeviceId", "ApplicationName", "ThreatFamily", "Category",
                 "EntityType", "ResourceType", "OSFamily", "CountryCode"]
TE_COLUMNS = ["AlertTitle", "DetectorId", "ApplicationName", "ThreatFamily", "Category", "EntityType",
              "ResourceType", "CountryCode"]
INTERACTIONS = {
    "Category__EntityType": ("Category", "EntityType"),
    "Category__EvidenceRole": ("Category", "EvidenceRole"),
    "OSFamily__Category": ("OSFamily", "Category"),
    "ResourceType__EntityType": ("ResourceType", "EntityType"),
    "CountryCode__Category": ("CountryCode", "Category"),
}

# ATT&CK tactic tag -> GUIDE Category level (exact name equivalence only).
TACTIC_TO_CATEGORY = {
    "initial-access": "InitialAccess", "execution": "Execution", "persistence": "Persistence",
    "privilege-escalation": "PrivilegeEscalation", "defense-evasion": "DefenseEvasion",
    "credential-access": "CredentialAccess", "discovery": "Discovery", "lateral-movement": "LateralMovement",
    "collection": "Collection", "command-and-control": "CommandAndControl", "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def _bundle_dir() -> Path:
    env = os.environ.get("ML_TRIAGE_BUNDLE_DIR")
    if env:
        return Path(env)
    # backend/app/services -> backend/app/data/ml_triage/ml_triage_production_v1
    return Path(__file__).resolve().parent.parent / "data" / "ml_triage" / "ml_triage_production_v1"


def _mode() -> str:
    m = os.environ.get("ML_TRIAGE_MODE", "auto").strip().lower()
    return m if m in ("off", "auto") else "auto"


def _min_coverage() -> float:
    try:
        return float(os.environ.get("ML_MIN_COVERAGE", "0.5"))
    except ValueError:
        return 0.5


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class MLTriageEngine:
    """Loads the frozen bundle once and scores GUIDE-shaped records."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loaded = False
        self.error: str | None = None
        self.model = None
        self.feature_names: list[str] = []
        self.levels: dict[str, list[str]] = {}
        self.freq: dict[str, dict[str, int]] = {}
        self.te: dict[str, dict[str, tuple[float, float, float]]] = {}
        self.priors: list[float] = []
        self.integrity: dict[str, Any] = {}

    # ---------------------------------------------------------------- loading
    def ensure_loaded(self) -> bool:
        if self._loaded:
            return self.error is None
        with self._lock:
            if self._loaded:
                return self.error is None
            try:
                self._load()
                self.error = None
            except Exception as exc:  # never crash the hunt pipeline
                self.error = f"{type(exc).__name__}: {exc}"
                log.warning("ML triage bundle unavailable: %s", self.error)
            self._loaded = True
        return self.error is None

    def _load(self) -> None:
        import joblib
        import pandas as pd
        import xgboost as xgb

        root = _bundle_dir()
        manifest_path = root / "bundle_manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"bundle not found at {root}")
        manifest = json.loads(manifest_path.read_text())

        # Integrity: every manifest file must exist and match. Skipping the check is not allowed.
        verify_all = os.environ.get("ML_VERIFY_FULL_BUNDLE", "1") != "0"
        checked, bad = 0, []
        for item in manifest["files"]:
            p = root / item["path"]
            if not p.exists():
                bad.append(f"missing:{item['path']}")
                continue
            if not verify_all and item["size_bytes"] > 5_000_000:
                if p.stat().st_size != item["size_bytes"]:
                    bad.append(f"size:{item['path']}")
                continue
            if _sha256(p) != item["sha256"]:
                bad.append(f"sha256:{item['path']}")
            checked += 1
        if bad:
            raise RuntimeError(f"bundle integrity check failed: {bad[:5]}")
        self.integrity = {"files_in_manifest": len(manifest["files"]), "hash_verified": checked, "status": "ok"}

        self.levels = joblib.load(root / "model" / "categorical_levels_v3_1.joblib")
        self.freq = joblib.load(root / "preprocessing" / "train_frequency_maps_v2.joblib")
        te_contract = json.loads((root / "preprocessing" / "target_encoding" /
                                  "target_encoding_contract_v3_1.json").read_text())
        self.priors = [float(x) for x in te_contract["global_train_priors"]]
        for col in TE_COLUMNS:
            df = pd.read_parquet(root / "preprocessing" / "target_encoding" / f"{col}_mapping.parquet")
            self.te[col] = {str(v): (float(a), float(b), float(c))
                            for v, a, b, c in zip(df["value"], df["te_tp"], df["te_bp"], df["te_fp"])}

        clf = xgb.XGBClassifier()
        clf.load_model(str(root / "model" / "xgboost_te_v3_1.json"))
        self.model = clf
        self.feature_names = list(clf.get_booster().feature_names)
        if len(self.feature_names) != 103:
            raise RuntimeError(f"unexpected feature count {len(self.feature_names)}")

    # ---------------------------------------------------------------- features
    @staticmethod
    def _canon(v: Any) -> str:
        if v is None:
            return MISSING
        if isinstance(v, float) and math.isnan(v):
            return MISSING
        s = str(v)
        return MISSING if s.strip() == "" or s.lower() in ("nan", "<na>", "none") else s

    @staticmethod
    def _present(v: Any) -> int:
        return int(v is not None and not (isinstance(v, float) and math.isnan(v)) and str(v).strip() != "")

    def build_frame(self, records: list[dict[str, Any]]):
        import numpy as np
        import pandas as pd

        n = len(records)
        canon = {c: [self._canon(r.get(c)) for r in records]
                 for c in set(CATEGORICAL_RAW + IDENTITY_RAW + FREQUENCY_RAW)}
        cols: dict[str, Any] = {}

        # categoricals (12 base + 5 interactions), unseen -> missing (NaN) via fixed categories
        for c in CATEGORICAL_RAW:
            cols[c] = canon[c]
        for out, (l, r) in INTERACTIONS.items():
            cols[out] = [f"{a}||{b}" for a, b in zip(canon[l], canon[r])]

        pres = {}
        for raw, out in PRESENCE_RAW.items():
            pres[out] = [self._present(r.get(raw)) for r in records]
        cols.update(pres)

        def s(*names):
            return [sum(pres[nm][i] for nm in names) for i in range(n)]

        cols["evidence_presence_count"] = s(*PRESENCE_RAW.values())
        cols["identity_evidence_count"] = s("has_account_sid", "has_account_upn", "has_account_object_id")
        cols["network_evidence_count"] = s("has_ip_address", "has_url", "has_network_message", "has_email_cluster")
        cols["file_evidence_count"] = s("has_sha256", "has_file_name", "has_folder_path")
        cols["registry_evidence_count"] = s("has_registry_key")

        import re
        tech_re = re.compile(r"T\d{4}(?:\.\d{3})?")
        cols["mitre_technique_count"] = [min(20, len(tech_re.findall(v))) for v in canon["MitreTechniques"]]
        cols["roles_count"] = [0 if v == MISSING else min(20, len(re.findall(r"[,;|]", v)) + 1)
                               for v in canon["Roles"]]
        cols["alert_title_length"] = [min(500, len(v)) for v in canon["AlertTitle"]]

        ts = pd.to_datetime(pd.Series([r.get("Timestamp") for r in records]), errors="coerce", utc=True)
        hour, dow, month, dom = ts.dt.hour, ts.dt.dayofweek, ts.dt.month, ts.dt.day
        two_pi = 2 * np.pi
        cols["hour_sin"] = np.sin(two_pi * hour.fillna(0) / 24)
        cols["hour_cos"] = np.cos(two_pi * hour.fillna(0) / 24)
        cols["dow_sin"] = np.sin(two_pi * dow.fillna(0) / 7)
        cols["dow_cos"] = np.cos(two_pi * dow.fillna(0) / 7)
        cols["month_sin"] = np.sin(two_pi * (month.fillna(1) - 1) / 12)
        cols["month_cos"] = np.cos(two_pi * (month.fillna(1) - 1) / 12)
        cols["dom_sin"] = np.sin(two_pi * (dom.fillna(1) - 1) / 31)
        cols["dom_cos"] = np.cos(two_pi * (dom.fillna(1) - 1) / 31)
        cols["is_weekend"] = dow.isin([5, 6]).astype(int)
        cols["is_business_hours"] = (dow.isin([0, 1, 2, 3, 4]) & hour.between(8, 18)).astype(int)
        cols["is_night"] = ((hour < 6) | (hour >= 22)).fillna(False).astype(int)
        cols["timestamp_missing"] = ts.isna().astype(int)

        for c in FREQUENCY_RAW:
            m = self.freq.get(c, {})
            counts = np.array([m.get(v, 0) for v in canon[c]], dtype=np.int64)
            cols[f"{c}__train_logfreq"] = np.log1p(counts)
            cols[f"{c}__seen_in_train"] = (counts > 0).astype(int)
            cols[f"{c}__rare_in_train"] = ((counts > 0) & (counts <= 10)).astype(int)

        for c in TE_COLUMNS:
            m = self.te[c]
            vals = [m.get(v, tuple(self.priors)) for v in canon[c]]   # unseen -> global prior
            cols[f"te_{c}_tp"] = [v[0] for v in vals]
            cols[f"te_{c}_bp"] = [v[1] for v in vals]
            cols[f"te_{c}_fp"] = [v[2] for v in vals]

        df = pd.DataFrame(cols)
        for c, levels in self.levels.items():
            df[c] = pd.Categorical(df[c].astype(str), categories=levels)   # unseen -> NaN (missing)
        missing_cols = [c for c in self.feature_names if c not in df.columns]
        if missing_cols:
            raise RuntimeError(f"feature builder missing columns: {missing_cols[:5]}")
        df = df[self.feature_names]
        for c in df.columns:
            if c not in self.levels:
                df[c] = df[c].astype("float32")
        return df

    # ---------------------------------------------------------------- coverage
    @staticmethod
    def coverage(record: dict[str, Any]) -> dict[str, Any]:
        present = [f for f in SEMANTIC_FIELDS if MLTriageEngine._canon(record.get(f)) != MISSING]
        return {"fields_total": len(SEMANTIC_FIELDS), "fields_present": len(present),
                "ratio": round(len(present) / len(SEMANTIC_FIELDS), 3),
                "present": present, "missing": [f for f in SEMANTIC_FIELDS if f not in present]}

    # ---------------------------------------------------------------- scoring
    def score_records(self, records: list[dict[str, Any]], enforce_coverage: bool = True) -> list[dict[str, Any]]:
        """Score GUIDE-shaped records. Returns one result per record (ML or explicit unavailable)."""
        if _mode() == "off":
            return [self._unavailable("ML_TRIAGE_MODE=off", self.coverage(r)) for r in records]
        if not self.ensure_loaded():
            return [self._unavailable(f"bundle unavailable: {self.error}", self.coverage(r)) for r in records]
        if len(records) > BATCH_LIMIT:
            raise ValueError(f"batch limit is {BATCH_LIMIT}")

        covs = [self.coverage(r) for r in records]
        ok_idx = [i for i, c in enumerate(covs) if (not enforce_coverage) or c["ratio"] >= _min_coverage()]
        results: list[dict[str, Any]] = [
            self._unavailable(f"insufficient feature coverage ({c['fields_present']}/{c['fields_total']} "
                              f"< {_min_coverage():.0%}); fields are not invented", c) for c in covs]
        if not ok_idx:
            return results
        try:
            import numpy as np
            frame = self.build_frame([records[i] for i in ok_idx])
            proba = self.model.predict_proba(frame, iteration_range=(0, BEST_ITERATION + 1)).astype(np.float64)
            proba = proba / proba.sum(axis=1, keepdims=True)           # identity calibration + normalisation
            for row, i in zip(proba, ok_idx):
                results[i] = self._decide(row, covs[i])
        except Exception as exc:
            log.exception("ML scoring failed")
            for i in ok_idx:
                results[i] = self._unavailable(f"scoring error: {type(exc).__name__}: {exc}", covs[i])
        return results

    @staticmethod
    def _decide(p, cov) -> dict[str, Any]:
        scores = [p[k] * MULTIPLIERS[k] for k in range(3)]
        k = max(range(3), key=lambda j: scores[j])
        if k == 0:
            route = "PRIORITY_ESCALATION" if p[0] >= TP_THRESHOLD else "NEEDS_REVIEW"
        elif k == 1:
            route = "BENIGN_REVIEW_QUEUE"
        else:
            route = "FALSE_POSITIVE_REVIEW_QUEUE"
        return {
            "available": True, "status": "ml", "triage_source": "ml_model", "model_version": MODEL_VERSION,
            "predicted_class": CLASSES[k],
            "probability_true_positive": round(float(p[0]), 6),
            "probability_benign_positive": round(float(p[1]), 6),
            "probability_false_positive": round(float(p[2]), 6),
            "model_probability": round(float(p[k]), 6),
            "route": route, "needs_review": route != "PRIORITY_ESCALATION",
            "autonomous_action": False, "coverage": cov,
            "note": "Analyst-assisted prioritisation. Not a final verdict; no automatic close/suppress.",
        }

    @staticmethod
    def _unavailable(reason: str, cov: dict[str, Any]) -> dict[str, Any]:
        return {"available": False, "status": "ml_unavailable", "triage_source": "heuristic_fallback",
                "model_version": MODEL_VERSION, "reason": reason, "coverage": cov, "autonomous_action": False}

    def status(self) -> dict[str, Any]:
        loaded = self.ensure_loaded() if _mode() != "off" else False
        return {"mode": _mode(), "model_version": MODEL_VERSION, "bundle_dir": str(_bundle_dir()),
                "loaded": loaded, "error": self.error, "integrity": self.integrity,
                "min_coverage": _min_coverage(), "feature_count": len(self.feature_names),
                "deployment_mode": "analyst_assisted", "autonomous_actions_enabled": False}


_engine: MLTriageEngine | None = None
_engine_lock = threading.Lock()


def get_engine() -> MLTriageEngine:
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = MLTriageEngine()
    return _engine


# ------------------------------------------------------------------ platform adapter
def build_guide_record(fields: dict[str, Any], meta: dict[str, Any], tags: list[str],
                       technique_ids: list[str]) -> dict[str, Any]:
    """Map a platform rule match to GUIDE-style inputs.

    Only semantically equivalent fields are filled:
      Category        <- ATT&CK tactic tag (exact tactic name equivalence)
      MitreTechniques <- rule technique ids ('T1059;T1059.001' format)
      Timestamp       <- event timestamp
      presence flags  <- whether the event actually carries IP/URL/hash/host/account/registry/file/path
    Everything else (AlertTitle, DetectorId, ThreatFamily, EntityType, OS*, geo, ...) is left absent.
    """
    rec: dict[str, Any] = {}
    for t in tags or []:
        tt = str(t).lower()
        if tt.startswith("attack."):
            cat = TACTIC_TO_CATEGORY.get(tt[len("attack."):])
            if cat:
                rec["Category"] = cat
                break
    if technique_ids:
        rec["MitreTechniques"] = ";".join(dict.fromkeys(technique_ids))
    rec["Timestamp"] = meta.get("timestamp")
    g = fields.get
    rec["IpAddress"] = g("DestinationIp") or g("SourceIp") or g("IpAddress")
    rec["Url"] = g("Url") or g("DestinationHostname")
    rec["Sha256"] = g("Sha256") or g("Hashes")
    rec["DeviceId"] = meta.get("host") or g("Computer")
    rec["AccountUpn"] = g("User")
    rec["RegistryKey"] = g("TargetObject")
    rec["FileName"] = g("TargetFilename") or g("Image")
    rec["FolderPath"] = g("CurrentDirectory")
    return rec


def ml_triage_for_match(fields: dict[str, Any], meta: dict[str, Any], tags: list[str],
                        technique_ids: list[str]) -> dict[str, Any]:
    """Safe entry point used by the campaign engine. Never raises."""
    try:
        rec = build_guide_record(fields, meta, tags, technique_ids)
        return get_engine().score_records([rec])[0]
    except Exception as exc:
        log.exception("ml_triage_for_match failed")
        return MLTriageEngine._unavailable(f"adapter error: {type(exc).__name__}: {exc}",
                                           {"fields_total": len(SEMANTIC_FIELDS), "fields_present": 0,
                                            "ratio": 0.0, "present": [], "missing": list(SEMANTIC_FIELDS)})
