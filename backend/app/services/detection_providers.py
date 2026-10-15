"""
services/detection_providers.py
-------------------------------
Pluggable "detection synthesis" providers. Anything that can turn a hypothesis
into a Sigma rule implements Provider. The validation gate is applied by the
CALLER to every provider's output, so a future LLM can never bypass it.

  template      keyword template (fallback, honest about being a stub)
  corpus        retrieval of curated SigmaHQ rules from the platform DB
  llm_qwen3     Qwen3-8B + QLoRA hypothesis->Sigma model, served by vLLM through its
                OpenAI-compatible API. Available only when LLM_PROVIDER_URL is set.

Environment:
  LLM_PROVIDER_URL   base URL incl. /v1, e.g. http://gpu-host:8000/v1   (required)
  LLM_MODEL          served model name / LoRA adapter name               (default: qwen3-8b-sigma)
  LLM_API_KEY        bearer key if vLLM was started with --api-key       (optional)
  LLM_TIMEOUT        seconds per request                                 (default: 120)
  LLM_MAX_TOKENS     generation limit                                    (default: 1200)

LLM output is untrusted. The caller always runs validate_rule() on it.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.services.rule_generator import generate_rule_draft
from app.services.rule_retrieval import find_candidates


class ProviderUnavailable(Exception):
    pass


@dataclass
class Generated:
    yaml_text: str
    method: str
    source_rule_id: str | None = None
    note: str = ""


class Provider:
    id = "base"
    label = "Base"
    kind = "deterministic"
    description = ""
    connected = True
    reason = ""
    metrics: dict[str, Any] = {}

    def describe(self) -> dict[str, Any]:
        return {"id": self.id, "label": self.label, "kind": self.kind, "description": self.description,
                "available": self.connected, "reason": "" if self.connected else self.reason, "metrics": self.metrics,
                "gate_required": True}

    def generate(self, db: Session, hypothesis: str, technique_id: str | None, platform: str, **ctx) -> list[Generated]:
        raise NotImplementedError


class TemplateProvider(Provider):
    id, label, kind = "template", "Keyword template", "deterministic"
    description = "Deterministic keyword templates. Fallback only; often produces a rule that still needs an indicator."

    def generate(self, db, hypothesis, technique_id, platform, **ctx):
        d = generate_rule_draft(hypothesis, technique_id, platform, ctx.get("objective"), ctx.get("behaviors"), ctx.get("limits"))
        return [Generated(d.yaml_text, "template_v0")]


class CorpusProvider(Provider):
    id, label, kind = "corpus", "Sigma corpus retrieval", "retrieval"
    description = "Selects curated SigmaHQ rules for the technique, ranked by platform, loaded telemetry and a dry-run."

    def generate(self, db, hypothesis, technique_id, platform, **ctx):
        if not technique_id:
            return []
        limit = int(ctx.get("limit", 1))
        return [Generated(c.yaml_text, "corpus_retrieval_v1", c.corpus_rule_id, f"score {c.score:.0f}; {c.reason}")
                for c in find_candidates(db, technique_id, platform, limit=limit)]


_THINK_RE = re.compile(r"<think>.*?</think>", re.S | re.I)
_FENCE_RE = re.compile(r"```(?:yaml|yml)?\s*\n(.*?)```", re.S | re.I)

SYSTEM_PROMPT = (
    "You are a detection engineer. Convert the hunt hypothesis into ONE vendor-neutral Sigma rule in YAML. "
    "Use only fields that exist for the given log source. Do not invent Event IDs or indicators. "
    "Include title, id, status, description, tags (attack.tXXXX), logsource, detection with a condition, "
    "falsepositives and level. Return only the YAML."
)


def extract_yaml(text: str) -> str:
    """Pull the Sigma YAML out of a chat completion (strips <think> blocks and code fences)."""
    text = _THINK_RE.sub("", text or "").strip()
    m = _FENCE_RE.search(text)
    if m:
        text = m.group(1).strip()
    i = text.find("title:")
    return text[i:].strip() if i > 0 else text


class QwenProvider(Provider):
    id, label, kind = "llm_qwen3", "Qwen3-8B + QLoRA (LLM)", "llm"
    description = ("Fine-tuned model that converts a grounded hypothesis into a vendor-neutral Sigma rule. "
                   "Output is untrusted until it passes the same validation gate as every other source.")
    # Reported in the Phase-1 MVP report (398-example held-out set). Not re-measured by this platform.
    metrics = {
        "model": "Qwen3-8B, QLoRA 4-bit", "inference": "vLLM (OpenAI-compatible API)",
        "structural_validity": "394/398 (99.0%) vs 0/398 prompt-only baseline",
        "attack_tag_presence": "66.6% vs 52.5% baseline",
        "provenance": "Phase 1 MVP report, preliminary; grouped held-out re-evaluation pending",
    }
    _health_cache: tuple[float, bool, str] = (0.0, False, "")

    @property
    def endpoint(self) -> str:
        return os.environ.get("LLM_PROVIDER_URL", "").rstrip("/")

    def _headers(self) -> dict[str, str]:
        key = os.environ.get("LLM_API_KEY", "")
        return {"Authorization": f"Bearer {key}"} if key else {}

    def _probe(self) -> tuple[bool, str]:
        """Is the endpoint reachable? Cached for 30 s so /generator/providers stays fast."""
        if not self.endpoint:
            return False, "LLM_PROVIDER_URL is not set; no inference endpoint is wired to the platform."
        ts, ok, why = QwenProvider._health_cache
        if time.time() - ts < 30:
            return ok, why
        try:
            import httpx
            r = httpx.get(f"{self.endpoint}/models", headers=self._headers(), timeout=3)
            ok, why = (r.status_code < 400, "" if r.status_code < 400 else f"endpoint answered HTTP {r.status_code}")
        except Exception as exc:  # noqa: BLE001
            ok, why = False, f"endpoint unreachable: {exc}"
        QwenProvider._health_cache = (time.time(), ok, why)
        return ok, why

    @property
    def connected(self) -> bool:  # type: ignore[override]
        return self._probe()[0]

    @property
    def reason(self) -> str:  # type: ignore[override]
        return self._probe()[1]

    def build_messages(self, hypothesis: str, technique_id: str | None, platform: str, **ctx) -> list[dict[str, str]]:
        lines = [f"Hypothesis: {hypothesis.strip()}"]
        if technique_id:
            lines.append(f"ATT&CK technique: {technique_id}")
        lines.append(f"Platform: {platform}")
        if ctx.get("objective"):
            lines.append(f"Detection objective: {ctx['objective']}")
        if ctx.get("behaviors"):
            lines.append("Observable behaviors:\n- " + "\n- ".join(ctx["behaviors"]))
        if ctx.get("limits"):
            lines.append("Known limitations:\n- " + "\n- ".join(ctx["limits"]))
        return [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": "\n".join(lines)}]

    def generate(self, db, hypothesis, technique_id, platform, **ctx):
        if not self.endpoint:
            raise ProviderUnavailable(self.reason)
        import httpx
        body = {
            "model": os.environ.get("LLM_MODEL", "qwen3-8b-sigma"),
            "messages": self.build_messages(hypothesis, technique_id, platform, **ctx),
            "temperature": 0.0,
            "max_tokens": int(os.environ.get("LLM_MAX_TOKENS", "1200")),
            "chat_template_kwargs": {"enable_thinking": False},
        }
        try:
            r = httpx.post(f"{self.endpoint}/chat/completions", json=body, headers=self._headers(),
                           timeout=float(os.environ.get("LLM_TIMEOUT", "120")))
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"]
        except Exception as exc:  # noqa: BLE001
            QwenProvider._health_cache = (0.0, False, "")
            raise ProviderUnavailable(f"LLM request failed: {exc}") from exc
        y = extract_yaml(text)
        try:
            import yaml as _yaml
            doc = _yaml.safe_load(y)
        except Exception as exc:  # noqa: BLE001
            raise ProviderUnavailable(f"model did not return valid YAML: {exc}") from exc
        if not isinstance(doc, dict) or "detection" not in doc:
            raise ProviderUnavailable("model output is not a Sigma rule (no detection block)")
        return [Generated(y, "llm_qwen3", None, f"model {body['model']}")]


_PROVIDERS: dict[str, Provider] = {p.id: p for p in (CorpusProvider(), TemplateProvider(), QwenProvider())}


def get(provider_id: str) -> Provider:
    if provider_id not in _PROVIDERS:
        raise KeyError(provider_id)
    return _PROVIDERS[provider_id]


def describe_all() -> list[dict[str, Any]]:
    return [p.describe() for p in _PROVIDERS.values()]
