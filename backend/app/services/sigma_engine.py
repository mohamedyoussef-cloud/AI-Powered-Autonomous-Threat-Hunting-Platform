"""
services/sigma_engine.py
------------------------
A self-contained Sigma engine so that the rule an analyst reviews is the
rule that actually executes.

  parse_rule()      YAML -> SigmaRule (+ structured validation issues)
  SigmaRule.match() evaluate the rule against one normalized event
  compile_spl()     Sigma -> Splunk SPL (single `| where` predicate)
  validate_rule()   pre-execution gate: schema, placeholders, unsupported
                    features, ATT&CK tags, field availability

Supported: field maps, OR-lists of maps, keyword lists, modifiers
contains/startswith/endswith/all/re/windash/lt/lte/gt/gte/exists,
wildcards, conditions with and/or/not/parentheses and "1 of x*" /
"all of x*" / "1 of them" / "all of them".

Not supported (rule is reported as `unsupported`, never silently skipped):
aggregations (`| count`, `near`), cidr, base64/base64offset, fieldref,
expand. pySigma can be used for those when installed (see compile_spl()).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

PLACEHOLDER_MARKERS = ("REPLACE_WITH_INDICATOR", "TODO", "CHANGEME", "REPLACE_ME")
SUPPORTED_MODS = {
    "contains", "startswith", "endswith", "all", "re", "i", "m", "s",
    "windash", "lt", "lte", "gt", "gte", "exists", "cased",
}
UNSUPPORTED_MODS = {"cidr", "base64", "base64offset", "fieldref", "expand", "utf16", "utf16le", "utf16be", "wide"}

SPL_SOURCETYPE = {
    "process_creation": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "network_connection": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "file_event": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "registry_set": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "image_load": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "dns_query": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "process_access": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
}
SPL_SERVICE_SOURCETYPE = {
    "security": "WinEventLog:Security",
    "system": "WinEventLog:System",
    "powershell": "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
    "sysmon": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
}


class UnsupportedFeature(Exception):
    pass


# --------------------------------------------------------------------------
# Value matchers
# --------------------------------------------------------------------------
def _norm(v: Any) -> str:
    return "" if v is None else str(v)


def _windash_variants(s: str) -> list[str]:
    if "-" not in s:
        return [s]
    out = {s}
    for dash in ("/", "\u2013", "\u2014", "\u2015"):
        out.add(re.sub(r"(?<![\w-])-(?=\w)", dash, s))
    return list(out)


def _glob_to_regex(pattern: str, mode: str) -> str:
    """Sigma wildcards: * and ?, backslash-escape. mode: exact|contains|startswith|endswith"""
    out, i = [], 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
        i += 1
    body = "".join(out)
    if mode == "contains":
        return f".*{body}.*"
    if mode == "startswith":
        return f"{body}.*"
    if mode == "endswith":
        return f".*{body}"
    return body


@dataclass
class FieldMatcher:
    field: str
    mods: list[str]
    values: list[Any]

    def __post_init__(self):
        for m in self.mods:
            if m in UNSUPPORTED_MODS:
                raise UnsupportedFeature(f"modifier '{m}' on field '{self.field}'")
            if m not in SUPPORTED_MODS:
                raise UnsupportedFeature(f"unknown modifier '{m}' on field '{self.field}'")
        self._compiled: list[tuple[str, Any]] = []
        mode = "exact"
        for m in ("contains", "startswith", "endswith"):
            if m in self.mods:
                mode = m
        self.require_all = "all" in self.mods
        cased = "cased" in self.mods
        flags = 0 if cased else re.IGNORECASE
        if "re" in self.mods:
            if "i" in self.mods:
                flags |= re.IGNORECASE
            if "m" in self.mods:
                flags |= re.MULTILINE
            if "s" in self.mods:
                flags |= re.DOTALL
            for v in self.values:
                try:
                    self._compiled.append(("re", re.compile(_norm(v), flags)))
                except re.error as exc:
                    raise UnsupportedFeature(f"invalid regex on '{self.field}': {exc}")
            return
        if "exists" in self.mods:
            self._compiled.append(("exists", bool(self.values[0]) if self.values else True))
            return
        for op in ("lt", "lte", "gt", "gte"):
            if op in self.mods:
                for v in self.values:
                    self._compiled.append((op, float(v)))
                return
        for v in self.values:
            if v is None:
                self._compiled.append(("null", None))
                continue
            variants = _windash_variants(_norm(v)) if "windash" in self.mods else [_norm(v)]
            for s in variants:
                self._compiled.append(("re", re.compile(f"^{_glob_to_regex(s, mode)}$", flags | re.DOTALL)))

    def _one(self, kind: str, arg: Any, raw: Any) -> bool:
        if kind == "exists":
            return (raw is not None) == arg
        if kind == "null":
            return raw is None or raw == ""
        if raw is None:
            return False
        if kind == "re":
            return arg.search(_norm(raw)) is not None if "re" in self.mods else arg.match(_norm(raw)) is not None
        try:
            num = float(raw)
        except (TypeError, ValueError):
            return False
        return {"lt": num < arg, "lte": num <= arg, "gt": num > arg, "gte": num >= arg}[kind]

    def match(self, event: "Event") -> bool:
        raw = event.get(self.field)
        results = [self._one(k, a, raw) for k, a in self._compiled]
        if not results:
            return False
        return all(results) if self.require_all else any(results)


class Event:
    """Case-insensitive field view over a normalized event dict."""

    def __init__(self, data: dict[str, Any]):
        self._d = {str(k).lower(): v for k, v in data.items()}

    def get(self, name: str) -> Any:
        return self._d.get(name.lower())

    def text(self) -> str:
        return " ".join(_norm(v) for v in self._d.values())


@dataclass
class Selection:
    name: str
    groups: list[list[FieldMatcher]] = field(default_factory=list)  # OR of ANDs
    keywords: list[re.Pattern] = field(default_factory=list)

    def match(self, ev: Event) -> bool:
        if self.keywords:
            text = ev.text()
            if any(k.search(text) for k in self.keywords):
                return True
        return any(all(m.match(ev) for m in g) for g in self.groups if g)

    def fields(self) -> set[str]:
        return {m.field for g in self.groups for m in g}


def _build_selection(name: str, spec: Any) -> Selection:
    sel = Selection(name=name)
    items = spec if isinstance(spec, list) else [spec]
    for item in items:
        if isinstance(item, dict):
            group = []
            for key, val in item.items():
                parts = str(key).split("|")
                values = val if isinstance(val, list) else [val]
                group.append(FieldMatcher(parts[0], parts[1:], values))
            sel.groups.append(group)
        elif isinstance(item, (str, int, float)):
            sel.keywords.append(re.compile(_glob_to_regex(str(item), "contains"), re.IGNORECASE | re.DOTALL))
        else:
            raise UnsupportedFeature(f"selection '{name}' has unsupported shape")
    return sel


# --------------------------------------------------------------------------
# Condition parser  ->  nested tuples
# --------------------------------------------------------------------------
_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


def _tokenize(cond: str) -> list[str]:
    return _TOKEN.findall(cond)


class _CondParser:
    def __init__(self, tokens: list[str], names: list[str]):
        self.t, self.i, self.names = tokens, 0, names

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        node = self.or_()
        if self.i != len(self.t):
            raise UnsupportedFeature(f"unexpected token '{self.t[self.i]}' in condition")
        return node

    def or_(self):
        node = self.and_()
        while self.peek() == "or":
            self.take()
            node = ("or", node, self.and_())
        return node

    def and_(self):
        node = self.not_()
        while self.peek() == "and":
            self.take()
            node = ("and", node, self.not_())
        return node

    def not_(self):
        if self.peek() == "not":
            self.take()
            return ("not", self.not_())
        return self.atom()

    def atom(self):
        tok = self.peek()
        if tok is None:
            raise UnsupportedFeature("condition ended unexpectedly")
        if tok == "(":
            self.take()
            node = self.or_()
            if self.peek() != ")":
                raise UnsupportedFeature("missing ')' in condition")
            self.take()
            return node
        if tok in ("1", "all") and self.i + 2 < len(self.t) + 0 and self.t[self.i + 1].lower() == "of":
            quant = self.take().lower()
            self.take()
            target = self.take()
            if target.lower() == "them":
                matched = list(self.names)
            else:
                matched = [n for n in self.names if fnmatch.fnmatchcase(n.lower(), target.lower())]
            if not matched:
                raise UnsupportedFeature(f"'{quant} of {target}' matches no selection")
            return ("all_of" if quant == "all" else "any_of", matched)
        name = self.take()
        if name.lower() in ("|", "count", "near") or name.startswith("|"):
            raise UnsupportedFeature("aggregation / temporal conditions are not supported")
        if name not in self.names:
            raise UnsupportedFeature(f"condition references unknown selection '{name}'")
        return ("sel", name)


# --------------------------------------------------------------------------
# Rule
# --------------------------------------------------------------------------
@dataclass
class Issue:
    severity: str  # error | warning | info
    code: str
    message: str

    def dict(self):
        return {"severity": self.severity, "code": self.code, "message": self.message}


@dataclass
class SigmaRule:
    raw: dict[str, Any]
    title: str
    rule_id: str
    level: str
    tags: list[str]
    logsource: dict[str, str]
    selections: dict[str, Selection]
    condition: str
    ast: Any
    issues: list[Issue] = field(default_factory=list)

    # ---- introspection
    @property
    def technique_ids(self) -> list[str]:
        out = []
        for t in self.tags:
            m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(t).lower())
            if m:
                out.append(m.group(1).upper())
        return out

    def referenced_fields(self) -> set[str]:
        out: set[str] = set()
        for s in self.selections.values():
            out |= s.fields()
        return out

    def has_placeholder(self) -> bool:
        blob = yaml.safe_dump(self.raw.get("detection", {}))
        return any(m in blob for m in PLACEHOLDER_MARKERS)

    # ---- evaluation
    def _eval(self, node, ev: Event, cache: dict[str, bool]) -> bool:
        kind = node[0]
        if kind == "sel":
            n = node[1]
            if n not in cache:
                cache[n] = self.selections[n].match(ev)
            return cache[n]
        if kind == "and":
            return self._eval(node[1], ev, cache) and self._eval(node[2], ev, cache)
        if kind == "or":
            return self._eval(node[1], ev, cache) or self._eval(node[2], ev, cache)
        if kind == "not":
            return not self._eval(node[1], ev, cache)
        results = []
        for n in node[1]:
            if n not in cache:
                cache[n] = self.selections[n].match(ev)
            results.append(cache[n])
        return all(results) if kind == "all_of" else any(results)

    def match(self, event: dict[str, Any] | Event) -> bool:
        ev = event if isinstance(event, Event) else Event(event)
        return self._eval(self.ast, ev, {})

    def logsource_compatible(self, category: str | None, service: str | None, product: str | None) -> bool:
        ls = self.logsource
        if ls.get("product") and product and ls["product"].lower() != product.lower():
            return False
        if ls.get("category") and ls["category"].lower() != (category or "").lower():
            return False
        if ls.get("service") and ls["service"].lower() != (service or "").lower():
            return False
        return True


def parse_rule(yaml_text: str) -> tuple[SigmaRule | None, list[Issue]]:
    issues: list[Issue] = []
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        return None, [Issue("error", "yaml_invalid", f"YAML parse error: {exc}")]
    if not isinstance(doc, dict):
        return None, [Issue("error", "yaml_not_mapping", "Rule must be a YAML mapping")]
    for req in ("title", "logsource", "detection"):
        if req not in doc:
            issues.append(Issue("error", "missing_field", f"Missing required field '{req}'"))
    det = doc.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        issues.append(Issue("error", "missing_condition", "detection.condition is required"))
        return None, issues
    cond = det["condition"]
    if isinstance(cond, list):
        cond = " or ".join(f"({c})" for c in cond)
    cond = str(cond)
    if "|" in cond:
        issues.append(Issue("error", "unsupported_condition", "aggregation conditions (| count / near) are not supported by the built-in engine"))
        return None, issues
    selections: dict[str, Selection] = {}
    try:
        for name, spec in det.items():
            if name in ("condition", "timeframe"):
                continue
            selections[name] = _build_selection(name, spec)
        ast = _CondParser(_tokenize(cond), list(selections)).parse()
    except UnsupportedFeature as exc:
        issues.append(Issue("error", "unsupported_feature", str(exc)))
        return None, issues
    logsource = {k: str(v) for k, v in (doc.get("logsource") or {}).items() if v}
    rule = SigmaRule(
        raw=doc, title=str(doc.get("title", "")), rule_id=str(doc.get("id", "")),
        level=str(doc.get("level", "medium")), tags=[str(t) for t in (doc.get("tags") or [])],
        logsource=logsource, selections=selections, condition=cond, ast=ast, issues=issues,
    )
    return rule, issues


# --------------------------------------------------------------------------
# Pre-execution validation gate
# --------------------------------------------------------------------------
def validate_rule(
    yaml_text: str,
    available_fields: set[str] | None = None,
    expected_technique: str | None = None,
) -> dict[str, Any]:
    """Returns {ok, executable, issues[], rule?, missing_fields[], techniques[]}"""
    rule, issues = parse_rule(yaml_text)
    result: dict[str, Any] = {
        "ok": False, "executable": False, "issues": issues, "rule": rule,
        "missing_fields": [], "techniques": [],
    }
    if rule is None:
        return result
    result["techniques"] = rule.technique_ids
    if rule.has_placeholder():
        issues.append(Issue("error", "placeholder_indicator",
                            "Rule still contains a placeholder indicator (e.g. REPLACE_WITH_INDICATOR); it would match nothing meaningful."))
    if not rule.technique_ids:
        issues.append(Issue("warning", "no_attack_tag", "Rule has no attack.tNNNN tag"))
    elif expected_technique and expected_technique.upper() not in rule.technique_ids \
            and expected_technique.upper().split(".")[0] not in [t.split(".")[0] for t in rule.technique_ids]:
        issues.append(Issue("warning", "attack_tag_mismatch",
                            f"Rule tags {rule.technique_ids} do not include expected technique {expected_technique}"))
    if not rule.logsource:
        issues.append(Issue("error", "no_logsource", "Rule has no logsource"))
    if available_fields is not None:
        avail = {f.lower() for f in available_fields}
        missing = sorted(f for f in rule.referenced_fields() if f.lower() not in avail and f.lower() != "eventid")
        result["missing_fields"] = missing
        if missing:
            issues.append(Issue("warning", "fields_unavailable",
                                f"Fields not present in loaded telemetry: {', '.join(missing)}"))
    result["ok"] = not any(i.severity == "error" for i in issues)
    result["executable"] = result["ok"]
    return result


# --------------------------------------------------------------------------
# SPL compiler
# --------------------------------------------------------------------------
def _spl_str(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _spl_like(value: str, mode: str) -> str:
    # Sigma glob -> SQL-like pattern for like(); lowercase to keep case-insensitive
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(value[i + 1])
            i += 2
            continue
        out.append("%" if ch == "*" else "_" if ch == "?" else ("\\%" if ch == "%" else "\\_" if ch == "_" else ch))
        i += 1
    body = "".join(out).lower()
    if mode == "contains":
        body = f"%{body}%"
    elif mode == "startswith":
        body = f"{body}%"
    elif mode == "endswith":
        body = f"%{body}"
    return body


def _spl_matcher(m: FieldMatcher) -> str:
    f = m.field
    if "exists" in m.mods:
        want = bool(m.values[0]) if m.values else True
        return f"isnotnull({f})" if want else f"isnull({f})"
    parts: list[str] = []
    mode = "exact"
    for x in ("contains", "startswith", "endswith"):
        if x in m.mods:
            mode = x
    for op in ("lt", "lte", "gt", "gte"):
        if op in m.mods:
            sym = {"lt": "<", "lte": "<=", "gt": ">", "gte": ">="}[op]
            parts = [f"tonumber({f}){sym}{float(v):g}" for v in m.values]
            break
    else:
        for v in m.values:
            if v is None:
                parts.append(f"(isnull({f}) OR {f}=\"\")")
            elif "re" in m.mods:
                flags = "(?i)" if "cased" not in m.mods else ""
                parts.append(f'match({f}, "{_spl_str(flags + _norm(v))}")')
            else:
                variants = _windash_variants(_norm(v)) if "windash" in m.mods else [_norm(v)]
                for s in variants:
                    if mode == "exact" and "*" not in s and "?" not in s:
                        parts.append(f'lower({f})="{_spl_str(s.lower())}"')
                    else:
                        parts.append(f'like(lower({f}), "{_spl_str(_spl_like(s, mode))}")')
    joiner = " AND " if m.require_all else " OR "
    return "(" + joiner.join(parts) + ")" if len(parts) > 1 else parts[0]


def _spl_selection(sel: Selection) -> str:
    groups = [" AND ".join(_spl_matcher(m) for m in g) for g in sel.groups if g]
    groups = [f"({g})" if " AND " in g else g for g in groups]
    for k in sel.keywords:
        groups.append(f'match(_raw, "(?i){_spl_str(k.pattern)}")')
    return "(" + " OR ".join(groups) + ")" if len(groups) > 1 else groups[0]


def _spl_node(rule: SigmaRule, node) -> str:
    kind = node[0]
    if kind == "sel":
        return _spl_selection(rule.selections[node[1]])
    if kind == "and":
        return f"({_spl_node(rule, node[1])} AND {_spl_node(rule, node[2])})"
    if kind == "or":
        return f"({_spl_node(rule, node[1])} OR {_spl_node(rule, node[2])})"
    if kind == "not":
        return f"NOT {_spl_node(rule, node[1])}"
    joiner = " AND " if kind == "all_of" else " OR "
    return "(" + joiner.join(_spl_selection(rule.selections[n]) for n in node[1]) + ")"


def compile_spl(rule: SigmaRule, index: str = "*", earliest: str = "-30d") -> str:
    """Sigma rule -> Splunk SPL. Uses `| where` so every modifier is honoured."""
    cat = rule.logsource.get("category")
    svc = (rule.logsource.get("service") or "").lower()
    sourcetype = SPL_SOURCETYPE.get(cat or "") or SPL_SERVICE_SOURCETYPE.get(svc)
    head = f'search index={index} earliest={earliest}'
    if sourcetype:
        head += f' sourcetype="{sourcetype}"'
    return f"{head}\n| where {_spl_node(rule, rule.ast)}"


def compile_native(rule: SigmaRule, backend: str) -> tuple[str | None, str | None]:
    """(query, error). Uses pySigma if present for non-Splunk backends."""
    backend = backend.lower()
    if backend in ("splunk", "local"):
        try:
            return compile_spl(rule), None
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)
    try:  # optional pySigma path for Elastic / Sentinel / etc.
        from sigma.collection import SigmaCollection  # type: ignore
        coll = SigmaCollection.from_yaml(yaml.safe_dump(rule.raw))
        if backend in ("elastic", "elasticsearch", "lucene"):
            from sigma.backends.elasticsearch import LuceneBackend  # type: ignore
            return "\n".join(LuceneBackend().convert(coll)), None
        if backend == "sentinel":
            from sigma.backends.kusto import KustoBackend  # type: ignore
            return "\n".join(KustoBackend().convert(coll)), None
    except ImportError:
        return None, f"pySigma backend for '{backend}' is not installed"
    except Exception as exc:  # noqa: BLE001
        return None, f"pySigma conversion failed: {exc}"
    return None, f"no compiler for backend '{backend}'"
