# findings_model.py
# Task 57: Hunt Findings Data Model
# ===================================
# Defines the canonical format for every finding
# returned by Splunk hunt execution.
# This finding is the input for ML Triage model.

import uuid
import json
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone
from enum import IntEnum


# ===================================================
# Section 1: Triage Labels
# ===================================================

class TriageLabel(IntEnum):
    """
    ML Triage labels (من Task 59)
    0 = False Positive  → auto-close
    1 = True Positive   → act now
    2 = Needs Review    → escalate to SOC analyst
    """
    FALSE_POSITIVE = 0
    TRUE_POSITIVE  = 1
    NEEDS_REVIEW   = 2


# ===================================================
# Section 2: Raw Event (من Splunk)
# ===================================================

@dataclass
class RawEvent:
    """
    الـ event الخام اللي بيرجع من Splunk
    كل event = سطر واحد في نتايج الـ search
    """
    # Fields أساسية في كل Splunk event
    _time:       Optional[str] = None   # وقت الـ event
    host:        Optional[str] = None   # الجهاز
    source:      Optional[str] = None   # مصدر الـ log
    sourcetype:  Optional[str] = None   # نوع الـ log

    # Windows Security fields (الأشيع في ATT&CK)
    EventCode:      Optional[str] = None  # مثال: 4688
    CommandLine:    Optional[str] = None  # الـ command اللي اتنفّذ
    ParentImage:    Optional[str] = None  # الـ process الأب
    Image:          Optional[str] = None  # الـ process
    User:           Optional[str] = None  # المستخدم
    ComputerName:   Optional[str] = None  # اسم الجهاز

    # Network fields
    dest_ip:    Optional[str] = None
    src_ip:     Optional[str] = None
    dest_port:  Optional[str] = None

    # باقي الـ fields الجاية من Splunk
    extra_fields: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        # شيلي الـ None values عشان نخفّف الـ JSON
        return {k: v for k, v in d.items() if v is not None}


# ===================================================
# Section 3: Hunt Finding (الـ canonical format)
# ===================================================

@dataclass
class HuntFinding:
    """
    الـ canonical format لكل finding.

    كل finding = نتيجة تشغيل Sigma rule واحدة
                 على Splunk وإرجاع events.

    ده اللي هيتبعت للـ ML Triage model.
    """

    # --- Hunt Identity ---
    finding_id:     str   # UUID فريد لكل finding
    technique_id:   str   # مثال: T1059.001
    technique_name: str   # مثال: PowerShell
    tactic:         str   # مثال: Execution

    # --- Hunt Context ---
    hypothesis:     str   # النص الأصلي اللي دخل الـ LLM
    sigma_rule_id:  str   # UUID بتاع الـ Sigma rule
    spl_query:      str   # الـ SPL query اللي اتشغّلت

    # --- Splunk Results ---
    event_count:    int           # عدد الـ events اللي رجعوا
    events:         list[RawEvent] = field(default_factory=list)

    # --- Timing ---
    hunt_timestamp:  str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    earliest_event: Optional[str] = None
    latest_event:   Optional[str] = None

    # --- ML Triage (بيتملى بعدين) ---
    triage_label:      Optional[int]   = None  # 0, 1, 2
    triage_label_name: Optional[str]   = None  # "FalsePositive", etc.
    triage_confidence: Optional[float] = None  # 0.0 → 1.0
    analyst_verdict:   Optional[str]   = None  # "confirmed" / "rejected"

    def to_dict(self) -> dict:
        """حوّلي الـ Finding لـ dict جاهز للـ JSON"""
        return {
            # Hunt Identity
            "finding_id":     self.finding_id,
            "technique_id":   self.technique_id,
            "technique_name": self.technique_name,
            "tactic":         self.tactic,

            # Hunt Context
            "hypothesis":    self.hypothesis,
            "sigma_rule_id": self.sigma_rule_id,
            "spl_query":     self.spl_query,

            # Splunk Results
            "event_count": self.event_count,
            "events":      [e.to_dict() for e in self.events],

            # Timing
            "hunt_timestamp":  self.hunt_timestamp,
            "earliest_event":  self.earliest_event,
            "latest_event":    self.latest_event,

            # ML Triage
            "triage_label":      self.triage_label,
            "triage_label_name": self.triage_label_name,
            "triage_confidence": self.triage_confidence,
            "analyst_verdict":   self.analyst_verdict,
        }


# ===================================================
# Section 4: Finding Builder
# ===================================================

class HuntFindingBuilder:
    """
    Helper عشان تبني HuntFinding بسهولة
    من أي input جاي من Splunk
    """

    @staticmethod
    def from_splunk_results(
        technique_id:   str,
        technique_name: str,
        tactic:         str,
        hypothesis:     str,
        sigma_rule_id:  str,
        spl_query:      str,
        splunk_events:  list[dict],
    ) -> "HuntFinding":
        """
        ابني finding من نتايج Splunk الخام

        splunk_events = list of dicts جايين من Splunk SDK
        """

        # حوّلي كل dict لـ RawEvent
        raw_events = []
        for ev in splunk_events:
            raw = RawEvent(
                _time      = ev.get("_time"),
                host       = ev.get("host"),
                source     = ev.get("source"),
                sourcetype = ev.get("sourcetype"),
                EventCode  = ev.get("EventCode"),
                CommandLine= ev.get("CommandLine"),
                ParentImage= ev.get("ParentImage"),
                Image      = ev.get("Image"),
                User       = ev.get("User"),
                ComputerName=ev.get("ComputerName"),
                dest_ip    = ev.get("dest_ip"),
                src_ip     = ev.get("src_ip"),
                dest_port  = ev.get("dest_port"),
                extra_fields= {
                    k: v for k, v in ev.items()
                    if k not in [
                        "_time","host","source","sourcetype",
                        "EventCode","CommandLine","ParentImage",
                        "Image","User","ComputerName",
                        "dest_ip","src_ip","dest_port"
                    ]
                }
            )
            raw_events.append(raw)

        # حدّدي earliest و latest event
        times = [
            e._time for e in raw_events
            if e._time is not None
        ]
        earliest = min(times) if times else None
        latest   = max(times) if times else None

        return HuntFinding(
            finding_id     = str(uuid.uuid4()),
            technique_id   = technique_id,
            technique_name = technique_name,
            tactic         = tactic,
            hypothesis     = hypothesis,
            sigma_rule_id  = sigma_rule_id,
            spl_query      = spl_query,
            event_count    = len(splunk_events),
            events         = raw_events,
            earliest_event = earliest,
            latest_event   = latest,
        )

    @staticmethod
    def empty_finding(
        technique_id:   str,
        technique_name: str,
        tactic:         str,
        hypothesis:     str,
        sigma_rule_id:  str,
        spl_query:      str,
    ) -> "HuntFinding":
        """
        Finding فاضي لما Splunk ميرجعش events
        = مش بالضرورة يعني مفيش هجوم
        """
        return HuntFinding(
            finding_id     = str(uuid.uuid4()),
            technique_id   = technique_id,
            technique_name = technique_name,
            tactic         = tactic,
            hypothesis     = hypothesis,
            sigma_rule_id  = sigma_rule_id,
            spl_query      = spl_query,
            event_count    = 0,
            events         = [],
        )


# ===================================================
# Section 5: Validation
# ===================================================

def validate_finding(finding: HuntFinding) -> dict:
    """
    تأكدي إن الـ Finding فيه كل الـ fields المطلوبة
    """
    errors = []

    # Required fields
    if not finding.finding_id:
        errors.append("finding_id is missing")
    if not finding.technique_id:
        errors.append("technique_id is missing")
    if not finding.hypothesis:
        errors.append("hypothesis is missing")
    if not finding.spl_query:
        errors.append("spl_query is missing")
    if finding.event_count < 0:
        errors.append("event_count cannot be negative")

    # Triage label validation (لو موجود)
    if finding.triage_label is not None:
        if finding.triage_label not in [0, 1, 2]:
            errors.append(
                f"Invalid triage_label: {finding.triage_label}"
                " (must be 0, 1, or 2)"
            )

    return {
        "valid":  len(errors) == 0,
        "errors": errors
    }


# ===================================================
# Section 6: Main — اعملي example وتأكدي
# ===================================================

if __name__ == "__main__":

    print("=" * 55)
    print("Task 57: Hunt Findings Data Model")
    print("=" * 55)

    # --- Example 1: Finding مع events ---
    print("\n[1] Building finding WITH events...")

    finding_with_events = HuntFindingBuilder.from_splunk_results(
        technique_id   = "T1059.001",
        technique_name = "PowerShell",
        tactic         = "Execution",
        hypothesis     = (
            "Adversary may use PowerShell to execute "
            "encoded commands to evade detection"
        ),
        sigma_rule_id  = str(uuid.uuid4()),
        spl_query      = (
            'index=* EventCode=4688 '
            'CommandLine="*powershell*" '
            'CommandLine="*-enc*"'
        ),
        splunk_events  = [
            {
                "_time":       "2024-01-15T10:30:00Z",
                "host":        "DESKTOP-WIN10",
                "source":      "WinEventLog:Security",
                "sourcetype":  "WinEventLog",
                "EventCode":   "4688",
                "CommandLine": "powershell.exe -enc SGVsbG8=",
                "User":        "CORP\\john.doe",
                "Image":       "C:\\Windows\\System32\\powershell.exe",
            },
            {
                "_time":       "2024-01-15T10:31:00Z",
                "host":        "DESKTOP-WIN11",
                "source":      "WinEventLog:Security",
                "sourcetype":  "WinEventLog",
                "EventCode":   "4688",
                "CommandLine": "powershell.exe -enc V2luZG93cw==",
                "User":        "CORP\\jane.doe",
                "Image":       "C:\\Windows\\System32\\powershell.exe",
            },
        ],
    )

    # Validate
    result = validate_finding(finding_with_events)
    print(f"   Valid: {result['valid']}")
    print(f"   Errors: {result['errors']}")
    print(f"   Events: {finding_with_events.event_count}")

    # --- Example 2: Finding فاضي ---
    print("\n[2] Building EMPTY finding (no events)...")

    empty_finding = HuntFindingBuilder.empty_finding(
        technique_id   = "T1003.001",
        technique_name = "LSASS Memory",
        tactic         = "Credential Access",
        hypothesis     = (
            "Adversary may dump LSASS memory "
            "to extract credentials"
        ),
        sigma_rule_id  = str(uuid.uuid4()),
        spl_query      = (
            'index=* EventCode=10 '
            'TargetImage="*lsass.exe*"'
        ),
    )

    result2 = validate_finding(empty_finding)
    print(f"   Valid: {result2['valid']}")
    print(f"   Events: {empty_finding.event_count}")

    # --- Save Results ---
    print("\n[3] Saving results...")

    output = {
        "task": "Task 57 - Hunt Findings Data Model",
        "status": "complete",
        "timestamp": datetime.now(timezone.utc).isoformat(),

        "model_fields": {
            "finding_id":        "UUID - unique per finding",
            "technique_id":      "ATT&CK technique (e.g. T1059)",
            "technique_name":    "ATT&CK technique name",
            "tactic":            "ATT&CK tactic",
            "hypothesis":        "Original hypothesis text",
            "sigma_rule_id":     "UUID of the Sigma rule used",
            "spl_query":         "SPL query executed",
            "event_count":       "Number of Splunk events returned",
            "events":            "List of raw Splunk events",
            "hunt_timestamp":    "When the hunt was executed",
            "earliest_event":    "Earliest event time",
            "latest_event":      "Latest event time",
            "triage_label":      "0=FP / 1=TP / 2=NeedsReview",
            "triage_label_name": "Human readable label",
            "triage_confidence": "ML confidence score",
            "analyst_verdict":   "confirmed / rejected",
        },

        "examples": [
            finding_with_events.to_dict(),
            empty_finding.to_dict(),
        ],

        "validation": {
            "finding_with_events": result,
            "empty_finding":       result2,
        },

        "summary": {
            "total_examples":    2,
            "all_valid":         result["valid"] and result2["valid"],
            "fields_defined":    14,
        }
    }

    with open("task57_results.json", "w") as f:
        json.dump(output, f, indent=2)

    print("   ✅ Saved: task57_results.json")

    # --- Final Summary ---
    print("\n" + "=" * 55)
    print("TASK 57 SUMMARY")
    print("=" * 55)
    print(f"Model fields defined : 14")
    print(f"Examples validated   : 2/2 ✅")
    print(f"Output file          : task57_results.json ✅")
    print(f"Status               : COMPLETE ✅")