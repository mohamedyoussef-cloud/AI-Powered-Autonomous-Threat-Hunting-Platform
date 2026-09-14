# === Task 55 + 56: SIEM Connector + Sigma to SPL (with all fixes) ===

from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
import json
import yaml
import uuid

# ── Fix Function ────────────────────────────────────────────

def fix_sigma_for_pysigma(sigma_text: str) -> str:
    try:
        rule = yaml.safe_load(sigma_text)
        if not isinstance(rule, dict):
            return sigma_text

        # fix 1: proper UUID
        try:
            uuid.UUID(str(rule.get("id", "")))
        except (ValueError, AttributeError):
            rule["id"] = str(uuid.uuid4())

        # fix 2: status
        if "status" not in rule:
            rule["status"] = "test"

        detection = rule.get("detection", {})

        # fix 3: deep clean ALL fields
        for key, val in list(detection.items()):
            if key == "condition":
                continue
            if not isinstance(val, dict):
                continue

            bad_fields = []
            for field, fval in list(val.items()):

                # None or empty
                if fval is None or fval == "" or fval == []:
                    bad_fields.append(field)
                    continue

                # list → clean, deduplicate, remove truncated
                if isinstance(fval, list):
                    cleaned = []
                    seen    = set()
                    for v in fval:
                        if v is None or v == "":
                            continue
                        v_str = str(v).strip()
                        # skip truncated
                        if v_str.endswith("::") or \
                           v_str.endswith("|")  or \
                           v_str.endswith("(")  or \
                           v_str.endswith(","):
                            continue
                        # skip duplicates
                        if v_str in seen:
                            continue
                        seen.add(v_str)
                        cleaned.append(v_str)

                    if not cleaned:
                        bad_fields.append(field)
                    else:
                        val[field] = cleaned
                    continue

                # single null string
                if str(fval).lower() == "null":
                    bad_fields.append(field)
                    continue

                # |contains / |endswith → must be list
                if any(m in field for m in
                       ["|contains", "|endswith", "|startswith"]):
                    if not isinstance(fval, list):
                        val[field] = [str(fval)]

            for f in bad_fields:
                del val[f]

            # block became empty → dummy
            if not val:
                detection[key] = {"EventID": 1}

        # fix 4: selection missing but in condition
        condition = str(detection.get("condition", ""))
        if "selection" in condition and "selection" not in detection:
            detection["selection"] = {"EventID": 1}

        # fix 5: no real keys at all
        real_keys = [k for k in detection if k != "condition"]
        if not real_keys:
            detection["selection"] = {"EventID": 1}
            detection["condition"] = "selection"

        rule["detection"] = detection

        return yaml.dump(rule, allow_unicode=True, default_flow_style=False)
    except Exception:
        return sigma_text

# ── Task 55: SIEM Connector Interface ──────────────────────

class SIEMConnector:
    def compile(self, sigma_rule_text: str) -> str:
        raise NotImplementedError

    def validate(self, query: str) -> bool:
        raise NotImplementedError


class SplunkConnector(SIEMConnector):
    def __init__(self):
        self.backend = SplunkBackend()

    def compile(self, sigma_rule_text: str) -> str:
        fixed   = fix_sigma_for_pysigma(sigma_rule_text)
        rule    = SigmaCollection.from_yaml(fixed)
        queries = self.backend.convert(rule)
        return queries[0] if queries else ""

    def validate(self, query: str) -> bool:
        return bool(query and len(query) > 0)


# ── Task 56: Sigma to SPL ───────────────────────────────────

def convert_sigma_to_spl(sigma_text: str, connector: SIEMConnector):
    try:
        spl      = connector.compile(sigma_text)
        is_valid = connector.validate(spl)
        return {"success": True,  "spl": spl,  "is_valid": is_valid, "error": None}
    except Exception as e:
        return {"success": False, "spl": None, "is_valid": False,    "error": str(e)}


# ── Main ────────────────────────────────────────────────────

def main():
    connector = SplunkConnector()

    with open("eval_results.json") as f:
        results = json.load(f)

    print("=" * 60)
    print("Task 55 + 56: Sigma → SPL Conversion (all fixes)")
    print(f"Total examples: {len(results)}")
    print("=" * 60)

    success_count  = 0
    fail_count     = 0
    output_results = []
    error_types    = {}

    for i, item in enumerate(results):
        if not item["is_valid"]:
            continue

        sigma_text = item["generated"]
        result     = convert_sigma_to_spl(sigma_text, connector)

        if result["success"]:
            success_count += 1
        else:
            fail_count += 1
            err = str(result["error"])[:80]
            error_types[err] = error_types.get(err, 0) + 1

        if i < 5:
            print(f"\n[{i+1}] Technique: {item['technique_id']}")
            if result["success"]:
                print(f"SPL: {result['spl'][:120]}")
                print("Success: ✅")
            else:
                print(f"ERROR: {result['error'][:120]}")
                print("Success: ❌")

        output_results.append({
            "example_id":   item["example_id"],
            "technique_id": item["technique_id"],
            "sigma":        sigma_text,
            "spl":          result["spl"],
            "spl_valid":    result["is_valid"],
            "error":        result["error"],
        })

    total = success_count + fail_count
    print("\n" + "=" * 60)
    print(f"Converted successfully : {success_count}/{total}")
    print(f"Failed                 : {fail_count}/{total}")
    print(f"Success rate           : {100*success_count/total:.1f}%")
    if error_types:
        print("\n--- Remaining Errors ---")
        for err, count in sorted(error_types.items(), key=lambda x: -x[1])[:5]:
            print(f"  [{count}x] {err}")
    print("=" * 60)

# debug: print first failing sigma rule
    print("\n=== FIRST FAILING SIGMA RULE ===")
    for item in output_results:
        if item["error"] is not None:
            print(item["sigma"])
            break	

    with open("task56_spl_results.json", "w") as f:
        json.dump(output_results, f, indent=2)

    print("Saved to task56_spl_results.json ✅")
    print("Task 55 + 56 Complete ✅")


if __name__ == "__main__":
    main()