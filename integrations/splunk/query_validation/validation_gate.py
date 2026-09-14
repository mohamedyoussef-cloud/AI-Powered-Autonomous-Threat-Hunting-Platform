# === Task 78: Query Validation Gate ===
import json
import re

BLOCKLIST = [
    "delete", "drop", "shutdown", "restart",
    "remove", "truncate", "purge"
]

def validate_spl_query(spl: str, technique_id: str) -> dict:
    reasons = []

    # check 1: empty query
    if not spl or spl.strip() == "":
        return {
            "passed":       False,
            "technique_id": technique_id,
            "spl":          spl,
            "reasons":      ["Query is empty"],
            "action":       "BLOCK"
        }

    # check 2: dangerous SPL COMMANDS only (after | pipe)
    spl_lower    = spl.lower()
    spl_commands = re.findall(r'\|\s*(\w+)', spl_lower)
    found_dangerous = [cmd for cmd in BLOCKLIST if cmd in spl_commands]
    if found_dangerous:
        reasons.append(f"Dangerous SPL commands found: {found_dangerous}")

    # check 3: query too long
    if len(spl) > 10000:
        reasons.append(f"Query too long: {len(spl)} chars (max 10,000)")

    # check 4: query too short
    if len(spl.strip()) < 5:
        reasons.append("Query too short to be valid")

    # check 5: must have field condition OR quoted search terms OR OR/AND logic
    has_field     = "=" in spl or "IN" in spl or "in" in spl
    has_quoted    = '"' in spl or "'" in spl
    has_logic     = " OR " in spl or " AND " in spl or " NOT " in spl
    if not has_field and not has_quoted and not has_logic:
        reasons.append("Query has no field conditions or search terms")

    if reasons:
        return {
            "passed":       False,
            "technique_id": technique_id,
            "spl":          spl,
            "reasons":      reasons,
            "action":       "BLOCK"
        }

    return {
        "passed":       True,
        "technique_id": technique_id,
        "spl":          spl,
        "reasons":      [],
        "action":       "ALLOW"
    }


def main():
    with open("task56_spl_results.json") as f:
        spl_results = json.load(f)

    print("=" * 60)
    print("Task 78: Query Validation Gate")
    print(f"Total SPL queries: {len(spl_results)}")
    print("=" * 60)

    passed_count  = 0
    blocked_count = 0
    validated     = []

    for item in spl_results:
        spl          = item.get("spl") or ""
        technique_id = item.get("technique_id", "unknown")

        result = validate_spl_query(spl, technique_id)

        if result["passed"]:
            passed_count += 1
        else:
            blocked_count += 1

        validated.append({
            "example_id":   item.get("example_id"),
            "technique_id": technique_id,
            "sigma":        item.get("sigma"),
            "spl":          spl,
            "validation":   result
        })

    total = passed_count + blocked_count
    print(f"\nALLOWED  : {passed_count}/{total}")
    print(f"BLOCKED  : {blocked_count}/{total}")
    print(f"Pass rate: {100*passed_count/total:.1f}%")

    blocked = [v for v in validated if not v["validation"]["passed"]]
    if blocked:
        print("\n--- Sample Blocked Queries ---")
        for b in blocked[:3]:
            print(f"\nTechnique: {b['technique_id']}")
            print(f"Reason   : {b['validation']['reasons']}")
            print(f"SPL      : {b['spl'][:80]}")
    else:
        print("\n✅ No queries were blocked!")

    with open("task78_validation_results.json", "w") as f:
        json.dump(validated, f, indent=2)

    print("\n" + "=" * 60)
    print("Saved to task78_validation_results.json ✅")
    print("Task 78 Complete ✅")


if __name__ == "__main__":
    main()