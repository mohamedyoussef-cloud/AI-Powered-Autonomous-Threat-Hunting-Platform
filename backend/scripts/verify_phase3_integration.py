from __future__ import annotations

from app.services.phase3_hypothesis import load_phase3

bundle = load_phase3()
print(f"Phase 3 root: {__import__('app.core.config', fromlist=['get_settings']).get_settings().TEAM_PHASE3_ROOT}")
print(f"Total techniques: {len(bundle['records'])}")
print(f"Routes: {bundle['route_counts']}")
print(f"Model: {bundle['model']}")
assert len(bundle["records"]) == 697, "Expected 697 Phase 3 records"
assert bundle["route_counts"].get("runtime_hunt") == 522
assert bundle["route_counts"].get("collection_gap_resolution") == 49
assert bundle["route_counts"].get("environment_resolution") == 30
assert bundle["route_counts"].get("pre_attack_hunt") == 96
print("PASS: Phase 3 integration data is readable and matches the team's published counts.")
