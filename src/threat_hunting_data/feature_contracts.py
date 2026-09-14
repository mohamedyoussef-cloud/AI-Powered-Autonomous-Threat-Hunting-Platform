from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet


GLOBAL_FEATURES: FrozenSet[str] = frozenset({
    "event_count",
    "duration_seconds",
    "unique_host_count",
    "unique_user_count",
    "unique_source_count",
    "rule_count",
    "technique_count",
    "events_per_minute",
    "after_hours_ratio",
    "asset_criticality",
    "technique_priority_score",
})

DOMAIN_FEATURES: dict[str, FrozenSet[str]] = {
    "process_behavior": frozenset({
        "command_line_length_mean",
        "command_line_entropy_mean",
        "encoded_command_present",
        "suspicious_argument_count",
        "process_name_rarity",
        "process_path_rarity",
        "parent_child_rarity",
        "temporary_path_execution_ratio",
        "system_directory_execution_ratio",
    }),
    "authentication_behavior": frozenset({
        "failed_login_count",
        "success_after_failures",
        "unique_source_ip_count",
        "new_device_indicator",
        "privileged_account_indicator",
    }),
    "network_behavior": frozenset({
        "unique_destination_count",
        "rare_port_ratio",
        "bytes_out",
        "bytes_in",
        "external_destination_ratio",
        "beaconing_score",
    }),
}

PROHIBITED_PREDICTORS: FrozenSet[str] = frozenset({
    "dataset_name",
    "source_dataset",
    "source_file",
    "finding_id",
    "rule_id",
    "raw_command_line",
    "analyst_verdict",
    "reviewer",
})


@dataclass(frozen=True)
class FeatureContract:
    finding_type: str
    version: str

    @property
    def allowed_features(self) -> FrozenSet[str]:
        return GLOBAL_FEATURES | DOMAIN_FEATURES.get(self.finding_type, frozenset())

    def validate_names(self, feature_names: set[str]) -> list[str]:
        errors: list[str] = []
        prohibited = sorted(feature_names & PROHIBITED_PREDICTORS)
        unknown = sorted(feature_names - self.allowed_features - PROHIBITED_PREDICTORS)
        if prohibited:
            errors.append(f"prohibited predictive features: {prohibited}")
        if unknown:
            errors.append(f"features not defined in contract {self.version}: {unknown}")
        return errors
