from threat_hunting_data.feature_contracts import FeatureContract


def test_prohibited_source_identity():
    contract = FeatureContract("process_behavior", "process_v1.0.0")
    errors = contract.validate_names({"event_count", "dataset_name"})
    assert errors
    assert "prohibited" in errors[0]
