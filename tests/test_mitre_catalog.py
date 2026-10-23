"""
ATT&CK drift guard: every technique ID in the event->technique map must exist
in the vendored ATT&CK cloud catalog and must not be revoked.
"""
from detection.mitre_mappings import validate_against_attack_catalog, EVENT_TECHNIQUE_MAP


def test_all_mapped_techniques_exist_in_catalog():
    unknown, revoked = validate_against_attack_catalog()
    assert unknown == [], f"technique IDs not in ATT&CK catalog: {unknown}"
    assert revoked == [], f"technique IDs revoked in ATT&CK: {revoked}"


def test_terminate_instances_maps_to_data_destruction():
    m = EVENT_TECHNIQUE_MAP["TerminateInstances"]
    assert m.technique_id == "T1485"
