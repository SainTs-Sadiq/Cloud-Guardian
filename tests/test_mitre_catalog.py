"""
ATT&CK single-source guard.

detection/mitre_mappings.py (EVENT_TECHNIQUE_MAP) is the only canonical mapping.
detection/attack_catalog.py is the vendored reference list. These tests fail if the
two drift apart, if /coverage counts diverge from the map, or if a detector emits a
technique ID that the catalog does not know and that is not explicitly excepted.
"""
from collections import Counter

from detection.attack_catalog import ATTACK_CLOUD_CATALOG, ATTACK_CLOUD_INDEX
from detection.mitre_mappings import (
    DETECTOR_ID_EXCEPTIONS,
    EVENT_TECHNIQUE_MAP,
    Tactic,
    all_tactics_summary,
    detector_technique_literals,
    mapped_technique_ids,
    uncovered_tactics,
    validate_against_attack_catalog,
    validate_single_source,
)


def test_all_mapped_techniques_exist_in_catalog():
    unknown, revoked = validate_against_attack_catalog()
    assert unknown == [], f"technique IDs not in ATT&CK catalog: {unknown}"
    assert revoked == [], f"technique IDs revoked in ATT&CK: {revoked}"


def test_single_source_check_is_clean():
    problems = validate_single_source()
    assert all(not v for v in problems.values()), problems


def test_catalog_has_no_duplicate_ids():
    counts = Counter(t.technique_id for t in ATTACK_CLOUD_CATALOG)
    dupes = sorted(k for k, n in counts.items() if n > 1)
    assert dupes == [], f"duplicate catalog IDs: {dupes}"


def test_catalog_index_matches_list():
    assert len(ATTACK_CLOUD_INDEX) == len(ATTACK_CLOUD_CATALOG)


# Known name drift between EVENT_TECHNIQUE_MAP display names and the vendored catalog.
# Left unchanged on purpose (changing a display name changes alert output). Any NEW
# mismatch fails test_mapped_names_match_catalog_except_known_drift.
# T1556.009 (Conditional Access Policies) is semantically wrong for SAML provider events; left unchanged
# pending a decision (see mitre_mappings.py). T1651 name fixed to Cloud Administration Command.
KNOWN_NAME_DRIFT = {"T1550.001", "T1556.009", "T1578.005", "T1685.002"}


def test_mapped_names_match_catalog_except_known_drift():
    drift = set()
    for m in EVENT_TECHNIQUE_MAP.values():
        catalog = ATTACK_CLOUD_INDEX[m.technique_id].name
        if m.technique_name.lower() != catalog.lower() and \
           m.technique_name.split(": ")[-1].lower() != catalog.lower():
            drift.add(m.technique_id)
    new_drift = sorted(drift - KNOWN_NAME_DRIFT)
    assert new_drift == [], f"new name drift vs catalog: {new_drift}"
    stale = sorted(KNOWN_NAME_DRIFT - drift)
    assert stale == [], f"KNOWN_NAME_DRIFT entries that no longer drift: {stale}"


def test_mapped_technique_names_are_consistent_per_id():
    # One ID must carry one display name everywhere it is mapped.
    names = {}
    for m in EVENT_TECHNIQUE_MAP.values():
        names.setdefault(m.technique_id, set()).add(m.technique_name)
    conflicts = {k: sorted(v) for k, v in names.items() if len(v) > 1}
    assert conflicts == {}, conflicts


def test_detector_literals_are_known_or_excepted():
    literals = detector_technique_literals()
    assert literals, "scanner found no technique literals; the scan path is broken"
    for tid, sites in literals.items():
        if tid in DETECTOR_ID_EXCEPTIONS:
            continue
        assert tid in ATTACK_CLOUD_INDEX, f"{tid} emitted at {sites} but not in catalog"
        assert not ATTACK_CLOUD_INDEX[tid].revoked, f"{tid} revoked, emitted at {sites}"


def test_detector_exceptions_are_still_used():
    # A stale exception means the code was fixed but the list was not trimmed.
    literals = detector_technique_literals()
    stale = [t for t in DETECTOR_ID_EXCEPTIONS if t not in literals]
    assert stale == [], f"exceptions no longer emitted by code: {stale}"


def test_coverage_count_is_distinct_techniques_not_event_rows():
    distinct = {m.technique_id for m in EVENT_TECHNIQUE_MAP.values()}
    assert len(mapped_technique_ids()) == len(distinct)
    assert len(distinct) < len(EVENT_TECHNIQUE_MAP)  # guards against regressing to row counts


def test_tactic_summary_counts_distinct_techniques_per_tactic():
    summary = all_tactics_summary()
    assert set(summary) == {t.value for t in Tactic}
    for tactic in Tactic:
        expected = {m.technique_id for m in EVENT_TECHNIQUE_MAP.values()
                    if m.tactic is tactic}
        assert summary[tactic.value] == len(expected), tactic.value


def test_uncovered_tactics_are_the_zero_count_tactics():
    summary = all_tactics_summary()
    assert uncovered_tactics() == [t for t, n in summary.items() if n == 0]


def test_terminate_instances_maps_to_data_destruction():
    m = EVENT_TECHNIQUE_MAP["TerminateInstances"]
    assert m.technique_id == "T1485"
