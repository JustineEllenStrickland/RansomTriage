import pytest
import json
import tempfile
from pathlib import Path
from dataclasses import dataclass, field

# Import our hardened implementations
from src.models.attack_mapping import AttackMapping, Condition, EvaluationLogic
from src.services.report_generator import ReportGenerator
from src.services.attack_mapper import AttackMapper
from src.services.evidence_recommender import EvidenceRecommender
from src.services.storage_service import StorageService

# Mock Case object to simulate src.models.case.Case during test runtime
@dataclass
class MockCase:
    case_title: str = "Operation Cobalt"
    analyst: str = "SecOps Analyst"
    affected_asset: str = "DC-01.corp"
    observation_category: str = "windows_core_ransomware"
    observations: str = "VSSAdmin deletion activity detected."
    candidate_mappings: list = field(default_factory=list)
    evidence_recommendations: list = field(default_factory=list)
    unavailable_telemetry: list = field(default_factory=list)
    analyst_notes: str = "Immediate isolation recommended."

    def to_dict(self):
        return self.__dict__.copy()


# ============================================================================
# 1. ATTACKMAPPING MODEL TESTS (Case-Insensitive & Weighted Rules)
# ============================================================================

def test_attack_mapping_case_insensitive_matching():
    """Validates that evaluation logic handles variant casing without dropping matches."""
    mapping = AttackMapping.from_dict({
        "technique_id": "T1490",
        "technique_name": "Inhibit System Recovery",
        "tactic": "Impact",
        "observation_category": "windows_core_ransomware",
        "evaluation_logic": {"rule": "any_match"},
        "conditions": [{"id": "SHADOW_DELETED", "description": "vssadmin used", "severity": "high", "weight": 5}]
    })
    
    # Input coming from UI layer might be lowercased or padded
    assert mapping.evaluate_match(["shadow_deleted "]) is True
    assert mapping.evaluate_match(["SHADOW_DELETED"]) is True


def test_attack_mapping_weighted_threshold_rule():
    """Verifies that critical severities short-circuit, and weights accumulate perfectly."""
    mapping = AttackMapping.from_dict({
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "observation_category": "windows_core_ransomware",
        "evaluation_logic": {"rule": "any_critical_or_weighted_threshold", "threshold_score": 10},
        "conditions": [
            {"id": "RANSOM_NOTE", "description": "Note dropped", "severity": "critical", "weight": 2},
            {"id": "HIGH_ENTROPY", "description": "Mass renaming", "severity": "high", "weight": 6},
            {"id": "LSASS_DUMP", "description": "Creds access", "severity": "medium", "weight": 5}
        ]
    })

    # Scenario A: Short-circuit matching via an immediate Critical flag
    assert mapping.evaluate_match(["ransom_note"]) is True

    # Scenario B: Accumulate non-critical components to pass the score threshold (6 + 5 >= 10)
    assert mapping.evaluate_match(["high_entropy", "lsass_dump"]) is True

    # Scenario C: Fail score threshold constraints safely (6 < 10)
    assert mapping.evaluate_match(["high_entropy"]) is False


# ============================================================================
# 2. ATTACKMAPPER SERVICE TESTS (Configuration Loading & Normalization)
# ============================================================================

def test_attack_mapper_lookup_normalization(tmp_path):
    """Ensures configuration files with uneven capitalization are smoothed out by initialization."""
    config_file = tmp_path / "test_attack_mappings.json"
    config_data = {
        "mappings": [{
            "technique_id": "t1490 ", # Trailing space and lowercase
            "technique_name": "Inhibit System Recovery",
            "tactic": "Impact",
            "observation_category": "Windows_Core_Ransomware", # Mixed case category
            "conditions": [{"id": "vss_del", "description": "deleted", "severity": "high", "weight": 1}]
        }]
    }
    config_file.write_text(json.dumps(config_data), encoding="utf-8")
    
    mapper = AttackMapper(config_file)
    
    # Verify O(1) specific lookup normalizes case variants on query execution
    match = mapper.get_mapping_by_id("T1490", category="windows_core_ransomware")
    assert match is not None
    assert match.technique_name == "Inhibit System Recovery"


# ============================================================================
# 3. EVIDENCE RECOMMENDER TESTS (Out-of-Order Gap Management)
# ============================================================================

def test_evidence_recommender_out_of_order_resolution(tmp_path):
    """Verifies that dynamic telemetry checks don't trap log sources in the missing list."""
    evidence_file = tmp_path / "telemetry_schema.json"
    evidence_data = {
        "evidence_sources": [
            {"id": "win_evt", "name": "Windows Event Logs"},
            {"id": "sysmon", "name": "Sysmon Telemetry"}
        ]
    }
    evidence_file.write_text(json.dumps(evidence_data), encoding="utf-8")
    
    recommender = EvidenceRecommender(evidence_file)

    # Technique A and B both mapped out
    mapping_a = AttackMapping.from_dict({
        "technique_id": "T1490", "technique_name": "A", "tactic": "I", "observation_category": "cat",
        "evidence_sources": ["win_evt"]
    })
    mapping_b = AttackMapping.from_dict({
        "technique_id": "T1486", "technique_name": "B", "tactic": "I", "observation_category": "cat",
        "evidence_sources": ["win_evt", "sysmon"]
    })

    # Analyst indicates 'win_evt' is active/online, but 'sysmon' is missing
    available = ["WIN_EVT"] # Simulating mixed casing from checkbox models
    
    recommended, missing = recommender.recommend([mapping_b, mapping_a], available)
    
    # Assertions
    assert "Windows Event Logs" in [r["name"] for r in recommended]
    assert "Sysmon Telemetry" in missing
    assert "Windows Event Logs" not in missing, "Bug found: Available telemetry was wrongly cataloged as a visibility gap!"


# ============================================================================
# 4. REPORT GENERATOR TESTS (Syntax Recovery Engine Fallbacks)
# ============================================================================

def test_report_generator_malformed_template_fallback(tmp_path):
    """Guarantees the renderer drops back to the internal string layout if a file breaks syntax parsing."""
    broken_template = tmp_path / "broken_template.md"
    # Injecting an unclosed Jinja2 execution control loop block
    broken_template.write_text("# Corrupted Template\n{% for item in items %}", encoding="utf-8")
    
    reporter = ReportGenerator(broken_template)
    case = MockCase()
    
    # Execute compilation phase loop
    report_output = reporter.generate_markdown(case)
    
    # The output should belong to the internal fallback layout string structure, not the corrupted text file
    assert "# RansomTriage Case Summary" in report_output
    assert "Operation Cobalt" in report_output


# ============================================================================
# 5. STORAGE SERVICE TESTS (Cross-Platform Atomic Commit Operations)
# ============================================================================

def test_storage_service_atomic_swap_and_file_unlock(tmp_path):
    """Confirms that temporary files are cleanly unlinked and file locks drop prior to swapping steps."""
    save_target = tmp_path / "cases" / "incident_001.json"
    
    storage = StorageService()
    case = MockCase()
    
    # Run serialization cycle
    committed_path = storage.save_case(case, save_target)
    
    assert committed_path.exists()
    
    # Read back layout validations
    with committed_path.open("r", encoding="utf-8") as f:
        saved_json = json.load(f)
        
    assert saved_json["case_title"] == "Operation Cobalt"
    assert saved_json["affected_asset"] == "DC-01.corp"
    
    # Check that temporary storage frames in the parent folder were cleanly erased/renamed
    remaining_files = list(save_target.parent.glob("*"))
    assert len(remaining_files) == 1, "Temporary transaction lock file was abandoned or left un-swapped!"
