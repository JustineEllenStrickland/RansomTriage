from pathlib import Path

from src.services.attack_mapper import AttackMapper


def test_attack_mapper_returns_candidate_powershell_mapping():
    path = Path("src/config/attack_mappings.json")
    mapper = AttackMapper(path)

    responses = {
        "ps_encoded_command": True,
        "ps_download_behavior": False,
        "ps_unusual_parent": False
    }

    results = mapper.map_responses("suspicious_powershell", responses)

    assert len(results) == 1
    assert results[0]["technique_id"] == "T1059.001"
    assert results[0]["label"] == "candidate"
