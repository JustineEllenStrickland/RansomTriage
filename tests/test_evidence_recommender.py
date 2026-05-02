from pathlib import Path

from src.services.evidence_recommender import EvidenceRecommender


def test_evidence_recommender_filters_available_telemetry():
    path = Path("src/config/evidence_sources.json")
    recommender = EvidenceRecommender(path)

    mappings = [
        {
            "technique_id": "T1059.001",
            "evidence_sources": ["windows_event_logs", "sysmon", "edr"]
        }
    ]

    recommendations, unavailable = recommender.recommend(
        candidate_mappings=mappings,
        available_telemetry=["windows_event_logs"]
    )

    assert len(recommendations) == 1
    assert recommendations[0]["id"] == "windows_event_logs"
    assert "sysmon" in unavailable
    assert "edr" in unavailable
