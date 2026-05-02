import json
from pathlib import Path


class EvidenceRecommender:
    def __init__(self, evidence_path: str | Path):
        self.evidence_path = Path(evidence_path)
        self.config = self._load_config()

    def _load_config(self) -> dict:
        with self.evidence_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    def recommend(self, candidate_mappings: list[dict], available_telemetry: list[str]) -> tuple[list[dict], list[str]]:
        source_lookup = {
            source["id"]: source
            for source in self.config.get("evidence_sources", [])
        }

        recommended = []
        unavailable = set()

        for mapping in candidate_mappings:
            for source_id in mapping.get("evidence_sources", []):
                source = source_lookup.get(source_id)
                if not source:
                    continue

                if source_id in available_telemetry:
                    if source not in recommended:
                        recommended.append(source)
                else:
                    unavailable.add(source_id)

        return recommended, sorted(unavailable)
