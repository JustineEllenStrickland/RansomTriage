import json
from pathlib import Path


class AttackMapper:
    def __init__(self, mapping_path: str | Path):
        self.mapping_path = Path(mapping_path)
        self.config = self._load_config()

    def _load_config(self) -> dict:
        with self.mapping_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    def map_responses(self, observation_category: str, responses: dict) -> list[dict]:
        results = []

        for mapping in self.config.get("mappings", []):
            if mapping.get("observation_category") != observation_category:
                continue

            conditions = mapping.get("conditions", [])
            minimum_matches = mapping.get("minimum_matches", 1)
            matches = sum(1 for condition in conditions if responses.get(condition) is True)

            if matches >= minimum_matches:
                results.append({
                    "technique_id": mapping["technique_id"],
                    "technique_name": mapping["technique_name"],
                    "tactic": mapping["tactic"],
                    "label": mapping.get("label", "candidate"),
                    "rationale": mapping["rationale"],
                    "evidence_sources": mapping.get("evidence_sources", []),
                    "revision_date": mapping.get("revision_date", "")
                })

        return results
