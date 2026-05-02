import json
from pathlib import Path


class WorkflowEngine:
    def __init__(self, config_path: str | Path):
        self.config_path = Path(config_path)
        self.config = self._load_config()

    def _load_config(self) -> dict:
        with self.config_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    def get_categories(self) -> list[dict]:
        return self.config.get("observation_categories", [])

    def get_questions(self, observation_category: str) -> list[dict]:
        for category in self.get_categories():
            if category.get("id") == observation_category:
                return category.get("questions", [])
        return []

    def is_complete(self, observation_category: str, responses: dict) -> bool:
        required_ids = [q["id"] for q in self.get_questions(observation_category)]
        return all(question_id in responses for question_id in required_ids)
