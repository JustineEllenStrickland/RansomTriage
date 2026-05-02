import json
from pathlib import Path

from src.models.case import Case


class StorageService:
    def save_case(self, case: Case, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", encoding="utf-8") as file:
            json.dump(case.to_dict(), file, indent=2)

        return path

    def load_case(self, path: str | Path) -> Case:
        path = Path(path)

        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        return Case.from_dict(data)
