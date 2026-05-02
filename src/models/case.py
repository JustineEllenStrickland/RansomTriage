from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Case:
    case_title: str
    analyst: str
    observation_category: str
    affected_asset: str = ""
    observations: str = ""
    analyst_notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    triage_responses: dict[str, Any] = field(default_factory=dict)
    candidate_mappings: list[dict[str, Any]] = field(default_factory=list)
    evidence_recommendations: list[dict[str, Any]] = field(default_factory=list)
    unavailable_telemetry: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Case":
        return cls(**data)
