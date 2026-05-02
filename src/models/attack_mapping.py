from dataclasses import dataclass


@dataclass
class AttackMapping:
    technique_id: str
    technique_name: str
    tactic: str
    label: str
    rationale: str
    evidence_sources: list[str]
    revision_date: str
