from dataclasses import dataclass


@dataclass
class EvidenceSource:
    id: str
    name: str
    category: str
    description: str
