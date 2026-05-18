import copy
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List

@dataclass
class Case:
    case_title: str
    analyst: str
    observation_category: str
    affected_asset: str = ""
    observations: str = ""
    analyst_notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    triage_responses: Dict[str, Any] = field(default_factory=dict)
    candidate_mappings: List[Dict[str, Any]] = field(default_factory=list)
    evidence_recommendations: List[Dict[str, Any]] = field(default_factory=list)
    unavailable_telemetry: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes the Case instance using a deep copy to ensure nested lists
        and dictionaries cannot mutate the core state of this in-memory instance.
        """
        return copy.deepcopy(self.__dict__)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Case":
        """
        Safely instantiates a Case model from a dictionary.
        Filters out obsolete keys and sets missing defaults to prevent schema mismatch crashes.
        """
        filtered_data = {}
        for field_name in cls.__dataclass_fields__:
            if field_name in data:
                filtered_data[field_name] = data[field_name]
        
        if "case_title" not in filtered_data:
            filtered_data["case_title"] = data.get("case_title", "Unknown Case")
        if "analyst" not in filtered_data:
            filtered_data["analyst"] = data.get("analyst", "Unknown Analyst")
        if "observation_category" not in filtered_data:
            filtered_data["observation_category"] = data.get("observation_category", "General")
            
        return cls(**filtered_data)
