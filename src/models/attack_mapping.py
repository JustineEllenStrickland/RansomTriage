from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Set


@dataclass
class Condition:
    id: str
    description: str
    severity: str
    weight: int


@dataclass
class EvaluationLogic:
    rule: str
    threshold_score: Optional[int] = None
    required_conditions: Optional[List[str]] = field(default_factory=list)


@dataclass
class RansomwareContext:
    associated_groups: List[str] = field(default_factory=list)
    common_tooling: List[str] = field(default_factory=list)


@dataclass
class HuntingQuery:
    platform: str
    query: str


@dataclass
class AnalystActions:
    containment_recommendation: str
    hunting_queries: List[HuntingQuery] = field(default_factory=list)


@dataclass
class AttackMapping:
    technique_id: str
    technique_name: str
    tactic: str
    attack_phase: str
    confidence_score: str
    observation_category: str
    evaluation_logic: EvaluationLogic
    conditions: List[Condition]
    ransomware_context: RansomwareContext
    analyst_actions: AnalystActions
    evidence_sources: List[str]
    revision_date: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackMapping":
        """Factory method to safely parse nested JSON data into typed objects."""
        eval_data = data.get("evaluation_logic", {})
        eval_logic = EvaluationLogic(
            rule=eval_data.get("rule", "any_match"),
            threshold_score=eval_data.get("threshold_score"),
            required_conditions=eval_data.get("required_conditions", [])
        )

        # Defensive Unpacking: Protect against malformed config fields crashing initialization
        conditions = []
        for cond in data.get("conditions", []):
            conditions.append(Condition(
                id=cond.get("id", ""),
                description=cond.get("description", ""),
                severity=cond.get("severity", "medium"),
                weight=int(cond.get("weight", 0))
            ))

        ctx_data = data.get("ransomware_context", {})
        ransomware_ctx = RansomwareContext(
            associated_groups=ctx_data.get("associated_groups", []),
            common_tooling=ctx_data.get("common_tooling", [])
        )

        action_data = data.get("analyst_actions", {})
        queries = [
            HuntingQuery(platform=q.get("platform", ""), query=q.get("query", "")) 
            for q in action_data.get("hunting_queries", [])
        ]
        
        analyst_actions = AnalystActions(
            containment_recommendation=action_data.get("containment_recommendation", ""),
            hunting_queries=queries
        )

        return cls(
            technique_id=data["technique_id"],
            technique_name=data["technique_name"],
            tactic=data["tactic"],
            attack_phase=data.get("attack_phase", "Unknown"),
            confidence_score=data.get("confidence_score", "Medium"),
            observation_category=data["observation_category"],
            evaluation_logic=eval_logic,
            conditions=conditions,
            ransomware_context=ransomware_ctx,
            analyst_actions=analyst_actions,
            evidence_sources=data.get("evidence_sources", []),
            revision_date=data.get("revision_date", "")
        )

    def evaluate_match(self, observed_condition_ids: List[str]) -> bool:
        """
        Evaluates triage inputs to identify a MITRE ATT&CK technique match.
        Enforces case-insensitive O(1) matching thresholds.
        """
        # Ensure all incoming IDs are clean and lowercased
        observed_set: Set[str] = {str(cid).strip().lower() for cid in observed_condition_ids}

        # Rule Type 1: Absolute Match Requirement
        if self.evaluation_logic.rule == "absolute_match":
            if not self.evaluation_logic.required_conditions:
                return False
            return all(
                str(req).strip().lower() in observed_set 
                for req in self.evaluation_logic.required_conditions
            )

        # Rule Type 2: Weighted Score Threshold Calculation
        if self.evaluation_logic.rule == "any_critical_or_weighted_threshold":
            total_score = 0
            for cond in self.conditions:
                clean_cond_id = str(cond.id).strip().lower()
                if clean_cond_id in observed_set:
                    if str(cond.severity).strip().lower() == "critical":
                        return True
                    total_score += cond.weight
            
            threshold = self.evaluation_logic.threshold_score or 0
            return total_score >= threshold

        # Default fallback: check if at least one observed condition matches (case-insensitive)
        return any(str(cond.id).strip().lower() in observed_set for cond in self.conditions)
