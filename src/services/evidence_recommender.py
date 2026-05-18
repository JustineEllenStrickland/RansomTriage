import json
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Any, Set, Union
from src.models.attack_mapping import AttackMapping


class EvidenceRecommender:
    def __init__(self, evidence_path: str | Path):
        self.evidence_path = Path(evidence_path)
        self.config: Dict[str, Any] = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Loads telemetry reference schemas with error isolation boundaries."""
        try:
            with self.evidence_path.open("r", encoding="utf-8") as file:
                return json.load(file)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logging.error(f"[-] Error loading telemetry baseline reference configuration maps: {e}")
            return {"evidence_sources": []}

    def recommend(
        self, 
        candidate_input: Union[List[AttackMapping], List[str]], 
        available_telemetry: List[str],
        attack_mapper: Any = None
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Cross-references identified tactics against available telemetry baselines to locate gaps.
        Defensively handles case-insensitivity and prevents out-of-order evaluation logic bugs.
        """
        # Lowercase lookup keys to completely neutralize configuration layout casing issues
        source_lookup = {
            str(source["id"]).strip().lower(): source
            for source in self.config.get("evidence_sources", []) if "id" in source
        }

        # Normalize incoming available telemetry list parameters to a clean lowercase set
        available_set = {str(t).strip().lower() for t in available_telemetry}
        
        recommended_items: List[Dict[str, Any]] = []
        recommended_ids_seen: Set[str] = set()
        unavailable_ids_tracked: Set[str] = set()

        # Step 1: Normalize input to full AttackMapping objects where possible
        resolved_mappings: List[AttackMapping] = []
        for item in candidate_input:
            if isinstance(item, AttackMapping):
                resolved_mappings.append(item)
            elif isinstance(item, str) and attack_mapper is not None:
                mapping_obj = attack_mapper.get_mapping_by_id(item)
                if mapping_obj:
                    resolved_mappings.append(mapping_obj)
            else:
                logging.warning(f"[!] Unable to process telemetry recommendation for candidate type: {type(item)}")

        # Step 2: Evaluate source matrices ensuring bulletproof tracking state updates
        for mapping in resolved_mappings:
            source_ids = getattr(mapping, "evidence_sources", [])
            if not isinstance(source_ids, list):
                continue
                
            for raw_source_id in source_ids:
                clean_source_id = str(raw_source_id).strip().lower()
                source_record = source_lookup.get(clean_source_id)
                
                if not source_record:
                    logging.warning(f"[-] Mapping references an unknown forensic target log asset ID: '{raw_source_id}'")
                    continue

                if clean_source_id in available_set:
                    # Target telemetry pipeline is online and verified
                    if clean_source_id not in recommended_ids_seen:
                        recommended_ids_seen.add(clean_source_id)
                        recommended_items.append(source_record)
                    
                    # Defensively purge from gaps case-insensitively if it was previously flagged out of order
                    if clean_source_id in unavailable_ids_tracked:
                        unavailable_ids_tracked.remove(clean_source_id)
                else:
                    # Target telemetry pipeline is missing. Only log it as an active gap 
                    # if no other identified tactic has confirmed it is online.
                    if clean_source_id not in recommended_ids_seen:
                        unavailable_ids_tracked.add(clean_source_id)

        # Map clean normalized IDs back to their human-readable configuration equivalents for the report
        final_unavailable_names = []
        for missing_id in unavailable_ids_tracked:
            record = source_lookup.get(missing_id)
            if record and "name" in record:
                final_unavailable_names.append(record["name"])
            else:
                final_unavailable_names.append(missing_id.upper())

        return recommended_items, sorted(final_unavailable_names)
