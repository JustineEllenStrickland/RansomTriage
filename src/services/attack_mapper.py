import json
import logging
from pathlib import Path
from typing import List, Union, Dict, DefaultDict, Optional
from collections import defaultdict
from src.models.attack_mapping import AttackMapping


class AttackMapper:
    # Service-layer tactical lookup map resolving source items to clear investigator goals
    FORENSIC_PLAYBOOK_MAP = {
        "windows_event_logs": "Extract and review Windows Security Event Logs (Event ID 4624/4625 for logon validation, 4656/4663 for object manipulation tracking).",
        "sysmon": "Parse Sysmon Operational Logs (Event ID 1 for process execution spikes, Event ID 11 for rapid file creation/extension alterations).",
        "edr": "Query EDR telemetry consoles for active endpoint process memory dump alerts and hook impairment patterns.",
        "network_firewall_logs": "Inspect network boundary logs looking for high-volume egress targets or persistent unauthorized management port connections.",
        "cloud_idp_logs": "Audit Cloud IdP Unified Logs filtering for impossible travel alerts, session token modifications, or administrative account provisions.",
        "cloud_storage_logs": "Verify retention block locks via cloud console APIs; inspect bucket metadata changes or data lifecycle rule adjustments.",
        "linux_auditd": "Parse Linux auditd output targeting file monitoring access rules, service execution states, and commands manipulating data blocks.",
        "syslog": "Analyze local authentication facilities and system logging units for explicit daemon kills or auth anomalies.",
        "esxi_shell_logs": "Inspect host /var/log/vobd.log and esxcli operation pathways for backend virtual disk detachment or local execution calls.",
        "vpn_access_logs": "Isolate external connection tables, corroborating entry session tokens against identity authentication anomalies.",
        "web_server_logs": "Analyze HTTP request paths looking for server application exploit strings, upload targets, or web shell footprints.",
        "storage_console_logs": "Verify central storage fabric logs for programmatic administrative commands modifying production block spaces.",
        "file_server_logs": "Monitor concurrent file tracking events to evaluate the scope and blast radius of modified and renamed assets."
    }

    def __init__(self, mapping_path: Union[str, Path]):
        self.mapping_path = Path(mapping_path)
        # Partitioned mappings tracking criteria buckets safely
        self._partitioned_mappings: DefaultDict[str, List[AttackMapping]] = defaultdict(list)
        # Collision-proof composite cache: (category, technique_id) -> AttackMapping
        self._composite_lookup_cache: Dict[tuple[str, str], AttackMapping] = {}
        # Secondary fallback global index tracking raw technique_id safely
        self._global_id_cache: Dict[str, List[AttackMapping]] = defaultdict(list)
        
        self._load_config()

    def _load_config(self) -> None:
        """Loads JSON config data and groups target items into partitioned dataclass buckets."""
        try:
            with self.mapping_path.open("r", encoding="utf-8") as file:
                raw_data = json.load(file)
                
            mappings_list = raw_data.get("mappings", [])
            for m in mappings_list:
                try:
                    mapping_obj = AttackMapping.from_dict(m)
                    category = str(mapping_obj.observation_category).strip().lower()
                    
                    # Sanitize Technique ID for defensive key storage consistency
                    tech_id = str(mapping_obj.technique_id).strip().upper() if mapping_obj.technique_id else ""
                    
                    self._partitioned_mappings[category].append(mapping_obj)
                    
                    # Store explicitly by a composite unique token to prevent data loss collisions
                    if tech_id:
                        self._composite_lookup_cache[(category, tech_id)] = mapping_obj
                        self._global_id_cache[tech_id].append(mapping_obj)
                        
                except Exception as entry_err:
                    logging.warning(f"Skipping malformed ATT&CK mapping schema row: {entry_err}")
                    
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            logging.error(f"[-] Critical Error initializing AttackMapper configurations: {e}")

    def get_evidence_recommendations(self, identified_techniques: List[str]) -> List[str]:
        """
        Gathers a deduplicated checklist of active evidence targets for the analyst
        by investigating the underlying evidence_sources assigned to the flagged techniques.
        """
        recommendations = []
        seen_sources = set()

        for tech_id in identified_techniques:
            clean_tech_id = str(tech_id).strip().upper()
            mappings = self._global_id_cache.get(clean_tech_id, [])
            
            for mapping in mappings:
                # Introspect safe source definitions assigned to data structures
                sources = getattr(mapping, "evidence_sources", []) or []
                for src in sources:
                    clean_src = str(src).strip().lower()
                    if clean_src not in seen_sources:
                        seen_sources.add(clean_src)
                        # Translate the core evidence source to an actionable analyst task string
                        task_desc = self.FORENSIC_PLAYBOOK_MAP.get(clean_src)
                        if task_desc:
                            recommendations.append(task_desc)
                            
        return recommendations

    def get_all_mappings(self) -> List[AttackMapping]:
        """Flattens and returns all loaded MITRE ATT&CK object mapping profiles."""
        all_mappings = []
        for mappings_list in self._partitioned_mappings.values():
            all_mappings.extend(mappings_list)
        return all_mappings

    def get_mapping_by_id(self, technique_id: str, category: Optional[str] = None) -> Optional[AttackMapping]:
        """
        Retrieves an AttackMapping object by its MITRE ID. 
        Enforces defensive normalization checks against inputs.
        """
        clean_tech_id = str(technique_id).strip().upper()
        
        if category:
            clean_category = str(category).strip().lower()
            return self._composite_lookup_cache.get((clean_category, clean_tech_id))
            
        global_matches = self._global_id_cache.get(clean_tech_id)
        return global_matches[0] if global_matches else None

    def get_technique_name(self, technique_id: str, fallback_default: str = "Triage Matrix Flagged Indicator") -> str:
        """Resolves a human-readable technique name from a raw ID via global cache sweeps."""
        clean_tech_id = str(technique_id).strip().upper()
        global_matches = self._global_id_cache.get(clean_tech_id)
        if global_matches and global_matches[0].technique_name:
            return global_matches[0].technique_name
        return fallback_default

    def map_responses(self, observation_category: str, responses: Dict[str, bool]) -> List[AttackMapping]:
        """
        Evaluates triage dashboard responses against the filtered rules sub-engine.
        Defensively handles potential string mismatch anomalies.
        """
        clean_category = str(observation_category).strip().lower()
        category_pool = self._partitioned_mappings.get(clean_category)
        if not category_pool:
            logging.warning(f"[-] Evaluation request processed for unknown category: '{observation_category}'")
            return []

        # Isolate true observed condition items, standardizing case parameters safely
        observed_condition_ids = [
            str(condition_id).strip().lower() 
            for condition_id, was_observed in responses.items() 
            if was_observed
        ]

        # Optimization: If no parameters are selected, exit early
        if not observed_condition_ids:
            return []

        matched_techniques = []
        for mapping in category_pool:
            try:
                # Fallback safeguard checks: evaluate using exact lookups, lowered fallbacks, or mapped criteria loops
                if hasattr(mapping, "evaluate_match") and mapping.evaluate_match(observed_condition_ids):
                    matched_techniques.append(mapping)
            except Exception as eval_err:
                logging.error(f"[-] Mapping evaluation failed on technique object '{getattr(mapping, 'technique_id', 'Unknown')}': {eval_err}")

        return matched_techniques
