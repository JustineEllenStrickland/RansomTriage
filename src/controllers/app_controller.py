import logging
from pathlib import Path
from typing import Optional, Dict, Any, List

from src.models.case import Case
from src.services.attack_mapper import AttackMapper
from src.services.evidence_recommender import EvidenceRecommender
from src.services.storage_service import StorageService
from src.services.report_generator import ReportGenerator


class AppController:
    def __init__(
        self,
        mapping_json_path: str | Path,
        evidence_json_path: str | Path,
        template_md_path: str | Path
    ):
        """Initializes and binds the core backend engine subsystems."""
        # Initialize Backend Subsystems
        self.attack_mapper = AttackMapper(mapping_json_path)
        self.evidence_recommender = EvidenceRecommender(evidence_json_path)
        self.storage_service = StorageService()
        self.report_generator = ReportGenerator(template_md_path)
        
        # Application State Trackers
        self.active_case: Optional[Case] = None
        self.current_case_path: Optional[Path] = None
        
        # A registry of UI callbacks to trigger view-layer updates
        self._state_changed_callbacks: List[callable] = []

    def register_state_callback(self, callback: callable) -> None:
        """Allows PyQt tabs to register view refreshment slots dynamically."""
        if callback not in self._state_changed_callbacks:
            self._state_changed_callbacks.append(callback)

    def _notify_state_changed(self) -> None:
        """Broadcaster loop that forces UI views to pull fresh incident metrics."""
        for callback in self._state_changed_callbacks:
            try:
                callback()
            except Exception as e:
                logging.error(f"[-] Failed to update view component registration slot: {e}")

    def initialize_new_case(self, title: str, analyst: str, asset: str) -> Case:
        """Instantiates a fresh Case model context and clears stale session states."""
        self.active_case = Case(
            case_title=title,
            analyst=analyst,
            affected_asset=asset,
            observation_category="",
            observations=""
        )
        self.current_case_path = None
        self._notify_state_changed()
        return self.active_case

    def process_triage_submission(
        self, 
        observation_category: str, 
        responses: Dict[str, bool], 
        available_telemetry: List[str],
        raw_observations_notes: str = ""
    ) -> None:
        """
        Executes our hardened analytical processing loop. Takes raw UI dashboard 
        inputs, runs mapping matrices, establishes data visibility gaps, 
        and updates the active Case instance safely.
        """
        if not self.active_case:
            logging.warning("[!] Attempted processing triage responses without an active case context.")
            return

        # 1. Update primary text telemetry fields
        self.active_case.observation_category = observation_category
        self.active_case.observations = raw_observations_notes

        # 2. Run the case-insensitive MITRE ATT&CK Mapping matrix check loop
        matched_mappings = self.attack_mapper.map_responses(observation_category, responses)
        self.active_case.candidate_mappings = matched_mappings

        # 3. Cross-reference available log profiles to map structural visibility gaps
        recommended_sources, missing_source_names = self.evidence_recommender.recommend(
            candidate_input=matched_mappings,
            available_telemetry=available_telemetry,
            attack_mapper=self.attack_mapper
        )
        
        # 4. Hydrate calculated findings into the primary Case state machine
        self.active_case.evidence_recommendations = [str(r.get("name", r.get("id"))) for r in recommended_sources]
        self.active_case.unavailable_telemetry = missing_source_names

        # 5. Broadcast changes across views to draw fresh metrics on Dashboard/Report screens
        self._notify_state_changed()

    def commit_active_case_to_disk(self, export_path: str | Path) -> bool:
        """Serializes and saves the ongoing case file atomically via StorageService."""
        if not self.active_case:
            logging.error("[-] No active case available to commit to disk storage.")
            return False
            
        try:
            saved_path = self.storage_service.save_case(self.active_case, export_path)
            self.current_case_path = saved_path
            return True
        except Exception as e:
            logging.error(f"[-] Core controller failed to save case context: {e}")
            return False

    def ingest_case_from_disk(self, import_path: str | Path) -> bool:
        """Loads an old workspace dump profile, updating overall application status indicators."""
        try:
            loaded_case = self.storage_service.load_case(import_path)
            if loaded_case:
                self.active_case = loaded_case
                self.current_case_path = Path(import_path)
                self._notify_state_changed()
                return True
            return False
        except Exception as e:
            logging.error(f"[-] Ingestion handler failed processing case path '{import_path}': {e}")
            return False

    def compile_markdown_report(self, save_target_path: str | Path) -> Optional[Path]:
        """Compiles reporting markdown artifacts using Jinja template fallback engines."""
        if not self.active_case:
            logging.error("[-] Compilation terminated: No active incident records initialized.")
            return None
            
        try:
            compiled_report = self.report_generator.save_markdown(self.active_case, save_target_path)
            return compiled_report
        except Exception as e:
            logging.error(f"[-] Report compilation pipeline broken: {e}")
            return None
