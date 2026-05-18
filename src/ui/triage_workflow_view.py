import json
import logging
from pathlib import Path
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QLabel, QMessageBox, QGridLayout)
from PyQt6.QtCore import Qt
from src.services.attack_mapper import AttackMapper

class TriageCapsuleButton(QPushButton):
    """Custom rounded rectangular tile for modern, high-visibility option selections."""
    def __init__(self, label_text: str, data_value: str, parent=None):
        super().__init__(label_text, parent)
        self.data_value = str(data_value)  
        self.setCheckable(True)
        self.setMinimumHeight(55)
        self.setStyleSheet("""
            QPushButton {
                background-color: #14141F;
                color: #FFFFFF;
                border: 1px solid #2D2D3F;
                border-radius: 8px;
                padding: 12px 20px;
                font-size: 13px;
                font-weight: bold;
                text-align: center;
            }
            QPushButton:hover {
                background-color: #1C1C2A;
                border-color: #00DFFF;
                color: #00DFFF;
            }
            QPushButton:checked {
                background-color: #0B2535;
                color: #00FF00;
                border: 2px solid #00FF00;
            }
        """)


class TriageWorkflowView(QWidget):
    def __init__(self, attack_mapper: AttackMapper, parent_main_window=None):
        super().__init__()
        self.mapper = attack_mapper
        self.main_window = parent_main_window 
        
        project_root = self.main_window.project_root if self.main_window else Path(".")
        self.config_path = project_root / "src" / "config" / "triage_workflow.json"
        
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.matrix_data = json.load(f)
        except Exception as e:
            logging.critical(f"[-] Failed to load triage matrix configuration definitions: {e}")
            self.matrix_data = {"root_nodes": {}, "threat_nodes": {}}
            
        # State Machine tracking parameters
        self.current_phase = "ROOT_PLATFORM"  
        self.selected_platforms = []          
        self.mapped_threat_platforms = []    
        self.active_platform_index = 0        
        self.active_question_index = 0        
        self.active_capsules = []
        self.answers_log = {}
        
        self.identified_techniques = []
        self.phase_history = [] 

        self.THREAT_KEY_MAP = {
            "windows": "windows_core_ransomware",
            "linux": "linux_host_ransomware",
            "esxi": "esxi_hypervisor_ransomware",
            "cloud: identity provider": "cloud_idp_compromise",
            "cloud: saas": "cloud_idp_compromise",
            "cloud: office suite": "cloud_idp_compromise",
            "cloud: iaas": "cloud_idp_compromise",
            "cloud: generic": "cloud_idp_compromise"
        }

        self.init_ui()

    def init_ui(self):
        """Builds workspace panel optimized for tracking diagnostic questions cleanly."""
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(30, 30, 30, 30)
        self.main_layout.setSpacing(20)
        
        self.phase_lbl = QLabel("")
        self.phase_lbl.setStyleSheet("font-size: 12px; font-weight: bold; color: #888899; letter-spacing: 2px;")
        self.main_layout.addWidget(self.phase_lbl)
        
        self.question_lbl = QLabel("")
        self.question_lbl.setWordWrap(True)
        self.question_lbl.setStyleSheet("font-size: 20px; font-weight: bold; color: #00DFFF; padding-bottom: 5px;")
        self.main_layout.addWidget(self.question_lbl)
        
        self.guidance_lbl = QLabel("")
        self.guidance_lbl.setWordWrap(True)
        self.guidance_lbl.setStyleSheet("""
            background-color: #0F0F14; color: #A0A0B0; 
            border-left: 4px solid #00FF00; padding: 15px; 
            font-size: 13px; border-radius: 4px;
        """)
        self.main_layout.addWidget(self.guidance_lbl)
        
        self.capsule_container = QWidget()
        self.capsule_grid = QGridLayout(self.capsule_container)
        self.capsule_grid.setSpacing(15)
        self.capsule_grid.setContentsMargins(0, 10, 0, 10)
        self.main_layout.addWidget(self.capsule_container)
        
        self.main_layout.addStretch()
        
        nav_layout = QHBoxLayout()
        self.back_btn = QPushButton("◀ STEP BACKWARD")
        self.back_btn.setMinimumHeight(45)
        self.back_btn.setMinimumWidth(160)
        self.back_btn.setStyleSheet("""
            QPushButton { background-color: #1A1A24; color: #888899; font-weight: bold; font-size: 13px; border: 1px solid #2D2D3F; border-radius: 6px; }
            QPushButton:hover { background-color: #252535; color: #FFFFFF; border-color: #888899; }
        """)
        self.back_btn.clicked.connect(self.step_backward)
        nav_layout.addWidget(self.back_btn)
        nav_layout.addStretch()

        self.submit_btn = QPushButton("PROCEED TO NEXT MATRIX PHASE ➔")
        self.submit_btn.setMinimumHeight(45)
        self.submit_btn.setMinimumWidth(250)
        self.submit_btn.setStyleSheet("""
            QPushButton { background-color: #00FF00; color: #000000; font-weight: bold; font-size: 13px; border-radius: 6px; }
            QPushButton:hover { background-color: #00CC00; }
        """)
        self.submit_btn.clicked.connect(self.run_wizard_step)
        nav_layout.addWidget(self.submit_btn)
        self.main_layout.addLayout(nav_layout)

        self.goto_root_platform_phase()

    def render_ui_node(self, node_data: dict, title_prefix: str):
        """Flushes previous layout and draws clean custom option capsule buttons."""
        while self.capsule_grid.count():
            item = self.capsule_grid.takeAt(0)
            w = item.widget()
            if w: w.deleteLater()
        self.active_capsules.clear()
        
        self.question_lbl.setText(node_data.get("text", "No prompt found."))
        self.guidance_lbl.setText(node_data.get("guidance", "Analyze environment logs for matching indicators."))
        self.phase_lbl.setText(title_prefix.upper())
        
        options_pool = list(node_data.get("options", []))
        
        if self.current_phase == "THREAT_QUESTIONS":
            q_id = node_data.get("id", "UNKNOWN")
            options_pool.append({"label": "Other / Ambiguous Signature", "value": f"{q_id}_OTHER"})
            options_pool.append({"label": "I Don't Know (Telemetry Gap)", "value": f"{q_id}_DONT_KNOW"})

        columns = 2
        for index, opt in enumerate(options_pool):
            btn = TriageCapsuleButton(opt["label"], opt["value"])
            
            # Precise rehydration normalization check
            if opt["value"] in self.answers_log:
                btn.setChecked(self.answers_log[opt["value"]])
            else:
                btn.setChecked(opt["value"] in self.selected_platforms)

            if opt["value"].endswith("_DONT_KNOW"):
                btn.clicked.connect(lambda checked, target_btn=btn: self.handle_dont_know_click(target_btn))
            elif self.current_phase == "THREAT_QUESTIONS":
                btn.clicked.connect(lambda checked, target_btn=btn: self.handle_regular_capsule_click(target_btn))

            self.capsule_grid.addWidget(btn, index // columns, index % columns)
            self.active_capsules.append(btn)

        self.back_btn.setVisible(len(self.phase_history) > 0)

    def handle_dont_know_click(self, dont_know_btn: TriageCapsuleButton):
        if dont_know_btn.isChecked():
            for btn in self.active_capsules:
                if btn != dont_know_btn:
                    btn.setChecked(False)

    def handle_regular_capsule_click(self, regular_btn: TriageCapsuleButton):
        if regular_btn.isChecked():
            for btn in self.active_capsules:
                if btn.data_value.endswith("_DONT_KNOW"):
                    btn.setChecked(False)

    def push_state_to_history(self):
        """Caches snapshot parameters before updating wizard configurations."""
        snapshot = {
            "phase": self.current_phase,
            "selected_platforms": list(self.selected_platforms),
            "mapped_threat_platforms": list(self.mapped_threat_platforms),
            "active_platform_index": self.active_platform_index,
            "active_question_index": self.active_question_index,
            "answers_log": self.answers_log.copy()
        }
        self.phase_history.append(snapshot)

    def step_backward(self):
        """Reverts wizard engine back one interaction step to adjust operational inputs."""
        if not self.phase_history:
            return
            
        previous_state = self.phase_history.pop()
        self.current_phase = previous_state["phase"]
        self.selected_platforms = previous_state["selected_platforms"]
        self.mapped_threat_platforms = previous_state["mapped_threat_platforms"]
        self.active_platform_index = previous_state["active_platform_index"]
        self.active_question_index = previous_state["active_question_index"]
        self.answers_log = previous_state["answers_log"]

        if self.current_phase == "ROOT_PLATFORM":
            self.goto_root_platform_phase()
        elif self.current_phase == "SUB_BREAKDOWN":
            node = self.matrix_data["root_nodes"]["Q2_1"]
            self.render_ui_node(node, "PHASE 2: INFRASTRUCTURE SUB-BREAKDOWN")
        elif self.current_phase == "THREAT_QUESTIONS":
            current_platform = self.mapped_threat_platforms[self.active_platform_index]
            questions_pool = self.matrix_data["threat_nodes"].get(current_platform, [])
            q = questions_pool[self.active_question_index]
            prefix = f"TACTICAL AUDIT: {current_platform.replace('_', ' ').upper()} — STEP {self.active_question_index + 1}/{len(questions_pool)}"
            self.render_ui_node(q, prefix)

    def goto_root_platform_phase(self):
        self.current_phase = "ROOT_PLATFORM"
        node = self.matrix_data["root_nodes"]["Q1"]
        self.render_ui_node(node, "PHASE 1: ROOT INFRASTRUCTURE AUDIT")

    def goto_sub_breakdown_phase(self):
        self.current_phase = "SUB_BREAKDOWN"
        node = self.matrix_data["root_nodes"]["Q2_1"]
        self.render_ui_node(node, "PHASE 2: INFRASTRUCTURE SUB-BREAKDOWN")

    def start_threat_questions_phase(self):
        """Maps user choices to target backend data node keys via case-normalized lookup checks."""
        self.current_phase = "THREAT_QUESTIONS"
        self.active_platform_index = 0
        self.active_question_index = 0
        
        mapped_keys = []
        for p in self.selected_platforms:
            translated_key = self.THREAT_KEY_MAP.get(str(p).lower().strip())
            if translated_key and translated_key not in mapped_keys:
                mapped_keys.append(translated_key)

        self.mapped_threat_platforms = mapped_keys
        self.load_active_threat_question()

    def load_active_threat_question(self):
        """Sequentially serves the next threat question block for the current active platform tree."""
        if self.active_platform_index >= len(self.mapped_threat_platforms):
            self.finalize_triage_workflow()
            return

        current_platform = self.mapped_threat_platforms[self.active_platform_index]
        questions_pool = self.matrix_data["threat_nodes"].get(current_platform, [])

        if not questions_pool:
            self.active_platform_index += 1
            self.active_question_index = 0
            self.load_active_threat_question()
            return

        if self.active_question_index < len(questions_pool):
            q = questions_pool[self.active_question_index]
            prefix = f"TACTICAL AUDIT: {current_platform.replace('_', ' ').upper()} — STEP {self.active_question_index + 1}/{len(questions_pool)}"
            self.render_ui_node(q, prefix)
        else:
            self.active_platform_index += 1
            self.active_question_index = 0
            self.load_active_threat_question()

    def run_wizard_step(self):
        """Evaluates active check states, modifies state records, and steps ahead."""
        raw_values = [str(btn.data_value) for btn in self.active_capsules if btn.isChecked()]
        sanitized_check = [v.lower().strip() for v in raw_values]

        if self.current_phase == "ROOT_PLATFORM":
            if not raw_values:
                QMessageBox.warning(self, "Selection Required", "Please select at least one environment platform option to continue.")
                return
            
            self.push_state_to_history()
            self.selected_platforms = raw_values.copy()
            
            if "enterprise" in sanitized_check:
                self.goto_sub_breakdown_phase()
            else:
                self.start_threat_questions_phase()
                
        elif self.current_phase == "SUB_BREAKDOWN":
            if not raw_values:
                QMessageBox.warning(self, "Selection Required", "Please select an asset category or identify a target baseline anomaly.")
                return

            self.push_state_to_history()
            
            # Cleanly merge structural breakdown details using case-insensitive validation lookups
            for val in raw_values:
                if val.lower().strip() != "infrastructure unknown" and val not in self.selected_platforms:
                    self.selected_platforms.append(val)
            
            # Case-insensitive filtering of structural anchor terms
            self.selected_platforms = [p for p in self.selected_platforms if p.lower().strip() != "enterprise"]
                
            self.start_threat_questions_phase()

        elif self.current_phase == "THREAT_QUESTIONS":
            self.push_state_to_history()
            for btn in self.active_capsules:
                self.answers_log[btn.data_value] = btn.isChecked()
            
            self.active_question_index += 1
            self.load_active_threat_question()

    def finalize_triage_workflow(self):
        """Concludes assessment phase, builds dynamic summary notes, collects technique IDs, and updates Case Intake."""
        self.current_phase = "COMPLETE"
        
        summary_lines = ["=== TELEMETRY TRIAGE MATRIX INDICATOR LOG ==="]
        affirmatives_found = False
        self.identified_techniques.clear()
        
        for threat_key in self.mapped_threat_platforms:
            questions = self.matrix_data.get("threat_nodes", {}).get(threat_key, [])
            
            for q in questions:
                question_header_added = False
                q_id = q.get("id", "UNKNOWN")
                
                # 1. Log regular checked findings (Drop negative responses explicitly)
                for opt in q.get("options", []):
                    val = opt["value"]
                    if self.answers_log.get(val) is True:
                        if any(term in val.upper() for term in ["ABSENT", "CLEAN", "PROGRESS"]):
                            continue
                            
                        if not question_header_added:
                            summary_lines.append(f"\n• [{q_id}] Phase: {q.get('phase', 'Triage Phase')}")
                            summary_lines.append(f"  Question: {q.get('text')}")
                            question_header_added = True
                            
                        summary_lines.append(f"    └─ Flagged Alert: {opt['label']} ({q.get('technique_id', 'T1000')})")
                        affirmatives_found = True
                        
                        tech_id = q.get("technique_id")
                        if tech_id and tech_id not in self.identified_techniques:
                            self.identified_techniques.append(tech_id)
                
                # 2. Log dynamic fallbacks safely
                if self.answers_log.get(f"{q_id}_OTHER") is True:
                    if not question_header_added:
                        summary_lines.append(f"\n• [{q_id}] Phase: {q.get('phase', 'Triage Phase')}")
                        summary_lines.append(f"  Question: {q.get('text')}")
                        question_header_added = True
                    summary_lines.append("    └─ Flagged Alert: Other / Ambiguous Signature alternative flagged.")
                    affirmatives_found = True
                    
                if self.answers_log.get(f"{q_id}_DONT_KNOW") is True:
                    if not question_header_added:
                        summary_lines.append(f"\n• [{q_id}] Phase: {q.get('phase', 'Triage Phase')}")
                        summary_lines.append(f"  Question: {q.get('text')}")
                        question_header_added = True
                    summary_lines.append("    └─ Flagged Alert: Analyst marked as Telemetry Gap / Unknown.")
                    affirmatives_found = True

        if not affirmatives_found:
            summary_lines.append("\n• No critical ransomware indicators were flagged present in this infrastructure pass.")
            
        summary_lines.append("\n\nOperational Guidance: Proceed with tactical host isolation rules mapped to discovered techniques.")
        
        # --- NEW CODE SECTION: DYNAMIC EVIDENCE CHECKLISTS ---
        summary_lines.append("\n## Evidence Recommendations")
        
        # Pull generated recommendations checklist directly from service layer data definitions
        recommendations = []
        if self.mapper and hasattr(self.mapper, "get_evidence_recommendations"):
            recommendations = self.mapper.get_evidence_recommendations(self.identified_techniques)
            
        if recommendations:
            for rec in recommendations:
                summary_lines.append(f"- [ ] {rec}")
        else:
            summary_lines.append("- No specific evidence recommendations generated.")
        # --- END OF NEW CODE SECTION ---

        final_notes_string = "\n".join(summary_lines)

        QMessageBox.information(
            self, "Analysis Matrix Complete",
            "Environment triage metrics compiled successfully. Proceeding to Case Intake profiling options."
        )
        
        if self.main_window:
            self.main_window.enable_case_intake()
            if hasattr(self.main_window, "populate_intake_notes"):
                self.main_window.populate_intake_notes(final_notes_string, self.mapped_threat_platforms)
            self.main_window.tabs.setCurrentIndex(2)

    def refresh_board(self):
        self.selected_platforms.clear()
        self.mapped_threat_platforms.clear()
        self.answers_log.clear()
        self.phase_history.clear()
        self.identified_techniques.clear()
        self.active_platform_index = 0
        self.active_question_index = 0
        self.goto_root_platform_phase()
