import logging
import json
from pathlib import Path
from datetime import datetime

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QScrollArea,
    QTabWidget,
    QGridLayout,
)
from PyQt6.QtCore import Qt

from src.models.case import Case
from src.services.attack_mapper import AttackMapper
from src.services.evidence_recommender import EvidenceRecommender
from src.services.report_generator import ReportGenerator
from src.services.storage_service import StorageService
from src.ui.triage_workflow_view import TriageWorkflowView


def setup_runtime_logging(project_root: Path):
    """Initializes a dual-stream engine capturing terminal output and file preservation logs."""
    log_dir = project_root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "ransomtriage.log"

    # Define a clean, professional DFIR format structure
    log_format = '[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)d] ➔ %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    root_logger = logging.getLogger()
    
    # Clears out any implicit handlers hidden or broken by other imports
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Force absolute baseline configuration instantly mapped to files and stdout
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8", mode="a"), # Append mode
            logging.StreamHandler() # Direct to Kali terminal stdout
        ]
    )

    logging.info("[*] RansomTriage Logging System Initialized Successfully.")

class MainWindow(QMainWindow):
    def __init__(self, project_root: Path):
        super().__init__()
        self.project_root = Path(project_root)
        
        # Spin up the logging streams immediately!
        setup_runtime_logging(self.project_root)
        
        self.current_case = None
        self.setWindowTitle("RansomTriage: Guided Ransomware Incident Operations")
        self.resize(1000, 750) 
        self.setMinimumSize(800, 600)

        self._apply_stylesheet()
        self._initialize_services()
        self._build_ui()

    def _apply_stylesheet(self):
        """Applies tactical dark-mode aesthetic boundaries."""
        self.setStyleSheet("""
            QMainWindow { background-color: #0A0A0D; color: #FFFFFF; }
            QTabWidget::pane { border: 1px solid #2D2D3F; background-color: #0F0F14; border-radius: 4px; }
            QTabBar::tab { background-color: #1A1A24; color: #888888; padding: 10px 20px; font-weight: bold; border: 1px solid #2D2D3F; border-bottom: none; border-top-left-radius: 4px; border-top-right-radius: 4px; }
            QTabBar::tab:selected { background-color: #0F0F14; color: #00DFFF; border-bottom: 2px solid #00DFFF; }
            QTabBar::tab:hover { background-color: #252535; color: #FFFFFF; }
            QGroupBox { border: 1px solid #2D2D3F; border-radius: 6px; margin-top: 15px; font-weight: bold; color: #00DFFF; background-color: #0F0F14; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
            QLabel { color: #E0E0E0; }
            QLineEdit, QTextEdit, QComboBox { background-color: #1A1A24; color: #FFFFFF; border: 1px solid #2D2D3F; border-radius: 4px; padding: 4px; }
            QPushButton { background-color: #252535; color: #FFFFFF; border: 1px solid #3D3D5C; padding: 6px; font-weight: bold; border-radius: 4px; }
            QPushButton:hover { background-color: #2D2D3F; border-color: #00FF00; }
            QPushButton:disabled { background-color: #111116; color: #444455; border-color: #22222C; }
            QCheckBox { color: #E0E0E0; }
            QScrollArea { border: none; background-color: #0A0A0D; }
        """)

    def _initialize_services(self):
        """Safely verifies filesystem configuration baselines before spinning up sub-engines."""
        config_dir = self.project_root / "src" / "config"
        
        mapping_path = config_dir / "attack_mappings.json"
        evidence_path = config_dir / "evidence_sources.json"
        template_path = config_dir / "export_template.md"

        for p in [mapping_path, evidence_path, template_path]:
            if not p.exists():
                logging.critical(f"[-] Missing critical configuration dependency file asset: {p}")
                QMessageBox.critical(self, "Environment Dependency Error", f"Required asset missing:\n{p.name}\n\nVerify app is executed from the correct project root.")

        logging.info("[*] Verifying and linking service sub-engines into system context.")
        self.attack_mapper = AttackMapper(mapping_path)
        self.evidence_recommender = EvidenceRecommender(evidence_path)
        self.report_generator = ReportGenerator(template_path)
        self.storage_service = StorageService()

    def _build_ui(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self._build_home_tab()
        
        self.triage_workflow_panel = TriageWorkflowView(self.attack_mapper, self)
        self.tabs.addTab(self.triage_workflow_panel, "1. Incident Matrix")
        
        self._build_case_tab()
        self._build_report_tab()

        self.tabs.setTabEnabled(2, False)  
        self.tabs.setTabEnabled(3, False)  

    def _build_home_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(35, 35, 35, 35)
        layout.setSpacing(25)

        # 1. Main Banner Header Layout
        header_layout = QVBoxLayout()
        title = QLabel("RansomTriage: Interactive Defensive Flight Deck")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #00FF00; letter-spacing: 1px;")
        subtitle = QLabel("Tactical Triage Pipeline & MITRE ATT&CK Mapping Engine")
        subtitle.setStyleSheet("font-size: 13px; color: #888899; margin-bottom: 5px;")
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        layout.addLayout(header_layout)

        # 2. Grid layout deployment for modular step documentation cards
        grid_container = QWidget()
        grid = QGridLayout(grid_container)
        grid.setSpacing(20)
        grid.setContentsMargins(0, 0, 0, 0)

        phases = [
            ("STEP 1", "Incident Matrix Triage", 
             "Assess environment telemetry anomalies sequentially using the triage wizard tab. "
             "Identify platform-specific ransomware signatures to automatically harvest relevant MITRE ATT&CK Technique IDs."),
            
            ("STEP 2", "Case Profile Intake", 
             "Bridge your environment logs with tactical context. The gathered matrix logs map automatically "
             "to target profiles where you can define assets, document manual insights, and state telemetry pipelines."),
            
            ("STEP 3", "Automated Analytics Export", 
             "Review coverage maps computed against known extortion patterns. The platform evaluates missing "
             "telemetry gaps and exports a clean, dynamic Markdown case report directly to your deployment disk.")
        ]

        for index, (step, name, description) in enumerate(phases):
            card = QGroupBox(f" {step} ")
            card.setStyleSheet("""
                QGroupBox {
                    border: 1px solid #2D2D3F;
                    border-radius: 6px;
                    font-weight: bold;
                    color: #00DFFF;
                    background-color: #0F0F14;
                    padding-top: 15px;
                }
            """)
            card_layout = QVBoxLayout()
            
            card_title = QLabel(name)
            card_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #FFFFFF; padding-bottom: 5px;")
            
            card_desc = QLabel(description)
            card_desc.setWordWrap(True)
            card_desc.setStyleSheet("color: #A0A0B0; font-size: 12px; line-height: 18px;")
            
            card_layout.addWidget(card_title)
            card_layout.addWidget(card_desc)
            card.setLayout(card_layout)
            
            grid.addWidget(card, 0, index)

        layout.addWidget(grid_container)

        # 3. Operational Notice Boundary Box
        boundary_box = QWidget()
        boundary_box.setStyleSheet("background-color: #14141F; border-left: 4px solid #00DFFF; border-radius: 4px;")
        boundary_layout = QVBoxLayout(boundary_box)
        boundary_layout.setContentsMargins(15, 12, 15, 12)
        
        boundary_text = QLabel(
            "⚠️ Operational Notice: This software serves as decision support documentation loops. "
            "All computed technique scores and mapping arrays require an analyst verification sequence before "
            "triggering isolation workflows."
        )
        boundary_text.setWordWrap(True)
        boundary_text.setStyleSheet("color: #E0E0E0; font-size: 12px;")
        boundary_layout.addWidget(boundary_text)
        layout.addWidget(boundary_box)

        layout.addStretch()

        # 4. Interactive Navigation Call To Action
        start_btn = QPushButton("Initialize New Triage Wizard Session ➔")
        start_btn.setMinimumHeight(50)
        start_btn.setStyleSheet("""
            QPushButton { 
                font-size: 14px; 
                font-weight: bold;
                color: #00FF00; 
                background-color: #0B2535;
                border: 2px solid #00FF00;
                border-radius: 6px;
            }
            QPushButton:hover { 
                background-color: #00FF00; 
                color: #000000; 
            }
        """)
        start_btn.clicked.connect(lambda: self.tabs.setCurrentIndex(1))
        layout.addWidget(start_btn)

        self.tabs.addTab(tab, "Home Deck")

    def _build_case_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        form_layout = QVBoxLayout(content)

        intake_box = QGroupBox("Step 2: Case Intake Profile Context")
        form = QFormLayout()

        self.case_title = QLineEdit()
        self.case_title.setPlaceholderText("Generating standard incident track schema...")

        self.analyst = QLineEdit()
        self.analyst.setPlaceholderText("Enter Analyst Identifier (e.g., ASMITH)")

        self.affected_asset = QLineEdit()
        self.affected_asset.setPlaceholderText("Enter Target Hostname / Asset Tag")

        self.observation_category = QComboBox()
        self.observation_category.addItem("Windows Core Ransomware Ecosystem", "windows_core_ransomware")
        self.observation_category.addItem("Linux Host Ransomware Vector", "linux_host_ransomware")
        self.observation_category.addItem("ESXi Hypervisor Target Encryption", "esxi_hypervisor_ransomware")
        self.observation_category.addItem("Cloud Identity & SaaS Control Compromise", "cloud_idp_compromise")

        self.observations = QTextEdit()
        self.observations.setMinimumHeight(120)
        self.observations.setReadOnly(True)

        self.analyst_notes_input = QTextEdit()
        self.analyst_notes_input.setMinimumHeight(80)
        self.analyst_notes_input.setPlaceholderText("Type your investigative insights, incident history, or custom team notes here...")

        form.addRow("Case Reference Title:", self.case_title)
        form.addRow("Investigating Analyst:", self.analyst)
        form.addRow("Target System Asset:", self.affected_asset)
        form.addRow("Primary Threat Grouping:", self.observation_category)
        form.addRow("Automated Matrix Output:", self.observations)
        form.addRow("Analyst Notes / Insights:", self.analyst_notes_input)

        intake_box.setLayout(form)
        form_layout.addWidget(intake_box)

        telemetry_box = QGroupBox("Pipelines Available for Investigation")
        tel_layout = QVBoxLayout()
        self.telemetry_checks = {
            "windows_event_logs": QCheckBox("Windows Event Logs"),
            "sysmon": QCheckBox("Sysmon Logs"),
            "edr": QCheckBox("Endpoint Detection and Response"),
            "identity_logs": QCheckBox("Identity Logs"),
            "entra_id_logs": QCheckBox("Entra ID Sign In Logs"),
            "dns_logs": QCheckBox("DNS Logs"),
            "firewall_logs": QCheckBox("Firewall Logs"),
            "file_server_logs": QCheckBox("File Server Logs")
        }
        for check in self.telemetry_checks.values():
            check.setChecked(False)
            tel_layout.addWidget(check)
        telemetry_box.setLayout(tel_layout)
        form_layout.addWidget(telemetry_box)

        self.run_report_check = QCheckBox("Automatically run intelligence report generation sweep upon creation")
        self.run_report_check.setChecked(True)
        self.run_report_check.setStyleSheet("color: #00DFFF; font-weight: bold; margin: 5px 0;")
        form_layout.addWidget(self.run_report_check)

        self.create_case_button = QPushButton("Compile Findings and Instantiate Formal Profile")
        self.create_case_button.setStyleSheet("padding: 10px; font-size: 13px; color: #00FF00; border-color: #00FF00;")
        self.create_case_button.clicked.connect(self.create_case_and_start_triage)
        form_layout.addWidget(self.create_case_button)

        scroll.setWidget(content)
        layout.addWidget(scroll)
        self.tabs.addTab(tab, "2. Case Intake")

    def _build_report_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        review_box = QGroupBox("Step 3: Intelligence Output Review")
        rev_layout = QVBoxLayout()
        
        self.review_box = QTextEdit()
        self.review_box.setPlaceholderText("Complete Matrix Triage and Form Intake to process target metrics summary data.")
        rev_layout.addWidget(self.review_box)
        review_box.setLayout(rev_layout)
        layout.addWidget(review_box)

        self.export_button = QPushButton("Save Tactical Markdown Document to Disk")
        self.export_button.setStyleSheet("padding: 10px; font-size: 13px; color: #00DFFF; border-color: #00DFFF;")
        self.export_button.clicked.connect(self.export_summary)
        self.export_button.setEnabled(False)
        layout.addWidget(self.export_button)

        self.tabs.addTab(tab, "3. Report Output")

    def enable_case_intake(self):
        self.tabs.setTabEnabled(2, True)
        logging.info("[*] Triage Matrix workflow completed. Case Profile tab has been unsealed.")

    def populate_intake_notes(self, summary_text: str, mapped_categories: list):
        self.observations.setPlainText(summary_text)
        current_date_string = datetime.now().strftime("%Y%m%d")
        
        case_index = 1
        try:
            export_dir = self.project_root / "exports"
            if export_dir.exists():
                case_index = len(list(export_dir.glob("*.md"))) + 1
        except Exception:
            pass
            
        self.case_title.setText(f"RansomTriage-{current_date_string}-{case_index:03d}")

        if mapped_categories:
            primary_detected_vector = mapped_categories[0]
            matching_index = self.observation_category.findData(primary_detected_vector)
            if matching_index != -1:
                self.observation_category.setCurrentIndex(matching_index)
                
        logging.info(f"[*] Generated auto-ingested case parameters. Tracking layout index set: {self.case_title.text()}")

    def create_case_and_start_triage(self):
        if not self.analyst.text().strip() or not self.affected_asset.text().strip():
            logging.warning("[-] Blocked creation request: Attempted intake registration with empty identity fields.")
            QMessageBox.warning(self, "Missing Profile Information", "Please specify an Investigating Analyst and Target System Asset tag before generating report profiles.")
            return

        # 1. Instantiate Core Model
        self.current_case = Case(
            case_title=self.case_title.text(),
            analyst=self.analyst.text(),
            observation_category=self.observation_category.currentData(),
            affected_asset=self.affected_asset.text(),
            observations=self.observations.toPlainText(),
            analyst_notes=self.analyst_notes_input.toPlainText() if self.analyst_notes_input.toPlainText().strip() else "No analyst notes provided.",
        )

        triage_answers = getattr(self.triage_workflow_panel, "answers_log", {})
        self.current_case.triage_responses = triage_answers.copy()
        
        logging.info(f"[+] Case registered securely: {self.current_case.case_title} mapped by Analyst {self.current_case.analyst}")

        # 2. Map ATT&CK Profiling using the dedicated AttackMapper Service
        current_category = self.observation_category.currentData()
        matched_mappings = self.attack_mapper.map_responses(current_category, triage_answers)
        
        # Merge manual wizard technique flagging overrides with type safety protection
        technique_ids_detected = getattr(self.triage_workflow_panel, "identified_techniques", [])
        for tech_id in technique_ids_detected:
            if not any(m.technique_id == tech_id for m in matched_mappings):
                resolved_name = self.attack_mapper.get_technique_name(tech_id)
                
                # Dynamic model fallback imports to isolate structural signatures securely
                from src.models.attack_mapping import AttackMapping, EvaluationLogic, RansomwareContext, AnalystActions
                
                fallback_mapping = AttackMapping(
                    technique_id=tech_id,
                    technique_name=resolved_name,
                    tactic="Staged Detection",
                    attack_phase="Triage Matrix Flagged Indicator",
                    confidence_score="Medium",
                    observation_category=current_category,
                    evaluation_logic=EvaluationLogic(rule="any_match"),
                    conditions=[],
                    ransomware_context=RansomwareContext(), 
                    analyst_actions=AnalystActions(containment_recommendation=""), 
                    evidence_sources=[],
                    revision_date=datetime.now().strftime("%Y-%m-%d")
                )
                matched_mappings.append(fallback_mapping)

        # 3. FIXED: Purged syntax structural duplicate mapping block safely
        self.current_case.candidate_mappings = [
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "confidence_score": m.confidence_score
            }
            for m in matched_mappings
        ]

        # 4. Process Telemetry recommendations
        available_telemetry = [key for key, cb in self.telemetry_checks.items() if cb.isChecked()]
        recommended_records, missing_telemetry_ids = self.evidence_recommender.recommend(
            matched_mappings, 
            available_telemetry,
            attack_mapper=self.attack_mapper
        )

        recommendations_list = []
        for record in recommended_records:
            recommendations_list.append(
                f"Acquire and cross-reference **{record['name']}** ({record['category'].upper()} level). Action playbook item: {record['description']}"
            )
        self.current_case.evidence_recommendations = recommendations_list

        self.current_case.unavailable_telemetry = [
            cb.text() for cb in self.telemetry_checks.values() if not cb.isChecked()
        ]
        
        self.current_case.limitations = [
            "Matrix indicator matching requires independent manual verification loops.",
            "Operates bound strictly against verified telemetry schemas.",
        ]

        # 5. Storage and Reporting Generation Execution
        runtime_dir = self.project_root / "runtime"
        runtime_dir.mkdir(parents=True, exist_ok=True) 
        self.storage_service.save_case(self.current_case, runtime_dir / "demo_case.json")
        logging.info(f"[*] Cached current triage schema parameters to active database pool: {runtime_dir / 'demo_case.json'}")

        if self.run_report_check.isChecked():
            summary = self.report_generator.generate_markdown(self.current_case)
            self.review_box.setPlainText(summary)
            logging.info(f"[+] Dynamic Jinja analytical engine report evaluated successfully for target host: {self.current_case.affected_asset}")
            
            self.tabs.setTabEnabled(3, True)
            self.export_button.setEnabled(True)
            self.tabs.setCurrentIndex(3)
            QMessageBox.information(self, "Case Formulated", "Forensic profiles structured and metrics summary compiled.")
        else:
            self.tabs.setTabEnabled(3, True)
            self.export_button.setEnabled(True)
            QMessageBox.information(self, "Case Registered", "Case profile established. Access Report Output tab to finalize summary templates manually.")

    def _reset_session_state(self):
        """Completely flushes UI session state to isolate sequential case operations."""
        logging.info("[*] Executing global session cleanup. Flushing parameters to baseline zero states safely.")
        self.current_case = None
        self.analyst.clear()
        self.affected_asset.clear()
        self.case_title.clear()
        self.analyst_notes_input.clear()
        self.observations.clear()
        
        for cb in self.telemetry_checks.values():
            cb.setChecked(False)
            
        if hasattr(self.triage_workflow_panel, "answers_log"):
            self.triage_workflow_panel.answers_log.clear()
        if hasattr(self.triage_workflow_panel, "identified_techniques"):
            self.triage_workflow_panel.identified_techniques.clear()
            
        if hasattr(self.triage_workflow_panel, "refresh_board"):
            self.triage_workflow_panel.refresh_board()

    def export_summary(self):
        if not self.current_case:
            logging.error("[-] Blocked disk write call: Attempted export sequence without active case payload.")
            QMessageBox.warning(self, "Export Error", "No active profile data is compiled to generate markdown output.")
            return

        safe_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_dir = self.project_root / "exports"
        export_dir.mkdir(parents=True, exist_ok=True) 
        output_path = export_dir / f"ransomtriage_case_{safe_time}.md"

        try:
            self.report_generator.save_markdown(self.current_case, output_path)
            logging.info(f"[+] Case Report permanently written out to filesystem storage track: {output_path}")
            QMessageBox.information(self, "Export Finalized", f"Markdown system analysis generated locally:\n{output_path}")
            
            self._reset_session_state()
            self.tabs.setTabEnabled(2, False)
            self.tabs.setTabEnabled(3, False)
            self.tabs.setCurrentIndex(0)
        except Exception as e:
            logging.error(f"[-] Critical file I/O error writing document compilation array to disk: {e}")
            QMessageBox.critical(self, "Export Failure", f"Could not write file asset out to target path context: {e}")
