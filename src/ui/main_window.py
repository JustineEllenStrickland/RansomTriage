from pathlib import Path
from datetime import datetime

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from src.models.case import Case
from src.services.attack_mapper import AttackMapper
from src.services.evidence_recommender import EvidenceRecommender
from src.services.report_generator import ReportGenerator
from src.services.storage_service import StorageService


class MainWindow(QMainWindow):
    def __init__(self, project_root: Path):
        super().__init__()
        self.project_root = Path(project_root)
        self.current_case = None

        self.setWindowTitle("RansomTriage")
        self.resize(950, 750)

        self.attack_mapper = AttackMapper(self.project_root / "src/config/attack_mappings.json")
        self.evidence_recommender = EvidenceRecommender(self.project_root / "src/config/evidence_sources.json")
        self.report_generator = ReportGenerator(self.project_root / "src/config/export_template.md")
        self.storage_service = StorageService()

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()

        title = QLabel("RansomTriage: Early Ransomware Triage Prototype")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        layout.addWidget(title)

        subtitle = QLabel(
            "Decision support only. Candidate ATT&CK mappings require analyst validation."
        )
        subtitle.setStyleSheet("font-size: 12px; color: #555;")
        layout.addWidget(subtitle)

        # Case intake
        intake_box = QGroupBox("1. Case Intake")
        form = QFormLayout()

        self.case_title = QLineEdit()
        self.case_title.setText("Suspicious PowerShell and rapid file modification")

        self.analyst = QLineEdit()
        self.analyst.setText("Demo Analyst")

        self.affected_asset = QLineEdit()
        self.affected_asset.setText("Workstation-Example-01")

        self.observation_category = QComboBox()
        self.observation_category.addItem("Suspicious PowerShell Activity", "suspicious_powershell")
        self.observation_category.addItem("Abnormal Authentication Activity", "abnormal_authentication")
        self.observation_category.addItem("Rapid File Modification", "rapid_file_modification")

        self.observations = QTextEdit()
        self.observations.setPlainText(
            "Sanitized demo scenario. Suspicious PowerShell activity and rapid file modification were observed. "
            "No real incident data is used."
        )

        form.addRow("Case Title:", self.case_title)
        form.addRow("Analyst:", self.analyst)
        form.addRow("Affected Asset:", self.affected_asset)
        form.addRow("Observation Category:", self.observation_category)
        form.addRow("Observations:", self.observations)

        intake_box.setLayout(form)
        layout.addWidget(intake_box)

        self.create_case_button = QPushButton("Create Case")
        self.create_case_button.clicked.connect(self.create_case)
        layout.addWidget(self.create_case_button)

        # Triage questions
        triage_box = QGroupBox("2. Guided Triage Questions")
        triage_layout = QVBoxLayout()

        self.ps_encoded_command = QCheckBox("Encoded or obfuscated PowerShell observed")
        self.ps_download_behavior = QCheckBox("PowerShell used to download or execute remote content")
        self.ps_unusual_parent = QCheckBox("PowerShell launched by unusual parent process")
        self.file_many_changes = QCheckBox("Many files modified in a short time period")
        self.file_extension_pattern = QCheckBox("Unusual extensions or renamed files observed")

        self.ps_encoded_command.setChecked(True)
        self.file_many_changes.setChecked(True)

        for checkbox in [
            self.ps_encoded_command,
            self.ps_download_behavior,
            self.ps_unusual_parent,
            self.file_many_changes,
            self.file_extension_pattern,
        ]:
            triage_layout.addWidget(checkbox)

        triage_box.setLayout(triage_layout)
        layout.addWidget(triage_box)

        # Available telemetry
        telemetry_box = QGroupBox("3. Available Telemetry")
        telemetry_layout = QVBoxLayout()

        self.telemetry_checks = {
            "windows_event_logs": QCheckBox("Windows Event Logs"),
            "sysmon": QCheckBox("Sysmon Logs"),
            "edr": QCheckBox("Endpoint Detection and Response"),
            "identity_logs": QCheckBox("Identity Logs"),
            "entra_id_logs": QCheckBox("Entra ID Sign In Logs"),
            "dns_logs": QCheckBox("DNS Logs"),
            "firewall_logs": QCheckBox("Firewall Logs"),
            "file_server_logs": QCheckBox("File Server Logs"),
        }

        self.telemetry_checks["windows_event_logs"].setChecked(True)
        self.telemetry_checks["sysmon"].setChecked(True)

        for checkbox in self.telemetry_checks.values():
            telemetry_layout.addWidget(checkbox)

        telemetry_box.setLayout(telemetry_layout)
        layout.addWidget(telemetry_box)

        self.run_triage_button = QPushButton("Run Guided Triage")
        self.run_triage_button.clicked.connect(self.run_triage)
        layout.addWidget(self.run_triage_button)

        # Review/export
        self.review_box = QTextEdit()
        self.review_box.setPlaceholderText("Candidate mappings, evidence recommendations, and summary will appear here.")
        layout.addWidget(self.review_box)

        self.export_button = QPushButton("Export Markdown Case Summary")
        self.export_button.clicked.connect(self.export_summary)
        layout.addWidget(self.export_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def create_case(self):
        self.current_case = Case(
            case_title=self.case_title.text(),
            analyst=self.analyst.text(),
            observation_category=self.observation_category.currentData(),
            affected_asset=self.affected_asset.text(),
            observations=self.observations.toPlainText(),
            analyst_notes="Demo case created for Unit 4 system demonstration.",
        )

        runtime_path = self.project_root / "runtime/demo_case.json"
        self.storage_service.save_case(self.current_case, runtime_path)

        self.review_box.setPlainText(
            f"Case created successfully.\n\n"
            f"Case Title: {self.current_case.case_title}\n"
            f"Analyst: {self.current_case.analyst}\n"
            f"Affected Asset: {self.current_case.affected_asset}\n"
            f"Observation Category: {self.current_case.observation_category}\n"
            f"Saved Locally: {runtime_path}\n"
        )

    def run_triage(self):
        if not self.current_case:
            self.create_case()

        responses = {
            "ps_encoded_command": self.ps_encoded_command.isChecked(),
            "ps_download_behavior": self.ps_download_behavior.isChecked(),
            "ps_unusual_parent": self.ps_unusual_parent.isChecked(),
            "file_many_changes": self.file_many_changes.isChecked(),
            "file_extension_pattern": self.file_extension_pattern.isChecked(),
        }

        self.current_case.triage_responses = responses

        mappings = self.attack_mapper.map_responses(
            self.current_case.observation_category,
            responses,
        )

        # Add rapid file modification mapping when file indicators are selected.
        if responses["file_many_changes"] or responses["file_extension_pattern"]:
            file_mappings = self.attack_mapper.map_responses(
                "rapid_file_modification",
                responses,
            )
            mappings.extend(file_mappings)

        self.current_case.candidate_mappings = mappings

        available_telemetry = [
            key for key, checkbox in self.telemetry_checks.items()
            if checkbox.isChecked()
        ]

        recommendations, unavailable = self.evidence_recommender.recommend(
            candidate_mappings=mappings,
            available_telemetry=available_telemetry,
        )

        self.current_case.evidence_recommendations = recommendations
        self.current_case.unavailable_telemetry = unavailable
        self.current_case.limitations = [
            "Candidate mappings require analyst validation.",
            "This demonstration uses sanitized data.",
            "No live enterprise telemetry was used.",
        ]

        summary = self.report_generator.generate_markdown(self.current_case)
        self.review_box.setPlainText(summary)

    def export_summary(self):
        if not self.current_case:
            QMessageBox.warning(self, "No case", "Create and triage a case before exporting.")
            return

        if not self.current_case.candidate_mappings:
            self.run_triage()

        safe_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = self.project_root / "exports" / f"ransomtriage_case_{safe_time}.md"
        self.report_generator.save_markdown(self.current_case, output_path)

        QMessageBox.information(self, "Export complete", f"Summary exported to:\n{output_path}")
