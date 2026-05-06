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
from src.services.workflow_engine import WorkflowEngine


class MainWindow(QMainWindow):
    def __init__(self, project_root: Path):
        super().__init__()
        self.project_root = Path(project_root)
        self.current_case = None
        self.questions = []
        self.current_question_index = 0
        self.responses = {}

        self.setWindowTitle("RansomTriage: Guided Ransomware Triage")
        self.resize(950, 760)

        self.workflow_engine = WorkflowEngine(self.project_root / "src/config/workflow_questions.json")
        self.attack_mapper = AttackMapper(self.project_root / "src/config/attack_mappings.json")
        self.evidence_recommender = EvidenceRecommender(self.project_root / "src/config/evidence_sources.json")
        self.report_generator = ReportGenerator(self.project_root / "src/config/export_template.md")
        self.storage_service = StorageService()

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()

        title = QLabel("RansomTriage: Early Ransomware Triage Question Tree")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        layout.addWidget(title)

        subtitle = QLabel(
            "Decision support only. Candidate ATT&CK mappings require analyst validation."
        )
        subtitle.setStyleSheet("font-size: 12px; color: #555;")
        layout.addWidget(subtitle)

        intake_box = QGroupBox("1. Case Intake")
        form = QFormLayout()

        self.case_title = QLineEdit()
        self.case_title.setText("Suspicious PowerShell activity")

        self.analyst = QLineEdit()
        self.analyst.setText("Demo Analyst")

        self.affected_asset = QLineEdit()
        self.affected_asset.setText("Workstation-Example-01")

        self.observation_category = QComboBox()
        self.observation_category.addItem("Suspicious PowerShell Activity", "suspicious_powershell")
        self.observation_category.addItem("Abnormal Authentication Activity", "abnormal_authentication")
        self.observation_category.addItem("Rapid File Modification", "rapid_file_modification")

        self.observations = QTextEdit()
        self.observations.setMaximumHeight(90)
        self.observations.setPlainText(
            "Sanitized demo scenario. Suspicious activity was observed. No real incident data is used."
        )

        form.addRow("Case Title:", self.case_title)
        form.addRow("Analyst:", self.analyst)
        form.addRow("Affected Asset:", self.affected_asset)
        form.addRow("Observation Category:", self.observation_category)
        form.addRow("Observations:", self.observations)

        intake_box.setLayout(form)
        layout.addWidget(intake_box)

        self.create_case_button = QPushButton("Create Case and Start Guided Triage")
        self.create_case_button.clicked.connect(self.create_case_and_start_triage)
        layout.addWidget(self.create_case_button)

        question_box = QGroupBox("2. Guided Question Tree")
        question_layout = QVBoxLayout()

        self.question_label = QLabel("Create a case to begin the guided triage question tree.")
        self.question_label.setWordWrap(True)
        self.question_label.setStyleSheet("font-size: 15px; font-weight: bold;")
        question_layout.addWidget(self.question_label)

        self.yes_button = QPushButton("Yes")
        self.yes_button.clicked.connect(lambda: self.answer_question(True))
        self.yes_button.setEnabled(False)
        question_layout.addWidget(self.yes_button)

        self.no_button = QPushButton("No")
        self.no_button.clicked.connect(lambda: self.answer_question(False))
        self.no_button.setEnabled(False)
        question_layout.addWidget(self.no_button)

        question_box.setLayout(question_layout)
        layout.addWidget(question_box)

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

        self.review_box = QTextEdit()
        self.review_box.setPlaceholderText(
            "Candidate mappings, evidence recommendations, limitations, and summary will appear here."
        )
        layout.addWidget(self.review_box)

        self.export_button = QPushButton("Export Markdown Case Summary")
        self.export_button.clicked.connect(self.export_summary)
        self.export_button.setEnabled(False)
        layout.addWidget(self.export_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def create_case_and_start_triage(self):
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

        self.questions = self.workflow_engine.get_questions(self.current_case.observation_category)
        self.current_question_index = 0
        self.responses = {}

        if not self.questions:
            self.question_label.setText("No questions were found for this observation category.")
            return

        self.yes_button.setEnabled(True)
        self.no_button.setEnabled(True)
        self.export_button.setEnabled(False)

        self.review_box.setPlainText(
            f"Case created successfully.\n\n"
            f"Case Title: {self.current_case.case_title}\n"
            f"Observation Category: {self.current_case.observation_category}\n"
            f"Saved Locally: {runtime_path}\n\n"
            f"Beginning guided triage question tree..."
        )

        self.show_current_question()

    def show_current_question(self):
        question = self.questions[self.current_question_index]
        self.question_label.setText(
            f"Question {self.current_question_index + 1} of {len(self.questions)}:\n"
            f"{question['text']}"
        )

    def answer_question(self, answer: bool):
        question = self.questions[self.current_question_index]
        self.responses[question["id"]] = answer

        self.current_question_index += 1

        if self.current_question_index < len(self.questions):
            self.show_current_question()
        else:
            self.finish_triage()

    def finish_triage(self):
        self.yes_button.setEnabled(False)
        self.no_button.setEnabled(False)

        self.current_case.triage_responses = self.responses

        mappings = self.attack_mapper.map_responses(
            self.current_case.observation_category,
            self.responses,
        )

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

        if mappings:
            self.question_label.setText("Guided triage complete. Candidate findings generated.")
        else:
            self.question_label.setText(
                "Guided triage complete. No candidate mapping met the current rule threshold."
            )

        summary = self.report_generator.generate_markdown(self.current_case)
        self.review_box.setPlainText(summary)
        self.export_button.setEnabled(True)

    def export_summary(self):
        if not self.current_case:
            QMessageBox.warning(self, "No case", "Create and triage a case before exporting.")
            return

        safe_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = self.project_root / "exports" / f"ransomtriage_case_{safe_time}.md"

        self.report_generator.save_markdown(self.current_case, output_path)

        QMessageBox.information(
            self,
            "Export complete",
            f"Markdown case summary exported to:\n{output_path}",
        )
