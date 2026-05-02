from pathlib import Path

from PyQt6.QtWidgets import QLabel, QMainWindow, QTabWidget, QWidget, QVBoxLayout

from src.ui.case_intake_view import CaseIntakeView
from src.ui.triage_workflow_view import TriageWorkflowView
from src.ui.review_export_view import ReviewExportView


class MainWindow(QMainWindow):
    def __init__(self, project_root: Path):
        super().__init__()
        self.project_root = project_root
        self.setWindowTitle("RansomTriage")
        self.resize(1000, 700)

        self.tabs = QTabWidget()
        self.tabs.addTab(CaseIntakeView(), "Case Intake")
        self.tabs.addTab(TriageWorkflowView(project_root), "Triage Workflow")
        self.tabs.addTab(ReviewExportView(project_root), "Review and Export")

        wrapper = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("RansomTriage: Early Ransomware Triage Decision Support"))
        layout.addWidget(self.tabs)
        wrapper.setLayout(layout)

        self.setCentralWidget(wrapper)
