from pathlib import Path

from PyQt6.QtWidgets import QLabel, QListWidget, QVBoxLayout, QWidget

from src.services.workflow_engine import WorkflowEngine


class TriageWorkflowView(QWidget):
    def __init__(self, project_root: Path):
        super().__init__()
        config_path = project_root / "src" / "config" / "workflow_questions.json"
        self.engine = WorkflowEngine(config_path)

        self.category_list = QListWidget()
        for category in self.engine.get_categories():
            self.category_list.addItem(f"{category['id']} - {category['label']}")

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Select an observation category. Branching questions will be implemented here."))
        layout.addWidget(self.category_list)

        self.setLayout(layout)
