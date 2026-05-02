from pathlib import Path

from PyQt6.QtWidgets import QLabel, QPushButton, QTextEdit, QVBoxLayout, QWidget


class ReviewExportView(QWidget):
    def __init__(self, project_root: Path):
        super().__init__()
        self.project_root = project_root

        self.review_box = QTextEdit()
        self.review_box.setPlainText(
            "Candidate mappings, evidence recommendations, limitations, and analyst notes will appear here."
        )

        self.export_button = QPushButton("Export Markdown Case Summary")

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Review candidate findings before export."))
        layout.addWidget(self.review_box)
        layout.addWidget(self.export_button)

        self.setLayout(layout)
