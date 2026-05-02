from PyQt6.QtWidgets import QFormLayout, QLineEdit, QTextEdit, QVBoxLayout, QWidget, QLabel


class CaseIntakeView(QWidget):
    def __init__(self):
        super().__init__()

        self.case_title = QLineEdit()
        self.analyst = QLineEdit()
        self.affected_asset = QLineEdit()
        self.observations = QTextEdit()

        form = QFormLayout()
        form.addRow("Case Title:", self.case_title)
        form.addRow("Analyst:", self.analyst)
        form.addRow("Affected Asset:", self.affected_asset)
        form.addRow("Observations:", self.observations)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Create a new triage case."))
        layout.addLayout(form)

        self.setLayout(layout)
