from PyQt6.QtWidgets import QWidget, QVBoxLayout, QFormLayout, QLineEdit, QTextEdit, QLabel, QPushButton, QHBoxLayout
from PyQt6.QtCore import Qt

class CaseIntakeView(QWidget):
    def __init__(self, parent_main_window=None):
        super().__init__()
        self.main_window = parent_main_window

        # Form Interactive Fields
        self.case_title = QLineEdit()
        self.case_title.setPlaceholderText("e.g., Incident-2026-05A: Win_Ransomware")
        
        self.analyst = QLineEdit()
        self.analyst.setPlaceholderText("Analyst Name / ID")
        
        self.affected_asset = QLineEdit()
        self.affected_asset.setPlaceholderText("e.g., DC-01, VCENTER-CLUSTER, USER-LAPTOP-5")
        
        self.observations = QTextEdit()
        self.observations.setPlaceholderText("Triage matrix logs will automatically populate here, or you can manually enter evidence notes...")

        # UI Styling Constraints
        self.case_title.setMinimumHeight(35)
        self.analyst.setMinimumHeight(35)
        self.affected_asset.setMinimumHeight(35)
        self.observations.setMinimumHeight(200)

        # Form Layout Setup
        form = QFormLayout()
        form.setSpacing(15)
        form.addRow("Case Title:", self.case_title)
        form.addRow("Analyst Name:", self.analyst)
        form.addRow("Affected Asset(s):", self.affected_asset)
        form.addRow("Observations & Telemetry Log:", self.observations)

        # Navigation & Submission Layout
        nav_layout = QHBoxLayout()
        
        self.clear_btn = QPushButton("RESET FORM")
        self.clear_btn.setMinimumHeight(40)
        self.clear_btn.setMinimumWidth(120)
        self.clear_btn.setStyleSheet("""
            QPushButton { background-color: #1A1A24; color: #888899; font-weight: bold; border: 1px solid #2D2D3F; border-radius: 4px; }
            QPushButton:hover { background-color: #252535; color: #FFFFFF; }
        """)
        self.clear_btn.clicked.connect(self.clear_form)
        
        self.export_btn = QPushButton("GENERATE FINAL INCIDENT REPORT ➔")
        self.export_btn.setMinimumHeight(40)
        self.export_btn.setMinimumWidth(280)
        self.export_btn.setStyleSheet("""
            QPushButton { background-color: #00DFFF; color: #000000; font-weight: bold; border-radius: 4px; }
            QPushButton:hover { background-color: #00B3CC; }
        """)
        self.export_btn.clicked.connect(self.proceed_to_report)

        nav_layout.addWidget(self.clear_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.export_btn)

        # Main Layout Assembly
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        header_lbl = QLabel("Step 2: Case Intake Profile")
        header_lbl.setStyleSheet("font-size: 18px; font-weight: bold; color: #FFFFFF;")
        
        layout.addWidget(header_lbl)
        layout.addLayout(form)
        layout.addStretch()
        layout.addLayout(nav_layout)

    def populate_triage_data(self, notes: str, platforms: list):
        """Receives incoming data payload from the Wizard Engine seamlessly."""
        # Update the observations text box with the generated telemetry log
        self.observations.setPlainText(notes)
        
        # Smart formatting for default case title generation
        platform_string = ", ".join([p.upper() for p in platforms]) if platforms else "UNKNOWN"
        self.case_title.setText(f"RansomTriage Case Profile [{platform_string}]")

    def clear_form(self):
        """Flushes active field configurations safely."""
        self.case_title.clear()
        self.analyst.clear()
        self.affected_asset.clear()
        self.observations.clear()

    def proceed_to_report(self):
        """Passes gathered data records directly over to the final reporting tab view."""
        if self.main_window:
            # We will ensure the main window has a hook to enable/switch to the report view tab
            if hasattr(self.main_window, "enable_report_generation"):
                # Constructing a clean data payload dictionary
                case_payload = {
                    "title": self.case_title.text().strip(),
                    "analyst": self.analyst.text().strip(),
                    "asset": self.affected_asset.text().strip(),
                    "observations": self.observations.toPlainText().strip()
                }
                self.main_window.enable_report_generation(case_payload)
                self.main_window.tabs.setCurrentIndex(3) # Switches to Report Tab
