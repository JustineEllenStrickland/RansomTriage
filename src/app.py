from pathlib import Path
import sys

from PyQt6.QtWidgets import QApplication

from src.ui.main_window import MainWindow


def run_app() -> int:
    app = QApplication(sys.argv)
    window = MainWindow(project_root=Path(__file__).resolve().parent.parent)
    window.show()
    return app.exec()
