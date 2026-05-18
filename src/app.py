import sys
import logging
from pathlib import Path
from PyQt6.QtWidgets import QApplication, QMessageBox
from src.ui.main_window import MainWindow

# Configure a fallback logging channel for unexpected interface failures
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

def handle_exception(exc_type, exc_value, exc_traceback):
    """Global crash handling framework to catch and report unexpected GUI failures."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    logging.error("Unhandled exception encountered during triage execution:", exc_info=(exc_type, exc_value, exc_traceback))
    
    # Visual warning fallback to prevent the application from freezing silently
    if QApplication.instance():
        QMessageBox.critical(
            None,
            "Critical Triage System Error",
            f"An unhandled internal fault occurred:\n\n{exc_value}\n\nCheck logs for execution traces."
        )

def run_app() -> int:
    """Initializes back-end dependencies and opens the desktop graphical loop."""
    sys.excepthook = handle_exception
    
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    logging.info("[*] Launching RansomTriage Application Systems...")
    
    app = QApplication(sys.argv)
    
    # Instantiate layout window and inject the unified project root directory
    window = MainWindow(PROJECT_ROOT)
    window.show()

    return app.exec()
