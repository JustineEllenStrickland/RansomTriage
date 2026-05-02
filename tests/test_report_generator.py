from pathlib import Path

from src.models.case import Case
from src.services.report_generator import ReportGenerator


def test_report_generator_creates_markdown_summary():
    generator = ReportGenerator(Path("src/config/export_template.md"))
    case = Case(
        case_title="Test Case",
        analyst="Analyst",
        observation_category="suspicious_powershell",
        observations="Encoded PowerShell observed."
    )

    output = generator.generate_markdown(case)

    assert "Test Case" in output
    assert "Encoded PowerShell observed." in output
    assert "decision support only" in output
