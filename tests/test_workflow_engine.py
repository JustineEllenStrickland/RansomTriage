from pathlib import Path

from src.services.workflow_engine import WorkflowEngine


def test_get_questions_for_suspicious_powershell():
    path = Path("src/config/workflow_questions.json")
    engine = WorkflowEngine(path)

    questions = engine.get_questions("suspicious_powershell")

    assert len(questions) >= 1
    assert questions[0]["id"] == "ps_encoded_command"
