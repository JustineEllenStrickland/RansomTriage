from pathlib import Path
from src.models.case import Case
from src.services.storage_service import StorageService

def test_storage_service_saves_and_loads_case(tmp_path):
    service = StorageService()
    # Ensure this matches your actual project Case model constructor constraints
    case = Case(
        case_title="Storage Test",
        analyst="Analyst",
        observation_category="suspicious_powershell"
    )

    path = tmp_path / "case.json"
    service.save_case(case, path)
    loaded = service.load_case(path)

    assert loaded is not None
    assert loaded.case_title == "Storage Test"
    assert loaded.observation_category == "suspicious_powershell"
