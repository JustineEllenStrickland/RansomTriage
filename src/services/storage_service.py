import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Optional, Any
from src.models.case import Case


class StorageService:
    @staticmethod
    def _json_fallback_encoder(obj: Any) -> Any:
        """
        Fallback encoder to automatically serialize complex nested custom objects
        encountered by json.dump without risking unhandled recursive lock loops.
        """
        # If the sub-object contains a structured mapping parser, utilize it directly
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        
        # Guard against nested dataclass/object serialization deadlocks
        if hasattr(obj, "__dict__"):
            try:
                # Isolate values safely, checking if components are primitive
                return {k: str(v) if hasattr(v, "__dict__") else v for k, v in obj.__dict__.items()}
            except Exception:
                return str(obj)
                
        # Fallback to standard string casting so serialization never crashes mid-flight
        return str(obj)

    def save_case(self, case: Case, path: str | Path) -> Path:
        """
        Saves a serialized triage case structure atomically using a safe write-swap approach.
        Explicitly closes file handles before substitution to ensure cross-platform safety.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        dir_name = path.parent

        temp_path = None
        try:
            # Step 1: Open and write structural components safely to the temporary file
            with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
                temp_path = Path(tf.name)
                
                # Extract structural dictionary context cleanly
                case_payload = case.to_dict() if hasattr(case, "to_dict") else case.__dict__
                
                json.dump(
                    case_payload, 
                    tf, 
                    indent=2, 
                    default=self._json_fallback_encoder
                )
            
            # Step 2: Context manager has closed the handle. Securely swap files now.
            if temp_path and temp_path.exists():
                temp_path.replace(path)

        except Exception as e:
            logging.error(f"[-] Atomic save failure for case path '{path}': {e}")
            if temp_path and temp_path.exists():
                try:
                    os.unlink(temp_path)
                except OSError as unlink_err:
                    logging.warning(f"[!] Abandoned orphan temp file at '{temp_path}': {unlink_err}")
            raise e

        return path

    def load_case(self, path: str | Path) -> Optional[Case]:
        """
        Loads and parses a case from storage. Returns None if data is unreadable or malformed.
        """
        path = Path(path)
        if not path.exists():
            logging.error(f"[-] Attempted to load non-existent case data path: {path}")
            return None

        try:
            with path.open("r", encoding="utf-8") as file:
                data = json.load(file)
                
            if hasattr(Case, "from_dict"):
                return Case.from_dict(data)
            return Case(**data) # Flat fallback hydration initialization mapping 

        except (json.JSONDecodeError, TypeError) as parse_err:
            logging.critical(f"[-] Integrity breach: Corrupted triage JSON file at '{path}': {parse_err}")
            return None
        except Exception as general_err:
            logging.error(f"[-] Unhandled exception accessing data file path '{path}': {general_err}")
            return None
