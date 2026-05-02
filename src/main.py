import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.app import run_app


if __name__ == "__main__":
    raise SystemExit(run_app())
