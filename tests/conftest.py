"""Pytest configuration and environment fixtures."""

import sys
from pathlib import Path

# Add project root and cloud/lambda directory to sys.path so lambda handlers
# and shared modules can be imported directly, avoiding Python's reserved 'lambda' keyword.
ROOT_DIR = Path(__file__).resolve().parent.parent
LAMBDA_DIR = ROOT_DIR / "cloud" / "lambda"

for path in (str(ROOT_DIR), str(LAMBDA_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)
