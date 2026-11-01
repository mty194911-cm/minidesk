from pathlib import Path
import shutil
import subprocess

import pytest


def test_browser_state_machines():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the browser state-machine tests")
    root = Path(__file__).parents[2]
    result = subprocess.run([node, "--test", str(root / "tests" / "client_core.test.cjs")],
                            capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
