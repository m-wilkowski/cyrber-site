"""Tests for Celery task configuration — timeouts and soft time limits.

Uses AST parsing to read decorator arguments, bypassing mock pollution
from other tests that mock modules.tasks at sys.modules level.
"""

import ast
import os
import pytest

TASKS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "modules", "tasks.py")
MENS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "modules", "mens_task.py")


def _parse_task_timeouts(filepath: str) -> dict[str, dict]:
    """Parse a Python file and extract soft_time_limit/time_limit from @celery_app.task decorators."""
    with open(filepath) as f:
        tree = ast.parse(f.read())

    tasks = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for deco in node.decorator_list:
            # Match @celery_app.task(...) calls
            if not isinstance(deco, ast.Call):
                continue
            func = deco.func if hasattr(deco, "func") else None
            if func is None:
                continue
            # Check it's celery_app.task
            if not (isinstance(func, ast.Attribute) and func.attr == "task"):
                continue

            soft = None
            hard = None
            for kw in deco.keywords:
                if kw.arg == "soft_time_limit" and isinstance(kw.value, ast.Constant):
                    soft = kw.value.value
                elif kw.arg == "time_limit" and isinstance(kw.value, ast.Constant):
                    hard = kw.value.value
            tasks[node.name] = {"soft_time_limit": soft, "time_limit": hard}
    return tasks


# Parse both files at module load time
_TASKS_TIMEOUTS = _parse_task_timeouts(TASKS_PATH)
_TASKS_TIMEOUTS.update(_parse_task_timeouts(MENS_PATH))

# Expected timeouts
EXPECTED = {
    "full_scan_task": (7200, 7260),
    "osint_scan_task": (3600, 3660),
    "agent_scan_task": (3600, 3660),
    "run_due_schedules": (300, 360),
    "run_intel_sync": (1800, 1860),
    "run_attack_sync": (1800, 1860),
    "run_euvd_sync": (1800, 1860),
    "run_misp_sync": (1800, 1860),
    "run_urlhaus_sync": (1800, 1860),
    "run_exploitdb_sync": (1800, 1860),
    "run_malwarebazaar_sync": (1800, 1860),
    "retest_finding": (600, 660),
    "mens_run_task": (28800, 28860),
}


class TestCeleryTimeouts:
    """Every Celery task must have soft_time_limit and time_limit set."""

    @pytest.mark.parametrize("task_name", list(EXPECTED.keys()))
    def test_soft_time_limit_set(self, task_name):
        info = _TASKS_TIMEOUTS.get(task_name)
        assert info is not None, f"Task {task_name} not found in source"
        expected_soft = EXPECTED[task_name][0]
        assert info["soft_time_limit"] == expected_soft, (
            f"{task_name} soft_time_limit={info['soft_time_limit']}, expected {expected_soft}"
        )

    @pytest.mark.parametrize("task_name", list(EXPECTED.keys()))
    def test_hard_time_limit_set(self, task_name):
        info = _TASKS_TIMEOUTS.get(task_name)
        assert info is not None, f"Task {task_name} not found in source"
        expected_hard = EXPECTED[task_name][1]
        assert info["time_limit"] == expected_hard, (
            f"{task_name} time_limit={info['time_limit']}, expected {expected_hard}"
        )

    def test_no_task_without_timeout(self):
        """Verify all known tasks have a soft_time_limit (not None)."""
        missing = [
            name for name, info in _TASKS_TIMEOUTS.items()
            if info["soft_time_limit"] is None and name in EXPECTED
        ]
        assert missing == [], f"Tasks without soft_time_limit: {missing}"
