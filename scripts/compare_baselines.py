#!/usr/bin/env python3
"""Compare CYRBER scan baselines for trend tracking.

Reads current and previous baseline JSON files, outputs a markdown delta table,
and appends to GITHUB_STEP_SUMMARY if running in GitHub Actions.
"""

import json
import os
import sys


def compare(current: dict, previous: dict) -> str:
    """Generate markdown comparison table with delta arrows."""
    cur_counts = current.get("severity_counts", {})
    prev_counts = previous.get("severity_counts", {})

    lines = [
        "## CYRBER Trend Comparison\n",
        f"**Current:** {current.get('risk_level', '?')} | "
        f"**Previous:** {previous.get('risk_level', '?')}\n",
        "| Severity | Previous | Current | Delta |",
        "|----------|----------|---------|-------|",
    ]

    total_prev = 0
    total_cur = 0

    for sev in ("critical", "high", "medium", "low", "info"):
        p = prev_counts.get(sev, 0)
        c = cur_counts.get(sev, 0)
        total_prev += p
        total_cur += c
        delta = c - p
        if delta > 0:
            arrow = f"+{delta} ↑"
        elif delta < 0:
            arrow = f"{delta} ↓"
        else:
            arrow = "→"
        lines.append(f"| {sev.capitalize()} | {p} | {c} | {arrow} |")

    delta_total = total_cur - total_prev
    if delta_total > 0:
        arrow = f"+{delta_total} ↑"
    elif delta_total < 0:
        arrow = f"{delta_total} ↓"
    else:
        arrow = "→"
    lines.append(f"| **Total** | **{total_prev}** | **{total_cur}** | **{arrow}** |")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 3:
        print("Usage: compare_baselines.py <current.json> <previous.json>")
        sys.exit(1)

    current_path = sys.argv[1]
    previous_path = sys.argv[2]

    if not os.path.exists(current_path):
        print(f"Current baseline not found: {current_path}")
        sys.exit(1)

    if not os.path.exists(previous_path):
        print("No previous baseline found — skipping comparison")
        sys.exit(0)

    with open(current_path) as f:
        current = json.load(f)
    with open(previous_path) as f:
        previous = json.load(f)

    md = compare(current, previous)
    print(md)

    # Append to GITHUB_STEP_SUMMARY
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            f.write("\n" + md + "\n")


if __name__ == "__main__":
    main()
