"""
analyze_log.py
Reads attempt_log.jsonl and computes statistics for presentation.
"""

import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from fcgd_ah.config import LOG_FILE


def load_log():
    if not os.path.exists(LOG_FILE):
        print(f"[!] Log file not found: {LOG_FILE}")
        print("    Run batch_run.py first.")
        sys.exit(1)
    records = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def analyze(records):
    # Group by session_id to determine final result per session
    sessions = defaultdict(list)
    for r in records:
        sessions[r["session_id"]].append(r)

    total_sessions = len(sessions)
    succeeded = 0
    retries_to_success = []
    try1 = try2 = try3 = failed = 0
    latencies = [r["latency_ms"] for r in records]

    for sid, attempts in sessions.items():
        attempts.sort(key=lambda x: x["attempt_number"])
        passed_attempt = next((a for a in attempts if a["passed"]), None)
        if passed_attempt:
            succeeded += 1
            n = passed_attempt["attempt_number"]
            retries_to_success.append(n)
            if n == 1: try1 += 1
            elif n == 2: try2 += 1
            elif n == 3: try3 += 1
        else:
            failed += 1

    success_rate = (succeeded / total_sessions * 100) if total_sessions else 0
    avg_retries  = (sum(retries_to_success) / len(retries_to_success)) if retries_to_success else 0

    return {
        "total_sessions": total_sessions,
        "succeeded": succeeded,
        "failed": failed,
        "success_rate": success_rate,
        "avg_retries_to_success": avg_retries,
        "try1": try1, "try2": try2, "try3": try3,
        "latency_min":  min(latencies) if latencies else 0,
        "latency_max":  max(latencies) if latencies else 0,
        "latency_mean": sum(latencies) / len(latencies) if latencies else 0,
        "total_attempts": len(records),
    }


def bar(value, total, width=30):
    filled = int((value / total) * width) if total else 0
    return "█" * filled + "░" * (width - filled)


if __name__ == "__main__":
    records = load_log()
    s = analyze(records)

    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║        FCGD-AH — Attempt Log Analysis                   ║")
    print("╚══════════════════════════════════════════════════════════╝\n")

    print(f"  Total sessions    : {s['total_sessions']}")
    print(f"  Total attempts    : {s['total_attempts']}")
    print(f"  Succeeded         : {s['succeeded']}")
    print(f"  Failed (all 3)    : {s['failed']}")
    print(f"  Success rate      : {s['success_rate']:.1f}%")
    print(f"  Avg retries/success: {s['avg_retries_to_success']:.2f}")

    print(f"\n  ── Try Breakdown ─────────────────────────────────────────")
    t = s['succeeded'] or 1
    print(f"  Passed on Try-1   : {s['try1']:3d}  {bar(s['try1'], t)}  ({s['try1']/t*100:.1f}%)")
    print(f"  Passed on Try-2   : {s['try2']:3d}  {bar(s['try2'], t)}  ({s['try2']/t*100:.1f}%)")
    print(f"  Passed on Try-3   : {s['try3']:3d}  {bar(s['try3'], t)}  ({s['try3']/t*100:.1f}%)")
    print(f"  All 3 failed      : {s['failed']:3d}  {bar(s['failed'], t)}")

    print(f"\n  ── Latency Stats (per attempt) ───────────────────────────")
    print(f"  Min               : {s['latency_min']:.3f} ms")
    print(f"  Max               : {s['latency_max']:.3f} ms")
    print(f"  Mean              : {s['latency_mean']:.3f} ms")
    print()
