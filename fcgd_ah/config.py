import os

# ── Retry configuration ──────────────────────────────────────────────────────
MAX_ATTEMPTS: int = 3

# "Temperature" here is purely a variant selector (0.9=creative, 0.3=conservative)
TEMPERATURE_SCHEDULE: list[float] = [0.9, 0.6, 0.3]

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_FILE: str = os.path.join(os.path.dirname(__file__), "attempt_log.jsonl")
