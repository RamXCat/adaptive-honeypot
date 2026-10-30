"""
logger.py
Appends one structured JSONL record per generation attempt to attempt_log.jsonl.
"""

import json
from datetime import datetime, timezone
from .config import LOG_FILE
from .schemas import GenerationAttempt


def log_attempt(
    session_id: str,
    category: str,
    attempt: GenerationAttempt,
) -> None:
    record = {
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "session_id":     session_id,
        "category":       category,
        "attempt_number": attempt.attempt_number,
        "temperature":    attempt.temperature,
        "latency_ms":     attempt.latency_ms,
        "passed":         attempt.passed,
        "issues":         [
            {"criterion": i.criterion, "description": i.description}
            for i in attempt.issues
        ],
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
