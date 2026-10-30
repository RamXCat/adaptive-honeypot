"""
retry_loop.py
Orchestrates bounded generation → validation → retry loop.
"""

import time
from typing import Optional

from .taxonomy import ArtifactCategory
from .schemas import SessionState, ValidationIssue, GenerationAttempt, ModuleResult
from .config import MAX_ATTEMPTS, TEMPERATURE_SCHEDULE
from . import generator, validator, logger


def run(
    session: SessionState,
    category: ArtifactCategory,
) -> ModuleResult:
    """
    Runs the bounded retry loop.
    Returns a ModuleResult (deployed=True) on first passing attempt,
    or (deployed=False, artifact_content=None) if all attempts fail.
    """
    all_issues: list[ValidationIssue] = []
    attempts: list[GenerationAttempt] = []
    prior_issues: Optional[list[ValidationIssue]] = None

    for attempt_num in range(1, MAX_ATTEMPTS + 1):
        temperature = TEMPERATURE_SCHEDULE[attempt_num - 1]

        t_start = time.perf_counter()
        content, path = generator.generate(
            session=session,
            category=category,
            temperature=temperature,
            prior_issues=prior_issues,
        )
        issues = validator.validate(
            content=content,
            suggested_path=path,
            session=session,
            category_name=category.value,
        )
        latency_ms = (time.perf_counter() - t_start) * 1000

        passed = len(issues) == 0

        attempt = GenerationAttempt(
            attempt_number=attempt_num,
            temperature=temperature,
            artifact_content=content,
            suggested_path=path,
            passed=passed,
            issues=issues,
            latency_ms=round(latency_ms, 3),
        )
        attempts.append(attempt)
        logger.log_attempt(session.session_id, category.value, attempt)

        if passed:
            return ModuleResult(
                deployed=True,
                artifact_content=content,
                suggested_path=path,
                attempts_consumed=attempt_num,
                all_issues=[],
            )

        # Accumulate issues for next attempt's corrective feedback
        all_issues.extend(issues)
        prior_issues = issues

    # All attempts failed
    return ModuleResult(
        deployed=False,
        artifact_content=None,
        suggested_path=None,
        attempts_consumed=MAX_ATTEMPTS,
        all_issues=all_issues,
    )
