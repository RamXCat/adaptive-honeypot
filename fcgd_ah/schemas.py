from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class EnvironmentFacts:
    hostname: str
    org_name: str
    existing_users: List[str] = field(default_factory=list)
    previously_generated_artifacts: List[str] = field(default_factory=list)


@dataclass
class MalwareInterestProfile:
    file_type_interests: List[str] = field(default_factory=list)       # e.g. [".env", ".json", ".pem"]
    credential_patterns: List[str] = field(default_factory=list)       # e.g. ["AWS", "password", "token"]
    network_destinations: List[str] = field(default_factory=list)      # e.g. ["api.internal.local"]


@dataclass
class SessionState:
    session_id: str
    commands_run: List[str] = field(default_factory=list)
    files_touched: List[str] = field(default_factory=list)
    duration_s: float = 0.0
    env_facts: EnvironmentFacts = field(default_factory=lambda: EnvironmentFacts(
        hostname="server", org_name="org"
    ))
    malware_profile: MalwareInterestProfile = field(
        default_factory=MalwareInterestProfile
    )


@dataclass
class ValidationIssue:
    criterion: str          # e.g. "referential_consistency"
    description: str        # Human-readable explanation of the failure


@dataclass
class GenerationAttempt:
    attempt_number: int
    temperature: float
    artifact_content: Optional[str]
    suggested_path: Optional[str]
    passed: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    latency_ms: float = 0.0


@dataclass
class ModuleResult:
    deployed: bool
    artifact_content: Optional[str]
    suggested_path: Optional[str]
    attempts_consumed: int
    all_issues: List[ValidationIssue] = field(default_factory=list)
