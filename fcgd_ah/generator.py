"""
generator.py
Picks and fills the correct template for the requested ArtifactCategory,
using session context and branching on prior validation issues on retries.
"""

from typing import Optional, Tuple
from .taxonomy import ArtifactCategory
from .schemas import SessionState, ValidationIssue
from . import templates as T


def generate(
    session: SessionState,
    category: ArtifactCategory,
    temperature: float,
    prior_issues: Optional[list[ValidationIssue]] = None,
) -> Tuple[str, str]:
    """
    Returns (artifact_content, suggested_path).
    Branches template/variant choice based on prior_issues feedback.
    """
    prior_criteria = [i.criterion for i in (prior_issues or [])]
    env = session.env_facts
    hostname = env.hostname
    org = env.org_name
    existing_users = env.existing_users or ["deploy"]

    if category == ArtifactCategory.AWS_CREDENTIALS:
        return T.build_aws_credentials(hostname, org, temperature)

    elif category == ArtifactCategory.SSH_PRIVATE_KEY:
        return T.build_ssh_private_key(hostname, org, temperature)

    elif category == ArtifactCategory.APP_CONFIG_FILE:
        return T.build_app_config_file(
            hostname, org, temperature,
            prior_issue_criteria=prior_criteria
        )

    elif category == ArtifactCategory.DATABASE_CREDENTIALS:
        return T.build_database_credentials(hostname, org, temperature)

    elif category == ArtifactCategory.DECOY_DIRECTORY:
        return T.build_decoy_directory(
            hostname, org, temperature,
            existing_users=existing_users,
            prior_issue_criteria=prior_criteria
        )

    elif category == ArtifactCategory.VULNERABLE_SERVICE_BANNER:
        return T.build_vulnerable_service_banner(hostname, org, temperature)

    elif category == ArtifactCategory.MALWARE_C2_INFRASTRUCTURE:
        return T.build_malware_c2_infrastructure(hostname, org, temperature)

    else:
        raise ValueError(f"Unknown category: {category}")
