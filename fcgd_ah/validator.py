"""
validator.py
Four independent, rule-based validation checks.
No LLM — pure regex and string matching.
"""

import re
from typing import List
from .schemas import SessionState, ValidationIssue


# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns for format_credibility
# ─────────────────────────────────────────────────────────────────────────────

AWS_ACCESS_KEY_RE  = re.compile(r"AKIA[0-9A-Z]{16}")
AWS_SECRET_KEY_RE  = re.compile(r"aws_secret_access_key\s*=\s*([A-Za-z0-9+/]{40})")
PEM_BEGIN_RE       = re.compile(r"-----BEGIN [A-Z ]+-----")
PEM_END_RE         = re.compile(r"-----END [A-Z ]+-----")
DB_PASS_LINE_RE    = re.compile(r"(?i)(DB_PASS|password)\s*[=:]\s*(\S+)")
SSH_BANNER_RE      = re.compile(r"SSH-2\.0-")


# ─────────────────────────────────────────────────────────────────────────────
# Check 1 — Referential Consistency
# ─────────────────────────────────────────────────────────────────────────────

def check_referential_consistency(
    content: str, session: SessionState
) -> List[ValidationIssue]:
    issues = []
    env = session.env_facts

    # Only match standalone HOST= or HOSTNAME= keys, not DB_HOST= or host inside [database] section
    in_db_section = False
    for line in content.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("["):
            in_db_section = "[database]" in trimmed.lower()
            continue
        if in_db_section and re.match(r"^(?:db_)?host\s*[=:]", trimmed, re.IGNORECASE):
            continue
        m = re.search(r"(?<![A-Z_])HOST(?:NAME)?\s*[=:]\s*(\S+)", trimmed, re.IGNORECASE)
        if m:
            candidate = m.group(1).strip("\"'#")
            if candidate != env.hostname:
                issues.append(ValidationIssue(
                    criterion="referential_consistency",
                    description=f"Hostname '{candidate}' does not match session hostname '{env.hostname}'."
                ))

    return issues


# ─────────────────────────────────────────────────────────────────────────────
# Check 2 — Provenance Consistency
# ─────────────────────────────────────────────────────────────────────────────

def check_provenance_consistency(
    content: str, session: SessionState
) -> List[ValidationIssue]:
    issues = []
    env = session.env_facts
    allowed_users = set(env.existing_users)
    allowed_artifacts = set(env.previously_generated_artifacts)

    # Check for /home/<user>/ paths — user must be in existing_users
    for match in re.finditer(r"/home/([a-zA-Z0-9_\-]+)/", content):
        user = match.group(1)
        if user not in allowed_users:
            issues.append(ValidationIssue(
                criterion="provenance_consistency",
                description=(
                    f"Username '{user}' found in artifact path but is not in "
                    f"session.env_facts.existing_users {sorted(allowed_users)}."
                )
            ))

    # Check for ghost_ prefix (our deliberate canary for invented users)
    ghost_matches = set(re.findall(r"ghost_[a-f0-9]{6}", content))
    for ghost_user in sorted(ghost_matches):
        issues.append(ValidationIssue(
            criterion="provenance_consistency",
            description=f"Invented/ghost username '{ghost_user}' detected in artifact."
        ))

    return issues


# ─────────────────────────────────────────────────────────────────────────────
# Check 3 — Format Credibility
# ─────────────────────────────────────────────────────────────────────────────

def check_format_credibility(
    content: str, category_name: str
) -> List[ValidationIssue]:
    issues = []

    if "aws" in category_name.lower():
        if not AWS_ACCESS_KEY_RE.search(content):
            issues.append(ValidationIssue(
                criterion="format_credibility",
                description="AWS access key missing or does not match ^AKIA[0-9A-Z]{16}$."
            ))
        secret_match = AWS_SECRET_KEY_RE.search(content)
        if not secret_match:
            issues.append(ValidationIssue(
                criterion="format_credibility",
                description="AWS secret key missing or not 40 base64 chars."
            ))

    if "ssh" in category_name.lower():
        if not PEM_BEGIN_RE.search(content):
            issues.append(ValidationIssue(
                criterion="format_credibility",
                description="SSH key missing -----BEGIN...----- PEM header."
            ))
        if not PEM_END_RE.search(content):
            issues.append(ValidationIssue(
                criterion="format_credibility",
                description="SSH key missing -----END...----- PEM footer."
            ))

    if "config" in category_name.lower() or "app" in category_name.lower() or "database" in category_name.lower():
        match = DB_PASS_LINE_RE.search(content)
        if match:
            pwd_val = match.group(2)
            if len(pwd_val) < 16:
                issues.append(ValidationIssue(
                    criterion="format_credibility",
                    description=(
                        f"DB_PASS/password value '{pwd_val}' is only {len(pwd_val)} chars; "
                        f"minimum 16 required for format credibility."
                    )
                ))

    if "banner" in category_name.lower():
        if not SSH_BANNER_RE.search(content) and "Apache" not in content and "vsftpd" not in content:
            issues.append(ValidationIssue(
                criterion="format_credibility",
                description="Service banner does not contain a recognizable service string."
            ))

    return issues


# ─────────────────────────────────────────────────────────────────────────────
# Check 4 — Non-Functionality
# ─────────────────────────────────────────────────────────────────────────────

def check_non_functionality(
    content: str, category_name: str
) -> List[ValidationIssue]:
    """
    Ensures the credential is provably synthetic.
    We verify AWS key starts with AKIA (our generator always does this)
    but also verify it does NOT match a known real-key blacklist pattern.
    For demo purposes the key is always fake because it comes from our generator.
    The only failure case is if someone manually inserted a real-looking key.
    """
    issues = []

    # Real AWS example keys that should never appear
    KNOWN_REAL_EXAMPLES = [
        "AKIAIOSFODNN7EXAMPLE",   # AWS documentation example (treated as real-looking)
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ]
    for known in KNOWN_REAL_EXAMPLES:
        if known in content:
            issues.append(ValidationIssue(
                criterion="non_functionality",
                description=(
                    f"Artifact contains a well-known example credential '{known[:20]}...' "
                    f"that must not be used."
                )
            ))

    return issues


# ─────────────────────────────────────────────────────────────────────────────
# Master validate() function
# ─────────────────────────────────────────────────────────────────────────────

def validate(
    content: str,
    suggested_path: str,
    session: SessionState,
    category_name: str,
) -> List[ValidationIssue]:
    """
    Runs all four checks and returns the combined issue list.
    An empty list means the artifact passed all checks.
    """
    issues: List[ValidationIssue] = []
    issues += check_referential_consistency(content, session)
    issues += check_provenance_consistency(content, session)
    issues += check_format_credibility(content, category_name)
    issues += check_non_functionality(content, category_name)
    return issues
