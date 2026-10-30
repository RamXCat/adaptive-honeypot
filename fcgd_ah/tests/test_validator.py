"""
tests/test_validator.py
Adversarial pytest suite for validator.py.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import pytest
from fcgd_ah.schemas import SessionState, EnvironmentFacts, MalwareInterestProfile
from fcgd_ah.validator import (
    check_referential_consistency,
    check_provenance_consistency,
    check_format_credibility,
    check_non_functionality,
    validate,
)


def make_session(hostname="prod-server-01", org="DemoCorp", users=None):
    return SessionState(
        session_id="test_sess",
        commands_run=[],
        files_touched=[],
        duration_s=60.0,
        env_facts=EnvironmentFacts(
            hostname=hostname,
            org_name=org,
            existing_users=users or ["deploy", "ubuntu"],
            previously_generated_artifacts=["/var/www/app/.env"],
        ),
        malware_profile=MalwareInterestProfile(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. REFERENTIAL CONSISTENCY
# ─────────────────────────────────────────────────────────────────────────────

class TestReferentialConsistency:
    def test_correct_hostname_passes(self):
        session = make_session(hostname="prod-server-01")
        content = "HOST=prod-server-01\nDB_PASS=verylongsecretpassword123\n"
        issues = check_referential_consistency(content, session)
        assert not any(i.criterion == "referential_consistency" for i in issues)

    def test_fabricated_hostname_fails(self):
        """A hostname not in env_facts must fail referential_consistency."""
        session = make_session(hostname="prod-server-01")
        content = "HOST=evil-external-server\nDB_PASS=verylongsecretpassword123\n"
        issues = check_referential_consistency(content, session)
        assert any(i.criterion == "referential_consistency" for i in issues), \
            "Expected referential_consistency failure for fabricated hostname"

    def test_no_hostname_field_passes(self):
        session = make_session(hostname="prod-server-01")
        content = "[default]\naws_access_key_id=AKIAABCDEFGH12345678\n"
        issues = check_referential_consistency(content, session)
        assert not issues


# ─────────────────────────────────────────────────────────────────────────────
# 2. PROVENANCE CONSISTENCY
# ─────────────────────────────────────────────────────────────────────────────

class TestProvenanceConsistency:
    def test_valid_existing_user_passes(self):
        session = make_session(users=["deploy", "ubuntu"])
        content = "drwxr-x--- 2 deploy deploy 4096 Sep 01 backup/\n"
        issues = check_provenance_consistency(content, session)
        assert not issues

    def test_invented_user_fails(self):
        """A /home/<user>/ path for a non-existent user must fail provenance_consistency."""
        session = make_session(users=["deploy", "ubuntu"])
        content = "drwxr-x--- 2 phantom phantom 4096 Sep 01 /home/phantom/secret/\n"
        issues = check_provenance_consistency(content, session)
        assert any(i.criterion == "provenance_consistency" for i in issues), \
            "Expected provenance_consistency failure for unknown user 'phantom'"

    def test_ghost_canary_username_fails(self):
        """ghost_ prefix (our deliberate canary) must always fail provenance_consistency."""
        session = make_session(users=["deploy"])
        content = "/home/ghost_a1b2c3/backup/\n"
        issues = check_provenance_consistency(content, session)
        assert any(i.criterion == "provenance_consistency" for i in issues), \
            "Expected provenance_consistency failure for ghost_ canary username"


# ─────────────────────────────────────────────────────────────────────────────
# 3. FORMAT CREDIBILITY
# ─────────────────────────────────────────────────────────────────────────────

class TestFormatCredibility:
    def test_valid_aws_key_passes(self):
        content = "aws_access_key_id=AKIAABCDEFGHIJKLMNOP\naws_secret_access_key=abcdefghijklmnopqrstuvwxyz1234567890ABCD\n"
        issues = check_format_credibility(content, "aws_credentials")
        assert not issues

    def test_near_valid_aws_key_too_short_fails(self):
        """AKIA prefix but only 14 trailing chars (needs 16) must fail format_credibility."""
        content = "aws_access_key_id=AKIASHORT123456\naws_secret_access_key=abcdefghijklmnopqrstuvwxyz1234567890ABCD\n"
        issues = check_format_credibility(content, "aws_credentials")
        assert any(i.criterion == "format_credibility" for i in issues), \
            "Expected format_credibility failure for 14-char AWS key suffix"

    def test_aws_key_wrong_prefix_fails(self):
        content = "aws_access_key_id=XKIA1234567890ABCDEF\naws_secret_access_key=abcdefghijklmnopqrstuvwxyz1234567890ABCD\n"
        issues = check_format_credibility(content, "aws_credentials")
        assert any(i.criterion == "format_credibility" for i in issues)

    def test_app_config_short_password_fails(self):
        """DB_PASS under 16 chars must fail format_credibility."""
        content = "HOST=prod-server-01\nDB_PASS=short\nSECRET_KEY=abc\n"
        issues = check_format_credibility(content, "app_config_file")
        assert any(i.criterion == "format_credibility" for i in issues), \
            "Expected format_credibility failure for 5-char DB_PASS"

    def test_app_config_long_password_passes(self):
        content = "HOST=prod-server-01\nDB_PASS=VeryLongPassword123!!!\nSECRET_KEY=abc\n"
        issues = check_format_credibility(content, "app_config_file")
        assert not any(i.criterion == "format_credibility" for i in issues)

    def test_ssh_key_valid_pem_passes(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\naGVsbG8gd29ybGQ=\n-----END RSA PRIVATE KEY-----\n"
        issues = check_format_credibility(content, "ssh_private_key")
        assert not issues

    def test_ssh_key_missing_header_fails(self):
        content = "aGVsbG8gd29ybGQ=\n-----END RSA PRIVATE KEY-----\n"
        issues = check_format_credibility(content, "ssh_private_key")
        assert any(i.criterion == "format_credibility" for i in issues)

    def test_database_credentials_valid_passes(self):
        content = "[database]\ndb_host = 10.1.2.3\npassword = VeryLongPassword123!!!\n"
        issues = check_format_credibility(content, "database_credentials")
        assert not any(i.criterion == "format_credibility" for i in issues)

    def test_database_credentials_short_password_fails(self):
        content = "[database]\ndb_host = 10.1.2.3\npassword = short\n"
        issues = check_format_credibility(content, "database_credentials")
        assert any(i.criterion == "format_credibility" for i in issues)


# ─────────────────────────────────────────────────────────────────────────────
# 4. NON-FUNCTIONALITY
# ─────────────────────────────────────────────────────────────────────────────

class TestNonFunctionality:
    def test_known_example_key_fails(self):
        """AWS documentation example key must fail non_functionality."""
        content = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        issues = check_non_functionality(content, "aws_credentials")
        assert any(i.criterion == "non_functionality" for i in issues), \
            "Expected non_functionality failure for well-known AWS doc example key"

    def test_random_generated_key_passes(self):
        """A key generated by our fake_aws_access_key() helper should pass."""
        content = "aws_access_key_id=AKIAZ9X4QT2YMNOPKLRS\naws_secret_access_key=abcdefghijklmnopqrstuvwxyz1234567890ABCD\n"
        issues = check_non_functionality(content, "aws_credentials")
        assert not issues


# ─────────────────────────────────────────────────────────────────────────────
# 5. Full validate() integration
# ─────────────────────────────────────────────────────────────────────────────

class TestFullValidate:
    def test_clean_aws_artifact_passes_all(self):
        session = make_session(hostname="prod-server-01")
        content = (
            "aws_access_key_id=AKIAZ9X4QT2YMNOPKLRS\n"
            "aws_secret_access_key=abcdefghijklmnopqrstuvwxyz1234567890ABCD\n"
            "region=us-east-1\n"
        )
        issues = validate(content, "~/.aws/credentials", session, "aws_credentials")
        assert not issues, f"Expected no issues, got: {issues}"

    def test_clean_db_artifact_passes_all(self):
        session = make_session(hostname="prod-server-01")
        content = (
            "[database]\n"
            "db_host = 10.10.1.50\n"
            "port = 5432\n"
            "user = db_admin\n"
            "password = ComplexSecurePassword_2024!\n"
            "dbname = democorp_core\n"
            "# Generated for prod-server-01\n"
        )
        issues = validate(content, "/etc/app/db.conf", session, "database_credentials")
        assert not issues, f"Expected no issues, got: {issues}"
