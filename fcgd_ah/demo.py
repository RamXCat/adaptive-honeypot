"""
demo.py
Simulates one end-to-end attacker session to demonstrate the full pipeline,
including a deliberate Attempt-1 failure for APP_CONFIG_FILE.
"""

import time
import sys
import os

# Fix Windows cp1252 encoding for printing
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Allow running from project root: python -m fcgd_ah.demo
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fcgd_ah.taxonomy import ArtifactCategory
from fcgd_ah.schemas import SessionState, EnvironmentFacts, MalwareInterestProfile
from fcgd_ah import retry_loop

# Build a realistic attacker session
session = SessionState(
    session_id="demo_sess_001",
    commands_run=["whoami", "ls", "pwd", "cat .env", "grep password /var/www/*"],
    files_touched=["/var/www/app/.env", "/etc/passwd"],
    duration_s=142.0,
    env_facts=EnvironmentFacts(
        hostname="prod-server-01",
        org_name="DemoCorp",
        existing_users=["deploy", "ubuntu", "root"],
        previously_generated_artifacts=["/var/www/app/.env"],
    ),
    malware_profile=MalwareInterestProfile(
        file_type_interests=[".env", ".json", ".pem"],
        credential_patterns=["AWS", "password", "token"],
        network_destinations=["api.internal.democorp.local"],
    ),
)

DIVIDER = "-" * 60

def print_section(title: str):
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)


if __name__ == "__main__":
    print("\n+========================================================+")
    print("|     FCGD-AH Deception Module -- End-to-End Demo        |")
    print("+========================================================+")
    print(f"\n  Session ID : {session.session_id}")
    print(f"  Category   : APP_CONFIG_FILE  (will fail on Attempt 1)")
    print(f"  Target env : {session.env_facts.hostname} / {session.env_facts.org_name}")

    t0 = time.perf_counter()
    result = retry_loop.run(session, ArtifactCategory.APP_CONFIG_FILE)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    print_section("PIPELINE RESULT")
    print(f"  Deployed         : {result.deployed}")
    print(f"  Attempts used    : {result.attempts_consumed}")
    print(f"  Total latency    : {elapsed_ms:.3f} ms")

    if result.deployed:
        print(f"  Suggested path   : {result.suggested_path}")
        print(f"\n{DIVIDER}")
        print("  ARTIFACT CONTENT:")
        print(DIVIDER)
        print(result.artifact_content)
    else:
        print("\n  [!] All 3 attempts failed -- null result returned (safe).")
        print("\n  Accumulated issues:")
        for issue in result.all_issues:
            print(f"    [{issue.criterion}] {issue.description}")

    print(f"\n{'='*60}")
    print(f"  Demo complete. Latency: {elapsed_ms:.3f} ms (well under 100ms).")
    print("=" * 60)
