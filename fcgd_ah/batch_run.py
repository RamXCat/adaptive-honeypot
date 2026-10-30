"""
batch_run.py
Runs the pipeline across 15+ varied simulated sessions (all 7 categories)
to populate attempt_log.jsonl with enough data for real statistics.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from fcgd_ah.taxonomy import ArtifactCategory
from fcgd_ah.schemas import SessionState, EnvironmentFacts, MalwareInterestProfile
from fcgd_ah import retry_loop

CATEGORIES = list(ArtifactCategory)

SESSIONS = [
    # (session_id, hostname, org, existing_users, commands, duration)
    ("sess_001", "prod-server-01", "DemoCorp",     ["deploy", "ubuntu"],     ["whoami", "cat .env"],                   45.0),
    ("sess_002", "db-master-01",   "FinTechLtd",   ["postgres", "root"],     ["ls", "grep password"],                   90.0),
    ("sess_003", "web-app-02",     "RetailCo",     ["www-data", "deploy"],   ["cat .env", "cat ~/.aws/credentials"],   120.0),
    ("sess_004", "staging-01",     "HealthOrg",    ["ubuntu", "deploy"],     ["whoami", "ls", "find / -name *.pem"],  200.0),
    ("sess_005", "prod-server-02", "DemoCorp",     ["deploy", "root"],       ["cat ~/.ssh/id_rsa"],                     55.0),
    ("sess_006", "analytics-01",   "DataInc",      ["analyst", "ubuntu"],    ["ls /var/www"],                           30.0),
    ("sess_007", "api-gateway-01", "CloudCo",      ["api_user", "root"],     ["cat .env", "env"],                       80.0),
    ("sess_008", "db-replica-01",  "FinTechLtd",   ["postgres"],             ["grep -r password ."],                   110.0),
    ("sess_009", "web-app-03",     "RetailCo",     ["www-data"],             ["cat /etc/app/db.conf"],                  65.0),
    ("sess_010", "ci-server-01",   "DevShop",      ["jenkins", "deploy"],    ["ls", "cat config.yml"],                  40.0),
    ("sess_011", "prod-server-03", "DemoCorp",     ["root", "deploy"],       ["cat ~/.aws/credentials"],                95.0),
    ("sess_012", "monitoring-01",  "OpsTeam",      ["prometheus", "ubuntu"], ["cat .env"],                              70.0),
    ("sess_013", "vpn-server-01",  "SecureCo",     ["vpnuser", "root"],      ["ls /etc", "cat hosts"],                  50.0),
    ("sess_014", "mail-server-01", "CorpMail",     ["postfix", "ubuntu"],    ["grep -i pass /etc/postfix/"],           130.0),
    ("sess_015", "backup-srv-01",  "DataInc",      ["backup", "root"],       ["ls /backup", "cat .env"],               155.0),
    ("sess_016", "edge-node-01",   "CloudCo",      ["edge", "ubuntu"],       ["cat .ssh/authorized_keys"],              85.0),
    ("sess_017", "prod-server-04", "DemoCorp",     ["deploy"],               ["find / -name credentials"],             100.0),
    ("sess_018", "db-master-02",   "HealthOrg",    ["postgres", "root"],     ["cat /etc/app/db.conf"],                  60.0),
    ("sess_019", "web-app-04",     "RetailCo",     ["www-data", "ubuntu"],   ["ls", "cat .env", "whoami"],              75.0),
    ("sess_020", "build-server-01","DevShop",      ["jenkins"],              ["grep -r token ."],                       45.0),
    ("sess_021", "proxy-01",       "SecureCo",     ["nginx", "ubuntu"],      ["cat nginx.conf"],                        35.0),
]


def make_session(row) -> SessionState:
    sess_id, hostname, org, users, cmds, dur = row
    return SessionState(
        session_id=sess_id,
        commands_run=cmds,
        files_touched=["/var/www/app/.env"],
        duration_s=dur,
        env_facts=EnvironmentFacts(
            hostname=hostname,
            org_name=org,
            existing_users=users,
            previously_generated_artifacts=[],
        ),
        malware_profile=MalwareInterestProfile(
            file_type_interests=[".env", ".pem", ".json"],
            credential_patterns=["password", "token", "AWS"],
            network_destinations=[f"api.internal.{org.lower().replace(' ','')}.local"],
        ),
    )


if __name__ == "__main__":
    print("Running batch simulation across 21 sessions × 7 categories…\n")
    total = 0
    for i, row in enumerate(SESSIONS):
        session = make_session(row)
        category = CATEGORIES[i % len(CATEGORIES)]
        result = retry_loop.run(session, category)
        status = "[DEPLOYED]" if result.deployed else "[FAILED] "
        print(
            f"  [{row[0]}] {category.value:<30} "
            f"attempts={result.attempts_consumed}  {status}"
        )
        total += 1

    print(f"\nDone. {total} sessions logged to attempt_log.jsonl")
