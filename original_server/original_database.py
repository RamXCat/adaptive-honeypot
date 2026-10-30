"""
Original Enterprise Production Database (SQLite & Schema Mock).
This represents the genuine, uncompromised corporate relational database of DemoCorp Inc.
It stores real hashed customer records, PCI-DSS compliance audits, internal microservice tokens,
and financial transaction logs.
"""
import sqlite3
import os
import hashlib

DB_PATH = os.path.join(os.path.dirname(__file__), "democorp_production.db")

def init_original_database():
    """Initializes the genuine enterprise database with realistic production schemas and records."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # 1. Corporate Staff & Sensitive Roles
    cur.execute("""
    CREATE TABLE IF NOT EXISTS corporate_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL,
        department TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        mfa_seed TEXT NOT NULL,
        last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 2. Production Customers (PII & Financial)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS customer_accounts (
        account_id TEXT PRIMARY KEY,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL,
        account_balance_usd REAL NOT NULL,
        tax_id_ssn_masked TEXT NOT NULL,
        kyc_status TEXT NOT NULL
    )
    """)

    # 3. Enterprise Microservice API Tokens & Secrets
    cur.execute("""
    CREATE TABLE IF NOT EXISTS service_credentials (
        service_name TEXT PRIMARY KEY,
        environment TEXT NOT NULL,
        api_token TEXT NOT NULL,
        rotation_cycle_days INTEGER NOT NULL,
        status TEXT NOT NULL
    )
    """)

    # Populate genuine seed records if empty
    cur.execute("SELECT COUNT(*) FROM corporate_users")
    if cur.fetchone()[0] == 0:
        def sha(s): return hashlib.sha256(s.encode()).hexdigest()

        cur.executemany("""
        INSERT INTO corporate_users (username, full_name, role, department, password_hash, mfa_seed)
        VALUES (?, ?, ?, ?, ?, ?)
        """, [
            ("sec_admin", "Dr. Sarah Mitchell", "CISO / Superadmin", "InfoSec", sha("VaultK3y_Master2026!"), "JBSWY3DPEHPK3PXP"),
            ("lead_dev", "Alex Rivera", "Principal Architect", "Engineering", sha("Rivera_Arch#992"), "KZXW6YTBOJUW4ZZ2"),
            ("db_admin", "Marcus Vance", "Lead DBA", "Infrastructure", sha("Postgres_Cluster_Root#"), "MFRGGZDFMY2TQOI="),
            ("auditor", "Elena Rostova", "Compliance Officer", "Internal Audit", sha("PCI_DSS_Compliant_2026"), "NBSWY3DPEHPK3PXP")
        ])

        cur.executemany("""
        INSERT INTO customer_accounts (account_id, full_name, email, account_balance_usd, tax_id_ssn_masked, kyc_status)
        VALUES (?, ?, ?, ?, ?, ?)
        """, [
            ("ACC-90421", "OmniCorp International", "billing@omnicorp.io", 1450200.50, "XXX-XX-9481", "VERIFIED"),
            ("ACC-90422", "Apex Logistics Ltd", "finance@apexlogistics.com", 823400.00, "XXX-XX-1029", "VERIFIED"),
            ("ACC-90423", "Vanguard Health Systems", "payables@vanguardhealth.org", 3120950.75, "XXX-XX-5521", "VERIFIED"),
            ("ACC-90424", "Helios Energy Global", "treasury@heliosenergy.com", 5890000.20, "XXX-XX-8844", "VERIFIED")
        ])

        cur.executemany("""
        INSERT INTO service_credentials (service_name, environment, api_token, rotation_cycle_days, status)
        VALUES (?, ?, ?, ?, ?)
        """, [
            ("Stripe_Payment_Gateway", "PRODUCTION", "rk_test_51M0xOrgDemoCorpTrueSecret94810294812", 90, "ACTIVE"),
            ("AWS_KMS_Master_Key", "PRODUCTION", "arn:aws:kms:us-east-1:992019283019:key/d8e12a0f-901b", 365, "ACTIVE"),
            ("SendGrid_Transactional", "PRODUCTION", "SG_MOCK_9928102_TestSendgridTokenPayload", 60, "ACTIVE"),
            ("Internal_LDAP_Sync", "INTERNAL_CORP", "ldap_bind_dn_secops_corp_auth_token_091", 30, "ACTIVE")
        ])

        conn.commit()

    conn.close()

def query_db_cli(query: str) -> str:
    """Executes a SQL query on the original database and returns formatted ASCII tabular output."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(query)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        conn.close()

        if not cols:
            return "Query executed successfully. (0 rows returned)\n"

        # Format tabular output
        widths = [max(len(str(col)), max((len(str(row[i])) for row in rows), default=0)) for i, col in enumerate(cols)]
        sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
        hdr = "| " + " | ".join(f"{col:<{widths[i]}}" for i, col in enumerate(cols)) + " |"

        lines = [sep, hdr, sep]
        for row in rows:
            line = "| " + " | ".join(f"{str(row[i]):<{widths[i]}}" for i, col in enumerate(cols)) + " |"
            lines.append(line)
        lines.append(sep)
        lines.append(f"({len(rows)} rows)\n")
        return "\n".join(lines)
    except Exception as e:
        return f"Database Error: {str(e)}\n"

if __name__ == "__main__":
    init_original_database()
    print("Original Production Database initialized successfully.")
    print(query_db_cli("SELECT id, username, full_name, role, department FROM corporate_users"))
