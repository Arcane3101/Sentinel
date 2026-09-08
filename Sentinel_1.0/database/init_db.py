import sqlite3
import os
from cryptography.fernet import Fernet

def init_database():
    db_path = "database/signatures.db"
    quarantine_dir = "database/quarantine"

    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    os.makedirs(quarantine_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Table signatures (hash, nom, sévérité, catégorie)
    cursor.execute("""CREATE TABLE IF NOT EXISTS signatures (
        hash TEXT PRIMARY KEY,
        name TEXT,
        detection_count INTEGER DEFAULT 0,
        file_type TEXT,
        last_updated TIMSTAMP
    )""")

    # Table whitelist (path ou hash)
    cursor.execute("""CREATE TABLE IF NOT EXISTS whitelist (
        identifier TEXT PRIMARY KEY,
        type TEXT CHECK(type IN ('file', 'hash', 'ip', 'domain'))
    )""")

    # Table firewall_rules
    cursor.execute("""CREATE TABLE IF NOT EXISTS firewall_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        domain TEXT,
        port INTEGER,
        direction TEXT CHECK(direction IN ('in', 'out')),
        action TEXT CHECK(action IN ('block', 'allow'))
    )""")

    # Table logs
    cursor.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        level TEXT,
        message TEXT
    )""")

    conn.commit()
    conn.close()

    print("✅ Base de données et dossier quarantaine initialisés.")

    # Clé AES pour chiffrer la quarantaine
    key_path = "database/fernet.key"
    if not os.path.exists(key_path):
        with open(key_path, "wb") as f:
            f.write(Fernet.generate_key())

if __name__ == "__main__":
    init_database()