import os
import hashlib
import sqlite3
import threading
import time
import json
from pathlib import Path
from datetime import datetime
from cryptography.fernet import Fernet
import requests
import logging
import shutil

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════
# RATE LIMITER VT (4 req/min max, 500/jour)
# ═══════════════════════════════════════════
class VTRateLimiter:
    def __init__(self, max_per_minute=3, max_per_day=400):
        self.max_per_minute = max_per_minute
        self.max_per_day = max_per_day
        self._timestamps = []
        self._daily_count = 0
        self._day_start = datetime.now().date()

    def can_request(self) -> bool:
        now = datetime.now()
        # Reset daily counter if new day
        if now.date() != self._day_start:
            self._daily_count = 0
            self._day_start = now.date()
        if self._daily_count >= self.max_per_day:
            return False
        # Filter timestamps to last 60s
        self._timestamps = [t for t in self._timestamps if (now - t).total_seconds() < 60]
        if len(self._timestamps) >= self.max_per_minute:
            return False
        return True

    def record(self):
        self._timestamps.append(datetime.now())
        self._daily_count += 1


# ═══════════════════════════════════════════
# CLIENT VT
# ═══════════════════════════════════════════
class VTClient:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("VT_API_KEY", "")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}
        self.rate_limiter = VTRateLimiter()

    def get_file_report(self, file_hash: str) -> dict | None:
        if not self.rate_limiter.can_request():
            logger.debug("[VT] Rate limit atteint, skip online check")
            return None
        url = f"{self.base_url}/files/{file_hash}"
        try:
            resp = requests.get(url, headers=self.headers, timeout=10)
            self.rate_limiter.record()
            if resp.status_code == 200:
                return resp.json().get("data", {}).get("attributes", {})
            elif resp.status_code == 403:
                logger.warning("[VT] Rate limit API (403)")
            elif resp.status_code == 401:
                logger.warning("[VT] Clé API invalide (401)")
        except Exception as e:
            logger.warning(f"[VT] Erreur API pour {file_hash}: {e}")
        return None

    def fetch_malware_signatures(self, limit: int = 50) -> list:
        if not self.rate_limiter.can_request():
            logger.debug("[VT] Rate limit atteint, skip fetch")
            return []
        url = f"{self.base_url}/signatures?limit={limit}"
        try:
            resp = requests.get(url, headers=self.headers, timeout=15)
            self.rate_limiter.record()
            if resp.status_code == 200:
                return resp.json().get("data", [])
            elif resp.status_code == 401:
                logger.warning("[VT] Clé API invalide (401) - vérifie config.json")
        except Exception as e:
            logger.warning(f"[VT] Erreur fetch: {e}")
        return []


# ═══════════════════════════════════════════
# SCANNER
# ═══════════════════════════════════════════
class Scanner:
    def __init__(self, db_path: str, quarantine_dir: str, api_key: str = None):
        self.db_path = Path(db_path)
        self.quarantine_dir = Path(quarantine_dir)

        # Créer les dossiers
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        # Init SQLite
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS signatures (
                hash TEXT PRIMARY KEY,
                name TEXT,
                detection_count INTEGER DEFAULT 0,
                file_type TEXT,
                last_updated TIMESTAMP
            )""")
            conn.commit()

        # Fernet
        fernet_key_path = Path("database/fernet.key")
        fernet_key_path.parent.mkdir(parents=True, exist_ok=True)
        if not fernet_key_path.exists():
            with open(fernet_key_path, 'wb') as f:
                f.write(Fernet.generate_key())
        with open(fernet_key_path, 'rb') as f:
            self.fernet = Fernet(f.read())

        # VT Client
        self.vt_client = VTClient(api_key=api_key)

        # Chargement initial des signatures
        self._load_local_signatures()

        # Scheduler (toutes les 6h)
        self._update_thread = None
        self.start_periodic_updates(interval_hours=6)

    # ─── PROPRIÉTÉ POUR L'UI (retourne le COUNT) ───
    @property
    def signatures(self) -> int:
        """Retourne le nombre de signatures en DB"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM signatures")
                return cursor.fetchone()[0]
        except Exception:
            return 0

    # ─── SIGNATURES ───
    def _load_local_signatures(self):
        """Charge les signatures seed depuis JSON local"""
        seed_path = Path("data/seed_signatures.json")
        if seed_path.exists():
            with open(seed_path, "r", encoding="utf-8") as f:
                sigs = json.load(f)
            with sqlite3.connect(self.db_path) as conn:
                for sig in sigs:
                    conn.execute("""INSERT OR REPLACE INTO signatures
                        (hash, name, detection_count, file_type, last_updated)
                        VALUES (?, ?, ?, ?, ?)""",
                        (sig["hash"], sig["name"],
                         sig.get("detections", 1),
                         sig.get("type", "malware"),
                         datetime.now().isoformat()))
                conn.commit()
            logger.info(f"[Scanner] {len(sigs)} signatures locales chargées")
        else:
            self._create_seed()

    def _create_seed(self):
        """Crée un seed initial avec des hashes connus"""
        seed = [
            {
                "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "name": "EICAR-Standard-Test-String",
                "detections": 72,
                "type": "test"
            }
        ]
        os.makedirs("data", exist_ok=True)
        with open("data/seed_signatures.json", "w", encoding="utf-8") as f:
            json.dump(seed, f, indent=2)
        # Insérer en DB
        with sqlite3.connect(self.db_path) as conn:
            for sig in seed:
                conn.execute("""INSERT OR REPLACE INTO signatures
                    (hash, name, detection_count, file_type, last_updated)
                    VALUES (?, ?, ?, ?, ?)""",
                    (sig["hash"], sig["name"], sig["detections"],
                     sig["type"], datetime.now().isoformat()))
            conn.commit()
        logger.info("[Scanner] Seed signatures créé (1 entrée)")

    # ─── SCHEDULER ───
    def start_periodic_updates(self, interval_hours: int = 6):
        if self._update_thread and self._update_thread.is_alive():
            return
        self._update_thread = threading.Thread(
            target=self._periodic_update_loop, args=(interval_hours,), daemon=True
        )
        self._update_thread.start()

    def _periodic_update_loop(self, interval_hours: int):
        while True:
            time.sleep(interval_hours * 3600)
            try:
                logger.info("[VT] Mise a jour signatures depuis VirusTotal...")
                self.update_signatures_from_vt()
            except Exception as e:
                logger.error(f"[VT] Erreur update: {e}")

    def update_signatures_from_vt(self):
        sigs = self.vt_client.fetch_malware_signatures(limit=50)
        if not sigs:
            logger.info("[VT] Aucune nouvelle signature (ou rate limit)")
            return
        with sqlite3.connect(self.db_path) as conn:
            for sig in sigs:
                attrs = sig.get("attributes", {})
                conn.execute("""INSERT OR REPLACE INTO signatures
                    (hash, name, detection_count, file_type, last_updated)
                    VALUES (?, ?, ?, ?, ?)""",
                    (sig.get("id", ""), attrs.get("name", "Unknown"),
                     len(attrs.get("last_analysis_results", [])),
                     "vt", datetime.now().isoformat()))
            conn.commit()
        logger.info(f"[VT] {len(sigs)} signatures ajoutees")

    # ─── CHECK ONLINE ───
    def check_online(self, file_hash: str) -> dict | None:
        # 1. Cache local
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT name, detection_count FROM signatures WHERE hash=?", (file_hash,)
            )
            match = cursor.fetchone()
        if match:
            return {"local": True, "name": match[0], "detections": match[1]}

        # 2. VT online (respecte rate limit)
        report = self.vt_client.get_file_report(file_hash)
        if report and report.get("last_analysis_stats", {}).get("malicious", 0) > 0:
            return {
                "local": False,
                "name": report.get("meaningful_name", "Unknown"),
                "detections": report["last_analysis_stats"]["malicious"]
            }
        return None

    # ─── SCAN ───
    def scan_directory(self, directory: str) -> list[dict]:
        threats = []
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.warning(f"[Scan] Dossier introuvable: {directory}")
            return threats

        file_count = 0
        for filepath in dir_path.rglob("*"):
            if filepath.is_file() and filepath.suffix.lower() in (
                ".exe", ".dll", ".py", ".js", ".bat", ".ps1",
                ".docx", ".xlsx", ".vbs", ".scr", ".jar"
            ):
                try:
                    file_hash = self._hash_file(str(filepath))
                    file_count += 1

                    # Check local
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.execute(
                            "SELECT name, detection_count FROM signatures WHERE hash=?",
                            (file_hash,)
                        )
                        match = cursor.fetchone()

                    # Check VT (seulement si pas en local ET rate limit OK)
                    if not match:
                        match = self.check_online(file_hash)

                    if match and match.get("detections", 0) > 0:
                        threats.append({
                            "path": str(filepath),
                            "hash": file_hash,
                            "name": match["name"],
                            "detections": match["detections"]
                        })
                        logger.warning(f"[Scan] MENACE: {filepath} ({match['name']})")
                except Exception as e:
                    logger.debug(f"[Scan] Erreur {filepath}: {e}")

        logger.info(f"[Scan] Terminé: {file_count} fichiers, {len(threats)} menaces")
        return threats

    # ─── HASH ───
    def _hash_file(self, filepath: str) -> str:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    # ─── QUARANTINE ───
    def _quarantine(self, filepath: str) -> bool:
        try:
            filename = Path(filepath).name
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            dest = self.quarantine_dir / f"{timestamp}_{filename}"
            shutil.move(str(filepath), str(dest))

            # Chiffrer
            with open(dest, "rb") as f:
                encrypted = self.fernet.encrypt(f.read())
            dest.unlink()
            with open(dest.with_suffix(".enc"), "wb") as f:
                f.write(encrypted)
            logger.info(f"[Quarantine] {filename} isolé")
            return True
        except Exception as e:
            logger.error(f"[Quarantine] Erreur {filepath}: {e}")
            return False

    def get_quarantine_list(self) -> list[dict]:
        items = []
        for enc_file in self.quarantine_dir.glob("*.enc"):
            try:
                with open(enc_file, "rb") as f:
                    decrypted = self.fernet.decrypt(f.read())
                # Récupère le nom original (après le timestamp)
                parts = enc_file.stem.split("_", 1)
                original_name = parts[1] if len(parts) > 1 else enc_file.name
                items.append({
                    "name": original_name,
                    "size_kb": round(len(decrypted) / 1024, 1),
                    "date": datetime.fromtimestamp(enc_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                })
            except Exception as e:
                logger.error(f"[Quarantine] Erreur lecture {enc_file}: {e}")
        return items
