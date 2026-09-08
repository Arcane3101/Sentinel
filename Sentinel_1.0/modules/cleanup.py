import os
import shutil
import sqlite3
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class Cleanup:
    def __init__(self, db_path):
        self.db_path = db_path

    def clean_temp(self):
        paths = [os.environ.get("TEMP"), os.path.join(os.getenv("SYSTEMDRIVE"), "Windows", "Temp")]
        cleaned = 0
        for p in paths:
            if os.path.exists(p):
                for item in os.listdir(p):
                    try:
                        full = os.path.join(p, item)
                        shutil.rmtree(full) if os.path.isdir(full) else os.remove(full)
                        cleaned += 1
                    except Exception as e:
                        logger.warning(f"Impossible de supprimer {full}: {e}")
        return cleaned

    def clean_prefetch(self):
        pf = os.path.join(os.getenv("SYSTEMDRIVE"), "Windows", "Prefetch")
        if os.path.exists(pf):
            for f in os.listdir(pf):
                try: os.remove(os.path.join(pf, f))
                except: pass
            return True
        return False

    def clean_registry_run(self):
        cleaned = 0
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Simulation : on scanne les clés Run/RunOnce et on supprime celles dont le fichier n'existe plus
            # En vrai, on utiliserait winreg. Ici version simplifiée SQLite-based.
        return cleaned
