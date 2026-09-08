import psutil
import sqlite3
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

WHITELISTED_PROCS = {
    "system", "svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
    "winlogon.exe", "explorer.exe", "dwm.exe", "sihost.exe",
    "spoolsv.exe", "searchhost.exe", "conhost.exe", "taskhostw.exe",
    "runtimebroker.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "securityhealthservice.exe", "wmiaprservice.exe", "audiodg.exe",
    "python.exe", "pythonw.exe", "node.exe", "code.exe",
    "chrome.exe", "msedge.exe", "firefox.exe",
    "spotify.exe", "discord.exe", "teams.exe",
    "sentinel.exe", "pyav.exe"
}

class Monitor:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.cpu_threshold = 95
        self.ram_threshold = 2048

    def check_processes(self) -> list:
        """Retourne les processus réellement suspects"""
        anomalies = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                try:
                    name = (proc.info['name'] or "").lower()
                    # Ignore les processus whitelistés
                    if name in WHITELISTED_PROCS:
                        continue
                    if not name:
                        continue

                    cpu = proc.info['cpu_percent'] or 0
                    ram_mb = (proc.info['memory_info'].rss / 1024**2) if proc.info['memory_info'] else 0

                    # Seule anomalie : CPU > 95% ET RAM > 2Go simultanément
                    if cpu > self.cpu_threshold and ram_mb > self.ram_threshold_mb:
                        anomalies.append({
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "cpu": round(cpu, 1),
                            "ram_mb": round(ram_mb),
                            "reason": f"CPU {cpu:.0f}% + RAM {ram_mb:.0f}MB"
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            logger.debug(f"[monitor] Erreur : {e}")

        return anomalies

    def get_system_overview(self) -> dict:
        """Stats système pour le dashboard"""
        try:
            return {
                "cpu_percent": psutil.cpu_percent(interval=0.5),
                "ram_percent": psutil.virtual_memory().percent,
                "ram_used_gb": round(psutil.virtual_memory().used / 1024**3, 1),
                "ram_total_gb": round(psutil.virtual_memory().total / 1024**3, 1),
                "disk_percent": psutil.disk_usage("C:\\").percent,
                "process_count": len(psutil.pids()),
                "connections": len(psutil.net_connections(kind='inet'))
            }
        except Exception:
            return {}