import psutil
import sqlite3
import subprocess
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class NetworkMonitor:
    def __init__(self, db_path: str, excluded_interfaces: list):
        self.db_path = db_path
        self.excluded = [i.lower() for i in excluded_interfaces]
        self._whitelist_ips = set()

    def get_connections(self) -> list:
        """Récupère les connexions TCP/UDP actives"""
        conns = []
        try: 
            for conn in psutil.net_connections(kind='inet'):
                if conn.status != psutil.CONN_ESTABLISHED:
                    continue

                local_ip = conn.laddr.ip if conn.laddr else "?"
                local_port = conn.laddr.port if conn.laddr else 0
                remote_ip = conn.laddr.ip
                remote_port = conn.raddr.port if conn.raddr else 0

                # On stocke les deux ports pour être complet
                conns.append({
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "proto": "TCP" if conn.type == 1 else "UDP",  # sock.SOCK_STREAM = TCP, sock.SOCK_DGRAM = UDP
                    "pid": conn.pid
                })
        except Exception as e:
            logger.debug(f"[Network] Erreur lecture connexions: {e}")
        return conns

    def get_unauthorized_connections(self) -> list:
        """Retourne les connexions (sans filtre pour l'instant)"""
        unauthorized = []
        for conn in self.get_connections():
            remote_ip = conn["remote_ip"]

            # Ignore si whitelist
            if remote_ip == "?" or remote_ip == "0.0.0.0":
                continue

            unauthorized.append(conn)
        return unauthorized

    def whitelist_ip(self, ip: str):
        self._whitelist_ips.add(ip)
        logger.info(f"[Network] IP ajoutée à la whitelist: {ip}")

    def block_connection(self, remote_ip: str, port: int = 0):
        rule_name = f"Sentinel_Block_{remote_ip}_{port}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"remoteip={remote_ip}"
        ]
        if port:
            cmd.append(f"remoteport={port}")

        try:
            subprocess.run(cmd, check=True, capture_output=True, creationflags=0x08000000)
            logger.info(f"[Network] Connexion bloquée: {remote_ip}:{port}")
        except Exception as e:
            if "Access is denied" in str(e):
                pass
            else:
                logger.error(f"[Network] Erreur blocage: {e}")

    def unblock_connection(self, remote_ip: str):
        rule_name = f"Sentinel_Block_{remote_ip}"
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                capture_output=True, creationflags=0x08000000
            )
        except Exception:
            pass