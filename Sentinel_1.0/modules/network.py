import psutil
import sqlite3
import subprocess
import logging
import socket
from datetime import datetime

logger = logging.getLogger(__name__)

class NetworkMonitor:
    def __init__(self, db_path: str, excluded_interfaces: list):
        self.db_path = db_path
        self.excluded = [i.lower() for i in excluded_interfaces]
        self._whitelist_ips = set()
        self._seen = set()

    def get_connections(self) -> list:
        """Connexions TCP/UDP actives avec structure fixe"""
        conns = []
        try:
            for c in psutil.net_connections(kind='inet'):
                if not c.raddr:
                    continue  # sockets en écoute / UDP non connectés
                if c.type == socket.SOCK_STREAM and c.status != psutil.CONN_ESTABLISHED:
                    continue

                process_name = "System"
                if c.pid:
                    try:
                        process_name = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_name = "N/A"

                conns.append({
                    "src_ip": c.laddr.ip if c.laddr else "0.0.0.0",
                    "src_port": c.laddr.port if c.laddr else 0,
                    "dst_ip": c.raddr.ip,
                    "dst_port": c.raddr.port,
                    "proto": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                    "pid": c.pid,
                    "process": process_name,
                })
        except Exception:
            logger.exception("[Network] Erreur lecture connexions")
        return conns

    def get_unauthorized_connections(self) -> list:
        current = {}
        for conn in self.get_connections():
            ip = conn["dst_ip"]
            if ip in ("0.0.0.0", "", "?") or ip in self._whitelist_ips:
                continue
            key = (conn["src_ip"], conn["src_port"], ip,
                   conn["dst_port"], conn["proto"], conn["pid"])
            current[key] = conn
        new = [c for k, c in current.items() if k not in self._seen]
        self._seen = set(current)  # purge les connexions fermées
        return new

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