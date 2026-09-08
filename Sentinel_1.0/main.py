import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

import json
import logging
from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu
from PyQt6.QtGui import QIcon, QAction, QPixmap, QPainter, QColor
from PyQt6.QtCore import QTimer

# Ajouter le dossier racine au path pour les imports relatifs
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui.main_window import MainWindow
from database.init_db import init_database
from modules.scanner import Scanner
from modules.monitor import Monitor
from modules.network import NetworkMonitor
from modules.cleanup import Cleanup

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PyAV")

class PyAVApp(QApplication):
    def __init__(self, argv):
        super().__init__(argv)
        self.setOrganizationName("Sentinel_Corp")
        self.setApplicationName("Sentinel_1.0.0")

        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icon.ico")
        if os.path.exists(icon_path):
            self.app_icon = QIcon(icon_path)
        else:
            from PyQt6.QtGui import QPixmap, QColor
            pixmap = QPixmap(64, 64)
            pixmap.fill(QColor(30, 144, 255))
            self.app_icon = QIcon(pixmap)

        self.setWindowIcon(self.app_icon)
        
        # 1. Charger config
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                self.config = json.load(f)
        except FileNotFoundError:
            logger.error("config.json introuvable. Création d'un fichier par défaut...")
            self.config = {
                "app_name": "Sentinel",
                "version": "1.0.0",
                "scan_interval_hours": 24,
                "db_path": "data/signatures.db",
                "quarantine_path": "quarantine",
                "excluded_interfaces": ["Wi-Fi", "Bluetooth"],
                "log_level": "INFO"
            }
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=4)

        # 2. Initialiser DB si nécessaire
        if not os.path.exists(self.config["db_path"]):
            logger.info("Initialisation de la base de donnée...")
            init_database()

        # 3. Instancier modules
        api_key = self.config.get("vt_api_key", "")
        
        logger.info("Initialisation des modules...")
        self.scanner = Scanner(
            db_path=self.config["db_path"], 
            quarantine_dir=self.config["quarantine_path"],
            api_key=api_key
        )
        self.monitor = Monitor(self.config["db_path"])
        self.network = NetworkMonitor(self.config["db_path"], self.config["excluded_interfaces"])
        self.cleanup = Cleanup(self.config["db_path"])

        # 4. UI principale
        self.window = MainWindow(self)
        self.window.show()

        # 5. Tray Icon
        app_icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icon.ico")
        if os.path.exists(app_icon_path):
            app_icon = QIcon(app_icon_path)
        else:
            pixmap = QPixmap(64, 64)
            pixmap.fill(QColor(30, 144, 255))
            app_icon = QIcon(pixmap)

        self.tray = QSystemTrayIcon(self.app_icon, self)
        self.tray.setToolTip(f"Sentinel v{self.config['version']}")
        
        menu = QMenu()
        show_action = QAction("Afficher", menu)
        show_action.triggered.connect(self.window.showNormal)

        quit_action = QAction("Quitter", menu)
        quit_action.triggered.connect(self.quit)

        menu.addActions([show_action, quit_action])
        
        self.tray.setContextMenu(menu)

        # Gérer le double clic sur l'icone système
        self.tray.activated.connect(self._on_tray_activated)
        self.tray.show()

        logger.info("Sentinel démarré avec succès.")

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.window.showNormal()
            self.window.activateWindow()

    def start_background_tasks(self):
        """Lance les boucles de monitoring (appelé via QTimer au démarrage)"""
        logger.info("Démarrage des tâches de fond (Monitoring & Réseau)...")

        # Monitoring processus toutes les 10s
        QTimer.singleShot(100, self._monitor_loop)
        
        # Scan réseau toutes les 5s
        QTimer.singleShot(50, self._network_loop)
        
        # Scan complet périodique (configuré en heures)
        scan_interval_ms = int(self.config.get("scan_interval_hours", 24) * 60 * 60 * 1000)
        QTimer.singleShot(scan_interval_ms, self._periodic_scan)

    def _monitor_loop(self):
        try:
            anomalies = self.monitor.check_processes()
            if anomalies:
                self.window.update_monitor_tab(anomalies)
                for a in anomalies:
                    logger.warning(f"[Monitor] {a['name']} (PID {a['pid']}) - {a['reason']}")
                else:
                    logger.debug("[Monitor] Aucun processus anormal")
        except Exception as e:
            logger.error(f"Erreur monitoring: {e}")
        # Prochain appel dans 10s
        QTimer.singleShot(10000, self._monitor_loop)

    def _network_loop(self):
        try:
            unauthorized = self.network.get_unauthorized_connections()
            if unauthorized:
                self.window.update_network_tab(unauthorized)
        except Exception as e:
            logger.error(f"Erreur réseau: {e}")

        # Prochazin appel dans 5s
        QTimer.singleShot(5000, self._network_loop)

    def _periodic_scan(self):
        """Lance un scan automatique"""
        logger.info("Lancement du scan périodique...")
        scan_paths = [
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Downloads"),
            "C:\\Program Files"
        ]

        threats_found = []
        for path in scan_paths:
            if os.path.exists(path):
                threats = self.scanner.scan_directory(path)
                threats_found.extend(threats)

        if threats_found:
            logger.warning(f"{len(threats_found)} menaces détectées lors du scan périodique.")
            self.window.show_threat_alert(threats_found)
        else:
            logger.info("Scan périodique terminé: aucune menace détectée.")

        # Prochain scan dans 24h (ou config)
        scan_interval_ms = int(self.config.get("scan_interval_hours", 24) * 60 * 60 * 1000)
        QTimer.singleShot(scan_interval_ms, self._periodic_scan)

    def closeEvent(self, event):
        """Quand on ferme la fenêtre, on minimise dans la tray plutôt que de quitter"""
        self.window.hide()
        event.ignore()

if __name__ == "__main__":
    app = PyAVApp(sys.argv)
    QTimer.singleShot(1000, app.start_background_tasks)
    sys.exit(app.exec())
