import os
import logging
from datetime import datetime
from PyQt6.QtWidgets import (QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QTextEdit, 
                             QTableWidget, QTableWidgetItem, QMessageBox, QHeaderView)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon

logger = logging.getLogger(__name__)

class MainWindow(QMainWindow):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setWindowTitle(f"Sentinel v{app.config['version']}")
        self.setWindowIcon(app.windowIcon() if app.windowIcon() else QIcon())
        self.resize(900, 650)
        
        # Charger style
        qss_path = os.path.join(os.path.dirname(__file__), "styles.qss")
        with open(qss_path, "r", encoding="utf-8") as f:
            self.setStyleSheet(f.read())

        self._setup_ui()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        
        # Header
        header = QHBoxLayout()
        title_label = QLabel("Sentinel_1.0.0")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #e0e0e0;")
        status_label = QLabel("Statut : En veille")
        status_label.setObjectName("statusLabel")
        header.addWidget(title_label)
        header.addStretch()
        header.addWidget(status_label)
        
        main_layout.addLayout(header)
        
        # Tabs
        self.tabs = QTabWidget()
        self._setup_dashboard_tab()
        self._setup_scanner_tab()
        self._setup_network_tab()
        self._setup_cleanup_tab()
        self._setup_logs_tab()
        
        main_layout.addWidget(self.tabs)

    def _setup_dashboard_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        info_box = QTextEdit()
        info_box.setReadOnly(True)
        info_box.setStyleSheet("background: #1e1e1e; color: #d4d4d4; border-radius: 5px;")
        self._update_dashboard_info(info_box)
        layout.addWidget(info_box)
        
        btn_scan = QPushButton("Lancer un scan rapide")
        btn_scan.clicked.connect(lambda: self.app.scanner.scan_directory(os.path.expanduser("~")))
        layout.addWidget(btn_scan)
        
        self.tabs.addTab(tab, "Tableau de bord")

    def _update_dashboard_info(self, text_edit):
        info = f"""
            Version : {self.app.config['version']}
            Base de signatures : {self.app.scanner.signatures} entrées
            Fichiers protégés : Actifs
            Monitoring processus : Actif
            Firewall réseau : Actif (sauf Wi-Fi/Bluetooth)
            Dernier scan : Jamais
        """.strip()
        text_edit.setPlainText(info)

    def _setup_scanner_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.scan_table = QTableWidget(0, 4)
        self.scan_table.setHorizontalHeaderLabels(["Fichier", "Type", "Signature", "Action"])
        header = self.scan_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.scan_table)
        
        btn_clear = QPushButton("Vider les résultats")
        btn_clear.clicked.connect(lambda: self.scan_table.setRowCount(0))
        layout.addWidget(btn_clear)
        
        self.tabs.addTab(tab, "Scanner")

    def _setup_network_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.net_table = QTableWidget(0, 7)
        self.net_table.setHorizontalHeaderLabels([
            "Heure", "IP source", "Port local", "IP destination",
            "Port distant", "Protocole", "Processus (PID)"
            ])
        header = self.net_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.net_table)
        
        self.tabs.addTab(tab, "Réseau")

    def _setup_cleanup_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        info_label = QLabel("Nettoyage des fichiers temporaires et logs obsolètes.")
        layout.addWidget(info_label)
        
        btn_clean = QPushButton("Lancer le nettoyage")
        btn_clean.clicked.connect(lambda: self._run_cleanup())
        layout.addWidget(btn_clean)
        
        self.tabs.addTab(tab, "Nettoyage")

    def _setup_logs_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("background: #1e1e1e; color: #d4d4d4; border-radius: 5px;")
        layout.addWidget(self.log_text)
        
        btn_clear_logs = QPushButton("Effacer les logs")
        btn_clear_logs.clicked.connect(lambda: self.log_text.clear())
        layout.addWidget(btn_clear_logs)
        
        self.tabs.addTab(tab, "Logs")

    # Méthodes appelées par les threads/background tasks
    def update_monitor_tab(self, anomalies):
        if not anomalies:
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        for proc in anomalies:
            # Ajouter dans le tableau Scanner
            row = self.scan_table.rowCount()
            self.scan_table.insertRow(row)
            self.scan_table.setItem(row, 0, QTableWidgetItem(proc["name"]))
            self.scan_table.setItem(row, 1, QTableWidgetItem("Haute ressource"))
            self.scan_table.setItem(row, 2, QTableWidgetItem(proc["reason"]))
            self.scan_table.setItem(row, 3, QTableWidgetItem(f"PID {proc['pid']}"))

            # Log lisible
            self.log_text.append(
                f"[{timestamp}] [PROC] {proc['name']} "
                f"(PID {proc['pid']}) - {proc['reason']}"
            )

    SERVICES = {80: "HTTP", 443: "HTTPS", 22: "SSH", 53: "DNS", 3389: "RDP"}
    MAX_ROWS = 2000

    def update_network_tab(self, unauthorized):
        if not unauthorized:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        for conn in unauthorized:
            port = conn["dst_port"]
            service = self.SERVICES.get(port)
            info = f"{conn['process']} ({conn['pid']})" if conn["pid"] else "System"
            values = [ts, conn["src_ip"], str(conn["src_port"]), conn["dst_ip"],
                    f"{port} ({service})" if service else str(port),
                    conn["proto"], info]
            row = self.net_table.rowCount()
            self.net_table.insertRow(row)
            for col, v in enumerate(values):
                self.net_table.setItem(row, col, QTableWidgetItem(v))
            if self.net_table.rowCount() > self.MAX_ROWS:
                self.net_table.removeRow(0)
        self.net_table.scrollToBottom()

        logger.info(f"[UI] {len(unauthorized)} nouvelles entrées réseau ajoutées")

    def show_threat_alert(self, threats):
        QMessageBox.warning(
            self, "Menace détectée", 
            f"{len(threats)} menace(s) trouvée(s).\nVoulez-vous les isoler dans le bac à sable ?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if QMessageBox.StandardButton.Yes:
            for t in threats:
                self.app.scanner.quarantine_file(t["path"])
            self.log_text.append(f"[{self._get_timestamp()}] Quarantaine : {len(threats)} fichiers déplacés")

    def _run_cleanup(self):
        cleaned = self.app.cleanup.run()
        QMessageBox.information(self, "Nettoyage terminé", f"{cleaned} octets libérés.")
        self.log_text.append(f"[{self._get_timestamp()}] Nettoyage : {cleaned} octets supprimés")

    def _get_timestamp(self):
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def closeEvent(self, event):
        self.hide()
        event.ignore()