#!/usr/bin/env python3
"""PyQt UI for hard_vless_client.py."""

from __future__ import annotations

import shlex
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class ConnectOptions:
    protocol: str
    mode: str
    server_ip: str
    server_port: int
    uplink_iface: str
    tunnel_iface: str = ""
    system_proxy_host: str = "127.0.0.1"
    system_proxy_port: int = 1080
    allow_lan: str = ""
    log_file: str = ""
    verbose: bool = False
    dry_run: bool = False
    cleanup_on_exit: bool = False
    core_cmd: str = ""


def build_connect_command(options: ConnectOptions) -> list[str]:
    cmd = [
        sys.executable,
        "hard_vless_client.py",
        "connect",
        "--protocol",
        options.protocol,
        "--mode",
        options.mode,
        "--server-ip",
        options.server_ip,
        "--server-port",
        str(options.server_port),
        "--uplink-iface",
        options.uplink_iface,
    ]

    if options.log_file:
        cmd += ["--log-file", options.log_file]
    if options.verbose:
        cmd.append("--verbose")
    if options.dry_run:
        cmd.append("--dry-run")
    if options.cleanup_on_exit:
        cmd.append("--cleanup-on-exit")
    if options.allow_lan.strip():
        cmd += ["--allow-lan", options.allow_lan.strip()]

    if options.mode == "tun" and options.tunnel_iface.strip():
        cmd += ["--tunnel-iface", options.tunnel_iface.strip()]
    if options.mode == "system-proxy":
        cmd += ["--system-proxy-host", options.system_proxy_host.strip()]
        cmd += ["--system-proxy-port", str(options.system_proxy_port)]

    if options.core_cmd.strip():
        cmd += ["--", *shlex.split(options.core_cmd.strip())]

    return cmd


def build_disconnect_command(mode: str, dry_run: bool = False, log_file: str = "", verbose: bool = False) -> list[str]:
    cmd = [sys.executable, "hard_vless_client.py", "disconnect", "--mode", mode]
    if log_file:
        cmd += ["--log-file", log_file]
    if verbose:
        cmd.append("--verbose")
    if dry_run:
        cmd.append("--dry-run")
    return cmd


try:
    from PyQt6.QtCore import QProcess
    from PyQt6.QtGui import QFont
    from PyQt6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QFormLayout,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QSpinBox,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:  # pragma: no cover
    PYQT_IMPORT_ERROR = exc
else:
    PYQT_IMPORT_ERROR = None


if PYQT_IMPORT_ERROR is None:

    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("Hardened VPN Client")
            self.resize(940, 660)

            self.process = QProcess(self)
            self.process.readyReadStandardOutput.connect(self._read_stdout)
            self.process.readyReadStandardError.connect(self._read_stderr)
            self.process.finished.connect(self._process_finished)

            root = QWidget()
            self.setCentralWidget(root)
            layout = QVBoxLayout(root)
            layout.setContentsMargins(16, 16, 16, 16)
            layout.setSpacing(12)

            title = QLabel("🛡️ Hardened VPN Client")
            title_font = QFont()
            title_font.setPointSize(16)
            title_font.setBold(True)
            title.setFont(title_font)
            layout.addWidget(title)

            layout.addWidget(self._build_config_box())
            layout.addWidget(self._build_mode_box())
            layout.addWidget(self._build_flags_box())
            layout.addLayout(self._build_buttons())

            self.log_output = QTextEdit()
            self.log_output.setReadOnly(True)
            self.log_output.setPlaceholderText("Logs and command output will appear here...")
            layout.addWidget(self.log_output, stretch=1)

            self._on_mode_changed(self.mode_box.currentText())

        def _build_config_box(self) -> QWidget:
            box = QGroupBox("Connection")
            grid = QGridLayout(box)

            self.protocol_box = QComboBox()
            self.protocol_box.addItems(["vless", "vmess", "trojan", "shadowsocks", "hysteria2"])

            self.mode_box = QComboBox()
            self.mode_box.addItems(["tun", "system-proxy"])
            self.mode_box.currentTextChanged.connect(self._on_mode_changed)

            self.server_ip_edit = QLineEdit("203.0.113.10")
            self.server_port_spin = QSpinBox()
            self.server_port_spin.setRange(1, 65535)
            self.server_port_spin.setValue(443)
            self.uplink_iface_edit = QLineEdit("eth0")

            grid.addWidget(QLabel("Protocol"), 0, 0)
            grid.addWidget(self.protocol_box, 0, 1)
            grid.addWidget(QLabel("Mode"), 0, 2)
            grid.addWidget(self.mode_box, 0, 3)

            grid.addWidget(QLabel("Server IP"), 1, 0)
            grid.addWidget(self.server_ip_edit, 1, 1)
            grid.addWidget(QLabel("Server Port"), 1, 2)
            grid.addWidget(self.server_port_spin, 1, 3)

            grid.addWidget(QLabel("Uplink Iface"), 2, 0)
            grid.addWidget(self.uplink_iface_edit, 2, 1)
            return box

        def _build_mode_box(self) -> QWidget:
            box = QGroupBox("Mode Details")
            form = QFormLayout(box)
            self.tunnel_iface_edit = QLineEdit("tun0")
            self.proxy_host_edit = QLineEdit("127.0.0.1")
            self.proxy_port_spin = QSpinBox()
            self.proxy_port_spin.setRange(1, 65535)
            self.proxy_port_spin.setValue(1080)
            form.addRow("Tunnel interface", self.tunnel_iface_edit)
            form.addRow("System proxy host", self.proxy_host_edit)
            form.addRow("System proxy port", self.proxy_port_spin)
            return box

        def _build_flags_box(self) -> QWidget:
            box = QGroupBox("Advanced")
            form = QFormLayout(box)
            self.allow_lan_edit = QLineEdit()
            self.allow_lan_edit.setPlaceholderText("e.g. 192.168.0.0/16,10.0.0.0/8")
            self.log_file_edit = QLineEdit("./logs/client.log")
            self.core_cmd_edit = QLineEdit("sing-box run -c /etc/sing-box/config.json")
            self.verbose_chk = QCheckBox("Verbose")
            self.dry_run_chk = QCheckBox("Dry run")
            self.cleanup_chk = QCheckBox("Cleanup on exit")
            flags = QHBoxLayout()
            flags.addWidget(self.verbose_chk)
            flags.addWidget(self.dry_run_chk)
            flags.addWidget(self.cleanup_chk)
            flags.addStretch(1)
            form.addRow("Allow LAN CIDRs", self.allow_lan_edit)
            form.addRow("Log file", self.log_file_edit)
            form.addRow("Core command", self.core_cmd_edit)
            form.addRow("Flags", flags)
            return box

        def _build_buttons(self) -> QHBoxLayout:
            row = QHBoxLayout()
            self.connect_btn = QPushButton("Connect")
            self.disconnect_btn = QPushButton("Disconnect")
            self.clear_btn = QPushButton("Clear Logs")
            self.connect_btn.clicked.connect(self.on_connect)
            self.disconnect_btn.clicked.connect(self.on_disconnect)
            self.clear_btn.clicked.connect(self.log_output.clear)
            row.addWidget(self.connect_btn)
            row.addWidget(self.disconnect_btn)
            row.addWidget(self.clear_btn)
            row.addStretch(1)
            return row

        def _on_mode_changed(self, mode: str) -> None:
            tun = mode == "tun"
            self.tunnel_iface_edit.setEnabled(tun)
            self.proxy_host_edit.setEnabled(not tun)
            self.proxy_port_spin.setEnabled(not tun)

        def _append(self, text: str) -> None:
            self.log_output.append(text.rstrip())

        def _read_stdout(self) -> None:
            data = bytes(self.process.readAllStandardOutput()).decode(errors="replace")
            if data:
                self._append(data)

        def _read_stderr(self) -> None:
            data = bytes(self.process.readAllStandardError()).decode(errors="replace")
            if data:
                self._append(f"[stderr] {data}")

        def _process_finished(self, code: int, _status: QProcess.ExitStatus) -> None:
            self._append(f"\nProcess finished with code {code}\n")
            self.connect_btn.setEnabled(True)

        def _run_command(self, command: list[str]) -> None:
            if self.process.state() != QProcess.ProcessState.NotRunning:
                QMessageBox.warning(self, "Process running", "A client process is already running.")
                return
            self._append("$ " + shlex.join(command))
            self.connect_btn.setEnabled(False)
            self.process.start(command[0], command[1:])

        def on_connect(self) -> None:
            opts = ConnectOptions(
                protocol=self.protocol_box.currentText(),
                mode=self.mode_box.currentText(),
                server_ip=self.server_ip_edit.text().strip(),
                server_port=self.server_port_spin.value(),
                uplink_iface=self.uplink_iface_edit.text().strip(),
                tunnel_iface=self.tunnel_iface_edit.text().strip(),
                system_proxy_host=self.proxy_host_edit.text().strip(),
                system_proxy_port=self.proxy_port_spin.value(),
                allow_lan=self.allow_lan_edit.text().strip(),
                log_file=self.log_file_edit.text().strip(),
                verbose=self.verbose_chk.isChecked(),
                dry_run=self.dry_run_chk.isChecked(),
                cleanup_on_exit=self.cleanup_chk.isChecked(),
                core_cmd=self.core_cmd_edit.text().strip(),
            )
            if not opts.server_ip:
                QMessageBox.critical(self, "Missing input", "Server IP is required.")
                return
            if not opts.uplink_iface:
                QMessageBox.critical(self, "Missing input", "Uplink interface is required.")
                return
            self._run_command(build_connect_command(opts))

        def on_disconnect(self) -> None:
            cmd = build_disconnect_command(
                mode=self.mode_box.currentText(),
                dry_run=self.dry_run_chk.isChecked(),
                log_file=self.log_file_edit.text().strip(),
                verbose=self.verbose_chk.isChecked(),
            )
            self._append("$ " + shlex.join(cmd))
            try:
                output = subprocess.run(cmd, check=True, text=True, capture_output=True)
            except subprocess.CalledProcessError as exc:
                self._append(exc.stdout)
                self._append(exc.stderr)
                QMessageBox.critical(self, "Disconnect failed", f"Exit code: {exc.returncode}")
                return
            if output.stdout:
                self._append(output.stdout)
            if output.stderr:
                self._append(output.stderr)
            QMessageBox.information(self, "Done", "Disconnect command executed.")


def main() -> int:
    if PYQT_IMPORT_ERROR:
        print(
            "PyQt6 is required to run this UI. Install with: pip install PyQt6\n"
            f"Import error: {PYQT_IMPORT_ERROR}",
            file=sys.stderr,
        )
        return 1

    app = QApplication(sys.argv)
    app.setStyleSheet(
        """
        QWidget { font-size: 13px; }
        QGroupBox { border: 1px solid #d8d8d8; border-radius: 10px; margin-top: 10px; }
        QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }
        QPushButton { padding: 8px 14px; border-radius: 8px; }
        QTextEdit { border: 1px solid #e0e0e0; border-radius: 8px; background: #fafafa; }
        """
    )
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
