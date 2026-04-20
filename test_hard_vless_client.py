import unittest

from hard_vless_client import GuardConfig, Protocol, WorkMode, build_nft_rules
from hard_vless_client_ui import (
    ConnectOptions,
    PYQT_IMPORT_ERROR,
    build_connect_command,
    build_disconnect_command,
)


class GuardTests(unittest.TestCase):
    def test_rules_include_tun_server_and_lan(self):
        cfg = GuardConfig(
            protocol=Protocol.VLESS,
            mode=WorkMode.TUN,
            server_ip="203.0.113.10",
            server_port=443,
            uplink_iface="eth0",
            tunnel_iface="tun0",
            allow_lan_cidr=("192.168.0.0/16",),
        )
        rules = build_nft_rules(cfg)
        self.assertIn('oifname "tun0" accept', rules)
        self.assertIn('ip daddr 203.0.113.10 tcp dport 443 accept', rules)
        self.assertIn('ip daddr 192.168.0.0/16 accept', rules)

    def test_rules_include_system_proxy_allow(self):
        cfg = GuardConfig(
            protocol=Protocol.TROJAN,
            mode=WorkMode.SYSTEM_PROXY,
            server_ip="203.0.113.10",
            server_port=443,
            uplink_iface="eth0",
            system_proxy_host="127.0.0.1",
            system_proxy_port=1080,
        )
        rules = build_nft_rules(cfg)
        self.assertIn('ip daddr 127.0.0.1 tcp dport 1080 accept', rules)

    def test_validate_tun_requires_tunnel_iface(self):
        cfg = GuardConfig(
            protocol=Protocol.VMESS,
            mode=WorkMode.TUN,
            server_ip="203.0.113.10",
            server_port=443,
            uplink_iface="eth0",
        )
        with self.assertRaises(ValueError):
            cfg.validate()

    def test_validate_system_proxy_mode(self):
        cfg = GuardConfig(
            protocol=Protocol.SHADOWSOCKS,
            mode=WorkMode.SYSTEM_PROXY,
            server_ip="203.0.113.10",
            server_port=443,
            uplink_iface="eth0",
            system_proxy_host="127.0.0.1",
            system_proxy_port=1080,
        )
        cfg.validate()


class UiCommandBuilderTests(unittest.TestCase):
    def test_build_connect_command_tun(self):
        cmd = build_connect_command(
            ConnectOptions(
                protocol="vless",
                mode="tun",
                server_ip="203.0.113.10",
                server_port=443,
                uplink_iface="eth0",
                tunnel_iface="tun0",
                core_cmd="xray -c /etc/xray/config.json",
            )
        )
        rendered = " ".join(cmd)
        self.assertIn("--mode tun", rendered)
        self.assertIn("--tunnel-iface tun0", rendered)
        self.assertIn("xray", rendered)

    def test_build_disconnect_command(self):
        cmd = build_disconnect_command(mode="system-proxy", dry_run=True, verbose=True, force_default_route=True, tunnel_iface="tun0")
        rendered = " ".join(cmd)
        self.assertIn("disconnect", rendered)
        self.assertIn("--mode system-proxy", rendered)
        self.assertIn("--dry-run", rendered)
        self.assertIn("--verbose", rendered)
        self.assertIn("--force-default-route", rendered)
        self.assertIn("--tunnel-iface tun0", rendered)




class HybridModeTests(unittest.TestCase):
    def test_rules_include_tun_and_proxy_in_hybrid(self):
        cfg = GuardConfig(
            protocol=Protocol.VLESS,
            mode=WorkMode.TUN_SYSTEM_PROXY,
            server_ip="203.0.113.10",
            server_port=443,
            uplink_iface="eth0",
            tunnel_iface="tun0",
            system_proxy_host="127.0.0.1",
            system_proxy_port=1080,
        )
        rules = build_nft_rules(cfg)
        self.assertIn('oifname "tun0" accept', rules)
        self.assertIn('ip daddr 127.0.0.1 tcp dport 1080 accept', rules)

    def test_ui_builder_force_default_route_and_hybrid_mode(self):
        cmd = build_connect_command(
            ConnectOptions(
                protocol="vless",
                mode="tun-system-proxy",
                server_ip="203.0.113.10",
                server_port=443,
                uplink_iface="eth0",
                tunnel_iface="tun0",
                force_default_route=True,
            )
        )
        rendered = " ".join(cmd)
        self.assertIn("--mode tun-system-proxy", rendered)
        self.assertIn("--force-default-route", rendered)

@unittest.skipIf(PYQT_IMPORT_ERROR is not None, "PyQt6 is not installed in this environment")
class UiRuntimeTests(unittest.TestCase):
    def test_mainwindow_has_log_output_and_clear_binding(self):
        import os

        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt6.QtWidgets import QApplication
        from hard_vless_client_ui import MainWindow

        app = QApplication.instance() or QApplication([])
        window = MainWindow()
        self.assertTrue(hasattr(window, "log_output"))
        self.assertTrue(hasattr(window, "clear_btn"))
        window.log_output.setText("hello")
        window.clear_btn.click()
        self.assertEqual(window.log_output.toPlainText(), "")
        window.close()



if __name__ == "__main__":
    unittest.main()
