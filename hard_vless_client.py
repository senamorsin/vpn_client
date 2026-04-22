#!/usr/bin/env python3
"""Hardened multi-protocol VPN client wrapper with leak-prevention controls."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import platform
import shlex
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable

TABLE_NAME = "vpn_guard"


class Protocol(str, Enum):
    VLESS = "vless"
    VMESS = "vmess"
    TROJAN = "trojan"
    SHADOWSOCKS = "shadowsocks"
    HYSTERIA2 = "hysteria2"


class WorkMode(str, Enum):
    TUN = "tun"
    SYSTEM_PROXY = "system-proxy"
    TUN_SYSTEM_PROXY = "tun-system-proxy"


@dataclass(frozen=True)
class GuardConfig:
    protocol: Protocol
    mode: WorkMode
    server_ip: str
    server_port: int
    uplink_iface: str
    tunnel_iface: str = ""
    system_proxy_host: str = "127.0.0.1"
    system_proxy_port: int = 1080
    allow_lan_cidr: tuple[str, ...] = ()
    force_default_route: bool = False

    def validate(self) -> None:
        ipaddress.ip_address(self.server_ip)
        if not (1 <= self.server_port <= 65535):
            raise ValueError("server_port must be in range 1..65535")
        if not self.uplink_iface:
            raise ValueError("uplink_iface is required")

        if self.mode in (WorkMode.TUN, WorkMode.TUN_SYSTEM_PROXY) and not self.tunnel_iface:
            raise ValueError("tunnel_iface is required for tun mode")

        if self.mode in (WorkMode.SYSTEM_PROXY, WorkMode.TUN_SYSTEM_PROXY):
            ipaddress.ip_address(self.system_proxy_host)
            if not (1 <= self.system_proxy_port <= 65535):
                raise ValueError("system_proxy_port must be in range 1..65535")

        for cidr in self.allow_lan_cidr:
            ipaddress.ip_network(cidr, strict=False)


def setup_logger(log_file: str | None, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("hard_vpn_client")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(path)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger


def _allow_mode_lines(cfg: GuardConfig) -> str:
    lines: list[str] = []

    if cfg.mode in (WorkMode.TUN, WorkMode.TUN_SYSTEM_PROXY):
        lines.append(f'  oifname "{cfg.tunnel_iface}" accept')

    if cfg.mode in (WorkMode.SYSTEM_PROXY, WorkMode.TUN_SYSTEM_PROXY):
        lines.append(
            f"  ip daddr {cfg.system_proxy_host} tcp dport {cfg.system_proxy_port} accept"
        )

    return "\n".join(lines)



def _allow_mode_lines_v6(cfg: GuardConfig) -> str:
    lines: list[str] = []
    if cfg.mode in (WorkMode.TUN, WorkMode.TUN_SYSTEM_PROXY):
        lines.append(f'  oifname "{cfg.tunnel_iface}" accept')
    if cfg.mode in (WorkMode.SYSTEM_PROXY, WorkMode.TUN_SYSTEM_PROXY) and cfg.system_proxy_host == "::1":
        lines.append(
            f"  ip6 daddr {cfg.system_proxy_host} tcp dport {cfg.system_proxy_port} accept"
        )
    return "\n".join(lines)

def build_nft_rules(cfg: GuardConfig) -> str:
    allow_lan_lines = "\n".join(
        f"  ip daddr {cidr} accept" for cidr in cfg.allow_lan_cidr
    )

    mode_lines = _allow_mode_lines(cfg)
    mode_lines_v6 = _allow_mode_lines_v6(cfg)

    return f"""
flush table inet {TABLE_NAME}
table inet {TABLE_NAME} {{
 chain output {{
  type filter hook output priority 0;
  policy drop;

  ct state established,related accept
  oifname \"lo\" accept

  # Work mode policy.
{mode_lines if mode_lines else '  # no mode-specific allow rules'}

  # Allow control/data channel to upstream VPN server on uplink.
  oifname \"{cfg.uplink_iface}\" ip daddr {cfg.server_ip} tcp dport {cfg.server_port} accept
  oifname \"{cfg.uplink_iface}\" ip daddr {cfg.server_ip} udp dport {cfg.server_port} accept

  # Block local DNS leaks except loopback resolver.
  ip daddr != 127.0.0.1 udp dport 53 drop
  ip daddr != 127.0.0.1 tcp dport 53 drop

  # Optional local network access.
{allow_lan_lines if allow_lan_lines else '  # (no LAN CIDRs configured)'}
 }}

 chain output_v6 {{
  type filter hook output priority 0;
  policy drop;

  ct state established,related accept
  oifname "lo" accept

  # Work mode policy (IPv6).
{mode_lines_v6 if mode_lines_v6 else '  # no IPv6 mode-specific allow rules'}

  # deny IPv6 DNS when not explicitly tunneled
  ip6 daddr ::1 udp dport 53 accept
  ip6 daddr ::1 tcp dport 53 accept
 }}
}}
""".strip() + "\n"


def apply_nft(rules: str, dry_run: bool = False, logger: logging.Logger | None = None) -> None:
    if dry_run:
        print(rules)
        if logger:
            logger.info("Dry-run: nft rules printed")
        return
    subprocess.run(["nft", "-f", "-"], input=rules.encode(), check=True)
    if logger:
        logger.info("Applied nftables guard")


def clear_nft(dry_run: bool = False, logger: logging.Logger | None = None) -> None:
    cmd = ["nft", "delete", "table", "inet", TABLE_NAME]
    if dry_run:
        print(shlex.join(cmd))
        if logger:
            logger.info("Dry-run: nft delete table command printed")
        return
    subprocess.run(cmd, check=False)
    if logger:
        logger.info("Removed nftables guard table")


def run_command(cmd: list[str], dry_run: bool, logger: logging.Logger, ignore_error: bool = False) -> bool:
    if dry_run:
        print(shlex.join(cmd))
        logger.info("Dry-run command: %s", shlex.join(cmd))
        return True
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0 and not ignore_error:
        raise subprocess.CalledProcessError(result.returncode, cmd)
    if result.returncode != 0 and ignore_error:
        logger.warning("Command failed but ignored (%s): %s", result.returncode, shlex.join(cmd))
        return False
    return True


def get_default_routes(family: str, logger: logging.Logger | None = None) -> list[str]:
    try:
        out = subprocess.run(
            ["ip", family, "route", "show", "default"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        if logger:
            logger.warning("ip command not found; cannot read current %s default routes", family)
        return []
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


def force_default_route_to_tun(cfg: GuardConfig, dry_run: bool, logger: logging.Logger) -> tuple[list[str], list[str]]:
    """Force default traffic through TUN and return previous routes for rollback."""
    if dry_run:
        saved_v4 = []
        saved_v6 = []
    else:
        saved_v4 = get_default_routes("-4", logger)
        saved_v6 = get_default_routes("-6", logger)

    run_command(["ip", "-4", "route", "replace", "default", "dev", cfg.tunnel_iface], dry_run, logger)
    run_command(["ip", "-6", "route", "replace", "default", "dev", cfg.tunnel_iface], dry_run, logger, ignore_error=True)

    logger.info("Default routes forced through %s", cfg.tunnel_iface)
    return saved_v4, saved_v6


def restore_default_routes(saved_v4: list[str], saved_v6: list[str], dry_run: bool, logger: logging.Logger) -> None:
    for line in saved_v4:
        run_command(["ip", "-4", "route", "replace", *line.split()], dry_run, logger)
    for line in saved_v6:
        run_command(["ip", "-6", "route", "replace", *line.split()], dry_run, logger, ignore_error=True)
    logger.info("Default routes restored")


def configure_system_proxy(host: str, port: int, dry_run: bool, logger: logging.Logger) -> None:
    cmds = [
        ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"],
        ["gsettings", "set", "org.gnome.system.proxy.socks", "host", host],
        ["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(port)],
    ]

    if not shutil_which("gsettings"):
        logger.warning("gsettings not found; skipping system proxy setup")
        return

    for cmd in cmds:
        run_command(cmd, dry_run, logger)
    logger.info("Configured system proxy to %s:%s", host, port)


def clear_system_proxy(dry_run: bool, logger: logging.Logger) -> None:
    if not shutil_which("gsettings"):
        logger.warning("gsettings not found; skipping system proxy cleanup")
        return
    run_command(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"], dry_run, logger)
    logger.info("System proxy disabled")


def shutil_which(binary: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / binary
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def parse_lan(value: str) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())



def get_public_ip(logger: logging.Logger, timeout_sec: int = 10) -> str | None:
    try:
        result = subprocess.run(
            ["curl", "-fsS", "--max-time", str(timeout_sec), "ifconfig.me"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        logger.warning("curl not found; falling back to urllib for IP check")
        try:
            with urllib.request.urlopen("https://ifconfig.me", timeout=timeout_sec) as response:  # nosec B310
                return response.read().decode().strip()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Public IP check failed via urllib: %s", exc)
            return None

    if result.returncode != 0:
        logger.warning("Public IP check via curl failed: %s", result.stderr.strip())
        return None

    return result.stdout.strip()


def wait_for_expected_public_ip(
    expected_ip: str,
    logger: logging.Logger,
    retries: int = 10,
    interval_sec: float = 2.0,
    timeout_sec: int = 10,
    proc: subprocess.Popen | None = None,
) -> bool:
    for attempt in range(1, retries + 1):
        if proc is not None and proc.poll() is not None:
            logger.error("Core process exited before public IP verification completed")
            return False

        observed = get_public_ip(logger=logger, timeout_sec=timeout_sec)
        if observed == expected_ip:
            logger.info("Public IP check passed: %s", observed)
            return True

        logger.warning(
            "Public IP mismatch (attempt %s/%s): expected=%s observed=%s",
            attempt,
            retries,
            expected_ip,
            observed or "<unavailable>",
        )
        time.sleep(interval_sec)

    return False


def run_core(
    command: list[str],
    logger: logging.Logger,
    verify_egress_ip: bool = False,
    expected_ip: str = "",
    verify_retries: int = 10,
    verify_interval_sec: float = 2.0,
    verify_timeout_sec: int = 10,
) -> int:
    logger.info("Starting core: %s", shlex.join(command))
    proc = subprocess.Popen(command)

    def forward(sig: int, _frame: object) -> None:
        if proc.poll() is None:
            logger.info("Forward signal %s to core process", sig)
            proc.send_signal(sig)

    signal.signal(signal.SIGINT, forward)
    signal.signal(signal.SIGTERM, forward)

    if verify_egress_ip and expected_ip:
        ok = wait_for_expected_public_ip(
            expected_ip=expected_ip,
            logger=logger,
            retries=verify_retries,
            interval_sec=verify_interval_sec,
            timeout_sec=verify_timeout_sec,
            proc=proc,
        )
        if not ok:
            logger.error("Egress IP verification failed. VPN session will be terminated.")
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
            return 2

    exit_code = proc.wait()
    logger.info("Core exited with code %s", exit_code)
    return exit_code



def core_binary_from_command(command: list[str]) -> str | None:
    if not command:
        return None
    return command[0]


def is_binary_available(binary: str) -> bool:
    if os.path.isabs(binary):
        return os.path.exists(binary) and os.access(binary, os.X_OK)
    return shutil_which(binary) is not None


def _detect_singbox_asset() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {"linux": "linux", "darwin": "darwin"}
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }

    if system not in os_map:
        raise RuntimeError(f"Unsupported OS for auto-install: {system}")
    if machine not in arch_map:
        raise RuntimeError(f"Unsupported architecture for auto-install: {machine}")

    return os_map[system], arch_map[machine]


def install_sing_box(dry_run: bool, logger: logging.Logger) -> Path:
    os_name, arch = _detect_singbox_asset()
    api_url = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"

    with urllib.request.urlopen(api_url, timeout=20) as response:  # nosec B310
        release = json.load(response)

    tag = release.get("tag_name")
    if not tag:
        raise RuntimeError("Could not determine latest sing-box release tag")

    expected_suffix = f"{os_name}-{arch}.tar.gz"
    assets = release.get("assets", [])
    asset = next((a for a in assets if str(a.get("name", "")).endswith(expected_suffix)), None)
    if not asset:
        raise RuntimeError(f"No sing-box asset found for {expected_suffix}")

    download_url = asset.get("browser_download_url")
    if not download_url:
        raise RuntimeError("Missing browser_download_url for sing-box asset")

    target_dir = Path.home() / ".local" / "bin"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / "sing-box"

    if dry_run:
        logger.info("Dry-run: would install sing-box %s from %s to %s", tag, download_url, target_path)
        print(f"install sing-box from {download_url} -> {target_path}")
        return target_path

    with tempfile.TemporaryDirectory(prefix="sing-box-install-") as tmp_dir:
        archive_path = Path(tmp_dir) / "sing-box.tar.gz"
        urllib.request.urlretrieve(download_url, archive_path)  # nosec B310

        with tarfile.open(archive_path, "r:gz") as tar:
            member = next((m for m in tar.getmembers() if m.name.endswith("/sing-box") or m.name == "sing-box"), None)
            if member is None:
                raise RuntimeError("sing-box binary not found in downloaded archive")
            destination = (Path(tmp_dir) / member.name).resolve()
            base = Path(tmp_dir).resolve()
            if not str(destination).startswith(str(base)):
                raise RuntimeError("Unsafe path in sing-box archive")
            tar.extract(member, path=tmp_dir)
            extracted = Path(tmp_dir) / member.name
            extracted.chmod(0o755)
            target_path.write_bytes(extracted.read_bytes())
            target_path.chmod(0o755)

    logger.info("Installed sing-box to %s", target_path)
    return target_path


def ensure_core_available(command: list[str], auto_install_core: bool, dry_run: bool, logger: logging.Logger) -> str:
    binary = core_binary_from_command(command)
    if not binary:
        return ""

    if is_binary_available(binary):
        return binary

    logger.warning("Core binary '%s' was not found in PATH", binary)
    if dry_run and not auto_install_core:
        logger.info("Dry-run: skipping hard failure for missing core binary %s", binary)
        return binary
    if not auto_install_core:
        raise FileNotFoundError(
            f"Core binary '{binary}' was not found. Install it or re-run with --auto-install-core."
        )

    if binary != "sing-box":
        raise FileNotFoundError(
            f"Auto-install is currently supported only for sing-box, got '{binary}'."
        )

    installed_path = install_sing_box(dry_run=dry_run, logger=logger)
    if is_binary_available(binary):
        return binary
    return str(installed_path)


def safety_warnings(cfg: GuardConfig, logger: logging.Logger) -> None:
    if cfg.mode in (WorkMode.SYSTEM_PROXY, WorkMode.TUN_SYSTEM_PROXY):
        logger.warning(
            "Browser WebRTC may still expose host candidates; disable/limit WebRTC in browser settings."
        )
    logger.warning(
        "Validate with IPv4/IPv6/DNS leak tests after each config change; IPv6 leakage is common on IPv4-only tunnels."
    )


def build_config(args: argparse.Namespace) -> GuardConfig:
    return GuardConfig(
        protocol=Protocol(args.protocol),
        mode=WorkMode(args.mode),
        server_ip=args.server_ip,
        server_port=args.server_port,
        uplink_iface=args.uplink_iface,
        tunnel_iface=args.tunnel_iface,
        system_proxy_host=args.system_proxy_host,
        system_proxy_port=args.system_proxy_port,
        allow_lan_cidr=parse_lan(args.allow_lan),
        force_default_route=args.force_default_route,
    )



def normalize_core_cmd(cmd: list[str]) -> list[str]:
    if cmd and cmd[0] == "--":
        return cmd[1:]
    return cmd


def cmd_connect(args: argparse.Namespace) -> int:
    logger = setup_logger(args.log_file, args.verbose)
    cfg = build_config(args)
    cfg.validate()
    logger.info("Connect requested: protocol=%s mode=%s", cfg.protocol.value, cfg.mode.value)
    safety_warnings(cfg, logger)

    saved_v4: list[str] = []
    saved_v6: list[str] = []

    rules = build_nft_rules(cfg)
    apply_nft(rules, dry_run=args.dry_run, logger=logger)

    if cfg.force_default_route and cfg.mode in (WorkMode.TUN, WorkMode.TUN_SYSTEM_PROXY):
        saved_v4, saved_v6 = force_default_route_to_tun(cfg, args.dry_run, logger)

    if cfg.mode in (WorkMode.SYSTEM_PROXY, WorkMode.TUN_SYSTEM_PROXY):
        configure_system_proxy(cfg.system_proxy_host, cfg.system_proxy_port, args.dry_run, logger)

    core_cmd = args.core_cmd if args.core_cmd else args.core_cmd_positional
    core_cmd = normalize_core_cmd(core_cmd)

    if not core_cmd:
        logger.info("Guard applied; no core command specified")
        return 0

    resolved_binary = ensure_core_available(core_cmd, args.auto_install_core, args.dry_run, logger)
    if resolved_binary and core_cmd:
        core_cmd[0] = resolved_binary

    if args.dry_run:
        logger.info("Dry-run: would run core command: %s", shlex.join(core_cmd))
        print(shlex.join(core_cmd))
        return 0

    try:
        return run_core(
            core_cmd,
            logger,
            verify_egress_ip=args.verify_egress_ip,
            expected_ip=cfg.server_ip,
            verify_retries=args.verify_retries,
            verify_interval_sec=args.verify_interval_sec,
            verify_timeout_sec=args.verify_timeout_sec,
        )
    finally:
        if args.cleanup_on_exit:
            if cfg.mode in (WorkMode.SYSTEM_PROXY, WorkMode.TUN_SYSTEM_PROXY):
                clear_system_proxy(dry_run=args.dry_run, logger=logger)
            if cfg.force_default_route and cfg.mode in (WorkMode.TUN, WorkMode.TUN_SYSTEM_PROXY):
                restore_default_routes(saved_v4, saved_v6, args.dry_run, logger)
            clear_nft(dry_run=args.dry_run, logger=logger)


def cmd_disconnect(args: argparse.Namespace) -> int:
    logger = setup_logger(args.log_file, args.verbose)

    if args.mode in (WorkMode.SYSTEM_PROXY.value, WorkMode.TUN_SYSTEM_PROXY.value):
        clear_system_proxy(dry_run=args.dry_run, logger=logger)

    if args.force_default_route and args.tunnel_iface:
        # best-effort: remove forced route by dropping tunnel default if present
        run_command(["ip", "-4", "route", "del", "default", "dev", args.tunnel_iface], args.dry_run, logger)
        run_command(["ip", "-6", "route", "del", "default", "dev", args.tunnel_iface], args.dry_run, logger, ignore_error=True)

    clear_nft(dry_run=args.dry_run, logger=logger)
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    cfg = build_config(args)
    cfg.validate()
    print(build_nft_rules(cfg), end="")
    return 0


def _add_global(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--log-file", default="", help="Path to log file")
    parser.add_argument("--verbose", action="store_true")


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--protocol", choices=[p.value for p in Protocol], required=True)
    parser.add_argument("--mode", choices=[m.value for m in WorkMode], required=True)
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--server-port", required=True, type=int)
    parser.add_argument("--uplink-iface", required=True)
    parser.add_argument("--tunnel-iface", default="")
    parser.add_argument("--system-proxy-host", default="127.0.0.1")
    parser.add_argument("--system-proxy-port", default=1080, type=int)
    parser.add_argument("--allow-lan", default="", help="Comma-separated CIDRs")
    parser.add_argument("--force-default-route", action="store_true", help="Route all traffic via tunnel interface")
    parser.add_argument("--dry-run", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hardened multi-protocol VPN wrapper")
    sub = parser.add_subparsers(dest="command", required=True)

    connect = sub.add_parser("connect", help="Apply guard and run VPN core")
    _add_global(connect)
    _add_common(connect)
    connect.add_argument(
        "--core-cmd",
        nargs=argparse.REMAINDER,
        help="Command for VPN core (legacy form)",
    )
    connect.add_argument(
        "core_cmd_positional",
        nargs=argparse.REMAINDER,
        help="Command for VPN core (preferred: append after --, e.g. -- sing-box run -c config.json)",
    )
    connect.add_argument("--cleanup-on-exit", action="store_true")
    connect.add_argument("--auto-install-core", action="store_true", help="Auto-install sing-box if missing")
    connect.add_argument("--verify-egress-ip", dest="verify_egress_ip", action="store_true", help="Verify that public IP matches configured server IP")
    connect.add_argument("--no-verify-egress-ip", dest="verify_egress_ip", action="store_false", help="Disable post-connect egress IP verification")
    connect.add_argument("--verify-retries", type=int, default=10)
    connect.add_argument("--verify-interval-sec", type=float, default=2.0)
    connect.add_argument("--verify-timeout-sec", type=int, default=10)
    connect.set_defaults(func=cmd_connect, verify_egress_ip=True)

    disconnect = sub.add_parser("disconnect", help="Remove guard and optional proxy")
    _add_global(disconnect)
    disconnect.add_argument("--mode", choices=[m.value for m in WorkMode], required=True)
    disconnect.add_argument("--tunnel-iface", default="")
    disconnect.add_argument("--force-default-route", action="store_true")
    disconnect.add_argument("--dry-run", action="store_true")
    disconnect.set_defaults(func=cmd_disconnect)

    render = sub.add_parser("render-rules", help="Print nftables rules")
    _add_common(render)
    render.set_defaults(func=cmd_render)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
