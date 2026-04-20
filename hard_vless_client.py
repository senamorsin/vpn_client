#!/usr/bin/env python3
"""Hardened multi-protocol VPN client wrapper with leak-prevention controls."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import shlex
import signal
import subprocess
import sys
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


def get_default_routes(family: str) -> list[str]:
    out = subprocess.run(
        ["ip", family, "route", "show", "default"],
        check=False,
        capture_output=True,
        text=True,
    )
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


def force_default_route_to_tun(cfg: GuardConfig, dry_run: bool, logger: logging.Logger) -> tuple[list[str], list[str]]:
    """Force default traffic through TUN and return previous routes for rollback."""
    saved_v4 = get_default_routes("-4")
    saved_v6 = get_default_routes("-6")

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


def run_core(command: list[str], logger: logging.Logger) -> int:
    logger.info("Starting core: %s", shlex.join(command))
    proc = subprocess.Popen(command)

    def forward(sig: int, _frame: object) -> None:
        if proc.poll() is None:
            logger.info("Forward signal %s to core process", sig)
            proc.send_signal(sig)

    signal.signal(signal.SIGINT, forward)
    signal.signal(signal.SIGTERM, forward)
    exit_code = proc.wait()
    logger.info("Core exited with code %s", exit_code)
    return exit_code


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

    if not args.core_cmd:
        logger.info("Guard applied; no core command specified")
        return 0

    try:
        return run_core(args.core_cmd, logger)
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
        help="Command for VPN core (prefix with --, e.g. -- sing-box run -c config.json)",
    )
    connect.add_argument("--cleanup-on-exit", action="store_true")
    connect.set_defaults(func=cmd_connect)

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
