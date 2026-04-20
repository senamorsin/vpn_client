#!/usr/bin/env python3
"""Hardened multi-protocol VPN client wrapper with leak-prevention controls.

The tool does not implement protocols itself; it wraps an existing core process
(e.g. sing-box / xray) and applies strict egress policy + optional system proxy
configuration.
"""

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

TABLE_NAME = "vless_guard"


class Protocol(str, Enum):
    VLESS = "vless"
    VMESS = "vmess"
    TROJAN = "trojan"
    SHADOWSOCKS = "shadowsocks"
    HYSTERIA2 = "hysteria2"


class WorkMode(str, Enum):
    TUN = "tun"
    SYSTEM_PROXY = "system-proxy"


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

    def validate(self) -> None:
        ipaddress.ip_address(self.server_ip)
        if not (1 <= self.server_port <= 65535):
            raise ValueError("server_port must be in range 1..65535")
        if not self.uplink_iface:
            raise ValueError("uplink_iface is required")

        if self.mode == WorkMode.TUN and not self.tunnel_iface:
            raise ValueError("tunnel_iface is required for tun mode")

        if self.mode == WorkMode.SYSTEM_PROXY:
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


def build_nft_rules(cfg: GuardConfig) -> str:
    allow_lan_lines = "\n".join(
        f"  ip daddr {cidr} accept" for cidr in cfg.allow_lan_cidr
    )

    mode_allow = (
        f'  oifname "{cfg.tunnel_iface}" accept\n'
        if cfg.mode == WorkMode.TUN
        else "  # System proxy mode: direct egress allowed only to proxy endpoint.\n"
        f"  ip daddr {cfg.system_proxy_host} tcp dport {cfg.system_proxy_port} accept\n"
    )

    return f"""
flush table inet {TABLE_NAME}
table inet {TABLE_NAME} {{
 chain output {{
  type filter hook output priority 0;
  policy drop;

  ct state established,related accept
  oifname \"lo\" accept

  # Work mode policy.
{mode_allow.rstrip()}

  # Allow connection to upstream VPN server (control/data plane to uplink).
  oifname \"{cfg.uplink_iface}\" ip daddr {cfg.server_ip} tcp dport {cfg.server_port} accept
  oifname \"{cfg.uplink_iface}\" ip daddr {cfg.server_ip} udp dport {cfg.server_port} accept

  # Optional local network access.
{allow_lan_lines if allow_lan_lines else '  # (no LAN CIDRs configured)'}
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
            logger.info("Dry-run: nft table delete command printed")
        return
    subprocess.run(cmd, check=False)
    if logger:
        logger.info("Removed nftables guard table")


def configure_system_proxy(
    host: str,
    port: int,
    dry_run: bool,
    logger: logging.Logger,
) -> None:
    """Configure GNOME proxy settings if gsettings exists."""
    cmds = [
        ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"],
        ["gsettings", "set", "org.gnome.system.proxy.socks", "host", host],
        ["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(port)],
    ]

    if dry_run:
        for cmd in cmds:
            print(shlex.join(cmd))
        logger.info("Dry-run: system proxy commands printed")
        return

    if not shutil_which("gsettings"):
        logger.warning("gsettings not found; skipping system proxy setup")
        return

    for cmd in cmds:
        subprocess.run(cmd, check=True)
    logger.info("Configured system proxy to %s:%s", host, port)


def clear_system_proxy(dry_run: bool, logger: logging.Logger) -> None:
    cmd = ["gsettings", "set", "org.gnome.system.proxy", "mode", "none"]
    if dry_run:
        print(shlex.join(cmd))
        logger.info("Dry-run: clear system proxy command printed")
        return

    if not shutil_which("gsettings"):
        logger.warning("gsettings not found; skipping system proxy cleanup")
        return

    subprocess.run(cmd, check=False)
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
    )


def cmd_connect(args: argparse.Namespace) -> int:
    logger = setup_logger(args.log_file, args.verbose)
    cfg = build_config(args)
    cfg.validate()
    logger.info("Connect requested: protocol=%s mode=%s", cfg.protocol.value, cfg.mode.value)

    rules = build_nft_rules(cfg)
    apply_nft(rules, dry_run=args.dry_run, logger=logger)

    if cfg.mode == WorkMode.SYSTEM_PROXY:
        configure_system_proxy(
            host=cfg.system_proxy_host,
            port=cfg.system_proxy_port,
            dry_run=args.dry_run,
            logger=logger,
        )

    if not args.core_cmd:
        logger.info("Guard applied; no core command specified")
        return 0

    try:
        return run_core(args.core_cmd, logger)
    finally:
        if args.cleanup_on_exit:
            if cfg.mode == WorkMode.SYSTEM_PROXY:
                clear_system_proxy(dry_run=args.dry_run, logger=logger)
            clear_nft(dry_run=args.dry_run, logger=logger)


def cmd_disconnect(args: argparse.Namespace) -> int:
    logger = setup_logger(args.log_file, args.verbose)
    if args.mode == WorkMode.SYSTEM_PROXY.value:
        clear_system_proxy(dry_run=args.dry_run, logger=logger)
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
