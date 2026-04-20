# Hardened Multi-Protocol VPN Client Wrapper

This project provides a hardened controller around VPN/proxy cores (for example `sing-box` / `xray`) to reduce IP/DNS leak risk.

## Supported protocols

- VLESS
- VMess
- Trojan
- Shadowsocks
- Hysteria2

> This tool does not re-implement these protocols. It orchestrates an existing core and enforces guardrails.

## Modes

- `tun` — tunnel routing mode.
- `system-proxy` — system SOCKS proxy mode.
- `tun-system-proxy` — both at the same time (like many existing clients).

## Key features

- nftables kill-switch (`inet vpn_guard`, default-drop output policy)
- optional **force default route via TUN** (`--force-default-route`) to push all traffic through the tunnel
- optional GNOME system proxy configuration (`gsettings`)
- logging to stdout and file (`--log-file`)
- cleanup on exit and disconnect helpers

## Examples

### Full-tunnel with TUN + System Proxy

```bash
sudo python3 hard_vless_client.py connect \
  --protocol vless \
  --mode tun-system-proxy \
  --server-ip 203.0.113.10 \
  --server-port 443 \
  --uplink-iface eth0 \
  --tunnel-iface tun0 \
  --system-proxy-host 127.0.0.1 \
  --system-proxy-port 1080 \
  --force-default-route \
  --cleanup-on-exit \
  --log-file ./logs/client.log \
  -- sing-box run -c /etc/sing-box/config.json
```

### Render rules before applying

```bash
python3 hard_vless_client.py render-rules \
  --protocol vless \
  --mode tun-system-proxy \
  --server-ip 203.0.113.10 \
  --server-port 443 \
  --uplink-iface eth0 \
  --tunnel-iface tun0
```

## PyQt UI

```bash
pip install PyQt6
python3 hard_vless_client_ui.py
```

UI supports `tun-system-proxy` mode and the `Force default route via TUN` toggle.

## Safety notes

- After any config change, run leak checks for **IP + DNS + IPv6 + WebRTC**.
- Browser WebRTC can leak host candidates in proxy scenarios; harden browser settings too.
- Prefer clients/configurations that support strict routing and traffic redirection in TUN mode.
