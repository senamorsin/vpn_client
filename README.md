# Hardened Multi-Protocol VPN Client Wrapper

Этот репозиторий содержит безопасный клиент-контроллер, который уменьшает риск утечки реального IP через строгий egress-kill-switch.

## Поддерживаемые протоколы

- VLESS
- VMess
- Trojan
- Shadowsocks
- Hysteria2

> Важно: скрипт не реализует эти протоколы с нуля; он запускает ваш существующий core (`sing-box`, `xray`) и добавляет защитные механизмы.

## Поддерживаемые режимы

- **TUN mode** — разрешается трафик через интерфейс туннеля (`--tunnel-iface`).
- **System Proxy mode** — настраивается системный SOCKS proxy (GNOME `gsettings`) и разрешается трафик к proxy endpoint.

## Что делает

`hard_vless_client.py`:

- применяет `nftables` таблицу `inet vless_guard` с `policy drop` в `output`;
- оставляет только нужные allow-правила (loopback, VPN uplink endpoint, TUN или system proxy);
- поддерживает structured logging в stdout и файл (`--log-file`);
- умеет запускать core-команду и корректно передавать сигналы;
- умеет снимать guard и очищать system proxy в `disconnect`.

## Примеры

### 1) TUN mode

```bash
sudo python3 hard_vless_client.py connect \
  --protocol vless \
  --mode tun \
  --server-ip 203.0.113.10 \
  --server-port 443 \
  --uplink-iface eth0 \
  --tunnel-iface tun0 \
  --log-file ./logs/client.log \
  --cleanup-on-exit \
  -- sing-box run -c /etc/sing-box/config.json
```

### 2) System Proxy mode

```bash
sudo python3 hard_vless_client.py connect \
  --protocol trojan \
  --mode system-proxy \
  --server-ip 203.0.113.10 \
  --server-port 443 \
  --uplink-iface eth0 \
  --system-proxy-host 127.0.0.1 \
  --system-proxy-port 1080 \
  --cleanup-on-exit \
  -- xray -c /etc/xray/config.json
```

## Ограничения

- Для `nft` нужен root.
- Настройка system proxy сейчас реализована через GNOME `gsettings`.
- Рекомендуется дополнительно принудить DNS в туннель и обработать IPv6 отдельно.

## PyQt UI

Добавлен GUI-клиент `hard_vless_client_ui.py` на PyQt6:

- выбор протокола, режима и параметров подключения;
- запуск `connect`/`disconnect` без ручного ввода длинной CLI-команды;
- live-вывод логов процесса в окне;
- аккуратный современный интерфейс (карточки, стили, валидация базовых полей).

Запуск:

```bash
pip install PyQt6
python3 hard_vless_client_ui.py
```
