# ShockNet VPN

Self-hosted VPN service based on Xray/VLESS+Reality, with a Telegram access-management bot, a subscription web panel, Nginx TLS termination, and visitor analytics.

The repository is deliberately safe to publish: it contains no server keys, user UUIDs, bot tokens, live configurations, databases, or logs. The installer generates fresh credentials on the target server.

## Components

| Component | Purpose |
| --- | --- |
| `xray/` | Primary VLESS endpoints: Reality (4443), HAPP/mobile (2053), and WebSocket behind Nginx |
| `xray2/` | Additional Reality endpoints on 8443–8446, using alternate SNI domains |
| `bot/` | Telegram bot that approves users and adds/removes them in both Xray configurations |
| `webserver/` | Subscription links, QR pages, Clash YAML, admin dashboard, and traffic display |
| `log-monitor/` | Nginx visitor-log analytics with local GeoIP cache |
| `systemd/` | Units for Xray, bot, panel, and monitoring |

## Requirements

- A new Ubuntu 22.04 or 24.04 server with root access.
- A public IPv4 address and a domain whose `A` record already points to the server.
- A Telegram bot token, its username, and the administrator's Telegram username.
- TCP ports `80`, `443`, `2053`, `4443`, and `8443–8446` open in the firewall/provider panel.

## Installation

Clone this repository, then run the installer as root:

```bash
git clone https://github.com/dmitriyshock/shocknet-vpn.git /tmp/shocknet-vpn
sudo bash /tmp/shocknet-vpn/setup.sh
```

The script installs OS and Python dependencies into `/opt/vpnserver/venv`, downloads Xray, creates fresh Reality keys and an initial administrator profile, obtains a Let's Encrypt certificate, configures Nginx, and enables five services. It asks for secrets without echoing the bot token. Generated secrets are stored only in `/opt/vpnserver/.env` (`0600`).

To update an existing installation, run the same command again. It preserves `.env` and Xray client configurations while updating application files and restarting services.

## Operations

```bash
systemctl status xray xray2 vpnbot subserver log-monitor
journalctl -u vpnbot -f
journalctl -u xray -f
```

The web panel is available at `https://YOUR_DOMAIN`; the Telegram login-protected dashboard is at `/admin`. The bot issues access through its approval flow and updates both Xray instances automatically.

## Security notes

- Do not commit `/opt/vpnserver/.env`, `/opt/xray*/config.json`, bot user data, logs, or databases. `.gitignore` covers these files.
- Back up `/opt/vpnserver/.env`, `/opt/xray/config.json`, `/opt/xray2/config.json`, and `/opt/vpnbot/users.json` securely before rebuilding a server.
- Rotate any credential that was ever present in a Git remote URL, configuration file, terminal history, or chat.
- This project is intended for lawful use and is operated at the administrator's responsibility.
