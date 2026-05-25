# Termux Relay Agent

این پوشه یک نسخه standalone از relay agent است و برای اجرا روی گوشی به کل ریپوی اصلی نیاز ندارد.

## نیازمندی‌ها

- Python 3.11+
- Termux
- پکیج‌های `httpx` و `cryptography`

## نصب در Termux

```bash
pkg update
pkg install python git
git clone <TEMP_REPO_URL> termux-relay-agent
cd termux-relay-agent
pip install -r requirements.txt
chmod +x run_forever.sh
```

## اجرای دائم

```bash
export SERVER_URL="https://example.com"
export RELAY_SECRET="YOUR_VPN_RELAY_SHARED_SECRET"
export AGENT_NAME="termux-ir-1"
export POLL_SECONDS="2"
./run_forever.sh
```

## اجرای خودکار بعد از reboot

اپ `Termux:Boot` را نصب کن، بعد:

```bash
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/start-relay.sh <<'SH'
#!/data/data/com.termux/files/usr/bin/bash
export SERVER_URL="https://example.com"
export RELAY_SECRET="YOUR_VPN_RELAY_SHARED_SECRET"
export AGENT_NAME="termux-ir-1"
export POLL_SECONDS="2"
cd "$HOME/termux-relay-agent"
nohup ./run_forever.sh >> "$HOME/.vpn-relay-agent/bootstrap.log" 2>&1 &
SH
chmod +x ~/.termux/boot/start-relay.sh
```

## لاگ

```bash
tail -f ~/.vpn-relay-agent/agent.log
```