#!/usr/bin/env bash
# resi-agent 一键安装（由 Worker 渲染，__HUB__ / __TOKEN__ 在下发时替换）
set -euo pipefail
HUB="__HUB__"
TOKEN="__TOKEN__"

[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }
[ -c /dev/net/tun ] || { echo "缺少 /dev/net/tun，请先在 VPS 控制台开启 TUN/TAP"; exit 1; }

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y openvpn python3 iproute2 curl iputils-ping
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y epel-release || true
  dnf install -y openvpn python3 iproute curl iputils
else
  echo "仅支持 Debian/Ubuntu/RHEL 系"; exit 1
fi

ver="$(openvpn --version | head -1 | awk '{print $2}')"
if [ "$(printf '%s\n2.5.0\n' "$ver" | sort -V | head -1)" != "2.5.0" ]; then
  echo "OpenVPN $ver 过旧，需要 >= 2.5（建议 Debian 11+/Ubuntu 22.04+）"; exit 1
fi

install -d -m 700 /opt/resi-agent
curl -fsSL -H "Authorization: Bearer $TOKEN" "$HUB/agent.py" -o /opt/resi-agent/agent.py

cat > /etc/resi-agent.env <<ENV
HUB_URL=$HUB
AGENT_TOKEN=$TOKEN
NODE_ID=$(hostname)
ENV
chmod 600 /etc/resi-agent.env

cat > /etc/systemd/system/resi-agent.service <<'UNIT'
[Unit]
Description=resi-agent
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/resi-agent.env
ExecStart=/usr/bin/python3 /opt/resi-agent/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable resi-agent
systemctl restart resi-agent
echo "已安装。查看日志: journalctl -u resi-agent -f"
echo "记得在 VPS 防火墙/安全组放行面板里设置的代理端口（默认 7920）。"
