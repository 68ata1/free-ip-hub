#!/usr/bin/env bash
# resi-agent 完全卸载：停止服务、清理路由 / tun 设备、删除程序与配置
set -uo pipefail

[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }

echo "[1/5] 停止并禁用服务"
systemctl stop resi-agent 2>/dev/null || true
systemctl disable resi-agent 2>/dev/null || true

echo "[2/5] 结束残留的 openvpn 进程"
pkill -f "openvpn --config /opt/resi-agent/current.ovpn" 2>/dev/null || true
sleep 1

echo "[3/5] 清理策略路由与 tun 设备"
for _ in 1 2 3; do ip rule del oif tun_rp lookup 100 2>/dev/null || true; done
ip route flush table 100 2>/dev/null || true
ip link del tun_rp 2>/dev/null || true

echo "[4/5] 删除服务文件、配置与程序目录"
rm -f /etc/systemd/system/resi-agent.service /etc/resi-agent.env
rm -rf /opt/resi-agent
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

echo "[5/5] 完成"
echo "已完全卸载 resi-agent。依赖包（openvpn / python3 等）未删除，如不需要可自行 apt remove。"
echo "请回到面板，在「节点」列表点「删除」移除该节点记录。"
