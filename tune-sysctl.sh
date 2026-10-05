#!/usr/bin/env bash
# ============================================================================
#  内核参数调优 —— 让高并发扫描不把系统拖垮
#
#  用法（root）：bash tune-sysctl.sh          # 应用并持久化
#                bash tune-sysctl.sh --dry-run # 只看会改什么
#
#  为什么需要：
#    实测扫描把 726MB 的机器榨干，SSH 连上立刻被断开，只能硬重启。
#    根因是内核给每个 socket 默认预留 208KB 收 + 208KB 发缓冲，
#    3000 并发就是 1.2GB —— 远超机器内存。
#    脚本里已经把 socket 缓冲压到 16KB，但内核还有几张表默认值偏小。
# ============================================================================
set -e
DRY=0
[ "$1" = "--dry-run" ] && DRY=1

# 要改的参数：值 说明
SETTINGS="
net.ipv4.tcp_max_orphans=65536|孤儿 socket 上限。默认 4096 太小，高并发时内核会 RST 连接
net.ipv4.tcp_max_tw_buckets=65536|TIME_WAIT 桶上限。默认 4096，超了立刻回收
net.ipv4.ip_local_port_range=10000 65535|临时端口范围。默认 28232 个，扩到 55536 个
net.ipv4.tcp_tw_reuse=2|TIME_WAIT 可复用于新连接
net.ipv4.tcp_fin_timeout=15|TIME_WAIT 保持时间，默认 60s 偏长
net.ipv4.tcp_max_syn_backlog=1024|SYN 队列。默认 128，SSH 都可能被挤掉
net.core.somaxconn=1024|accept 队列
net.ipv4.tcp_syncookies=1|SYN flood 保护
"

echo "==> 当前值 / 目标值"
CHANGED=0
printf '%s\n' "$SETTINGS" | while IFS='|' read -r kv desc; do
  [ -z "$kv" ] && continue
  key="${kv%%=*}"; val="${kv#*=}"
  cur=$(sysctl -n "$key" 2>/dev/null || echo "?")
  if [ "$cur" = "$val" ]; then
    printf '  %-34s %-16s (已是目标值)\n' "$key" "$cur"
  else
    printf '  %-34s %-16s -> %s\n' "$key" "$cur" "$val"
    printf '      %s\n' "$desc"
  fi
done

if [ "$DRY" = "1" ]; then
  echo
  echo "  （--dry-run，没有实际修改）"
  exit 0
fi

echo
echo "==> 应用"
printf '%s\n' "$SETTINGS" | while IFS='|' read -r kv desc; do
  [ -z "$kv" ] && continue
  key="${kv%%=*}"; val="${kv#*=}"
  sysctl -w "$key=$val" >/dev/null 2>&1 && echo "  ✓ $key = $val" || echo "  ✗ $key（内核不支持，跳过）"
done

echo
echo "==> 持久化到 /etc/sysctl.d/99-cfip.conf"
{
  echo "# Cloudflare 反代 IP 优选 —— 高并发扫描的内核参数调优"
  echo "# 由 tune-sysctl.sh 生成"
  printf '%s\n' "$SETTINGS" | while IFS='|' read -r kv desc; do
    [ -z "$kv" ] && continue
    echo "# $desc"
    echo "${kv%%=*} = ${kv#*=}"
  done
} > /etc/sysctl.d/99-cfip.conf
echo "  ✓ 已写入（重启后仍然生效）"

echo
echo "==> 同时限制 systemd 日志大小（扫描期间日志涨得很快）"
if [ -f /etc/systemd/journald.conf ]; then
  if grep -q '^SystemMaxUse=' /etc/systemd/journald.conf; then
    sed -i 's/^SystemMaxUse=.*/SystemMaxUse=100M/' /etc/systemd/journald.conf
  else
    echo 'SystemMaxUse=100M' >> /etc/systemd/journald.conf
  fi
  systemctl restart systemd-journald 2>/dev/null || true
  journalctl --vacuum-size=100M >/dev/null 2>&1 || true
  echo "  ✓ journal 上限 100M"
fi

echo
echo "==> 完成。建议重启 cfip 让新参数生效："
echo "    systemctl restart cfip"
