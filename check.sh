#!/usr/bin/env bash
# ============================================================================
#  Web 面板外网访问诊断
#
#  用法（在 VPS 上）：
#     bash check.sh              # 诊断默认 8080 端口
#     bash check.sh 9000         # 诊断指定端口
#
#  它会从「服务是否在跑」一路查到「公网能不能连上」，逐项告诉你卡在哪。
# ============================================================================
PORT="${1:-}"
UNIT="/etc/systemd/system/cfip-web.service"
OK=$'\033[32m ✓\033[0m'; NO=$'\033[31m ✗\033[0m'; WARN=$'\033[33m !\033[0m'
BLD=$'\033[1m'; RST=$'\033[0m'

# 没给端口就从 unit 文件里读 —— 装的时候经常用的是非标端口，
# 手动传错端口会导致诊断结果全是误导。
UNIT_PORT=""
if [ -f "$UNIT" ]; then
  UNIT_PORT=$(grep -oP '(?<=-port )\d+' "$UNIT" 2>/dev/null | head -1)
fi
if [ -z "$PORT" ]; then
  PORT="${UNIT_PORT:-8080}"
fi

echo "${BLD}============================================================${RST}"
echo "${BLD}  Web 面板外网访问诊断 · 端口 ${PORT}${RST}"
if [ -f "$UNIT" ] && [ -z "${1:-}" ]; then
  echo "  （端口是从 $UNIT 自动读出来的，也可手动指定：bash check.sh 9000）"
fi
echo "${BLD}============================================================${RST}"
echo

# ---------------------------------------------------------------- 1. 服务
echo "${BLD}[1] systemd 服务${RST}"
if [ ! -f "$UNIT" ]; then
  echo "${NO} 找不到 $UNIT —— Web 面板没装，或装到了别处"
  echo "    重装：bash install.sh  然后选「开 Web 面板」"
else
  echo "  单元文件：$UNIT"
  # 注意：不能用 [ "$(systemctl is-active X)" = "active" ] 来判断 ——
  # systemctl 的输出是【本地化】的，中文系统上会返回「运行中」/「失败」，
  # 跟英文 "active" 比较永远不相等，会把正在跑的服务误报成挂了。
  # 正确做法是用 --quiet 看退出码，跟语言无关。
  if systemctl is-active --quiet cfip-web.service 2>/dev/null; then
    ACTIVE="active"
  else
    ACTIVE="inactive"
  fi
  if systemctl is-enabled --quiet cfip-web.service 2>/dev/null; then
    ENABLED="enabled"
  else
    ENABLED="disabled"
  fi
  if [ "$ACTIVE" = "active" ]; then
    echo "${OK} 运行中（开机自启：$ENABLED）"
  else
    echo "${NO} 没在跑 —— 这就是外网打不开的直接原因"
    echo
    echo "  ${BLD}服务日志（最后 25 行，失败原因通常就在这里）${RST}"
    journalctl -u cfip-web -n 25 --no-pager 2>/dev/null | sed 's/^/    /'
    echo
    echo "    试着启动： systemctl start cfip-web"
    echo "    再看日志： journalctl -u cfip-web -n 50 --no-pager"
  fi
  echo "  ExecStart："
  grep -E '^ExecStart' "$UNIT" | sed 's/^/    /'

  # 监听地址是不是 0.0.0.0
  if grep -q -- '-host 0\.0\.0\.0' "$UNIT"; then
    echo "${OK} 监听 0.0.0.0（对外）"
  else
    echo "${NO} 监听的是 127.0.0.1（只本机）—— 这就是外网连不上的直接原因"
    echo "    修法一：编辑 $UNIT，把 -host 127.0.0.1 改成 -host 0.0.0.0"
    echo "            systemctl daemon-reload && systemctl restart cfip-web"
    echo "    修法二：重跑 bash install.sh，Web 面板那步选「对外开放(2)」"
  fi
fi
echo

# ---------------------------------------------------------------- 2. 监听
echo "${BLD}[2] 端口监听${RST}"
if command -v ss >/dev/null 2>&1; then
  L=$(ss -lntp 2>/dev/null | grep -E "[:.]${PORT}\b")
elif command -v netstat >/dev/null 2>&1; then
  L=$(netstat -lntp 2>/dev/null | grep -E "[:.]${PORT}\b")
else
  L=""
fi
if [ -n "$L" ]; then
  echo "$L" | sed 's/^/  /'
  if echo "$L" | grep -q '0\.0\.0\.0\|\[::\]\|\*:'; then
    echo "${OK} 在 0.0.0.0 上监听（所有网卡都收）"
  else
    echo "${NO} 只在 127.0.0.1 上监听 —— 外网连不上"
  fi
else
  echo "${NO} 没有进程在监听 ${PORT}"
  echo "    看看日志：journalctl -u cfip-web -n 30"
fi
echo

# ---------------------------------------------------------------- 3. 本机自测
echo "${BLD}[3] 本机自测${RST}"
if command -v curl >/dev/null 2>&1; then
  C=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/healthz" 2>/dev/null)
  [ "$C" = "200" ] && echo "${OK} http://127.0.0.1:${PORT}/healthz -> 200" \
                   || echo "${NO} 本机都连不上（HTTP ${C:-000}）—— 服务本身有问题"
else
  echo "${WARN} 没有 curl，跳过"
fi
echo

# ---------------------------------------------------------------- 4. 系统防火墙
echo "${BLD}[4] 系统防火墙${RST}"
FOUND=0
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  FOUND=1
  echo "  ufw 已启用："
  ufw status | grep -E "^${PORT}|^${PORT}/" | sed 's/^/    /' || true
  if ufw status | grep -qE "^${PORT}(/tcp)?\s+ALLOW"; then
    echo "${OK} ufw 已放行 ${PORT}"
  else
    echo "${NO} ufw 没放行 ${PORT} —— 执行： ufw allow ${PORT}/tcp"
  fi
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
  FOUND=1
  if firewall-cmd --list-ports 2>/dev/null | grep -q "${PORT}/tcp"; then
    echo "${OK} firewalld 已放行 ${PORT}"
  else
    echo "${NO} firewalld 没放行 ${PORT} —— 执行："
    echo "      firewall-cmd --permanent --add-port=${PORT}/tcp && firewall-cmd --reload"
  fi
fi
if command -v iptables >/dev/null 2>&1; then
  if iptables -L INPUT -n 2>/dev/null | grep -qE "DROP|REJECT"; then
    FOUND=1
    echo "  iptables INPUT 链有 DROP/REJECT 规则："
    iptables -L INPUT -n --line-numbers 2>/dev/null | head -12 | sed 's/^/    /'
    echo "    如果默认策略是 DROP 且没有放行 ${PORT}，外网就连不上"
  fi
fi
[ "$FOUND" = "0" ] && echo "${OK} 没检测到启用的系统防火墙（或没有相关规则）"
echo

# ---------------------------------------------------------------- 5. 云厂商安全组
echo "${BLD}[5] 云厂商防火墙 / 安全组（最容易漏的一环）${RST}"
# 从主机名也能看出厂商 —— 很多便宜 VPS 的 hostname 就是 <随机>.厂商域名
HOSTN=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "")
VENDOR=""
[ -f /sys/class/dmi/id/product_name ] && VENDOR=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
COMBINED="$VENDOR $HOSTN"
CLOUD=""
case "$COMBINED" in
  *bytevirt*)   CLOUD="ByteVirt —— 客户面板 → 防火墙/Firewall → 放行 TCP ${PORT}" ;;
  *racknerd*)   CLOUD="RackNerd —— SolusVM 面板 → Firewall → 放行 TCP ${PORT}" ;;
  *vultr*)      CLOUD="Vultr —— 控制台 → Firewall → Add Rule → TCP ${PORT}" ;;
  *digitalocean*|*droplet*) CLOUD="DigitalOcean —— Networking → Firewalls → Inbound → TCP ${PORT}" ;;
  *linode*|*akamai*)        CLOUD="Linode —— Cloud Manager → Firewalls → Inbound → TCP ${PORT}" ;;
  *oracle*|*oci*)           CLOUD="Oracle Cloud —— VCN → Security Lists → Ingress → TCP ${PORT}（还有 iptables！OCI 镜像默认开着 iptables）" ;;
  *Alibaba*|*ecs*)          CLOUD="阿里云 ECS —— ECS 控制台 → 安全组 → 配置规则 → 入方向 → 添加 TCP ${PORT}/0.0.0.0/0" ;;
  *Tencent*|*CVM*)          CLOUD="腾讯云 —— 控制台 → 防火墙/安全组 → 添加 TCP ${PORT}" ;;
  *Huawei*)                 CLOUD="华为云 —— ECS → 安全组 → 入方向规则 → 添加 TCP ${PORT}" ;;
  *Amazon*|*AWS*|*ec2*)     CLOUD="AWS —— EC2 → Security Groups → Inbound → Custom TCP ${PORT}" ;;
  *)                        CLOUD="你的云控制台 → 安全组/防火墙 → 入方向放行 TCP ${PORT}" ;;
esac
[ -n "$HOSTN" ] && echo "  主机名：$HOSTN"
[ -n "$VENDOR" ] && echo "  DMI   ：$VENDOR"
echo "${WARN} ${CLOUD}"
echo "    ⚠ 这是在云控制台里改的，操作系统里改了没用。"
echo

# ---------------------------------------------------------------- 6. 公网自测
echo "${BLD}[6] 从公网侧自测${RST}"
PUB=$(curl -sS --max-time 8 https://api.ipify.org 2>/dev/null \
      || curl -sS --max-time 8 https://ifconfig.me 2>/dev/null \
      || curl -sS --max-time 8 https://ipinfo.io/ip 2>/dev/null)
PC="000"
if [ -n "$PUB" ]; then
  echo "  本机公网 IP：$PUB"
  PC=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 "http://${PUB}:${PORT}/healthz" 2>/dev/null)
  if [ "$PC" = "200" ]; then
    echo "${OK} 从公网 IP 能连上 —— 服务侧没问题"
    echo "    如果浏览器还是打不开，检查："
    echo "      1) 面板地址要带 token： http://${PUB}:${PORT}/?token=你的口令"
    echo "      2) 本机防火墙/杀毒软件"
  else
    echo "${NO} 从公网 IP 连不上（HTTP $C）"
    echo "    服务在跑、本机也能连，说明【被挡在中间了】—— 基本就是："
    echo "      · 云厂商安全组没放行 ${PORT}   ← 最常见"
    echo "      · 系统防火墙没放行 ${PORT}"
    echo "      · 运营商封了这个端口（换个端口试试，比如 18080）"
  fi
else
  echo "${WARN} 取不到公网 IP（可能是网络受限），手动测："
  echo "    curl -v http://你的公网IP:${PORT}/healthz"
fi
echo

# ---------------------------------------------------------------- 7. token
echo "${BLD}[7] 访问口令${RST}"
if [ -f "$UNIT" ]; then
  T=$(grep -oP '(?<=-token )\S+' "$UNIT" 2>/dev/null)
  if [ -n "$T" ]; then
    echo "  口令：${T:0:6}…（完整值在 $UNIT 里）"
    echo "  完整访问地址： http://<你的公网IP>:${PORT}/?token=${T}"
  else
    echo "${WARN} 单元文件里没找到 -token —— 如果监听 0.0.0.0 会拒绝启动，检查日志"
  fi
fi
echo
echo "${BLD}============================================================${RST}"
echo "${BLD}  结论${RST}"
echo "${BLD}============================================================${RST}"

# 汇总各环节，给出唯一该做的那件事
SVC_OK=0; [ -f "$UNIT" ] && systemctl is-active --quiet cfip-web.service 2>/dev/null && SVC_OK=1
LISTEN_OK=0; [ -n "$L" ] && echo "$L" | grep -q '0\.0\.0\.0\|\[::\]\|\*:' && LISTEN_OK=1
LOCAL_OK=0; [ "${C:-000}" = "200" ] && LOCAL_OK=1
PUB_OK=0; [ "${PC:-000}" = "200" ] && PUB_OK=1

if [ "$SVC_OK" = "0" ]; then
  echo "  ${NO} 服务没在跑 —— 先解决这个，看上面 [1] 里的日志"
  echo "      systemctl start cfip-web && journalctl -u cfip-web -n 50 --no-pager"
elif [ "$LISTEN_OK" = "0" ]; then
  echo "  ${NO} 服务在跑但没在 0.0.0.0 上监听 —— 改 unit 文件里的 -host"
elif [ "$LOCAL_OK" = "0" ]; then
  echo "  ${NO} 本机都连不上 —— 服务本身有问题，看 journalctl -u cfip-web"
elif [ "$PUB_OK" = "1" ]; then
  echo "  ${OK} 服务侧全部正常，公网也能连上"
  echo "      浏览器打不开的话，确认地址带 token："
  echo "      http://<你的公网IP>:${PORT}/?token=你的口令"
elif [ "$PORT" != "$UNIT_PORT" ] && [ -n "$UNIT_PORT" ]; then
  echo "  ${NO} 你在检查端口 ${PORT}，但服务实际监听的是 ${UNIT_PORT} —— 端口传错了"
  echo "      bash check.sh ${UNIT_PORT}"
else
  echo "  ${WARN} 服务在跑、监听正常、本机也能连，但公网连不上"
  echo "      → 【被挡在中间了】，按可能性排序："
  echo "        1. 云厂商防火墙/安全组没放行 ${PORT}   ← 八成是这个"
  echo "        2. 系统防火墙（上面 [4] 已查）"
  echo "        3. 运营商封了这个端口 → 换个端口，比如 18080 或 30502"
  echo
  echo "      验证是不是安全组问题：临时换一个端口试试"
  echo "        sed -i 's/-port ${PORT}/-port 18080/' $UNIT"
  echo "        systemctl daemon-reload && systemctl restart cfip-web"
  echo "        bash check.sh 18080"
  echo "      如果 18080 通了，说明 ${PORT} 被挡了（安全组或运营商）。"
fi

echo
echo "${BLD}  最省事的替代方案：不开公网，用 SSH 端口转发${RST}"
echo "    在你自己的电脑上： ssh -L ${PORT}:127.0.0.1:${PORT} root@你的VPS"
echo "    然后浏览器打开：   http://127.0.0.1:${PORT}/?token=你的口令"
echo "  面板永远不暴露在公网，不用碰安全组，比开公网安全得多。"
echo "${BLD}============================================================${RST}"
