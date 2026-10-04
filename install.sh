#!/usr/bin/env bash
# ============================================================================
#  Cloudflare 反代 IP 优选 —— 一键安装脚本
#
#  用法（一行命令）：
#     curl -fsSL https://raw.githubusercontent.com/JuLuogo/CF-PY/main/install.sh | bash
#
#  也可以先下载再跑，方便看内容：
#     curl -fsSLO https://raw.githubusercontent.com/JuLuogo/CF-PY/main/install.sh
#     bash install.sh
#
#  安装过程会问你几个问题：怎么运行、扫哪些厂商、要不要开 Web 面板。
#  全部回车就是推荐配置。
# ============================================================================
set -uo pipefail

REPO_URL="${CFIP_REPO:-https://github.com/JuLuogo/CF-PY}"
INSTALL_DIR="${CFIP_DIR:-/opt/cfip}"
WEB_PORT_DEFAULT=8080

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYN=$'\033[36m'; BLD=$'\033[1m'; RST=$'\033[0m'
info() { printf '%s\n' "${CYN}==>${RST} $*"; }
ok()   { printf '%s\n' "${GRN} ✓${RST} $*"; }
warn() { printf '%s\n' "${YEL} !${RST} $*"; }
die()  { printf '%s\n' "${RED} ✗${RST} $*" >&2; exit 1; }

# 脚本是 curl | bash 执行的，stdin 是管道，交互必须走 /dev/tty。
#
# 但不能只看 /dev/tty 能不能打开 —— 在 CI、重定向、被别的脚本调用等
# 没有终端的环境里，/dev/tty 依然可以打开，`read` 就会永久阻塞。
# 判据：/dev/tty 是字符设备 **且 stdout 是终端**。
#   curl | bash（人在终端前）：stdout 是 tty  -> 交互
#   被脚本调用 / CI / 重定向日志：stdout 是管道 -> 全用默认值，不阻塞
if [ -c /dev/tty ] && [ -t 1 ] && [ "${CFIP_NONINTERACTIVE:-0}" != "1" ]; then
  TTY=/dev/tty
else
  TTY=""
fi

ask() {  # ask <提示> <默认值>
  local prompt="$1" def="$2" ans=""
  if [ -n "$TTY" ]; then
    printf '%s' "$prompt" > "$TTY" 2>/dev/null || true
    # 再兜一层超时：万一终端断了，也不至于卡死
    IFS= read -r -t "${CFIP_ASK_TIMEOUT:-120}" ans < "$TTY" || ans=""
  fi
  printf '%s' "${ans:-$def}"
}

ask_secret() {
  local prompt="$1" def="$2" ans=""
  if [ -n "$TTY" ]; then
    printf '%s' "$prompt" > "$TTY" 2>/dev/null || true
    IFS= read -r -t "${CFIP_ASK_TIMEOUT:-120}" ans < "$TTY" || ans=""
  fi
  printf '%s' "${ans:-$def}"
}

confirm() {  # confirm <提示> <y|n>
  local a
  a=$(ask "$1 [y/n] " "$2")
  case "$a" in y|Y|yes|YES) return 0;; *) return 1;; esac
}

# ---------------------------------------------------------------- 前置检查
[ "$(id -u)" = "0" ] || die "请用 root 运行（或 sudo bash install.sh）"

if [ -n "$TTY" ]; then
  printf '%s\n' "${BLD}============================================================${RST}" > "$TTY"
  printf '%s\n' "${BLD}  Cloudflare 反代 IP 优选 · 安装向导${RST}" > "$TTY"
  printf '%s\n' "${BLD}============================================================${RST}" > "$TTY"
fi

# ---------------------------------------------------------------- 系统识别
DISTRO=""; PKG=""
if [ -f /etc/os-release ]; then . /etc/os-release; DISTRO="${ID:-unknown}"; fi
case "$DISTRO" in
  debian|ubuntu|raspbian) PKG="apt";;
  centos|rhel|rocky|almalinux|fedora|openEuler|anolis) PKG="yum";;
  alpine) PKG="apk";;
  *) if command -v apt-get >/dev/null 2>&1; then PKG="apt"
     elif command -v dnf >/dev/null 2>&1; then PKG="yum"
     elif command -v apk >/dev/null 2>&1; then PKG="apk"
     else die "认不出包管理器，请手动装：python3 curl iputils-ping traceroute"; fi;;
esac
info "系统：${DISTRO}（包管理器 ${PKG}）"

install_pkgs() {
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get update -qq &&
         DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
    yum) if command -v dnf >/dev/null 2>&1; then dnf install -y -q "$@"; else yum install -y -q "$@"; fi ;;
    apk) apk add --no-cache "$@" ;;
  esac
}

# ---------------------------------------------------------------- 装依赖
info "安装依赖：python3 curl ping traceroute ..."
NEED=()
command -v python3 >/dev/null 2>&1 || NEED+=(python3)
command -v curl    >/dev/null 2>&1 || NEED+=(curl)
command -v ping    >/dev/null 2>&1 || NEED+=(iputils-ping)
command -v traceroute >/dev/null 2>&1 || NEED+=(traceroute)
[ ${#NEED[@]} -gt 0 ] && install_pkgs "${NEED[@]}" || true
# Alpine 的 ping/traceroute 包名不同
command -v ping >/dev/null 2>&1 || install_pkgs iputils 2>/dev/null || true
command -v traceroute >/dev/null 2>&1 || install_pkgs traceroute 2>/dev/null || true

command -v python3 >/dev/null 2>&1 || die "python3 装不上，请手动安装后重试"
PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
ok "python3 ${PYV}"

for c in curl ping traceroute; do
  command -v "$c" >/dev/null 2>&1 && ok "$c 就绪" || warn "$c 缺失 —— 对应功能会不可用"
done

# ---------------------------------------------------------------- 拉代码
info "下载项目到 ${INSTALL_DIR}"
mkdir -p "$(dirname "$INSTALL_DIR")"
if [ -d "$INSTALL_DIR/.git" ]; then
  git -C "$INSTALL_DIR" pull --ff-only >/dev/null 2>&1 && ok "已更新到最新" || warn "更新失败，用现有代码继续"
elif command -v git >/dev/null 2>&1 && git clone --depth 1 "$REPO_URL" "$INSTALL_DIR" >/dev/null 2>&1; then
  ok "git clone 完成"
else
  warn "git 不可用或仓库不可访问，改用 tarball 下载"
  TARBALL="${REPO_URL%.git}/archive/refs/heads/main.tar.gz"
  mkdir -p "$INSTALL_DIR"
  if curl -fsSL "$TARBALL" | tar -xz -C "$INSTALL_DIR" --strip-components=1; then
    ok "tarball 下载完成"
  else
    die "代码下载失败。请检查网络，或手动把项目文件放到 ${INSTALL_DIR}"
  fi
fi
[ -f "$INSTALL_DIR/fetch_ips.py" ] || die "${INSTALL_DIR} 里没有 fetch_ips.py，代码不完整"

# ---------------------------------------------------------------- 交互配置
printf '\n' > "${TTY:-/dev/null}" 2>/dev/null || true
info "下面几个问题决定怎么跑，全部回车 = 推荐配置"

# 1) 运行方式
if [ -n "$TTY" ]; then
cat > "$TTY" <<'EOF'

  怎么运行？
    [1] systemd 常驻服务（推荐，开机自启、崩溃自动重启）
    [2] Docker 容器（需要先装 docker）
    [3] 只跑一次看看效果，不装服务
EOF
fi
RUNMODE=$(ask "  选择 [1]: " "1")

# 2) 扫哪些厂商
if [ -n "$TTY" ]; then
cat > "$TTY" <<'EOF'

  扫哪些厂商的网段？
    [1] niche  小众优质线路（DMIT/搬瓦工/Akile/Cloudie 等，约 4000 个网段，几十秒一轮）
    [2] vps    主流便宜 VPS（含阿里云/腾讯云/甲骨文/Vultr/Contabo 等，约 22 万个网段）
    [3] all    除大陆外全部厂商（含亚马逊/微软/谷歌，约 204 万个网段，一轮约 4 小时）
EOF
fi
PRESET=$(ask "  选择 [2]: " "2")
case "$PRESET" in
  1|niche) ASNS="niche";;
  3|all)   ASNS="all";;
  *)       ASNS="vps";;
esac
ok "ASN 档位：${ASNS}"

# 3) 采样与循环
SAMPLE=$(ask "  每轮采样多少个网段？(0=全量) [300]: " "300")
LOOP=$(ask   "  每轮间隔多少秒？[1800]: " "1800")
THREADS=$(ask "  并发线程数？(VPS 建议 50~200) [50]: " "50")

# 4) Web 面板
WEB_ENABLE="n"; WEB_PORT="$WEB_PORT_DEFAULT"; WEB_TOKEN=""
if confirm "  要不要开 Web 管理面板（浏览器看状态和结果）？" "y"; then
  WEB_ENABLE="y"
  WEB_PORT=$(ask "  面板端口 [${WEB_PORT_DEFAULT}]: " "$WEB_PORT_DEFAULT")
  AUTO_TOKEN=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
  WEB_TOKEN=$(ask "  访问口令（直接回车用随机生成的）: " "$AUTO_TOKEN")
  BIND=$(ask "  只允许本机访问(1) 还是对外开放(2)？[1]: " "1")
  if [ "$BIND" = "2" ]; then WEB_HOST="0.0.0.0"; else WEB_HOST="127.0.0.1"; fi
fi

# ---------------------------------------------------------------- 写配置
info "写入配置"
CONF="$INSTALL_DIR/config.ini"
python3 - "$CONF" "$ASNS" "$SAMPLE" <<'PYEOF'
import re, sys
path, asns, sample = sys.argv[1], sys.argv[2], sys.argv[3]
txt = open(path, encoding='utf-8').read()
def setkey(txt, key, val):
    pat = re.compile(rf'^{re.escape(key)}\s*=.*$', re.M)
    line = f'{key} = {val}'
    return pat.sub(line, txt, count=1) if pat.search(txt) else txt + f'\n{line}\n'
txt = setkey(txt, 'ASNS', f'"{asns}"')
txt = setkey(txt, 'ASN_SAMPLE', sample)
txt = setkey(txt, 'ASN_EXCLUDE_REGIONS', '"CN"')
open(path, 'w', encoding='utf-8').write(txt)
print('  ASNS =', asns, '| ASN_SAMPLE =', sample)
PYEOF

# 环境文件（给 systemd / docker 读）
cat > "$INSTALL_DIR/cfip.env" <<EOF
ASNS=${ASNS}
ASN_SAMPLE=${SAMPLE}
ASN_EXCLUDE_REGIONS=CN
PYTHONUNBUFFERED=1
PYTHONUTF8=1
TZ=Asia/Shanghai
EOF
chmod 600 "$INSTALL_DIR/cfip.env"
ok "配置已写入 ${CONF}"

RUN_CMD="python3 fetch_ips.py -source asn -loop ${LOOP} -run -- -threads ${THREADS} -d 5 -log -quiet"

# 小硬盘保护：写进配置，让 ip.py 也走精简日志
python3 - "$CONF" <<'PYEOF'
import re, sys
path = sys.argv[1]
txt = open(path, encoding='utf-8').read()
def setkey(txt, key, val):
    pat = re.compile(rf'^{re.escape(key)}\s*=.*$', re.M)
    line = f'{key} = {val}'
    return pat.sub(line, txt, count=1) if pat.search(txt) else txt + f'\n{line}\n'
# 逐条进度日志是磁盘杀手，默认改成每 200 条一行
txt = setkey(txt, 'PROGRESS_EVERY', '200')
txt = setkey(txt, 'LOG_MAX_BYTES', '8388608')
txt = setkey(txt, 'KEEP_LOGS', '5')
txt = setkey(txt, 'KEEP_RESULTS', '20')
txt = setkey(txt, 'KEEP_DAYS', '7')
txt = setkey(txt, 'MIN_FREE_MB', '300')
open(path, 'w', encoding='utf-8').write(txt)
print('  已启用小硬盘保护：PROGRESS_EVERY=200 / LOG_MAX_BYTES=8MB / 自动清理')
PYEOF

# ---------------------------------------------------------------- 模式 3：只跑一次
if [ "$RUNMODE" = "3" ]; then
  info "试跑一轮（Ctrl+C 可中断）"
  cd "$INSTALL_DIR"
  set -a; . ./cfip.env; set +a
  exec python3 fetch_ips.py -source asn -max 200 -run -- -threads "$THREADS" -d 3 -log
fi

# ---------------------------------------------------------------- 模式 2：Docker
if [ "$RUNMODE" = "2" ]; then
  command -v docker >/dev/null 2>&1 || die "没装 docker。先装：curl -fsSL https://get.docker.com | sh"
  info "用 Docker Compose 启动"
  cd "$INSTALL_DIR"
  sed -i "s|^    image:.*|    build: .|" docker-compose.yml 2>/dev/null || true
  cat > docker-compose.override.yml <<EOF
services:
  cfip:
    environment:
      ASNS: "${ASNS}"
      ASN_SAMPLE: "${SAMPLE}"
      ASN_EXCLUDE_REGIONS: "CN"
    command: ["-source","asn","-loop","${LOOP}","-run","--","-threads","${THREADS}","-d","5","-log","-quiet"]
EOF
  if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi
  $DC up -d --build && ok "容器已启动" || die "启动失败，看 $DC logs"
  printf '\n'; $DC ps
  echo; info "看日志：cd ${INSTALL_DIR} && ${DC} logs -f"
  exit 0
fi

# ---------------------------------------------------------------- 模式 1：systemd
info "安装 systemd 服务"
cat > /etc/systemd/system/cfip.service <<EOF
[Unit]
Description=Cloudflare 反代 IP 优选（扫描+实测）
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/cfip.env
ExecStart=/usr/bin/env python3 fetch_ips.py -source asn -loop ${LOOP} -run -- -threads ${THREADS} -d 5 -log -quiet
Restart=always
RestartSec=30
# ping / traceroute 需要 raw socket
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cfip

[Install]
WantedBy=multi-user.target
EOF

if [ "$WEB_ENABLE" = "y" ]; then
cat > /etc/systemd/system/cfip-web.service <<EOF
[Unit]
Description=Cloudflare 反代 IP 优选 · Web 控制台
After=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/env python3 webui.py -host ${WEB_HOST} -port ${WEB_PORT} -token ${WEB_TOKEN} -run-args "-source asn -max 200 -run -- -threads ${THREADS} -d 3 -log"
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cfip-web

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable --now cfip.service >/dev/null 2>&1 && ok "cfip.service 已启动" || warn "启动失败，看 journalctl -u cfip -n 50"
if [ "$WEB_ENABLE" = "y" ]; then
  systemctl enable --now cfip-web.service >/dev/null 2>&1 && ok "cfip-web.service 已启动" || warn "Web 服务启动失败"
fi

sleep 2
printf '\n'
printf '%s\n' "${BLD}============================================================${RST}"
printf '%s\n' "${GRN} 安装完成${RST}"
printf '%s\n' "${BLD}============================================================${RST}"
echo "  安装目录 : ${INSTALL_DIR}"
echo "  配置文件 : ${CONF}"
echo "  扫描档位 : ${ASNS}   采样 ${SAMPLE}   每 ${LOOP}s 一轮   并发 ${THREADS}"
echo
echo "  常用命令："
echo "    systemctl status cfip          # 看运行状态"
echo "    journalctl -u cfip -f          # 实时日志"
echo "    systemctl restart cfip         # 重启"
echo "    ls ${INSTALL_DIR}/output/      # 看结果（ip.txt / bestips-*.csv）"
if [ "$WEB_ENABLE" = "y" ]; then
  IP=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || echo "<本机IP>")
  echo
  echo "  Web 控制台："
  if [ "$WEB_HOST" = "0.0.0.0" ]; then
    echo "    http://${IP}:${WEB_PORT}/?token=${WEB_TOKEN}"
    echo "    ${YEL}注意：面板已对外开放，请确认防火墙/安全组已放行 ${WEB_PORT}${RST}"
  else
    echo "    仅本机可访问，用 SSH 端口转发："
    echo "      ssh -L ${WEB_PORT}:127.0.0.1:${WEB_PORT} root@${IP}"
    echo "    然后浏览器打开 http://127.0.0.1:${WEB_PORT}/?token=${WEB_TOKEN}"
  fi
fi
echo
printf '%s\n' "${YEL} 提醒：扫描第三方网段请保持克制，不要调高并发或缩短间隔。${RST}"
