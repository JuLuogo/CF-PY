cd /opt/cfip || exit 1
SHA=cd31e0e

echo "===== 1) 用 jsDelivr 按 commit hash 拉最新代码 ====="
for f in fetch_ips.py ip.py webui.py notify.py; do
  URL="https://cdn.jsdelivr.net/gh/JuLuogo/CF-PY@${SHA}/${f}"
  if curl -fsSL --max-time 30 "$URL" -o "$f.new" 2>/dev/null; then
    mv "$f.new" "$f"
    echo "  ✓ $f ($(stat -c%s $f) bytes)"
  else
    rm -f "$f.new"; echo "  ✗ $f"
  fi
done
chmod +x *.py
rm -rf __pycache__

echo
echo "===== 2) 校验新架构就位 ====="
echo "  run_asn_pipeline:      $(grep -c 'def run_asn_pipeline' fetch_ips.py)"
echo "  iter_asn_batches:      $(grep -c 'def iter_asn_batches' fetch_ips.py)"
echo "  池子安全阀:            $(grep -c 'POOL_MIN_KEEP_RATIO' fetch_ips.py)"
echo "  面板读池子:            $(grep -c \"await api('/api/pool')\" webui.py)"

echo
echo "===== 3) 清掉旧的中间产物 ====="
rm -f ip.csv output/stage1.csv output/stage1.csv.new
rm -rf output/2026-*
df -h / | sed 's/^/  /'

echo
echo "===== 4) 配置确认（先跑 niche 验证新架构）====="
set_key() {
  if grep -q "^$1" config.ini; then sed -i "s|^$1 = .*|$1 = $2|" config.ini
  else echo "$1 = $2" >> config.ini; fi
}
set_key ASNS '"niche"'
set_key ASN_SAMPLE 0
set_key FULL_SCAN true
set_key UPSTREAM_STAGE1_ONLY true
set_key POOL_ENABLED true
set_key POOL_MODE '"auto"'
set_key POOL_MIN_KEEP_RATIO 0.1
set_key STAGE0_CONCURRENCY 2000
set_key ASYNCIO_CONCURRENCY 800
grep -E '^(ASNS|ASN_SAMPLE|FULL_SCAN|UPSTREAM_|POOL_|STAGE0_CONC|ASYNCIO_CONC)' config.ini | sed 's/^/    /'

echo
echo "===== 5) 启动 ====="
systemctl restart cfip cfip-web
sleep 8
for s in cfip cfip-web; do
  systemctl is-active --quiet $s && echo "  ✓ $s" || echo "  ✗ $s"
done

echo
echo "===== 6) 观察 120 秒（看磁盘是否稳定）====="
for i in 1 2 3 4; do
  sleep 30
  USED=$(df -m / | tail -1 | awk '{print $3}')
  S1=$(stat -c%s output/stage1.csv.new 2>/dev/null || echo 0)
  IC=$(stat -c%s ip.csv 2>/dev/null || echo 0)
  printf "  %3ds  磁盘已用 %sMB  stage1.new=%s字节  ip.csv=%s字节\n" $((i*30)) "$USED" "$S1" "$IC"
done

echo
echo "===== 7) 最终状态 ====="
df -h / | sed 's/^/  /'
free -m | sed 's/^/  /'
echo
ps aux --sort=-rss | grep -E "fetch_ips|ip\.py|webui" | grep -v grep \
  | awk '{printf "  PID %-8s CPU %-6s RSS %7.1fMB\n", $2, $3"%", $6/1024}'
echo
echo "  --- 日志 ---"
journalctl -u cfip -n 8 --no-pager | tail -8 | sed 's/^/  /'
echo
echo "  --- 进度 ---"
TOKEN=$(grep -oP '(?<=-token )\S+' /etc/systemd/system/cfip-web.service | head -1)
PORT=$(grep -oP '(?<=-port )\d+' /etc/systemd/system/cfip-web.service | head -1)
curl -sS --max-time 8 "http://127.0.0.1:${PORT}/api/status?token=${TOKEN}" -o /tmp/s.json
python3 - <<'PY'
import json
d = json.load(open('/tmp/s.json'))
print("    state:", d.get('state'))
for k, p in (d.get('progress') or {}).items():
    print("    [%s] %s/%s (%.1f%%)" % (k, p.get('done'), p.get('total'), p.get('pct',0)))
PY
